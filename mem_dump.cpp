/*
 * mem_dump.cpp — 进程内存快照实现
 *
 * 关键取舍：
 *   - 读内存一律走 process_vm_readv：踩到 guard page / PROT_NONE 只是返回
 *     错误，不会像直接 memcpy 那样把进程打挂
 *   - 读不到的页补零而不是跳过：blob 的文件偏移与区段偏移严格 1:1，回放端
 *     直接 mmap 到 dump_start 即可，不用再算洞
 *   - 单区段超限整段跳过（不截断）：截断的半截数据在回放时比没有更危险，
 *     index.tsv 里记 skip，回放端能看出「这段我没有」
 *   - 栈只 dump sp 之上的活跃部分：sp 以下是垃圾，且主线程栈区段动辄 8MB，
 *     全读会把未触碰的零页真的 commit 出来
 */

#include "mem_dump.h"

#include <android/log.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <unistd.h>

#include <atomic>
#include <cstdio>
#include <cstring>

#define LOG_TAG "duck"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

static constexpr size_t kPageSize = 0x1000;
static constexpr size_t kChunkSize = 256 * 1024; // 单次 process_vm_readv 上限
static constexpr uint64_t kStackTailDefault = 1 << 20; // 没有 sp 落在栈里时兜底 dump 的尾部长度

// 上限：单区段 32MB（放得下正常 so / 栈 / 绝大多数匿名段，挡住 ART 大堆），
// 单次 dump 总预算 512MB
static uint64_t g_limit_per_region = 32ULL << 20;
static uint64_t g_limit_total = 512ULL << 20;

// dump 序号：同一次运行里多次 dump 各占一个子目录，按序号天然有序
static std::atomic<uint32_t> g_dump_seq{ 0 };

void mem_dump_set_limits(uint64_t perRegion, uint64_t total)
{
	g_limit_per_region = perRegion;
	g_limit_total = total;
}

// ============================================================================
// 基础工具
// ============================================================================

static bool write_all(int fd, const void *buf, size_t len)
{
	const char *p = static_cast<const char *>(buf);
	while (len > 0) {
		ssize_t n = ::write(fd, p, len);
		if (n <= 0) {
			if (n < 0 && errno == EINTR) {
				continue;
			}
			return false;
		}
		p += n;
		len -= (size_t)n;
	}
	return true;
}

// 逐级 mkdir（等价 mkdir -p），已存在的 EEXIST 忽略
static void mkdir_p(const std::string &path)
{
	std::string cur;
	for (size_t i = 0; i < path.size(); i++) {
		cur += path[i];
		if (path[i] == '/' && cur.size() > 1) {
			mkdir(cur.c_str(), 0755);
		}
	}
	mkdir(path.c_str(), 0755);
}

static ssize_t read_remote(uint64_t addr, void *buf, size_t len)
{
	struct iovec local = { buf, len };
	struct iovec remote = { (void *)(uintptr_t)addr, len };
	return process_vm_readv(getpid(), &local, 1, &remote, 1, 0);
}

// ============================================================================
// /proc/self/maps
// ============================================================================

static bool read_file_all(const char *path, std::string &out)
{
	int fd = ::open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		return false;
	}
	out.clear();
	char buf[8192];
	for (;;) {
		ssize_t n = ::read(fd, buf, sizeof(buf));
		if (n < 0) {
			if (errno == EINTR) {
				continue;
			}
			break;
		}
		if (n == 0) {
			break;
		}
		out.append(buf, (size_t)n);
	}
	::close(fd);
	return true;
}

bool mem_read_maps(std::vector<MapRegion> &out, std::string *raw)
{
	std::string text;
	if (!read_file_all("/proc/self/maps", text)) {
		return false;
	}
	if (raw != nullptr) {
		*raw = text;
	}

	out.clear();
	size_t pos = 0;
	while (pos < text.size()) {
		size_t eol = text.find('\n', pos);
		if (eol == std::string::npos) {
			eol = text.size();
		}
		std::string line = text.substr(pos, eol - pos);
		pos = eol + 1;
		if (line.empty()) {
			continue;
		}

		// 7f8a2c0000-7f8a2d0000 r-xp 00000000 fd:03 1234   /path/with spaces.so
		MapRegion r;
		memset(r.prot, 0, sizeof(r.prot));
		unsigned maj = 0, min = 0;
		unsigned long ino = 0;
		int consumed = 0;
		int got = sscanf(line.c_str(),
			"%" SCNx64 "-%" SCNx64 " %4s %" SCNx64 " %x:%x %lu %n",
			&r.start,
			&r.end,
			r.prot,
			&r.fileOff,
			&maj,
			&min,
			&ino,
			&consumed);
		if (got < 7 || r.end <= r.start) {
			continue;
		}
		if (consumed > 0 && (size_t)consumed < line.size()) {
			r.path = line.substr((size_t)consumed);
		}
		out.push_back(std::move(r));
	}
	return !out.empty();
}

// ============================================================================
// 区段分类
// ============================================================================

enum RegionKind
{
	KIND_NONE = 0,
	KIND_SO, // 目标 so 的文件映射段
	KIND_SO_BSS, // 紧跟 so 之后的匿名段（linker 给 .bss 的映射）
	KIND_STACK,
	KIND_ANON_X, // 匿名 r-xp / rwxp
	KIND_ANON_RW, // 匿名 rw-p
};

static const char *kind_name(RegionKind k)
{
	switch (k) {
	case KIND_SO:
		return "so";
	case KIND_SO_BSS:
		return "so-bss";
	case KIND_STACK:
		return "stack";
	case KIND_ANON_X:
		return "anon-x";
	case KIND_ANON_RW:
		return "anon-rw";
	default:
		return "-";
	}
}

static int kind_flag(RegionKind k)
{
	switch (k) {
	case KIND_SO:
	case KIND_SO_BSS:
		return MEM_DUMP_TARGET_SO;
	case KIND_STACK:
		return MEM_DUMP_STACK;
	case KIND_ANON_X:
		return MEM_DUMP_ANON_EXEC;
	case KIND_ANON_RW:
		return MEM_DUMP_ANON_RW;
	default:
		return 0;
	}
}

// 标记目标 so 的运行期映射：以 moduleBase 所在区段为锚，向后吃掉同路径的段，
// 以及紧邻其后的匿名 rw 段（.bss，部分 bionic 版本命名为 [anon:.bss]，老版本无名）
static void mark_module_regions(const std::vector<MapRegion> &regions,
	const MemDumpRequest &req,
	std::vector<RegionKind> &kinds)
{
	if (req.moduleBase == 0) {
		return;
	}
	size_t anchor = regions.size();
	for (size_t i = 0; i < regions.size(); i++) {
		if (regions[i].contains(req.moduleBase)) {
			anchor = i;
			break;
		}
	}
	if (anchor == regions.size()) {
		return;
	}

	// 锚点区段的路径就是权威路径：dli_fname 可能是 apk 内路径等变体，不强行比对。
	// 但 so 直接从 apk 映射时（path 都是 base.apk），同 apk 里别的 so 路径完全相同，
	// 光比路径会误吃，所以真正的边界判据是「地址连续」——一出现断层就停。
	const std::string &soPath = regions[anchor].path;
	if (soPath.empty()) {
		return;
	}
	uint64_t prevEnd = 0;
	for (size_t i = anchor; i < regions.size(); i++) {
		const MapRegion &r = regions[i];
		if (prevEnd != 0 && r.start != prevEnd) {
			break; // 地址断层：已经走出这个模块
		}
		if (r.path == soPath) {
			kinds[i] = KIND_SO;
		} else if (!r.readable() && !r.writable() && !r.exec()) {
			// ---p 空洞（linker 的 RELRO / 页对齐 padding）：没内容可读，跳过但
			// 继续往后走。这里若 break，后面的 .data/.bss 会被整段漏掉，而
			// VMP 的 dispatch table 恰恰常驻 .data。
		} else if (r.anon() && r.path != "[stack]" && r.writable() && !r.exec()) {
			kinds[i] = KIND_SO_BSS;
		} else {
			break;
		}
		prevEnd = r.end;
	}
}

static void classify(const std::vector<MapRegion> &regions, const MemDumpRequest &req, std::vector<RegionKind> &kinds)
{
	kinds.assign(regions.size(), KIND_NONE);
	mark_module_regions(regions, req, kinds);

	for (size_t i = 0; i < regions.size(); i++) {
		if (kinds[i] != KIND_NONE) {
			continue;
		}
		const MapRegion &r = regions[i];
		if (!r.readable()) {
			continue; // ---p / guard page，没内容可读
		}

		bool isStack = (r.path == "[stack]");
		for (uint64_t sp : req.stacks) {
			if (sp != 0 && r.contains(sp)) {
				isStack = true;
				break;
			}
		}
		if (isStack) {
			kinds[i] = KIND_STACK;
		} else if (r.anon() && r.exec()) {
			kinds[i] = KIND_ANON_X;
		} else if (r.anon() && r.writable()) {
			kinds[i] = KIND_ANON_RW;
		}
	}
}

// 栈只取活跃部分：sp 向下取整到页 → 区段末尾。没有 sp 落在里面就兜底取尾部 1MB。
static void stack_range(const MapRegion &r, const MemDumpRequest &req, uint64_t &start, uint64_t &size)
{
	uint64_t best = 0;
	for (uint64_t sp : req.stacks) {
		if (sp != 0 && r.contains(sp) && (best == 0 || sp < best)) {
			best = sp;
		}
	}
	if (best != 0) {
		start = best & ~(uint64_t)(kPageSize - 1);
	} else {
		uint64_t tail = r.size() < kStackTailDefault ? r.size() : kStackTailDefault;
		start = r.end - tail;
	}
	size = r.end - start;
}

// ============================================================================
// 落盘
// ============================================================================

// 把 [start, start+size) 写到 path。读不到的页补零，*zeroPages 返回补零页数。
static bool dump_range(const std::string &path, uint64_t start, uint64_t size, uint64_t *zeroPages)
{
	int fd = ::open(path.c_str(), O_CREAT | O_WRONLY | O_TRUNC | O_CLOEXEC, 0644);
	if (fd < 0) {
		return false;
	}
	char *buf = static_cast<char *>(
		mmap(nullptr, kChunkSize, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));
	if (buf == MAP_FAILED) {
		::close(fd);
		return false;
	}

	bool ok = true;
	*zeroPages = 0;
	for (uint64_t off = 0; off < size; off += kChunkSize) {
		size_t n = (size_t)((size - off < kChunkSize) ? (size - off) : kChunkSize);
		if (read_remote(start + off, buf, n) != (ssize_t)n) {
			// 整块读失败：退化到逐页，读不到的页补零，保持偏移对齐
			memset(buf, 0, n);
			for (size_t p = 0; p < n; p += kPageSize) {
				size_t pn = (n - p < kPageSize) ? (n - p) : kPageSize;
				if (read_remote(start + off + p, buf + p, pn) != (ssize_t)pn) {
					memset(buf + p, 0, pn);
					(*zeroPages)++;
				}
			}
		}
		if (!write_all(fd, buf, n)) {
			ok = false;
			break;
		}
	}

	munmap(buf, kChunkSize);
	::close(fd);
	if (!ok) {
		::unlink(path.c_str());
	}
	return ok;
}

// note 统一构造：{} / {"hot":"1"} / {"hot":"1","skip":"budget"} ...
static std::string make_note(bool hot, const char *key, const char *val)
{
	std::string body;
	if (hot) {
		body = "\"hot\":\"1\"";
	}
	if (key != nullptr) {
		if (!body.empty()) {
			body += ",";
		}
		body += "\"";
		body += key;
		body += "\":\"";
		body += val;
		body += "\"";
	}
	return body.empty() ? std::string("{}") : "{" + body + "}";
}

// index.tsv 一行：tag line start end rva prot type dump_start dump_size file path note
static void append_index(int fd,
	const std::string &tag,
	uint64_t line,
	const MapRegion &r,
	RegionKind kind,
	uint64_t moduleBase,
	uint64_t dumpStart,
	uint64_t dumpSize,
	const std::string &file,
	const std::string &note)
{
	// RVA 只对目标 so 的段有意义。PC 锚点必须用 RVA——绝对地址会随 ASLR 漂移
	char rva[24];
	if ((kind == KIND_SO || kind == KIND_SO_BSS) && moduleBase != 0 && r.start >= moduleBase) {
		snprintf(rva, sizeof(rva), "0x%-10" PRIx64, r.start - moduleBase);
	} else {
		snprintf(rva, sizeof(rva), "%-12s", "-");
	}

	char row[1024];
	int n = snprintf(row,
		sizeof(row),
		"%s\t%" PRIx64 "\t0x%-12" PRIx64 "\t0x%-12" PRIx64 "\t%s\t%s\t%-8s\t0x%-12" PRIx64 "\t0x%-9" PRIx64
		"\t%s\t%s\t%s\n",
		tag.c_str(),
		line,
		r.start,
		r.end,
		rva,
		r.prot,
		kind_name(kind),
		dumpStart,
		dumpSize,
		file.empty() ? "-" : file.c_str(),
		r.path.empty() ? "-" : r.path.c_str(),
		note.c_str());
	if (n > 0) {
		write_all(fd, row, (size_t)((size_t)n < sizeof(row) ? (size_t)n : sizeof(row) - 1));
	}
}

int mem_dump_run(const std::string &outDir, const MemDumpRequest &req)
{
	if (req.flags == 0) {
		return 0;
	}

	std::vector<MapRegion> regions;
	std::string rawMaps;
	if (!mem_read_maps(regions, &rawMaps)) {
		LOGE("mem_dump: read /proc/self/maps failed");
		return -1;
	}

	std::string memDir = outDir + "/mem";
	mkdir_p(memDir);

	uint32_t seq = g_dump_seq.fetch_add(1);
	std::string tagName = req.tag.empty() ? std::string("dump") : req.tag;
	char sub[64];
	snprintf(sub, sizeof(sub), "%02u_%s", seq, tagName.c_str());
	std::string blobDir = memDir + "/" + sub;

	// ---- maps 快照：每次 dump 一份（布局会随 dlopen/mmap 变化）----
	if (req.flags & MEM_DUMP_MAPS) {
		std::string mapsPath = memDir + "/" + std::string(sub) + "_maps.txt";
		int fd = ::open(mapsPath.c_str(), O_CREAT | O_WRONLY | O_TRUNC | O_CLOEXEC, 0644);
		if (fd >= 0) {
			write_all(fd, rawMaps.data(), rawMaps.size());
			::close(fd);
		}
	}

	std::vector<RegionKind> kinds;
	classify(regions, req, kinds);

	// index.tsv 追加打开：多次 dump 共用一份清单，靠 line/file 列区分
	std::string indexPath = memDir + "/index.tsv";
	bool fresh = (::access(indexPath.c_str(), F_OK) != 0);
	int idxFd = ::open(indexPath.c_str(), O_CREAT | O_WRONLY | O_APPEND | O_CLOEXEC, 0644);
	if (idxFd >= 0 && fresh) {
		const char *hdr =
			"#tag\tline\tstart\tend\trva\tprot\ttype\tdump_start\tdump_size\tfile\tpath\tnote\n";
		write_all(idxFd, hdr, strlen(hdr));
	}
	// 每次 dump 先写一行元信息：模块基址在这里，下游算 RVA 不用再去翻 maps.txt
	if (idxFd >= 0) {
		char meta[640];
		int mn = snprintf(meta,
			sizeof(meta),
			"#dump\ttag=%s\tseq=%u\tline=%" PRIx64 "\tmodule_base=0x%" PRIx64 "\tmodule=%s\n",
			tagName.c_str(),
			seq,
			req.line,
			req.moduleBase,
			req.modulePath.empty() ? "-" : req.modulePath.c_str());
		if (mn > 0) {
			write_all(idxFd, meta, (size_t)((size_t)mn < sizeof(meta) ? (size_t)mn : sizeof(meta) - 1));
		}
	}

	mkdir_p(blobDir);

	// 热区标记：trace 期间真正被读写过的区段。VMP 的字节码和 dispatch table 必然
	// 在这里面，所以它们优先占预算、且不受单区段上限约束——否则一块大 anon-rw
	// （ART 堆之类）先把 512MB 预算吃光，字节码区就只剩一行 skip 了。
	std::vector<bool> hot(regions.size(), false);
	for (uint64_t page : req.hotPages) {
		for (size_t i = 0; i < regions.size(); i++) {
			// 桶未必和区段边界对齐，按区间相交判定
			if (kinds[i] != KIND_NONE && page < regions[i].end && page + MEM_DUMP_HOT_BUCKET > regions[i].start) {
				hot[i] = true;
			}
		}
	}

	// 按重要性分批：预算用光时先保住目标 so 和栈，最后才轮到大块匿名数据
	const RegionKind passes[] = { KIND_SO, KIND_SO_BSS, KIND_STACK, KIND_ANON_X, KIND_ANON_RW };
	uint64_t used = 0;
	int dumped = 0;

	// 两轮：先 trace 命中过的热区（预算优先给它们），再其余
	for (int phase = 0; phase < 2; phase++) {
		for (RegionKind pass : passes) {
			if ((req.flags & kind_flag(pass)) == 0) {
				continue;
			}
			for (size_t i = 0; i < regions.size(); i++) {
				if (kinds[i] != pass) {
					continue;
				}
				if ((phase == 0) != (bool)hot[i]) {
					continue;
				}
				const MapRegion &r = regions[i];

				uint64_t dumpStart = r.start;
				uint64_t dumpSize = r.size();
				if (pass == KIND_STACK) {
					stack_range(r, req, dumpStart, dumpSize);
				}

				// trace 自身的脚手架内存（专用大栈等）：工具的东西，不是目标
				// 进程状态，照样记一行让清单和 maps 对得上，但不落盘
				bool skipExcluded = false;
				for (const auto &x : req.excludes) {
					if (dumpStart < x.second && dumpStart + dumpSize > x.first) {
						skipExcluded = true;
						break;
					}
				}
				if (skipExcluded) {
					append_index(idxFd, tagName, req.line, r, pass, req.moduleBase, dumpStart, dumpSize, "",
						make_note(hot[i], "skip", "trace_internal"));
					continue;
				}

				// so 段是这套工具的主角；热区是本次 trace 真正碰过的内存。都不限尺寸
				bool exempt = (pass == KIND_SO || pass == KIND_SO_BSS) || hot[i];
				if (!exempt && g_limit_per_region != 0 && dumpSize > g_limit_per_region) {
					append_index(idxFd, tagName, req.line, r, pass, req.moduleBase, dumpStart, dumpSize, "",
						make_note(hot[i], "skip", "too_large"));
					continue;
				}
				if (g_limit_total != 0 && used + dumpSize > g_limit_total) {
					append_index(idxFd, tagName, req.line, r, pass, req.moduleBase, dumpStart, dumpSize, "",
						make_note(hot[i], "skip", "budget"));
					continue;
				}

				char nameBuf[64];
				snprintf(nameBuf, sizeof(nameBuf), "%" PRIx64 "-%" PRIx64 ".bin", dumpStart, dumpStart + dumpSize);
				std::string rel = std::string(sub) + "/" + nameBuf;

				uint64_t zeroPages = 0;
				if (!dump_range(blobDir + "/" + nameBuf, dumpStart, dumpSize, &zeroPages)) {
					append_index(idxFd, tagName, req.line, r, pass, req.moduleBase, dumpStart, dumpSize, "",
						make_note(hot[i], "skip", "read_failed"));
					continue;
				}

				std::string note;
				if (zeroPages != 0) {
					char zb[32];
					snprintf(zb, sizeof(zb), "0x%" PRIx64, zeroPages);
					note = make_note(hot[i], "zero_pages", zb);
				} else {
					note = make_note(hot[i], nullptr, nullptr);
				}
				append_index(
					idxFd, tagName, req.line, r, pass, req.moduleBase, dumpStart, dumpSize, rel, note);
				used += dumpSize;
				dumped++;
			}
		}
	}

	if (idxFd >= 0) {
		::close(idxFd);
	}
	LOGI("mem dump [%s]: %d regions, %" PRIu64 " KB -> %s", sub, dumped, used >> 10, blobDir.c_str());
	return dumped;
}
