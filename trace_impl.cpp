/*
 * trace_impl.cpp — QBDI + Frida Gum 指令级 trace agent 核心实现
 *
 * 架构（沿袭 defer/qdbi_demo/vm.cpp 的嵌套 VM 方案）：
 *   1. Frida Gum hook 目标函数（attach listener 或 replace）
 *   2. hook 命中时，把 GumCpuContext 灌进一个新建的 QBDI VM，
 *      从函数入口 run 到 LR（返回地址），整条指令流走 QBDI
 *   3. QBDI 回调把结果写进三文件（code/rw/bl.log，格式见 docs/TraceFormat.md）
 *
 * 关键坑（来自项目经验，勿踩）：
 *   - EXEC_TRANSFER_CALL 的调用目标在 GPRState->pc（AArch64），不是 lr
 *   - SVC 指令 QBDI 无法执行，必须注册 mnemonic 回调兜底
 *   - 寄存器 regCtxIdx：0-30 = x0..lr，31 = sp，32 = nzcv，33 = pc
 *   - 输出目录默认 /data/data/<包名>/files/trace_logs，frida spawn 的 app
 *     没有 /data/local/tmp 写权限
 */

#include "trace_impl.h"
#include "raw_logger.h"

#include <android/log.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <unistd.h>

#include <atomic>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

#include "QBDI.h"
#include "frida-gum.h"

#define LOG_TAG "duck"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

// 专用 trace 栈大小：QBDI 执行目标函数 + InstCallback + trace 机制自身的
// C++ 栈帧都搬到这块大栈上，避免被 hook 函数从接近耗尽的 app 线程栈调用时
// 顶穿 guard page（真机实测 hook 点处仅剩 ~0x60-0x110 字节余量）。
static constexpr size_t kTraceStackSize = 8 * 1024 * 1024;

// ============================================================================
// 输出目录 & 三文件初始化
// ============================================================================

static std::string g_output_dir; // 空 = 默认 /data/data/<pkg>/files/trace_logs
static bool g_loggers_inited = false;
static std::mutex g_loggers_mutex;

// trace 记录范围（字节数）。0 = 不限（记录目标函数所在模块全部执行流）
static uint64_t g_trace_range_size = 0;

static std::string get_process_data_dir()
{
	char cmdline[256] = { 0 };
	int fd = ::open("/proc/self/cmdline", O_RDONLY);
	if (fd >= 0) {
		ssize_t n = ::read(fd, cmdline, sizeof(cmdline) - 1);
		(void)n;
		::close(fd);
	}
	std::string name(cmdline); // 已含 '\0'，string 构造在此截断
	size_t pos = name.find(':');
	if (pos != std::string::npos) {
		name = name.substr(0, pos); // 去掉 :process 后缀
	}
	return "/data/data/" + name;
}

static std::string getFilename(const std::string &path)
{
	size_t pos = path.find_last_of("/\\");
	return pos == std::string::npos ? path : path.substr(pos + 1);
}

static void init_trace_logs_locked()
{
	if (g_loggers_inited) {
		return;
	}
	if (g_raw_logger == nullptr) {
		g_raw_logger = new RawMemoryLogger();
	}
	if (g_rw_logger == nullptr) {
		g_rw_logger = new RawMemoryLogger();
	}
	if (g_bl_logger == nullptr) {
		g_bl_logger = new RawMemoryLogger();
	}

	std::string dir = g_output_dir;
	if (dir.empty()) {
		dir = get_process_data_dir() + "/files/trace_logs";
	}
	mkdir(dir.c_str(), 0755);

	int ok = 0;
	ok += (g_raw_logger->init((dir + "/code.log").c_str()) == 0);
	ok += (g_rw_logger->init((dir + "/rw.log").c_str()) == 0);
	ok += (g_bl_logger->init((dir + "/bl.log").c_str()) == 0);
	if (ok == 3) {
		g_loggers_inited = true;
		LOGI("trace logs: %s/{code,rw,bl}.log", dir.c_str());
	} else {
		LOGE("init trace logs failed (%d/3)", ok);
	}
}

static void ensure_loggers()
{
	std::lock_guard<std::mutex> lock(g_loggers_mutex);
	init_trace_logs_locked();
}

int vmtrace_set_output_dir(const char *dir)
{
	std::lock_guard<std::mutex> lock(g_loggers_mutex);
	g_output_dir = dir ? dir : "";
	if (g_loggers_inited) {
		// 已打开过：先关掉，下次 trace 时用新目录重新打开
		if (g_raw_logger != nullptr) {
			g_raw_logger->close();
		}
		if (g_rw_logger != nullptr) {
			g_rw_logger->close();
		}
		if (g_bl_logger != nullptr) {
			g_bl_logger->close();
		}
		g_loggers_inited = false;
	}
	return 0;
}

int vmtrace_set_function_size(uint64_t size)
{
	g_trace_range_size = size;
	return 0;
}

// ============================================================================
// 工具函数
// ============================================================================

// 全局行号：跨 trace 会话递增，保证三文件行号索引全局唯一
static std::atomic<uint64_t> g_line_num{ 0 };

// hexdump：统一从 addr-0x10 起，0x30 字节（TraceFormat.md 约定）
static void write_hexdump(RawMemoryLogger *logger, uint64_t addr)
{
	if (logger == nullptr) {
		return;
	}
	uint64_t start = (addr >= 0x10) ? (addr - 0x10) : 0;

	uint8_t buf[0x30];
	struct iovec local = { buf, sizeof(buf) };
	struct iovec remote = { (void *)(uintptr_t)start, sizeof(buf) };
	ssize_t got = process_vm_readv(getpid(), &local, 1, &remote, 1, 0);
	if (got <= 0) {
		return;
	}
	size_t bytes = (size_t)got;

	char row[256];
	for (size_t off = 0; off < bytes; off += 16) {
		int p = 0;
		p += snprintf(row + p, sizeof(row) - p, "%08llx: ", (unsigned long long)(start + off));
		for (int i = 0; i < 16; i++) {
			if (off + (size_t)i < bytes) {
				p += snprintf(row + p, sizeof(row) - p, "%02x ", buf[off + i]);
			} else {
				p += snprintf(row + p, sizeof(row) - p, "   ");
			}
		}
		p += snprintf(row + p, sizeof(row) - p, "|");
		for (int i = 0; i < 16; i++) {
			if (off + (size_t)i < bytes) {
				uint8_t c = buf[off + i];
				row[p++] = (c >= 0x20 && c < 0x7f) ? (char)c : '.';
			} else {
				row[p++] = ' ';
			}
		}
		row[p++] = '|';
		row[p] = '\0';
		raw_logger_write_cached(logger, row, p);
		raw_logger_write_cached(logger, "\n", 1);
	}
}

// ============================================================================
// QBDI 回调数据
// ============================================================================

// 一个指令操作数的寄存器引用（W{} 需要 POSTINST 才读得到值）
struct RegRef
{
	std::string name;
	QBDI::OperandType type;
	int16_t regCtxIdx;
	uint8_t size;
};

// 读寄存器要的是 PRE 值，直接在 PREINST 算好存进来
struct RegVal
{
	std::string name;
	QBDI::OperandType type;
	int16_t regCtxIdx;
	uint64_t value;
};

// 一条指令的 PRE 分析结果（PREINST 缓存，POSTINST 消费）
struct CachedInst
{
	uint64_t lineNum;
	uint64_t offset;
	std::string disasm;
	std::vector<RegVal> reads;
	std::vector<RegRef> writes;
	uint64_t memBase; // 基址寄存器 PRE 值（rw.log 的 0xbase 部分）
	bool haveMemBase;
};

// 单次 trace 会话（嵌套 VM 一次执行）
struct TraceSession
{
	uint64_t baseAddr;
	std::string moduleName;
	uint64_t currentLine; // 最近一条指令的行号（transfer 事件用）
	std::unordered_map<uint64_t, CachedInst> cache;
	// SVC 指令 → syscall 注解串（mnemonic 回调 PREINST 填，POSTINST 消费）
	// 用独立表而不塞 CachedInst：避免与 PREINST 代码回调的执行顺序耦合
	std::unordered_map<uint64_t, std::string> syscallNotes;
};

// 安全追加格式化输出（防 snprintf 返回超长导致越界）
struct Buf
{
	char *data;
	size_t cap;
	int len;

	Buf(char *d, size_t c)
		: data(d)
		, cap(c)
		, len(0)
	{
	}

	void appendf(const char *fmt, ...)
	{
		if ((size_t)len >= cap) {
			return;
		}
		va_list ap;
		va_start(ap, fmt);
		int n = vsnprintf(data + len, cap - len, fmt, ap);
		va_end(ap);
		if (n < 0) {
			return;
		}
		len += n;
		if ((size_t)len >= cap) {
			len = (int)cap - 1; // 截断，绝不越界
		}
	}

	void append(const char *s)
	{
		appendf("%s", s);
	}
};

// 把同一行标记写到三个文件（Trace Start/End 用，方便区分 trace 会话）
static void write_trace_marker(const char *fmt, ...)
{
	char tmp[256];
	va_list ap;
	va_start(ap, fmt);
	vsnprintf(tmp, sizeof(tmp), fmt, ap);
	va_end(ap);

	char m_raw[256];
	Buf m(m_raw, sizeof(m_raw));
	m.append(tmp);
	m.append("\n");
	m_raw[m.len] = '\0';
	raw_logger_write_cached(g_raw_logger, m_raw, m.len);
	raw_logger_write_cached(g_rw_logger, m_raw, m.len);
	raw_logger_write_cached(g_bl_logger, m_raw, m.len);
}

// 读 GPR/FPR 寄存器值；GPR 按操作数位宽截断（w 寄存器只显低 32 位）
static uint64_t reg_ref_value(const QBDI::GPRState *gpr, const QBDI::FPRState *fpr, const RegRef &ref, bool truncate)
{
	if (ref.type == QBDI::OPERAND_FPR) {
		if (ref.regCtxIdx >= 0 && ref.regCtxIdx < 32 && fpr != nullptr) {
			// FPRState v0..v31 各 16 字节，取低 64 位
			const uint64_t *base = (const uint64_t *)&fpr->v0;
			return base[ref.regCtxIdx * 2];
		}
		return 0;
	}
	if (ref.regCtxIdx < 0) {
		return 0;
	}
	if (ref.regCtxIdx <= (int16_t)QBDI::REG_LR) { // 0..30 = x0..x29, lr
		uint64_t v = QBDI_GPR_GET(gpr, ref.regCtxIdx);
		if (truncate && ref.size <= 4) {
			v &= 0xFFFFFFFF;
		}
		return v;
	}
	if (ref.regCtxIdx == (int16_t)QBDI::REG_SP) {
		return gpr->sp;
	}
	if (ref.regCtxIdx == (int16_t)QBDI::REG_PC) {
		return gpr->pc;
	}
	if (ref.regCtxIdx == (int16_t)QBDI::REG_FLAG) {
		return gpr->nzcv;
	}
	return 0;
}

// 把一组寄存器拼成 JSON 对象：{"x2":"0x1234","x3":"0x5678"}；空向量输出 {}。
// 字段只含 [a-z0-9]（寄存器名）与 0x[0-9a-f]（值），无需 JSON 转义；
// 若未来把任意字符串塞进来，必须先加转义，否则破坏此不变式。
static void append_reg_json(Buf &b, const std::vector<RegVal> &regs)
{
	b.append("{");
	for (size_t i = 0; i < regs.size(); i++) {
		if (i != 0) {
			b.append(",");
		}
		b.appendf("\"%s\":\"0x%llx\"", regs[i].name.c_str(), (unsigned long long)regs[i].value);
	}
	b.append("}");
}

// writes 版：RegRef 只有名字，POSTINST 时从 gpr 取结果值
static void append_reg_json(Buf &b, const std::vector<RegRef> &regs,
	const QBDI::GPRState *gpr, const QBDI::FPRState *fpr)
{
	b.append("{");
	for (size_t i = 0; i < regs.size(); i++) {
		if (i != 0) {
			b.append(",");
		}
		b.appendf("\"%s\":\"0x%llx\"", regs[i].name.c_str(),
			(unsigned long long)reg_ref_value(gpr, fpr, regs[i], true));
	}
	b.append("}");
}

// ============================================================================
// QBDI 回调
// ============================================================================

// PREINST：收集读寄存器（PRE 值）+ 写寄存器名 + 基址分解，缓存到会话
static QBDI::VMAction trace_preinst(QBDI::VMInstanceRef vm, QBDI::GPRState *gpr, QBDI::FPRState *fpr, void *data)
{
	TraceSession *ts = static_cast<TraceSession *>(data);
	const QBDI::InstAnalysis *inst = vm->getInstAnalysis(
		QBDI::ANALYSIS_INSTRUCTION | QBDI::ANALYSIS_DISASSEMBLY | QBDI::ANALYSIS_OPERANDS);
	if (inst == nullptr) {
		return QBDI::CONTINUE;
	}

	CachedInst ci;
	ci.lineNum = g_line_num.fetch_add(1);
	ci.offset = inst->address - ts->baseAddr;
	ci.disasm = inst->disassembly ? inst->disassembly : "";
	// QBDI/capstone 反汇编带前导空格，剥掉让引号内紧跟汇编（"stp ..." 而非 "    stp ..."）
	{
		size_t start = ci.disasm.find_first_not_of(" \t");
		if (start != std::string::npos && start > 0) {
			ci.disasm = ci.disasm.substr(start);
		}
	}
	// capstone 反汇编 mnemonic 与操作数之间恒有一个 tab，会把 TSV 列拆碎（有/无操作数 → 7/8 列）。
	// find 找到即替换（tab 在 mnemonic 后第 3-5 个字符，提前退出，免整串扫描），
	// 配合输出端双引号，整条汇编恒为一个字段，列数稳定为 7。
	size_t tab = ci.disasm.find('\t');
	if (tab != std::string::npos) {
		ci.disasm[tab] = ' ';
	}
	ci.memBase = 0;
	ci.haveMemBase = false;

	for (uint8_t i = 0; i < inst->numOperands; i++) {
		const QBDI::OperandAnalysis &op = inst->operands[i];
		if (op.type != QBDI::OPERAND_GPR && op.type != QBDI::OPERAND_FPR && op.type != QBDI::OPERAND_SEG) {
			continue;
		}
		if (op.regCtxIdx < 0) {
			continue;
		}

		RegRef ref;
		ref.name = op.regName ? op.regName : "";
		ref.type = op.type;
		ref.regCtxIdx = op.regCtxIdx;
		ref.size = op.size;

		// rw.log 基址分解：取第一个 ADDR 标志操作数的 PRE 值（不截断）
		if (!ci.haveMemBase && (op.flag & QBDI::OPERANDFLAG_ADDR)) {
			ci.memBase = reg_ref_value(gpr, fpr, ref, false);
			ci.haveMemBase = true;
		}

		if (op.regAccess & QBDI::REGISTER_READ) {
			bool dup = false;
			for (const auto &r : ci.reads) {
				if (r.regCtxIdx == op.regCtxIdx && r.type == op.type) {
					dup = true;
					break;
				}
			}
			if (!dup) {
				RegVal rv;
				rv.name = ref.name;
				rv.type = ref.type;
				rv.regCtxIdx = ref.regCtxIdx;
				rv.value = reg_ref_value(gpr, fpr, ref, true);
				ci.reads.push_back(rv);
			}
		}
		if (op.regAccess & QBDI::REGISTER_WRITE) {
			bool dup = false;
			for (const auto &r : ci.writes) {
				if (r.regCtxIdx == op.regCtxIdx && r.type == op.type) {
					dup = true;
					break;
				}
			}
			if (!dup) {
				ci.writes.push_back(ref);
			}
		}
	}

	// 记录当前指令行号：紧随其后的 transfer 事件（bl/blr）用它当 bl.log 索引
	ts->currentLine = ci.lineNum;
	ts->cache[inst->address] = std::move(ci);
	return QBDI::CONTINUE;
}

// POSTINST：写 code.log 一行 + 本指令的内存访问写 rw.log
static QBDI::VMAction trace_postinst(QBDI::VMInstanceRef vm, QBDI::GPRState *gpr, QBDI::FPRState *fpr, void *data)
{
	TraceSession *ts = static_cast<TraceSession *>(data);
	const QBDI::InstAnalysis *inst = vm->getInstAnalysis(QBDI::ANALYSIS_INSTRUCTION);
	if (inst == nullptr) {
		return QBDI::CONTINUE;
	}

	auto it = ts->cache.find(inst->address);
	if (it == ts->cache.end()) {
		return QBDI::CONTINUE;
	}
	CachedInst ci = std::move(it->second);
	ts->cache.erase(it);

	// ---- code.log（TSV 7 列，见 docs/TraceFormat.md）----
	// reads/writes 是 JSON 对象列；addr/offset/insn/reads/writes 补最小宽度空格，
	// cat/less 直接对齐（超长溢出只破该行视觉，tab 仍在，结构不坏）。
	char reads_json[512];
	Buf rb(reads_json, sizeof(reads_json));
	append_reg_json(rb, ci.reads);
	reads_json[rb.len] = '\0';

	char writes_json[512];
	Buf wb(writes_json, sizeof(writes_json));
	append_reg_json(wb, ci.writes, gpr, fpr);
	writes_json[wb.len] = '\0';

	// 第 7 列 note：恒为 JSON 对象（无注解时 {}，svc 行是 syscall 记录）
	std::string note = "{}";
	auto sIt = ts->syscallNotes.find(inst->address);
	if (sIt != ts->syscallNotes.end()) {
		note = std::move(sIt->second);
		ts->syscallNotes.erase(sIt);
	}

	// 汇编套双引号：整条恒为一个字段；引号由格式串直接产出，不另建 string（热路径免堆分配）
	char raw_line[2048];
	Buf line(raw_line, sizeof(raw_line));
	line.appendf("%llx\t0x%-12llx\t0x%-8llx\t\"%s\"\t%-28s\t%-28s\t%s",
		(unsigned long long)ci.lineNum,
		(unsigned long long)inst->address,
		(unsigned long long)ci.offset,
		ci.disasm.c_str(),
		reads_json,
		writes_json,
		note.c_str());
	raw_line[line.len] = '\0';
	raw_logger_write_cached(g_raw_logger, raw_line, line.len);
	raw_logger_write_cached(g_raw_logger, "\n", 1);

	// ---- rw.log ----
	std::vector<QBDI::MemoryAccess> accesses = vm->getInstMemoryAccess();
	for (const auto &a : accesses) {
		uint64_t addr = a.accessAddress & 0xFFFFFFFFFFFFULL;
		const char *rw = (a.type == QBDI::MEMORY_READ) ? "r" : "w";

		// 基址分解：base 取地址操作数 PRE 值，diff = 访问地址 - base
		uint64_t base = ci.haveMemBase ? ci.memBase : 0;
		if (base == 0) {
			base = addr;
		}
		int64_t diff = (int64_t)addr - (int64_t)base;

		char a_raw[160];
		Buf aline(a_raw, sizeof(a_raw));
		// rw.log 索引行（TSV：line \t r/w \t base±offset），后面跟 hexdump
		if (diff >= 0) {
			aline.appendf("%llx\t%s\t0x%llx+0x%llx",
				(unsigned long long)ci.lineNum,
				rw,
				(unsigned long long)base,
				(unsigned long long)diff);
		} else {
			aline.appendf("%llx\t%s\t0x%llx-0x%llx",
				(unsigned long long)ci.lineNum,
				rw,
				(unsigned long long)base,
				(unsigned long long)(-diff));
		}
		a_raw[aline.len] = '\0';
		raw_logger_write_cached(g_rw_logger, a_raw, aline.len);
		raw_logger_write_cached(g_rw_logger, "\n", 1);
		write_hexdump(g_rw_logger, addr);
	}

	raw_logger_check_and_flush(ci.lineNum);
	return QBDI::CONTINUE;
}

// EXEC_TRANSFER_CALL：外部函数调用 → bl.log
// 注意：AArch64 下调用目标在 gpr->pc（老代码用 lr 是坑）
static QBDI::VMAction trace_transfer_call(QBDI::VMInstanceRef vm,
	const QBDI::VMState *vmState,
	QBDI::GPRState *gpr,
	QBDI::FPRState *fpr,
	void *data)
{
	(void)vm;
	(void)fpr;
	TraceSession *ts = static_cast<TraceSession *>(data);

	uint64_t target = gpr->pc;
	if (target == 0) {
		target = vmState->basicBlockStart;
	}

	// 符号解析
	Dl_info info;
	memset(&info, 0, sizeof(info));
	dladdr((void *)(uintptr_t)target, &info);

	char name[256];
	if (info.dli_sname != nullptr) {
		snprintf(name, sizeof(name), "%s", info.dli_sname);
	} else if (info.dli_fbase != nullptr) {
		std::string mod = info.dli_fname ? getFilename(info.dli_fname) : "unknown";
		snprintf(name,
			sizeof(name),
			"%s!0x%llx",
			mod.c_str(),
			(unsigned long long)(target - (uint64_t)(uintptr_t)info.dli_fbase));
	} else {
		snprintf(name, sizeof(name), "0x%llx", (unsigned long long)target);
	}

	char b_raw[512];
	Buf bline(b_raw, sizeof(b_raw));
	// bl.log 索引行（TSV：line \t target \t symbol），后面跟 hexdump
	bline.appendf("%llx\t0x%llx\t%s",
		(unsigned long long)ts->currentLine,
		(unsigned long long)target,
		name);
	b_raw[bline.len] = '\0';
	raw_logger_write_cached(g_bl_logger, b_raw, bline.len);
	raw_logger_write_cached(g_bl_logger, "\n", 1);
	write_hexdump(g_bl_logger, target);
	return QBDI::CONTINUE;
}

// ============================================================================
// Syscall 名字表（AArch64 Android，来自 NDK asm/unistd_64.h）
// ============================================================================

struct SyscallName
{
	unsigned int nr;
	const char *name;
};

static const SyscallName kSyscallNames[] = {
#include "syscall_names.inc"
};

// 按号码二分查找；找不到返回 nullptr
static const char *syscall_name(unsigned int nr)
{
	const int n = (int)(sizeof(kSyscallNames) / sizeof(kSyscallNames[0]));
	int lo = 0, hi = n - 1;
	while (lo <= hi) {
		int mid = (lo + hi) / 2;
		if (kSyscallNames[mid].nr == nr) {
			return kSyscallNames[mid].name;
		}
		if (kSyscallNames[mid].nr < nr) {
			lo = mid + 1;
		} else {
			hi = mid - 1;
		}
	}
	return nullptr;
}

// SVC 兜底回调：QBDI 无法执行 SVC，注册 mnemonic 回调后指令会原生执行。
// 这里在 PREINST（寄存器还是 syscall 入参状态）读 x8(号码)+x0-x5(参数)，
// 生成注解串挂到 syscallNotes，POSTINST 写 code.log 行尾时附上。
static QBDI::VMAction trace_svc(QBDI::VMInstanceRef vm, QBDI::GPRState *gpr, QBDI::FPRState *fpr, void *data)
{
	(void)fpr;
	TraceSession *ts = static_cast<TraceSession *>(data);
	const QBDI::InstAnalysis *inst = vm->getInstAnalysis(QBDI::ANALYSIS_INSTRUCTION);
	if (inst == nullptr) {
		return QBDI::CONTINUE;
	}

	unsigned int nr = (unsigned int)(gpr->x8 & 0xFFFFFFFF);
	const char *name = syscall_name(nr);

	// 生成 JSON 注解：{"syscall":"read","args":["0x1","0x7fd2dd3370",...]}
	// args 用十六进制字符串保 0x（JSON 数字不允许 0x 前缀），int(x,16) 取回数值
	char s_raw[256];
	Buf s(s_raw, sizeof(s_raw));
	if (name != nullptr) {
		s.appendf("{\"syscall\":\"%s\",\"args\":[\"0x%llx\",\"0x%llx\",\"0x%llx\",\"0x%llx\",\"0x%llx\",\"0x%llx\"]}",
			name,
			(unsigned long long)gpr->x0,
			(unsigned long long)gpr->x1,
			(unsigned long long)gpr->x2,
			(unsigned long long)gpr->x3,
			(unsigned long long)gpr->x4,
			(unsigned long long)gpr->x5);
	} else {
		s.appendf("{\"syscall\":\"syscall_%u\",\"args\":[\"0x%llx\",\"0x%llx\",\"0x%llx\",\"0x%llx\",\"0x%llx\",\"0x%llx\"]}",
			nr,
			(unsigned long long)gpr->x0,
			(unsigned long long)gpr->x1,
			(unsigned long long)gpr->x2,
			(unsigned long long)gpr->x3,
			(unsigned long long)gpr->x4,
			(unsigned long long)gpr->x5);
	}
	s_raw[s.len] = '\0';
	ts->syscallNotes[inst->address] = s_raw;
	return QBDI::CONTINUE;
}

// ============================================================================
// QBDI 嵌套执行核心
// ============================================================================

// 串行化 trace 会话：同一时刻只允许一个嵌套 VM 在跑。
// recursive：run_trace_on_big_stack 切栈前先锁（防多线程并发切到同一个共享
// 专用栈互相踩踏），executeWithQBDI 里还会再锁一次，故需要可重入。
static std::recursive_mutex g_exec_mutex;

// 用 QBDI 从 target 执行到 lr，输入/输出状态都通过 gpr/fpr 进出。
// 返回函数返回值（x0）。
static uint64_t executeWithQBDI(void *targetAddress, QBDI::GPRState *gpr, QBDI::FPRState *fpr)
{
	std::lock_guard<std::recursive_mutex> lock(g_exec_mutex);
	ensure_loggers();

	Dl_info info;
	memset(&info, 0, sizeof(info));
	dladdr(targetAddress, &info);

	TraceSession ts;
	ts.baseAddr = (uint64_t)(uintptr_t)info.dli_fbase;
	ts.moduleName = info.dli_fname ? getFilename(info.dli_fname) : "unknown";
	ts.currentLine = 0;

	if (ts.baseAddr != 0) {
		LOGI("QBDI trace: %s+0x%llx",
			ts.moduleName.c_str(),
			(unsigned long long)((uint64_t)(uintptr_t)targetAddress - ts.baseAddr));
	} else {
		LOGI("QBDI trace: %p (module unknown)", targetAddress);
	}

	QBDI::VM *vm = new QBDI::VM();
	QBDI::GPRState *vmGpr = vm->getGPRState();
	QBDI::FPRState *vmFpr = vm->getFPRState();
	if (gpr != nullptr) {
		memcpy(vmGpr, gpr, sizeof(QBDI::GPRState));
	}
	if (fpr != nullptr) {
		memcpy(vmFpr, fpr, sizeof(QBDI::FPRState));
	}
	// 专用 VM 栈：目标函数 + InstCallback 在独立大栈上执行，
	// 避免目标函数执行把调用方栈（可能已近耗尽）顶穿 guard page。
	uint8_t *vmStack = nullptr;
	uint64_t origSp = (gpr != nullptr) ? gpr->sp : 0;
	if (gpr != nullptr) {
		QBDI::allocateVirtualStack(vmGpr, kTraceStackSize, &vmStack);
	}
	vmGpr->pc = (QBDI::rword)(uintptr_t)targetAddress;
	vm->setGPRState(vmGpr);
	vm->setFPRState(vmFpr);

	vm->clearAllCache();
	if (!vm->addInstrumentedModuleFromAddr((QBDI::rword)(uintptr_t)targetAddress)) {
		LOGE("addInstrumentedModuleFromAddr failed, trace may be empty");
	}

	// 记录范围：默认整模块执行流（范围广）；设了 FUNCTION_SIZE 就只记
	// [函数入口, 入口+size) 内的指令，同模块其他函数不再展开
	if (g_trace_range_size != 0) {
		QBDI::rword rs = (QBDI::rword)(uintptr_t)targetAddress;
		QBDI::rword re = rs + g_trace_range_size;
		vm->addCodeRangeCB(rs, re, QBDI::PREINST, trace_preinst, &ts, QBDI::PRIORITY_DEFAULT);
		vm->addCodeRangeCB(rs, re, QBDI::POSTINST, trace_postinst, &ts, QBDI::PRIORITY_DEFAULT);
	} else {
		vm->addCodeCB(QBDI::PREINST, trace_preinst, &ts, QBDI::PRIORITY_DEFAULT);
		vm->addCodeCB(QBDI::POSTINST, trace_postinst, &ts, QBDI::PRIORITY_DEFAULT);
	}
	vm->addVMEventCB(QBDI::EXEC_TRANSFER_CALL, trace_transfer_call, &ts);
	vm->addMnemonicCB("SVC", QBDI::PREINST, trace_svc, &ts, QBDI::PRIORITY_DEFAULT);
	vm->recordMemoryAccess(QBDI::MEMORY_READ_WRITE);

	// ---- 开始标记 ----
	write_trace_marker("=== Trace Start: %s+0x%llx%s ===",
		ts.moduleName.c_str(),
		(unsigned long long)((uint64_t)(uintptr_t)targetAddress - ts.baseAddr),
		g_trace_range_size ? "" : " (full module)");
	LOGI("=== Trace Start: %s+0x%llx%s ===",
		ts.moduleName.c_str(),
		(unsigned long long)((uint64_t)(uintptr_t)targetAddress - ts.baseAddr),
		g_trace_range_size ? "" : " (full module)");

	// 从函数入口跑到返回地址（lr）；lr 处不执行，QBDI 在此停机
	uint64_t stop = (gpr != nullptr) ? gpr->lr : 0;
	bool ok = vm->run((QBDI::rword)(uintptr_t)targetAddress, (QBDI::rword)stop);
	if (!ok) {
		// run 返回 false：可能目标函数提前异常/SVC 未处理，不阻塞，照常取 x0
		LOGE("QBDI run stopped early (ok=false)");
	}

	vmGpr = vm->getGPRState();
	uint64_t ret = vmGpr->x0;

	// ---- 结束标记 + 返回值 ----
	write_trace_marker("=== Trace End, return 0x%llx%s ===", (unsigned long long)ret, ok ? "" : " (stopped early)");
	LOGI("=== Trace End, return 0x%llx%s ===", (unsigned long long)ret, ok ? "" : " (stopped early)");

	// 把最终状态写回调用方（Frida 上下文 / vmtrace_call 用）
	if (gpr != nullptr) {
		memcpy(gpr, vmGpr, sizeof(QBDI::GPRState));
		// VM 在独立大栈上执行，最终 sp 是新栈顶，恢复调用方 sp
		gpr->sp = origSp;
	}
	if (fpr != nullptr) {
		memcpy(fpr, vm->getFPRState(), sizeof(QBDI::FPRState));
	}
	if (vmStack != nullptr) {
		QBDI::alignedFree(vmStack);
	}

	delete vm;
	raw_logger_flush_all();
	return ret;
}

// ============================================================================
// 专用大栈
//
// 真机实测：被 hook 函数被调用时，app 线程栈往往已近耗尽（hook 点处仅剩
// ~0x60-0x110 字节余量）。trace 机制本身的栈帧（executeWithQBDI + 回调 +
// QBDI 执行目标函数）会把 app 栈顶穿 guard page → SIGSEGV。
// 因此：
//   1. 用 trace_run_on_stack 把整个 trace worker 切到 8MB 专用栈上跑
//      （保护 trace 机制自身的 C++ 栈帧）
//   2. 用 QBDI::qbdi_allocateVirtualStack 给 VM 执行再分配一块独立大栈
//      （保护目标函数 + InstCallback 的执行栈）
// ============================================================================

static void *g_trace_stack = nullptr;
static uint64_t g_trace_stack_top = 0;
static std::once_flag g_trace_stack_once;

static void init_trace_stack()
{
	void *p = mmap(nullptr, kTraceStackSize, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (p != MAP_FAILED) {
		g_trace_stack = p;
		g_trace_stack_top = (uint64_t)(uintptr_t)p + kTraceStackSize;
	} else {
		g_trace_stack = nullptr;
		g_trace_stack_top = 0;
	}
}

static uint64_t ensure_trace_stack_top()
{
	std::call_once(g_trace_stack_once, init_trace_stack);
	return g_trace_stack_top;
}

// 在专用栈上运行 worker(arg)，返回 worker 的返回值（AArch64）。
// 调用约定：worker 为 `uint64_t (*)(void*)`，参数走 x0。
// 汇编流程：保存旧 sp/lr → 切到 stackTop → 压 lr/旧sp/worker/arg →
//           调 worker(arg) → 结果放 x1 → 弹栈恢复 → 切回旧栈 → ret。
extern "C" uint64_t trace_run_on_stack(void *worker, void *arg, uint64_t stackTop);

__asm__(".text\n"
	".align 4\n"
	".global trace_run_on_stack\n"
	".type trace_run_on_stack, %function\n"
	"trace_run_on_stack:\n"
	"  mov  x9, sp\n" // x9 = 旧 sp
	"  mov  x8, x30\n" // x8 = 返回地址 lr
	"  mov  sp, x2\n" // 切到专用栈
	"  stp  x8, x9, [sp, #-16]!\n" // 压 [lr, 旧sp]
	"  stp  x0, x1, [sp, #-16]!\n" // 压 [worker, arg]
	"  ldr  x0, [sp, #8]\n" // x0 = arg
	"  ldr  x8, [sp, #0]\n" // x8 = worker
	"  blr  x8\n" // worker(arg)
	"  str  x0, [sp, #8]\n" // 结果暂存到 arg 槽
	"  ldp  x0, x1, [sp], #16\n" // x1 = 结果
	"  ldp  x8, x9, [sp], #16\n" // x8 = lr, x9 = 旧sp
	"  mov  x0, x1\n" // x0 = 结果
	"  mov  sp, x9\n" // 切回旧栈
	"  mov  x30, x8\n" // 恢复返回地址
	"  ret\n"
	".size trace_run_on_stack, .-trace_run_on_stack\n");

// ============================================================================
// Frida Gum 集成
// ============================================================================

struct HookContext
{
	void *targetAddress;
	GumInterceptor *interceptor;
	std::string logTag;
	bool useQBDI;
	bool traceOnce;
};

static std::mutex g_hooks_mutex;
static std::unordered_map<void *, HookContext *> g_hooks;
static GumInterceptor *g_interceptor = nullptr;
static bool g_gum_initialized = false;

static void ensure_gum_initialized()
{
	if (!g_gum_initialized) {
		gum_init_embedded();
		g_interceptor = gum_interceptor_obtain();
		g_gum_initialized = true;
	}
}

// GumCpuContext -> QBDI GPR/FPR
static void convert_gum_to_qbdi(const GumCpuContext *ctx, QBDI::GPRState *gpr, QBDI::FPRState *fpr)
{
	if (ctx == nullptr || gpr == nullptr) {
		return;
	}
	for (int i = 0; i < 29; i++) { // x0..x28
		QBDI_GPR_SET(gpr, i, ctx->x[i]);
	}
	gpr->x29 = ctx->fp;
	gpr->lr = ctx->lr;
	gpr->sp = ctx->sp;
	gpr->pc = ctx->pc;
	gpr->nzcv = ctx->nzcv;
	if (fpr != nullptr) {
		memcpy(&fpr->v0, ctx->v[0].q, 32 * 16);
	}
}

// QBDI GPR/FPR -> GumCpuContext
static void convert_qbdi_to_gum(const QBDI::GPRState *gpr, const QBDI::FPRState *fpr, GumCpuContext *ctx)
{
	if (ctx == nullptr || gpr == nullptr) {
		return;
	}
	for (int i = 0; i < 29; i++) {
		ctx->x[i] = QBDI_GPR_GET(gpr, i);
	}
	ctx->fp = gpr->x29;
	ctx->lr = gpr->lr;
	ctx->sp = gpr->sp;
	ctx->pc = gpr->pc;
	ctx->nzcv = gpr->nzcv;
	if (fpr != nullptr) {
		memcpy(ctx->v[0].q, &fpr->v0, 32 * 16);
	}
}

// 从 GumCpuContext 启动 QBDI 追踪；返回 x0
static uint64_t execute_with_qbdi_from_gum(void *target, const GumCpuContext *inCtx, GumCpuContext *outCtx)
{
	QBDI::GPRState gpr;
	QBDI::FPRState fpr;
	memset(&gpr, 0, sizeof(gpr));
	memset(&fpr, 0, sizeof(fpr));
	convert_gum_to_qbdi(inCtx, &gpr, &fpr);
	uint64_t ret = executeWithQBDI(target, &gpr, &fpr);
	convert_qbdi_to_gum(&gpr, &fpr, outCtx);
	return ret;
}

// 大栈 worker 参数
struct TraceRunCtx
{
	void *target;
	const GumCpuContext *inCtx;
	GumCpuContext *outCtx;
};

static uint64_t trace_worker(void *rawArg)
{
	TraceRunCtx *c = static_cast<TraceRunCtx *>(rawArg);
	return execute_with_qbdi_from_gum(c->target, c->inCtx, c->outCtx);
}

// 在专用大栈上跑 trace worker（大栈分配失败时退回当前栈直接跑）。
// 必须先拿 g_exec_mutex 再切栈：专用栈是单块全局 mmap，若并发触发的多个线程
// 都在拿锁之前切到同一个 stackTop，后到线程的 trace_run_on_stack 槽位会覆盖
// 正在执行线程的槽位，执行完的线程会从错误地址返回（直接崩）。锁在切栈前获取，
// 抢锁失败的线程阻塞在调用方自己的栈上，不会进专用栈。
static uint64_t run_trace_on_big_stack(const TraceRunCtx &c)
{
	std::lock_guard<std::recursive_mutex> lock(g_exec_mutex);
	uint64_t stackTop = ensure_trace_stack_top();
	if (stackTop != 0) {
		// 函数指针转 void*：POSIX 上实现定义但可用
		void *worker = reinterpret_cast<void *>(reinterpret_cast<uintptr_t>(trace_worker));
		return trace_run_on_stack(worker, (void *)(uintptr_t)&c, stackTop);
	}
	return trace_worker((void *)(uintptr_t)&c);
}

// ============================================================================
// GumInvocationListener（attach 模式）
// ============================================================================

typedef struct _VMTraceListener VMTraceListener;
typedef struct _VMTraceListenerClass VMTraceListenerClass;

struct _VMTraceListener
{
	GObject parent;
	HookContext *hookCtx;
};

struct _VMTraceListenerClass
{
	GObjectClass parent_class;
};

static void vmtrace_listener_iface_init(gpointer g_iface, gpointer iface_data);

G_DEFINE_TYPE_EXTENDED(VMTraceListener,
	vmtrace_listener,
	G_TYPE_OBJECT,
	0,
	G_IMPLEMENT_INTERFACE(GUM_TYPE_INVOCATION_LISTENER, vmtrace_listener_iface_init))

static void vmtrace_listener_on_enter(GumInvocationListener *listener, GumInvocationContext *context)
{
	VMTraceListener *self = (VMTraceListener *)listener;
	HookContext *hookCtx = self->hookCtx;
	if (hookCtx == nullptr) {
		return;
	}

	GumCpuContext original = *context->cpu_context; // 保存进入时上下文

	LOGI("hook enter %p", hookCtx->targetAddress);
	LOGI("  x0=0x%llx x1=0x%llx x2=0x%llx x3=0x%llx",
		(unsigned long long)original.x[0],
		(unsigned long long)original.x[1],
		(unsigned long long)original.x[2],
		(unsigned long long)original.x[3]);

	if (hookCtx->traceOnce) {
		gum_interceptor_detach(hookCtx->interceptor, listener);
		gum_interceptor_flush(hookCtx->interceptor);
		LOGI("hook detached (trace once)");
	}

	if (hookCtx->useQBDI) {
		TraceRunCtx rc = { hookCtx->targetAddress, &original, context->cpu_context };
		uint64_t result = run_trace_on_big_stack(rc);

		// 原生函数还会继续执行：恢复进入时上下文，避免 QBDI 运行污染参数
		//（否则原生执行会用被改坏的 x0-x3，副作用和返回值都会错）
		*context->cpu_context = original;

		// 结果在 on_leave 替换返回值
		gpointer invData = gum_invocation_context_get_listener_invocation_data(context, sizeof(uint64_t));
		if (invData != nullptr) {
			*(uint64_t *)invData = result;
		}
	}
}

static void vmtrace_listener_on_leave(GumInvocationListener *listener, GumInvocationContext *context)
{
	VMTraceListener *self = (VMTraceListener *)listener;
	HookContext *hookCtx = self->hookCtx;
	if (hookCtx == nullptr || !hookCtx->useQBDI) {
		return;
	}
	gpointer invData = gum_invocation_context_get_listener_invocation_data(context, sizeof(uint64_t));
	if (invData != nullptr) {
		uint64_t result = *(uint64_t *)invData;
		gum_invocation_context_replace_return_value(context, (gpointer)(uintptr_t)result);
		LOGI("hook leave, return 0x%llx", (unsigned long long)result);
	}
}

static void vmtrace_listener_class_init(VMTraceListenerClass *klass)
{
	(void)klass;
}

static void vmtrace_listener_init(VMTraceListener *self)
{
	self->hookCtx = nullptr;
}

static void vmtrace_listener_iface_init(gpointer g_iface, gpointer iface_data)
{
	(void)iface_data;
	GumInvocationListenerInterface *iface = (GumInvocationListenerInterface *)g_iface;
	iface->on_enter = vmtrace_listener_on_enter;
	iface->on_leave = vmtrace_listener_on_leave;
}

static VMTraceListener *vmtrace_listener_new(HookContext *hookCtx)
{
	VMTraceListener *listener = (VMTraceListener *)g_object_new(vmtrace_listener_get_type(), NULL);
	listener->hookCtx = hookCtx;
	return listener;
}

// ============================================================================
// Replacement（replace 模式）
// ============================================================================

// 完全替换原函数：只跑一份 QBDI，原生不重复执行，副作用只有一份
static void replacement_function(GumInvocationContext *context, gpointer user_data)
{
	(void)context;
	(void)user_data;
	GumInvocationContext *ic = gum_interceptor_get_current_invocation();
	if (ic == nullptr) {
		return;
	}
	HookContext *hookCtx = (HookContext *)gum_invocation_context_get_replacement_data(ic);
	if (hookCtx == nullptr) {
		return;
	}
	GumCpuContext *cpuCtx = ic->cpu_context;

	LOGI("replace %p", hookCtx->targetAddress);

	if (hookCtx->traceOnce) {
		gum_interceptor_revert(hookCtx->interceptor, hookCtx->targetAddress);
		gum_interceptor_flush(hookCtx->interceptor);
		LOGI("revert (trace once)");
	}

	if (hookCtx->useQBDI) {
		TraceRunCtx rc = { hookCtx->targetAddress, cpuCtx, cpuCtx };
		uint64_t result = run_trace_on_big_stack(rc);
		cpuCtx->x[0] = result;
		LOGI("replace return 0x%llx", (unsigned long long)result);
	}
}

// ============================================================================
// 公开 API
// ============================================================================

static HookContext *make_hook_context(void *targetAddress, const char *logTag, int useQBDI, int traceOnce)
{
	HookContext *hookCtx = new HookContext();
	hookCtx->targetAddress = targetAddress;
	hookCtx->interceptor = g_interceptor;
	hookCtx->logTag = logTag ? logTag : "trace";
	hookCtx->useQBDI = (useQBDI != 0);
	hookCtx->traceOnce = (traceOnce != 0);
	return hookCtx;
}

int vmtrace_hook_attach(void *targetAddress, const char *logTag, int useQBDI, int traceOnce)
{
	if (targetAddress == nullptr) {
		LOGE("vmtrace_hook_attach: null target");
		return -1;
	}
	ensure_gum_initialized();

	HookContext *hookCtx = make_hook_context(targetAddress, logTag, useQBDI, traceOnce);
	VMTraceListener *listener = vmtrace_listener_new(hookCtx);

	gum_interceptor_begin_transaction(g_interceptor);
	GumAttachReturn ret = gum_interceptor_attach(g_interceptor,
		targetAddress,
		GUM_INVOCATION_LISTENER(listener),
		nullptr);
	gum_interceptor_end_transaction(g_interceptor);

	if (ret != GUM_ATTACH_OK) {
		LOGE("attach failed at %p (%d)", targetAddress, ret);
		g_object_unref(listener);
		delete hookCtx;
		return -1;
	}

	{
		std::lock_guard<std::mutex> lock(g_hooks_mutex);
		g_hooks[targetAddress] = hookCtx;
	}
	LOGI("hook attach %p qbdi=%d traceOnce=%d", targetAddress, useQBDI, traceOnce);
	return 0;
}

int vmtrace_hook_replace(void *targetAddress, const char *logTag, int useQBDI, int traceOnce)
{
	if (targetAddress == nullptr) {
		LOGE("vmtrace_hook_replace: null target");
		return -1;
	}
	ensure_gum_initialized();

	HookContext *hookCtx = make_hook_context(targetAddress, logTag, useQBDI, traceOnce);

	gum_interceptor_begin_transaction(g_interceptor);
	GumReplaceReturn ret = gum_interceptor_replace(g_interceptor,
		targetAddress,
		(gpointer)replacement_function,
		hookCtx,
		nullptr);
	gum_interceptor_end_transaction(g_interceptor);

	if (ret != GUM_REPLACE_OK) {
		LOGE("replace failed at %p (%d)", targetAddress, ret);
		delete hookCtx;
		return -1;
	}

	{
		std::lock_guard<std::mutex> lock(g_hooks_mutex);
		g_hooks[targetAddress] = hookCtx;
	}
	LOGI("hook replace %p qbdi=%d traceOnce=%d", targetAddress, useQBDI, traceOnce);
	return 0;
}

int vmtrace_unhook(void *targetAddress)
{
	if (targetAddress == nullptr || g_interceptor == nullptr) {
		return -1;
	}
	HookContext *hookCtx = nullptr;
	{
		std::lock_guard<std::mutex> lock(g_hooks_mutex);
		auto it = g_hooks.find(targetAddress);
		if (it != g_hooks.end()) {
			hookCtx = it->second;
			g_hooks.erase(it);
		}
	}
	if (hookCtx == nullptr) {
		return -1;
	}
	gum_interceptor_revert(g_interceptor, targetAddress);
	gum_interceptor_flush(g_interceptor);
	delete hookCtx;
	LOGI("hook removed %p", targetAddress);
	return 0;
}

void vmtrace_unhook_all(void)
{
	if (g_interceptor == nullptr) {
		return;
	}
	std::vector<void *> addrs;
	{
		std::lock_guard<std::mutex> lock(g_hooks_mutex);
		for (auto &kv : g_hooks) {
			addrs.push_back(kv.first);
		}
	}
	for (void *a : addrs) {
		vmtrace_unhook(a);
	}
}

int vmtrace_hook_by_name(const char *moduleName,
	const char *functionName,
	const char *logTag,
	int useQBDI,
	int traceOnce)
{
	if (moduleName == nullptr || functionName == nullptr) {
		return -1;
	}
	void *handle = dlopen(moduleName, RTLD_NOW | RTLD_NOLOAD);
	if (handle == nullptr) {
		handle = dlopen(moduleName, RTLD_NOW);
	}
	if (handle == nullptr) {
		LOGE("dlopen %s failed: %s", moduleName, dlerror());
		return -1;
	}
	void *func = dlsym(handle, functionName);
	dlclose(handle);
	if (func == nullptr) {
		LOGE("dlsym %s!%s failed", moduleName, functionName);
		return -1;
	}
	return vmtrace_hook_attach(func, logTag, useQBDI, traceOnce);
}

int vmtrace_hook_by_offset(const char *moduleName, uint64_t offset, const char *logTag, int useQBDI, int traceOnce)
{
	if (moduleName == nullptr) {
		return -1;
	}
	void *handle = dlopen(moduleName, RTLD_NOW | RTLD_NOLOAD);
	if (handle == nullptr) {
		handle = dlopen(moduleName, RTLD_NOW);
	}
	if (handle == nullptr) {
		LOGE("dlopen %s failed: %s", moduleName, dlerror());
		return -1;
	}
	Dl_info info;
	memset(&info, 0, sizeof(info));
	if (!dladdr(handle, &info) || info.dli_fbase == nullptr) {
		dlclose(handle);
		LOGE("dladdr %s failed", moduleName);
		return -1;
	}
	void *func = (void *)((uint64_t)(uintptr_t)info.dli_fbase + offset);
	dlclose(handle);
	return vmtrace_hook_attach(func, logTag, useQBDI, traceOnce);
}

int64_t vmtrace_call(void *targetAddress, int64_t args, int argNum, const char *logTag)
{
	(void)logTag;
	if (targetAddress == nullptr) {
		return 0;
	}
	ensure_gum_initialized();

	QBDI::GPRState gpr;
	QBDI::FPRState fpr;
	memset(&gpr, 0, sizeof(gpr));
	memset(&fpr, 0, sizeof(fpr));

	uint64_t *argArray = (uint64_t *)(uintptr_t)args;
	if (argArray != nullptr && argNum > 0) {
		for (int i = 0; i < argNum && i < 8; i++) {
			QBDI_GPR_SET(&gpr, i, argArray[i]);
		}
	}

	// 分配一块干净栈，LR = 0 让 QBDI 在函数 ret 时停机
	const size_t stackSize = 1024 * 1024;
	void *stack = malloc(stackSize);
	if (stack == nullptr) {
		return 0;
	}
	gpr.sp = (QBDI::rword)(uintptr_t)stack + stackSize - 0x100;
	gpr.lr = 0;

	uint64_t result = executeWithQBDI(targetAddress, &gpr, &fpr);
	free(stack);
	return (int64_t)result;
}

void vmtrace_cleanup(void)
{
	vmtrace_unhook_all();
	{
		std::lock_guard<std::mutex> lock(g_loggers_mutex);
		if (g_raw_logger != nullptr) {
			g_raw_logger->close();
		}
		if (g_rw_logger != nullptr) {
			g_rw_logger->close();
		}
		if (g_bl_logger != nullptr) {
			g_bl_logger->close();
		}
		g_loggers_inited = false;
	}
	if (g_gum_initialized) {
		if (g_interceptor != nullptr) {
			g_object_unref(g_interceptor);
			g_interceptor = nullptr;
		}
		gum_deinit_embedded();
		g_gum_initialized = false;
	}
	LOGI("trace cleanup done");
}
