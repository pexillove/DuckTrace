/*
 * mem_dump.h — 进程内存快照（面向 unidbg 回放）
 *
 * trace 只记录「执行了什么」，回放还需要「执行前内存长什么样」。本模块在
 * trace 开始（可选结束）时把这几类区段原样落盘：
 *
 *   maps       /proc/self/maps 原始快照（地址布局的唯一权威）
 *   target so  目标 so 的运行期映射（已重定位/已解密，和磁盘上的文件不同）
 *   anon r-xp  匿名可执行段（JIT / 壳解密出的 shellcode）
 *   anon rw-p  匿名可写段（堆、malloc arena、各类运行期数据）
 *   stack      栈：app 线程栈 + QBDI 虚拟栈（只 dump sp 之上的活跃部分）
 *
 * 输出布局见 docs/TraceFormat.md：
 *   trace_logs/mem/maps.txt
 *   trace_logs/mem/index.tsv
 *   trace_logs/mem/<seq>_<tag>/<start>-<end>.bin
 */

#ifndef MEM_DUMP_H
#define MEM_DUMP_H

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

// dump 类别位掩码（与 trace_impl.h 的 VMTRACE_DUMP_* 取值一致）
enum
{
	MEM_DUMP_MAPS = 0x01,
	MEM_DUMP_TARGET_SO = 0x02,
	MEM_DUMP_ANON_EXEC = 0x04,
	MEM_DUMP_ANON_RW = 0x08,
	MEM_DUMP_STACK = 0x10,
};

// 「热区」归桶粒度：trace 期间访问过的地址按这个尺寸归桶上报，dump 时命中的
// 区段优先落盘且不受单区段上限约束——VMP 的字节码和 dispatch table 必在其中
static constexpr uint64_t MEM_DUMP_HOT_BUCKET = 1ULL << 20;

// /proc/self/maps 的一行
struct MapRegion
{
	uint64_t start;
	uint64_t end;
	char prot[8]; // "rwxp"
	uint64_t fileOff;
	std::string path; // 可能为空 / "[stack]" / "[anon:libc_malloc]" / 文件路径

	bool readable() const
	{
		return prot[0] == 'r';
	}
	bool writable() const
	{
		return prot[1] == 'w';
	}
	bool exec() const
	{
		return prot[2] == 'x';
	}
	// 匿名：无路径，或内核/bionic 给的 [xxx] 命名（[stack]、[anon:.bss]、[anon:scudo:...]）
	bool anon() const
	{
		return path.empty() || path[0] == '[';
	}
	uint64_t size() const
	{
		return end - start;
	}
	bool contains(uint64_t addr) const
	{
		return addr >= start && addr < end;
	}
};

// 解析 /proc/self/maps；raw 非空时顺带返回原始文本
bool mem_read_maps(std::vector<MapRegion> &out, std::string *raw);

// 一次 dump 的输入
struct MemDumpRequest
{
	int flags = 0; // MEM_DUMP_* 位掩码
	uint64_t moduleBase = 0; // 目标 so 基址，0 = 不做 so 专项 dump
	std::string modulePath; // 目标 so 路径（dli_fname），可空
	std::vector<uint64_t> stacks; // 要覆盖的栈指针（app sp / QBDI 虚拟栈 sp）
	std::vector<uint64_t> hotPages; // trace 期间访问过的地址（MEM_DUMP_HOT_BUCKET 对齐）
	std::vector<std::pair<uint64_t, uint64_t>> excludes; // [start,end) 整段跳过（trace 自身的脚手架内存）
	std::string tag; // 本次 dump 的标签："start" / "end" / 自定义
	uint64_t line = 0; // dump 时的 trace 行号（关联 code.log）
};

// 执行一次 dump，输出到 <outDir>/mem/。返回成功落盘的区段数，失败返回负值。
int mem_dump_run(const std::string &outDir, const MemDumpRequest &req);

// 上限（字节）。perRegion：单区段超过就整段跳过（不截断，避免回放读到半截数据）；
// total：单次 dump 的总预算。0 = 不限。
// 目标 so 段和 hotPages 命中的区段不受 perRegion 限制，且优先占用 total 预算。
void mem_dump_set_limits(uint64_t perRegion, uint64_t total);

#endif // MEM_DUMP_H
