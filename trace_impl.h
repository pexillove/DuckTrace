/*
 * trace_impl.h — QBDI + Frida Gum 指令级 trace agent 导出 API
 *
 * 输出格式见 docs/TraceFormat.md（code/rw/bl.log 三文件）。
 */

#ifndef TRACE_IMPL_H
#define TRACE_IMPL_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// ============================================================================
// 输出配置
// ============================================================================

// 设置 trace 输出目录。留空 (NULL) = 默认 /data/data/<包名>/files/trace_logs
// 需在首次触发 trace 前调用，之后会重新打开三文件。
int vmtrace_set_output_dir(const char *dir);

// 限定 trace 记录范围（字节数）。默认 0 = 记录目标函数所在模块的全部执行流
// （范围很广）。设为目标函数大小后，只记录 [函数入口, 入口+size) 内的指令，
// 目标函数调用的同模块其他函数不再展开。需在 hook 前调用。
int vmtrace_set_function_size(uint64_t size);

// ============================================================================
// Hook 管理
// ============================================================================

// attach 模式：hook 目标函数，命中后嵌套 QBDI VM 追踪执行。
// useQBDI 非 0 时启用指令级 trace，traceOnce 非 0 时只追踪一次后自动 detach。
int vmtrace_hook_attach(void *targetAddress, const char *logTag, int useQBDI, int traceOnce);

// replace 模式：完全替换原函数，仅 QBDI 一份执行（无原生重复副作用）。
int vmtrace_hook_replace(void *targetAddress, const char *logTag, int useQBDI, int traceOnce);

// 移除指定地址的 hook
int vmtrace_unhook(void *targetAddress);

// 移除所有 hook
void vmtrace_unhook_all(void);

// 按模块名 + 导出函数名 hook
int vmtrace_hook_by_name(const char *moduleName,
	const char *functionName,
	const char *logTag,
	int useQBDI,
	int traceOnce);

// 按模块名 + 偏移 hook
int vmtrace_hook_by_offset(const char *moduleName, uint64_t offset, const char *logTag, int useQBDI, int traceOnce);

// ============================================================================
// 直接调用
// ============================================================================

// 使用 QBDI 追踪执行目标函数，args 为 uint64_t[] 数组指针，argNum 为参数个数
int64_t vmtrace_call(void *targetAddress, int64_t args, int argNum, const char *logTag);

// 清理所有资源（unhook + 关闭 logger）
void vmtrace_cleanup(void);

#ifdef __cplusplus
}
#endif

#endif // TRACE_IMPL_H
