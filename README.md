# QBDI Trace Agent (libtrace.so)

Frida Gum + QBDI 指令级 trace agent，输出三文件格式（`docs/TraceFormat.md`）。

## 架构

```
目标进程 (Android AArch64)
├── frida 注入
│   └── ../trace.js — 加载 libQBDI.so + libtrace.so，定位目标函数，启动 hook
└── libtrace.so
    ├── Gum interceptor hook 目标函数（attach listener 或 replace）
    ├── hook 命中 → 新建 QBDI VM，从函数入口 run 到 LR
    ├── PREINST/POSTINST → code.log（汇编 + R{读}/W{写} 寄存器）
    ├── EXEC_TRANSFER_CALL → bl.log（外部调用 + 目标 hexdump）
    └── MemoryAccess → rw.log（内存读写 + hexdump）
```

嵌套 VM 方案沿袭 `defer/qdbi_demo/vm.cpp`：只有目标函数自身的指令走 QBDI，
内部调用的外部函数由 QBDI ExecBroker 原生执行，回跳后继续插桩。

## 文件

| 文件 | 说明 |
|------|------|
| `trace_impl.{h,cpp}` | QBDI + Frida Gum 核心实现 |
| `raw_logger.{h,cpp}` | code/rw/bl 三文件 mmap 缓存写入器 |
| `syscall_names.inc` | AArch64 syscall 名字表（从 NDK `asm/unistd_64.h` 生成） |
| `build.sh` | NDK 交叉编译（主构建路径） |
| `CMakeLists.txt` | CMake 构建（可选） |

`syscall_names.inc` 重新生成（NDK 升级后）：

```bash
grep "#define __NR_" $NDK/sysroot/usr/include/aarch64-linux-android/asm/unistd_64.h \
  | sed -E 's/#define __NR_([a-z0-9_]+)[[:space:]]+([0-9]+)/  { \2, "\1" },/' \
  | sort -t'{' -k2 -n > syscall_names.inc
```

## 编译

```bash
# 默认路径（NDK、QBDI usr、frida-gum devkit 都在仓库内）
./build.sh

# 覆盖路径
NDK=/path/to/ndk QDBI_HOME=/path/to/usr ./build.sh
```

产物 `libtrace.so`（arm64，`-static-libstdc++`，动态依赖 libQBDI.so + 系统库）。

## 部署 & 使用

```bash
adb push ../usr/local/lib/libQBDI.so /data/local/tmp/
adb push libtrace.so                    /data/local/tmp/
adb push ../trace.js                    /data/local/tmp/

frida -U -f com.target.app -l /data/local/tmp/trace.js
# 触发目标函数，输出在设备 /data/data/<包名>/files/trace_logs/
adb pull /data/data/<包名>/files/trace_logs/ .
```

`trace.js` 里改 `MODULE_NAME` / `FUNCTION_OFFSET`；`FUNCTION_SIZE` 限定 trace 记录范围
（0 = 整模块执行流，否则只追 `[入口, 入口+size)`）；`TRACE_DIR` 留空用应用数据目录。
每次 trace 的三文件首尾都有标记行：

```
=== Trace Start: libtwo.so+0xc70 (full module) ===
...
=== Trace End, return 0x1f ===
```

logcat 过滤用 `duck` 标签（`adb logcat -s duck` 或 `adb logcat | grep duck`）。

## 导出 API

- `vmtrace_set_output_dir(dir)` — 覆盖输出目录（默认 `files/trace_logs`）
- `vmtrace_set_function_size(size)` — 限定 trace 记录范围（0 = 整模块执行流）
- `vmtrace_hook_attach(target, tag, useQBDI, traceOnce)` — attach 模式
- `vmtrace_hook_replace(target, tag, useQBDI, traceOnce)` — replace 模式（无重复副作用）
- `vmtrace_unhook` / `vmtrace_unhook_all`
- `vmtrace_hook_by_name` / `vmtrace_hook_by_offset`
- `vmtrace_call(target, args, argNum, tag)` — 直接调用 + trace
- `vmtrace_cleanup()`

## 已知坑

- 输出目录默认 `/data/data/<包名>/files/trace_logs`；frida spawn 的 app 没有
  `/data/local/tmp` 写权限，不要写那里。
- `EXEC_TRANSFER_CALL` 的调用目标在 `GPRState->pc`（AArch64），不是 `lr`。
- SVC 指令 QBDI 无法执行，已注册 mnemonic 回调兜底（原生执行）；同时在
  PREINST 读 `x8`(syscall 号)+`x0-x5`(参数) 生成注解，追在 code.log 的 SVC
  行尾，如 `...  "svc #0x0"  ;syscall read(0x1,0x7fd...,0x40,...)`。
- **专用大栈**：目标函数被调用时 app 线程栈往往已近耗尽（真机实测 hook 点仅剩
  ~0x60-0x110 字节余量），trace 机制自身的 C++ 栈帧会把栈顶穿 guard page 崩掉。
  因此整个 trace worker 用 `trace_run_on_stack`（AArch64 asm thunk）切到 8MB 专用栈，
  再给 QBDI 执行分配一块独立大栈（`QBDI::allocateVirtualStack`）。
  **限制**：目标函数在独立大栈上执行，靠栈传参（第 8 个及以后参数）的函数读不到
  真实参数（读到的 0）；绝大多数 ≤7 寄存器参数函数不受影响。
- attach 模式：QBDI 嵌套执行 + 原生再执行各一份，外部副作用会重复；
  要单份副作用用 `vmtrace_hook_replace`。
- 多会话共享同一份行号计数器（`g_line_num`），保证三文件索引全局唯一。
