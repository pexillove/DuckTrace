# QBDI Trace Agent (libtrace.so)

## 架构

```
目标进程 (Android AArch64)
├── frida 注入
│   └── ./trace.js — 加载 libQBDI.so + libtrace.so，定位目标函数，启动 hook
└── libtrace.so
    ├── Gum interceptor hook 目标函数（attach listener 或 replace）
    ├── hook 命中 → 新建 QBDI VM，从函数入口 run 到 LR
    ├── PREINST/POSTINST → code.log（汇编 + reads/writes 两列 JSON 寄存器值）
    ├── EXEC_TRANSFER_CALL → bl.log（外部调用 + 目标 hexdump）
    └── MemoryAccess → rw.log（内存读写 + hexdump）
```

嵌套 VM 方案只有目标函数自身的指令走 QBDI，内部调用的外部函数由 QBDI ExecBroker 原生执行，回跳后继续插桩。

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

## 环境搭建

本 agent 只依赖 3 个构建期第三方组件 + 1 个部署工具，全部来自官方 release 包，开箱即编：

| 组件 | 用途 | 版本 |
|------|------|------|
| Android NDK | 交叉编译工具链 | 我自己使用 r29 |
| QBDI | DBI 引擎（AArch64 插桩） | 0.12.1 · `QBDI-0.12.1-android-AARCH64.tar.gz` |
| frida-gum devkit | hook 目标函数（Gum Interceptor） | 较新版本 · `frida-gum-devkit-*-android-arm64.tar.xz` |
| frida-tools | 部署/驱动（运行时，可选） | 与设备上 frida-server 版本一致 |

> frida-gum devkit 用的是稳定的 Gum Interceptor C API（attach/replace/revert），
> 近几年任意版本都能直接链接，不必和 frida-server 版本强绑定。

### 目录布局（环境目录 tree）

仓库根位置任意，但**内部相对布局固定** —— `build.sh` 的所有默认路径都相对
`build.sh` 所在目录推导，按下面的结构摆好三个依赖即可一键编译：

```
<repo>/                                # 仓库根，位置任意，内部相对布局保持不变
├── NDK/                               # Android NDK (r2x)，解压后重命名放到 <repo>/NDK
│   └── toolchains/llvm/prebuilt/linux-x86_64/bin/
│       └── aarch64-linux-android{21..35}-clang++   # build.sh 自动挑最高可用版本
├── code/
│   └── QDBI/
│       ├── usr/                       # QBDI 0.12.1 android-AARCH64 包（解压出 local/ 子目录）
│       │   └── local/
│       │       ├── include/
│       │       │   ├── QBDI.h
│       │       │   └── QBDI/          # QBDI/*.h 头文件
│       │       ├── lib/
│       │       │   ├── libQBDI.so     # 编译期链接；运行期随 trace.js 一起推送到设备
│       │       │   └── libQBDI.a      # 静态库（build.sh 不引用）
│       │       ├── bin/               # qbdi-*-template-AARCH64（调试用）
│       │       └── share/qbdiAARCH64/ # 官方 frida-qbdi 模板
│       ├── frida-gum-devkit/          # frida-gum devkit (android-arm64)
│       │   ├── frida-gum.h
│       │   └── libfrida-gum.a
│       └── trace/                     # 本 agent 源码（README 所在目录）
│           ├── build.sh               # 一键编译 → 生成 libtrace.so
│           ├── CMakeLists.txt         # 可选 CMake 构建
│           ├── trace_impl.{h,cpp}     # QBDI + Frida Gum 核心实现
│           ├── raw_logger.{h,cpp}     # code/bl/rw 三文件 mmap 写入器
│           ├── syscall_names.inc      # AArch64 syscall 名表
│           ├── trace.js               # Frida 驱动脚本（部署用）
│           ├── README.md
│           └── libtrace.so            # build.sh 产物（arm64）
├── docs/
│   └── TraceFormat.md                 # 三文件 trace 格式规范（唯一权威）
└── defer/                             # 参考实现（不参与构建）
    ├── frida_stalker.cpp
    └── qdbi_demo/
```

```bash
# QBDI（解压出 local/）
mkdir -p code/QBDI/usr
tar xzf QBDI-0.12.1-android-AARCH64.tar.gz -C code/QBDI/usr

# frida-gum devkit（frida-gum.h、libfrida-gum.a 落在顶层）
mkdir -p code/QBDI/frida-gum-devkit
tar xJf frida-gum-devkit-<ver>-android-arm64.tar.xz -C code/QBDI/frida-gum-devkit

# NDK（解压后按需重命名为 NDK）
unzip android-ndk-r29-linux.zip
```

不想按这个布局放的话，用环境变量 `NDK` / `QDBI_HOME` / `FRIDA_INC` / `FRIDA_LIB` 覆盖，见下节。

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
adb push trace.js                       /data/local/tmp/   # trace.js 在本目录（见上方 tree）

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

## 输出格式

每次 trace 输出 `code.log` / `bl.log` / `rw.log` 三个文件，行号（**十六进制**）是它们之间的全局索引。完整规范见 `docs/TraceFormat.md`（唯一权威来源），下面是速查。

### code.log — 主指令流（恒 7 列 TSV）

```
hex行号\t绝对地址\t模块偏移\t"汇编指令"\tR{JSON}\tW{JSON}\tsvc{JSON}
```

- 汇编列带双引号、**恒为单个字段**（反汇编内部 mnemonic 与操作数之间的 tab 已替换为空格，不会拆列）
- `R` 是执行前（PRE）值，`W` 是执行后（POST）值；`w` 寄存器已截断为低 32 位
- 最后三列都是合法 JSON，可直接 `json.loads`；地址/偏移/R/W/note 各列带对齐填充空格，汇编列不带
- 文件首行 `=== Trace Start: ... ===` 为注释行，解析时跳过

```bash
grep -P "^4ee\t" code.log   # 第 0x4ee 条指令
cut -f4 code.log | tr -d '"' | awk '{print $1}' | sort | uniq -c | sort -rn  # 指令统计
```

```
e	0x76ff44fb98  	0xf4b98   	"add x0, sp, #0x108"                    	{"SP":"0x6fd25e1d80"}       	{"X0":"0x6fd25e1e88"}       	{}
f	0x76ff44fb9c  	0xf4b9c   	"movk w27, #0xc076, lsl #16"            	{"W27":"0xce4d"}            	{"W27":"0xc076ce4d"}        	{}
10	0x76ff44fba0  	0xf4ba0   	"movk w21, #0x8ffd, lsl #16"            	{"W21":"0xf9fe"}            	{"W21":"0x8ffdf9fe"}        	{}
11	0x76ff44fba4  	0xf4ba4   	"stur x8, [x29, #-0x60]"                	{"X8":"0x73555f635f9c96b7","FP":"0x6fd25e1fe0"}	{}                          	{}
12	0x76ff44fba8  	0xf4ba8   	"sub sp, sp, #0x50"                     	{"SP":"0x6fd25e1d80"}       	{"SP":"0x6fd25e1d30"}       	{}
13	0x76ff44fbac  	0xf4bac   	"stp x29, x30, [sp, #0x40]"             	{"FP":"0x6fd25e1fe0","LR":"0x7704c5ebfc","SP":"0x6fd25e1d30"}	{}                          	{}
14	0x76ff44fbb0  	0xf4bb0   	"stp x0, x1, [sp]"                      	{"X0":"0x6fd25e1e88","X1":"0x7a0f89cf20","SP":"0x6fd25e1d30"}	{}                          	{}
15	0x76ff44fbb4  	0xf4bb4   	"stp x2, x3, [sp, #0x10]"               	{"X2":"0x18","X3":"0x1089ec0dba","SP":"0x6fd25e1d30"}	{}                          	{}
16	0x76ff44fbb8  	0xf4bb8   	"stp x4, x5, [sp, #0x20]"               	{"X4":"0xffffffffffffff","X5":"0x1275ce","SP":"0x6fd25e1d30"}	{}                          	{}
17	0x76ff44fbbc  	0xf4bbc   	"stp x6, x7, [sp, #0x30]"               	{"X6":"0xd","X7":"0x799fba2378","SP":"0x6fd25e1d30"}	{}                          	{}
18	0x76ff44fbc0  	0xf4bc0   	"bl #0x10"                              	{"SP":"0x6fd25e1d30"}       	{"LR":"0x76ff44fbc4"}       	{}
19	0x76ff44fbd0  	0xf4bd0   	"sub sp, sp, #0x10"                     	{"SP":"0x6fd25e1d30"}       	{"SP":"0x6fd25e1d20"}       	{}
1a	0x76ff44fbd4  	0xf4bd4   	"stp x29, x30, [sp]"                    	{"FP":"0x6fd25e1fe0","LR":"0x76ff44fbc4","SP":"0x6fd25e1d20"}	{}                          	{}
1b	0x76ff44fbd8  	0xf4bd8   	"ldr x0, [sp, #0x8]"                    	{"SP":"0x6fd25e1d20"}       	{"X0":"0x76ff44fbc4"}       	{}
1c	0x76ff44fbdc  	0xf4bdc   	"ldp x29, x30, [sp]"                    	{"SP":"0x6fd25e1d20"}       	{"FP":"0x6fd25e1fe0","LR":"0x76ff44fbc4"}	{}
```

### bl.log — 函数调用

```
hex行号\t目标地址\t符号名
目标地址 - 0x10 起 0x30 字节 hexdump
```

```bash
grep -P "^4ee\t" bl.log   # 第 0x4ee 条指令触发的调用
```

### rw.log — 内存读写

```
hex行号\tr|w\t0x基址±0x偏移
访问地址 - 0x10 起 0x30 字节 hexdump
```

```bash
grep -P "^4ee\t" rw.log   # 第 0x4ee 条指令的内存访问
```

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
  PREINST 读 `x8`(syscall 号)+`x0-x5`(参数) 生成 JSON 注解，放在 code.log 的
  SVC 行第 7 列（note），如 `{"syscall":"read","args":["0x1","0x7fd...","0x40"]}`。
- **专用大栈**：目标函数被调用时 app 线程栈往往已近耗尽（真机实测 hook 点仅剩
  ~0x60-0x110 字节余量），trace 机制自身的 C++ 栈帧会把栈顶穿 guard page 崩掉。
  因此整个 trace worker 用 `trace_run_on_stack`（AArch64 asm thunk）切到 8MB 专用栈，
  再给 QBDI 执行分配一块独立大栈（`QBDI::allocateVirtualStack`）。
  **限制**：目标函数在独立大栈上执行，靠栈传参（第 8 个及以后参数）的函数读不到
  真实参数（读到的 0）；绝大多数 ≤7 寄存器参数函数不受影响。
- **并发触发**：专用栈是单块全局 mmap，`run_trace_on_big_stack` 在切栈**之前**拿
  `g_exec_mutex`（recursive），抢锁失败的线程阻塞在调用方自己的栈上，不进专用栈。
  不要把锁挪到切栈之后——多个线程并发切到同一个 stackTop 会互相覆盖
  `trace_run_on_stack` 槽位，先执行完的线程在 asm epilogue 读到错误地址返回（必崩）。
- attach 模式：QBDI 嵌套执行 + 原生再执行各一份，外部副作用会重复；
  要单份副作用用 `vmtrace_hook_replace`。
- 多会话共享同一份行号计数器（`g_line_num`），保证三文件索引全局唯一；
  打印行号用 `%llx`（64 位），别截断成 32 位——累计执行超过 2^32 条指令会回绕，
  三文件索引重复。
