// QBDI Trace 驱动
//
// 用法：
//   1. 推送依赖和设备端运行:
//      adb push code/QDBI/usr/local/lib/libQBDI.so /data/local/tmp/
//      adb push code/QDBI/trace/libtrace.so  /data/local/tmp/
//      adb push code/QDBI/trace.js           /data/local/tmp/
//   2. 启动 trace (spawn 模式, 或 attach 到运行中的进程):
//      frida -U -f com.target.app -l /data/local/tmp/trace.js
//      frida -U -n com.target.app -l /data/local/tmp/trace.js
//   3. 触发目标函数调用, trace 输出到设备 /data/data/<包名>/files/trace_logs/
//      (路径由 trace.js 打印), 然后:
//      adb pull /data/data/<包名>/files/trace_logs/ .
//
// 配置：
//   MODULE_NAME     目标模块名 (需先被 app 加载)
//   FUNCTION_OFFSET 目标函数在模块内的偏移
//   TRACE_ONCE      true = 只 trace 一次后自动 detach
//   TRACE_DIR       输出目录 (设备端)。留空 = 用应用数据目录
//                   /data/data/<包名>/files/trace_logs (与 gum.cpp 一致)
//   DUMP_FLAGS      内存快照类别 (位掩码, 见下)。0 = 关闭
//                   默认只在第一次 trace 前 dump 一份, 输出到 <输出目录>/mem/
//   DUMP_PER_REGION 单区段上限 (字节), 超过整段跳过。目标 so 段不受限
//   DUMP_TOTAL      单次 dump 总预算 (字节)

var MODULE_NAME = "libksxgs.so";            // TODO: 改成目标 so
var FUNCTION_OFFSET = 0x27a2c;              // TODO: 改成目标函数偏移
var TRACE_ONCE = true;
var TRACE_DIR = "";

// 内存快照 (unidbg 回放用): maps + 目标 so 运行期映射 + 匿名 r-xp/rwxp +
// 匿名 rw-p + 栈。DUMP_ALL 已是常用组合, 按需再加 AT_END / EVERY_RUN。
var DUMP_MAPS = 0x01;       // /proc/self/maps 原始快照
var DUMP_TARGET_SO = 0x02;  // 目标 so 的运行期映射 (已重定位/已解密, 含 .bss)
var DUMP_ANON_EXEC = 0x04;  // 匿名可执行段 (JIT / 壳解出来的代码)
var DUMP_ANON_RW = 0x08;    // 匿名可写段 (堆 / 运行期数据)
var DUMP_STACK = 0x10;      // 栈 (app 线程栈 + QBDI 虚拟栈, 只取 sp 之上)
var DUMP_ALL = 0x1f;
var DUMP_AT_END = 0x100;    // 额外出一份 end 快照 (落在最后一次 trace 之后), 与 start 差异
var DUMP_EVERY_RUN = 0x200; // 每次 trace 都 dump (默认只第一次, 防止循环 hook 刷爆磁盘)

// 默认带 AT_END: 只有 start/end 两份快照都在, 才能差异出「哪些内存是执行期间
// 才被改写/解密的」——壳解出来的字节码常常就藏在这个差异里
var DUMP_FLAGS = DUMP_ALL | DUMP_AT_END;
var DUMP_PER_REGION = 32 * 1024 * 1024;
var DUMP_TOTAL = 512 * 1024 * 1024;

var QBDI_SO_PATH = "/data/local/tmp/libQBDI.so";
var TRACE_SO_PATH = "/data/local/tmp/libtrace.so";

// 读取当前进程包名，得到应用数据目录 (参考 gum.cpp 的 get_process_data_dir)
function getAppDataDir() {
	try {
		var name = File.readAllLines("/proc/self/cmdline")[0];
		name = name.replace(/\x00.*$/, "");
		var idx = name.indexOf(":");
		if (idx !== -1) name = name.substring(0, idx);
		return "/data/data/" + name;
	} catch (e) {
		return null;
	}
}

function trace() {
	// 1. 先加载 QBDI (libtrace.so 的 DT_NEEDED)
	Module.load(QBDI_SO_PATH);

	// 2. 加载 agent
	var libtrace = Module.load(TRACE_SO_PATH);

	// 3. 配置输出目录
	var setDir = new NativeFunction(
		libtrace.getExportByName("vmtrace_set_output_dir"), "int", ["pointer"]);
	if (TRACE_DIR !== "") {
		setDir(Memory.allocUtf8String(TRACE_DIR));
	} else {
		var dataDir = getAppDataDir();
		if (dataDir !== null) {
			console.log("[*] trace 输出目录: " + dataDir + "/files/trace_logs");
			console.log("[*]   adb pull " + dataDir + "/files/trace_logs/ .");
		}
	}

	// 4. 配置内存快照
	var setDump = new NativeFunction(
		libtrace.getExportByName("vmtrace_set_mem_dump"), "int", ["int"]);
	setDump(DUMP_FLAGS);
	if (DUMP_FLAGS !== 0) {
		var setDumpLimit = new NativeFunction(
			libtrace.getExportByName("vmtrace_set_mem_dump_limit"),
			"int", ["uint64", "uint64"]);
		setDumpLimit(DUMP_PER_REGION, DUMP_TOTAL);
		console.log("[*] 内存快照: flags=0x" + DUMP_FLAGS.toString(16) + " -> <输出目录>/mem/");
	}

	// 5. 定位目标函数
	var base = Module.findBaseAddress(MODULE_NAME);
	if (base === null) {
		console.log("[!] 模块未加载: " + MODULE_NAME);
		return;
	}
	var target = base.add(FUNCTION_OFFSET);

	// 6. attach hook 启动 trace
	var attach = new NativeFunction(
		libtrace.getExportByName("vmtrace_hook_attach"),
		"int", ["pointer", "pointer", "int", "int"]);

	var logTag = Memory.allocUtf8String(MODULE_NAME);
	var ret = attach(target, logTag, 1, TRACE_ONCE ? 1 : 0);
	console.log("[*] vmtrace_hook_attach(" + target + ", useQBDI=1, traceOnce=" +
		TRACE_ONCE + ") => " + ret);
}

// trace();
