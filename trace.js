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

var MODULE_NAME = "libksxgs.so";            // TODO: 改成目标 so
var FUNCTION_OFFSET = 0x27a2c;              // TODO: 改成目标函数偏移
var TRACE_ONCE = true;
var TRACE_DIR = "";

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

	// 4. 定位目标函数
	var base = Module.findBaseAddress(MODULE_NAME);
	if (base === null) {
		console.log("[!] 模块未加载: " + MODULE_NAME);
		return;
	}
	var target = base.add(FUNCTION_OFFSET);

	// 5. attach hook 启动 trace
	var attach = new NativeFunction(
		libtrace.getExportByName("vmtrace_hook_attach"),
		"int", ["pointer", "pointer", "int", "int"]);

	var logTag = Memory.allocUtf8String(MODULE_NAME);
	var ret = attach(target, logTag, 1, TRACE_ONCE ? 1 : 0);
	console.log("[*] vmtrace_hook_attach(" + target + ", useQBDI=1, traceOnce=" +
		TRACE_ONCE + ") => " + ret);
}

// trace();
