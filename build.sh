#!/usr/bin/env bash
# 编译 QBDI Trace Agent (libtrace.so)
#
# 一键构建：按 README.md 的目录布局放好三个依赖后，在仓库内任意机器上直接
# ./build.sh 即可，脚本内默认路径全部相对 build.sh 位置推导，无需改脚本。
#
# 依赖（相对布局见 README.md「目录布局」）：
#   <repo>/NDK/                       Android NDK (linux-x86_64, r2x)
#   <repo>/code/QDBI/usr/             QBDI (解压后含 local/{include,lib})
#   <repo>/code/QDBI/frida-gum-devkit/  frida-gum.h + libfrida-gum.a 在顶层
#
# 覆盖路径（环境变量，非默认布局时用）：
#   CXX=/path/to/aarch64-linux-android-clang++
#   NDK=/path/to/ndk
#   QDBI_HOME=/path/to/qbdi/usr
#   FRIDA_INC=/path/to/frida-gum-headers
#   FRIDA_LIB=/path/to/libfrida-gum.a
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"

fail() { echo "[!] $*" >&2; exit 1; }

# --- QBDI Android 包（解压后含 local/ 子目录） ---
QDBI_HOME="${QDBI_HOME:-$(cd "$SCRIPT_DIR/.." && pwd)/usr}"
QBDI_INC="$QDBI_HOME/local/include"
QBDI_LIB="$QDBI_HOME/local/lib"

# --- Android NDK（默认 <repo>/NDK） ---
NDK="${NDK:-$REPO_ROOT/NDK}"
TOOLCHAIN="$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin"

# --- frida-gum devkit（frida-gum.h、libfrida-gum.a 在顶层） ---
FRIDA_INC="${FRIDA_INC:-$(cd "$SCRIPT_DIR/.." && pwd)/frida-gum-devkit}"
FRIDA_LIB="${FRIDA_LIB:-$FRIDA_INC/libfrida-gum.a}"

OUT="$SCRIPT_DIR/libtrace.so"

# --- 逐个检查依赖，缺什么报什么（不等到链接阶段才爆） ---
[ -d "$NDK" ]       || fail "Android NDK 不存在: $NDK" \
                       "  - 默认按 README 布局找 <repo>/NDK，或 export NDK=/path/to/ndk"
[ -d "$TOOLCHAIN" ] || fail "NDK 缺少 llvm 工具链: $TOOLCHAIN" \
                       "  - 确认下载的是 linux-x86_64 版本的 NDK"

[ -d "$QBDI_INC" ]  || fail "QBDI 头文件不存在: $QBDI_INC" \
                       "  - 解压 QBDI-*-android-AARCH64.tar.gz 到 code/QDBI/usr，或 export QDBI_HOME=..."
[ -f "$QBDI_LIB/libQBDI.so" ] || fail "QBDI 库不存在: $QBDI_LIB/libQBDI.so" \
                       "  - 同上（解压后应有 usr/local/lib/libQBDI.so）"

[ -f "$FRIDA_INC/frida-gum.h" ] || fail "frida-gum.h 不存在: $FRIDA_INC/frida-gum.h" \
                       "  - 解压 frida-gum-devkit-*-android-arm64.tar.xz 到 code/QDBI/frida-gum-devkit，或 export FRIDA_INC=..."
[ -f "$FRIDA_LIB" ] || fail "libfrida-gum.a 不存在: $FRIDA_LIB" \
                       "  - 同上（devkit 顶层应有 libfrida-gum.a），或 export FRIDA_LIB=..."

# --- 选 clang++：不同 NDK 版本可用 API level 不同，不能写死 ---
# 优先用户显式指定的 CXX，其次 README 记录的 android29，再自动挑最高可用版本，
# 最后兜底旧 NDK 的免版本号 clang++。
if [ -n "$CXX" ]; then
    [ -x "$CXX" ] || fail "CXX 指定但不可执行: $CXX"
elif [ -x "$TOOLCHAIN/aarch64-linux-android29-clang++" ]; then
    CXX="$TOOLCHAIN/aarch64-linux-android29-clang++"
elif [ -x "$TOOLCHAIN/aarch64-linux-android-clang++" ]; then
    CXX="$TOOLCHAIN/aarch64-linux-android-clang++"
else
    CXX="$(ls "$TOOLCHAIN"/aarch64-linux-android*-clang++ 2>/dev/null | sort -V | tail -1)"
    [ -n "$CXX" ] && [ -x "$CXX" ] || fail "未找到 aarch64-linux-android*-clang++" \
        "  - NDK 工具链不完整，或版本过旧/过新，确认路径: $TOOLCHAIN"
fi

echo "[*] CXX        = $CXX"
echo "[*] QDBI_HOME  = $QDBI_HOME"
echo "[*] FRIDA_INC  = $FRIDA_INC"
echo "[*] FRIDA_LIB  = $FRIDA_LIB"
echo "[*] OUT        = $OUT"

"$CXX" \
    -std=c++17 \
    -O2 \
    -fPIC -shared \
    -static-libstdc++ \
    -I"$QBDI_INC" \
    -I"$FRIDA_INC" \
    "$SCRIPT_DIR/trace_impl.cpp" \
    "$SCRIPT_DIR/raw_logger.cpp" \
    "$FRIDA_LIB" \
    -L"$QBDI_LIB" -lQBDI \
    -llog -ldl -lm -lc -landroid \
    -Wl,--gc-sections \
    -o "$OUT"

echo "[*] built: $OUT"
