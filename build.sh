#!/usr/bin/env bash
# 编译 QBDI Trace Agent (libtrace.so)
#
# 依赖：
#   - Android NDK (clang++)
#   - QBDI Android AArch64 包 (code/QDBI/usr)
#   - frida-gum 头文件 + 静态库 (可从 frida 官方预编译包或旧工程获取)
#
# 通过环境变量覆盖路径：
#   NDK=/path/to/ndk
#   QDBI_HOME=/path/to/qbdi/usr
#   FRIDA_INC=/path/to/frida-gum-headers
#   FRIDA_LIB=/path/to/libfrida-gum.a
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
QDBI_HOME="${QDBI_HOME:-$(cd "$SCRIPT_DIR/.." && pwd)/usr}"

# Android NDK（默认 <Trace>/NDK，与 code/ 同级；可通过 NDK=xxx 覆盖）
NDK="${NDK:-$(cd "$SCRIPT_DIR/../../.." && pwd)/NDK}"
TOOLCHAIN="$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin"
CXX="$TOOLCHAIN/aarch64-linux-android29-clang++"
if [ ! -x "$CXX" ]; then
    CXX="$TOOLCHAIN/aarch64-linux-android-clang++"
fi
if [ ! -x "$CXX" ]; then
    echo "[!] clang++ not found in $TOOLCHAIN" >&2
    exit 1
fi

# frida-gum (头文件 + 静态库)
FRIDA_INC="${FRIDA_INC:-$(cd "$SCRIPT_DIR/.." && pwd)/frida-gum-devkit}"
FRIDA_LIB="${FRIDA_LIB:-$(cd "$SCRIPT_DIR/.." && pwd)/frida-gum-devkit/libfrida-gum.a}"

OUT="$SCRIPT_DIR/libtrace.so"

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
    -I"$QDBI_HOME/local/include" \
    -I"$FRIDA_INC" \
    "$SCRIPT_DIR/trace_impl.cpp" \
    "$SCRIPT_DIR/raw_logger.cpp" \
    "$FRIDA_LIB" \
    -L"$QDBI_HOME/local/lib" -lQBDI \
    -llog -ldl -lm -lc -landroid \
    -Wl,--gc-sections \
    -o "$OUT"

echo "[*] built: $OUT"
