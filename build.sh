#!/bin/sh
# GhostLock (CVE-2026-43499) — OPPO Find X5 Pro (PFEM10) exploit build
#
# Targets: kernel 5.10.236-android12-9-o-gaf2075ad2c06, NDK r28c.
# Build params are FIXED: -O1 / android26 keeps the reclaim stack-frame
# geometry (delta=0 calibration). Changing them requires re-calibrating
# the stack geometry on device.
#
# Usage: ./build.sh
set -e

if [ -n "$NDK_HOME" ]; then
    NDK_ROOT="$NDK_HOME"
elif [ -n "$LOCALAPPDATA" ]; then
    NDK_ROOT="$(cygpath -u "$LOCALAPPDATA" 2>/dev/null || echo "$LOCALAPPDATA")/Android/Sdk/ndk/r28c"
else
    NDK_ROOT="$HOME/Android/Sdk/ndk/r28c"
fi
TOOLCHAIN="$NDK_ROOT/toolchains/llvm/prebuilt/windows-x86_64/bin"
CC="$TOOLCHAIN/aarch64-linux-android26-clang"

if [ ! -x "$CC" ]; then
    echo "toolchain not found: $CC" >&2
    echo "install NDK r28c or set NDK_HOME" >&2
    exit 1
fi

# device exploit (single self-contained binary; payload.c / kernelsnitch are #included)
"$CC" -D__ARM=1 -O1 -Wall -Wextra -pthread -o exploit src/exploit.c
echo "built: $(pwd)/exploit  (-O1 android26, PFEM10 delta=0 calibration)"

# host-side rtmutex chain-walk model (optional, no NDK needed)
if command -v gcc >/dev/null 2>&1; then
    if gcc -O2 -Wall -Wextra -o model_check model/model.c 2>/dev/null; then
        echo "built: $(pwd)/model_check  (host verification, run scenarios via argv)"
    else
        echo "note: host model build failed (gcc), skipping" >&2
    fi
fi
