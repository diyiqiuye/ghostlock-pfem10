#!/bin/sh
# GhostLock — OPPO Find X5 Pro (PFEM10) exploit build
#
# Targets: kernel 5.10.236-android12-9-o-gaf2075ad2c06, NDK r28c.
# Build params are FIXED (-O1 / API 26 / -D__ARM=1) — see Makefile.
#
# Usage:  ./build.sh
#   NDK resolution order: $NDK_HOME -> $ANDROID_NDK_HOME -> $ANDROID_HOME/ndk/r28c
#                         -> $HOME/Android/Sdk/ndk/r28c

set -e
cd "$(dirname "$0")"

if [ -n "$NDK_HOME" ]; then
    :
elif [ -n "$ANDROID_NDK_HOME" ]; then
    NDK_HOME="$ANDROID_NDK_HOME"
elif [ -n "$ANDROID_HOME" ] && [ -d "$ANDROID_HOME/ndk/r28c" ]; then
    NDK_HOME="$ANDROID_HOME/ndk/r28c"
elif [ -n "$LOCALAPPDATA" ]; then
    NDK_HOME="$(cygpath -u "$LOCALAPPDATA" 2>/dev/null || echo "$LOCALAPPDATA")/Android/Sdk/ndk/r28c"
else
    NDK_HOME="$HOME/Android/Sdk/ndk/r28c"
fi

NDK_HOME="$NDK_HOME" exec make "$@"
