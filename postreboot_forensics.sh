#!/bin/bash
# ============================================================================
# postreboot_forensics.sh — reboot forensics that does NOT depend on the poller
# ============================================================================
# Why this exists
# ---------------
# Every attempt to explain this project's reboots rests on one question: did a
# panic happen?  Every answer so far came from a host-side poller streaming
# `dmesg`.  That channel has now failed in a way that invalidates the conclusion:
#
#   run 9   capture brackets its reboot; no BUG/panic marker
#   run 10  capture is the NEXT boot (the redirect in start_klog failed)
#   run 11  klog.host is 0 bytes
#   run 13  klog.host is 0 bytes
#
# So "all reboots were orderly, no panic" has a sample of ONE, not four.
#
# This script uses a channel the poller cannot corrupt: whatever the kernel
# itself left in pstore/ramoops, which survives a reset.
#
# Why pstore is decisive on THIS kernel
# -------------------------------------
#   CONFIG_PSTORE=y  CONFIG_PSTORE_CONSOLE=y  CONFIG_PSTORE_RAM=y
#       -> a panic writes the console tail into ramoops; it survives the reset.
#   CONFIG_PANIC_TIMEOUT=-1
#       -> panic() does NOT auto-reboot.  The box hangs.
#
# Together those make the readings mutually exclusive:
#   * a clean `bootreason=reboot` cannot be a panic, because a panic does not
#     reboot -- unless something else (PMIC / hardware watchdog) resets the hung
#     box, and in that case ramoops STILL holds the panic text.
#
#   `kernel BUG at ...` in pstore  =>  it was a panic.
#   pstore empty                   =>  no panic (only if ramoops is registered).
#
# Stated so it is not over-read: an empty pstore is evidence of absence ONLY once
# the reserved region is confirmed.  This script checks for it and says which
# verdict it is entitled to, instead of asserting "no panic".
#
# Usage:  ./postreboot_forensics.sh [tag]
# ============================================================================
set -u
export MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL="*"

ADB=${ADB:-adb}
SER=${SER:-$( "$ADB" devices 2>/dev/null | sed -n "2s/[[:space:]].*//p" )}
TAG=${TAG:-$(date +%m%d_%H%M%S)}
OUT=${OUT:-./forensics_$TAG}
mkdir -p "$OUT" || { echo "cannot create $OUT"; exit 1; }

A() { "$ADB" -s "$SER" shell "$@"; }
say() { echo "[$(date +%H:%M:%S)] $*"; }

[ -z "$SER" ] && { echo "!! no device on $ADB"; exit 1; }

say "=== device ==="
A 'uname -r; cut -d" " -f1 /proc/uptime; cat /proc/sys/kernel/random/boot_id' \
  | tr -d '\r' | sed 's/^/  /'

# ---------------------------------------------------------------- 1. reason
say "=== 1. boot reason — the STRING, not just the epoch ==="
A 'getprop ro.boot.bootreason' | tr -d '\r' | sed 's/^/  ro.boot.bootreason = /'
# The history property is "epoch,reason:epoch,reason:...".  Earlier entries on
# this device carried suffixes (reboot,shell / bootloader / reboot,edl), so a
# shell actor IS distinguishable -- which is exactly why the reason string
# matters and the epoch alone does not.
A 'getprop persist.sys.boot.reason.history' | tr -d '\r' | sed 's/^/  history(raw) = /'
A 'getprop persist.sys.boot.reason.history' | tr -d '\r' | tr ':' '\n' \
  | awk -F, 'NF{ printf "  history[%d] epoch=%s reason=%s\n", NR, $1, $2 }'
A 'getprop persist.sys.oplus.total_abnormalreboot_count; getprop persist.sys.oplus.total_abnormalreboot_count_neras' \
  | tr -d '\r' | sed 's/^/  oplus_abnormal = /'

# ---------------------------------------------------------------- 2. pstore
say "=== 2. pstore / ramoops (survives the reset; poller-independent) ==="
A 'ls -la /sys/fs/pstore/ 2>&1' | tr -d '\r' | sed 's/^/  /'
A 'mount 2>/dev/null | grep -c pstore' | tr -d '\r' | sed 's/^/  pstore mounts = /'
A 'grep -i -m3 ramoops /proc/iomem 2>/dev/null || echo NO_RAMOOPS_IOMEM' \
  | tr -d '\r' | sed 's/^/  iomem: /'
A 'ls /proc/device-tree/ 2>/dev/null | grep -i -m3 -E "ramoops|pstore" || echo NO_RAMOOPS_DT_NODE' \
  | tr -d '\r' | sed 's/^/  dt: /'
A 'for f in /sys/module/ramoops/parameters/*; do [ -e "$f" ] && echo "$(basename $f)=$(cat $f 2>/dev/null)"; done 2>/dev/null | head -20' \
  | tr -d '\r' | sed 's/^/  ramoops_param: /'

say "  --- pulling the records ---"
mkdir -p "$OUT/pstore"
"$ADB" -s "$SER" pull /sys/fs/pstore/. "$OUT/pstore/" 2>&1 | tail -2 | sed 's/^/  /'
if [ -z "$(ls -A "$OUT/pstore/" 2>/dev/null)" ]; then
    # pull usually needs root; fall back to a plain read of the known names
    for f in dmesg-ramoops-0 dmesg-ramoops-1 dmesg-ramoops-2 \
             console-ramoops-0 console-ramoops-1 pmsg-ramoops-0; do
        A "cat /sys/fs/pstore/$f 2>/dev/null" | tr -d '\r' > "$OUT/pstore/$f" 2>/dev/null
    done
fi

say "  --- the actual criterion ---"
PAT='kernel BUG at|BUG: |Unable to handle|Internal error|Kernel panic|Call trace|__put_cred|commit_creds|cred\.c|brk #0x800'
HITS=0
for f in "$OUT"/pstore/*; do
    [ -f "$f" ] || continue
    [ -s "$f" ] || continue
    n=$(grep -c -a -E "$PAT" "$f" 2>/dev/null)
    if [ "${n:-0}" -gt 0 ]; then
        HITS=$((HITS+1))
        say "  ★ $f : $n marker(s)"
        grep -a -n -E "$PAT" "$f" 2>/dev/null | head -12 | sed 's/^/      /'
    fi
done

NONEMPTY=$(find "$OUT/pstore" -type f -size +0c 2>/dev/null | wc -l)
RAMOOPS=$(A 'grep -c -i ramoops /proc/iomem 2>/dev/null; ls /proc/device-tree/ 2>/dev/null | grep -c -i ramoops' | tr -d '\r' | tr '\n' ' ')
if [ "$HITS" -gt 0 ]; then
    say "  ⇒ VERDICT: a panic/exception record EXISTS. The reboot is a kernel fault"
    say "    path, and the marker above names the site."
elif [ "$NONEMPTY" -gt 0 ]; then
    say "  ⇒ VERDICT: pstore has content but NO fault marker. Read it — it is the"
    say "    console tail, i.e. the last thing the kernel said before it went."
else
    say "  ⇒ VERDICT: pstore is EMPTY.  ramoops presence counts: [$RAMOOPS]"
    say "    If the reserved region is present, this FALSIFIES the panic hypothesis"
    say "    for this reboot: with PANIC_TIMEOUT=-1 a panic hangs rather than"
    say "    reboots, and it would have left a record here.  If the region is NOT"
    say "    present, ramoops is not armed and this reading carries no information."
fi

# ---------------------------------------------------------------- 3. dmesg
say "=== 3. dmesg (readable only in Permissive; may legitimately be empty) ==="
A 'dmesg 2>/dev/null | grep -a -i -E "kernel BUG|BUG: |Unable to handle|Internal error|Kernel panic|Call trace|ROOTCHECK" | tail -20' \
  | tr -d '\r' | sed 's/^/  /'
A 'dmesg 2>/dev/null | tail -5' | tr -d '\r' | sed 's/^/  tail: /'

say "=== artifacts in $OUT ==="
ls -la "$OUT" "$OUT/pstore" 2>/dev/null | sed 's/^/  /'
