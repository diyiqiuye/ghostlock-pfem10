#!/bin/bash
# ============================================================================
# postreboot_forensics.sh — reboot forensics that does NOT depend on the poller
# ============================================================================
# Why this exists
# ---------------
# Every attempt to explain this project's reboots rests on one question: did a
# panic happen?  Every answer so far came from a host-side poller streaming
# `dmesg`.  That channel has failed in a way that invalidates the conclusion:
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
# The criterion is ONE condition, and it does not involve bootreason
# ------------------------------------------------------------------
#   CONFIG_PSTORE=y  CONFIG_PSTORE_CONSOLE=y  CONFIG_PSTORE_RAM=y
#
# `panic()` calls `kmsg_dump(KMSG_DUMP_PANIC)`, which is what copies the console
# tail into ramoops.  That happens BEFORE any reset -- the machine may then hang,
# reboot cleanly, or be taken down by a watchdog; it makes no difference, the
# record is already in the reserved region.
#
#   `kernel BUG at ...` in pstore  =>  it was a panic.  Full stop.
#   pstore reachable and empty     =>  no panic in this boot.
#
# An earlier revision of this file additionally argued from
# `CONFIG_PANIC_TIMEOUT=-1` ("a panic hangs rather than reboots, so a clean
# bootreason=reboot cannot be a panic").  That argument is REMOVED, for two
# reasons:
#
#   1. It is unnecessary.  The record is written before the reset either way, so
#      the criterion never needed bootreason to participate.
#   2. It is WRONG in a dangerous direction.  On Qualcomm an SoC watchdog assert
#      resets the part through the PMIC PON block, so "panic -> hang -> watchdog
#      -> PMIC reset -> clean-looking bootreason=reboot" is a self-consistent
#      chain.  The device's own counter says
#      `total_abnormalreboot_count = total_17_dump_0_pmic_17` -- 17 abnormal
#      reboots all attributed to pmic.  `pmic` is the ORDINARY SHAPE of a
#      watchdog reset, not evidence of a hardware cause; `dump_0` refers to the
#      SBL/QSEE mini-dump channel (unrelated to ramoops, and possibly already
#      consumed by OPPO's own dumper); and the absence of a `,shell` suffix only
#      rules out a shell-initiated reboot.  So that clue narrows nothing, and
#      reading "clean reboot" as "no panic" is exactly the over-read to avoid.
#
# ⛔ And the third state, which an earlier revision got wrong
# ----------------------------------------------------------
# The first version decided "empty" from a count of files it had successfully
# read.  Under Enforcing, `/sys/fs/pstore/*` is not readable by `shell`, so
# `adb pull` and `cat` BOTH fail and produce empty output -- which is
# indistinguishable from "read it, and it was empty".  That version would have
# printed "pstore is EMPTY => this FALSIFIES the panic hypothesis" on a device
# where it had simply been unable to look.  That is 铁律 8 (a "no kernel signal"
# conclusion must first prove the channel is reachable) violated by the very
# script that cites it.
#
# This version probes reachability FIRST and keeps three states:
#     CHANNEL UNREACHABLE  -> says nothing about panic.  Fix access and re-run.
#     REACHABLE, EMPTY     -> no panic in this boot.
#     CONTENT              -> report it, and say whether a fault marker is in it.
#
# Ordering matters (do not get this wrong)
# ----------------------------------------
#   1. reboot happens
#   2. IMMEDIATELY run W1 to get Permissive   (SELinux is what blocks the read)
#   3. IMMEDIATELY run this script
# Late is the same as never: this device's boot-time dumper moves the pstore
# records away and unlinks them, so a reading taken minutes later can be empty
# for a reason that has nothing to do with what happened.
#
# Null test (do this once, before trusting any "empty" reading)
# ------------------------------------------------------------
# After a CLEAN `adb reboot` with no exploit activity:
#     ./postreboot_forensics.sh --baseline
# If that cannot reach the channel, then "empty pstore" never carries
# information on this device and every later reading must say UNREACHABLE.
#
# Usage:  ./postreboot_forensics.sh [--baseline] [tag]
# ============================================================================
set -u
export MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL="*"

BASELINE=0
[ "${1:-}" = "--baseline" ] && { BASELINE=1; shift; }
TAG=${1:-$(date +%m%d_%H%M%S)}
# NB: `${BASELINE:+baseline_}` would ALWAYS expand -- BASELINE is always set, to
# "0" or "1", and `:+` tests only for non-empty. Build the prefix explicitly.
PFX=""
[ "$BASELINE" = "1" ] && PFX="baseline_"

ADB=${ADB:-adb}
SER=${SER:-$( "$ADB" devices 2>/dev/null | sed -n "2s/[[:space:]].*//p" )}
OUT=${OUT:-./forensics_${PFX}${TAG}}
mkdir -p "$OUT" || { echo "cannot create $OUT"; exit 1; }

A() { "$ADB" -s "$SER" shell "$@"; }
say() { echo "[$(date +%H:%M:%S)] $*"; }

[ -z "$SER" ] && { echo "!! no device on $ADB"; exit 1; }

say "=== device ==="
A 'uname -r; cut -d" " -f1 /proc/uptime; cat /proc/sys/kernel/random/boot_id' \
  | tr -d '\r' | sed 's/^/  /'
# Enforcing is the thing that makes the channel unreadable, so record it with
# the reading rather than near it.
ENF=$(A 'getenforce' | tr -d '\r')
say "  getenforce = $ENF"
if [ "$ENF" != "Permissive" ]; then
    say "  ⚠ SELinux is NOT Permissive.  The pstore read below will very likely"
    say "    fail, and a failure is NOT evidence about panic.  Run W1 first, then"
    say "    re-run this script immediately."
fi

# ---------------------------------------------------------------- 1. reason
say "=== 1. boot reason — the STRING, not just the epoch ==="
say "    (recorded for context only; the criterion in section 2 does not use it)"
A 'getprop ro.boot.bootreason' | tr -d '\r' | sed 's/^/  ro.boot.bootreason = /'
A 'getprop persist.sys.boot.reason.history' | tr -d '\r' | sed 's/^/  history(raw) = /'
A 'getprop persist.sys.boot.reason.history' | tr -d '\r' | tr ':' '\n' \
  | awk -F, 'NF{ printf "  history[%d] epoch=%s reason=%s\n", NR, $1, $2 }'
# A counter is only interpretable against a baseline: read once after a reboot
# it cannot distinguish "this one incremented" from "the device's history".
# Record it here and compare with the previous run's file.
A 'getprop persist.sys.oplus.total_abnormalreboot_count; getprop persist.sys.oplus.total_abnormalreboot_count_neras' \
  | tr -d '\r' | sed 's/^/  oplus_abnormal = /'
PREV=$(ls -1t ./forensics_*/10_counters.txt 2>/dev/null | head -1)
if [ -n "$PREV" ]; then
    say "  previous counters ($PREV):"
    sed 's/^/    /' "$PREV"
    say "  ⚠ increment only means an ABNORMAL reboot happened; it does not name a cause."
else
    say "  (no previous counter file — this reading is the baseline)"
fi
A 'getprop persist.sys.oplus.total_abnormalreboot_count; getprop persist.sys.oplus.total_abnormalreboot_count_neras' \
  | tr -d '\r' > "$OUT/10_counters.txt"

# ---------------------------------------------------------------- 2. pstore
say "=== 2. pstore / ramoops ==="
say "  --- 2a. is ramoops even registered? (if not, an empty pstore means nothing) ---"
A 'grep -i -m3 ramoops /proc/iomem 2>/dev/null || echo NO_RAMOOPS_IOMEM' \
  | tr -d '\r' | sed 's/^/  iomem: /'
A 'ls /proc/device-tree/ 2>/dev/null | grep -i -m3 -E "ramoops|pstore" || echo NO_RAMOOPS_DT_NODE' \
  | tr -d '\r' | sed 's/^/  dt: /'
A 'for f in /sys/module/ramoops/parameters/*; do [ -e "$f" ] && echo "$(basename $f)=$(cat $f 2>/dev/null)"; done 2>/dev/null | head -20' \
  | tr -d '\r' | sed 's/^/  ramoops_param: /'

say "  --- 2b. REACHABILITY PROBE (this is the state that was missing) ---"
LS_OUT=$(A 'ls -la /sys/fs/pstore/ 2>&1' | tr -d '\r')
printf '%s\n' "$LS_OUT" | sed 's/^/  ls: /'
# Per-name probe that separates "absent" from "present but unreadable".  Both
# used to collapse into empty output, which is how the earlier revision could
# claim "empty" when it had actually been denied.
PROBE=$(A 'for f in dmesg-ramoops-0 dmesg-ramoops-1 dmesg-ramoops-2 console-ramoops-0 console-ramoops-1 pmsg-ramoops-0; do
  p=/sys/fs/pstore/$f
  if [ -e "$p" ]; then
    if cat "$p" >/dev/null 2>&1; then echo "$f EXISTS READABLE"; else echo "$f EXISTS UNREADABLE"; fi
  else
    echo "$f ABSENT"
  fi
done' | tr -d '\r')
printf '%s\n' "$PROBE" | sed 's/^/  /'
N_READABLE=$(printf '%s\n' "$PROBE" | grep -c 'READABLE')
N_UNREADABLE=$(printf '%s\n' "$PROBE" | grep -c 'UNREADABLE')
N_EXISTS=$(( N_READABLE + N_UNREADABLE ))
LS_DENIED=0
printf '%s\n' "$LS_OUT" | grep -qi 'denied\|not permitted\|Permission' && LS_DENIED=1

say "  --- 2c. pulling the records (best effort) ---"
mkdir -p "$OUT/pstore"
"$ADB" -s "$SER" pull /sys/fs/pstore/. "$OUT/pstore/" 2>&1 | tail -2 | sed 's/^/  /'
if [ -z "$(ls -A "$OUT/pstore/" 2>/dev/null)" ]; then
    for f in dmesg-ramoops-0 dmesg-ramoops-1 dmesg-ramoops-2 \
             console-ramoops-0 console-ramoops-1 pmsg-ramoops-0; do
        A "cat /sys/fs/pstore/$f 2>/dev/null" | tr -d '\r' > "$OUT/pstore/$f" 2>/dev/null
    done
fi
NONEMPTY=$(find "$OUT/pstore" -type f -size +0c 2>/dev/null | wc -l)

say "  --- 2d. the actual criterion ---"
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

VERDICT=""
if [ "$HITS" -gt 0 ]; then
    VERDICT="PANIC"
elif [ "$N_READABLE" -eq 0 ] && { [ "$N_UNREADABLE" -gt 0 ] || [ "$LS_DENIED" = 1 ] || [ -z "$LS_OUT" ]; }; then
    VERDICT="UNREACHABLE"
elif [ "$NONEMPTY" -gt 0 ]; then
    VERDICT="CONTENT"
elif [ "$N_READABLE" -gt 0 ]; then
    VERDICT="EMPTY"
else
    # ls worked, no file present, nothing readable: reachable and genuinely bare
    VERDICT="EMPTY"
fi

echo
case "$VERDICT" in
PANIC)
    say "  ⇒ VERDICT: PANIC.  A fault marker is in the reserved region, which means"
    say "    panic() ran kmsg_dump(KMSG_DUMP_PANIC) before the reset. The marker above"
    say "    names the site.  This is independent of how the box came back up." ;;
UNREACHABLE)
    say "  ⇒ VERDICT: CHANNEL UNREACHABLE — says NOTHING about panic."
    say "    ls_denied=$LS_DENIED  readable=$N_READABLE  unreadable=$N_UNREADABLE  getenforce=$ENF"
    say "    Either SELinux is enforcing (run W1 for Permissive and re-run this"
    say "    script IMMEDIATELY), or the files are DAC-restricted to root."
    say "    ⛔ Do NOT record this as 'pstore empty' and do NOT let it support any"
    say "       'no panic' claim. 铁律 8." ;;
EMPTY)
    say "  ⇒ VERDICT: REACHABLE and EMPTY — no panic in this boot."
    say "    Reachable means the directory listed and at least one record name was"
    say "    stat-able (or the directory was listable with nothing in it), so this is"
    say "    a reading, not a denial.  Confirm ramoops is registered (2a) and that"
    say "    BASELINE mode reached the same state at least once, or an empty reading"
    say "    could still be this device's normal shape." ;;
CONTENT)
    say "  ⇒ VERDICT: pstore has CONTENT but no fault marker. Read it — it is the"
    say "    console tail, i.e. the last thing the kernel said before it went." ;;
esac
echo

if [ "$BASELINE" = "1" ]; then
    say "=== BASELINE MODE ==="
    say "  This run was for the NULL TEST only: a clean reboot with no exploit"
    say "  activity. It answers one question — can this channel produce anything at"
    say "  all on this device, at this SELinux state, at this timing?"
    case "$VERDICT" in
    UNREACHABLE) say "  ⇒ The channel is NOT usable. Every later 'empty pstore' must be"
                 say "    reported as UNREACHABLE, never as evidence of absence." ;;
    *)           say "  ⇒ The channel IS usable at getenforce=$ENF. An empty reading"
                 say "    afterwards is therefore a real reading." ;;
    esac
fi

# ---------------------------------------------------------------- 3. dmesg
say "=== 3. dmesg (readable only in Permissive; may legitimately be empty) ==="
A 'dmesg 2>/dev/null | grep -a -i -E "kernel BUG|BUG: |Unable to handle|Internal error|Kernel panic|Call trace|ROOTCHECK" | tail -20' \
  | tr -d '\r' | sed 's/^/  /'
A 'dmesg 2>/dev/null | tail -5' | tr -d '\r' | sed 's/^/  tail: /'

say "=== artifacts in $OUT ==="
printf '%s\n' "$VERDICT" > "$OUT/verdict.txt"
ls -la "$OUT" "$OUT/pstore" 2>/dev/null | sed 's/^/  /'
say "verdict recorded: $OUT/verdict.txt = $VERDICT"
