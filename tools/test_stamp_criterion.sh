#!/bin/bash
# ============================================================================
# test_stamp_criterion.sh — host-side regression test for run_bootA.sh's
# 0x778 landing criterion.
#
# Why this exists
# ---------------
# The criterion had an awk off-by-one (`$3` = euid instead of `$4` = suid).  It
# made stamp_ok() return "no stamp" for a shot that landed, which silently gated
# off step 6 and the launder gate.  Nothing raised an error, because "no stamp"
# is ALSO the normal result of a genuine miss -- so the run just quietly did
# nothing and the operator would have gone looking for a hit-rate problem.
#
# That class of failure (probe_state, `dmesg -w`, the empty klog, the blank
# readback) always presents as "nothing happened", and "nothing happened" is a
# legitimate experimental outcome.  A self-test against a known-positive sample
# is the only thing that breaks the loop, so it is wired into preflight and
# backed by this regression test.
#
# It extracts the REAL functions out of run_bootA.sh (no re-implementation --
# a test that re-implements the check proves nothing) and drives them with the
# measured values from out/t5_w7_778.txt / evidence/notes.md §11.
#
# Usage:  bash tools/test_stamp_criterion.sh [path-to-run_bootA.sh]
# ============================================================================
set -u

SCRIPT=${1:-}
if [ -z "$SCRIPT" ]; then
    # find run_bootA.sh relative to wherever this is run from: workspace root,
    # repo root, or the repo's tools/ directory.
    for c in delivery/ghostlock-pfem10/run_bootA.sh run_bootA.sh ../run_bootA.sh; do
        [ -f "$c" ] && { SCRIPT=$c; break; }
    done
fi
[ -n "$SCRIPT" ] && [ -f "$SCRIPT" ] || { echo "cannot find run_bootA.sh"; exit 2; }

pass=0; fail=0
ok()   { pass=$((pass+1)); printf '  ok   %s\n' "$1"; }
bad()  { fail=$((fail+1)); printf '  FAIL %s\n' "$1"; }

# --- extract the functions under test, verbatim, from the real script --------
# Everything from uid_suid_field through the end of stamp_selftest.
start=$(grep -n '^uid_suid_field()' "$SCRIPT" | cut -d: -f1)
end=$(grep -n '^alive()' "$SCRIPT" | cut -d: -f1)
[ -n "$start" ] && [ -n "$end" ] || { echo "cannot locate the criterion functions"; exit 2; }
eval "$(sed -n "${start},$((end-1))p" "$SCRIPT")"

# stub the /proc readers so stamp_ok can be driven with synthetic lines
UID_LINE=""; GID_LINE=""
uid_line() { printf '%s' "$UID_LINE"; }
gid_line() { printf '%s' "$GID_LINE"; }

WT=0xffffff8800cdd178           # measured: out/t5_w7_778.txt
HI=4294967176                   # 0xffffff88  -> the Uid: line's 4th awk field
LO=13488504                     # 0x00cdd178  -> the Gid: line's 2nd awk field

echo "=== 1. field extraction (the off-by-one) ==="
got=$(uid_suid_field "Uid: 0 0 4294967176 0")
[ "$got" = "$HI" ] && ok "Uid 4th awk field = $got (= suid = hi32)" \
                   || bad "Uid 4th awk field = $got, expected $HI"
got3=$(printf '%s' "Uid: 0 0 4294967176 0" | awk '{print $3}')
[ "$got3" != "$HI" ] && ok "old \$3 = $got3 != $HI  (the bug reproduced: euid, not suid)" \
                     || bad "old \$3 == hi32 -- the regression is not what we think it is"
got=$(gid_gid_field "Gid: 13488504 0 0 0")
[ "$got" = "$LO" ] && ok "Gid 2nd awk field = $got (= gid = low32)" \
                   || bad "Gid 2nd awk field = $got, expected $LO"
# tab-separated input, as the device actually emits it before tr
got=$(uid_suid_field "$(printf 'Uid:\t0\t0\t4294967176\t0')")
[ "$got" = "$HI" ] && ok "tab-separated input handled" || bad "tab-separated input -> $got"

echo "=== 2. stamp_selftest() ==="
if stamp_selftest; then ok "stamp_selftest passes"; else bad "stamp_selftest FAILS"; fi

echo "=== 3. stamp_ok() three states ==="
UID_LINE="Uid: 0 0 $HI 0"; GID_LINE="Gid: $LO 0 0 0"
stamp_ok 1 "$WT"; rc=$?
[ "$rc" = 0 ] && ok "stamped page  -> rc=0 (PRESENT)" || bad "stamped page -> rc=$rc, expected 0"

UID_LINE="Uid: 2000 2000 2000 2000"; GID_LINE="Gid: 2000 2000 2000 2000"
stamp_ok 1 "$WT"; rc=$?
[ "$rc" = 1 ] && ok "unprivileged  -> rc=1 (NO stamp)" || bad "unprivileged -> rc=$rc, expected 1"

# the dangerous one: a DIFFERENT page that also has uid 0.  uid half passes,
# gid half must fail -> rc=1, which is what makes the gate catch "both landed,
# different pages".
UID_LINE="Uid: 0 0 0 0"; GID_LINE="Gid: 0 0 0 0"
stamp_ok 1 "$WT"; rc=$?
[ "$rc" = 1 ] && ok "other uid-0 page -> rc=1 (gid half catches it)" \
              || bad "other uid-0 page -> rc=$rc, expected 1 (uid half alone is not enough)"

UID_LINE=""; GID_LINE=""
stamp_ok 1 "$WT"; rc=$?
[ "$rc" = 2 ] && ok "empty read    -> rc=2 (UNREADABLE, not 'no stamp')" \
              || bad "empty read -> rc=$rc, expected 2 (铁律 8)"

UID_LINE="Uid: 0 0 $HI 0"; GID_LINE=""
stamp_ok 1 "$WT"; rc=$?
[ "$rc" = 2 ] && ok "half-empty    -> rc=2 (UNREADABLE)" || bad "half-empty -> rc=$rc, expected 2"

stamp_ok 1 ""; rc=$?
[ "$rc" = 2 ] && ok "no write_target -> rc=2 (UNREADABLE, cannot judge)" \
              || bad "no write_target -> rc=$rc, expected 2"

echo "=== 4. the lo32/hi32 split is the whole point ==="
# T+0x778 and T+0x780 differ by 8, so two different pages cannot both match.
W1=0xffffff8800cdd178; W2=0xffffff8800cdd180
printf '  (T+0x778 lo=%s  T+0x780 lo=%s  differ by %s)\n' \
    "$((W1 & 0xffffffff))" "$((W2 & 0xffffffff))" "$(( (W2 & 0xffffffff) - (W1 & 0xffffffff) ))"
UID_LINE="Uid: 0 0 $HI 0"; GID_LINE="Gid: $((W2 & 0xffffffff)) 0 0 0"
stamp_ok 1 "$WT"; rc=$?
[ "$rc" = 1 ] && ok "page written for T+0x780 does not satisfy T+0x778's stamp" \
              || bad "cross-page stamp matched -- the gate would pass a divergent pair"

echo
echo "passed=$pass failed=$fail"
[ "$fail" = 0 ] || exit 1
