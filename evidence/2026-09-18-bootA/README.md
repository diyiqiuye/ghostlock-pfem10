# Boot A — first device run, 2026-09-18

One boot, one question: with the private sprayed cred page and **no execve**,
does the framework survive? Answer: **the question was not reached.** Both
attempts ended with the device rebooting, and in neither of them did a
credential write take effect.

Raw logs in this directory. Read this file first.

---

## 0. What was being tested

`V12_NO_EXEC=1` (reach uid=0, then only report + sleep — experiment 8.4), with
the fake cred in the sprayed page instead of the global `init_cred` (9.0), and
no `execve` of any `/data` path (9.1). `V12_CRED_VALUE_OFF=0` explicitly.
`V12_ALLOW_INIT_CRED` deliberately unset. No module load, no ksud.

## 1. Attempt 1 — `run3_0445.log`

| time | event |
|---|---|
| 04:46:04 | already Permissive (carried over) — W1 skipped |
| 04:46:08 | kernel-log capture started (see §3 — it was blind) |
| 04:46:33 | LT leak OK: `task=0xffffff8798ed0000 child_pid=11758` — inside the accepted direct-map window |
| 04:46:34 | `0x778` → `probe_state=R` → miss |
| 04:47:27 | `0x780` → `probe_state=D` → miss |
| 04:48:18 | local repair → `probe_state=R` → miss |
| 04:49:02 | readback: `Uid: 2000 2000 2000 2000`, `CapEff: 0000000000000000` |
| 04:49:05 | poke attempt: `device not found` — **the device was already gone** |
| 04:50:24 | device back, `uptime=43`, framework `5/5`, `kernelsu=0` |

`ro.boot.bootreason = reboot` — an **orderly reboot, not a panic**. New
`boot_id`. All three writes reported miss, and the target's uid never moved, so
**nothing about the cred was actually tested.**

## 2. Attempt 2 — `run4_0500.log` (after fixing the runner)

| time | event |
|---|---|
| 05:00:47 | preflight: Permissive, uptime 11 min, load 3.5 |
| 05:01:22 | LT leak OK: `task=0xffffff8995550000 child_pid=5350` |
| 05:01:24 | `0x778` round 1 → miss |
| 05:02:13 | `0x778` round 2 → miss |
| 05:03:15 | `0x778` round 3 started |
| ~05:03:20 | **device dropped mid-round** |

So both reboots happened **inside the `0x778` write sequence**. Two data points
is not a diagnosis, but it is the pattern to chase.

## 3. The capture method was wrong — `dmesg -w` is a no-op on this device

toybox's `dmesg` **ignores `-w`**: it dumps the buffer once and exits. Measured
directly:

```
$ setsid nohup dmesg -w > /data/local/tmp/wtest.txt 2>&1 </dev/null &
$ sleep 6; wc -c /data/local/tmp/wtest.txt
1575072        # and it never grows again
```

Consequence: attempt 1's "kernel log" contains **only the history that was
already in the ring buffer when the capture started**. Its last line converts to
wall time **04:45:54**, eleven seconds *before* the capture was launched at
04:46:05. It holds **zero** incident data.

**So "there is no `[ROOTCHECK-*]` in the log" is not evidence of anything.** It
was a blind capture. This is the single most important correction from this
session, because it is exactly the mistake that would otherwise be read as
"no report was made".

Two further reasons the device-side file is the wrong place for a kernel log:

* the ring buffer is gone after a reboot, so a device-side file is the only copy
  — and the interesting event *is* the reboot;
* after one of these events the files in `/data/local/tmp` become
  **SELinux-denied to shell** (`ls -la` shows `-????????? ? ? ? ? ?`, `stat`
  itself is refused, and even `rm`/`mv` fail). The previous boot's log could
  only be read after re-reaching Permissive.

**Correct method — poll, and stream to the host, never to the device:**

```bash
# host side; the delta is computed from the previous line count
adb shell 'n=0; while :; do dmesg > /data/local/tmp/_k.tmp; \
  c=$(wc -l < /data/local/tmp/_k.tmp); [ "$c" -lt "$n" ] && n=0; \
  tail -n +$((n+1)) /data/local/tmp/_k.tmp; n=$c; sleep 2; done' >> klog.host &
```

`evidence/notes.md` §6 has been updated to this.

## 4. `probe_state` is not a "did it land" signal

From the W1 pass in the same session:

```
probe_state    = R
probe_done     = 0
enforce read   = 0 value='0'
★ W1 SELinux disabled (enforcing byte == 0)
```

The write **landed** (`enforcing` really did go to 0) while `probe_state`
reported `R`. The same pattern appears in attempt 2's `0x778` rounds:
`probe_state = R`, `probe_done = 0`, and then `HOLD 600s` — the probe simply did
not complete inside the chain wait.

**The judge has to be the target's own readback** (`/proc/<pid>/status`), not
`probe_state`. In attempt 1 the readback said `uid=2000`, so those writes really
did not take — but that conclusion comes from the readback, not from the miss.

## 5. What is confirmed working

* `V12_CRED_VALUE_OFF` now defaults to **0**, and the on-device evidence shows it:
  `write value = private cred page 0xffffff8787aaade0 (+0 shape comp)`.
* `V12_HOLD_SEC` pins the payload page: `W7[W7] HOLD 600s (payload page pinned)`.
* The LT leak works and lands inside the accepted window.
* The `init_cred` refusal does not obstruct the normal path.

## 6. Still unexplained, and not claimed

* **Why the device reboots.** `bootreason=reboot` both times — orderly, no
  panic, no BUG, no Call trace, framework healthy afterwards. The two available
  kernel logs are either blind (attempt 1) or never pulled (attempt 2, the
  device was unreachable and Enforcing afterwards). **No cause is established.**
* Whether `SIGKILL`ing a miss mid-pass contributes. Attempt 1 did no killing and
  still rebooted, so it is not the sole factor — but that is the extent of what
  two runs support.
* `audit: audit_lost=56541 audit_rate_limit=5` in the earlier boot means SELinux
  denials are dropped; "no `avc` line" is likewise not evidence.

## 7. Next

Re-run with the capture streaming to the host (§3) so that a reboot still leaves
the kernel side on the host disk. Nothing else in the plan changes.
