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

---

## 8. Attempt 3 — `run7_0542.log` (2026-09-18 05:42 → 05:50): **no reboot**

First run of the rewritten runner. Full sequence completed.

| time | event |
|---|---|
| 05:43:01 | already Permissive — W1 skipped entirely |
| 05:43:02 | host-side `dmesg` poll started (`/dev/kmsg` unreadable, see §9) |
| 05:43:31 | LT leak **OK**: `task=0xffffff87d9382500 child_pid=9708` |
| 05:43:34 | one shot `0x778` → Uid stayed `2000 2000 2000 2000` → recorded, not aborted |
| 05:45:09 | **machine alive: yes** |
| 05:45:09 | one shot `0x780` → Uid unchanged |
| 05:46:30 | one shot local repair → Uid unchanged |
| 05:47:59 | verdict: cred did not take |
| 05:48:04 | poke → child reports `iter=11 uid=2000 caps=0 capeff=0x0` |
| 05:48:05–05:49:50 | 60 s watch: `services=5/5` at every sample, uptime 2629 → 2716 monotonic |
| 05:49:52 | kernel log: **799 212 lines**, guard markers **0**, reboot/panic markers **0** |

The only `watchdog` lines anywhere in the capture are routine
`kick-init-watchdog` / `[init_watchdog]init process is alive` heartbeats.

**What this does and does not say.** It does say: three shots were fired with a
sprayed-heap `write_value` and the machine did not reboot, and the guard did not
report. It does **not** say "a landed sprayed-page write is safe", because **no
write landed** — `Uid:` stayed `2000 2000 2000 2000` through all three, and the
child's own `getuid()` was still 2000. With one shot per offset and a per-shot
hit rate well under 1, missing is the expected outcome; the earlier successful
`0x778` writes in this project took 3–8 rounds.

**So the reboot question is still open**, but its shape has changed: runs 3 and 4
rebooted *while also missing* (their readbacks never moved either), so the reboot
was never correlated with a landed write. The deliberate differences in this run
were the runner changes — no `SIGKILL`, `V12_PIN_FORK=1`, `V12_CHAIN_WAIT_MS=4000`,
and **`V12_NODRAIN=1`, which removes the `slab_drain()` storm (5 waves × 400
forked children, each `pause()`d then killed) from the start of every W7
invocation**. That last one is the most load-heavy difference and therefore the
obvious single-variable test: repeat this exact run with `V12_NODRAIN` unset.
Two runs and one non-reboot do not establish a cause; this is a candidate.

## 9. `/dev/kmsg` is unreadable here — the stream method does not work

Measured with SELinux already Permissive:

```
$ head -c1 /dev/kmsg     ->  head: /dev/kmsg: Permission denied
$ dmesg | wc -l          ->  21143
```

So `adb exec-out cat /dev/kmsg`, the natural "stream it to the host" recipe, is
not available on this device, and `dmesg -w` is a no-op anyway (§3). The runner
now probes `/dev/kmsg` and falls back to polling `dmesg` **from the host**, one
adb round per 2 s, writing only the delta. Running the poll on the host is the
point: each round's output is on host disk before the next round starts, so the
lines before a reboot survive it — which one long-lived `adb shell` stream would
not. §6 of `notes.md` carries the same correction.

One side effect worth knowing: the poll appends the whole buffer on its first
round, so the file is much larger than the ring buffer (73 MB / 799 k lines for a
5-minute run). Only the extracts are committed.
