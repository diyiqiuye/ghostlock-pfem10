# Reboot history (authoritative) vs what each run wrote

`persist.sys.boot.reason.history`, read at 07:00:51, epoch → local:

| reboot epoch | local | run | that run's shot(s) | write target | landed? |
|---|---|---|---|---|---|
| 1789683051 | 06:10:51 | run 9 | `0x778` R, `0x780` **D** | `task+0x778`/`0x780` | yes (0x780) |
| 1789683778 | 06:22:58 | run 10 | `0x778` **D** | `task+0x778` | yes |
| 1789684354 | 06:32:34 | run 11 | `0x778`r1 R, r2 died ~2 s in | `task+0x778` | no / unknown |
| 1789685861 | 06:57:41 | **run 13** | `0x778` R (see below) | `task+0x778` | **NO** |

**Run 12 (06:43–06:55) is NOT in the list.** Its `boot_id` `5fe2227e-…` is
identical to run 13's preflight `boot_id`, so run 12 did not reboot. The reboot
that was noticed was run 13's, at 06:57:41.

## run 13's uid.trace settles whether "landing" is required

The trace (started before the shots, 85 samples, and it **spans the reboot**)
reads `Uid: 2000 2000 2000 2000  Gid: 2000 2000 2000 2000` from 06:56:27 all the
way to **06:56:53**, and the device is unreachable from 06:56:54. The shot fired
at 06:56:29 with a 6000 ms chain wait, so by 06:56:53 the chain had long since
finished — and the cred **never moved**.

So run 13 is: shot did **not** land, and the box went down anyway (~25 s to adb
loss, reboot recorded 06:57:41). **That retracts the previous conclusion** — a
landed write to a task cred is *sufficient* (runs 3/9/10) but **not necessary**.

## What the data separates now

| shape | write_value / write_target | CHAINWAIT | instances | reboot |
|---|---|---|---|---|
| A: W1, and W7 with `MIMIC_W1` | `base+0x100` / global `selinux_enforcing` | 20000 | run 8, run 10, run 11 (their W1 rounds) | **no** |
| A: W7 pass with `MIMIC_W1` | `base+0x100` / global `selinux_enforcing` | 6000 | run 12 | **no** |
| B: W7 | sprayed page / `task+0x778` or `0x780` | 4000 | run 7, run 8 | **no** |
| B: W7 | sprayed page / `task+0x778` or `0x780` | 6000 | run 9, run 10, run 11, run 13 | **YES** |

Two things are true at once, and neither alone explains the table:

* **shape A has never rebooted**, at either chain wait (4 instances, all with
  `probe_state=D`, i.e. chain completed and write landed);
* **shape B at CHAINWAIT=6000 has always rebooted** (4/4), *whether or not the
  write landed* — runs 11 and 13 are the not-landed ones.

So the discriminator is the **shape** (or a shape × chain-wait interaction), not
the landing, and not "the target is a task cred" as such.

## Next single variable

Shape B at 4000 is 2/2 no-reboot; shape B at 6000 is 4/4 reboot. The cheapest
discriminator is therefore **shape A at CHAINWAIT=4000**:

* no reboot → the shape is the variable and CHAINWAIT was a coincidence of
  shape B;
* reboot → CHAINWAIT is real for both shapes and the shape story is wrong.

## Boundary

Every reboot is orderly (`bootreason=reboot`, no panic, no BUG, no Call trace in
any capture) and the delay from the shot to adb loss has been ~25–95 s. The
mechanism is **not** established.
