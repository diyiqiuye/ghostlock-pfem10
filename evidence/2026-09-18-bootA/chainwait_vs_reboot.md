# Boot A - every boot that fired a shot, re-tabulated

| run | time | CHAINWAIT | drain | 0x778 | 0x780 | reboot |
|---|---|---|---|---|---|---|
| run 3 | 04:45 | default 20000 | ON (not set) | R | D | YES |
| run 4 | 05:00 | default 20000 | ON (not set) | ? | - | YES |
| run 7 | 05:42 | 4000 | OFF | R | R | no |
| run 8 | 05:56 | 4000 | OFF | R | R | no |
| run 9 | 06:06 | 6000 | ON | R | D | YES |
| run 10 | 06:16 | 6000 | ON | D | - | YES |
| run 11 | 06:24 | 6000 | OFF | R | ? (died ~2s after launch) | YES |

## What each run excludes

| hypothesis | killed by |
|---|---|
| the slab_drain() fork storm | **run 11** - NODRAIN=1 and it rebooted anyway (and runs 7/8, also NODRAIN=1, did not) |
| the sprayed cred page being FREED while referenced | **run 10** - the pin child held the page for 7200 s (`PIN child 30688 holds the payload page 7200s`), the write landed, and the box still went down ~20 s later |
| the SIGKILL of a mid-protocol writer | runs 9/10/11 never kill anything, and all three rebooted |
| the capture method | runs 8/9/10/11 all used the deduped host-side poll; 9/10/11 rebooted |

## What is left, and it is cleaner than 'the write landed'

| CHAINWAIT | boots | reboots |
|---|---|---|
| 4000 (pass returns BEFORE the chain finishes) | run 7, run 8 - 5 shots total | **0** |
| 6000 | run 9, run 10, run 11 | **3** |
| 20000 (code default) | run 3, run 4 | **2** |

So the reboot tracks whether the PI chain WALK RAN TO COMPLETION, not whether
the write landed.  That also explains why probe_state=D looked like the
predictor: D can only be printed once the pass has finished, so 'D' and
'the chain completed' coincide.  And it explains the run 11 anomaly - its
round 1 was R, but with CHAINWAIT=6000 that R means 'finished and missed',
not 'cut short'; the box went down 95 s later, consistent with the delayed
reboots seen in run 9 (60 s) and run 10 (20 s).

**probe_state=R is therefore ambiguous and must always be read together with
CHAINWAIT**: with a long enough wait R means 'the chain ran and the reclaim
missed'; with a short wait it only means 'the pass gave up early'.

NOT ESTABLISHED: the mechanism.  The delayed, orderly nature (no panic, no
BUG, no Call trace, `bootreason=reboot`) and the variable 3-95 s delay point
at kernel damage that a userspace watchdog or a hung task eventually acts on,
but nothing in the capture says so.
