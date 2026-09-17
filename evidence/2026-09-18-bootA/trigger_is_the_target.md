# The trigger is the WRITE TARGET, not the chain and not the landing

Run 12 changed exactly one thing: `EXTRA=V12_W7_MIMIC_W1=1`, which makes the W7
pass write to the global `selinux_enforcing` instead of `task+0x778`.  Same
binary, same chain, same victim, same CHAINWAIT=6000, same NODRAIN=1, same
capture.

```
[w778r1] ONE shot: off=0x778 chainwait=6000ms hold=600s nodrain=1
  W7[W7] write_value = 0xffffff87b7368100
  W7[W7] write_target= 0xffffff802aa793c8      <- selinux_enforcing alias
  probe_state    = D                            <- LANDED
  probe_done     = 1
  PIN child 6066 holds the payload page 600s
  victim readback NOW: [Uid: 2000 2000 2000 2000]
watch 120s: t+5s .. t+120s  services=5/5  uptime 1048 -> 1338 monotonic
klog.host: 5037 lines, 5037 unique.  guard markers 0.  reboot markers 0.
```

## The table that matters

| what was written | chain completed | write landed | reboot |
|---|---|---|---|
| `selinux_enforcing` (W1, CHAINWAIT=20000) | yes (`probe_state=D`, `probe_done=1`) | yes (`enforce=0`) | **no** - runs 8, 10, 11 |
| `selinux_enforcing` (W7 pass, MIMIC_W1) | yes (`D`) | yes | **no** - run 12 |
| `task+0x778` or `task+0x780` | yes (`D`) | yes | **YES** - run 3 (0x780), run 9 (0x780), run 10 (0x778) |

Four independent instances of "chain completed + write landed on a global -> no
reboot", against three of "chain completed + write landed on task+0x778/0x780 ->
reboot".  Run 11 is the only unclassified case (its 0x778 round 1 was R and
round 2 died ~2 s after launch, so its state was never printed; a write can land
before the state is printed, so it is consistent either way).

## Ruled out, each by a specific run

| hypothesis | killed by |
|---|---|
| the slab_drain() fork storm | run 11 (NODRAIN=1, still rebooted) |
| the chain walking to completion | W1 evidence files: chain completed at CHAINWAIT=20000 and landed, three times, no reboot; run 12 the same at 6000 |
| the sprayed cred page being FREED while referenced | run 10 (pin child held it 7200 s, write landed, box still went down ~20 s later) |
| the SIGKILL of a mid-protocol writer | runs 9/10/11/12 kill nothing |
| the capture method | runs 8/9/10/11/12 all used the deduped host-side poll |
| CHAINWAIT itself | it only ever tracked whether a write happened to land; run 9/11's 0x778 show probe_done=0, i.e. those chains did not complete either, so R meant the same thing at 4000 and 6000 |

## So: pointing a live task's cred at a sprayed page is what reboots the box

Not the chain, not the landing, not the page's lifetime.  Mechanism still NOT
established: the reboot is orderly (no panic, no BUG, no Call trace,
`bootreason=reboot`) and delayed by a variable 20-95 s, which is the signature of
kernel damage that a watchdog or hung task eventually acts on.

## The measurement that would pin it down, and was lost twice

When a 0x778 write lands, the side effect puts `write_target` at `cred+8`, so
`/proc/<pid>/status` must read

    Uid:  0  0  <write_target >> 32>  0        and   Gid first field = <write_target & 0xffffffff>

That single line validates three things at once: that the write landed, that
`g_cred_copy_addr` really is the page the task now points at (the pin only proves
*some* page was pinned - where the second socketpair's skb actually landed is
never read back), and the side-effect model.  run 10 (predicted
`0xffffff88` / `0xd0745178`) lost it to a 45 s evidence read; the runner now
reads the victim immediately after each shot and streams `uid.trace` throughout.
