# probe_state vs reboot — the correlation across every boot with a shot

| run | 0x778 | 0x780 | write_value identity | reboot |
|---|---|---|---|---|
| run 3 (04:45) | R | **D** | sprayed page | **YES** (~3 s after readback) |
| run 4 (05:00) | ? (state never printed; device died mid-round) | — | sprayed page | **YES** |
| run 7 (05:42) | R | R | sprayed page | no |
| run 8 (05:56) | R | R | sprayed page | no |
| run 9 (06:06) | R | **D** | sprayed page | **YES** (~60 s after landing) |
| t5_w7_778 (09-14) | **D** | — | **init_cred image** | **no** (run continued; full chain + 120 s manager test) |

probe_state semantics for W7 (docs/28; tools/t5loop.sh line 11):
  D = the write LANDED, R = it did not, S = blocked/[7] passed.
  The exploit's own printout calls only S a HIT, so it prints "miss" on the
  runs that landed.  Reading that line instead of probe_state is what made an
  earlier reading of runs 3/4 ("rebooted while also missing") wrong.

=> reboot correlates with a LANDED write, not with NODRAIN, not with the
   SIGKILL, not with the capture.
=> and the landed sprayed-page writes rebooted while the landed init_cred
   write did not: the differing variable is the IDENTITY of write_value.

Candidate mechanism (NOT established): the sprayed cred page is freed while
the target task still points cred/real_cred at it.  run 3 had no hold at all
and rebooted ~3 s after the readback; run 9 held 20 s and rebooted ~60 s
after landing.  init_cred is a permanent object.  Single-variable test:
repeat run 9 with HOLD=600 instead of 20 and change nothing else.
