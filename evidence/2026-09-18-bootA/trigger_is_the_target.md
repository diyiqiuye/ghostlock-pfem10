# The three cells — and the one I left out

> **Superseded in part.** An earlier revision of this file concluded "the trigger
> is the write TARGET (task cred vs global)". That is incomplete: it compared
> only two of three cells, and it treated run 13 as a landing (it was not
> measurable). Both are corrected below.

## The table that matters

| # | `write_target` | `write_value` | landed | reboot | evidence |
|---|---|---|---|---|---|
| 1 | global `selinux_enforcing` | `base+0x100` (own sprayed page) | yes | **no** | W1 rounds of runs 10, 11, 12; run 12's W7 pass with `MIMIC_W1` |
| 2 | `task+0x778` | **`init_cred` P0 alias (permanent)** | yes | **no** | `out/t5_w7_778.txt` (09-14): the run continued through ksud late-load, `kernelsu ... Live`, manager alive 120 s |
| 3 | `task+0x778` / `task+0x780` | **`g_cred_copy_addr` (sprayed page)** | yes | **YES** | runs 9 (`0x780`), 10 (`0x778`) |

**Cells 2 and 3 have the same target and the same landing. The only thing that
differs is the identity of `write_value`.**

Cell 2's landing is not an assumption — the side-effect fingerprint is in the
capture:

```
in[0]=0xffffff802a7e0be0  (write_value = init_cred P0 alias)
in[2]=0xffffff8800cdd178  (write_target = child_task+0x778)
Uid:  0  0  4294967176  0     <- suid = 0xffffff88 = write_target >> 32
```

`4294967176` is exactly the high half of the write target, i.e. the side effect
landed at `cred+8` as modelled. So the write landed, and that run did not reboot.

⇒ **The discriminating quantity is whether the page installed as a live cred
pointer outlives the task pointing at it** — not the target, not the landing, not
the chain.

## What killed the earlier "target" framing

**run 13's `landed = NO` was an over-read, twice.**

1. **Not enough time.** Every measurable pass in the corpus takes 35–45 s from
   launch to evidence (run 12: 36 s twice; run 9: 37/39 s; run 10: 45 s), of which
   8.5 s is fixed (probe delay 2.5 s + chain wait 6 s) and the rest is spray. Run
   13 fired at 06:56:29 and was unreachable by 06:56:54 — **+25 s, shorter than
   the shortest pass ever measured**. And unreachability is an upper bound: the
   box was already gone at that instant. The write very likely had not happened
   yet. **The state is `unknown`, not `NO`.**
2. **The instrument had a constructive blind spot.** `uid.trace` reads
   `/proc/<pid>/status`, which is **`real_cred`** (`get_task_cred()` loads
   `task+0x778`). A `0x780` landing is invisible to it — its output is
   byte-identical to "nothing happened". And run 13 never poked at all (its
   second shot was fired 97 s after the box was dead).

So run 13 does not refute the lifetime reading; it is simply unclassified.

## Also corrected

* **run 8 does not belong in cell 1.** Run 8 was `already Permissive — skipping
  W1 entirely`, so it has no W1 round. Cell 1's `CHAINWAIT=20000` instances are
  the W1 rounds of runs **10, 11, 12**.

## A lead one `getprop` produced

```
persist.sys.oplus.total_abnormalreboot_count        : total_17_dump_0_pmic_17
persist.sys.oplus.total_abnormalreboot_count_neras  : total_17_dump_0_pmic_17
```

OPPO's own counter classifies these as **abnormal** reboots, **17** of them,
attributed to **`pmic`**, with **0 crash dumps**. And the four
`persist.sys.boot.reason.history` entries are plain `reboot` with **no `,shell`
suffix** — earlier entries in that history did carry suffixes (`reboot,shell`,
`bootloader`, `reboot,edl`), so a shell actor is distinguishable and is not
present here.

A PMIC-attributed reset with no dump is consistent with everything else: no
panic, no BUG, no Call trace, nothing in the capture, and an orderly-looking
`bootreason`. **Not established** — but the counter is cheap to re-read after the
next reboot, and if it increments then the reboots are PMIC resets and the
mechanism is power/hardware rather than a kernel fault path.

## Next shot: switch cells, not chain waits

Shape A at `CHAINWAIT=4000` is a low-information cell — shape A has never
rebooted at 20000 or 6000, and 4000 only makes the pass return early. The
high-information cell is **cell 2**, which the code already supports:

```bash
CONTROL=1 HOLD=600 ROUNDS=1 CHAINWAIT=6000 NODRAIN=1 WATCH=180 ./run_bootA.sh
```

* lands and does not reboot within 180 s ⇒ the lifetime reading holds, and it
  forms a perfect single-variable pair with cell 3;
* lands and still reboots ⇒ the target slot itself is the trigger and the
  lifetime reading is out.

**Instruments first**, or it is another "landed but nobody looked".
