# The three cells — and the one I left out

> **Superseded in part.** An earlier revision of this file concluded "the trigger
> is the write TARGET (task cred vs global)". That is incomplete: it compared
> only two of three cells, and it treated run 13 as a landing (it was not
> measurable). Both are corrected below.

## The table that matters

| # | `write_target` | `write_value` | landed | reboot | evidence |
|---|---|---|---|---|---|
| 1 | global `selinux_enforcing` | `base+0x100` (own sprayed page) | yes | **no** | W1 rounds of runs 10, 11, 12; run 12's W7 pass with `MIMIC_W1` |
| 2 | `task+0x778` **and** `task+0x780` | **`init_cred` P0 alias — THE SAME VALUE BOTH TIMES** | yes | **no** | `out/t5_w7_778.txt` + `out/t5_w7_780.txt` (09-14): both carry `in[0]=0xffffff802a7e0be0`; the run continued through ksud late-load, `kernelsu ... Live`, manager alive 120 s |
| 3 | `task+0x778` / `task+0x780` | **two DIFFERENT sprayed pages** | yes | **YES** | run 3 (`0xffffff8787b5ade0` vs `0xffffff881bad2de0`), run 9 (`0xffffff88679bade0` vs `0xffffff8785d6ade0`), run 10 |

**Cells 2 and 3 have the same target and the same landing. The only thing that
differs is the identity of `write_value`.**

### ★★★ and that difference is sharper than "which value": it is POINTER EQUALITY

`commit_creds()` opens with `BUG_ON(task->cred != task->real_cred)` and this
kernel has `PANIC_ON_OOPS=y`, so the two pointers must be **the same pointer**
when anything commits creds on the victim.  The comparison is on POINTERS, not
on the uid numbers behind them.

* **Cell 2 wrote one fixed address to both slots** ⇒ `real_cred == cred` ⇒ any
  later `commit_creds` (e.g. `execve` → `install_exec_creds`) is legal ⇒ ksud
  loads.  The old chain got this **by construction**: `tools/t5loop.sh` applies
  a single `$ENVV` to every offset, so `MODE=CRED` made both shots identical.
* **Cell 3 wrote two different pages** ⇒ even with both landed,
  `real_cred = pageA, cred = pageB` ⇒ divergent.  `run_bootA.sh` produced this
  unavoidably: step 5 and step 6 each fired with an empty `$extra`, so each
  sprayed its own page.

⇒ **The requirement is not "both shots land", it is "both shots write the SAME
value".**  `run_bootA.sh` now enforces this (`SAME_VALUE=1`, the default): step 6
reuses step 5's observed `write_value` verbatim, and refuses to fire at all if it
cannot recover that value.

⚠ **`HOLD` must outlive the second shot.**  If the first shot's PIN child dies
before step 6 fires, the page is freed and reallocated and "same value" becomes a
dangling pointer.  The default `HOLD=20` is **too short** for this sequence — use
`HOLD=600`.

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
high-information cell is **cell 2**, which the code now actually supports:

```bash
CONTROL=1 HOLD=600 ROUNDS=1 CHAINWAIT=6000 NODRAIN=1 WATCH=180 ./run_bootA.sh
```

* lands and does not reboot within 180 s ⇒ it forms a single-variable pair with
  cell 3 and the same-value reading holds;
* lands and still reboots ⇒ the target slot itself is the trigger.

**Instruments first**, or it is another "landed but nobody looked".

### ⛔ Correction (2026-09-18 late): `CONTROL=1` did NOT do what this file claimed

This section used to say cell 2 "is supported by the code already". It was not.
`CONTROL=1` only changed **step 5**; step 6 still fired with an empty `$extra`
and sprayed its own fresh page:

```
step 5 (0x778) → init_cred alias
step 6 (0x780) → a NEW private page          ← not init_cred
⇒ real_cred != cred ⇒ divergent pair, and step 8 pokes
⇒ any commit_creds after that is brk #0x800 under PANIC_ON_OOPS=y
```

So running the command above **as it was written would have manufactured the
divergent pair and then poked it**.  Fixed: `CONTROL=1` now sets both shots to
`V12_ALLOW_INIT_CRED=1 V12_W7_INIT_CRED=1` and logs
`[same-value] step 6 will reuse the init_cred image`.

⚠ Cell 2 works at a cost that must not be forgotten: writing the `init_cred`
pointer makes the write primitive's side effect corrupt `init_cred+8` **globally**
— `init_cred` is shared by every kernel thread, and the `Uid: 0 0 4294967176 0`
in the capture *is* that corruption.  Cell 2 is a **control**, not a target.

### ⛔ And a second correction: the divergence was NOT the reboot mechanism

An intermediate revision of the sibling report
(`delivery/验证_cred洗白与分歧_2026-09-18.md` §2.3) claimed the divergent pair
explained runs 3/9/10.  It does not:

* `commit_creds` gets its task from `current` (`0x1867a0 mrs x20, sp_el0`) — it
  only ever acts on the calling task;
* runs 3/9/10 all ran `V12_NO_EXEC=1`, so the victim never issued `execve` and
  never reached `commit_creds` at all;
* run 10 had no poke whatsoever;
* `exit_creds` nulls BOTH pointers before `put_cred`, so the victim's `_exit(0)`
  **erases** the divergence instead of tripping on it.

⇒ The divergence was **latent** in those runs.  The `BUG_ON` is real but it is a
landmine that has not gone off yet; what it actually constrains is **laundering**
(`setresuid` itself calls `commit_creds`).  See
`delivery/验证_分歧是惰性的_同值才是判据_2026-09-18.md`.

**Instruments first** — and now also: `postreboot_forensics.sh` for the
poller-independent panic check.
