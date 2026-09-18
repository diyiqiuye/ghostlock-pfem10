# GhostLock — OPPO Find X5 Pro (PFEM10)

**English** · [中文](README.zh-CN.md)

[![build](https://github.com/diyiqiuye/ghostlock-pfem10/actions/workflows/build.yml/badge.svg)](https://github.com/diyiqiuye/ghostlock-pfem10/actions/workflows/build.yml)

GhostLock (CVE-2026-43499) port for the OPPO Find X5 Pro on ColorOS 16. Reaches a `uid=0` child process and a loaded `kernelsu.ko`; the root process is intercepted.

## Vulnerability

**CVE-2026-43499** — futex PI use-after-free. `remove_waiter()` clears `current->pi_blocked_on` when `current` is the requeuer, on the `-EDEADLK` rollback path of `rt_mutex_start_proxy_lock()`.

`remove_waiter` @ `0xffffffc0081ed254` — pre-fix shape.

## Device

| | |
|---|---|
| Device | OPPO Find X5 Pro (PFEM10) |
| SoC | SM8450 / Adreno 730 |
| OS | ColorOS 16.0.3.520 (CN01) |
| Kernel | `5.10.236-android12-9-o-gaf2075ad2c06` |
| Bootloader | locked, green |
| VA_BITS | 39 — `KIMAGE_TEXT_BASE = 0xffffffc008000000` |

## Status

| Stage | |
|---|---|
| Compact waiter trigger (`CMP_REQUEUE_PI` → `EDEADLK`) | works |
| `task_struct` leak (perf) | works |
| PI write (8-byte; value = `0` or a valid kernel address) | works |
| `task+0x778` **or** `task+0x780` alone → `Uid=root` | works — **but a single-field landing leaves the task divergent**, and that is a latent hard `BUG_ON`. See [the divergence hazard](#-a-single-field-landing-leaves-the-task-divergent--and-that-is-a-hard-bug_on) |
| **Both fields written with ONE value** (a consistent pair) | ❌ **never produced with a sprayed page.** Only ever observed with the global `init_cred` alias (09-14, `CONTROL=1`). The runner now enforces it (`SAME_VALUE=1`); **not run on device** |
| Credential laundering (`setresgid` + `setresuid`) | implemented behind `V12_LAUNDER=1`; **not run on device** |
| `kernelsu.ko` loaded | works |
| Root process survives | ⚠ **not established** — see below |
| Reboot mechanism | ❌ **not established.** One candidate (the divergence) is now *excluded*; see below |
| `probe_state` as a landing criterion | ❌ **wrong — do not use.** Three counterexamples; see the table below |
| pstore/ramoops panic channel | ⚠ instrument exists; **channel never validated** (no null test yet) |
| "The victim spins in pure userspace" | ⚠ **no reading yet** — `uid.stream` now records `utime`/`stime`/`nvcsw` so it can be checked |
| pi-side single-pass dual write | ⚠ **not established**; `pi.pc`/`pi.left` are hard-coded 0 in `fdset_map.h` |
| Path A (UMH / `modprobe_path`) | `STATIC_USERMODEHELPER_PATH=""` |

On "root process survives": the runs in [`evidence/kill.log`](evidence/kill.log)
reach `uid=0` and load `kernelsu.ko`, and in the run that actually polled for it
the KernelSU manager process **survived 120 s** with `kernelsu` still `Live` in
`/proc/modules`. In a later run the same chain left the Android framework
services unreachable (`Can't find service: package/power/input/phone/wifi`)
while the module was still `Live`. **No `[ROOTCHECK-*]` kernel line and no
`$$sys_call_number@@` payload has ever been captured**, so the cause of the
later run's state is not attributed. See [`evidence/notes.md`](evidence/notes.md)
§2.3, §2.4 and §7.

## Offsets

`task_struct`

| Field | Offset |
|---|---|
| `real_cred` / `cred` | `0x778` / `0x780` |
| cached `syscallno` | `0xdf8` |
| cached `uid` / `euid` / `gid` / `egid` | `0xe00` / `0xe08` / `0xe10` / `0xe18` |

`thread_info`

| Field | Offset |
|---|---|
| `flags` | `0x0` |
| `addr_limit` | `0x8` |
| `ttbr0` | `0x10` |
| `preempt_count` | `0x18` |

`cred`

| Field | Offset | Field | Offset |
|---|---|---|---|
| `uid` | `0x4` | `cap_inheritable` | `0x28` |
| `gid` | `0x8` | `cap_permitted` | `0x30` |
| `suid` | `0xc` | `cap_effective` | `0x38` |
| `sgid` | `0x10` | `cap_bset` | `0x40` |
| `euid` | `0x14` | `cap_ambient` | `0x48` |
| `egid` | `0x18` | | |
| `fsuid` / `fsgid` | `0x1c` / `0x20` | | |

## Exploit Flow

```
LT          perf leak target task_struct → file
W7 stage 1  task+0x778 = V    (real_cred → private sprayed page; V observed)
W7 stage 2  task+0x780 = V    (cred)   ★ V12_W7_VALUE=V — THE SAME VALUE, not a new page
W7 stage 3  V+8 = 0           (LOCAL repair of the page that was installed, ZERO shape)
LT child    fexecve(memfd of loader) — no execve of a /data path
loader      ksud late-load                  → kernelsu ... Live
```

**Stage 2 must be given stage 1's value explicitly.** Stages 1 and 2 are two
independent processes, each with its own spray, so "write the cred page to both
slots" is a trap: read naively it produces `(pageA, pageB)`, and because
`commit_creds` compares **pointers**, that pair is divergent even when both writes
land. This is not hypothetical — it is exactly what runs 3 and 9 did:

```
run 9   0x778 shot  write value = 0xffffff88679bade0
        0x780 shot  write value = 0xffffff8785d6ade0     <- a different page
run 3   0x778 shot  write value = 0xffffff8787b5ade0
        0x780 shot  write value = 0xffffff881bad2de0     <- a different page
```

`run_bootA.sh` therefore fires stage 2 with `V12_W7_VALUE=<stage 1's observed
value>` and **refuses to fire it at all** if that value cannot be recovered.
`HOLD` must outlive stage 2, or stage 1's page is freed and reallocated and "the
same value" becomes a dangling pointer. See
[the same-value rule](#-the-two-shots-must-write-the-same-value--not-merely-both-land).

**One page per boot gets repaired.** Stage 3 zeroes `V+8`. With two *different*
pages, zeroing both would erase the gid/suid stamp (below) and make a divergence
look like agreement, so the runner repairs only the page that was actually
installed and stops if the two values disagree.

The cred page is built by `payload.c`: all eight id fields zero, all five
capability sets full, and `user` / `user_ns` / `group_info` pointed at
`root_user` / `init_user_ns` / `init_groups`. Stage 3 exists because the write's
side effect always clobbers `cred+8` (`gid`/`suid`) of whatever cred it installs.

### On `init_cred` — an explicit dichotomy

Two sections here used to contradict each other ("never the global `init_cred`"
vs "`CONTROL=1` reproduces cell 2", and cell 2 *is* `init_cred`). Both statements
are true of different roles:

* **Forbidden as a target.** Writing the `init_cred` pointer makes the side effect
  corrupt `init_cred+8` **globally** — `init_cred` is shared by every kernel
  thread, and `Uid: 0 0 4294967176 0` is precisely that corruption. The code
  refuses this path unless `V12_ALLOW_INIT_CRED=1` is set deliberately.
* **Retained as the only PROVEN consistent pair.** The 09-14 chain that reached
  ksud wrote one fixed address (`0xffffff802a7e0be0`) to both slots, so
  `real_cred == cred` by construction — that is why it survived to `execve`.
  `CONTROL=1` reproduces it. It is a **control**, not a configuration to build on.

perf leak: `PERF_TYPE_SOFTWARE` / `PERF_COUNT_SW_CPU_CLOCK`, `PERF_SAMPLE_REGS_INTR`, `exclude_user=1`.
Accept `[0xffffff8400000000, 0xffffff90000000)`, votes ≥ 15%.

## The write primitive, and its side effect

The UAF is driven through `rb_erase_cached` Case 1-left. That gives **two**
stores, not one:

```
*(write_target)          = write_value      // the store you aim
*(write_value + 0x08)    = write_target     // unavoidable side effect
```

`write_value` must be 8-byte aligned with bit 0 clear — it is either `0` or a
valid kernel address. **This is why `g_boot_state` cannot be set with this
primitive**: the byte you need to become `1` has its low bit forced to `0` by
the alignment requirement, and `write_value` is the same quantity as the
address the side effect lands at.

### The side effect writes into whatever `write_value` points at

`write_value` is both *the value stored* and *the address the side effect
writes to* (at `+8`). Point it at a global kernel object and you corrupt that
object.

**W7 used to do exactly this** — aiming `write_value` at the `init_cred` alias —
and it is visible in the readback. From `out/t5_w7_778.txt`:

```
shape shift=0 wps=5: in[0]=0xffffff802a7e0be0 (write_value) in[2]=0xffffff8800cdd178 (write_target)
W7[W7] write_target= 0xffffff8800cdd178
Uid:	0	0	4294967176	0
```

`write_value` was the `init_cred` alias and `write_target` was `child_task+0x778`.
`init_cred+8` is `gid`/`suid`, so the side effect stored `0xffffff8800cdd178`
there: `init_cred.gid = 0x00cdd178` and **`init_cred.suid = 0xffffff88 =
4294967176`** — precisely the 4th awk field of the `Uid:` line above. Zeroing
`init_cred+8` repaired it (`out/t5_repair.txt`: `Uid: 0 0 4294967176 0` →
`Uid: 0 0 0 0`), which is all that "W7 stage 3" ever was.

**This path is now refused in code.** `V12_W7_INIT_CRED=1` aborts with an
explanation unless `V12_ALLOW_INIT_CRED=1` is also set, and the W2/W6/LTC paths
no longer fall back to `init_cred` when the private cred page is missing — they
abort instead. The default, and the only sane path, is the sprayed cred page.

The side effect itself cannot be avoided: `write_value` must *be* the cred
pointer, so `cred+8` is always clobbered with the write target. Only its
location is a choice — and the repair is now a **local** zero of
`cred_page+8` (stage 3), not a write into a global object.

> A garbage `groups=` readout is a **separate** symptom, not this one. It was
> seen in a run where `gid` and `egid` read back clean, so it cannot come from
> the `init_cred+8` side effect; it points at the fake cred's own `group_info`
> field. See `evidence/notes.md` §10.6.

### ★ A single-field landing leaves the task divergent — and that is a hard `BUG_ON`

The primitive stores to **exactly one** address per pass. `task+0x778`
(`real_cred`) and `task+0x780` (`cred`) are two separate addresses, so **any
landed 0x778-only or 0x780-only write leaves the task with
`cred != real_cred`** — a divergence state.

On this image that state is a **hard panic**, not a warning. `commit_creds` opens
with `BUG_ON(task->cred != task->real_cred)`:

```
commit_creds @0xffffffc008186784
  0x1867a4  ldr  x19, [x20, #0x778]      ; old = task->real_cred
  0x1867a8  ldr  x8,  [x20, #0x780]      ;        task->cred
  0x1867ac  cmp  x8, x19
  0x1867b0  b.ne #0xffffffc008186b68
  0x186b68  brk #0x800                   ; == BUG()
```

and the kernel is built with **`CONFIG_PANIC_ON_OOPS=y`** (`CONFIG_PANIC_ON_OOPS_VALUE=1`).
`__put_cred @0xffffffc008185530` carries the same family of assertions
(`usage != 0` → BUG; `cred == current->cred` / `current->real_cred` → BUG).

So the divergence is *latent* — it does nothing while the victim just spins —
until **any** `commit_creds` happens on that task: `setresuid` / `setresgid` /
`setuid` / `setgid` / `capset`, or **`execve` via `install_exec_creds`**.

> **⛔ Retracted (2026-09-18 late): this is NOT the reboot mechanism.**
>
> An earlier revision of this section called the divergence "the leading mechanism
> candidate for the reboots" and said it "explains the shape split". It does not,
> and the reason is now measured rather than argued:
>
> * `commit_creds` takes its task from **`current`** — `0x1867a0 mrs x20, sp_el0`.
>   Its signature is `commit_creds(struct cred *new)`; there is no task argument.
>   So a divergence only matters if the task **holding** it calls `commit_creds`
>   itself.
> * The rebooting runs were all `V12_NO_EXEC=1` (stated verbatim at
>   `run3_0445.log:18`, `run9_0606.log:20`, `run10_0616.log:24`), so the victim
>   never issued `execve` and never reached `commit_creds` at all.
> * Run 10 had no poke whatsoever (`grep -c poke` = 0).
> * `exit_creds` nulls **both** pointers before `put_cred`
>   (`0x185cb8 str xzr,[x19,#0x778]`; `0x185d24 str xzr,[x19,#0x780]`), so the
>   victim's `_exit(0)` **erases** the divergence instead of tripping on it.
>
> ⇒ In those runs the divergence was **inert**. The `BUG_ON` is real, but it is a
> landmine that has not gone off. "Shape A never reboots" goes back to being a
> correlation. What the landmine actually constrains is **laundering**, because
> `setresgid`/`setresuid` call `commit_creds` themselves.
>
> **The quantity that actually separates the chains is pointer equality, and that
> means the two shots must write ONE value** — see the next subsection.

### ★★★ The two shots must write the *same* value — not merely both land

`BUG_ON` compares **pointers**. Two pages that both carry `uid 0` are still two
different objects. The captures make the distinction concrete:

| chain | 0x778 shot | 0x780 shot | pointers |
|---|---|---|---|
| old (`t5loop.sh MODE=CRED`) | `in[0]=0xffffff802a7e0be0` | `in[0]=0xffffff802a7e0be0` | **equal** → ksud loaded, manager alive 120 s |
| new (`run_bootA.sh`) | `0xffffff88679bade0` (run 9) | `0xffffff8785d6ade0` | **differ** → divergent even with both landed |

`tools/t5loop.sh` applies **one** `$ENVV` to **every** offset, so `MODE=CRED`
made both shots identical *by construction*. `run_bootA.sh` fired step 5 and
step 6 each with an empty `$extra`, so each sprayed its **own** page.

⇒ The requirement is **"both shots write the same value"**. `run_bootA.sh` now
enforces it (`SAME_VALUE=1`, the default): step 6 reuses step 5's observed
`write_value` verbatim, and **refuses to fire at all** if it cannot recover that
value — because firing would build a divergent pair.

⚠ `HOLD` must outlive the second shot. If the first shot's PIN child dies first,
the page is freed and reallocated and "same value" becomes a dangling pointer.
The default `HOLD=20` is **too short**; use `HOLD=600`.

⚠ `CONTROL=1` used to change **only step 5**, so it produced
`(init_cred, fresh page)` — a divergent pair — while this file claimed it
reproduced cell 2. Fixed: it now sets both shots to `init_cred`. (Cell 2's cost
stands: the side effect corrupts `init_cred+8` globally, which is what
`Uid: 0 0 4294967176 0` is.)

**Consequences for anything that wants to launder the credential**
(`setresgid` + `setresuid`, to swap the sprayed page for a real `struct cred`):

- The mechanism is real and verified — `commit_creds` writes `x21` to **both**
  `task+0x778` and `task+0x780` (`0x186998` / `0x1869a0`), so one call repairs the
  split permanently; `prepare_creds @0xffffffc008186070` is
  `kmem_cache_alloc(cred_jar)` + `memcpy(new, task->cred, 0xA8)` +
  `security_prepare_creds(...)`, and 147/149 are both on the guard's exempt list.
- **But its precondition is the opposite of "skip the 0x778 shot".** The launder
  itself calls `commit_creds`, so it must only be issued when **both** pointers
  already hold the same value.
- `V12_LAUNDER=1` is gated on **two** things, and the first is not an observation:
  1. **`V12_W7_SAME_VALUE=1`** — the *provenance* fact that both shots were given
     the same value. With no read primitive, pointer identity is unobservable, so
     this cannot be replaced by a better userspace check; it must be declared.
  2. `consistent=1` — the `0x780` view (`getuid()`) agreeing with the `0x778` view
     (`/proc/self/status` `Uid:`). **Necessary but not sufficient on its own**:
     two distinct pages both carrying `uid 0` read equal while the pointers differ
     — which is exactly the case the runner used to manufacture. Given (1), it
     becomes sufficient: agree + same value ⇒ both landed on the same page.
  Either check failing ⇒ refuse, and the four-case table goes into the evidence.
  The LT report line prints both views (`uid=` / `real_uid=` / `consistent=`) plus
  `same_value_declared=` so the state is read, not inferred.

### ★ Instrument 1 — the side effect is a STAMP aimed at the target

`*(write_value + 8) = write_target`, and `cred+8` / `cred+0xc` are `gid` / `suid`,
so one 8-byte store lands across both:

```
cred.gid  = low32(write_target)
cred.suid = hi32(write_target)
```

That is a measurement, not a model. `out/t5_w7_778.txt` has
`write_target = 0xffffff8800cdd178` and `Uid: 0 0 4294967176 0`, where
`4294967176 = 0xffffff88 = hi32(write_target)`; `notes.md` §11 records the other
half, `init_cred.gid = 0x00cdd178 = low32(write_target)`.

Two uses:

1. **It is the landing oracle for `task+0x778`.** `/proc/<pid>/status` reads
   `real_cred` = `task+0x778` — exactly the cred just installed — so the stamp is
   directly readable from userspace. Read it **before** stage 3: the repair
   zeroes `cred+8` and erases it (`notes.md` §11's `t5_repair.txt` reads
   `4294967176` before a successful repair and `0` after).
2. **It is a second, independent reason the launder gate can catch two different
   pages.** The uid half alone cannot: any page with uid 0 reads `0`, so two
   distinct pages both report "consistent". But `low32(T+0x778)` and
   `low32(T+0x780)` differ by exactly 8, so with two pages `getgid()` (from
   `cred`) and `status_gid` (from `real_cred`) disagree — and
   `lt_cred_ids_agree()` compares gid as well as uid.

⇒ `V12_W7_SAME_VALUE` is the **second** gate, not the only one. It still matters:
the stamp only discriminates if both side effects fired, so the same-value rule
closes that residual hole. And note what a gate *is* — a detector, not a
preventer. It can only refuse; it leaves the task divergent for the rest of the
boot. The same-value rule is what makes the pair **correct**, which is what the
old chain had and what is needed to reach `execve` at all.

### ★ Instrument 2 — `probe_state` is NOT a landing criterion

It has been wrong three times in this project: W1 landed on the global and
reported `R`; run 12's `D` was aimed at a global rather than at a cred; and run
11's `R` was written into a table as if it were a landing
(`run11_w778r1_miss.txt` and run 7's `w7_w7781.txt` are line-for-line
isomorphic — both `probe_state = R`, `probe_done = 0`). Use a per-target oracle:

| target | landing oracle |
|---|---|
| `task+0x778` | `Uid:` **4th awk field** `= hi32(write_target)` **and** `Gid:` **2nd awk field** `= low32(write_target)` — the stamp above; **read before stage 3** |
| `task+0x780` | the victim's own `getuid()` |
| global `selinux_enforcing` | `getenforce` |
| `probe_state` | ❌ **not a criterion.** A hint about the chain at best; never evidence that a write landed |

`run_bootA.sh` now uses the stamp for stage 1 — which is what makes `ROUNDS>1`
retries on `task+0x778` meaningful, since a failed round is *readable* instead of
inferred — and it will not fire stage 2 unless stage 1 landed.

> ⛔ **Say "awk field", never "3rd field".** `uid_line` prints the label too
> (`Uid: 0 0 4294967176 0`), so awk's `$1` is `"Uid:"` and the four id values are
> `$2..$5`: `$2`=uid `$3`=euid **`$4`=suid** `$5`=fsuid. The stamp sits at
> `cred+8`, i.e. `gid` (low32) and `suid` (hi32) — so it is `Gid:` `$2` and
> `Uid:` **`$4`**. Calling it "the third field" (which counts *values*, and is how
> `notes.md` §11 words it) invites the code to read `$3`, which is `euid` = `0` on
> the fake cred and can never equal `hi32(write_target)`. That off-by-one was
> present here: `stamp_ok()` returned "no stamp" for a shot that landed, so stage 2
> never fired and the launder gate refused forever — **with no error anywhere**,
> because "no stamp" is also the normal result of a genuine miss.

**A criterion that is never tested against a known-positive sample is not a
criterion, it is a guess** — and this class of failure (this off-by-one,
`probe_state`, `dmesg -w`, the empty `klog.host`, the blank readback) always
presents as *"nothing happened"*, which is also a legitimate experimental outcome.
So the check is now defended twice:

* **`stamp_selftest()`** runs in preflight and `exit 9`s on failure, driving the
  *same* extraction functions the gate uses against the measured values from
  `out/t5_w7_778.txt` (`write_target = 0xffffff8800cdd178` → `Uid` `$4` =
  `4294967176`, `Gid` `$2` = `13488504`) plus negative and unreadable samples.
  A self-test that re-implements the check proves nothing, so the field
  extraction is factored into `uid_suid_field` / `gid_gid_field`.
* **[`tools/test_stamp_criterion.sh`](tools/test_stamp_criterion.sh)** — the
  same thing as a standalone regression test, extracting the real functions out
  of `run_bootA.sh`.

`stamp_ok()` returns **three** states, because "cannot read" is not "no stamp"
(that conflation is what made run 13 look like "no change"): `0` = present,
`1` = readable and no stamp, `2` = **UNREADABLE**. And when it returns `1` while
`probe_state = D`, the runner prints **⛔ ORACLE INCONSISTENT** — "go check the
criterion" — instead of the "did not land" message, which sends the operator to a
completely different place (a fresh boot, or a hit-rate hunt).

Full derivation: [`evidence/2026-09-18-divergence-is-latent.md`](evidence/2026-09-18-divergence-is-latent.md)
and [`evidence/2026-09-18-cred-launder-verification.md`](evidence/2026-09-18-cred-launder-verification.md)
(the latter's §2.3 is retracted in place). The write-shape overlap self-check is
closed offline: the shape words live in the fd_set grid on the kernel stack while
the side effect lands inside the sprayed page, so the two cannot overlap in either
shape.

## Detection paths

Three independent reporters. None is a fallback for another, and **only path 1
can kill the calling task**.

| # | Hook | Trigger | Action |
|---|---|---|---|
| 1 | `oplus_root_check_post_handler`, sys_exit tracepoint | some id descended, or `addr_limit == KERNEL_DS` | `oplus_root_killed` → `printk` + `do_exit(SIGKILL)`; and `oplus_root_check_succ` → `kevent_send_to_user` |
| 2 | `oplus_exe_block_ret_handler`, sys_exit but only for `execve` (221) | `d_path(mm->exe_file)` starts with `/data`, `/data/local/tmp`, `/data/nativetest`, `/data/nativetest64` | `oplus_RWO_root_check` → `printk` + `kevent_send_to_user` (no `do_exit`) |
| 3 | `oplus_secure_harden` kretprobes | `setsockopt` optname ∈ {41,42,48}, `setxattr`, `/proc/cpuinfo`, SELinux policy reload | `oplus_heapspray_check` → `kevent_send_to_user` |

**Path 2 fires on `execve`, not on credential change, and it is a separate code
path from path 1.** It reports through `kevent_send_to_user`, so what happens
next is a userspace daemon's decision, not the kernel's.

The check is on the path of the image **being exec'd**, so it is not enough to
memfd-load the loader's *payload*: if the loader itself is exec'd from
`/data/local/tmp`, that first `execve` already reports. `d_path()` on a memfd is
`/memfd:…`, so **the loader must itself be exec'd through a memfd** —
`V12_EXEC_MEMFD` is now on by default for exactly this reason. The old behaviour
is visible in RUN 4:

```
LT child exec /data/local/tmp/glx12 (4 args)     <- execve of a /data path while uid=0
LT child memfd loaded 5014624 bytes (fd=5)       <- memfd only protected the second image
```

Greppable markers for path 2:

```
[ROOTCHECK-EXEC-INFO]:common %s result %s      with  "execve_report" / "execve_block"
%d,path@@%s                                    kevent payload fragment
```

Because path 2 and path 3 report only through kevent, **"no `[ROOTCHECK-*]` in
the kernel log" does not exclude either of them having fired.** That inference
needs the userspace receiver, which we have not located.

## Watchdog — `oplus_security_guard.ko`

`sys_enter` cache:

```asm
ldrsw x8, [x1, #0x118]          ; regs->syscallno
mrs   x9, sp_el0                ; current
ldr   x10, [x9, #0x780]         ; cred
str   x8,  [x9, #0xdf8]
ldr   w8,  [x10, #4]    → str x8, [x9, #0xe00]   ; uid
ldr   w8,  [x10, #0x14] → str x8, [x9, #0xe08]   ; euid
ldr   w8,  [x10, #8]    → str x8, [x9, #0xe10]   ; gid
ldr   w8,  [x10, #0x18] → str x8, [x9, #0xe18]   ; egid
```

`sys_exit` check:

```asm
ldr   x0,  [x8, #0xe00]         ; cached uid
cbz   x0, #0x48c                ; cached uid == 0 → return
adrp  x9, #0 ; ldrb w9, [x9]    ; g_boot_state
tbnz  w9, #0, #0x48c            ; is_unlocked → return
ldr   x9,  [x8, #0x780]         ; cred
ldr   w3,  [x8, #0xdf8]         ; cached syscallno
cmp   x0, w10 ; b.hi #0x468     ; uid descending → kill path
                                ; euid / gid / egid, same shape
ldr   x9,  [x8, #8]             ; addr_limit
cmp   x9,  #0x8000000001
b.lo  #0x48c                    ; addr_limit != KERNEL_DS → return
sub   w9,  w3, #0x8f            ; syscallno - 143
cmp   w9,  #0x47
b.hi  #0x4a0                    ; outside 143..214 → kill
ldrsw x12, [x10, x9, lsl #2]    ; jmp table @ .rodata+0
br    x11
0x48c: ret
0x4a0: bl oplus_root_check_succ ; printk + kevent_send_to_user
       bl oplus_root_killed     ; printk + do_exit(SIGKILL)
```

**Control-flow note (matters for exploit ordering).** The four descending-edge
comparisons branch **straight to `0x468`**, the syscall-number dispatch — they do
**not** fall through the `addr_limit` gate. `0x454`–`0x464` is only reached when
**no** id descended. So the dispatch is entered when *either* some id descended
*or* `addr_limit == KERNEL_DS`; it is **not** gated by `addr_limit`.

Consequences:

* The killer fires on the syscall **during which** the credentials changed — the
  one whose `sys_enter` still cached the old uid. If the task is already `uid=0`
  when a syscall enters (`0x400` `cbz`), the hook returns and stays blind from
  then on.
* Therefore a credential change is survivable **without** touching the module:
  let *another* task perform the write while the victim spins in user space, or
  route the change through one of the 12 exempt syscalls. See
  `delivery/外部建议评审_2026-09-18.md`.

`g_boot_state` — 1 byte `.data..ro_after_init`, set at module init from `verified_bootstate` via `strstr`. `is_unlocked()` = `LDRB` + `RET`.

Module VA writes fault (`CONFIG_STRICT_MODULE_RWX=y`) — use the physmap alias `0xffffff80…`.

Report payload: `$$sys_call_number@@%d`, `$$set_id_flag@@%d`, `$$addr_limit@@%lx`, `$$enforce@@%d`.

### Exempt syscalls — `.rodata+0`, indices 143–214

| 143 `setregid` | 144 `setgid` | 145 `setreuid` | 146 `setuid` |
|---|---|---|---|
| 147 `setresuid` | 149 `setresgid` | 203 `connect` | 204 `getsockname` |
| 208 `setsockopt` | 210 `shutdown` | 213 `readahead` | 214 `brk` |

Remaining 60 entries → report + kill.

**Do not block a thread on `sendmsg` (211) while its credentials change.** It is
not in the table, so the thread is reported and killed. The only syscalls that
are safe to be blocked in for that purpose are the twelve above:
`setregid`, `setgid`, `setreuid`, `setuid`, `setresuid`, `setresgid`,
`connect`, `getsockname`, `setsockopt`, `shutdown`, `readahead`, `brk`.

> **Correction (2026-09-18).** An earlier revision of this table labelled every
> entry **one lower** than the real arm64 syscall number (`146` was called
> `setresuid`; it is `setuid` — `setresuid` is `147`). The numbers were always
> right; only the names were wrong. Names are now resolved from
> `sys_call_table` @ `0xffffffc00a13d8c0` in this device's kernel image. In
> particular `sendmsg` (211), `munmap` (215), `getsockopt` (209) and
> `getpeername` (205) are **not** exempt — blocking a thread in any of those
> while its credentials change is a kill, not a pass. Regenerate with
> `tools/gen_exempt_table.py`.

## Heap-Spray Detector — `oplus_secure_harden.ko`

| kretprobe | Hooks | Filter |
|---|---|---|
| `socket_kretprobe` | `ip_setsockopt` | `regs[1]` ∈ {41, 42, 48} |
| `socket_ip6_kretprobe` | `do_ipv6_setsockopt` | `regs[1]` ∈ {41, 42} |
| `cpuinfo_kretprobe` | `cpuinfo_open` | — |
| `setxattr_kretprobe` | `setxattr` | — |
| `sepolicy_reload_kretprobe` | `spolicy_reload` | — |

```asm
ldr  w8, [x1, #8]       ; regs[1]
cmp  w8, #0x29          ; 41 IP_MSFILTER
b.eq #0xd58
cmp  w8, #0x30          ; 48 MCAST_MSFILTER
b.eq #0xd60
cmp  w8, #0x2a          ; 42 MCAST_JOIN_GROUP
b.ne #0xd68             ; else → return, no call
bl   oplus_heapspray_check
```

`entry_handler_setxattr` → `oplus_heapspray_check(7)`, `entry_handler_cpuinfo` → `(6)`, both unconditional.

`oplus_heapspray_check` — counters `heapspary_ip4` / `ip6` / `xttr` / `cpuinfo`, `ktime_get_real_ts64` delta, 7 report sites (`snprintf` + `printk` + `kevent_send_to_user`), gated on `verified_bootstate`.

### Avoidance

| Primitive | |
|---|---|
| `setsockopt` optname 46 `MCAST_JOIN_SOURCE_GROUP` | not filtered |
| `setsockopt` level `SOL_IPV6` (41) | not filtered if filter reads `level` |
| `setxattr` | always counted |
| `/proc/cpuinfo` | always counted |
| `socket()` / `socketpair()` | not hooked |
| `sendmsg`, `pipe`, `memfd`, `add_key`, `io_uring`, mmap | not hooked |

## Config

```
CONFIG_CFI_CLANG=y
CONFIG_PTR_AUTH=y
CONFIG_SHADOW_CALL_STACK=y
CONFIG_STRICT_MODULE_RWX=y
CONFIG_STATIC_USERMODEHELPER=y
CONFIG_STATIC_USERMODEHELPER_PATH=""
CONFIG_SET_FS=y
CONFIG_RANDOMIZE_BASE=y
CONFIG_RANDOMIZE_MODULE_REGION_FULL=n
CONFIG_UNMAP_KERNEL_AT_EL0=y
CONFIG_ARM64_VA_BITS=39
CONFIG_ARM64_SW_TTBR0_PAN=y
CONFIG_SLAB_FREELIST_RANDOM=y
CONFIG_SLAB_FREELIST_HARDENED=y
CONFIG_INIT_ON_ALLOC_DEFAULT_ON=y
CONFIG_RANDOM_KMALLOC_CACHES=n
CONFIG_USER_NS=n
CONFIG_NF_TABLES=n
CONFIG_SYSVIPC=n
CONFIG_ANDROID_BINDER_IPC=y
CONFIG_KASAN=y
```

`perf_event_paranoid = -1`

## Build

NDK **r28c**. `-O1` / API **26** / `-D__ARM=1` are **fixed** — they keep the reclaim stack-frame geometry (`delta=0` calibration). Changing any of them requires re-calibrating on device.

```bash
export ANDROID_NDK_HOME=/path/to/android-ndk-r28c
make                      # → exploit_guard
./build.sh                # same, with NDK auto-detection
```

Manual:

```bash
"$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android26-clang" \
  -D__ARM=1 -O1 -Wall -Wextra -pthread -Isrc/core -Isrc/devices/pfem10 \
  -o exploit_guard src/core/exploit.c
```

CI builds on every push (`.github/workflows/build.yml`, Ubuntu + NDK r28c, artifact `exploit_guard`).

## Setup

```bash
adb push exploit_guard /data/local/tmp/e
adb shell chmod 755 /data/local/tmp/e
adb shell /data/local/tmp/e
```

## Files

```
src/core/                 exploit.c  payload.c  payload.h  fdset_map.h
src/lib/                  KernelSnitch — kernelsnitch.h  futex_hash.h  timeutils.h  utils.h
src/devices/pfem10/       pfem10_target.h
model/                    model.c — host-side rtmutex chain-walk model
tools/                    kdis.py  kdis_ko.py  kdis_ko_reloc.py  gen_guard_disasm.py
                          gen_exempt_table.py  mod_layout.py  sct_dump.py
                          find_task_off.py  slide_resolve.py
                          test_stamp_criterion.sh   regression test for the 0x778
                                                    landing criterion (run it after
                                                    touching uid_line/gid_line)
artifacts/                guard_post_handler.s   kill chain, relocations resolved
                          guard_relocs.txt       raw .text relocation dump
                          guard_disasm.txt       guard + heap-spray detector
                          guard_exempt_table.txt 72-slot jump table, real names
evidence/                 kill.log  notes.md — device captures and their limits
Makefile  build.sh        exploit build (-O1, API 26, NDK r28c)
run.sh                    device-side run orchestration (retry across reboots)
.github/workflows/        build.yml — cloud build + artifact
```

## Evidence

[`evidence/kill.log`](evidence/kill.log) — verbatim `adb shell` transcripts of four
root runs: the full timeline, the moment the target task's uid becomes 0, the
`kernelsu.ko` load, and the state afterwards. Read the header block first: it
lists what the file does **not** contain and why.

[`evidence/notes.md`](evidence/notes.md) — the kernel side. Module addresses and
which `/proc` channels work in which SELinux state; the full `g_boot_state`
derivation including the `strstr` key; the corrected exempt table; the capture
recipe that would produce the missing kernel half; and a list of what is still
open.

[`evidence/2026-09-18-bootA/`](evidence/2026-09-18-bootA/README.md) — the first
device run of the current design, 13 boots. The reboots are **orderly**
(`bootreason=reboot`) and no panic line has ever been captured — **but read that
as a sample of one, not thirteen.** Of the four runs that rebooted, two saved an
empty `klog.host`, one saved the log of the *next* boot, and only one window can
plausibly bracket its own reboot. Likewise, one run's `probe_state` and victim
readback are both **empty** (the device was already gone), so it carries no
information about whether its write landed — a blank field is not "no change".
The directory also documents the methodology error worth knowing about:
**`dmesg -w` is a no-op on this device** (toybox dumps once and exits), so an
earlier run's kernel log held only pre-capture history — "no `[ROOTCHECK-*]`" was
not evidence of anything. `evidence/notes.md` §6 carries the corrected
poll-and-stream-to-host recipe.

[`evidence/2026-09-18-cred-launder-verification.md`](evidence/2026-09-18-cred-launder-verification.md)
— verification of the credential-laundering proposal against this image's own
disassembly (not generic 5.10 source): the `commit_creds` double store, the
`prepare_creds` allocation and measured `sizeof(struct cred) = 0xA8`, the
`BUG_ON(cred != real_cred)` divergence hazard above, the closed write-shape
overlap self-check, and the evidence-coverage audit of the 13 boots.
**§2.3 is retracted in place** — the divergence is latent, not the reboot
mechanism.

[`evidence/2026-09-18-divergence-is-latent.md`](evidence/2026-09-18-divergence-is-latent.md)
— the round-2 verification. `commit_creds` takes its task from `current`
(`0x1867a0 mrs x20, sp_el0`), `exit_creds` nulls both pointers before `put_cred`,
and the raw captures show the old chain wrote **one identical value**
(`0xffffff802a7e0be0`) to both slots while the new chain wrote two different
pages. So the criterion is pointer equality — "both shots write the same value",
not "both shots land".

[`postreboot_forensics.sh`](postreboot_forensics.sh) — reboot forensics that does
**not** depend on the poller. The criterion is a single condition:
`CONFIG_PSTORE_CONSOLE=y` makes `panic()` write the console tail into ramoops at
`kmsg_dump(KMSG_DUMP_PANIC)` — **before any reset** — so whether the box then
reboots or hangs is irrelevant. Pulls `/sys/fs/pstore/`, greps for `kernel BUG` /
`__put_cred` / `cred.c`, and prints the boot-reason **string** (history entries
have carried `reboot,shell` / `bootloader` / `reboot,edl` suffixes, so the reason
distinguishes an actor where the epoch does not).

> ⚠ **Do not read "clean `bootreason=reboot`" as "no panic."** On QCOM an SoC
> watchdog assert is reset through the PMIC PON block, so
> `panic → panic_timeout=-1 → hang → watchdog → PMIC reset → clean bootreason`
> is a self-consistent chain that is **indistinguishable** from a hardware reset
> on the evidence we hold. This repo's own `total_17_dump_0_pmic_17` attributes
> all 17 abnormal reboots to `pmic`, which is exactly the watchdog's normal
> shape, not evidence of "not the kernel." `bootreason` narrows nothing here;
> **ramoops is the only criterion.**

Two preconditions, or the script's verdict is void (铁律 8 — a no-signal
conclusion requires the channel to be proven reachable first):

- **Third state required.** `/sys/fs/pstore/*` is root-only, so under Enforcing
  both `adb pull` and `cat` fail — and "cannot read" produces the *same output*
  as "read it and it was empty". A two-state script prints "pstore is EMPTY ⇒
  panic disproven" from a channel it never opened. The script therefore emits
  **`CHANNEL UNREACHABLE`** (ls failed, or all known entries failed to *read*
  rather than not existing) and reports `getenforce` alongside.
- **Null test first.** A clean `adb reboot` followed by an immediate fetch. If a
  known-good reboot yields nothing readable, the channel is not proven and every
  later "empty pstore" is not evidence. **Ordering matters**: the device moves
  and unlinks the record shortly after boot, so the sequence is
  *reboot → get Permissive (W1) → run the script immediately*.

[`run_bootA.sh`](run_bootA.sh) — orchestration for that one boot, in the order
that matters (`0x778` → `0x780` **with the same value** → local repair of the cred
that was actually installed → confirm → only then poke). `ADB=`/`SER=`/
`BIN_LOCAL=` overridable; `SAME_VALUE=1` (default) enforces the same-value rule,
`CONTROL=1` reproduces the old `init_cred` cell, `LAUNDER=1` enables the gated
launder, `HOLD=600` is required for the same-value sequence.

**Both streams start before the thing they measure.** `uid.stream` runs from
stage 1; `cred.stream` starts **at the poke**, not after the watch — the poke
releases the child into its NO_EXEC report loop, which is 240 × 0.5 s = 120 s and
then `_exit(0)` (`exploit.c`: "LT child NO-EXEC mode done (120s)"), so the old
placement at t+~135 s started sampling after the child was already gone, at
exactly the window the instrument exists for. The runner also refuses to proceed
if `stamp_selftest()` fails, and prints **ORACLE INCONSISTENT** rather than "did
not land" when the stamp and `probe_state` disagree.

[`artifacts/guard_post_handler.s`](artifacts/guard_post_handler.s) — the kill
chain with relocations filled in. `adrp x9, #0` in the older listings is
`.data..ro_after_init`; `bl #0x4ac` is `oplus_root_check_succ`. Regenerate with
`tools/gen_guard_disasm.py` after pulling the vendor modules from your own device.

`tools/kdis_ko.py` — RELA matched by `sh_info`; on these builds `.text` relocs live in `.rela.text.<func>`, so name-based lookup returns nothing.

## Related

| Project | |
|---|---|
| [JoinChang/ghostlock-oneplus](https://github.com/JoinChang/ghostlock-oneplus) | reference implementation; 5.10 compact waiter |
| [NebuSec CyberMeowfia](https://github.com/NebuSec/CyberMeowfia) | original GhostLock research |

## License

GPL-3.0 — see [LICENSE](LICENSE).
