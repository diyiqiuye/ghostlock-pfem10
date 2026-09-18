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
| `task+0x778` **或** `task+0x780` 单独落地 → `Uid=root` | 成功 —— 但**单字段落地会让任务进入分歧态**，而这是一条潜伏的硬 `BUG_ON`。见[分歧态那一节](#-单字段落地会让任务进入分歧态--而这是一条硬-bug_on) |
| **两字段写成同一个值**（一致对） | ❌ **用喷页从未产生过。** 只在全局 `init_cred` 别名上出现过（09-14，`CONTROL=1`）。runner 现在强制它（`SAME_VALUE=1`）；**未上机** |
| cred 洗白（`setresgid` + `setresuid`） | 已实现（`V12_LAUNDER=1`）；**未上机** |
| `kernelsu.ko` 载入 | 成功 |
| root 进程存活 | ⚠ **未定论** —— 见下 |
| 重启机制 | ❌ **未建立。** 一个候选（分歧态）现已**被排除**；见下 |
| 把 `probe_state` 当落地判据 | ❌ **错的 —— 不要用。** 三个反例；见下表 |
| pstore/ramoops panic 通道 | ⚠ 仪器已有；**通道从未验证**（还没做 null test） |
| 「受害者在纯用户态自旋」 | ⚠ **还没有读数** —— `uid.stream` 现在记 `utime`/`stime`/`nvcsw`，所以它可被检验 |
| pi 侧单 pass 双写 | ⚠ **未建立**；`fdset_map.h` 里 `pi.pc`/`pi.left` 被硬编码为 0 |
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
LT          perf 泄漏目标 task_struct → 落文件
W7 阶段 1   task+0x778 = V（real_cred → 喷页内的私有页；V 是**观测到的**值）
W7 阶段 2   task+0x780 = V（cred）   ★ V12_W7_VALUE=V —— **同一个值**，不是新喷一页
W7 阶段 3   V+8 = 0（对**真正被装上**的那张页做**局部**修复，第二个进程，ZERO 形状）
LT 子进程   fexecve(loader 的 memfd) —— 不对 /data 路径做 execve
loader      ksud late-load                    → kernelsu ... Live
```

**阶段 2 必须显式拿到阶段 1 的值。** 阶段 1 与阶段 2 是**两个独立进程、各自喷各自的页**，
所以「把 cred 页写进两个槽」是个陷阱：照字面读会产出 `(pageA, pageB)`，
而因为 `commit_creds` 比的是**指针**，即便两枪都落地那也是分歧对。
这不是假设 —— run 3 和 run 9 干的就是这件事：

```
run 9   0x778 那一枪  write value = 0xffffff88679bade0
        0x780 那一枪  write value = 0xffffff8785d6ade0     <- 另一张页
run 3   0x778 那一枪  write value = 0xffffff8787b5ade0
        0x780 那一枪  write value = 0xffffff881bad2de0     <- 另一张页
```

因此 `run_bootA.sh` 用 `V12_W7_VALUE=<阶段 1 观测到的值>` 开阶段 2 那一枪，
**抽不到值就干脆不发**。`HOLD` 必须活过阶段 2，否则阶段 1 的页被释放并重新分配，
「同值」就变成悬垂指针。见[同值规则那一节](#-两枪必须写同一个值而不只是都落地)。

**一次 boot 只修一张页。** 阶段 3 清零 `V+8`。若两张页**不同**，把两页的 `+8` 都清零
会抹掉 gid/suid 那枚戳（见下），让分歧**看起来**一致，所以 runner 只修**真正被装上**的那张页，
且两枪值不一致时直接停。

cred 页由 `payload.c` 构造：8 个 id 字段全 0、5 组 caps 全满，`user` / `user_ns` /
`group_info` 指向 `root_user` / `init_user_ns` / `init_groups`。阶段 3 之所以存在，是因为写的副作用
**必然**把它装入的那张 cred 的 `+8`（`gid`/`suid`）打坏。

### 关于 `init_cred` —— 一个显式的二分

本节与另一处曾经互相打脸（「从来不是全局 `init_cred`」 vs 「`CONTROL=1` 复现 cell 2」，
而 cell 2 **就是** `init_cred`）。两句话对**不同角色**都是真的：

* **作为目标 —— 禁止。** 写入 `init_cred` 指针会让副作用**全局**写坏 `init_cred+8` ——
  `init_cred` 被所有内核线程共用，`Uid: 0 0 4294967176 0` 正是那次损坏。
  除非显式设 `V12_ALLOW_INIT_CRED=1`，代码拒绝这条路。
* **作为唯一被证实的一致对 —— 保留。** 09-14 走到 ksud 的那条链把**一个固定地址**
  （`0xffffff802a7e0be0`）写进两个槽，所以 `real_cred == cred` 是**构造出来的** ——
  这正是它能活到 `execve` 的原因。`CONTROL=1` 复现它。它是**对照**，不是可以依赖的配置。

perf 泄漏：`PERF_TYPE_SOFTWARE` / `PERF_COUNT_SW_CPU_CLOCK`，`PERF_SAMPLE_REGS_INTR`，`exclude_user=1`。
取值范围 `[0xffffff8400000000, 0xffffff90000000)`，票数 ≥ 15%。

## 写原语及其副作用

本漏洞经 `rb_erase_cached` Case 1-left 触发，产生的是**两次**写、不是一次：

```
*(write_target)        = write_value      // 你要写的那一次
*(write_value + 0x08)  = write_target     // 躲不掉的副作用
```

`write_value` 必须 8 字节对齐、bit0 = 0 —— 所以它只能是 `0` 或合法内核地址。
**这就是 8 字节写设不了 `g_boot_state` 的原因**：你需要变成 `1` 的那个字节，
低位被对齐要求强制成 `0`；而 `write_value` 与副作用落点是同一个量。

### 副作用会写进 `write_value` 指向的对象

`write_value` 既是**被写入的值**，也是**副作用写入的地址**（`+8`）。把它指向内核全局对象，
就会把那对象写坏。

**W7 以前就是这么干的** —— 把 `write_value` 指向 `init_cred` 别名 —— 回读里看得见。
来自 `out/t5_w7_778.txt`：

```
shape shift=0 wps=5: in[0]=0xffffff802a7e0be0 (write_value) in[2]=0xffffff8800cdd178 (write_target)
W7[W7] write_target= 0xffffff8800cdd178
Uid:	0	0	4294967176	0
```

当时 `write_value` 是 `init_cred` 别名，`write_target` 是 `child_task+0x778`。
`init_cred+8` 是 `gid`/`suid`，于是副作用把 `0xffffff8800cdd178` 写在那儿：
`init_cred.gid = 0x00cdd178`，而 **`init_cred.suid = 0xffffff88 = 4294967176`** ——
正好就是上面 `Uid:` 行的第 3 个字段。把 `init_cred+8` 清零即可修复
（`out/t5_repair.txt`：`Uid: 0 0 4294967176 0` → `Uid: 0 0 0 0`）—— 这就是"W7 阶段 3"的全部含义。

**这条路径现在被代码拒绝。** `V12_W7_INIT_CRED=1` 会直接中止并说明原因，除非同时显式
`V12_ALLOW_INIT_CRED=1`；W2 / W6 / LTC 三条路径在私有 cred 页缺失时**不再回落到 `init_cred`**，
而是中止。默认（也是唯一合理的）路径就是喷页内的 cred 副本。

副作用本身躲不掉：`write_value` 必须**就是**那个 cred 指针，所以 `cred+8` 必然被写入
write_target。能选的只有它的**落点** —— 而修复现在是对 `cred_page+8` 的**局部**清零
（阶段 3），不再是写进全局对象。

> `groups=` 读出垃圾是**另一个**症状，不是这个。它出现在一次 `gid`/`egid` 回读**正常**的 run 里，
> 所以不可能来自 `init_cred+8` 副作用；它指向假 cred 自己的 `group_info` 字段。见 `evidence/notes.md` §10.6。

### ★ 单字段落地会让任务进入分歧态 —— 而这是一条硬 `BUG_ON`

本原语**每趟只写一个地址**。`task+0x778`（`real_cred`）与 `task+0x780`（`cred`）是两个不同地址，
所以**任何一次落地的 0x778-only 或 0x780-only 写入，都会让任务留下 `cred != real_cred`** —— 分歧态。

在本镜像上，这个状态是**硬 panic**，不是警告。`commit_creds` 开头就是
`BUG_ON(task->cred != task->real_cred)`：

```
commit_creds @0xffffffc008186784
  0x1867a4  ldr  x19, [x20, #0x778]      ; old = task->real_cred
  0x1867a8  ldr  x8,  [x20, #0x780]      ;        task->cred
  0x1867ac  cmp  x8, x19
  0x1867b0  b.ne #0xffffffc008186b68
  0x186b68  brk #0x800                   ; == BUG()
```

而本内核编了 **`CONFIG_PANIC_ON_OOPS=y`**（`CONFIG_PANIC_ON_OOPS_VALUE=1`）。
`__put_cred @0xffffffc008185530` 还有同族断言（`usage != 0` → BUG；
`cred == current->cred` / `current->real_cred` → BUG）。

所以分歧态是**潜伏**的 —— 受害者进程只是自旋时什么都不会发生 —— 直到该任务上发生**任何**
`commit_creds`：`setresuid` / `setresgid` / `setuid` / `setgid` / `capset`，
或者 **`execve`（经 `install_exec_creds`）**。

> **⛔ 撤回（2026-09-18 晚）：这【不是】重启机制。**
>
> 本节早先的版本把分歧态称为「重启机制的头号候选」，并说它「解释了 shape 分界」。它不解释，
> 而且理由是**实测**的而不是论证的：
>
> * `commit_creds` 取任务的方式是 **`0x1867a0 mrs x20, sp_el0`** —— 它的签名是
>   `commit_creds(struct cred *new)`，**没有 task 参数**，只作用于 `current`。
>   所以分歧态只有在**持有它的那个任务自己**调 `commit_creds` 时才起作用。
> * 那些重启的 run **全都是 `V12_NO_EXEC=1`**（`run3_0445.log:18`、`run9_0606.log:20`、
>   `run10_0616.log:24` 逐字写明），受害者**从没发过 `execve`**，也就从没到过 `commit_creds`。
> * run 10 **一次 poke 都没有**（`grep -c poke` = 0）。
> * `exit_creds` 把**两个**指针先置 NULL 再 `put_cred`
>   （`0x185cb8 str xzr,[x19,#0x778]`；`0x185d24 str xzr,[x19,#0x780]`），
>   所以子进程的 `_exit(0)` 是**抹掉**分歧，而不是踩爆它。
>
> ⇒ 那几次里分歧态是**惰性**的。`BUG_ON` 是真的，但它是一颗**还没炸**的地雷。
> 「shape A 从不重启」退回为**相关性**。地雷真正约束的是**洗白**，因为
> `setresgid`/`setresuid` 自己就调 `commit_creds`。
>
> **真正把两条链分开的量是指针相等 —— 也就是两枪必须写同一个值。**

### ★★★ 两枪必须写**同一个值**，而不只是「都落地」

`BUG_ON` 比的是**指针**。两张都带 `uid 0` 的页仍然是两个不同的对象。原始证据里这个区别是硬的：

| 链 | 0x778 那一枪 | 0x780 那一枪 | 指针 |
|---|---|---|---|
| 老链（`t5loop.sh MODE=CRED`） | `in[0]=0xffffff802a7e0be0` | `in[0]=0xffffff802a7e0be0` | **相等** → ksud 载入、manager 活 120s |
| 新链（`run_bootA.sh`） | `0xffffff88679bade0`（run 9） | `0xffffff8785d6ade0` | **不等** → 即使两枪都落地也是分歧 |

`tools/t5loop.sh` 把**同一个** `$ENVV` 施加到**每一个** offset，所以 `MODE=CRED` 让两枪
**同值是构造出来的**。而 `run_bootA.sh` 的 step 5 与 step 6 各自以空 `$extra` 开火，
**各喷各的页**。

⇒ 要求是**「两枪写同一个值」**。`run_bootA.sh` 现在强制这一点（`SAME_VALUE=1`，默认开）：
step 6 逐字复用 step 5 观测到的 `write_value`，**抽不到值就拒绝发第二枪** —— 因为发出去就是
在制造分歧对。

⚠ `HOLD` 必须活过第二枪。第一枪的 PIN child 若先死，页会被释放并重新分配，
「同值」就变成悬垂指针。默认 `HOLD=20` **太短**，用 `HOLD=600`。现在只要 `SAME_VALUE=1`，
`600` 就是**默认值** —— 原来那个无条件的 20 让**默认配置本身就是陷阱** —— 而显式给一个
短 `HOLD` 配 `SAME_VALUE=1` 现在会**大声告警**，而不是静默产出悬垂指针。

⚠ `CONTROL=1` 以前**只改 step 5**，所以它产出的是 `(init_cred, 新喷页)` —— 一个分歧对 ——
而本文件却声称它复现了 cell 2。**已修**：现在两枪都设 `init_cred`。
（cell 2 的代价仍在：副作用会把 `init_cred+8` **全局**写坏，`Uid: 0 0 4294967176 0` 就是它。）

**对任何想洗白 cred 的方案（`setresgid` + `setresuid`，把喷页换成真正的 `struct cred`）的后果：**

- 机制是真的、已核实 —— `commit_creds` 把 `x21` 写进 **`task+0x778` 和 `task+0x780` 两处**
  （`0x186998` / `0x1869a0`），所以一次调用就永久修好分裂；`prepare_creds @0xffffffc008186070`
  = `kmem_cache_alloc(cred_jar)` + `memcpy(new, task->cred, 0xA8)` + `security_prepare_creds(...)`；
  147/149 都在看门狗豁免表内。
- **但它的前提与「跳过 0x778 那一枪」正好相反。** 洗白自身就要调 `commit_creds`，
  所以只能在**两个指针已经指向同一个对象**时才发。
- 因此 `V12_LAUNDER=1` 由**两个**条件把门，而且第一条不是观测：
  1. **`V12_W7_SAME_VALUE=1`** —— 两枪被指定了同一个值的**出身**事实。没有读原语 ⇒
     指针身份**不可观测** ⇒ 它不能被任何更好的用户态检查替代，只能**声明**。
  2. `consistent=1` —— `0x780` 视角（`getuid()`）与 `0x778` 视角（`/proc/self/status` 的 `Uid:`）一致。
     **单靠它必要但不充分**：两张不同的页都带 `uid 0` 时会读出「一致」而指针仍然不同 ——
     而这正是 runner 过去在生产的那一行。加上第 1 条之后它才充分：
     内容一致 + 同值 ⇒ 两枪都落在同一张页。
  任一条件不满足 ⇒ **拒绝**，并把四情形表打进证据。LT 报告行同时打印两个视角
  （`uid=` / `real_uid=` / `consistent=`）与 `same_value_declared=`，
  让状态被**读到**而不是被推断。

### ★ 仪器 1 —— 副作用是一枚「按目标打的戳」

`*(write_value + 8) = write_target`，而 `cred+8` / `cred+0xc` 正是 `gid` / `suid`，
所以一次 8 字节 store 同时落在两处：

```
cred.gid  = low32(write_target)
cred.suid = hi32(write_target)
```

这是**实测**，不是模型。`out/t5_w7_778.txt` 里 `write_target = 0xffffff8800cdd178`、
`Uid: 0 0 4294967176 0`，其中 `4294967176 = 0xffffff88 = hi32(write_target)`；
`notes.md` §11 记下了另一半：`init_cred.gid = 0x00cdd178 = low32(write_target)`。

两个用途：

1. **它就是 `task+0x778` 的落地判据。** `/proc/<pid>/status` 读的是 `real_cred` =
   `task+0x778` —— 正好是刚被装上的那张 cred —— 所以这枚戳**可从用户态直接读到**。
   必须在**阶段 3 之前**读：修复会清零 `cred+8`，把戳抹掉
   （`notes.md` §11 的 `t5_repair.txt`：修好之前读 `4294967176`，之后读 `0`）。
2. **它是洗白门能抓住「两张不同页」的第二个、独立的理由。** 单靠 uid 那一半抓不住：
   任何带 uid 0 的页都读 `0`，所以两张不同的页都会报「一致」。但
   `low32(T+0x778)` 与 `low32(T+0x780)` **正好相差 8**，所以两张页时
   `getgid()`（来自 `cred`）与 `status_gid`（来自 `real_cred`）不一致 ——
   而 `lt_cred_ids_agree()` 同时比 gid 和 uid。

⇒ `V12_W7_SAME_VALUE` 是**第二道**门，不是唯一一道。它仍然要紧：
这枚戳只在**两个副作用都触发过**时才有区分力，同值规则补上的正是这个残余缺口。
还要看清一道门**是什么** —— 它是检测器，不是阻止器。它只能拒绝；
被拒绝的任务会在这次 boot 的剩余时间里保持分歧。真正让这一对**正确**的是同值规则，
而这正是老链拥有、也是走到 `execve` 所必需的东西。

### ★ 仪器 2 —— `probe_state` **不是**落地判据

它在本项目里错了**三次**：W1 落在全局上却报 `R`；run 12 的 `D` 打在全局而非 cred 上；
run 11 的 `R` 被当成落地写进了表格（`run11_w778r1_miss.txt` 与 run 7 的 `w7_w7781.txt`
**逐行同构** —— 都是 `probe_state = R`、`probe_done = 0`）。请按目标各用各的判据：

| 目标 | 落地判据 |
|---|---|
| `task+0x778` | `Uid:` **第 4 个 awk 字段** `= hi32(write_target)` **且** `Gid:` **第 2 个 awk 字段** `= low32(write_target)` —— 即上面那枚戳；**在阶段 3 之前读** |
| `task+0x780` | 受害者自报的 `getuid()` |
| 全局 `selinux_enforcing` | `getenforce` |
| `probe_state` | ❌ **不是判据。** 顶多是链的一个提示；**永远不是**「写落地了」的证据 |

`run_bootA.sh` 现在用那枚戳判阶段 1 —— 这才让在 `task+0x778` 上做 `ROUNDS>1` 重试有意义，
因为失败的 round 变成**可读**的而不是靠推断 —— 而且阶段 1 没落地就**不发**阶段 2。

> ⛔ **必须说「awk 字段」，永远别说「第 3 个字段」。** `uid_line` 把标签也打出来
> （`Uid: 0 0 4294967176 0`），所以 awk 的 `$1` 是 `"Uid:"`，四个 id 值在 `$2..$5`：
> `$2`=uid `$3`=euid **`$4`=suid** `$5`=fsuid。戳落在 `cred+8`，即 `gid`（low32）与
> `suid`（hi32）—— 所以是 `Gid:` 的 `$2` 和 `Uid:` 的 **`$4`**。说成「第三个字段」
> （按**值**计数，`notes.md` §11 就是这么写的）会诱使代码去读 `$3`，而那是 `euid`，
> 在假 cred 上恒为 `0`，**永远**不等于 `hi32(write_target)`。这个差一错误**真的发生过**：
> `stamp_ok()` 对**已经落地**的一枪报「没有戳」⇒ 阶段 2 永不发火、洗白门永远拒绝 ——
> 而**全程没有任何报错**，因为「没有戳」也正是一次真实 miss 的正常结局。

**从未拿已知正样本验证过的判据不是判据，是猜测** —— 而这一类故障（这个差一、
`probe_state`、`dmesg -w`、空的 `klog.host`、空回读）**全都表现为「什么都没发生」**，
而「什么都没发生」恰好也是一个合法的实验结局。所以现在有两道防线：

* **`stamp_selftest()`** 在 preflight 里跑，失败即 `exit 9`；它驱动的是**门本身用的同一套**
  抽取函数，样本取自 `out/t5_w7_778.txt` 的**实测值**（`write_target = 0xffffff8800cdd178`
  ⇒ `Uid` `$4` = `4294967176`、`Gid` `$2` = `13488504`），外加负样本与不可读样本。
  **重新实现一遍判据的自检什么也证明不了**，所以字段抽取被抽成 `uid_suid_field` /
  `gid_gid_field`。
* **[`tools/test_stamp_criterion.sh`](tools/test_stamp_criterion.sh)** —— 同一件事的
  独立回归测试，直接从 `run_bootA.sh` 里抽真函数来跑。

`stamp_ok()` 返回**三态**，因为「读不到」不是「没有戳」（正是这个混淆让 run 13 看起来像
「没变化」）：`0` = 有戳，`1` = 可读但没有戳，`2` = **不可读**。而当它返回 `1` 且
`probe_state = D` 时，runner 会打印 **⛔ ORACLE INCONSISTENT**（「去查判据」），
而不是「没落地」那句话 —— 后者会把人引向完全不同的地方（换一个 boot，或者去查命中率）。

完整推导：[`evidence/2026-09-18-divergence-is-latent.md`](evidence/2026-09-18-divergence-is-latent.md)
与 [`evidence/2026-09-18-cred-launder-verification.md`](evidence/2026-09-18-cred-launder-verification.md)
（后者 §2.3 已就地标注撤回）。写形状重叠自查离线已关闭：形状词在内核栈的 fd_set 网格里，
而副作用落在喷页内，两者不可能重叠。

## 检测路径

三条互相独立的检测链。**没有一条是另一条的兜底**，而且**只有第 1 条会杀调用任务**。

| # | Hook | 触发 | 动作 |
|---|---|---|---|
| 1 | `oplus_root_check_post_handler`，sys_exit tracepoint | 某个 id 出现下降沿，或 `addr_limit == KERNEL_DS` | `oplus_root_killed` → `printk` + `do_exit(SIGKILL)`；同时 `oplus_root_check_succ` → `kevent_send_to_user` |
| 2 | `oplus_exe_block_ret_handler`，sys_exit 但只处理 `execve`(221) | `d_path(mm->exe_file)` 以 `/data`、`/data/local/tmp`、`/data/nativetest`、`/data/nativetest64` 开头 | `oplus_RWO_root_check` → `printk` + `kevent_send_to_user`（**无 `do_exit`**） |
| 3 | `oplus_secure_harden` 的 kretprobe | `setsockopt` optname ∈ {41,42,48}、`setxattr`、`/proc/cpuinfo`、SELinux 策略重载 | `oplus_heapspray_check` → `kevent_send_to_user` |

**第 2 条挂在 `execve` 上、不挂在凭据变化上，和第 1 条是两条独立的代码路径。**
它通过 `kevent_send_to_user` 上报，所以后续动作由用户态守护进程决定，不是内核决定。

检查的是**被 exec 的那个映像**的路径，所以只把 loader 的*载荷*塞进 memfd 是不够的：
如果 loader 本身是从 `/data/local/tmp` exec 的，那第一次 `execve` 就已经上报了。
memfd 的 `d_path()` 是 `/memfd:…`，因此**必须让 loader 自己经 memfd exec** ——
`V12_EXEC_MEMFD` 现在默认开启就是为了这个。旧行为在 RUN 4 里看得很清楚：

```
LT child exec /data/local/tmp/glx12 (4 args)     <- uid=0 时 execve 了 /data 路径
LT child memfd loaded 5014624 bytes (fd=5)       <- memfd 只保护了第二张映像
```

第 2 条的可 grep 标记：

```
[ROOTCHECK-EXEC-INFO]:common %s result %s      参数为  "execve_report" / "execve_block"
%d,path@@%s                                    kevent 载荷片段
```

由于第 2、3 条只经 kevent 上报，**"内核日志里没有 `[ROOTCHECK-*]`"并不能排除它们已经触发过。**
要排除得找到那个用户态接收方，目前还没定位到。

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

**不要把线程堵在 `sendmsg`(211) 上再改它的凭据。** 它不在表里，线程会被上报并击杀。
这个用途下能安全阻塞的 syscall 只有上面那 12 个：
`setregid`、`setgid`、`setreuid`、`setuid`、`setresuid`、`setresgid`、
`connect`、`getsockname`、`setsockopt`、`shutdown`、`readahead`、`brk`。

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
                          test_stamp_criterion.sh   0x778 落地判据的回归测试
                                                    （动过 uid_line/gid_line 就跑它）
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

[`evidence/2026-09-18-bootA/`](evidence/2026-09-18-bootA/README.md) —— 现行设计的首次上机，13 次 boot。
重启都是**有序**的（`bootreason=reboot`），也从未抓到 panic 行 —— **但请把它读成「样本 = 1」，不是 13。**
四次重启里，两次存下来的 `klog.host` 是**空的**，一次存的是**下一个 boot** 的日志，
只有一个窗口有可能覆盖到它自己的重启时刻。同样地，某一次的 `probe_state` 与受害者回读**都是空的**
（设备当时已经掉了），所以它对「写有没有落地」**不携带任何信息** —— 空字段不等于「无变化」。
该目录还记录了一个值得知道的方法学错误：**本机 `dmesg -w` 是空操作**（toybox dump 一次就退出），
所以早先那次 run 的内核日志只含抓取前的历史 —— 「没有 `[ROOTCHECK-*]`」不构成任何证据。
更正后的「host 侧轮询 + 增量落盘」配方在 `evidence/notes.md` §6。

[`evidence/2026-09-18-cred-launder-verification.md`](evidence/2026-09-18-cred-launder-verification.md)
—— 对 cred 洗白方案的核实，**依据是本镜像自己的反汇编**（不是通用 5.10 源码）：
`commit_creds` 的双写、`prepare_creds` 的真分配与实测 `sizeof(struct cred) = 0xA8`、
上面那条 `BUG_ON(cred != real_cred)` 分歧态、已关闭的写形状重叠自查，
以及对 13 次 boot 的证据覆盖审计。**其 §2.3 已就地标注撤回** —— 分歧是惰性的，不是重启机制。

[`evidence/2026-09-18-divergence-is-latent.md`](evidence/2026-09-18-divergence-is-latent.md)
—— 第二轮核实。`commit_creds` 取任务是 `current`（`0x1867a0 mrs x20, sp_el0`），
`exit_creds` 把两个指针先置 NULL 再 `put_cred`；而原始证据显示老链往两个槽里写的是**同一个值**
（`0xffffff802a7e0be0`），新链写的是**两张不同的页**。所以判据是**指针相等** ——
「两枪写同一个值」，不是「两枪都落地」。

[`postreboot_forensics.sh`](postreboot_forensics.sh) —— **不依赖 poller** 的重启后取证。
判据是**单条件**：`CONFIG_PSTORE_CONSOLE=y` ⇒ `panic()` 在
`kmsg_dump(KMSG_DUMP_PANIC)` 那一刻就把 console 尾部写进 ramoops —— **发生在任何复位之前** ——
所以机器之后是重启还是挂住**都无关**。脚本 pull `/sys/fs/pstore/`、grep `kernel BUG` / `__put_cred` / `cred.c`、
打出 boot reason 的**字符串**（历史上出现过 `reboot,shell` / `bootloader` / `reboot,edl` 后缀，
所以 reason 能区分执行者，epoch 不能）。

> ⚠ **不要把「干净的 `bootreason=reboot`」读成「没有 panic」。** QCOM 上 SoC 看门狗 assert
> 之后正是经 **PMIC PON 块**复位，所以
> `panic → panic_timeout=-1 → 挂住 → 看门狗 → PMIC 复位 → 干净的 bootreason`
> 是一条**自洽**的链路，在现有证据下与「PMIC/硬件复位」**不可区分**。
> 本仓库自己拿到的 `total_17_dump_0_pmic_17` 把 17 次异常重启全部归因 `pmic` ——
> 而那正是看门狗复位的常规外形，**不是**「与内核无关」的证据。
> `bootreason` 在这里**收窄不了任何东西**；**ramoops 是唯一判据。**

两个前提，否则脚本的结论作废（铁律 8 —— 无信号类结论必须先证明通道可达）：

- **必须有第三态。** `/sys/fs/pstore/*` 是 root-only，Enforcing 下 `adb pull` 与 `cat` **都会失败** ——
  而「读不到」与「读到且为空」**输出完全相同**。两态脚本会从一个**从未打开过的通道**里
  打印出「pstore 为空 ⇒ 证伪 panic」。因此脚本会给出 **`CHANNEL UNREACHABLE`**
  （ls 失败，或已知条目全是「读失败」而非「不存在」），并同时报告 `getenforce`。
- **先做 null test。** 干净 `adb reboot` + 立刻取一次。若一次已知良好的重启都取不到可读内容，
  通道就没被证明，之后**所有**「空 pstore」都不算证据。
  **顺序要紧**：设备开机后不久就会把记录搬走并 unlink，所以流程是
  *重启 → 立刻 W1 拿 Permissive → 立刻跑脚本*。

[`run_bootA.sh`](run_bootA.sh) —— 那一次 boot 的编排，顺序是要紧的
（`0x778` → `0x780` **用同一个值** → 对**真正被装上**的那个 cred 做本地修复 → 确认 → 才 poke）。
`ADB=`/`SER=`/`BIN_LOCAL=` 可覆盖；`SAME_VALUE=1`（默认）强制同值规则，
`LAUNDER=1` 打开带门的洗白，同值序列**必须** `HOLD=600`。

**重试按阶段拆开**（`R5`/`R6`），因为两个阶段的风险性质相反：

| | 阶段 | 重试安全性 |
|---|---|---|
| `R5` | step 5，`task+0x778` | **安全** —— 打偏不装任何东西，而且戳判据让失败的 round 变成**可读**的，所以再打一枪只是再试一次。`R5=3` 把单枪命中率从 ~p 提到 ~1−(1−p)³。 |
| `R6` | step 6，`task+0x780` | **不安全，也不需要** —— 它只在 step 5 落地之后才发火，此时任务已经处于分歧态：再打一枪只是又一次机会去装上**第二张、不同的页**，而一枪落地就已经凑成一致对了。保持 1。 |

`R5` 默认取 `ROUNDS`，`R6` 默认 `1`。

**推荐的洗白命令** —— 走默认的喷页路径，**不是** `CONTROL=1`：

```bash
LAUNDER=1 R5=3 R6=1 HOLD=600 CHAINWAIT=6000 NODRAIN=1 WATCH=180 ./run_bootA.sh
```

`CONTROL=1` 同样能造出一致对，但代价是写 `init_cred` 指针，其副作用会**全局**写坏
`init_cred+8` —— 而"框架会不会死"正是这次要观察的现象之一，把一个设备级的故障带进
被测量的背景里，恰好会搅浑这一枪唯一要取的那个读数。喷页路径的代价只是"两枪都要落地"，
而这正是 `R5=3` 的用途。`CONTROL=1` 保留为**唯一被证实过**的一致对和对照，不作为推荐配置。

**"被装上的到底是哪张页"取自那行无条件的打印。** `run_w7` 把写值打在**两行**上，只有一行
是无条件的：

```
L1793  W7[..] write value = private cred page 0x..   —— 只有喷页路径
L1802  W7[..] write_value = 0x..                     —— if/else 之后，所有路径
```

runner 原来只匹配第一种措辞，于是在 `CONTROL=1` 下抽取结果为空 ⇒ `if [ -n "$CRED" ]`
把整段 repair 跳过 ⇒ 同时同值合取式里那个 `[ -n "$CRED" ]` 项把 SV 压成 0 ⇒
洗白门会**永远拒绝**。两处都是静默失效，起因只是一个只认得两个打印点之一的正则。
现在它与 `write_target`（戳判据的**输入**）一起走 `wv_from`/`wt_from`，
并和判据本身一样由回归测试驱动。

**两条流都在它们要测量的东西开始之前启动。** `uid.stream` 从阶段 1 就跑；
`cred.stream` **在 poke 那一刻**启动，而不是等 watch 之后 —— poke 会把子进程放进它的
NO_EXEC 自报循环，那是 240 × 0.5 s = 120 s，然后 `_exit(0)`（`exploit.c`：
"LT child NO-EXEC mode done (120s)"）；旧位置在 t+~135 s，等于在子进程已经消失之后才开始采样，
而那正是这个仪器存在的意义所在的窗口。此外 runner 在 `stamp_selftest()` 失败时拒绝继续，
并在戳与 `probe_state` 冲突时打印 **ORACLE INCONSISTENT** 而不是「没落地」。

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
