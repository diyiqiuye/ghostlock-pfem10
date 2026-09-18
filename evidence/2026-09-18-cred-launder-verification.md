# 验证：cred 洗白链、写形状重叠、以及一个新发现的硬 BUG

> 日期 2026-09-18 · 对象 = 外部建议（GhostLock 两条路径对比 + 四条建议）
> 方法 = **对目标内核镜像 `out/kernel_payload.bin` 逐条反汇编**（不是对通用 5.10 源码），
> 工具 `tools/kdis.py`。所有地址都是本机镜像的真实 VA。
> 标注沿用仓库约定：**✅已验证 / ⚠假设 / ❌已排除**。

---

## 结论摘要

| 建议 | 判定 | 一句话 |
|---|---|---|
| §1 用 `setresgid/setresuid` 洗白（换真 cred） | **✅ 机制成立，但前提写反了** | `commit_creds` 确实同时写两个指针；但它开头有 `BUG_ON(cred != real_cred)` ⇒ **必须先写满 0x778 和 0x780，而不是"跳过 0x778"** |
| §2 "四把伪锁不重叠" 自查 | **✅ 无重叠，且预测被推翻** | 副作用落点永远在喷页内，与 fd_set 网格（内核栈）物理隔离；A/B 两种形状都安全 |
| §3 换 `setsockopt(MCAST_JOIN_SOURCE_GROUP)` optname 46 | **⏸ 未评估** | 需要上机；仓库 README 早已把它列为**唯一未被检测器过滤的 optname**，方向上一致 |
| §4 "NebuSec 那段可以不做" | **⚠ 部分成立** | 若洗白成立则 `physrw` 退化为"写 1 字节 enforcing"，但**该 1 字节仍需 byte 粒度写**，而 8 字节 PI 写做不到 |
| §5 建议顺序 | **⚠ 需改写** | 见文末"建议顺序 v2" |
| （新）重启机制候选 | **★★★ 新发现** | 单字段落地 ⇒ `cred != real_cred` ⇒ 后续任何 `commit_creds` 走 `brk #0x800`；本机 `CONFIG_PANIC_ON_OOPS=y` ⇒ 立即 panic |

---

## 一、§1 洗白链：逐条对镜像核实

### 1.1 ✅ `commit_creds` 同时写两个指针 —— 建议说对了

`commit_creds @0xffffffc008186784`：

```
0x1867a4  ldr  x19, [x20, #0x778]     ; old = task->real_cred      (x20 = sp_el0 = current)
0x1867a8  ldr  x8,  [x20, #0x780]     ;        task->cred
0x1867ac  cmp  x8, x19
0x1867b0  b.ne #0xffffffc008186b68
...
0x186998  add  x8, x20, #0x778
0x18699c  stlr x21, [x8]              ; task->real_cred = new
0x1869a0  add  x8, x20, #0x780
0x1869a4  stlr x21, [x8]              ; task->cred      = new     ← 同一个 x21
```

⇒ 一次 `commit_creds` 把 `0x778`/`0x780` 写成**同一个指针**。`/proc/status` 与 `getuid()` 从此一致，
`0x778`/`0x780` 分裂被永久消除。**建议这一条 ✅ 成立。**

`put_cred(old)` 调用两次也 ✅：`0x1869e8` 与 `0x186a48` 各有一条 `ldaddal w8,w9,[x19]`（对 `old->usage` 做原子减）。
⇒ `old->usage` 必须 ≥ 2 才安全。喷页副本 `usage = 0x40000000`（`payload.c` 实测值）⇒ 安全；`init_cred` usage=4 ⇒ 安全。**建议这一条 ✅ 成立。**

### 1.2 ✅ `setresuid`/`setresgid` 确实走 `prepare_creds` + `commit_creds`

`__arm64_sys_setresuid @0xffffffc00815ff18` → `__sys_setresuid @0x…ff4c`：

```
0x16006c  mrs  x25, sp_el0
0x160070  ldr  x19, [x25, #0x780]     ; ★ 权限检查读 current_cred() = 0x780（建议说对了）
0x160074  ldr  w8, [x19, #4]          ; uid
0x160078  ldr  w8, [x19, #0x14]       ; euid
0x16007c  ldr  w8, [x19, #0xc]        ; suid
0x160080  ldr  w8, [x19, #0x1c]       ; fsuid
0x160070  bl   prepare_creds          ; @0xffffffc008186070
...
0x16022c  bl   commit_creds           ; @0xffffffc008186784
```

`__sys_setresgid` 同构（`0x1603d4 bl prepare_creds`、`0x160478 bl commit_creds`），字段用 `gid@8/egid@0x18/sgid@0x10/fsgid@0x20`。
⇒ **建议"权限检查用 0x780"✅ 成立**，"走真分配 + commit"✅ 成立。

### 1.3 ✅ `prepare_creds` = 真分配 + 真 LSM blob

`prepare_creds @0xffffffc008186070`：

```
0x186084  adrp x8, #0xffffffc00a9c5000
0x186088  ldr  x0, [x8, #0xf68]       ; cred_jar
0x18608c  mov  w1, #0xcc0             ; GFP_KERNEL
0x186090  bl   kmem_cache_alloc
0x1860a0  ldr  x20, [x8, #0x780]      ; old = task->cred
0x1860a4  mov  w2, #0xa8              ; ★★★ sizeof(struct cred) = 0xA8
0x1860b0  bl   __memcpy               ; memcpy(new, task->cred, 0xA8)
0x1860b8  str  wzr, [x19, #0x98]      ; new->non_rcu = 0
0x1860bc  str  w8(=1), [x19]          ; new->usage = 1
...
0x1861a8  str  xzr, [x19, #0x78]      ; new->security = NULL
0x1861ac  bl   security_prepare_creds ; (new, old = task->cred, GFP_KERNEL|__GFP_ZERO)
0x1861b8  bl   abort_creds             ; 失败路径
```

**两条副产品（对我们是硬数据）：**
- ★★★ **`sizeof(struct cred) = 0xA8`**（来自 `mov w2,#0xa8` 实测，不是推断）。与 `payload.h` 的 `PFEM10_CRED_SIZE 0xA8` 一致。
- ★★ `prepare_creds` 会对 **`new`（= old 的副本）** 的 `group_info@0x90` / `user@0x80` / keyring `0x58/0x60/0x68/0x70` 做**原子加**，并让 `security_prepare_creds` 读 **`old->security` = `task->cred + 0x78`**。
  ⇒ **假 cred 页的这些字段必须全是合法内核指针，否则洗白当场 fault。**
  ⇒ 好消息：`payload.c` 已经填了（`user=root_user`、`user_ns=init_user_ns`、`group_info=init_groups`、`security=喷页内 secblob`）。**这一条我们本来就满足**（✅ 实测字段 dump 在 `payload.c` 的 Phase1 打印里）。

### 1.4 配置侧确认

`out/config.txt`：`CONFIG_DEBUG_CREDENTIALS` **not set**（⇒ 无 `subscribers`/`magic` 校验，布局与 payload 注释一致）；
`CONFIG_KEYS=y`（⇒ 0x58–0x70 是 keyring 区）；`CONFIG_SECURITY=y` + `CONFIG_SECURITY_SELINUX=y`（⇒ `security@0x78`）；
`CONFIG_MULTIUSER=y`；**`CONFIG_USER_NS` not set**（⇒ `user_ns` 恒为 `init_user_ns`）。
⇒ 假 cred 页布局 **✅ 逐字段对上镜像**。

---

## 二、★★★ 新发现：`commit_creds` 开头的 `BUG_ON` —— 这很可能就是重启机制

### 2.1 事实（✅ 已验证）

上面 `0x1867b0  b.ne #0xffffffc008186b68` 的目标：

```
0xffffffc008186b68  brk #0x800      ; ← BUG()
0xffffffc008186b6c  brk #0x800      ; ← BUG_ON(atomic_read(&new->usage) < 1)
```

即源码级的 `BUG_ON(task->cred != task->real_cred);`。

而本机 **`CONFIG_PANIC_ON_OOPS=y` + `CONFIG_PANIC_ON_OOPS_VALUE=1`**（`out/config.txt`）
⇒ 这个 BUG **不是 oops，是立即 panic**。

`__put_cred @0xffffffc008185530` 里还有一组同族断言：

```
0x185540  ldar w8, [x0]              ; cred->usage
0x185544  cbnz w8, #0x185594         ; usage != 0 -> BUG
0x18554c  ldr  x9, [x8, #0x780]      ; current->cred
0x185550  cmp  x9, x0 ; b.eq #0x185598   ; cred == current->cred -> BUG
0x185558  ldr  x8, [x8, #0x778]      ; current->real_cred
0x18555c  cmp  x8, x0 ; b.eq #0x18559c   ; cred == current->real_cred -> BUG
```

### 2.2 推论

**我方写原语一次只写一个地址。** 所以 W7 任何一次"落地的"单字段写都产生：

```
task->real_cred = 假页   (0x778 落地)      或   task->real_cred = 旧 cred
task->cred      = 旧 cred                   或   task->cred      = 假页  (0x780 落地)
⇒ cred != real_cred  ← 分歧态
```

分歧态本身不致命（受害者子进程在自旋，不调 `commit_creds`）。**但一旦有任何 `commit_creds` 发生 —— `setresuid`/`setresgid`/`setuid`/`setgid`/`capset`/**`execve`（`install_exec_creds`）** —— 就是 `brk #0x800` → panic → 重启。**

★★ 注意：**LT 子进程的报告循环结束后就是 `exec /system/bin/id`**（`LT_EXEC`）。`execve` → `begin_new_exec` → `install_exec_creds` → `commit_creds`。**这是分歧态到 panic 之间最短的一条路。**

### 2.3 与观测的吻合度

| run | 落地 | 重启 | 与分歧假设 |
|---|---|---|---|
| 3 | 0x780 = **D** | 是（~3s） | ✅ 分歧 → panic |
| 9 | 0x780 = **D** | 是（~108s） | ✅ 分歧 → panic |
| **10** | **0x778 = D** | **是（22s）** | ✅ **反向单字段落地也重启** —— 分歧假设唯一的对称预测，观测吻合 |
| 7 / 8 | 全 R | 否 | ✅ 没落地 = 没分歧 |
| 12 + W1 四例（shape A） | **D** | **从不** | ✅ **shape A 根本不碰 0x778/0x780** ⇒ 不可能产生分歧 ⇒ 从不重启。**"shape 分界"被机制解释，不再只是相关性** |
| 11 | R | 是 | ⚠ 反例：`R` 却重启。但 `R` 是歧义值（内存 §Boot A 已记） |
| 13 | **空** | 是 | ⚠ **无数据**，见 §四 |

⇒ **⚠假设（不是结论）**：重启 = 分歧态 + 某个 `commit_creds` 调用点。**判据是 `brk #0x800` 会 printk 一行 "kernel BUG at …" 然后 panic** —— 而我们从没在重启那次抓到过内核日志（§四）。

---

## 三、§2 写形状重叠自查：结论"无重叠"，且建议的预测被推翻

### 3.1 四个形状词在哪

`fdset_map.h`：`wps=5`（`nfds=320`），`δ=0`。词 → 槽位：

| waiter 字段 | word | 槽位 |
|---|---|---|
| `tree.pc` = **write_value** | 0 | `in[0]` |
| `tree.right` = 0 | 1 | `in[1]` |
| `tree.left` = **write_target** | 2 | `in[2]` |
| `pi.pc/pi.right` | 3,4 | `in[3..4]` |
| `pi.left` | 5 | `out[0]` |
| `task` = **fake_task** | 6 | `out[1]` |
| `lock` = **fake_lock** | 7 | `out[2]` |
| `prio` = 130 | 8 | `out[3]` |
| `deadline` | 9 | `out[4]` |

**这四个词全部落在内核栈上的 `core_sys_select` 缓冲区（fd_set 网格）里。**

### 3.2 副作用落点在哪

副作用是 `*(write_value + 0x08) = write_target`。两种在用形状的 `write_value` **都是喷页内地址**：

- **shape A**：`write_value = base + 0x100`；`payload_base = base + SKB_DATA_DELTA = base − 0xe20`
  ⇒ 落点 = `base + 0x108` = `payload_base + 0xF28`。
  喷页内既有对象：`fake_fops 0x1000`、`fake_lock 0x1350`、`fake_w0 0x2220`、`scratch 0x3000`、`fake_task 0x3200`、`leak P0 0x4100`、`rb_right 0x4440`、`rb_left 0x5550`。
  ⇒ **0xF28 < 0x1000，距最近的 `fake_fops` 还有 0xD8 字节，无重叠。**
- **shape B**：`write_value = g_cred_copy_addr = payload_base + 0x8000 + 0x3C00 = payload_base + 0xBC00`
  ⇒ 落点 `0xBC08` = `cred->gid`/`suid`（**就是已知的那处自伤**），仍在 cred 副本 `0xBC00..0xBCA8` 之内，**无重叠**。

### 3.3 判定

★★ **两种形状都不重叠** —— 落点在**喷页**，形状词在**内核栈**，两者物理隔离，不可能互相踩。
⇒ 建议 §2 的预测（"重叠的是 shape A，而 shape A 从不重启"）**与事实相反**：**shape A 本来就不重叠**。
⇒ 因此 **"erase 逃逸到真实内核对象"这一支 ❌ 已排除**（对在用形状而言）。**离线可判，不占机器。**

---

## 四、★★★ 证据覆盖失败：重启那一次的内核日志从来没抓到

这一条**独立于上面所有结论，而且更严重**。

`out/` 下确实有 5 个 run 的 klog：`run8_055633` / `run9_060605` / `run10_061604` / `run11_062421` / `run13_065539`。逐个查：

| run | klog 行数 | uptime 窗口 | 说明 |
|---|---|---|---|
| run8（未重启） | 4249 | 2889 → 3398 | 正常 |
| run9（重启） | 3888 | 3476 → 3935 | 末尾是例行充电/看门狗心跳，**无 BUG/panic** |
| **run10（重启）** | 9034 | **350 → 535** | ⚠ **这是"新 boot"的日志**，不是出事那次 |
| **run11（重启）** | **0** | — | ⚠ **空文件** |
| **run13（重启）** | **0** | — | ⚠ **空文件** |

⇒ **4 次重启里，只有 run 9 可能覆盖到出事时刻，而它的末尾没有任何 BUG/panic 标记。**
⇒ 之前"全部有序重启、无 panic/BUG/Call trace"的说法，**样本是 1（run 9）+ 若干次抓取失败**，不是 4。**覆盖范围必须如实。**

### 4.1 附带发现：**run 13 的证据整体无效**

```
[06:56:29]   [w778r1] ONE shot: off=0x778 chainwait=6000ms ...
adb.exe: device '91f71075' not found          ← 第一次"设备不在"出现在 shot 开始后不久
[06:57:56]   [w778r1] shot wall-clock: 86s
[06:58:03]   [w778r1] victim readback NOW: []      ← 空
[06:58:05]   [w778r1] probe_state=                 ← 空
[07:00:20]   [w780r1] probe_state=                 ← 空
[07:00:22]   !! DEVICE GONE after w780 round 1
```

`run13_uid.trace` 最后一行**有内容**的是 `06:56:53`（`Uid: 2000 2000 2000 2000`），之后全是空行。
⇒ **设备在 0x778 那一枪刚开火不久就没了，所有测量通道当时都已失效。**

⇒ ⛔ **必须撤回** MEMORY.md 里的：
> "run 13 的 `uid.trace` 证明 cred 从未动过 ⇒ 重启不需要'写落地'"

**这条撤回本身是错的**，理由有二：
1. `probe_state` 与 readback 都是**空**（通道已死），不是"没变化"；
2. `uid.trace` 读的是 `/proc/<pid>/status` = **`real_cred` (0x778)**，对 **0x780 的写入天然盲**。
   ⇒ 即便设备活着，"trace 没动"也只能证明 **0x778 没被写**，不能证明"写没落地"。

★ 这正是铁律 8（"无内核信号"类结论必须先验通道可达性）**第二次栽在同一个坑里**：把空字段读成"无变化"。

---

## 五、已实现的改动（仅编译，未上机）

`src/core/exploit.c`（+2 处）：

1. **`lt_cred_ids_agree()`** —— 新函数。同时读 `getuid()/getgid()`（= `cred@0x780`）与
   `/proc/self/status` 的 `Uid:`/`Gid:`（= `real_cred@0x778`），**判定两者是否一致**。
   函数头注释里带上了 `commit_creds` 的 `brk #0x800` 反汇编证据与"必要但不充分"的说明。
2. **`V12_LAUNDER=1` 门** —— 放在 LT 子进程报告循环之后、`NO_EXEC`/`exec` 之前。
   - 先做一致性检查；**不一致就直接拒绝并打印原因**（因为那一定会 panic）。
   - 一致才依次 `setgroups(0,NULL)` → `setresgid(0,0,0)` → `setresuid(0,0,0)`，
     然后回读 `uid/euid/gid/status_uid/status_gid/capeff/caps/consistent` 落进证据文件。
3. **报告行加instrument** —— 报告循环那一行现在同时打印
   `uid=`（0x780 视角）与 `real_uid=/real_gid=/consistent=`（0x778 视角）。
   ⇒ **分歧态从此在证据文件里直接可见，不需要推断。**

编译：NDK r28c / clang 19 / `-D__ARM=1 -O1 -Wall -Wextra`，**零警告**。
产物 `exploit_guard`：`ELF64 / DYN / AArch64`，`sha256 = 8f7f31bcfac931014fb2ff32358cbc9bdd1c74749f732416f46dbb4c2de0cef9`。

> ⚠ **没有上机。** 写设备必须用户逐次明令。

---

## 六、建议顺序 v2（替换原 §5）

原建议的"先做 V12_LAUNDER"**方向对，但会 panic**，因为它的前提写反了。修正后：

1. **先做"写满两个指针"的实验，再做洗白。** 单变量、最便宜、且直接判 §2 的机制：
   一 boot 两枪 —— `0x778` 一枪 + `0x780` 一枪（同一次运行内），然后看
   - 分歧消失（`consistent=1`）⇒ 再开 `V12_LAUNDER=1`，看是否不重启；
   - 仍然重启 ⇒ 分歧不是充分原因，回到机制未定。
   ⚠ 注意两枪都要落地才一致；只落一枪 = 分歧 = 比现在更危险。**建议先只跑这一项、单独一个 boot。**
2. **把"重启那次的内核日志"当成独立任务做掉。** run 11/13 的 klog 是 0 字节，run 10 抓的是新 boot
   ⇒ **现在的采集在"出事那一刻"是坏的**。先修采集（poller 存活确认 + 出事前落盘 + 校验非空），
   再谈任何机制结论。**这一步不做，后面所有机制讨论都是在猜。**
3. `V12_LAUNDER=1`（已实现、已编译）—— 只在上一步给出"一致"之后开。
4. `fdset_map.h` 重叠自查 —— **本轮已做完，结论"无重叠"**，不需要再占机器。
5. `setsockopt(MCAST_JOIN_SOURCE_GROUP)` optname 46 换栈整形 —— 单独一个 build、单独一个 boot，**不要和 1 混**。

## 七、仍然未定的（如实）

- ⚠ **分歧态到 panic 的具体调用点未定位**。`execve`（`install_exec_creds`）是逻辑上最短的一条，但**没有实测**。
- ⚠ **run 11 的 `R` 却重启** 仍未解释（`R` 是歧义值）。
- ⚠ **§3 的 optname 46 未评估**（需上机）。
- ❌ **不声称"重启机制已确立"**。本轮只是把"shape 相关性"提升为"有一个具体、可测的机制候选"。
