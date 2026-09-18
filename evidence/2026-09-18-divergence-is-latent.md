# 验证（第二轮）：分歧态是惰性的 —— 真正的判据是"两枪写同一个值"

> 对象：外部对 `验证_cred洗白与分歧_2026-09-18.md` 的评审。
> 方法：仍然是对**本机镜像**（`out/kernel_payload.bin`）反汇编 + 对**原始证据文件**逐行核对，
> 不引用通用 5.10 源码。
> 结论：**评审的四条实质指控全部成立**，其中两条推翻了我上一轮的结论，一条指出我写的代码有安全漏洞。
> 本报告同时记录本轮新增的一个**结构性发现**（§二），它比被推翻的那条更重要。

---

## 结论摘要

| # | 指控 | 判定 | 依据 |
|---|---|---|---|
| 1 | `commit_creds` 只作用于 `current`，runs 3/9/10 全是 NO_EXEC ⇒ 那三次**没有** `commit_creds` ⇒ 分歧是惰性的 | ✅ **成立** | `0x1867a0 mrs x20, sp_el0`；三个 run 的日志逐字写明 NO_EXEC；`exit_creds` 先置 NULL |
| 2 | run 10 根本没 poke | ✅ **成立** | `grep -c poke run10_0616.log` = 0 |
| 3 | 老链与新链的结构差别是"**同值**"而非"落地" | ✅ **成立，且已用原始证据证实** | `out/t5_w7_778.txt` 与 `out/t5_w7_780.txt` 的 `in[0]` 都是 `0xffffff802a7e0be0`；新链两枪各写各的页 |
| 4 | 我写的 `consistent=` 门是**漏的**（内容比较 vs 指针比较） | ✅ **成立** | `lt_cred_ids_agree()` 返回 `ruid == getuid()`，纯内容比较 |
| 5 | run 11 的 `R` 只能是 unknown | ✅ **成立** | `run11_w778r1_miss.txt` 与 `run7 w7_w7781.txt` 逐行同构 |
| 6 | `pi.pc/right/left` 在位图里但没有入口 | ✅ **成立** | `fdset_map.h` L132-143 vs L148-154 / L164-171 |
| 7 | "§1 成立 ⇒ 0x778 那一枪可以不打" | ✅ 评审自己撤回，**同意** | 见 §三 |

**一句话**：§2 找到的是一个**真实的地雷**，但它被放在了一个**从未触发**的场景里。真正把老链和新链分开的，
是 `BUG_ON` 比的是**指针**，而两次 W7 各写各的页。**先把两枪写成同一个值，再谈洗白。**

---

## 一、撤回：分歧态在 runs 3/9/10 是惰性的（✅ 已验证）

### 1.1 `commit_creds` 只作用于 `current`

```
0xffffffc008186784  paciasp
0xffffffc0081867a0  mrs  x20, sp_el0        ← task = current（不是参数！）
0xffffffc0081867a4  ldr  x19, [x20, #0x778]  ← real_cred
0xffffffc0081867a8  ldr  x8,  [x20, #0x780]  ← cred
0xffffffc0081867ac  cmp  x8, x19
0xffffffc0081867b0  b.ne #0xffffffc008186b68
0xffffffc008186b68  brk  #0x800              ← BUG_ON(task->cred != task->real_cred)
```

`x0` 是 `new`（`mov x21, x0`，随后 `ldar w8,[x0]` 是 usage 引用计数检查）——
签名是 `commit_creds(struct cred *new)`，**没有 task 参数**。

⇒ **分歧态只有在"持有该 cred 的那个任务自己"调用 `commit_creds` 时才会炸。**

### 1.2 那三次 run 都是 NO_EXEC

```
run3_0445.log:18  === step 3: LT child (pure userspace spin, NO_EXEC) ===
run9_0606.log:20  === step 4: LT child (pure userspace spin, NO_EXEC) ===
run10_0616.log:24 === step 4: LT child (pure userspace spin, NO_EXEC) ===
```

NO_EXEC ⇒ 子进程不发 `execve`（`exploit.c` L2547-2569：报告 240×0.5s 后直接 `_exit(0)`）
⇒ 没有 `install_exec_creds` ⇒ 没有 `commit_creds`。

### 1.3 `exit_creds` 把分歧**抹掉**而不是惩罚它

```
0xffffffc008185cb4  ldr  x0,  [x0, #0x778]   ← old1 = real_cred
0xffffffc008185cb8  str  xzr, [x19, #0x778]  ← real_cred = NULL
   ... put_cred(old1)
0xffffffc008185d20  ldr  x20, [x19, #0x780]  ← old2 = cred
0xffffffc008185d24  str  xzr, [x19, #0x780]  ← cred = NULL
   ... put_cred(old2)
```

`__put_cred` 的 BUG_ON 比较的是 `current->cred` / `current->real_cred`（`0x185ce8`/`0x185cf4`），
而此刻**两个都已经是 NULL**，被释放的 `old` 非 NULL（`cbz` 已挡）⇒ **不命中**。

⇒ 子进程 `_exit(0)` 时分歧态被清零。**惰性，不是地雷爆炸。**

### 1.4 run 10 没有 poke

```
$ grep -c poke run10_0616.log
0
```

且 run 10 的 0x778 落地（`probe_state=D`，page `0xffffff8874e9ade0`）后 **22 秒**设备就没了
（06:22:04 记录 D → 06:22:26 `DEVICE GONE`）。

### 1.5 判定

| run | 落地 | 重启 | 上一轮写的 | 修正后 |
|---|---|---|---|---|
| 3 | 0x780 = D | 是 | ✅ 分歧 → panic | ⚠ **未建立**（NO_EXEC，无 commit_creds） |
| 9 | 0x780 = D | 是 | ✅ 分歧 → panic | ⚠ **未建立**（同上） |
| 10 | 0x778 = D | 是 | ✅ 分歧 → panic | ⚠ **未建立**（同上，且无 poke） |
| 7/8 | 全 R | 否 | ✅ 没落地 = 没分歧 | ⚠ 相关性保留，机制解释撤回 |
| 12 + W1 四例 | D | 从不 | ✅ **shape 被机制解释** | ⚠ **降级为相关性** |
| 11 | R | 是 | ⚠ 反例 | ⚠ 反例（且 `R` 是 unknown，见 §四） |

**§2.1 的 `BUG_ON` 事实不变**（它确实存在、确实是 `PANIC_ON_OOPS=y` 下的立即 panic）。
撤回的是**把它当成这三次重启的解释**。

---

## 二、★★★ 真正的判据：两枪必须写**同一个值**（✅ 已用原始证据证实）

这是本轮最有价值的发现，而且它不是推测 —— 是两份原始证据文件里的 `in[0]` 直接对比。

### 2.1 老链：两枪写的是**同一个固定地址**

`out/t5_w7_778.txt`（09-14，0x778 那一枪）：
```
[*] shape shift=0 wps=5: in[0]=0xffffff802a7e0be0 (write_value) in[2]=0xffffff8800cdd178 (write_target)
probe_state    = D
Uid:	0	0	4294967176	0
*** 0x778 LANDED (Uid=0) ***
```

`out/t5_w7_780.txt`（同一链，0x780 那一枪，attempt 1 与 3 都是 `probe_state = D`）：
```
[*] shape shift=0 wps=5: in[0]=0xffffff802a7e0be0 (write_value) in[2]=0xffffff8800cdd180 (write_target)
probe_state    = D
```

**`in[0]` 两次完全相同：`0xffffff802a7e0be0`** —— `init_cred` 的 P0 别名，一个固定全局地址。

⇒ `real_cred == cred == init_cred` ⇒ **指针相等** ⇒ 后续 `execve`（→ `install_exec_creds` →
`commit_creds`）合法 ⇒ **ksud 能载、manager 活 120s**。

**为什么老链天然同值**：`tools/t5loop.sh` L28-32 与 L43 —— `$ENVV` 由 `MODE` 决定，而
**同一个 `$ENVV` 施加到循环里所有 offset**。所以 `MODE=CRED` 时两枪都写 `init_cred`，
**同值是构造出来的，不是碰运气**。

### 2.2 新链：两枪写的是**两张不同的喷页**

`run9_0606.log`：
```
step 5 (0x778): write value = private cred page 0xffffff88679bade0
step 6 (0x780): write value = private cred page 0xffffff8785d6ade0   ← 不同页
```
`run3_0445.log`：
```
step 4 (0x778): write value = private cred page 0xffffff8787b5ade0
step 5 (0x780): write value = private cred page 0xffffff881bad2de0   ← 不同页
```

两次的 PIN child 也是**不同进程**（run 9：24656 / 30873），各有各的喷页。

**为什么新链必然不同值**：`run_bootA.sh` 的 step 5 与 step 6 各自以**空的 `$extra`** 开火
（`shot_until 0x778 "" w778` / `shot_until 0x780 "" w780`），
⇒ 每次都走 `write_value = base + 0x100` 的**自己那张新喷页**分支。

### 2.3 所以要求不是"两枪都打"，是"两枪写同一个值"

即使两枪都落地，`(pageA, pageB)` 仍然是 `real_cred != cred`。**判据是指针相等，不是"有没有落地"。**

⇒ 这也让 §二 与 §一 自洽：**老链之所以能走到 ksud，不是因为它的枪打得准，而是因为它的两枪同值。**

---

## 三、我写的 `consistent=` 门是**漏的**（✅ 成立，已修）

### 3.1 漏洞

`lt_cred_ids_agree()` 的实现（`exploit.c`）：
```c
return (ruid == (unsigned)getuid()) && (rgid == (unsigned)getgid());
```
`ruid` 来自 `/proc/self/status`（= `real_cred` = `task+0x778`），
`getuid()` 来自 `current_cred()`（= `cred` = `task+0x780`）。
**这是内容比较；`BUG_ON` 比的是指针。两个问题不是同一个问题。**

| 情形 | 内容比较 | 指针 | 我的门 |
|---|---|---|---|
| 单枪落地 | `0` vs `2000` | 分歧 | ✅ 拦住 |
| **两枪落地、页不同** | **都是 0 ⇒ 报"一致"** | **仍分歧** | ❌ **放行 ⇒ panic** |
| 两枪都没落地 | `2000` / `2000` | 一致 | ✅ 放行，但 `setresgid` 在权限检查处 -EPERM → `abort_creds`，不 commit，无害 |

**而 runner 当时正在生产第 2 行**（step 5 / step 6 各喷各的页）。⇒ 我上一轮加的"安全门"
在它最该拦住的那个情形下会放行。

### 3.2 修法：门不能靠"观测"，只能靠"出身"

**没有读原语 ⇒ 指针身份在用户态不可观测。** 所以正确的门不是更好的观测，而是
**一个我们自己控制的事实**：两枪是否被指定了同一个值。

已实现：`V12_LAUNDER=1` 现在要求 `V12_W7_SAME_VALUE=1`（由 runner 在 step 6 复用 step 5 的
观测值时设置）。在此前提下，**内容一致 ⇔ 两枪都落在同一张页**，门才成立。
未声明 ⇒ 拒绝，并把"无法区分第 2 行和第 3 行"的理由打进证据。

---

## 四、run 11 的 `R` 只能是 unknown（✅ 成立）

`run11_w778r1_miss.txt` 与 `run7 w7_w7781.txt` 逐行同构：

| | run 11 | run 7 |
|---|---|---|
| `probe_state` | `R` | `R` |
| `probe_done` | `0` | `0` |
| exploit 自己的判定 | `✗ W7[W7] miss` | `✗ W7[W7] miss` |

run 7 **确定没落地且没重启**；run 11 是同一形态却重启。
⇒ run 11 的 `R` **不携带"落地了"的信息**，只能是 unknown。
上一轮在 §2.3 里把 run 11 的 `R` 当作"落地了"的证据，**内部不一致，撤回**。

（附带：`probe_state=D` 时 exploit 自己打印 `✗ miss` —— 这个已知 bug 在这两个文件里再次现身，
是"不要相信它的 HIT/miss 行"的又一个实例。）

---

## 五、pi 侧：评审的判断逐条对上 `fdset_map.h`（✅ 成立）

| 评审的说法 | 文件事实 |
|---|---|
| `pi.pc(in[3]) / pi.right(in[4]) / pi.left(out[0])` 在词表里 | ✅ `fdset_map.h` L136-138 有 `pi.pc`(word 3) / `pi.right`(word 4) / `pi.left`(word 5) |
| `fdsetm_write_shape_t` 没给入口 | ✅ L148-154 只有 `write_value`/`write_target`/`waiter_task`/`waiter_lock`/`waiter_prio` |
| `fdsetm_build` 的 switch 没给入口 ⇒ 恒为 0 | ✅ L164-171 无 `PI_PC_OFF`/`PI_RIGHT_OFF`/`PI_LEFT_OFF` 分支 ⇒ 落到 `default: break` ⇒ `v = w->value = 0` |

**如果 pi 侧的 store 与 tree 侧在同一次链走查里执行**，那么一次 pass 可以给出两对 store：
```
tree 侧: *(in[2]) = in[0]      pi 侧: *(out[0]) = in[3]
in[0] = P, in[2] = task+0x778, in[3] = P, out[0] = task+0x780
⇒ 同一个 P 写进两个槽 ⇒ 分歧态从"存在一整个 boot"变成"不存在"，且不再需要两枪。
```
⚠ **未建立**：`pi.*` 现在恒为 0，是否让整支被跳过，是**经验问题**。
评审给的验证法很省：**只改 fd_set 字节、不动 δ=0 几何**，令
`out[0] = p0_alias(SELINUX_ENFORCING)`、`in[3] = 低字节为 0 的页`，看 `getenforce` 是否变 0
—— **用 W1 已有的 oracle 去测 pi 侧存不存在**。⚠ 副作用可能落在 `+8` 或 `+0x10`；
若触发 `+0x10`，现在的 repair 只清 8 字节，**要跟着扩**。

---

## 六、本轮实现的改动（**仅编译与离线核对，未上机**）

### 6.1 `run_bootA.sh`

1. **★ step 6 复用 step 5 的写值**（新增 `SAME_VALUE=1`，默认开）
   —— 这是把"两枪各写各的页"改成"两枪同值"的**核心改动**。抽值用
   `sed -n 's/.*write_value *= *\(0x[0-9a-f]*\).*/\1/p'`，已对**真实证据文件**验证
   （`run11_w778r1_miss.txt` → `0xffffff8826c22de0`）。
   抽不到值 ⇒ **拒绝发第二枪**（并说明否则就是制造分歧对），可用 `SAME_VALUE=0` 强制。
2. **★ `CONTROL=1` 路径同时覆盖两枪** —— 见 §七，这是一处**新发现的坑**。
3. **`LAUNDER=1`** 透传 `V12_LAUNDER` 与 `V12_W7_SAME_VALUE` 给 LT 子进程。
4. **★ 内核日志采集加硬护栏** —— run 10 的采集就是死在
   `run_bootA.sh: line 152: .../run10_061604/klog.host: No such file or directory`，
   代价不是丢一个文件，而是**丢掉那次重启**（所以 run 10 抓的是新 boot）。
   现在 `start_klog` 先 `mkdir -p`，建不出来就**退出（exit 4）**，不让重定向决定我们能不能诊断重启。
5. **★ uid.stream 加 `utime/stime/voluntary_ctxt_switches`**
   —— 评审提的"最便宜的前提校验"。`/proc/<pid>/stat` 字段 14/15（剥掉 `pid (comm)` 前缀后是 12/13）。
   判据：纯用户态自旋 ⇒ **`utime` 涨、`stime` 平、`nvcsw` 不动**。
   此前"纯用户态自旋"只是**一句注释**；现在它有了签名，动一下就要重推所有"不可能有 commit_creds"的论证。

### 6.2 `src/core/exploit.c`

**门控重写**：`V12_LAUNDER=1` 现在要求 `V12_W7_SAME_VALUE=1`，否则拒绝，并把
"内容比较 vs 指针比较"的**四情形表**写进注释与证据行（`same_value_declared=` 字段）。
理由见 §三：没有读原语时，指针身份只能靠**出身**保证，不能靠观测。

### 6.3 新增 `postreboot_forensics.sh` —— 不依赖 poller 的证伪通道

评审这条是对的，而且本机的 config 让它**比想象的更有力**：

```
CONFIG_PSTORE=y  CONFIG_PSTORE_CONSOLE=y  CONFIG_PSTORE_RAM=y   → panic 把 console 尾部写进 ramoops，跨复位存活
CONFIG_PANIC_TIMEOUT=-1                                          → panic 后【不自动重启】，机器是挂住的
```

两者合起来 ⇒ **判据互斥**：干净的 `bootreason=reboot` **不可能**是 panic（panic 不重启），
除非另有力量（PMIC/看门狗）把挂住的机器复位 —— 而**即使那样 ramoops 里仍然留着 panic 文本**。

所以：pstore 里有 `kernel BUG at …` ⇒ 是 panic；pstore 空 ⇒ 没有 panic
（**前提**：ramoops 保留区确实注册了 —— 脚本会检查 `/proc/iomem`、device-tree、
`/sys/module/ramoops/parameters/*`，并按"它有权下哪个结论"分别打印，**不硬说"没有 panic"**）。

脚本同时按要求**打出 reason 串**（`ro.boot.bootreason` + 把 `persist.sys.boot.reason.history`
按 `epoch,reason` 拆开逐条列），因为历史上出现过 `reboot,shell` / `bootloader` / `reboot,edl`
——**只有 reason 串能区分是谁干的，epoch 不能**。

---

## 七、★ 新发现：评审建议的 `CONTROL=1` 命令，**按字面执行会制造分歧对**

评审 §4 第 1 条建议：

> `CONTROL=1` 重跑老链的两枪（零新代码）—— 这是本机唯一被证实能产生一致对的配置

**建议的意图是对的**（cell 2 确实是唯一被证实的一致对），但**代码不是这样实现的**：

```sh
# 修改前
if [ "$CONTROL" = "1" ]; then
    shot_until 0x778 "V12_ALLOW_INIT_CRED=1 V12_W7_INIT_CRED=1" w778ctl "$ROUNDS" || true
else
    shot_until 0x778 "" w778 "$ROUNDS" || true
fi
...
if shot_until 0x780 "" w780 "$ROUNDS"; then        # ← 空的 $extra，不受 CONTROL 影响
```

`CONTROL=1` **只改 step 5**；step 6 仍然以空 `$extra` 开火 ⇒ 仍然喷自己的新页
⇒ 结果是 `(init_cred, 新喷页)` ⇒ **分歧对** ⇒ 接着 step 8 poke（run_bootA 会 poke）
⇒ 一旦有任何 `commit_creds` ⇒ `brk #0x800` ⇒ panic。

**已修**：`CONTROL=1` 现在同时把两枪都设为 `V12_ALLOW_INIT_CRED=1 V12_W7_INIT_CRED=1`，
并在日志里标明 `[same-value] step 6 will reuse the init_cred image (cell-2 reproduction)`。

⚠ 同时必须记住：cell 2 之所以"有效"，代价是**把 `init_cred+8` 全局写坏**
（`Uid: 0 0 4294967176 0` 就是这个副作用；`init_cred` 被所有内核线程共用）。
它是**对照**，不是目标配置。

---

## 八、建议顺序 v3

1. **`postreboot_forensics.sh` —— 先修采集/判据，再谈机制。**
   它不依赖 poller，一条命令就能给"到底有没有 panic"一个**有权下的结论**。
   在它还空着之前，任何机制讨论都是猜。
2. **`CONTROL=1 HOLD=600 ROUNDS=1 CHAINWAIT=6000 NODRAIN=1 WATCH=180 ./run_bootA.sh`**
   —— **修好之后**的 CONTROL=1 才等于 cell 2。看 `consistent=1` 且 `uid=0`。
   这是唯一被证实能产生**一致对**的配置。
3. **同一 boot 追加 `LAUNDER=1`**（runner 现在会自动带上 `V12_W7_SAME_VALUE`），
   看它能否从 `init_cred` 走到真 cred。
4. **`SAME_VALUE=1` 的私有喷页版**（默认路径）—— 把一致对从"借固定全局"变成"自己的页"，
   从而摆脱 `init_cred` 被写坏的代价。**这是真正的目标配置。**
5. **pi 侧验证**（可离线先做）：用 W1 的 `getenforce` oracle 测 `out[0]`/`in[3]`，
   若成立 ⇒ 一次 pass 双写 ⇒ 不需要两枪，也不需要同值抽取。
6. `uid.stream` 的 `stime/nvcsw` 读数要**回看**：它是"纯用户态自旋"这个设计前提的第一个直接证据。

---

## 九、仍未定的（如实）

* ❌ **重启机制本身**：仍未确立。本轮只是**排除**了"分歧→panic"作为 runs 3/9/10 的解释，
  并没有给出替代解释。（`trigger_is_the_target.md` 的 PMIC 线索未证伪，但也没证实。）
* ❌ **到达 `commit_creds` 的确切调用点**：`execve`→`install_exec_creds` 是最短逻辑路径，**未测**。
* ⚠ **"纯用户态自旋"**：本轮才加上仪器，**还没有读数**。
* ⚠ **pi 侧 store 是否在同一次链走查里执行**：未建立。
* ⚠ **`SAME_VALUE=1` 的一致对是否真能产生**：未上机。抽值逻辑已对历史证据验证，
  但"两枪同值 + 都落地"这个组合**从未在真机上出现过**（老链用的是 `init_cred`，不是喷页）。
* ⚠ `HOLD` 必须 ≥ 第二枪开火时刻，否则第一枪的页被释放 ⇒ "同值"变成悬垂指针。
  默认 `HOLD=20` **不够**，用 `HOLD=600`。
