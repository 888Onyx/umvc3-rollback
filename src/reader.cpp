// reader.cpp — MtScalable header-reading classifier (the READER, v2: membership-based liveness).
//
// A SECOND read-only shadow path inside arena::load(). For each dirty page it computes the object-granular
// revert result and compares it byte-for-byte to page-blind's result, logging READER-DIFF / READER-VAP /
// READER-GAP. Zero writes to game/arena memory — the reader writes only its own scratch/bitmasks in .bss.
//
// -------------------------------------------------------------------------------------------------------
// The v2 FIX — liveness by LIST MEMBERSHIP, captured at the right TIME (not by reading arena header bits)
// -------------------------------------------------------------------------------------------------------
// v1 read in_use@now from live_pg / the live arena INSIDE compare_page. But compare_page runs after
// page-blind already reverted the page to its frame-N image, so that "live" bit was actually the frame-N
// bit => in_use@now == in_use@N always => the VAPORIZE (free@N & in-use@now) and RESURRECT (in-use@N &
// free@now) branches were DEAD CODE and READER-DIFF=0 was vacuously true. Fatal: the long run could not
// validate the reader.
//
// v2 derives both booleans from allocator LIST membership:
// in_use@now = block is on the LIVE control's ALLOC list, walked in begin() at the TOP of load() before
// any page-blind revert (arena still truly live). Recorded into a page-indexed live edge map.
// in_use@N = block is on the FRAME-N SNAPSHOT control's ALLOC list (walked via snap_read).
// block+0x38 bit0 is never used for liveness (page-blind mutates it); it is used only for SIZE:
// size = ((snap_u32(B+0x38) >> 1) << 4) = total block bytes incl the 0x50 header.
// Size for in_use@N blocks comes from the frame-N snapshot; for in_use@now-only blocks from begin()'s
// pre-revert live capture.
//
// Binary offsets (all confirmed vs FUN_1404CA650 / FUN_1404CB350 in umvc3_unpacked.exe):
// ctrl+0x90 pool_base | ctrl+0x98 pool_end | ctrl+0x534 == 0x20000000 pool_size sig
// desc[k] = ctrl+0xd8 + k*0xa8 (k=0..7); desc+0x40 alloc head/tail (walk start); desc+0x50 alloc count
// desc+0x58 free head. block+0x20 logical next (alloc+free); block+0x38 size|inuse; block+0x3c class;
// user-ptr = block+0x50.

#include "reader.h"
#include "arena.h"
#include "addr.h"
#include "log.h"
#include <cstring>
#include <intrin.h>

// ---- Binary-confirmed layout constants ----
static constexpr size_t   PAGE_SIZE         = 4096;
static constexpr size_t   MAX_PAGES         = 524288;   // ARENA_SIZE(2GB) / PAGE_SIZE
static constexpr size_t   BLOCK_HDR         = 0x50;     // user_ptr = block + 0x50
static constexpr int      MAX_CTRLS         = 64;     // registered-control registry cap (matches alloc_invariants's nreg clamp)
static constexpr size_t   DESC_STRIDE       = 0xa8;
static constexpr size_t   CTRL_DESC_OFF     = 0xd8;     // &desc[0] = ctrl + 0xd8
static constexpr size_t   CTRL_POOL_BASE    = 0x90;     // *(u64*)(ctrl+0x90) = pool_base
static constexpr size_t   CTRL_POOL_END     = 0x98;     // *(u64*)(ctrl+0x98) = pool_end
static constexpr size_t   CTRL_NCLS_OFF     = 0x648;    // *(int*)(ctrl+0x648) = active size-class count (clamp [1,8])
// Registry statics (addr::resolve of the IDA absolute addrs; identical to alloc_invariants.cpp's proven method).
static constexpr uintptr_t IDA_REG_COUNT    = 0x140D760E0ULL;  // u32 registered-control count
static constexpr uintptr_t IDA_REG_ARRAY    = 0x140D760F0ULL;  // array of control ptrs (8 bytes each)
static constexpr uintptr_t IDA_SCALABLE_VT  = 0x140B08620ULL;  // MtScalable vtable (a valid control's *(u64*)ctrl == this)
static constexpr size_t   BLOCK_NEXT        = 0x20;     // logical next in alloc/free list
static constexpr size_t   BLOCK_SLAB_BACKPTR= 0x08;     // 0 => level-1 (slab/reserve chunk); else => owning slab base
static constexpr size_t   BLOCK_INUSE_WORD  = 0x38;     // bit0=in_use; (>>1)<<4 = total bytes (incl the 0x50 hdr)
static constexpr size_t   BLOCK_CLASS_WORD  = 0x3c;     // (>>2)&0x1f = class nibble (0 for a slab, 1..8 for sub-blocks)
static constexpr size_t   DESC_ALLOC_TAIL   = 0x40;     // alloc-list head/tail (walk start for alloc)
static constexpr size_t   DESC_ALLOC_CNT    = 0x50;     // alloc block count (u32) — slack bound
static constexpr size_t   DESC_FREE_HEAD    = 0x58;     // free-list head (walk start for free; snapshot side only)

static constexpr int      WALK_ITER_GUARD   = 1 << 20;  // absolute max list hops/descriptor (a small size-class can hold >64k live blocks; the edge-pool cap is the real coverage bound)
static constexpr int      WALK_SLACK        = 512;      // hops allowed beyond the descriptor's block count
static constexpr size_t   MAX_BLOCK_SIZE    = 0x20000000; // pool_size — any block bigger => corrupt header
static constexpr uint32_t MAX_LIVE_EDGES    = 1u << 20; // page->live-block edges (16B each => 16 MB.bss)
static constexpr uint32_t MAX_SNAP_EDGES    = 1u << 21; // page->snap-block edges (24B each => 48 MB.bss; headroom for heavy loads now the walk is count-bounded)
static constexpr uint32_t EDGE_END          = 0xFFFFFFFFu;

namespace {

// ---- Controls (in-arena MtScalable control CACHE — discovered from the .data registry, alloc_invariants's method) ----
static uintptr_t g_ctrls[MAX_CTRLS];                  // control struct addrs (vtable-valid and pool in-arena)
static uint8_t   g_ctrl_ncls[MAX_CTRLS];              // active size-class count per control (clamped [1,8])
static uintptr_t g_ctrl_lo[MAX_CTRLS];                // pool_base per control (ctrl+0x90; ctor-invariant)
static uintptr_t g_ctrl_hi[MAX_CTRLS];                // pool_end per control (ctrl+0x98; ctor-invariant)
static int       g_nctrls = 0;                        // discovered count; 0 = reader not armed

// ---- Per-load epoch (bumped in begin(); invalidates the snapshot index) ----
static volatile LONG64 g_rd_epoch  = 0;               // 0 = begin() has never run this session
static int             g_begin_N   = 0;

// ---- LIVE page-indexed edge map — rebuilt every begin() from the LIVE control (alloc and free lists) ----
// alloc=1 => on the LIVE ALLOC list (in_use@now); alloc=0 => on the LIVE FREE list (a transient block that is
// free now). The free list must be walked because a block born-AND-freed within the rollback window is on the
// live free list, is not in the frame-N snapshot (didn't exist@N), and is not on the live alloc list — so
// without this it is the one dirty region nothing covers (a READER-GAP the block+slab walk cannot reach).
struct LiveEdge { uint64_t base; uint32_t size; uint32_t next; uint32_t alloc; };
static uint32_t g_live_head[MAX_PAGES];               // bucket heads (EDGE_END = empty)
static LiveEdge g_live_edge[MAX_LIVE_EDGES];
static uint32_t g_live_edge_count = 0;
static bool     g_live_overflow   = false;

// ---- SNAPSHOT (in_use@N) page-indexed edge map — rebuilt once per load in compare_page via snap_read ----
struct SnapEdge { uint64_t base; uint32_t size; uint32_t next; uint32_t alloc; }; // alloc=1 => on alloc list
static uint32_t g_snap_head[MAX_PAGES];
static SnapEdge g_snap_edge[MAX_SNAP_EDGES];
static uint32_t g_snap_edge_count = 0;
static bool     g_snap_overflow   = false;
static volatile LONG64 g_snap_epoch = -1;             // epoch the snapshot index was built for

// ---- Per-page scratch (reused each compare_page; single-threaded within load()) ----
static uint8_t g_reader_scratch[PAGE_SIZE];
static uint8_t g_reader_covered[PAGE_SIZE / 8];       // 1 bit/byte: attributed by some block
static uint8_t g_reader_vaporized[PAGE_SIZE / 8];     // 1 bit/byte: VAPORIZE body (EXPECTED divergence)

// ---- Cumulative counters ----
static volatile LONG64 g_rd_pages       = 0;   // dirty pool pages compared
static volatile LONG64 g_rd_diff        = 0;   // covered & differ (the defect signal — must be 0)
static volatile LONG64 g_rd_vap         = 0;   // covered VAPORIZE body & differ (EXPECTED — proof branch live)
static volatile LONG64 g_rd_gap         = 0;   // uncovered & differ, main-arena (chase)
static volatile LONG64 g_rd_gap_r1      = 0;   // uncovered & differ, heap-zone infra (expected)
static volatile LONG64 g_rd_revert      = 0;   // REVERT classifications (block-count; exercised>0)
static volatile LONG64 g_rd_resurrect   = 0;   // RESURRECT classifications (block-count; exercised>0)
static volatile LONG64 g_rd_vaporize    = 0;   // VAPORIZE classifications (block-count; exercised>0)
static volatile LONG64 g_rd_driven      = 0;   // bytes WRITTEN back to the arena by drive_page (the FLIP)
static volatile LONG64 g_rd_diff_logged = 0;
static volatile LONG64 g_rd_gap_logged  = 0;   // throttle for the GAP characterization sampler
static volatile LONG64 g_rd_guard_fires = 0;

// ---- Throttled truncation/degradation log — makes list truncation visible (never silently masked) ----
static void guard_fire(const char* reason) {
    LONG64 n = _InterlockedIncrement64(&g_rd_guard_fires);
    if (n <= 12) {
        bool w = rblog::is_suppressed(); rblog::suppress(false);
        rblog::write("READER-GUARD-FIRE: %s (list walk truncated/degraded to READER-GAP; fire #%lld) "
                     "-- truncation is VISIBLE, not silently masked as coverage", reason, (long long)n);
        rblog::suppress(w);
    }
}

// ---- Address helpers ----
static inline size_t page_of(uintptr_t addr) {
    uintptr_t b = arena::base();
    if (!b || addr < b) return (size_t)-1;
    size_t p = (addr - b) / PAGE_SIZE;
    return p < MAX_PAGES ? p : (size_t)-1;
}

// Intersection of block [B, B+sz) with page [pg_base, pg_end). Returns false if empty.
static inline bool intersect(uintptr_t B, size_t sz, uintptr_t pg_base, uintptr_t pg_end,
                             uintptr_t* b0, uintptr_t* b1, size_t* off0, size_t* off1) {
    uintptr_t lo = B > pg_base ? B : pg_base;
    uintptr_t hi = (B + sz) < pg_end ? (B + sz) : pg_end;
    if (lo >= hi) return false;
    *b0 = lo; *b1 = hi; *off0 = lo - pg_base; *off1 = hi - pg_base;
    return true;
}

static inline void mark_covered(size_t off0, size_t off1) {
    for (size_t b = off0; b < off1; b++) g_reader_covered[b >> 3] |= (uint8_t)(1u << (b & 7));
}

// ---- readable(): alloc_invariants's VirtualQuery-capable version (same as alloc_invariants.cpp). ----
// In-arena addrs use the fast arena bitmap (is_committed_addr); every other addr (the .data control REGISTRY,
// the heap-zone control STRUCT) falls back to VirtualQuery: MEM_COMMIT + not NOACCESS/GUARD + range fits. This
// is precisely what lets the reader read the .data control array — the old is_committed||in_heap_zone version
// could not read .data, so discovery/reads bailed and the reader stayed idle (the root of an earlier idle-reader run).
static bool readable(uintptr_t p, size_t n) {
    if (!p || n == 0) return false;
    if (arena::is_arena_addr(p) && arena::is_arena_addr(p + n - 1))
        return arena::is_committed_addr(p) && arena::is_committed_addr(p + n - 1);
    MEMORY_BASIC_INFORMATION mbi;
    if (!VirtualQuery((void*)p, &mbi, sizeof(mbi))) return false;
    if (mbi.State != MEM_COMMIT) return false;
    if (mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)) return false;
    uintptr_t end = (uintptr_t)mbi.BaseAddress + mbi.RegionSize;
    return p + n <= end;
}
static inline bool live_u64(uintptr_t addr, uint64_t* out) {
    if (!readable(addr, 8)) return false;
    memcpy(out, (const void*)addr, 8); return true;
}
static inline bool live_u32(uintptr_t addr, uint32_t* out) {
    if (!readable(addr, 4)) return false;
    memcpy(out, (const void*)addr, 4); return true;
}

// ---- SNAPSHOT reads (frame-N via arena::snap_read_bytes; false on out-of-arena or ABSENT) ----
static bool snap_u32(uintptr_t addr, int N, const int* slots, int cnt, const uint8_t* eff, uint32_t* out) {
    uint8_t buf[4]; bool absent = false;
    if (!arena::snap_read_bytes(addr, 4, N, slots, cnt, eff, buf, &absent) || absent) return false;
    memcpy(out, buf, 4); return true;
}
static bool snap_u64(uintptr_t addr, int N, const int* slots, int cnt, const uint8_t* eff, uint64_t* out) {
    uint8_t buf[8]; bool absent = false;
    if (!arena::snap_read_bytes(addr, 8, N, slots, cnt, eff, buf, &absent) || absent) return false;
    memcpy(out, buf, 8); return true;
}

// ---- Edge registration (an edge on every 4KB page the block [B,B+sz) spans; multi-page mandatory) ----
static void register_live_edge(uintptr_t B, size_t sz, bool alloc) {
    if (g_live_overflow) return;
    size_t p0 = page_of(B);
    if (p0 == (size_t)-1) return;                       // base out of arena — skip
    size_t p1 = page_of(B + sz - 1);
    if (p1 == (size_t)-1) p1 = MAX_PAGES - 1;           // clamp span into arena
    for (size_t p = p0; p <= p1 && p < MAX_PAGES; p++) {
        if (g_live_edge_count >= MAX_LIVE_EDGES) { g_live_overflow = true; guard_fire("begin: live edge pool full"); return; }
        uint32_t idx = g_live_edge_count++;
        g_live_edge[idx].base  = B;
        g_live_edge[idx].size  = (uint32_t)sz;
        g_live_edge[idx].alloc = alloc ? 1u : 0u;
        g_live_edge[idx].next  = g_live_head[p];
        g_live_head[p] = idx;
    }
}
static void register_snap_edge(uintptr_t B, size_t sz, bool alloc) {
    if (g_snap_overflow) return;
    size_t p0 = page_of(B);
    if (p0 == (size_t)-1) return;
    size_t p1 = page_of(B + sz - 1);
    if (p1 == (size_t)-1) p1 = MAX_PAGES - 1;
    for (size_t p = p0; p <= p1 && p < MAX_PAGES; p++) {
        if (g_snap_edge_count >= MAX_SNAP_EDGES) { g_snap_overflow = true; guard_fire("snap: snap edge pool full"); return; }
        uint32_t idx = g_snap_edge_count++;
        g_snap_edge[idx].base  = B;
        g_snap_edge[idx].size  = (uint32_t)sz;
        g_snap_edge[idx].alloc = alloc ? 1u : 0u;
        g_snap_edge[idx].next  = g_snap_head[p];
        g_snap_head[p] = idx;
    }
}

// ---- Membership tests (O(blocks on the block's BASE page)) ----
static bool live_contains(uintptr_t B) {                 // in_use@now = on the LIVE ALLOC list (alloc==1 only)
    size_t pb = page_of(B);
    if (pb == (size_t)-1) return false;
    for (uint32_t e = g_live_head[pb]; e != EDGE_END; e = g_live_edge[e].next)
        if (g_live_edge[e].base == B && g_live_edge[e].alloc) return true;
    return false;
}
static bool snap_contains(uintptr_t B) {                 // present@N: on either snap list (alloc or free)
    size_t pb = page_of(B);
    if (pb == (size_t)-1) return false;
    for (uint32_t e = g_snap_head[pb]; e != EDGE_END; e = g_snap_edge[e].next)
        if (g_snap_edge[e].base == B) return true;
    return false;
}
static bool snap_alloc_contains(uintptr_t B) {           // in_use@N: on the snap ALLOC list only (free@N != alloc@N)
    size_t pb = page_of(B);
    if (pb == (size_t)-1) return false;
    for (uint32_t e = g_snap_head[pb]; e != EDGE_END; e = g_snap_edge[e].next)
        if (g_snap_edge[e].base == B && g_snap_edge[e].alloc) return true;
    return false;
}

// ---- Apply helpers (write only into g_reader_scratch / g_reader_vaporized) ----
//
// Copy frame-N snapshot bytes over an intersection. ABSENT pages resolve to 0 — which is exactly what
// page-blind writes for an orphaned page — so the reader matches page-blind for absent regions too.
static void copy_snap(size_t scratch_off, uintptr_t src, size_t len,
                      int N, const int* slots, int cnt, const uint8_t* eff) {
    if (len > PAGE_SIZE) len = PAGE_SIZE;
    uint8_t tmp[PAGE_SIZE]; bool absent = false;
    if (arena::snap_read_bytes(src, len, N, slots, cnt, eff, tmp, &absent))
        memcpy(g_reader_scratch + scratch_off, tmp, len);
}

// VAPORIZE overlay for the frame-N-baseline restore model: keep a born-after-N object's BODY live ON TOP of the
// baseline. The header [B, B+0x50) stays frame-N (already in scratch from the whole-page baseline seed). The body
// [B+0x50, B+sz) ∩ page is copied from the LIVE page (shadow_live) and marked vaporized — the intended,
// structure-aware divergence from page-blind (page-blind wrongly reverts this live object's body to pre-birth
// bytes). Unlike vaporize_apply, this WRITES the live bytes (the baseline is frame-N, not live).
static void vaporize_overlay(uintptr_t B, size_t sz, uintptr_t pg_base, uintptr_t pg_end,
                             const uint8_t* shadow_live) {
    uintptr_t body = B + BLOCK_HDR;
    uintptr_t bd0  = body    > pg_base ? body    : pg_base;
    uintptr_t bd1  = (B + sz) < pg_end ? (B + sz) : pg_end;
    if (bd0 >= bd1) return;
    size_t o0 = bd0 - pg_base, o1 = bd1 - pg_base;
    memcpy(g_reader_scratch + o0, shadow_live + o0, o1 - o0);      // keep the live object body
    for (size_t b = o0; b < o1; b++) g_reader_vaporized[b >> 3] |= (uint8_t)(1u << (b & 7));
}

// ---- Build the SNAPSHOT (in_use@N) page index by walking the frame-N control lists (once per load()) ----

// MULTI-REGION (P1 donation): pool membership = primary [pool_base,pool_end) OR any donated region for this
// ctrl. Without this, a block carved from a donated region TERMINATES the walk early (silent truncation).
static inline bool in_pool_mr(uintptr_t ctrl, uint64_t pool_base, uint64_t pool_end, uintptr_t B) {
    if (B >= pool_base && B < pool_end) return true;
    return arena::in_owned_pool(ctrl, B);
}
static inline bool page_in_donated(uintptr_t ctrl, uintptr_t pg_base, uintptr_t pg_end) {
    int n = arena::donated_region_count();
    for (int i = 0; i < n; i++) { uintptr_t c, b; size_t sz;
        if (arena::donated_region_get(i, &c, &b, &sz) && c == ctrl && pg_end > b && pg_base < b + sz) return true; }
    return false;
}
static void walk_snap_list(uintptr_t ctrl, uintptr_t head_addr, bool alloc, uint64_t pool_base, uint64_t pool_end,
                           int N, const int* slots, int cnt, const uint8_t* eff) {
    uint64_t head = 0;
    if (!snap_u64(head_addr, N, slots, cnt, eff, &head)) return;   // empty / unresolved list
    // Bound by the descriptor's OWN block count (alloc: mgr+0x50, free: mgr+0x68 — both == head_addr+0x10),
    // not a blind 1M guard: a cyclic/torn frame-N list otherwise walks to WALK_ITER_GUARD, which blows the snap
    // edge pool and trips the size guard (the 3 guard-fires). count+slack, floored at slack, clamped to the guard.
    uint32_t lcount = 0; snap_u32(head_addr + 0x10, N, slots, cnt, eff, &lcount);
    int bound = (int)lcount + WALK_SLACK;
    if (bound < WALK_SLACK) bound = WALK_SLACK;                     // unreadable/garbage-huge count => small safe floor
    if (bound > WALK_ITER_GUARD) bound = WALK_ITER_GUARD;
    uintptr_t B = (uintptr_t)head;
    int iters = 0;
    while (B) {
        if (!in_pool_mr(ctrl, pool_base, pool_end, B)) break;         // off-pool => list terminator/sentinel (multi-region-aware)
        if (iters++ >= bound) { guard_fire(alloc ? "snap: alloc walk hit count bound" : "snap: free walk hit count bound"); break; }
        uint32_t w;
        if (!snap_u32(B + BLOCK_INUSE_WORD, N, slots, cnt, eff, &w)) { guard_fire("snap: block hdr absent/uncommitted"); break; }
        size_t sz = ((size_t)(w >> 1)) << 4;
        if (!sz || sz > MAX_BLOCK_SIZE) { guard_fire("snap: implausible block size"); break; }
        register_snap_edge(B, sz, alloc);
        uint64_t nxt = 0;
        if (!snap_u64(B + BLOCK_NEXT, N, slots, cnt, eff, &nxt)) { guard_fire("snap: next ptr absent"); break; }
        if ((uintptr_t)nxt == B) { guard_fire("snap: self-loop in list"); break; }
        B = (uintptr_t)nxt;
    }
}
static void build_snap_index(int N, const int* slots, int cnt, const uint8_t* eff) {
    memset(g_snap_head, 0xFF, sizeof(g_snap_head));
    g_snap_edge_count = 0;
    g_snap_overflow   = false;
    for (int c = 0; c < g_nctrls; c++) {
        uintptr_t ctrl = g_ctrls[c];
        uint64_t pool_base = 0, pool_end = 0;
        if (!live_u64(ctrl + CTRL_POOL_BASE, &pool_base) || !live_u64(ctrl + CTRL_POOL_END, &pool_end) ||
            !pool_base || !pool_end) { guard_fire("snap: pool bounds unreadable"); continue; }
        int ncls = g_ctrl_ncls[c];
        for (int k = 0; k < ncls; k++) {
            uintptr_t desc = ctrl + CTRL_DESC_OFF + (size_t)k * DESC_STRIDE;
            walk_snap_list(ctrl, desc + DESC_ALLOC_TAIL, /*alloc=*/true,  pool_base, pool_end, N, slots, cnt, eff);
            walk_snap_list(ctrl, desc + DESC_FREE_HEAD,  /*alloc=*/false, pool_base, pool_end, N, slots, cnt, eff);
        }
    }
}

// ---- Walk a LIVE (in_use@now / free@now) list into the live edge map (count-bounded, mirrors walk_snap_list). ----
static void walk_live_list(uintptr_t ctrl, uintptr_t head_addr, uintptr_t cnt_addr, bool alloc,
                           uint64_t pool_base, uint64_t pool_end) {
    uint32_t lcount = 0; live_u32(cnt_addr, &lcount);              // desc block count (alloc mgr+0x50 / free mgr+0x68)
    int bound = (int)lcount + WALK_SLACK;
    if (bound < WALK_SLACK) bound = WALK_SLACK;
    if (bound > WALK_ITER_GUARD) bound = WALK_ITER_GUARD;
    uint64_t head = 0;
    if (!live_u64(head_addr, &head)) return;
    uintptr_t B = (uintptr_t)head;
    int iters = 0;
    while (B) {
        if (!in_pool_mr(ctrl, pool_base, pool_end, B)) break;         // off-pool terminator/sentinel (multi-region-aware)
        if (iters++ >= bound) { guard_fire(alloc ? "begin: alloc walk hit count bound" : "begin: free walk hit count bound"); break; }
        uint32_t w;
        if (!live_u32(B + BLOCK_INUSE_WORD, &w)) { guard_fire("begin: block hdr uncommitted"); break; }
        size_t sz = ((size_t)(w >> 1)) << 4;
        if (!sz || sz > MAX_BLOCK_SIZE) { guard_fire("begin: implausible block size"); break; }
        register_live_edge(B, sz, alloc);
        uint64_t nxt = 0;
        if (!live_u64(B + BLOCK_NEXT, &nxt)) { guard_fire("begin: next ptr uncommitted"); break; }
        if ((uintptr_t)nxt == B) { guard_fire("begin: self-loop in list"); break; }
        B = (uintptr_t)nxt;
    }
}

// ---- Diagnostic: which block covers pg_base+off (for the READER-DIFF log line) ----
static uintptr_t block_at(size_t p, size_t off, bool* is_snap, bool* alloc_out) {
    uintptr_t addr = arena::base() + p * PAGE_SIZE + off;
    for (uint32_t e = g_snap_head[p]; e != EDGE_END; e = g_snap_edge[e].next) {
        uintptr_t B = g_snap_edge[e].base;
        if (addr >= B && addr < B + g_snap_edge[e].size) { *is_snap = true; *alloc_out = g_snap_edge[e].alloc != 0; return B; }
    }
    for (uint32_t e = g_live_head[p]; e != EDGE_END; e = g_live_edge[e].next) {
        uintptr_t B = g_live_edge[e].base;
        if (addr >= B && addr < B + g_live_edge[e].size) { *is_snap = false; *alloc_out = g_live_edge[e].alloc != 0; return B; }
    }
    return 0;
}

// ---- Diagnostic: nearest walked blocks flanking pg_base+off (characterizes a GAP byte) ----
// A GAP byte is uncovered => NO walked block contains it. The flanking blocks discriminate the cause:
// tight prev-end..next-base with a block-sized void -> a block we FAILED to walk (list truncation / missed class)
// a small sliver between two adjacent blocks -> inter-slab / allocator bookkeeping (not a block)
// Page-local scan: edges are registered on every page a block spans, so straddlers into page p are visible here;
// a flank on the adjacent page reads back as 0 (gap runs to this page's boundary).
static void nearest_blocks(size_t p, size_t off,
                           uintptr_t* prev_base, size_t* prev_size, uintptr_t* prev_end,
                           uintptr_t* next_base, size_t* next_size) {
    uintptr_t addr = arena::base() + p * PAGE_SIZE + off;
    *prev_base = 0; *prev_size = 0; *prev_end = 0; *next_base = 0; *next_size = 0;
    uintptr_t best_prev_end = 0, best_next_base = (uintptr_t)-1;
    for (uint32_t e = g_snap_head[p]; e != EDGE_END; e = g_snap_edge[e].next) {
        uintptr_t B = g_snap_edge[e].base; size_t sz = g_snap_edge[e].size; uintptr_t end = B + sz;
        if (end <= addr && end > best_prev_end)  { best_prev_end  = end; *prev_base = B; *prev_size = sz; }
        if (B   >  addr && B   < best_next_base) { best_next_base = B;   *next_base = B; *next_size = sz; }
    }
    for (uint32_t e = g_live_head[p]; e != EDGE_END; e = g_live_edge[e].next) {
        uintptr_t B = g_live_edge[e].base; size_t sz = g_live_edge[e].size; uintptr_t end = B + sz;
        if (end <= addr && end > best_prev_end)  { best_prev_end  = end; *prev_base = B; *prev_size = sz; }
        if (B   >  addr && B   < best_next_base) { best_next_base = B;   *next_base = B; *next_size = sz; }
    }
    *prev_end = best_prev_end;
}

// ---- Control discovery (alloc_invariants's proven registry method — count/array/vtable + in-arena pool filter) ----
// Reads the .data registry (count 0x140D760E0 / array 0x140D760F0 / vtable 0x140B08620) and caches every control
// that (a) passes the vtable check and (b) has an in-ARENA pool (is_arena_addr(lo)) so snap_read/is_committed work.
// Controls with real-heap pools are counted+logged but skipped (they can't be snapshotted; out of scope).
// Idempotent: the controls are persistent singletons — discover once and cache forever.
static void discover_controls() {
    // DYNAMIC: re-read the registry every begin() and APPEND new vtable-valid controls —
    // a post-boot allocator gets reader coverage the frame it appears. Read-only consumer => no lock-order hazard
    // (unlike the reverted resim-side re-discovery). Dedup by address; MAX_CTRLS=64 has ~8x headroom.
    int prev_n = g_nctrls;
    (void)prev_n;
    uintptr_t count_addr = addr::resolve(IDA_REG_COUNT);
    uintptr_t array_addr = addr::resolve(IDA_REG_ARRAY);
    uintptr_t target_vt  = addr::resolve(IDA_SCALABLE_VT);
    if (!readable(count_addr, 4) || !readable(array_addr, 8)) return;
    uint32_t nreg = *(uint32_t*)count_addr; if (nreg > (uint32_t)MAX_CTRLS) nreg = MAX_CTRLS;
    int skipped_heap = 0;
    for (uint32_t i = 0; i < nreg; i++) {
        uintptr_t ctrl = readable(array_addr + i * 8, 8) ? *(uintptr_t*)(array_addr + i * 8) : 0;
        if (!ctrl || !readable(ctrl, 8) || *(uintptr_t*)ctrl != target_vt) continue;      // vtable check (not +0x534)
        uintptr_t lo = readable(ctrl + CTRL_POOL_BASE, 8) ? *(uintptr_t*)(ctrl + CTRL_POOL_BASE) : 0;
        uintptr_t hi = readable(ctrl + CTRL_POOL_END,  8) ? *(uintptr_t*)(ctrl + CTRL_POOL_END)  : 0;
        int ncls = readable(ctrl + CTRL_NCLS_OFF, 4) ? *(int*)(ctrl + CTRL_NCLS_OFF) : 8;
        if (ncls < 1 || ncls > 8) ncls = 8;
        if (!lo || !hi || !arena::is_arena_addr(lo)) { skipped_heap++; continue; }         // pool not in arena — skip
        bool known = false;
        for (int c = 0; c < g_nctrls; c++) if (g_ctrls[c] == ctrl) { known = true; break; }   // dedup (dynamic re-scan)
        if (known) continue;
        if (g_nctrls >= MAX_CTRLS) break;
        g_ctrls[g_nctrls]     = ctrl;
        g_ctrl_ncls[g_nctrls] = (uint8_t)ncls;
        g_ctrl_lo[g_nctrls]   = lo;
        g_ctrl_hi[g_nctrls]   = hi;
        g_nctrls++;
    }
    if (g_nctrls > prev_n) {
        bool w = rblog::is_suppressed(); rblog::suppress(false);
        if (prev_n > 0) rblog::write("READER: registry GREW (%d -> %d controls) — new post-boot allocator(s) now covered", prev_n, g_nctrls);
        rblog::write("READER: discovered %d in-arena MtScalable control(s) — reader ARMED "
                     "(%d real-heap-pool control(s) skipped — can't snapshot, out of scope)", g_nctrls, skipped_heap);
        for (int c = 0; c < g_nctrls; c++)
            rblog::write("READER:   ctrl[%d]=0x%llx lo=0x%llx hi=0x%llx ncls=%d", c,
                         (unsigned long long)g_ctrls[c], (unsigned long long)g_ctrl_lo[c],
                         (unsigned long long)g_ctrl_hi[c], (int)g_ctrl_ncls[c]);
        rblog::suppress(w);
    } else {
        static bool logged_empty = false;
        if (!logged_empty && (nreg > 0 || skipped_heap > 0)) {
            logged_empty = true;
            bool w = rblog::is_suppressed(); rblog::suppress(false);
            rblog::write("READER: discover_controls saw %u registered control(s), %d real-heap (skipped) — "
                         "NONE in-arena yet, reader NOT armed", nreg, skipped_heap);
            rblog::suppress(w);
        }
    }
}

} // anon namespace

namespace reader {

volatile bool g_active = false;   // PERF: default OFF — the compare_page shadow-oracle is a read-only
                                  // diagnostic that runs after page-blind already wrote correct bytes (READER-DIFF=0
                                  // proven), costing 18-25ms per rollback inside the frozen suspend+restore window.
                                  // Re-arm by setting g_active for an RE session. Zero correctness change (pure diag).

// ---- Control discovery is now array-based (discover_controls, called from begin()). ----
// set_ctrl / probe_ctrl remain declared+defined (arena.cpp + idspine.cpp still call them) but are now harmless
// no-ops: the single-control hook+fingerprint path is dead. Their public signatures in reader.h are unchanged.
void set_ctrl(uintptr_t /*ctrl_addr*/) {
    // hint ignored — controls are discovered from the .data registry in discover_controls() (alloc_invariants's method).
}

bool probe_ctrl(uintptr_t /*heap_zone_base*/, size_t /*heap_zone_size*/) {
    // heap-zone scan retired; report armed-state from the registry-discovered cache instead.
    return g_nctrls > 0;
}

// ---- begin(): capture the LIVE (in_use@now) alloc set before page-blind reverts anything ----
void begin(int N) {
    if (!g_active) return;
    discover_controls();                         // idempotent; arms the reader from the .data registry (once)
    if (g_nctrls == 0) return;                   // not armed — no in-arena control found yet
    g_begin_N = N;
    _InterlockedIncrement64(&g_rd_epoch);        // new per-load epoch (invalidates the snapshot index)

    memset(g_live_head, 0xFF, sizeof(g_live_head));
    g_live_edge_count = 0;
    g_live_overflow   = false;

    for (int c = 0; c < g_nctrls; c++) {
        uintptr_t ctrl = g_ctrls[c];
        uint64_t pool_base = 0, pool_end = 0;
        if (!live_u64(ctrl + CTRL_POOL_BASE, &pool_base) || !live_u64(ctrl + CTRL_POOL_END, &pool_end) ||
            !pool_base || !pool_end) { guard_fire("begin: pool bounds unreadable"); continue; }
        int ncls = g_ctrl_ncls[c];
        for (int k = 0; k < ncls; k++) {
            uintptr_t desc = ctrl + CTRL_DESC_OFF + (size_t)k * DESC_STRIDE;
            // ALLOC list only = in_use@now. Under the frame-N-baseline model this is all the reader needs: the
            // only overlay is VAPORIZE (born-after-N live-ALLOC blocks). free@now / slab headers / inter-block
            // metadata all come from the frame-N baseline, so the free-list walk and the level-1 slab physical
            // walk (both added only to close READER-GAP under the old reconstruct-every-byte model) are retired.
            walk_live_list(ctrl, desc + DESC_ALLOC_TAIL, desc + DESC_ALLOC_CNT, /*alloc=*/true, pool_base, pool_end);
        }
    }
}

// ---- compare_page(): classify by list membership, then compare to page-blind ----
void compare_page(size_t p, int N,
                  const int* ordered_slots, int ordered_count,
                  const uint8_t* eff_bits,
                  const uint8_t* shadow_live,
                  const uint8_t* live_pg,
                  LONG /*load_id*/) {
    if (!g_active || g_nctrls == 0) return;
    if (g_rd_epoch == 0) return;                 // begin() has not run — live set uninitialized; stay idle

    uintptr_t pg_base = arena::base() + p * PAGE_SIZE;
    uintptr_t pg_end  = pg_base + PAGE_SIZE;
    // Not an MtScalable pool page unless it lands in some discovered control's pool [lo,hi) (ctor-invariant bounds).
    bool in_pool = false;
    for (int c = 0; c < g_nctrls; c++)
        if ((pg_end > g_ctrl_lo[c] && pg_base < g_ctrl_hi[c]) || page_in_donated(g_ctrls[c], pg_base, pg_end)) { in_pool = true; break; }
    if (!in_pool) return;                                                          // not an MtScalable pool page

    // Build the snapshot (in_use@N) index once per load (this walk IS the frame-N list enumeration).
    if (g_snap_epoch != g_rd_epoch) { build_snap_index(N, ordered_slots, ordered_count, eff_bits); g_snap_epoch = g_rd_epoch; }

    // ---- RESTORE MODEL ("dumb save / smart restore"; owned-heap Property 4) ----
    // BASELINE = frame-N for the whole page (== page-blind, i.e. the saved bytes). Structure-awareness is not a
    // per-byte reconstruction of the page — it is a set of OVERLAYS on the baseline, one per by-structure
    // exception. Today there is exactly one overlay:
    // VAPORIZE — a born-after-N LIVE object (in_use@now && !in_use@N). page-blind reverts its BODY to pre-birth
    // frame-N garbage while live references still point at it (the stale-reference crash); restore-by-structure
    // keeps the live object's body ALIVE. Its header stays frame-N (baseline).
    // Everything present@N (REVERT/RESURRECT/free/slab/inter-block allocator metadata) IS the baseline: it
    // reverts to the saved bytes, which is correct for state that existed at N. This is why the whole "enumerate
    // every metadata class to close READER-GAP" chase dissolves — non-object bytes come from the save, not from
    // reconstruction. (The next overlay, when the gp_crc oracle demands it, is own-reuse: freed-identity
    // stability for REVERT-block references — owned-heap Property 3 — not byte-level per-field pointer rewriting.)
    copy_snap(0, pg_base, PAGE_SIZE, N, ordered_slots, ordered_count, eff_bits);   // frame-N baseline (== page-blind)
    memset(g_reader_covered, 0xFF, sizeof(g_reader_covered));                       // baseline accounts for every byte
    memset(g_reader_vaporized, 0, sizeof(g_reader_vaporized));

    // Classify present@N blocks for the report (baseline already produced their bytes — this is bookkeeping only).
    for (uint32_t e = g_snap_head[p]; e != EDGE_END; e = g_snap_edge[e].next) {
        if (!g_snap_edge[e].alloc) continue;                       // only in_use@N (alloc) blocks are REVERT/RESURRECT
        uintptr_t B = g_snap_edge[e].base;
        if (page_of(B) != p) continue;                             // count once, at the block's base page
        if (live_contains(B)) _InterlockedIncrement64(&g_rd_revert);      // alloc@N && alloc@now
        else                  _InterlockedIncrement64(&g_rd_resurrect);   // alloc@N && !alloc@now
    }

    // OVERLAY: born-after-N live ALLOC blocks -> keep the BODY live (VAPORIZE). Header stays frame-N (baseline).
    // free@now transient blocks are DEAD -> baseline (revert to frame-N); no overlay.
    for (uint32_t e = g_live_head[p]; e != EDGE_END; e = g_live_edge[e].next) {
        if (!g_live_edge[e].alloc) continue;                       // free@now -> baseline
        uintptr_t B  = g_live_edge[e].base;
        size_t    sz = g_live_edge[e].size;
        if (snap_alloc_contains(B)) continue;                      // alloc@N (present as a live object@N) -> REVERT -> baseline
        // !alloc@N && alloc@now -> VAPORIZE. Covers both free@N-but-alloc@now (a slot reused into a live object)
        // And nonexistent@N — page-blind reverts either body to pre-object frame-N bytes; we keep the object live.
        if (page_of(B) == p) _InterlockedIncrement64(&g_rd_vaporize);
        vaporize_overlay(B, sz, pg_base, pg_end, shadow_live);     // body -> live, mark vaporized
    }

    // ---- Compare g_reader_scratch to live_pg (page-blind's result) byte-for-byte ----
    _InterlockedIncrement64(&g_rd_pages);
    bool zone = arena::in_heap_zone(pg_base);
    LONG64 diff = 0, vap = 0, gap = 0, gapr1 = 0;
    int first_off = -1; uint8_t first_s = 0, first_l = 0;
    int gap_first = -1; uint8_t gap_s = 0, gap_l = 0;
    for (size_t b = 0; b < PAGE_SIZE; b++) {
        if (g_reader_scratch[b] == live_pg[b]) continue;
        bool cov = (g_reader_covered[b >> 3]   >> (b & 7)) & 1;
        bool vp  = (g_reader_vaporized[b >> 3] >> (b & 7)) & 1;
        if (vp)             vap++;                                 // EXPECTED: VAPORIZE body kept live
        else if (cov)     { diff++; if (first_off < 0) { first_off = (int)b; first_s = g_reader_scratch[b]; first_l = live_pg[b]; } }
        else if (zone)      gapr1++;                               // heap-zone infra/control (expected)
        else              { gap++;  if (gap_first < 0) { gap_first = (int)b; gap_s = g_reader_scratch[b]; gap_l = live_pg[b]; } }
    }
    if (vap)   _InterlockedExchangeAdd64(&g_rd_vap,    vap);
    if (diff)  _InterlockedExchangeAdd64(&g_rd_diff,   diff);
    if (gap)   _InterlockedExchangeAdd64(&g_rd_gap,    gap);
    if (gapr1) _InterlockedExchangeAdd64(&g_rd_gap_r1, gapr1);

    if (diff && _InterlockedIncrement64(&g_rd_diff_logged) <= 12) {
        bool is_snap = false, is_alloc = false;
        uintptr_t blk = block_at(p, (size_t)first_off, &is_snap, &is_alloc);
        uint32_t cls = 0;
        if (blk) { uint32_t cw = 0;
            if (is_snap) snap_u32(blk + BLOCK_CLASS_WORD, N, ordered_slots, ordered_count, eff_bits, &cw);
            else         live_u32(blk + BLOCK_CLASS_WORD, &cw);
            cls = (cw >> 2) & 0x1f; }
        bool w = rblog::is_suppressed(); rblog::suppress(false);
        rblog::write("READER-DIFF p=%zu firstoff=%d reader=0x%02X pageblind=0x%02X diff_bytes=%lld N=%d "
                     "block=0x%llx list=%s class=%u -- covered block disagrees with page-blind "
                     "(resolver/extent bug; MUST be 0 before the flip)",
                     p, first_off, first_s, first_l, (long long)diff, N,
                     (unsigned long long)blk, blk ? (is_snap ? (is_alloc ? "snap-alloc" : "snap-free") : "live-alloc") : "none", cls);
        rblog::suppress(w);
    }

    // ---- GAP characterization sampler: an UNCOVERED main-arena byte that differs from page-blind. ----
    // Measures the contiguous uncovered-differing run + the flanking walked blocks so we KNOW the cause class
    // (list-walk truncation vs inter-slab metadata vs a missed block class) instead of guessing. Must reach 0
    // before the flip (restore must reconstruct every differing byte over the closed domain).
    if (gap && _InterlockedIncrement64(&g_rd_gap_logged) <= 24) {
        size_t run = 0;                                            // length of the uncovered-differing run at gap_first
        for (size_t b = (size_t)gap_first; b < PAGE_SIZE; b++) {
            if (g_reader_scratch[b] == live_pg[b]) break;
            if ((g_reader_covered[b >> 3]   >> (b & 7)) & 1) break;
            if ((g_reader_vaporized[b >> 3] >> (b & 7)) & 1) break;
            run++;
        }
        uintptr_t pb = 0, pe = 0, nb = 0; size_t ps = 0, ns = 0;
        nearest_blocks(p, (size_t)gap_first, &pb, &ps, &pe, &nb, &ns);
        uintptr_t ga    = pg_base + (size_t)gap_first;
        long long dprev = pe ? (long long)(ga - pe) : -1;         // bytes from prev block END to gap start
        long long dnext = nb ? (long long)(nb - ga) : -1;         // bytes from gap start to next block BASE

        // Probe the WALKED prev block (pb): the gap is its 0x50 TAIL [pb+regsize, next.base). Read pb's OWN
        // header both live and @N — raw size word, decoded size, user-req-size (+0x40), user-offset (+0x48),
        // class — plus its stride to next and its classification (snap_has/live_has => REVERT vs RESURRECT vs
        // VAPORIZE). This resolves the two live hypotheses and their safety:
        // (A) reader UNDER-SIZES pb (real size == stride, decoded 0x50 short) -> if pb is REVERT/RESURRECT the
        // tail reverts to frame-N anyway (safe extend); if VAPORIZE the tail is LIVE object body (must not
        // revert — a partial-vaporize bug), so the fix must extend the vaporize body, not blanket-revert.
        // (B) genuine inter-block padding pb doesn't own -> reverts to frame-N (safe).
        uintptr_t Bc = pb ? pb : (ga & ~(uintptr_t)0xF);
        uint32_t lsw = 0, lcw = 0, ssw = 0; uint64_t lus = 0, luo = 0, lbp = 0;
        bool lok = live_u32(Bc + BLOCK_INUSE_WORD, &lsw) && live_u32(Bc + BLOCK_CLASS_WORD, &lcw)
                 && live_u64(Bc + 0x40, &lus) && live_u64(Bc + 0x48, &luo) && live_u64(Bc + BLOCK_SLAB_BACKPTR, &lbp);
        bool sok = snap_u32(Bc + BLOCK_INUSE_WORD, N, ordered_slots, ordered_count, eff_bits, &ssw);
        size_t lsz = ((size_t)(lsw >> 1)) << 4, ssz = ((size_t)(ssw >> 1)) << 4;
        long long stride = (nb && pb) ? (long long)(nb - pb) : -1;
        const char* cls = (snap_contains(Bc) && live_contains(Bc)) ? "REVERT"
                        : (snap_contains(Bc) && !live_contains(Bc)) ? "RESURRECT"
                        : (!snap_contains(Bc) && live_contains(Bc)) ? "VAPORIZE" : "none";
        bool w = rblog::is_suppressed(); rblog::suppress(false);
        rblog::write("READER-GAP p=%zu off=%d run=%zu reader=0x%02X pageblind=0x%02X gap_bytes=%lld N=%d zone=%d | "
                     "prev[base=0x%llx regsz=%zu end=0x%llx] next[base=0x%llx dist=%lld] stride=%lld | "
                     "pb@0x%llx cls=%s live{ok=%d rawsz=0x%X sz=%zu inuse=%d clsn=%u usersz=%llu useroff=%llu bp=0x%llx} "
                     "snap{ok=%d sz=%zu inuse=%d} -- under-size vs padding, and is the tail a live vaporize body?",
                     p, gap_first, run, gap_s, gap_l, (long long)gap, N, (int)zone,
                     (unsigned long long)pb, ps, (unsigned long long)pe,
                     (unsigned long long)nb, dnext, stride,
                     (unsigned long long)Bc, cls,
                     (int)lok, lsw, lsz, (int)(lsw & 1), (lcw >> 2) & 0x1f,
                     (unsigned long long)lus, (unsigned long long)luo, (unsigned long long)lbp,
                     (int)sok, ssz, (int)(ssw & 1));
        rblog::suppress(w);
    }
}

// ---- Throttled stats (call from heartbeat / shadow_report; never per-frame) ----
void report() {
    bool w = rblog::is_suppressed(); rblog::suppress(false);
    rblog::write("READER-WALK: pages=%lld | READER-DIFF=%lld (MUST be 0 — restore disagrees w/ page-blind off the "
                 "vaporize set) READER-VAP=%lld (born-after-N object count; rollback drives 0 bytes over them) "
                 "READER-GAP=%lld (0 by construction — frame-N baseline accounts for every byte) "
                 "R1=%lld (heap-zone infra — expected) | classify: REVERT=%lld RESURRECT=%lld VAPORIZE=%lld "
                 "driven=%lld (bytes WRITTEN — always 0 under rollback; keep-live refuted) | "
                 "live_edges=%lu%s snap_edges=%lu%s guard_fires=%lld controls=%d ctrl0=0x%llx active=%d",
                 (long long)g_rd_pages, (long long)g_rd_diff, (long long)g_rd_vap,
                 (long long)g_rd_gap, (long long)g_rd_gap_r1,
                 (long long)g_rd_revert, (long long)g_rd_resurrect, (long long)g_rd_vaporize,
                 (long long)g_rd_driven,
                 (unsigned long)g_live_edge_count, g_live_overflow ? "(OVF)" : "",
                 (unsigned long)g_snap_edge_count, g_snap_overflow ? "(OVF)" : "",
                 (long long)g_rd_guard_fires, g_nctrls,
                 (unsigned long long)(g_nctrls > 0 ? g_ctrls[0] : 0), (int)g_active);
    rblog::suppress(w);
}

} // namespace reader
