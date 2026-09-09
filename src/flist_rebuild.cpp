#include "flist_rebuild.h"
#include "arena.h"
#include "log.h"
#include <windows.h>
#include <cstdint>
#include <cstdio>

namespace flist_rebuild {

// ---- block-header layout (verified against the binary) ----
// *(u32*)(b+0x38): bit0 = in-use(1)/free(0); >>1 = size in 16-byte units
// (set-in-use @0x1404ca989 `or edx,0x1`; cleared-free @0x1404cb3f7 `and [rsi+0x38],~1`)
// *(u32*)(b+0x3c): bits[6:2] = 1-based class tag, stamped verbatim from desc+0x70 @0x1404ca751; decode (>>2)&0x1f.
// (class is not re-derivable from size — split remainders keep the parent tag — so read it here.)
// manager (desc) @ ctrl+0xd8+k*0xa8: head +0x58, tail +0x60, count +0x68, size-sum +0x6c, class-tag +0x70.
// primary pool: [*(ctrl+0x90), *(ctrl+0x98)). (ctrl+0xc0 is the RESERVE pool — never enumerate from it: that
// was the refuted rebuild's wipe.) Physical-neighbor links +0x28/+0x30 and the stamps +0x38/+0x3c are physical
// truth, not list membership — a rebuild leaves them untouched and only rewrites the +0x18/+0x20 chain.
static inline uint64_t blk_total(uintptr_t b) { return (uint64_t)(*(uint32_t*)(b + 0x38) >> 1) << 4; }
static inline bool     blk_free (uintptr_t b) { return (*(uint32_t*)(b + 0x38) & 1) == 0; }
static inline uint32_t blk_class(uintptr_t b) { return (*(uint32_t*)(b + 0x3c) >> 2) & 0x1f; }
// +0x3c bits[1:0] = "kind": a manager's free list is a MIX of two kinds —
// kind==0 = split-remainder, inserted by the alloc/split path (and [rdx+0x3c],~3 => kind cleared to 0, FREE,
// tail-inserted @0x1404ca7bf/0x1404ca808) — this is the DOMINANT free block for a growing class;
// kind==1 = coalesced free, inserted by the free path (or [rbx+0x3c],1 @0x1404cb626);
// kind==2 = a GLOBAL-RESERVE chunk (or [rdi+0x3c],2 @0x1404ca485) — lives on the ctrl+0xc0 reserve list, class==0.
// So the rebuild must take kind 0 and 1 (every manager-free block) and exclude only kind==2. (An earlier "kind==1
// only" filter was the empty-collect bug: it dropped all the kind-0 remainders, collecting 0 of 41 real frees.)
static inline uint32_t blk_kind (uintptr_t b) { return (*(uint32_t*)(b + 0x3c) & 3); }

// Absolute cap. One class holding more than this is implausible => decline (never silently truncate the sweep).
static constexpr int REBUILD_MAX = 65536;
static uintptr_t g_scratch[REBUILD_MAX];   // collected free-block addrs — call is CS-held (single-threaded), so static is safe

static volatile long g_rebuilt_ok = 0, g_rebuilt_declined = 0;
long rebuilt_ok()       { return g_rebuilt_ok; }
long rebuilt_declined() { return g_rebuilt_declined; }

static inline bool canon(uintptr_t p) { return p >= 0x10000 && (p & 0x7) == 0; }

// committed-readable, arena-fast / VirtualQuery-fallback (same as edge_census.cpp — the ctrl
// block itself can be OUT-of-arena even though its pool is arena-owned, so is_committed_addr alone would wrongly
// reject the descriptor reads).
static bool rd(uintptr_t p, size_t n) {
    if (!canon(p)) return false;
    if (arena::is_arena_addr(p)) return arena::is_committed_addr(p) && arena::is_committed_addr(p + n - 1);
    MEMORY_BASIC_INFORMATION mbi; if (!VirtualQuery((void*)p, &mbi, sizeof(mbi))) return false;
    if ((mbi.State & MEM_COMMIT) == 0) return false;
    DWORD rw = PAGE_READONLY|PAGE_READWRITE|PAGE_EXECUTE_READ|PAGE_EXECUTE_READWRITE|PAGE_WRITECOPY|PAGE_EXECUTE_WRITECOPY;
    if ((mbi.Protect & rw) == 0 || (mbi.Protect & (PAGE_GUARD|PAGE_NOACCESS))) return false;
    return (p + n) <= (uintptr_t)mbi.BaseAddress + mbi.RegionSize;
}

// sweep diagnostics (set on the false-return path; call is CS-held single-threaded so statics are safe).
static const char* g_sweep_fail   = "";
static uintptr_t   g_sweep_fail_at = 0;
static int         g_sweep_scanned = 0;
static int         g_sweep_free = 0;        // free blocks of any class seen
static int         g_sweep_classmatch = 0;  // blocks with class==want of any free-state seen
static uintptr_t   g_sweep_lo = 0, g_sweep_hi = 0;   // last block-address range actually walked

// TWO-LEVEL STRUCTURE (binary+log verified, phys-trace) — the pool is not a flat heap (the earlier
// "flat boundary-tag" RE was refuted by live data). A size-stride from ctrl+0x90 lands only on kind==2 SLAB
// descriptors — one class-tagged 64K+ slab per class — because each slab's +0x38 reports its whole extent, so the
// stride jumps slab→slab and never enters the interior. The manager's real free blocks (kind 0/1) are SUB-BLOCKS
// inside those slabs: a boundary-tagged run starting at slab+0x50 (payload offset), each striding by its own +0x38.
// Evidence: SWEEP-CMP first8 = all `k=2 sz=64K` (classes 8/4/6/1/2/3/5/7); PHYS-TRACE anchored on a chain free
// block shows e.g. slab 0x84A40000 -> sub 0x84A40050(45K f=1 k=1 c=3) -> 0x84A4B780 ->... all k=1 c=3, staying
// inside the slab. So enumeration must DESCEND: at a class-k slab, walk [slab+0x50, slab+size) at the sub-block
// level. The +0x38 sizes / +0x3c stamps are PHYSICAL truth (intact even when the +0x18/+0x20 free-list is cyclic
// — the ratchet corrupts only list membership), which is exactly why this pool walk is the authoritative source.
//
// One sweep of [lo,hi): visit every block by its OWN size (never the corrupt +0x18/+0x20 chain), descending each
// class-`want_cls` slab into its sub-blocks, appending free class-`want_cls` sub-blocks to g_scratch. Returns false
// the instant the ground truth itself is unreadable or nonsensical (bad stride) — the caller then DECLINES the whole
// rebuild (case (b): if the stamps/sizes are corrupt, not just the sticky-notes, we must not derive from them).
static bool sweep_range(uintptr_t lo, uintptr_t hi, uint32_t want_cls, int& n) {
    if (!canon(lo) || hi <= lo || (hi - lo) > 0x40000000ull) { g_sweep_fail = "bad-range"; g_sweep_fail_at = lo; return false; }
    uintptr_t b = lo;
    while (b < hi) {
        if (!rd(b, 0x40)) { g_sweep_fail = "unreadable-hdr"; g_sweep_fail_at = b; return false; }   // covers +0x18/+0x20/+0x38/+0x3c
        uint64_t  bt = blk_total(b);
        uintptr_t nb = b + bt;
        if (bt == 0 || nb <= b || nb > hi) { g_sweep_fail = "bad-stride"; g_sweep_fail_at = b; return false; }
        if (blk_kind(b) == 2) {
            // A slab/reserve container. Slabs are class-homogeneous (segregated-fit), so descend only this class's
            // slabs into their real sub-block run [slab+0x50, slab+size). The slab itself is a container, not a free
            // block — do not count/collect it at this level.
            if (blk_class(b) == want_cls) {
                uintptr_t sub = b + 0x50;
                while (sub < nb) {
                    if (!rd(sub, 0x40)) { g_sweep_fail = "unreadable-sub"; g_sweep_fail_at = sub; return false; }
                    uint64_t sst = blk_total(sub); uintptr_t nsub = sub + sst;
                    if (sst == 0 || nsub <= sub || nsub > nb) { g_sweep_fail = "bad-sub-stride"; g_sweep_fail_at = sub; return false; }
                    bool sfree = blk_free(sub); uint32_t scls = blk_class(sub);
                    if (sfree) g_sweep_free++;
                    if (scls == want_cls) g_sweep_classmatch++;
                    if (sfree && blk_kind(sub) != 2 && scls == want_cls) {   // free manager-kind (0 remainder OR 1 coalesced) sub-block of this class
                        if (n >= REBUILD_MAX) { g_sweep_fail = "overflow"; g_sweep_fail_at = sub; return false; }
                        g_scratch[n++] = sub;
                    }
                    g_sweep_scanned++;
                    sub = nsub;
                }
            }
        } else {
            // A top-level (non-slab) block — collect it directly if it's a free block of this class.
            bool isfree = blk_free(b); uint32_t bcls = blk_class(b);
            if (isfree) g_sweep_free++;
            if (bcls == want_cls) g_sweep_classmatch++;
            if (isfree && bcls == want_cls) {
                if (n >= REBUILD_MAX) { g_sweep_fail = "overflow"; g_sweep_fail_at = b; return false; }
                g_scratch[n++] = b;
            }
        }
        g_sweep_scanned++;
        b = nb;
    }
    return true;
}

// static why-buffer (call is CS-held single-threaded); holds the decline/success detail for the caller's log.
static char g_why_buf[192];

int rebuild_free_list_from_pool(uintptr_t ctrl, int k, const char** out_why, uint32_t* out_us) {
    LARGE_INTEGER t0, t1, fq; QueryPerformanceCounter(&t0); QueryPerformanceFrequency(&fq);
    g_sweep_scanned = 0; g_sweep_fail = ""; g_sweep_fail_at = 0; g_sweep_free = 0; g_sweep_classmatch = 0;
    auto done = [&](const char* why, int rv) -> int {
        QueryPerformanceCounter(&t1);
        if (out_us)  *out_us  = (uint32_t)((t1.QuadPart - t0.QuadPart) * 1000000 / fq.QuadPart);
        if (out_why) *out_why = why;
        if (rv < 0) InterlockedIncrement(&g_rebuilt_declined); else InterlockedIncrement(&g_rebuilt_ok);
        return rv;
    };

    uintptr_t mgr = ctrl + 0xd8 + (uintptr_t)k * 0xa8;
    if (!rd(mgr + 0x58, 0x20) || !rd(ctrl + 0x90, 0x10))       // descriptor scalars [mgr+0x58,+0x78) + pool bounds [ctrl+0x90,+0xa0)
        return done("mgr/ctrl-unreadable", -1);
    uint32_t mgr_class   = *(uint32_t*)(mgr + 0x70);   // the engine's own 1-based class stamp (match target)
    uint32_t prior_count = *(uint32_t*)(mgr + 0x68);
    if (mgr_class < 1 || mgr_class > 8) { snprintf(g_why_buf, sizeof g_why_buf, "bad-class-tag=%u", mgr_class); return done(g_why_buf, -1); }

    int n = 0;
    // Primary pool [ctrl+0x90, ctrl+0x98) — arena's own canonicality bound (alloc_invariants uses the same).
    uintptr_t plo = *(uintptr_t*)(ctrl + 0x90), phi = *(uintptr_t*)(ctrl + 0x98);
    if (!sweep_range(plo, phi, mgr_class, n)) {
        snprintf(g_why_buf, sizeof g_why_buf, "sweep-%s @0x%llX after %d blk (pool[0x%llX,0x%llX) cls=%u prior=%u collected=%d)",
                 g_sweep_fail, (unsigned long long)g_sweep_fail_at, g_sweep_scanned,
                 (unsigned long long)plo, (unsigned long long)phi, mgr_class, prior_count, n);
        return done(g_why_buf, -1);
    }
    // Any donated regions belonging to this ctrl (arena's authoritative bookkeeping — never ctrl+0xc0).
    int dn = arena::donated_region_count();
    for (int i = 0; i < dn; i++) {
        uintptr_t dctrl = 0, dbase = 0; size_t dsize = 0;
        if (!arena::donated_region_get(i, &dctrl, &dbase, &dsize)) continue;
        if (dctrl != ctrl || dbase == 0 || dsize == 0) continue;
        if (!sweep_range(dbase, dbase + dsize, mgr_class, n)) {
            snprintf(g_why_buf, sizeof g_why_buf, "donated-sweep-%s @0x%llX after %d blk (cls=%u prior=%u collected=%d)",
                     g_sweep_fail, (unsigned long long)g_sweep_fail_at, g_sweep_scanned, mgr_class, prior_count, n);
            return done(g_why_buf, -1);
        }
    }

    // The safety guard: never commit an empty (or otherwise implausible) collection over a
    // manager that says it has blocks. This is the single thing the refuted version lacked (it wiped 64 managers
    // by committing a 0-collect). If the manager claims free blocks but the pool scan finds none, our ground
    // truth is inconsistent => DECLINE, leave the live state exactly as page-blind would.
    if (prior_count > 0 && n == 0) {
        // DECISIVE DIAGNOSTIC (capped): the sweep found 0 free class-k blocks though the mgr claims prior_count.
        // Sample the mgr's LIVE free chain (mgr+0x58, first 5 nodes, bounded=safe even if cyclic) to learn where its
        // free blocks physically are (IN/OUT of the swept pool) and their raw headers — this settles flat-vs-multiregion
        // and any decode mismatch in one run. Also dump the sweep histogram (free-seen / class-match-seen).
        static volatile long g_diagcap = 0;
        if (InterlockedIncrement(&g_diagcap) <= 8) {
            char samp[320]; int sp = 0; samp[0] = 0;
            uintptr_t node = *(uintptr_t*)(mgr + 0x58);
            for (int j = 0; j < 5 && node && sp < (int)sizeof(samp) - 64; j++) {
                if (!rd(node, 0x40)) { sp += snprintf(samp + sp, sizeof(samp) - sp, " [%d]0x%llX UNREADABLE", j, (unsigned long long)node); break; }
                uint32_t h38 = *(uint32_t*)(node + 0x38), h3c = *(uint32_t*)(node + 0x3c);
                bool inpool = (node >= plo && node < phi);
                sp += snprintf(samp + sp, sizeof(samp) - sp, " [%d]0x%llX %s free=%d kind=%u cls=%u",
                               j, (unsigned long long)node, inpool ? "IN" : "OUT", (int)((h38 & 1) == 0), h3c & 3, (h3c >> 2) & 0x1f);
                node = *(uintptr_t*)(node + 0x20);
            }
            rblog::write("FLIST-REBUILD DIAG mgr%d(cls=%u): swept pool[0x%llX,0x%llX) saw %d blk (free=%d class-match=%d) collected=0 | mgr free-chain head-nodes:%s",
                         k, mgr_class, (unsigned long long)plo, (unsigned long long)phi, g_sweep_scanned, g_sweep_free, g_sweep_classmatch, samp);
        }
        snprintf(g_why_buf, sizeof g_why_buf, "empty-collect (prior=%u scanned=%d free=%d clsmatch=%d cls=%u pool[0x%llX,0x%llX))",
                 prior_count, g_sweep_scanned, g_sweep_free, g_sweep_classmatch, mgr_class, (unsigned long long)plo, (unsigned long long)phi);
        return done(g_why_buf, -1);
    }

    // COMMIT (whole-or-nothing, last step, no earlier writes). g_scratch is in ascending-address order per range
    // (the linear sweep) — a consistent, LOOP-FREE-by-construction order (order is allocator-irrelevant per RE).
    uint64_t ssum = 0;
    for (int i = 0; i < n; i++) {
        *(uint64_t*)(g_scratch[i] + 0x18) = (i > 0)     ? g_scratch[i - 1] : 0;   // .prev (head.prev = 0)
        *(uint64_t*)(g_scratch[i] + 0x20) = (i < n - 1) ? g_scratch[i + 1] : 0;   // .next (tail.next = 0)
        ssum += (uint32_t)(*(uint32_t*)(g_scratch[i] + 0x38) >> 1);
    }
    *(uint64_t*)(mgr + 0x58) = n ? g_scratch[0]     : 0;   // head
    *(uint64_t*)(mgr + 0x60) = n ? g_scratch[n - 1] : 0;   // tail
    *(uint32_t*)(mgr + 0x68) = (uint32_t)n;                // count
    *(uint32_t*)(mgr + 0x6c) = (uint32_t)ssum;             // size-sum
    snprintf(g_why_buf, sizeof g_why_buf, "ok collected=%d (prior=%u scanned=%d cls=%u)", n, prior_count, g_sweep_scanned, mgr_class);
    return done(g_why_buf, n);
}

void probe_free_locations(uintptr_t ctrl, int k) {
    uintptr_t mgr = ctrl + 0xd8 + (uintptr_t)k * 0xa8;
    if (!rd(mgr + 0x58, 0x20) || !rd(ctrl + 0x90, 0x10)) return;
    uint32_t cnt = *(uint32_t*)(mgr + 0x68);
    if (cnt == 0) return;                              // nothing free in this class => nothing to classify
    uint32_t clsw = *(uint32_t*)(mgr + 0x70);
    uintptr_t plo = *(uintptr_t*)(ctrl + 0x90), phi = *(uintptr_t*)(ctrl + 0x98);
    uintptr_t node = *(uintptr_t*)(mgr + 0x58);
    int total = 0, in_pool = 0, in_donated = 0, in_arena_untracked = 0, out_of_arena = 0;
    uintptr_t first = 0; uint32_t f38 = 0, f3c = 0;
    for (int j = 0; j < 4096 && node && rd(node, 0x40); j++) {
        if (!first) { first = node; f38 = *(uint32_t*)(node + 0x38); f3c = *(uint32_t*)(node + 0x3c); }
        total++;
        if (node >= plo && node < phi)                in_pool++;              // in the primary [ctrl+0x90,+0x98) pool we sweep
        else if (arena::in_owned_pool(ctrl, node))    in_donated++;           // in a tracked donated region for this ctrl
        else if (arena::is_arena_addr(node))          in_arena_untracked++;   // in OUR arena but not tracked as this ctrl's memory
        else                                          out_of_arena++;         // outside the arena entirely (arena-full passthrough / unowned)
        uintptr_t nxt = *(uintptr_t*)(node + 0x20);
        if (nxt == node) break;                        // trivial self-loop guard
        node = nxt;
    }
    rblog::write("A4-OWNERSHIP mgr%d(cls=%u): free count=%u walked=%d | in_pool=%d in_donated=%d IN_ARENA_UNTRACKED=%d OUT_OF_ARENA=%d "
                 "| pool[0x%llX,0x%llX) first=0x%llX f38=0x%X f3c=0x%X",
                 k, clsw, cnt, total, in_pool, in_donated, in_arena_untracked, out_of_arena,
                 (unsigned long long)plo, (unsigned long long)phi, (unsigned long long)first, f38, f3c);

    // SWEEP ORACLE: run the chain-INDEPENDENT pool sweep (two-level descent) and compare to the walkable chain,
    // which is the ground truth here (this is a healthy manager). MATCH => the descent enumerates exactly the free
    // set the chain does, i.e. the rebuild's authoritative source is proven correct BY CONSTRUCTION for when the
    // chain later goes cyclic. MISMATCH => still desyncing: dump the first blocks + a phys-trace to see where.
    int sn = 0; g_sweep_scanned = 0; g_sweep_fail = ""; g_sweep_free = 0; g_sweep_classmatch = 0;
    LARGE_INTEGER st0, st1, sfq; QueryPerformanceCounter(&st0); QueryPerformanceFrequency(&sfq);
    bool ok = sweep_range(plo, phi, clsw, sn);
    QueryPerformanceCounter(&st1);
    uint32_t sweep_us = (uint32_t)((st1.QuadPart - st0.QuadPart) * 1000000 / sfq.QuadPart);
    rblog::write("A4-SWEEP-ORACLE mgr%d(cls=%u): %s collected=%d vs chain=%u | ok=%d scanned=%d free_seen=%d classmatch_seen=%d us=%u",
                 k, clsw, (sn == (int)cnt) ? "MATCH" : "MISMATCH", sn, cnt, (int)ok, g_sweep_scanned, g_sweep_free, g_sweep_classmatch, sweep_us);
    if (sn != (int)cnt) {
        char trc[320]; int tp = 0; trc[0] = 0;
        uintptr_t b = plo;
        for (int j = 0; j < 8 && b < phi && rd(b, 0x40) && tp < (int)sizeof(trc) - 48; j++) {
            uint32_t bh38 = *(uint32_t*)(b + 0x38), bh3c = *(uint32_t*)(b + 0x3c);
            uint64_t bt = (uint64_t)(bh38 >> 1) << 4;
            tp += snprintf(trc + tp, sizeof(trc) - tp, " 0x%llX(sz=%lluK free=%d k=%u c=%u)",
                           (unsigned long long)b, (unsigned long long)(bt >> 10), (int)((bh38 & 1) == 0), bh3c & 3, (bh3c >> 2) & 0x1f);
            if (bt == 0) { tp += snprintf(trc + tp, sizeof(trc) - tp, " STOP(sz0)"); break; }
            b += bt;
        }
        rblog::write("A4-SWEEP-CMP mgr%d(cls=%u): sweep_collected=%d vs chain=%u | ok=%d scanned=%d free_seen=%d classmatch_seen=%d | first8:%s",
                     k, clsw, sn, cnt, (int)ok, g_sweep_scanned, g_sweep_free, g_sweep_classmatch, trc);

        // PHYS-TRACE (cls3 only, focused): the free blocks are sub-blocks INSIDE 64K slabs. Anchor on a known free
        // block (chain head `first`) and walk both ways: +0x28 physical-next (should thread the interior sub-blocks)
        // and +0x30 physical-prev. This reveals how sub-blocks are laid out so the rebuild can descend into slabs.
        if (k == 2 && first) {
            char pt[360]; int pp = 0; pt[0] = 0;
            uintptr_t slab = first & ~(uintptr_t)0xFFFF;    // 64K-aligned containing slab
            pp += snprintf(pt + pp, sizeof(pt) - pp, "slab=0x%llX; +0x28 fwd:", (unsigned long long)slab);
            uintptr_t b = first;
            for (int j = 0; j < 7 && b && rd(b, 0x40) && pp < (int)sizeof(pt) - 64; j++) {
                uint32_t h38 = *(uint32_t*)(b + 0x38), h3c = *(uint32_t*)(b + 0x3c);
                pp += snprintf(pt + pp, sizeof(pt) - pp, " 0x%llX(%lluK f=%d k=%u c=%u)",
                               (unsigned long long)b, (unsigned long long)(((uint64_t)(h38 >> 1) << 4) >> 10),
                               (int)((h38 & 1) == 0), h3c & 3, (h3c >> 2) & 0x1f);
                uintptr_t nb = *(uintptr_t*)(b + 0x28);
                if (nb == b) break;
                b = nb;
            }
            rblog::write("A4-PHYS-TRACE cls3 chain-head=0x%llX f38=0x%X: %s", (unsigned long long)first, f38, pt);
        }
    }
}

} // namespace flist_rebuild
