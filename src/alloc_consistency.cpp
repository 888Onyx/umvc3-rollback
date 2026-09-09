// alloc_consistency.cpp — read-only allocator consistency probe (make-or-break for the REBUILD discipline).
// See alloc_consistency.h. Layout verified against the decompilation of FUN_1404caba0 / FUN_1404cb350:
// 8 size-class managers: control + 0xd8 + k*0xa8 (k=0..7); manager+0x70 = class (1..8).
// free list: manager+0x58 = head, +0x68 = count; node next-link = node+0x20.
// block class nibble: (*(u32*)(node+0x3c) >> 2) & 0x1f (== the manager's class when coherent;
// a node byte-reverted to its pre-carve image reads class 0, the "class-0 wall").
// We only READ. No link is written, no list altered.
#include "log.h"
#include "alloc_consistency.h"
#include "arena.h"
#include <windows.h>
#include <cstdint>

namespace alloc_consistency {

// The frame the allocator-control-block HEADS were restored from (10-slot alloc ring). Set by
// restore_allocators via note_head_frame(); -2 means "unknown / not yet noted this load".
static volatile int g_head_frame = -2;
void note_head_frame(int frame) { g_head_frame = frame; }

// Classify a corrupt node's BODY source against the HEAD source: live store vs cross-ring skew, in one read.
// last_source_frame: >=0 ring frame, -1 baseline, -2 orphan, -3 live/not-restored, -100 non-arena.
static const char* skew_verdict(uintptr_t node, int body_src, int head_src) {
    if (!arena::is_arena_addr(node)) return "OUT-OF-ARENA (Global/heap node — cross-allocator, not the in-arena ring)";
    if (body_src == -3)              return "W1-LIVE (body NOT restored this load => a live store corrupted it; next step is a hardware write watchpoint)";
    if (body_src == -2)              return "ORPHAN-ZERO (body page had no source <= target => zeroed)";
    if (head_src == -2)              return "head-frame-unknown (restore_allocators bailed => heads NOT restored, bodies were)";
    if (body_src != head_src)        return "W2-CROSS-RING-SKEW (body frame != head frame — the two-ring incoherence, CONFIRMED)";
    return "SAME-FRAME (head+body coherent — corruption is neither cross-ring nor live; look elsewhere)";
}

static bool readable(uintptr_t p, size_t n) {
    if (!p || n == 0) return false;
    // FAST PATH (the fix for the 6.9s/6.2s prep+postresim walk): free-list nodes are arena-resident, so
    // use the arena's committed BITMAP (ns) instead of a VirtualQuery SYSCALL (µs) per node. This walk runs
    // per-node ×8 mgrs ×N allocators ×2 (post-load + POSTRESIM); the syscall version cost ~13s/rollback.
    // Out-of-arena addresses (rare) fall back to VirtualQuery.
    if (arena::is_arena_addr(p) && arena::is_arena_addr(p + n - 1))
        return arena::is_committed_addr(p) && arena::is_committed_addr(p + n - 1);
    MEMORY_BASIC_INFORMATION mbi;
    if (!VirtualQuery((void*)p, &mbi, sizeof(mbi))) return false;
    if (mbi.State != MEM_COMMIT) return false;
    if (mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)) return false;
    uintptr_t end = (uintptr_t)mbi.BaseAddress + mbi.RegionSize;
    return (p + n) <= end;
}

void check(uintptr_t control, const char* tag, bool anomalies_only) {
    // Force the recip discriminator through the resim log-suppression window so the
    // when=ROLLBACK scan (called in the frozen restore window) co-prints with the when=SAVE scan on the fatal
    // frame — the decisive torn-at-save-vs-clean-at-restore signal that names the carrier.
    bool _sup = rblog::is_suppressed(); rblog::suppress(false);
    if (!readable(control + 0xd8, 8)) {
        rblog::write("ALLOC-CONSIST[%s]: control 0x%llX unreadable", tag, (unsigned long long)control);
        rblog::suppress(_sup);
        return;
    }
    // region bounds (informational — control-level; not gated on, the class check is the decisive one)
    uintptr_t region_lo = readable(control + 0x90, 8) ? *(uintptr_t*)(control + 0x90) : 0;
    uintptr_t region_hi = readable(control + 0x98, 8) ? *(uintptr_t*)(control + 0x98) : 0;

    int total_diverge = 0, total_walked = 0;
    for (int k = 0; k < 8; k++) {
        uintptr_t mgr = control + 0xd8 + (uintptr_t)k * 0xa8;
        if (!readable(mgr + 0x70, 4) || !readable(mgr + 0x68, 4) || !readable(mgr + 0x58, 8)) continue;
        uint32_t  mgr_class = *(uint32_t*)(mgr + 0x70);
        uint32_t  claimed   = *(uint32_t*)(mgr + 0x68);
        uintptr_t head      = *(uintptr_t*)(mgr + 0x58);

        int  walked = 0, badcls = 0, oob = 0, recip_break = 0, class0 = 0, skew_logged = 0;
        int  phys_break = 0, phys_skew = 0, phys_logged = 0;   // the UNCHECKED physical-coalesce dimension
        bool overrun = false, unreadable = false;
        uint32_t cap = (claimed < 65536 ? claimed : 65536) + 32;   // expected length + margin => cycle/garbage trips it
        uintptr_t node = head;
        while (node) {
            if ((uint32_t)walked > cap) { overrun = true; break; }
            if (!readable(node + 0x3c, 4) || !readable(node + 0x20, 8)) { unreadable = true; break; }
            uint32_t  ncls = (*(uint32_t*)(node + 0x3c) >> 2) & 0x1f;    // the node's OWN class
            uintptr_t next = *(uintptr_t*)(node + 0x20);                // next link
            bool bad_cls   = (ncls != mgr_class);                       // stale/class-0/wrong-list node
            bool is_class0 = (ncls == 0);                              // the FUN_1404cb350 underflow face specifically
            bool recip_bad = (next && readable(next + 0x18, 8) &&
                              *(uintptr_t*)(next + 0x18) != node);      // (ii) back-link broken (the link face)
            if (bad_cls)   badcls++;
            if (is_class0) class0++;
            if (recip_bad) recip_break++;
            if (region_lo && region_hi > region_lo && (node < region_lo || node >= region_hi)) oob++;
            // ── PHYSICAL-NEIGHBOR GRAPH (the dimension FUN_1404cb480 coalesces on) ──
            // FUN_1404cb480 merges with phys-next (+0x28) / phys-prev (+0x30),
            // gated only on owner(+0x08)==neighbor+0x08, sizeclass(+0x3c>>2&0x1f)==mgr+0x70, busy(+0x38&1)==0 —
            // no membership/cycle/canary; then FUN_1404ca220 re-inserts with no node!=head guard, so a torn
            // or stale phys link can mint a +0x20 self-loop = the guard-less FUN_1404ca650 spin. We READ this dimension
            // (no write) for two things: (1) is the coalesce graph structurally torn; (2) the timeline
            // question — was a phys neighbor rewound on a different timeline than this node (one RESTORED from
            // the ring >=0, the other still LIVE/forward -3) = dynrestore stitching the derived free-list graph
            // across the seam, the heap analog of the visual garble eliminated by not rewinding derived state.
            uintptr_t pnext = readable(node + 0x28, 8) ? *(uintptr_t*)(node + 0x28) : 0;  // phys-next neighbor
            uintptr_t pprev = readable(node + 0x30, 8) ? *(uintptr_t*)(node + 0x30) : 0;  // phys-prev neighbor
            uintptr_t owner = readable(node + 0x08, 8) ? *(uintptr_t*)(node + 0x08) : 0;  // owning chunk (+0x8)
            bool pn_recip_bad = pnext && readable(pnext + 0x30, 8) && *(uintptr_t*)(pnext + 0x30) != node;
            bool pp_recip_bad = pprev && readable(pprev + 0x28, 8) && *(uintptr_t*)(pprev + 0x28) != node;
            bool pn_owner_bad = pnext && owner && readable(pnext + 0x08, 8) && *(uintptr_t*)(pnext + 0x08) != owner;
            bool pp_owner_bad = pprev && owner && readable(pprev + 0x08, 8) && *(uintptr_t*)(pprev + 0x08) != owner;
            bool phys_struct_bad = pn_recip_bad || pp_recip_bad || pn_owner_bad || pp_owner_bad;
            int  nsrc  = arena::last_source_frame(node);
            int  pnsrc = pnext ? arena::last_source_frame(pnext) : -100;
            int  ppsrc = pprev ? arena::last_source_frame(pprev) : -100;
            // timeline tear = node reverted (src>=0) but a phys neighbor still LIVE/not-reverted (-3), or vice
            // versa. (Different >=0 frames is NORMAL under windowed restore — both are coherent <=target — so we
            // flag only the restored-vs-live CLASS split, the true cross-timeline stitch.)
            bool pn_tline_bad = pnext && ((nsrc >= 0) != (pnsrc >= 0));
            bool pp_tline_bad = pprev && ((nsrc >= 0) != (ppsrc >= 0));
            bool phys_tline_bad = pn_tline_bad || pp_tline_bad;
            if (phys_struct_bad) phys_break++;
            if (phys_tline_bad)  phys_skew++;
            if ((phys_struct_bad || phys_tline_bad) && phys_logged < 4) {
                phys_logged++;
                rblog::write("ALLOC-PHYS[%s] mgr%d node=0x%llX owner=0x%llX nodesrc=%d | pnext=0x%llX(recip=%s own=%s src=%d) "
                    "pprev=0x%llX(recip=%s own=%s src=%d) => %s%s",
                    tag, k, (unsigned long long)node, (unsigned long long)owner, nsrc,
                    (unsigned long long)pnext, pn_recip_bad ? "BROKEN" : "ok", pn_owner_bad ? "MISMATCH" : "ok", pnsrc,
                    (unsigned long long)pprev, pp_recip_bad ? "BROKEN" : "ok", pp_owner_bad ? "MISMATCH" : "ok", ppsrc,
                    phys_struct_bad ? "PHYS-STRUCT-TORN (coalesce graph broken => cb480 mis-splices => ca650 spin) " : "",
                    phys_tline_bad  ? "PHYS-TIMELINE-SKEW (phys neighbor on a DIFFERENT restore timeline than node => dynrestore is rewinding the derived free-list graph across the seam)" : "");
            }
            // The DISCRIMINATOR: on the first few corrupt nodes, correlate the node BODY's arena source
            // frame against the HEAD's source frame. body!=head => W2 cross-ring skew caught in the act;
            // body=-3 (live) => a wild live store (next step: hardware write watchpoint); out-of-arena => Global/cross-allocator node.
            if ((bad_cls || recip_bad) && skew_logged < 4) {
                skew_logged++;
                int body_src = arena::last_source_frame(node);
                int next_src = next ? arena::last_source_frame(next) : -100;
                rblog::write("ALLOC-SKEW[%s] mgr%d cls=%u node=0x%llX ncls=%u%s recip=%s next=0x%llX "
                    "| body_srcF=%d head_srcF=%d nextbody_srcF=%d orphaned=%d => %s",
                    tag, k, mgr_class, (unsigned long long)node, ncls, is_class0 ? "(CLASS0!)" : "",
                    recip_bad ? "BROKEN" : "ok", (unsigned long long)next,
                    body_src, g_head_frame, next_src, (int)arena::was_orphaned_last_load(node),
                    skew_verdict(node, body_src, g_head_frame));
            }
            node = next;
            walked++;
        }
        bool count_mismatch = (!overrun && !unreadable && walked != (int)claimed);
        bool diverge = overrun || unreadable || badcls || recip_break || count_mismatch || phys_break || phys_skew;
        total_walked += walked;
        if (diverge) total_diverge++;
        if (diverge || (!anomalies_only && walked > 0))
            rblog::write("ALLOC-CONSIST[%s] mgr%d cls=%u head=0x%llX walked=%d claimed=%u badcls=%d class0=%d recip=%d physbreak=%d physskew=%d oob=%d overrun=%d unread=%d => %s",
                tag, k, mgr_class, (unsigned long long)head, walked, claimed, badcls, class0, recip_break, phys_break, phys_skew, oob,
                (int)overrun, (int)unreadable, diverge ? "DIVERGE" : "consistent");
    }
    if (!anomalies_only || total_diverge)
        rblog::write("ALLOC-CONSIST[%s]: region=[0x%llX,0x%llX) %d/8 mgrs DIVERGE, freelist-nodes-walked=%d => %s",
            tag, (unsigned long long)region_lo, (unsigned long long)region_hi, total_diverge, total_walked,
            total_diverge ? "rebuild-from-headers would FIX (allocator JOINS dynamic restore)"
                          : "consistent (no restore-skew => deadlock forms DURING replay => allocator STAYS serial-gate)");
    rblog::suppress(_sup);
}

// Re-derive each manager's free-list count from the list it actually threads (acyclic at restore per the
// probe; walk is capped for safety). Writes only +0x68 (the count) — the minimal structure-aware fix for
// the observed count-mismatch. Does not touch links or tail (uncertain sentinel semantics). PH_POST_LOAD.
void rederive_counts(uintptr_t control, const char* tag) {
    if (!readable(control + 0xd8, 8)) return;
    int fixed = 0;
    for (int k = 0; k < 8; k++) {
        uintptr_t mgr = control + 0xd8 + (uintptr_t)k * 0xa8;
        if (!readable(mgr + 0x68, 4) || !readable(mgr + 0x58, 8)) continue;
        uintptr_t head = *(uintptr_t*)(mgr + 0x58);
        uint32_t old_count = *(uint32_t*)(mgr + 0x68);
        int walked = 0; uintptr_t node = head;
        while (node && walked < 70000) {                 // acyclic at restore; cap is a hard safety net
            if (!readable(node + 0x20, 8)) break;
            node = *(uintptr_t*)(node + 0x20);
            walked++;
        }
        if ((uint32_t)walked != old_count) {
            *(uint32_t*)(mgr + 0x68) = (uint32_t)walked;  // count:= derived-from-list (bookkeeping, not byte-reverted)
            fixed++;
            rblog::write("ALLOC-REDERIVE[%s] mgr%d: count %u->%d (re-derived from free list)", tag, k, old_count, walked);
        }
    }
    if (fixed) rblog::write("ALLOC-REDERIVE[%s]: %d manager counts re-derived from structure", tag, fixed);
}

} // namespace alloc_consistency
