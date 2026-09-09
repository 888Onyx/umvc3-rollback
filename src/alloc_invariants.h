#pragma once
#include <cstdint>
// alloc_invariants — per-type invariant checks on the allocator, replacing byte-diffing.
//
// Principle: a crash = an object OUTSIDE its type's valid set V_T — a state the
// game's own code never produces, so it derefs without checking. Each type has an invariant I_T. We do not
// chase address-determinism (a dead end); we check whether each object satisfies its invariant. A relocated-but-valid
// pointer SATISFIES the invariant (silent); only a genuinely broken invariant alarms, so the false-alarm storm a byte diff produces
// vanishes by construction.
//
// V1 scope = the crash-proven allocator invariants: L_FREE_LIST_DLL + L_ALLOC_LIST_DLL
// on each MtScalableAllocator sub-heap manager — the direct cause of the +0x202 fault at 0x1404CA852.
// Run at three phases per rollback so the first phase that breaks names the layer to fix:
// frozen (pre-arena::load, frame N coherent+frozen) — baseline; a break here = the game was already incoherent
// POSTLOAD (after arena::load, before resim) — a break here = the RESTORE produced an invalid object
// POSTRESIM(after replay) — a break only here = REPLAY/free-layer churn, not restore
// Must run frozen (callers pass already-suspended phases): a linked-list invariant can't be read while workers mutate it.
namespace alloc_invariants {
    enum Phase { PH_FROZEN = 0, PH_POSTLOAD = 1, PH_POSTRESIM = 2 };
    void check(Phase phase, int frame);   // evaluate the crash-proven invariants; log only INVARIANT_BROKEN / UNREADABLE
    void dump();                          // lifetime summary: breaks per phase per invariant
    void set_off(bool v);
    bool is_off();

    // ── INVARIANT REPAIRER (the torn-save fix) ──────────────────────────────────────────────────────────────
    // The checker proved the per-size-class FREE list tears at SAVE as a recip break: forward chain (+0x20) intact,
    // backward link (+0x18) stale — a split store (next written, prev not) captured by a contention-fallback
    // UNLOCKED save (atomic-save's all-CS TryEnter fails under combat load -> torn snapshot). The grand-invariant
    // "capture coherent" approach is structurally fragile (and a blocking acquire deadlocks via FUN_1404cb350's
    // mgr_k+0x80 ⊃ FUN_1404ca110's +0x620 nesting). So instead we RESTORE coherent: at POSTLOAD rebuild each free list's
    // +0x18 from the intact forward chain + reconcile tail/count/size-sum. Desync-free: +0x18/+0x20 are arena
    // pointers (gp_crc skips arena ptrs) and the mgr scalars are allocator bookkeeping (restored via the alloc
    // ring, never hashed). Makes any torn save harmless regardless of capture timing. Must run frozen + after
    // arena::load and restore_allocators (i.e. at POSTLOAD).
    void repair_freelists(int frame);     // rebuild reciprocal links on every scalable allocator's free lists
    void set_repair(bool v);              // A/B gate (default OFF)
    bool repair_on();
}
