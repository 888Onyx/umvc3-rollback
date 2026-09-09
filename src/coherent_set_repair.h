#pragma once
#include <cstdint>
// coherent_set_repair — the catalog-driven POSTLOAD repairer.
//
// Every rollback crash so far = a COHERENT SET split across the boundary: a HOLDER that survives/restores references a
// REFERENT that was freed / reverted to another epoch / reused as data; the holder later walks/derefs it -> crash. We
// fix them restore-side at POSTLOAD (frozen, post-restore, pre-resim): make each restored structure satisfy its invariant.
// Desync-free when we only touch arena pointers (gp_crc skips arena addrs) or non-gameplay bookkeeping/render scalars.
//
// This module is the realized design from the coherent-set catalog (verified against the binary):
// a TABLE of structure descriptors + generic repair kernels + a verified enumerator (the sUnit scheduler-line walk,
// HEAD=sUnit+0x50+line*0x30, next=node+0x18 — the engine's own FUN_14051b4c0 tick order).
// Adding a structure = a TABLE ROW, not new code. Each row has its own `enabled` gate so rows ship one at a time.
namespace coherent_set_repair {
    void run(int frame, int rollback_target, bool identity);  // CATALOG rows only now (scope-gated detect-and-repair; behind patch_pile)
    // Always-on: the two proven structural mechanisms — the render present/retirement-list
    // {count,base} compact + the sUnit MtList link-sever — run UNCONDITIONALLY (they close render-domain kept-live-vs-
    // reverted splits, orthogonal to the slab-reuse class P3 subsumes; gating them under patch_pile silently re-opened
    // the 0x1405DA4B5 {count,base} family). Same treatment as effect_splice/render_subchild_guard/rtv_probe.
    void run_structural(int frame, int rollback_target, bool identity);
    void set_enabled(bool v);     // master gate
    bool is_enabled();
    void cycle_scope();           // Numpad: OFF -> proven-rows-only -> all-rows -> OFF (A/B with F4 gp_crc)
    void report();
}
