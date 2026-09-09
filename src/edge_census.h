#pragma once
// edge_census — READ-ONLY ground-truth edge map builder. At the coherent frozen checkpoint, scans the arena,
// recognizes live objects by our 6064-vtable domain, and classifies every pointer field's target by actual
// RESIDENCE (in-arena / module-const / out-of-arena-heap). Accumulates per (vtable,offset) across the long run.
// Output = the ground-truth cross-boundary edge map for the owned-heap edge-coherent restore. A deterministic
// instrument over the census table (census_types.h). Dumps to edge_census.csv.
namespace edge_census {
    void census();   // call at the frozen checkpoint (coherent live state)
    void dump();     // write accumulated census to disk
    // edge_coherent_restore. Call at PH_POST_LOAD (after arena::load). Walks live objects, buckets each carrier
    // edge A/B/C/D, and NULLs bucket-A stale external edges. Live by default (g_live=1): load-bearing for the
    // census-exclusive offsets {0x8,0x10,0x160} on the sound channel node (443 nulls over a 100k-frame run, all
    // +0x160 — the only live repair of that churn); offsets that overlap sound_edge_reconcile were trimmed from BUCKET_A.
    void coherent_restore();
}
