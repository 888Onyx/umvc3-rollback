#pragma once
#include <cstdint>
#include <cstddef>
// edge_break — the complete cross-boundary edge detector. Answers "which edges does the revert break?" without
// depending on any probe's field of view.
//
// Why this exists: edge_census is a sampled, vtable-gated, allocator-scoped instrument. It can only report edges on
// objects (a) whose vtable is in census_types.h, (b) that sit at a block's payload start (one object per block, so
// slab-packed neighbours are invisible), (c) that live inside the 64 MtScalableAllocator regions, and (d) that its
// 200k-qword resume cursor happened to reach before they died. Anything in POD/raw memory, in a pooled slab behind
// the first object, on the CRT heap, or short-lived, is structurally unseeable. Extending a hand-maintained repair
// table from that data fixes only the shadow the probe casts.
//
// The INVARIANT instead: out-of-arena memory is never reverted. So any qword that (1) the revert changed and
// (2) held — before or after — a pointer to out-of-arena memory, is a cross-boundary edge the revert just broke.
// Both sides of that test are available for free at the revert site: arena::load already captures the pre-revert
// page (g_shadow_live) and then writes the restored page over it. Diffing them is complete by construction —
// every reverted byte is examined, regardless of type, layout, pooling, allocator, or lifetime.
//
// MEASURE-FIRST: this is READ-ONLY. It names the true edge set so the fix is aimed at reality, not at the probe.
namespace edge_break {

bool enabled();
void set_enabled(bool on);

void begin(int frame);                                   // per-rollback reset; call before the revert loop
void page(uintptr_t page_addr, const void* pre, const void* post, size_t len);   // diff one reverted page
void report(int frame);                                  // per-rollback summary + samples

} // namespace edge_break
