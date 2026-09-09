#pragma once
#include <cstdint>
// Read-only allocator consistency probe — the make-or-break for dynamic-restore's REBUILD discipline.
// After arena::load + restore_allocators, do the control-block free lists (byte-reverted metadata) AGREE
// with the blocks they thread (also byte-reverted)? For each of the 8 size-class managers, walk the free
// list and check every node's own class nibble (+0x3c) against the manager's class (+0x70), plus count
// (+0x68) and cycle. A node reverted to a stale/pre-carve image (the class-0 wall) shows as a class
// mismatch. DIVERGE => the byte-revert produced control-block-vs-block incoherence => rebuild-from-headers
// would fix it (the allocator JOINS dynamic restore). consistent => the deadlock forms during replay, not
// from restore skew => the allocator stays on the serial-gate model. Read-only.
namespace alloc_consistency {
// anomalies_only=true => suppress the routine per-mgr/summary lines (only print on a real anomaly). Use for the
// per-resim-frame calls (latch the BIRTH frame of a physical-graph tear) without flooding the rollback log.
void check(uintptr_t control, const char* tag, bool anomalies_only = false);
// Tell the probe which frame the allocator-control-block HEADS were restored from (the 10-slot alloc
// ring's chosen frame). check() compares it to each corrupt node BODY's arena source frame: a mismatch
// is the W2 cross-ring skew (head from frame Fh, body from Fb != Fh) caught in the act. Call from
// restore_allocators with g_alloc_ring_frames[best_slot] (or -1 if it bailed / heads not restored).
void note_head_frame(int frame);
// STRUCTURE-AWARE allocator restore (minimal form): re-derive each manager's free-list COUNT (+0x68)
// from the actual (acyclic-at-restore) list, replacing the byte-reverted-and-possibly-stale count.
// The count is bookkeeping over the list => derive it from the list, don't byte-revert it. F8-gated A/B.
void rederive_counts(uintptr_t control, const char* tag);
}
