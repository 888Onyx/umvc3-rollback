#pragma once
// dyndelete — the lifetime/generation TWIN of dynrestore. dynrestore restores VALUES by structure; dyndelete
// restores EXISTENCE by structure: it reconciles the lifetime-dependent structures (free lists, references)
// against the idspine generational liveness ledger so they agree with frame-N reality.
//
// SLICE 1 (this build) is the READ-ONLY LIE DETECTOR only — the hard gate before any reconcile WRITE ships.
// At PH_POST_LOAD (and POSTRESIM) it walks each allocator manager's free list and classifies every node
// against the ledger (idspine::lookup):
// COHERENT — death<=N (freed by the target), or birth>N (a later rebirth the rollback erases). Fine.
// STALE-LIVE — birth<=N<death: the ledger says this block was a LIVE object at frame N, yet it is on the
// restored free list. The smoking gun: a live object the allocator will hand back out.
// CYCLE — the free-list walk exceeds the count cap (self-loop / cycle => FUN_1404ca650 spin / hang root).
// UNKNOWN — never stamped (freed before the spine was recording); benign coverage gap, not corruption.
// pure READ-ONLY: reads the free list + our SHADOW ledger, writes nothing to game memory, only logs.
//
// The GATE: if the validator reports ALL-COHERENT while a crash still reproduces on that rollback, the ledger
// is blind/mis-keyed (or the corruption forms during replay, where reconcile cannot act) => NO sever ships.
// A nonzero STALE-LIVE/CYCLE on a crash-correlated rollback => dyndelete has a real target => reconcile is
// justified, and only then do we build the sever leg.
#include <cstdint>

namespace dyn_delete {

// Validate one allocator control block's free lists against the ledger. target_frame = the frame the restored
// (or post-resim) free list is expected to represent. No-op unless armed (set_validate / the Numpad7 long run).
void validate(uintptr_t control, int target_frame, const char* tag);

void set_validate(bool on);   // arm/disarm the read-only lie detector (default OFF; armed by the alloc-debug run)
bool validate_on();

} // namespace dyn_delete
