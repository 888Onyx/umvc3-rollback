#pragma once
// p4_shadow — READ-ONLY validation of the reuse-quarantine epoch-rebuild (de-risks the quarantine's open question).
// Before any free is ever DEFERRED, prove the quarantine/liveness set can be rebuilt from the reverted arena's own
// in-use bits post-load. Records only; orig_free still runs; zero game writes; gp_crc-neutral.
namespace p4_shadow {
void validate_epoch_rebuild(int target_frame);   // call at POST-LOAD (after arena::load + restore_allocators)
}
