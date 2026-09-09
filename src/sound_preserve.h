#pragma once
// sound_preserve — cross-boundary-pointer fix for the sound cue/source crash family.
// Field-level PRESERVE of each cue's descriptor vtable across arena::load: capture LIVE before the revert (at the
// rollback PRE-FREEZE window), write back identity-validated after. The detector (capture + revert log) is always
// on; the writeback is toggle-gated (default OFF).
namespace sound_preserve {
void capture(int frame);   // PRE-FREEZE (threads live): walk the cue slots, snapshot each busy descriptor's vtable. Read-only.
void restore(int frame);   // POST-LOAD: log reverted vtables; identity-validated writeback when armed.
bool enabled();
void toggle();             // arm/disarm the writeback (default OFF)
void report();
}
