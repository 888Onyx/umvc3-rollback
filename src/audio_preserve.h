#pragma once
// audio_preserve — PER-OBJECT keep-live for the NON-REFLECTED streaming audio engine objects (the streaming
// voiceP/channel/strips/resource the probe finds + the sSound/ss_sub containers). These are slab-packed in the
// SHARED Resource/Global MtScalableAllocator pools, so PAGE-exclusion is forbidden (it kept allocator free-list
// nodes LIVE across the rollback, overriding the coherent-full revert => torn free-list => crash). Instead we
// snapshot each object's exact bytes before arena::load and write them back after: the object keeps its live epoch
// (no garble) while the page reverts normally underneath it (allocator neighbor heals). Complements
// sound_resource_preserve (which covers the 52 REFLECTED r*Sound* resource vtables via the refcount-inc hook).
namespace audio_preserve {
void save();     // capture live bytes of the audio object set (call before arena::load)
void restore();  // write them back (call after arena::load)
}
