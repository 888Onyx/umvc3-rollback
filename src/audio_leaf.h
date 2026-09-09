#pragma once
// audio_leaf — render-suppression boundary completion (the 0x1405D73B6 close)
//
// The audio 3D-spatial-sync trunk FUN_1405CC040 is a per-frame subsystem tick (dispatcher calls it via
// [obj+0x401f0]->vt+0x30, alongside the other per-frame leaf ticks). It walks a channel array and, per channel,
// dereferences a holder (item+0x80) that points at an EXTERNAL render/skeleton transform-provider (vtbl family
// 0x140B11xxx) to fetch a bone/world matrix. It is a render-domain OUTPUT CONSUMER — a pure function of gameplay
// state, feeding nothing back into the sim. During resim, render ticking is SUPPRESSED (the render-suppression trade-off),
// so this consumer runs while its producer is frozen ⇒ it walks a stale/divergent holder edge into a byte-coherent-
// but-wrong-type object (rax=0x3F800000=1.0f used as a vtable) ⇒ crash 0x1405D73B6. Render-suppression suppressed
// the PRODUCER but left this CONSUMER running. Fix = put the consumer on the same side of the boundary: suppress
// the trunk during resim (like the draw-build chain). Benign — audio position re-syncs from the deterministic
// gameplay state on the next forward frame (the render-leaf principle: output is re-derived, not guarded or healed).
namespace audio_leaf {
void init();          // MH_CreateHook the audio-sync trunk; caller enables hooks
long long suppressed(); // count of resim-frame suppressions (measurement)
}
