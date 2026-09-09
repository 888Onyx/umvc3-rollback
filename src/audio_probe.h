#pragma once
#include <cstdint>
// audio_probe — read-only typed graph walk from the audio roots, to DERIVE the audio domain as a TYPE SET
// (not a sample). Uses the baked MtDTI type graph (audio_typegraph.inc) for precise pointer-following + extents,
// plus a curated table for the non-reflected low-level audio leaves (streaming voice/channel/strip/rSoundSource).
// run_once() dumps a per-TYPE aggregate; collect() returns the per-OBJECT regions for audio_preserve.
namespace audio_probe {
struct Region { uintptr_t base; uint32_t size; };
int  collect(Region* out, int max_n);   // walk from sSound, fill out[] with (base,size) audio objects, return count
void run_once();                          // safe to call every save; self-guards to fire exactly once (logging).
}
