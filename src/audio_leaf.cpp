// audio_leaf.cpp — see audio_leaf.h. Resim-suppress the audio 3D-spatial-sync trunk (render-domain output leaf).
#include "audio_leaf.h"
#include "resim.h"
#include "addr.h"
#include "log.h"
#include <MinHook.h>
#include <windows.h>
#include <intrin.h>
#include <cstdint>

namespace audio_leaf {

static constexpr uintptr_t TRUNK_IDA = 0x1405CC040ULL;   // per-frame audio 3D-sync trunk (walks the channel array)
typedef void (*fn4)(void*, void*, void*, void*);
static fn4 orig_trunk = nullptr;
static volatile LONG64 c_suppressed = 0, c_passed = 0;

// 4-ARG PASSTHROUGH (arity-safe): the trunk is a 1-arg vtable method (this in rcx, return unused), but
// passing all four arg registers through is arity-safe regardless of the true signature.
static void hk_trunk(void* a, void* b, void* c, void* d) {
    if (resim::resim_active()) { _InterlockedIncrement64(&c_suppressed); return; }   // SUPPRESS during resim
    _InterlockedIncrement64(&c_passed);
    orig_trunk(a, b, c, d);
}

void init() {
    uintptr_t t = addr::resolve(TRUNK_IDA);
    if (t && MH_CreateHook((void*)t, (void*)&hk_trunk, (void**)&orig_trunk) == MH_OK)
        rblog::write("AUDIO-LEAF ARMED: audio 3D-sync trunk FUN_1405CC040 suppressed during resim (render-domain output consumer, on the same side of the suppression boundary as its render producer) — closes 0x1405D73B6");
    else
        rblog::write("AUDIO-LEAF: trunk FUN_1405CC040 hook FAILED");
}
long long suppressed() { return c_suppressed; }

} // namespace audio_leaf
