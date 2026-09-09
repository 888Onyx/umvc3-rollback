// life_floor.cpp — see life_floor.h. Routes render-wrapper deaths to the engine's own retirement ring during resim.
#include "life_floor.h"
#include "resim.h"
#include "addr.h"
#include "log.h"
#include <MinHook.h>
#include <windows.h>
#include <intrin.h>
#include <cstdint>

namespace life_floor {

static int64_t (*orig_rel1)(void*) = nullptr;   // FUN_14076f760 — RTV (0x140BBEBD8+0x28) / DSV (0x140BBEC18+0x28)
static int64_t (*orig_rel2)(void*) = nullptr;   // FUN_140783650 — Texture (0x140BBEC60+0x28), same fork idiom
static uintptr_t g_agectr = 0;                  // DAT_140E1B708 (frame_counter_1) — READ only (never written)
static volatile LONG64 c_floored = 0;
static constexpr uint32_t MARGIN = 16;          // fresh by +16 epochs => survives the ~7-frame window, then drains

// Force the engine's Release fork to the RING branch by stamping the DYING object as fresh. The fork is
// `cmp [this+0x8], counter; jl immediate-dtor` (fallthrough = ring push). Setting [this+0x8] = counter+MARGIN makes
// jl not taken ⇒ ring. We touch only the dying wrapper's own 4-byte +0x8 stamp (the +0xc refcount is untouched so
// orig's atomic decrement is unaffected). If orig's decrement does not reach zero the fork isn't taken and the
// stamp bump merely delays this object's future retirement by MARGIN epochs (benign live-too-long, arena-reverted).
static inline void floor_stamp(void* self) {
    if (self && resim::resim_active() && g_agectr) {
        *(uint32_t*)((uintptr_t)self + 0x8) = *(volatile uint32_t*)g_agectr + MARGIN;
        _InterlockedIncrement64(&c_floored);
    }
}
static int64_t hk_rel1(void* self) { floor_stamp(self); return orig_rel1(self); }
static int64_t hk_rel2(void* self) { floor_stamp(self); return orig_rel2(self); }

void init() {
    g_agectr = addr::resolve(0x140E1B708ULL);
    uintptr_t r1 = addr::resolve(0x14076F760ULL), r2 = addr::resolve(0x140783650ULL);
    int ok = 0;
    if (r1 && MH_CreateHook((void*)r1, (void*)&hk_rel1, (void**)&orig_rel1) == MH_OK) ok++;
    else rblog::write("LIFE-FLOOR: Release fork FUN_14076F760 hook FAILED");
    if (r2 && MH_CreateHook((void*)r2, (void*)&hk_rel2, (void**)&orig_rel2) == MH_OK) ok++;
    else rblog::write("LIFE-FLOOR: Release fork FUN_140783650 hook FAILED");
    rblog::write("LIFE-FLOOR ARMED: %d/2 wrapper Release forks routed to the retirement ring during resim (stamp+=%u, render-domain only; age-ctr READ-ONLY @0x%llX) — restore-faithful, RING-UNIT restores the ring coherently",
                 ok, MARGIN, (unsigned long long)g_agectr);
}
long long floored() { return c_floored; }

} // namespace life_floor
