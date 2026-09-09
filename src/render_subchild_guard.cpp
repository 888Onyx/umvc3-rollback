// render_subchild_guard.cpp — see render_subchild_guard.h.
#include "render_subchild_guard.h"
#include "addr.h"
#include "arena.h"
#include "log.h"
#include "resim.h"
#include <MinHook.h>
#include <windows.h>
#include <cstdint>

namespace render_subchild_guard {

static constexpr uint64_t WALK_IDA      = 0x140615DE0ULL;  // FUN_140615de0 render-material draw-submit walk
static constexpr uint64_t SUBCHILD_OFF  = 0x60;            // material -> render sub-child ptr (P); **(M+0x60) is arg2
// The 4 render-material slots in param_1 that the 6 crash sites read (objdump-verified):
// r15+0x150 (x2 branches), r15+0x158, r15+0x160, r15+0x168. Site 6 reads param_2+0x3658 which
// ALIASES one of these same material objects (set mid-function), so fixing the object once covers it.
static constexpr uint64_t SLOTS[4]      = { 0x150, 0x158, 0x160, 0x168 };

// &g_zero is non-null and *(&g_zero)==0, so **(M+0x60) evaluates to 0 -> callee's param_2==0 path.
static uint64_t g_zero = 0;

typedef void (*walk_fn)(int64_t, int64_t);
static walk_fn orig_walk = nullptr;

static volatile long g_guarded = 0;

static inline bool canon(uint64_t p) { return p >= 0x10000ULL && p < 0x0000800000000000ULL; }
static bool readable(uint64_t p, size_t n) {
    if (!canon(p) || n == 0) return false;
    if (arena::is_arena_addr((uintptr_t)p) && arena::is_arena_addr((uintptr_t)(p + n - 1)))
        return arena::is_committed_addr((uintptr_t)p) && arena::is_committed_addr((uintptr_t)(p + n - 1));
    MEMORY_BASIC_INFORMATION mbi;
    if (!VirtualQuery((void*)p, &mbi, sizeof(mbi))) return false;
    if (mbi.State != MEM_COMMIT) return false;
    if (mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)) return false;
    return (p + n) <= (uintptr_t)mbi.BaseAddress + mbi.RegionSize;
}

// Active only when rollback can perturb render coherence (engine-on or mid-resim). In pure normal
// play (no rollback) the sub-child is never null, so this is a no-op anyway — the gate just removes
// the per-call slot-scan tax when the feature is off.
static inline bool guard_active() { return resim::engine_enabled() || resim::resim_active(); }

static void hk_walk(int64_t param_1, int64_t param_2) {
    if (!guard_active()) { orig_walk(param_1, param_2); return; }

    uint64_t p1 = (uint64_t)param_1;
    uint64_t patched[4];
    int       npatched = 0;

    if (canon(p1)) {
        for (int i = 0; i < 4; i++) {
            uint64_t slotaddr = p1 + SLOTS[i];
            if (!readable(slotaddr, 8)) continue;
            uint64_t M = *(uint64_t*)slotaddr;                 // the render material
            if (!canon(M) || !readable(M + SUBCHILD_OFF, 8)) continue;
            if (*(uint64_t*)(M + SUBCHILD_OFF) == 0) {         // sub-child absent (reverted to frame-N NULL)
                *(uint64_t*)(M + SUBCHILD_OFF) = (uint64_t)&g_zero;  // route to callee's param_2==0 path
                patched[npatched++] = M;
            }
        }
    }

    orig_walk(param_1, param_2);

    for (int i = 0; i < npatched; i++)
        *(uint64_t*)(patched[i] + SUBCHILD_OFF) = 0;           // restore the reverted NULL (no state change)

    if (npatched) {
        long n = InterlockedAdd(&g_guarded, npatched);
        if (n <= (long)npatched + 2 || (n % 5000) < npatched)
            rblog::write("RENDER-SUBCHILD-GUARD #%ld: param_1=0x%llX routed %d null sub-child(ren) to callee param_2==0 path",
                n, (unsigned long long)p1, npatched);
    }
}

void init() {
    // CreateHook only — resim.cpp enables MH_ALL_HOOKS once, after every module's init().
    void* t = (void*)addr::resolve(WALK_IDA);
    MH_STATUS st = MH_CreateHook(t, (void*)&hk_walk, (void**)&orig_walk);
    rblog::write("RENDER-SUBCHILD-GUARD: hook FUN_140615de0 @0x%llX %s "
                 "(null +0x60 sub-child -> callee's intended param_2==0 path; desync-safe render guard)",
        (unsigned long long)(uintptr_t)t, st == MH_OK ? "OK" : "FAILED");
}

long guarded_count() { return g_guarded; }

} // namespace render_subchild_guard
