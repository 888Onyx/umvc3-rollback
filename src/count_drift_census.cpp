// count_drift_census.cpp — see count_drift_census.h. The count-drift experiment: measure the native count-gated-unlink GUARD-SKIP, the
// mechanism of the a4 count-drift seed (ranked the dominant environment generator as "resim sprints
// 7 frames in ~1-2ms while a4-touching workers run real-time" — a timing compression vanilla never produces).
//
// FUN_1404CAA60 (the standalone count-gated free-list unlink) is `cmp DWORD[rdx+0x68],0; jbe ret` — if the manager's
// count is 0, the whole unlink NO-OPs. When count==0 while the node being unlinked is still the list's head/tail (the
// list is non-empty but the count cache says 0), that skip leaves a consumed block chained = the LOST-UNLINK seed.
//
// This hook is passive (reads + counts, then calls the original). It splits seed-skips by rollback context so a long run
// answers the open question without a guess:
// during-resim >> forward-play, and ~0 with the engine OFF => the seed is OUR resim timing => the environment fix
// (quiesce a4-touching workers during resim) is real.
// engine-OFF > 0 (skips in vanilla play) => vanilla-latent => faithful restore is the honest ceiling.
// Also splits by thread (main vs worker) — a worker skip while g_resim_active is the exact compressed-interleave window.
#include "count_drift_census.h"
#include "addr.h"
#include "arena.h"
#include "resim.h"
#include "log.h"
#include <MinHook.h>
#include <windows.h>
#include <cstdint>

namespace count_drift_census {

static constexpr uintptr_t UNLINK_IDA = 0x1404CAA60ULL;   // FUN_1404CAA60: standalone count-gated free-list unlink
typedef void (*unlink_fn)(void*, void*, void*);           // (a1=rcx, mgr=rdx, node=r8), void return
static unlink_fn orig_unlink = nullptr;
static DWORD g_main_tid = 0;
static bool  g_armed = false;

static volatile LONG64 c_calls = 0;        // every unlink call
static volatile LONG64 c_skip_all = 0;     // count==0 at entry (the jbe taken; unlink NO-OPs) — incl. benign empty-list
static volatile LONG64 c_seed = 0;         // count==0 and node is the list head/tail => non-empty-but-zero-count = the seed
static volatile LONG64 c_seed_resim = 0, c_seed_fwd = 0, c_seed_engoff = 0;   // seed split by rollback context
static volatile LONG64 c_seed_main = 0, c_seed_worker = 0;                    // seed split by thread

// FUN_1404CAA60(rcx=a1, rdx=mgr, r8=node). count @ mgr+0x68, head @ mgr+0x58, tail @ mgr+0x60 (per objdump). mgr is
// on the PROCESS HEAP (not the arena), so it is validated only by the game's own always-valid call convention here.
static void hk_unlink(void* a1, void* mgr, void* node) {
    uintptr_t m = (uintptr_t)mgr, nd = (uintptr_t)node;
    _InterlockedIncrement64(&c_calls);
    if (m > 0x10000 && nd) {
        uint32_t count = *(volatile uint32_t*)(m + 0x68);
        if (count == 0) {                                  // the jbe fires: this unlink will do nothing
            _InterlockedIncrement64(&c_skip_all);
            uintptr_t head = *(volatile uintptr_t*)(m + 0x58);
            uintptr_t tail = *(volatile uintptr_t*)(m + 0x60);
            if (nd == head || nd == tail) {                // a real chained node in a count==0 list = the lost-unlink seed
                _InterlockedIncrement64(&c_seed);
                if      (!resim::engine_enabled()) _InterlockedIncrement64(&c_seed_engoff);   // vanilla-ish window
                else if (resim::resim_active())    _InterlockedIncrement64(&c_seed_resim);    // the compressed-timing window
                else                               _InterlockedIncrement64(&c_seed_fwd);       // engine-on forward play
                if (GetCurrentThreadId() == g_main_tid) _InterlockedIncrement64(&c_seed_main);
                else                                    _InterlockedIncrement64(&c_seed_worker);
            }
        }
    }
    orig_unlink(a1, mgr, node);
}

void init() {
    if (g_armed) return;
    g_main_tid = GetCurrentThreadId();
    void* t = (void*)addr::resolve(UNLINK_IDA);
    if (t && MH_CreateHook(t, (void*)&hk_unlink, (void**)&orig_unlink) == MH_OK &&
        MH_EnableHook(t) == MH_OK) {
        g_armed = true;
        rblog::write("COUNT-DRIFT ARMED: hooked FUN_1404CAA60 (count-gated unlink) @0x%llX — PASSIVE guard-skip census "
                     "(seed = count==0 while node is head/tail), split by resim/forward/engine-off + main/worker. "
                     "The split settles resim-induced vs vanilla-latent for the a4 count-drift seed.",
                     (unsigned long long)(uintptr_t)t);
    } else {
        rblog::write("COUNT-DRIFT: hook FUN_1404CAA60 @0x%llX FAILED (t=%p)", (unsigned long long)(uintptr_t)t, t);
    }
}

void report() {
    if (!g_armed || !c_calls) return;
    bool w = rblog::is_suppressed(); rblog::suppress(false);
    rblog::write("COUNT-DRIFT: unlink-calls=%lld | count==0 skips=%lld | SEED(count==0 on head/tail)=%lld "
                 "{ during-resim=%lld forward-play=%lld engine-OFF=%lld } { main=%lld worker=%lld } "
                 "— resim>>forward & OFF≈0 => seed is OUR resim timing (justifies quiescing a4 workers during resim); OFF>0 => vanilla-latent floor",
                 (long long)c_calls, (long long)c_skip_all, (long long)c_seed,
                 (long long)c_seed_resim, (long long)c_seed_fwd, (long long)c_seed_engoff,
                 (long long)c_seed_main, (long long)c_seed_worker);
    rblog::suppress(w);
}

} // namespace count_drift_census
