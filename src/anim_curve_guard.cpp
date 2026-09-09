// anim_curve_guard.cpp — see anim_curve_guard.h. Sanitize the curve resolver's return: {0, committed entry}.
#include "anim_curve_guard.h"
#include "id_oracle.h"
#include "addr.h"
#include "resim.h"
#include "log.h"
#include <MinHook.h>
#include <windows.h>
#include <cstdint>

namespace anim_curve_guard {

static constexpr uintptr_t RESOLVER_IDA = 0x140879570ULL;   // FUN_140879570 — the rotation-curve/keyframe resolver
// Consumers read the quat at ret+0x8,+0xc,+0x10,+0x14 => the entry spans [ret, ret+0x18). Validate that extent.
static constexpr size_t    CURVE_SPAN   = 0x18;

// MS x64 ABI (MinGW win64 default): arg1=rcx, arg2=rdx, arg3(float)=xmm2. Verified: exactly 3 args, returns ptr in rax.
typedef void* (*resolver_fn)(void*, void*, float);
static resolver_fn orig_resolver = nullptr;

static volatile long g_guarded = 0;

// Active across the whole engine-on window (the crash fires post-rollback in FORWARD play) + during resim. In pure
// normal play (no rollback armed) the resolver never returns a wild pointer, so this is a no-op — the gate just
// removes the per-call validation tax when the feature is off. Mirrors render_subchild_guard::guard_active().
static inline bool guard_active() { return resim::engine_enabled() || resim::resim_active(); }

static void* hk_resolver(void* node, void* table, float blend) {
    void* r = orig_resolver(node, table, blend);
    if (r && guard_active() && !id_oracle::is_domain_valid((uintptr_t)r, CURVE_SPAN)) {
        // Wild resolved pointer (reverted/dangling arena chain) — coerce to the resolver's own null-return contract
        // so each caller's `test/je` default-pose branch fires. Refuses only a would-fault deref; a committed-but-
        // wrong pointer is left alone (render-LEAF cosmetic drift, self-heals) — we make the FAULT unrepresentable.
        long n = InterlockedIncrement(&g_guarded);
        if (n <= 3 || (n % 5000) == 0)
            rblog::write("ANIM-CURVE-GUARD #%ld: resolver FUN_140879570 returned wild 0x%llX (not domain-valid) -> 0; "
                         "routed to engine default-pose (0x14087D485 / 0x14096D837)",
                         n, (unsigned long long)(uintptr_t)r);
        return nullptr;
    }
    return r;
}

void init() {
    void* t = (void*)addr::resolve(RESOLVER_IDA);
    MH_STATUS st = MH_CreateHook(t, (void*)&hk_resolver, (void**)&orig_resolver);
    rblog::write("ANIM-CURVE-GUARD: hook FUN_140879570 @0x%llX %s "
                 "(wild curve-entry return -> 0 -> engine's own null-guard default-pose; RENDER-ONLY, desync-safe)",
                 (unsigned long long)(uintptr_t)t, st == MH_OK ? "OK" : "FAILED");
}

long guarded_count() { return g_guarded; }

} // namespace anim_curve_guard
