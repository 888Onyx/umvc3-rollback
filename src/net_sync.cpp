// net_sync.cpp — see net_sync.h.
#include "net_sync.h"
#include "net_transport.h"
#include "net_input.h"
#include "role.h"
#include "addr.h"
#include "log.h"
#include <MinHook.h>
#include <windows.h>

namespace net_sync {

// FUN_14000b350(matchctrl, seedU32): the single seed choke point. The engine's round-start
// broadcaster reads matchctrl+0x23424 (set here) and fans the seed into MAIN(0x140D765D8) + stage + per-object
// (+0x2d80). Substituting the seed here forces both peers' round identical. x64: rcx=matchctrl, edx=seed.
static constexpr uintptr_t SEED_SETTER_IDA = 0x14000B350ULL;
typedef void (*seed_setter_fn)(void* matchctrl, uint32_t seed);
static seed_setter_fn orig_setter = nullptr;

static volatile long     g_armed = 0;
static volatile uint32_t g_seed  = 0;
static int  g_delay = 2;
static bool g_hooked = false;
static long g_forced = 0;

static void hk_seed_setter(void* matchctrl, uint32_t seed) {
    // DIAG: log the first calls regardless of armed, to confirm this fn IS hit at match round-start.
    // If we never see this line even after starting a fight, FUN_14000b350 is the wrong seed path for that mode.
    static volatile long s_calls = 0;
    long nc = _InterlockedIncrement(&s_calls);
    if (nc <= 12) {
        bool w = rblog::is_suppressed(); rblog::suppress(false);
        rblog::write("NET-SYNC: seed-setter FUN_14000b350 CALLED #%ld (seed=0x%X armed=%d) — a round-start seed set.", nc, seed, (int)g_armed);
        rblog::suppress(w);
    }
    if (g_armed) {
        uint32_t use = g_seed;
        orig_setter(matchctrl, use);                 // force the shared seed into the round
        g_armed = 0;                                 // one-shot: this round-start is the sync point
        long n = ++g_forced;
        rblog::write("NET-SYNC(%s): FORCED SEED 0x%X at round-start (was 0x%X) — engine broadcast fans it to MAIN+stage+objects; net-frame 0 begins.", role::name(), use, seed);
        net_input::propose_epoch(g_delay);           // PROPOSE, do not act: a round-start is a LOCAL event; the peer may still be in menus.
        (void)n;
        return;
    }
    orig_setter(matchctrl, seed);                     // normal play: untouched
}

void init() {
    if (g_hooked) return;
    void* t = (void*)addr::resolve(SEED_SETTER_IDA);
    if (t && MH_CreateHook(t, (void*)&hk_seed_setter, (void**)&orig_setter) == MH_OK && MH_EnableHook(t) == MH_OK) {
        g_hooked = true;
        rblog::write("NET-SYNC ARMED: hooked seed setter FUN_14000b350 @0x%llX (force-seed match-start; substitutes only when armed).", (unsigned long long)(uintptr_t)t);
    } else {
        rblog::write("NET-SYNC: hook FUN_14000b350 @0x%llX FAILED (t=%p) — force-seed unavailable.", (unsigned long long)(uintptr_t)t, t);
    }
}

void arm(uint32_t seed, int delay) {
    g_seed = seed; g_delay = delay; g_armed = 1;
    net::Packet p{}; p.magic = net::NET_MAGIC; p.type = net::MSG_BEGIN; p.nonce = (uint32_t)delay; p.stamp_ms = seed;
    net::transport_send(p);
    rblog::write("NET-SYNC(%s): ARMED force-seed 0x%X (delay=%d) — sent MSG_BEGIN; next round-start on BOTH peers uses this seed = net-frame 0. Start/restart a round now.", role::name(), seed, delay);
}

void peer_arm(uint32_t seed, int delay) {
    g_seed = seed; g_delay = delay; g_armed = 1;
    rblog::write("NET-SYNC(%s): ARMED force-seed 0x%X (delay=%d, from peer) — next round-start = net-frame 0.", role::name(), seed, delay);
}

bool armed() { return g_armed != 0; }

void report() {
    if (!g_hooked) return;
    rblog::write("NET-SYNC(%s): hooked=%d armed=%d seed=0x%X forced=%ld", role::name(), (int)g_hooked, (int)g_armed, g_seed, g_forced);
}

} // namespace net_sync
