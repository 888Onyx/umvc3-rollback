// net_engine_arm.cpp — see net_engine_arm.h.
#include "net_engine_arm.h"
#include "net_transport.h"
#include "net_input.h"
#include "net_session.h"
#include "role.h"
#include "log.h"
#include <cstring>

namespace net_engine_arm {
namespace {

// Frames of lead time between proposing an arm and performing it. Must comfortably exceed the input delay so the
// proposal lands before the frame it names; 12 frames (~0.2s) covers a relayed link and is imperceptible against a
// human pressing a key.
constexpr int  ARM_LEAD_FRAMES = 12;   // ~0.2s: long enough to cross a relayed link, short enough to feel instant
constexpr uint32_t RESEND_MS   = 100;

static bool     g_armed   = false;      // set on the agreed frame; cleared by consume_disarm()
static bool     g_pending = false;
static int      g_target  = -1;
static uint32_t g_last_send_ms = 0;
static bool     g_disarm_req  = false;   // a disarm to perform locally
constexpr uint32_t DISARM_STAMP = 0xFFFFFFFFu;   // sentinel in stamp_ms: "drop the engine now"

static void send_proposal() {
    net::Packet p{};
    p.magic = net::NET_MAGIC;
    p.type  = net::MSG_ENGINE_ARM;
    p.nonce = 0;
    p.stamp_ms = (uint32_t)g_target;    // the agreed net-frame
    net::transport_send(p);
    g_last_send_ms = net::now_ms();
}

} // namespace

void propose() {
    if (g_armed) return;
    // A pending proposal must never SWALLOW a press. If one is already in flight, re-assert it immediately instead of
    // ignoring the player: the common case for a second press is "the first one did not appear to do anything", and
    // silently dropping it is the worst possible response to that.
    if (g_pending) { send_proposal(); rblog::write("ENGINE-ARM(%s): arm already pending for net-frame %d — re-sent.",
                                                   role::name(), g_target); return; }
    if (!net::session_running()) {
        // Solo: there is nobody to agree with, so arm on the very next tick. pending() is what the caller polls.
        g_target  = -1;
        g_pending = true;
        rblog::write("ENGINE-ARM(%s): F5 with no live session — arming locally on the next frame (solo).", role::name());
        return;
    }
    g_target  = net_input::net_frame() + ARM_LEAD_FRAMES;
    g_pending = true;
    send_proposal();
    rblog::write("ENGINE-ARM(%s): proposed — BOTH engines arm on net-frame %d (in %d frames). One press arms both "
                 "peers.", role::name(), g_target, ARM_LEAD_FRAMES);
}

void on_peer_propose(uint32_t target_frame) {
    if (g_armed) return;
    const int t = (int)target_frame;
    // Adopt the EARLIEST proposal seen. If both players press F5 at once we must converge on one frame, and taking
    // the earlier one is deterministic on both sides regardless of which datagram arrived first.
    if (g_pending && g_target <= t) { if (net::now_ms() - g_last_send_ms >= RESEND_MS) send_proposal(); return; }
    g_target  = t;
    g_pending = true;
    rblog::write("ENGINE-ARM(%s): peer proposed the arm — BOTH engines arm on net-frame %d. Adopted; re-asserting so "
                 "a dropped datagram cannot leave us out of step.", role::name(), g_target);
    send_proposal();
}

bool tick_should_arm() {
    if (g_armed || !g_pending) return false;
    // Keep re-sending until the frame lands: the peer must not miss this.
    if (net::now_ms() - g_last_send_ms >= RESEND_MS) send_proposal();

    const int now = net_input::net_frame();
    if (g_target >= 0 && now < g_target) return false;      // g_target<0 == solo: arm immediately
    g_pending = false;
    g_armed   = true;
    if (now > g_target)
        rblog::write("ENGINE-ARM(%s): arm frame %d already passed (now %d) — arming immediately. The two baselines "
                     "may be up to %d frames apart; that is a divergence risk worth knowing about.",
                     role::name(), g_target, now, now - g_target);
    else
        rblog::write("ENGINE-ARM(%s): ARMING NOW on net-frame %d — both peers, same frame.", role::name(), g_target);
    return true;
}

void propose_disarm() {
    if (!g_armed && !g_pending) return;
    g_pending = false;
    g_disarm_req = true;                       // perform locally on the next tick
    if (net::session_running()) {
        net::Packet p{};
        p.magic = net::NET_MAGIC; p.type = net::MSG_ENGINE_ARM; p.nonce = 0; p.stamp_ms = DISARM_STAMP;
        net::transport_send(p);
    }
    rblog::write("ENGINE-ARM(%s): DISARM requested — both peers drop the engine. F5 again to re-arm.", role::name());
}

void on_peer_disarm() {
    if (!g_armed && !g_pending) return;
    g_pending = false;
    g_disarm_req = true;
    rblog::write("ENGINE-ARM(%s): peer disarmed — dropping the engine here too so we never run it one-sided.", role::name());
}

bool consume_disarm() {
    if (!g_disarm_req) return false;
    g_disarm_req = false;
    g_armed = false;                           // re-armable: the latch is gone
    return true;
}

bool armed()   { return g_armed; }
bool pending() { return g_pending; }

void report() {
    if (!net::session_armed()) return;
    rblog::write("ENGINE-ARM(%s): armed=%d pending=%d target=%d (one F5 arms both; F5 again disarms both)",
                 role::name(), (int)g_armed, (int)g_pending, g_target);
}

} // namespace net_engine_arm
