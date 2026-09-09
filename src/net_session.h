#pragma once
#include <cstdint>
// net_session.h — lockstep netcode: the connection state machine over net_transport.
// Disconnected -> Syncing (5 nonce round-trips) -> Running (keepalive 200ms + quality/RTT 1000ms + timeouts).
// Connection only; input and rollback live in net_input / resim. Armed by a netplay.flag file next to the exe, so
// solo runs never touch the network. Ports are role-driven: P1 binds 7100<->7101, P2 binds 7101<->7100
// (127.0.0.1 loopback by default; netplay.cfg overrides).
namespace net {
void session_init();      // resolve role -> ports, arm if netplay.flag present, begin handshake
void session_pump();      // per-frame (hk_main_proc, main thread): drain packets + state machine + periodic sends
bool session_running();   // true once the handshake completed (the input exchange gates on this)
bool session_armed();     // true once armed (netplay.flag present + transport open), regardless of handshake state — the boot-stall gate
void session_report();    // throttled state/RTT line (heartbeat)
// The hold must release by MUTUAL agreement, never locally. session_running() is one side's opinion: if our
// handshake completes and the peer's does not, we start playing while they are still frozen at the title — measured
// in a real session as one game releasing a full MINUTE before the other, which desyncs them from frame 0 even if
// the link later recovers. MSG_KEEPALIVE is only ever emitted from the RUNNING state, so receiving one is PROOF the
// peer finished syncing. Release only when both sides are provably up.
bool session_both_running();

uint32_t session_rtt_ms();   // last measured round trip (TimeSync needs it to estimate the peer's frame)
}
