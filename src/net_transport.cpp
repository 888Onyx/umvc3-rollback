// net_transport.cpp — see net_transport.h. Winsock2 UDP, nonblocking. WIN32_LEAN_AND_MEAN (build-wide) keeps
// windows.h from pulling the old winsock.h, so including winsock2.h first is conflict-free.
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include "net_transport.h"
#include "log.h"
#include "net_charsel.h"
#include "net_engine_arm.h"

namespace net {

static SOCKET      g_sock  = INVALID_SOCKET;
static sockaddr_in g_relay{};                 // the box: relay fallback + (in matchmaker mode) where HELLOs go
static sockaddr_in g_peer{};                  // direct peer, learned from the box's MVCLP (hole-punch target)
static bool        g_have_peer = false;       // we know the peer's public addr and are punching
static bool        g_direct    = false;       // a datagram has arrived straight from the peer -> go peer-only
static bool        g_wsa   = false;

uint32_t now_ms() {
    static LARGE_INTEGER f{};
    if (!f.QuadPart) QueryPerformanceFrequency(&f);
    LARGE_INTEGER c; QueryPerformanceCounter(&c);
    return (uint32_t)((c.QuadPart * 1000) / f.QuadPart);
}

static inline bool addr_eq(const sockaddr_in& a, const sockaddr_in& b) {
    return a.sin_addr.s_addr == b.sin_addr.s_addr && a.sin_port == b.sin_port;
}

bool transport_open(uint16_t local_port, const char* remote_ip, uint16_t remote_port) {
    if (!g_wsa) {
        WSADATA w;
        if (WSAStartup(MAKEWORD(2, 2), &w) != 0) { rblog::write("NET: WSAStartup failed (%d)", WSAGetLastError()); return false; }
        g_wsa = true;
    }
    g_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (g_sock == INVALID_SOCKET) { rblog::write("NET: socket() failed (%d)", WSAGetLastError()); return false; }

    sockaddr_in local{};
    local.sin_family = AF_INET;
    local.sin_addr.s_addr = htonl(INADDR_ANY);
    local.sin_port = htons(local_port);
    if (bind(g_sock, (sockaddr*)&local, sizeof(local)) == SOCKET_ERROR) {
        rblog::write("NET: bind(%u) failed (%d)", local_port, WSAGetLastError());
        closesocket(g_sock); g_sock = INVALID_SOCKET; return false;
    }
    u_long nb = 1; ioctlsocket(g_sock, FIONBIO, &nb);   // nonblocking

    g_relay.sin_family = AF_INET;
    g_relay.sin_port   = htons(remote_port);
    inet_pton(AF_INET, remote_ip, &g_relay.sin_addr);
    g_have_peer = false; g_direct = false;

    rblog::write("NET: transport open — bind %u <-> %s:%u (UDP, nonblocking).", local_port, remote_ip, remote_port);
    return true;
}

void transport_close() {
    if (g_sock != INVALID_SOCKET) { closesocket(g_sock); g_sock = INVALID_SOCKET; }
    g_have_peer = false; g_direct = false;
}

void transport_set_peer(const char* peer_ip, uint16_t peer_port) {
    sockaddr_in p{};
    p.sin_family = AF_INET;
    p.sin_port   = htons(peer_port);
    if (inet_pton(AF_INET, peer_ip, &p.sin_addr) != 1) { rblog::write("NET: MVCLP bad peer ip '%s'", peer_ip); return; }
    if (g_have_peer && addr_eq(g_peer, p)) return;      // same peer — nothing to re-arm
    g_peer = p; g_have_peer = true; g_direct = false;
    rblog::write("NET: peer addr %s:%u learned from box — PUNCHING (relay stays as fallback until direct).", peer_ip, peer_port);
}

bool transport_is_direct() { return g_direct; }

// Direct is a preference, not a latch.
// The old rule was: receive one packet from the peer's address, set g_direct forever, stop relaying. That treats
// evidence about the peer->us direction as proof about us->peer, and those are independent through NAT. If our punch
// reaches them but theirs does not reach us (or the reverse), we abandon the one path that was working and strand a
// one-way connection: SYNC needs five round TRIPS, so it never completes and both games sit held at the title with
// one side unable to send. The relay saw exactly this: one side silent while the other kept relaying.
// Now: direct only counts while it is DEMONSTRABLY still delivering. If nothing arrives direct for DIRECT_STALE_MS we
// silently resume relaying (and keep punching), so a half-open path can never strand the match. Cost of being wrong
// in the safe direction is one duplicated 76-byte datagram per frame — about 4.5 KB/s. Cost of being wrong in the
// other direction is a session that can never connect.
static constexpr uint32_t DIRECT_STALE_MS = 1000;
static uint32_t g_last_direct_ms = 0;

// Relay-only while rollback is off.
// The hole-punch buys latency but costs determinism of behaviour: it can succeed one way, succeed then die, or land
// mid-session and change the timing under us. With no rollback to absorb a hiccup, every one of those becomes lost
// input rather than a corrected frame. The relay is one predictable path with one predictable RTT, which is exactly
// what a fixed input delay needs to be sized against. Punching comes back when rollback can pay for its variance.
// Drop `direct.off` beside the exe to force this even once direct is re-enabled; `direct.on` re-enables punching.
static int s_allow_direct = -1;
static bool allow_direct() {
    if (s_allow_direct < 0) {
        char p[MAX_PATH]; GetModuleFileNameA(NULL, p, MAX_PATH);
        char* sl = strrchr(p, '\\'); if (sl) sl[1] = 0; else p[0] = 0;
        char on[MAX_PATH]; strcpy(on, p); strncat(on, "direct.on", MAX_PATH - strlen(on) - 1);
        s_allow_direct = (GetFileAttributesA(on) != INVALID_FILE_ATTRIBUTES) ? 1 : 0;
        rblog::write("NET: peer-to-peer punching %s — %s.", s_allow_direct ? "ENABLED (direct.on present)" : "DISABLED",
                     s_allow_direct ? "direct path will be used once it proves itself"
                                    : "RELAY ONLY: one path, one stable RTT, which is what a fixed input delay needs "
                                      "while there is no rollback to absorb timing variance");
    }
    if (s_allow_direct == 1) return true;
    // The ON-SWITCH: relay through the menus (one stable path, one stable RTT, which the fixed delay is sized
    // against), then punch once the FIGHT starts — that is where the latency actually matters and where the rollback
    // engine is armed to absorb the timing change. The relay is not dropped: direct only takes over once it proves
    // itself delivering, and falls back automatically if it goes quiet (see direct_is_live).
    // Punch when the rollback engine is armed. This used to key off game-flow phase (8=intro / 5=round), which is
    // measurably useless: the same field reads 5 sitting in CHARACTER SELECT during solo play and 0 while fully in a
    // netplay match. Gating on it meant the punch never once engaged — which is exactly why everything stayed on the
    // relay. F5 is the one signal that reliably means "we are in a match", because a human decided it: it already
    // arms the engine on both peers, so let it enable direct on both peers at the same moment.
    return net_engine_arm::armed();
}

static bool direct_is_live() {
    if (!allow_direct()) return false;
    if (!g_direct) return false;
    if ((uint32_t)(now_ms() - g_last_direct_ms) < DIRECT_STALE_MS) return true;
    g_direct = false;                                  // demote, keep punching, resume relay
    rblog::write("NET: direct path went quiet (>%ums) — falling BACK to the relay and continuing to punch. "
                 "A half-open punch must never strand the session.", DIRECT_STALE_MS);
    return false;
}

bool transport_send_raw(const void* buf, int len) {
    if (g_sock == INVALID_SOCKET) return false;
    const bool live = direct_is_live();
    // Always reach the peer by every path we currently believe in. Until direct has proven itself bidirectional we
    // send both ways; the duplicate is harmless (the receiver de-dupes by frame) and it keeps the match connected
    // through the entire punch attempt instead of betting the session on one inbound datagram.
    int n = len;
    if (!live) n = sendto(g_sock, (const char*)buf, len, 0, (sockaddr*)&g_relay, sizeof(g_relay));
    if (g_have_peer && allow_direct())
        sendto(g_sock, (const char*)buf, len, 0, (sockaddr*)&g_peer, sizeof(g_peer));
    return n == len;
}

bool transport_send(const Packet& p) { return transport_send_raw(&p, sizeof(p)); }

int transport_recv_raw(void* buf, int cap) {
    if (g_sock == INVALID_SOCKET) return -1;
    sockaddr_in from{}; int flen = sizeof(from);
    int n = recvfrom(g_sock, (char*)buf, cap, 0, (sockaddr*)&from, &flen);
    if (n > 0) {
        // first packet straight from the peer's addr => the punch landed; leave the relay behind
        if (g_have_peer && allow_direct() && addr_eq(from, g_peer)) {
            g_last_direct_ms = now_ms();               // freshness stamp: direct is only trusted while it delivers
            if (!g_direct) {
                g_direct = true;
                rblog::write("NET: DIRECT P2P established — match traffic peer-to-peer. The relay stays warm and we "
                             "fall back automatically if this path stops delivering.");
            }
        }
        return n;
    }
    if (n == SOCKET_ERROR) { return (WSAGetLastError() == WSAEWOULDBLOCK) ? 0 : -1; }
    return 0;
}

} // namespace net
