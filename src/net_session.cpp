// net_session.cpp — see net_session.h.
#include "net_session.h"
#include "net_transport.h"
#include "net_input.h"
#include "net_engine_arm.h"
#include "net_sync.h"
#include "net_config.h"
#include "role.h"
#include "log.h"
#include <windows.h>
#include <cstring>
#include <cstdio>
#include <cstdlib>

namespace net {

enum State { DISCONNECTED, SYNCING, RUNNING };
static State    g_state = DISCONNECTED;
static bool     g_armed = false;
static uint32_t g_sync_nonce = 0;
static int      g_sync_ok = 0;
static uint32_t g_last_recv_ms = 0;
static uint32_t g_last_send_ms = 0;   // last sync/keepalive send
static uint32_t g_last_qr_ms   = 0;   // last quality-request send
// Measure RTT during the handshake, not after it.
// g_rtt_ms used to come only from MSG_QUALITY_REQ, which starts after the session reaches RUNNING. But the epoch —
// and with it the input delay — is decided the instant sync completes, so every delay calculation saw rtt=0 and fell
// back to the LAN default of 2 frames. On an 84ms link that guarantees the peer's input lands after the frame it
// belongs to and every button gets predicted away. The handshake is FIVE round trips; time them and the number is
// ready exactly when it is needed. Keep the best (lowest) sample: the minimum is the honest floor of the path.
static uint32_t g_sync_req_ms  = 0;
static uint32_t g_rtt_ms = 0;
static bool     g_interrupted = false;
static bool     g_peer_running = false;   // peer proved it reached RUNNING (only that state emits keepalive/input)
static bool     g_relay_mode = false;         // matchmaker: g_remote is the box, not the peer
static char     g_relay_code[32] = "";        // session code the relay routes by
static uint32_t g_last_hello_ms = 0;

static constexpr int      NUM_SYNC     = 5;
static constexpr uint32_t SYNC_RETRY_MS= 500;
static constexpr uint32_t KEEPALIVE_MS = 200;
static constexpr uint32_t QUALITY_MS   = 1000;
static constexpr uint32_t INTERRUPT_MS = 2000;
static constexpr uint32_t DISCONNECT_MS= 6000;
static constexpr uint32_t HELLO_MS     = 1000;   // re-assert relay mapping (survives datagram drop + NAT rebind)

static uint32_t make_nonce() {
    LARGE_INTEGER q; QueryPerformanceCounter(&q);
    return (uint32_t)(q.QuadPart ^ (uint64_t)(GetCurrentThreadId() * 2654435761u)) | 1u;   // never 0
}

static bool flag_present() {
    char path[MAX_PATH]; GetModuleFileNameA(NULL, path, MAX_PATH);
    char* slash = strrchr(path, '\\'); if (slash) slash[1] = 0; else path[0] = 0;
    strncat(path, "netplay.flag", MAX_PATH - strlen(path) - 1);
    return GetFileAttributesA(path) != INVALID_FILE_ATTRIBUTES;
}

static void send_pkt(uint8_t type, uint32_t nonce, uint32_t stamp) {
    Packet p{}; p.magic = NET_MAGIC; p.type = type; p.nonce = nonce; p.stamp_ms = stamp;
    transport_send(p);
}

// matchmaker/relay mode: with mode=matchmaker the game doesn't dial the peer — it dials the 24/7 box (g_remote =
// relay) and the box forwards each datagram to the other role in this session. The box only learns which socket is
// which from this HELLO ("MVCL" + {session,role}), keyed on the source addr it arrives from. We re-send it on a timer
// (session_pump) so a dropped HELLO or a NAT rebind self-heals — the mapping is continuously re-asserted, never
// assumed durable. The box's "MVCLOK" ack fails the NET_MAGIC check in session_pump and is harmlessly ignored.
static void send_hello() {
    if (!g_relay_mode) return;
    char buf[96];
    int n = snprintf(buf, sizeof(buf), "MVCL{\"session\":\"%s\",\"role\":\"%s\"}",
                     g_relay_code, role::is_p2() ? "P2" : "P1");
    if (n > 0) transport_send_raw(buf, n);
}

// hole-punch: the box answers our HELLO (once both roles are present) with MVCLP + {"ip","port"} = the other game's
// public addr. Hand it to the transport, which starts punching straight at the peer while the relay keeps carrying the
// match until a direct packet lands. Minimal hand-parse (no JSON lib in the DLL) — the box emits exactly this shape.
static void on_peer_info(const uint8_t* buf, int n) {
    if (n <= 5 || n > 250) return;
    char js[256]; int len = n - 5;
    memcpy(js, buf + 5, len); js[len] = 0;
    const char* p = strstr(js, "\"ip\":\"");
    const char* q = strstr(js, "\"port\":");
    if (!p || !q) return;
    p += 6; char ip[64] = ""; int i = 0;
    while (*p && *p != '"' && i < (int)sizeof(ip) - 1) ip[i++] = *p++;
    ip[i] = 0;
    int port = atoi(q + 7);
    if (ip[0] && port > 0 && port < 65536) transport_set_peer(ip, (uint16_t)port);
}

void session_init() {
    if (!flag_present()) { rblog::write("NET: netplay.flag absent — networking DISARMED (solo run)."); return; }

    // config-driven: the launcher writes netplay.cfg (peer/relay addr + ports). Absent cfg = legacy
    // loopback so two-instances-on-one-PC still works. role stays from role:: (UMVC3_ROLLBACK_ROLE env).
    const net_config::Config& cfg = net_config::get();
    uint16_t local  = role::is_p2() ? 7101 : 7100;   // loopback defaults
    uint16_t remote = role::is_p2() ? 7100 : 7101;
    const char* peer_ip = "127.0.0.1";
    if (cfg.present) {
        if (cfg.local_port) local = cfg.local_port;
        if (cfg.peer_port)  remote = cfg.peer_port;
        if (cfg.peer_ip[0]) peer_ip = cfg.peer_ip;      // direct mode
    }

    // matchmaker/relay: dial the box, not the peer. The local bind port is irrelevant here — the box learns our
    // address from the HELLO, not from a fixed port — so bind ephemeral (0). That also makes relay mode bind-conflict-
    // proof (even two instances on one box get distinct OS-assigned ports). Missing relay fields => misconfigured, bail.
    if (cfg.present && strcmp(cfg.mode, "matchmaker") == 0) {
        if (!(cfg.relay_ip[0] && cfg.relay_port)) {
            rblog::write("NET: mode=matchmaker but relay_ip/port missing in netplay.cfg — disarmed.");
            return;
        }
        local   = 0;
        peer_ip = cfg.relay_ip;
        remote  = cfg.relay_port;
        g_relay_mode = true;
        strncpy(g_relay_code, cfg.code, sizeof(g_relay_code) - 1);
        g_relay_code[sizeof(g_relay_code) - 1] = 0;
    }

    if (!transport_open(local, peer_ip, remote)) { rblog::write("NET: transport open FAILED — disarmed."); return; }
    g_armed = true;
    g_state = SYNCING;
    g_sync_ok = 0;
    g_sync_nonce = make_nonce();
    g_last_recv_ms = g_last_send_ms = now_ms();
    send_hello();                     // register with the box first so it can forward our sync traffic to the peer
    g_last_hello_ms = now_ms();
    g_sync_req_ms = now_ms();
    send_pkt(MSG_SYNC_REQ, g_sync_nonce, 0);
    if (g_relay_mode)
        rblog::write("NET(%s): ARMED — SYNCING via RELAY %s:%u (code=%s, nonce=0x%X, need %d replies).",
                     role::name(), peer_ip, remote, g_relay_code, g_sync_nonce, NUM_SYNC);
    else
        rblog::write("NET(%s): ARMED — SYNCING (local %u -> %s:%u, nonce=0x%X, need %d replies).",
                     role::name(), local, peer_ip, remote, g_sync_nonce, NUM_SYNC);
}

void session_pump() {
    if (!g_armed) return;
    uint32_t t = now_ms();

    // keep the relay's addr->session mapping fresh (drop/NAT-rebind self-heal); no-op in direct/loopback mode.
    if (g_relay_mode && t - g_last_hello_ms >= HELLO_MS) { send_hello(); g_last_hello_ms = t; }

    static uint8_t buf[NET_MAX_PACKET];
    int n;
    while ((n = transport_recv_raw(buf, sizeof(buf))) > 0) {
        if (n < (int)sizeof(uint32_t) + 1) continue;                 // too small for magic+type
        if (g_relay_mode && n >= 5 && memcmp(buf, "MVCLP", 5) == 0) { on_peer_info(buf, n); continue; }  // box: peer addr for punch
        if (*(uint32_t*)buf != NET_MAGIC) continue;                  // foreign datagram (incl. the box's MVCLOK ack)
        uint8_t type = buf[4];
        g_last_recv_ms = t;
        if (g_interrupted) { g_interrupted = false; rblog::write("NET(%s): connection RESUMED.", role::name()); }
        // input path: route MSG_INPUT to the lockstep queue; keep control messages below
        if (type == MSG_INPUT || type == MSG_KEEPALIVE) {
            if (!g_peer_running) {
                g_peer_running = true;
                rblog::write("NET(%s): peer is RUNNING — both sides synced, releasing the title hold together.", role::name());
            }
        }
        if (type == MSG_INPUT) { net_input::on_recv_input(buf, n); continue; }
        if (type == MSG_BEGIN) { const Packet* bp = (const Packet*)buf; net_sync::peer_arm(bp->stamp_ms, (int)bp->nonce); continue; }
        if (type == MSG_ENGINE_ARM) {
            const Packet* ap = (const Packet*)buf;
            if (ap->stamp_ms == 0xFFFFFFFFu) net_engine_arm::on_peer_disarm();
            else                             net_engine_arm::on_peer_propose(ap->stamp_ms);
            continue;
        }
        if (type == MSG_EPOCH) { const Packet* ep = (const Packet*)buf; net_input::on_peer_epoch(ep->stamp_ms, (int)ep->nonce); continue; }   // {stamp_ms=epoch, nonce=delay}
        const Packet& in = *(const Packet*)buf;
        switch (in.type) {
        case MSG_SYNC_REQ:
            send_pkt(MSG_SYNC_REPLY, in.nonce, 0);   // echo their nonce so they can count us
            break;
        case MSG_SYNC_REPLY:
            if (g_state == SYNCING && in.nonce == g_sync_nonce) {
                if (g_sync_req_ms) {                     // this reply closes a round trip we timed
                    const uint32_t sample = t - g_sync_req_ms;
                    if (!g_rtt_ms || sample < g_rtt_ms) g_rtt_ms = sample;
                }
                if (++g_sync_ok >= NUM_SYNC) {
                    rblog::write("NET(%s): handshake RTT = %ums (measured across the sync round trips, so the input "
                                 "delay can be sized before the first frame).", role::name(), g_rtt_ms);
                    g_state = RUNNING; g_last_qr_ms = t;
                    rblog::write("NET(%s): SYNC COMPLETE — RUNNING (%d/%d replies matched).", role::name(), g_sync_ok, NUM_SYNC);
                    // AUTO-ARM force-seed on connect (no manual key): the host picks the shared seed and sends it;
                    // the next round-start on both peers force-seeds + begins lockstep automatically. The launcher/
                    // netcode handles sync — the player never presses a "sync" button.
                    if (!role::is_p2()) {
                        LARGE_INTEGER q; QueryPerformanceCounter(&q);
                        net_sync::arm((uint32_t)q.QuadPart | 1u, 2);
                        rblog::write("NET(%s): host AUTO-ARMED force-seed on connect — next round-start begins lockstep.", role::name());
                    }
                } else {
                    g_sync_nonce = make_nonce();               // fresh nonce per round
                    g_sync_req_ms = t;
                    send_pkt(MSG_SYNC_REQ, g_sync_nonce, 0);
                    g_last_send_ms = t;
                }
            }
            break;
        case MSG_QUALITY_REQ:
            send_pkt(MSG_QUALITY_REPLY, 0, in.stamp_ms);       // echo their stamp
            break;
        case MSG_QUALITY_REPLY:
            {   // Smooth the RTT. A single spike (252ms and 416ms both observed on the relay) was being taken at
                // face value and used to size the input delay — which then rides a new EPOCH, resetting the timeline
                // for a hiccup that lasted one packet. Keep a rolling minimum over the last few samples: the minimum
                // is the honest floor of the path, and a transient spike cannot drag it.
                const uint32_t sample = t - in.stamp_ms;
                static uint32_t ring[8] = {0}; static int n = 0;
                ring[n++ % 8] = sample;
                uint32_t lo = 0;
                for (int i = 0; i < 8; i++) if (ring[i] && (!lo || ring[i] < lo)) lo = ring[i];
                g_rtt_ms = lo ? lo : sample;
            }
            break;
        case MSG_KEEPALIVE: default:
            break;                                             // INPUT/INPUT_ACK arrive with the input exchange
        }
    }

    if (g_state == SYNCING) {
        if (t - g_last_send_ms >= SYNC_RETRY_MS) { g_sync_req_ms = t; send_pkt(MSG_SYNC_REQ, g_sync_nonce, 0); g_last_send_ms = t; }
    } else if (g_state == RUNNING) {
        if (t - g_last_send_ms >= KEEPALIVE_MS) { send_pkt(MSG_KEEPALIVE, 0, 0); g_last_send_ms = t; }
        if (t - g_last_qr_ms   >= QUALITY_MS)   { send_pkt(MSG_QUALITY_REQ, 0, now_ms()); g_last_qr_ms = t; }
        uint32_t idle = t - g_last_recv_ms;
        if (!g_interrupted && idle >= INTERRUPT_MS) { g_interrupted = true; rblog::write("NET(%s): INTERRUPTED (%ums silent).", role::name(), idle); }
        if (idle >= DISCONNECT_MS) {
            rblog::write("NET(%s): DISCONNECTED (%ums silent) — session down.", role::name(), idle);
            g_state = DISCONNECTED; g_armed = false; g_peer_running = false; transport_close();
        }
    }
}

uint32_t session_rtt_ms() { return g_rtt_ms; }

bool session_both_running() { return session_running() && g_peer_running; }

bool session_running() { return g_armed && g_state == RUNNING; }
bool session_armed()   { return g_armed; }

void session_report() {
    if (!g_armed) return;
    const char* s = (g_state == RUNNING) ? "RUNNING" : (g_state == SYNCING) ? "SYNCING" : "DISCONNECTED";
    rblog::write("NET(%s): state=%s rtt=%ums sync=%d/%d idle=%ums", role::name(), s, g_rtt_ms, g_sync_ok, NUM_SYNC, now_ms() - g_last_recv_ms);
}

} // namespace net
