#pragma once
#include <cstdint>
// net_transport.h — lockstep netcode: the UDP wire. A single nonblocking datagram socket +
// the GGPO 7-message-type wire format. No game/state coupling here — pure bytes in/out. Pumped from the game
// loop (hk_main_proc), GGPO-style — no network thread, so it stays on the deterministic main thread.
namespace net {

enum MsgType : uint8_t {
    MSG_SYNC_REQ     = 1,   // handshake: sender's nonce
    MSG_SYNC_REPLY   = 2,   // handshake: echoed nonce
    MSG_INPUT        = 3,   // per-frame input
    MSG_INPUT_ACK    = 4,   // ack highest received input frame
    MSG_QUALITY_REQ  = 5,   // ping: sender ms stamp
    MSG_QUALITY_REPLY= 6,   // pong: echoed stamp => RTT
    MSG_KEEPALIVE    = 7,   // liveness when otherwise idle
    MSG_BEGIN        = 8,   // P1 -> P2: start lockstep now, zero net-frame (nonce field carries the agreed delay)
    MSG_ENGINE_ARM   = 10,  // one-shot, both-peers rollback arm: {stamp_ms = the NET-FRAME to arm on}. Scheduled a
                            // few frames ahead rather than "arm on receipt" so both engines capture their baseline on
                            // the same net-frame — arming at different frames means two different starting states,
                            // which is the one thing a rollback engine must never have. Re-sent while pending so a
                            // dropped datagram cannot leave one side armed and the other not. stamp_ms = 0xFFFFFFFF
                            // is the collective DISARM (F5 again).
    MSG_EPOCH        = 9,   // epoch proposal: {nonce = delay, stamp_ms = proposed epoch}. Sent while inactive too —
                            // that is the point: an input packet cannot carry the proposal that starts the input
                            // stream, so the proposal needs a channel that works before lockstep exists.
};

static constexpr uint32_t NET_MAGIC = 0x33564D55u;   // "UMV3" — reject stray datagrams

#pragma pack(push, 1)
struct Packet {                 // control messages (sync/quality/keepalive) — small, fixed
    uint32_t magic;             // NET_MAGIC
    uint8_t  type;              // MsgType
    uint8_t  _pad[3];
    uint32_t nonce;             // sync req: random; sync reply: echoed
    uint32_t stamp_ms;          // quality req: sender ms; reply echoes it -> RTT
};
#pragma pack(pop)

// Input wire: each MSG_INPUT carries a small sliding window of recent inputs (redundancy) so a dropped datagram
// self-heals without a retransmit round-trip. blobs[i] is the input for frame (start_frame + i).
// WIRE PAYLOAD = the 12-byte raw XINPUT_GAMEPAD per frame (NET_INPUT_SIZE). Two earlier formats were retired: the
// whole 736-byte pad slot (of which ~94% was machine-local state discarded on arrival), then the engine's 44-byte
// derived input window. Both were superseded by presenting raw device state at the XInput seam (net_input.h), which
// also removes the need to scrub machine-specific fields (+0x40 timer, +0x78 counters, +0x140 device map): they are
// derived locally and never travel.
static constexpr int NET_INPUT_SIZE = 12;    // sizeof(XINPUT_GAMEPAD) — raw device state, not the derived window
// Send every unacked frame, not a fixed window. This was 4: each packet carried the last 4 frames and nothing
// else, so a loss burst longer than ~4 packets (~67ms — routine on a relay) dropped those frames PERMANENTLY. The
// peer then predicted them forever and, with no rollback, every one was a lost input. `ack_frame` drives the
// resend: GGPO retransmits from last_acked+1 to newest, so a frame keeps being re-sent until
// the peer confirms it. 32 x 12B = 384B/packet worst case, which is nothing next to losing inputs.
static constexpr int NET_INPUT_REDUNDANCY = 32;      // MAX frames of history per packet (unacked window cap)

#pragma pack(push, 1)
struct InputPacket {
    uint32_t magic;             // NET_MAGIC
    uint8_t  type;              // MSG_INPUT
    uint8_t  count;             // valid blobs [1..NET_INPUT_REDUNDANCY]
    uint8_t  _pad[2];
    // EPOCH — which lockstep timeline these frames belong to. net-frame numbering restarts at 0 every
    // time lockstep (re)activates, so a bare frame number is MEANINGLESS across a restart: peer A at frame 55 of a new
    // epoch and peer B at frame 55,255 of the old one were silently asking each other for different moments in time.
    // Carrying the epoch makes that mismatch detectable instead of silent — a frame is only ever matched within its
    // own epoch, and foreign-epoch input is DISCARDED rather than queued. `want_epoch` is this peer's proposal; both
    // sides converge on max(seen) so no side is the authority (GGPO's sync is symmetric; so is this).
    uint32_t epoch;             // the timeline start_frame/blobs are numbered against
    uint32_t want_epoch;        // this peer's proposed epoch (>= epoch); both adopt the max they have seen
    int32_t  start_frame;       // frame of blobs[0]
    int32_t  ack_frame;         // highest remote input frame we've stored (piggyback ack)
    // CONTROL-SCHEME FINGERPRINT — the button config is a determinism gate: we ship raw device bits, and each
    // engine permutes them through that PAD's config before gameplay sees them. Two peers with different schemes
    // derive different actions from identical wire bytes and desync instantly. This is the local machine's observed
    // permutation, hashed. It rides every input packet rather than a one-shot handshake, so it self-heals after a
    // dropped datagram and catches a scheme edited mid-session. 0 = not yet learned (too few buttons pressed).
    uint32_t cfg_hash;
    // TimeSync frame advantage (GGPO sign: POSITIVE = this peer is BEHIND the other). Each side ships its own
    // measurement and both sides compute the decision from both numbers, so exactly one of them concludes it is the
    // one ahead and slows down. That mutual agreement is what keeps the controller symmetric — neither peer is the
    // authority, and neither can unilaterally decide the other should wait.
    int16_t  frame_adv;
    int16_t  _pad2;
    uint8_t  blobs[NET_INPUT_REDUNDANCY][NET_INPUT_SIZE];
};
#pragma pack(pop)

static constexpr int NET_MAX_PACKET = (int)sizeof(InputPacket);   // largest datagram we send/recv

bool transport_open(uint16_t local_port, const char* remote_ip, uint16_t remote_port);
void transport_close();
bool transport_send(const Packet& p);              // control-message convenience wrapper
bool transport_send_raw(const void* buf, int len); // send an arbitrary datagram (input/state packets)
int  transport_recv_raw(void* buf, int cap);       // bytes received (>0), 0 = none, -1 = error; caller checks magic/type
uint32_t now_ms();                                 // QPC-based monotonic ms (fine resolution for RTT/timesync)

// Hole-punch: the box hands each game the OTHER's public addr (MVCLP). Calling this makes every send
// also fire at the peer directly (opening the NAT pinhole), while the primary send still rides the relay so the match
// stays connected meanwhile. The first datagram received from the peer's addr flips us to DIRECT — from then on sends
// go peer-only and the relay leaves the gameplay path. Idempotent; a fresh addr re-arms the punch.
void transport_set_peer(const char* peer_ip, uint16_t peer_port);
bool transport_is_direct();                        // true once a datagram has arrived straight from the peer

} // namespace net
