// net_input.cpp — see net_input.h.
#include "net_input.h"
#include "net_transport.h"
#include "input.h"
#include "dinput_probe.h"
#include "resim.h"
#include "net_engine_arm.h"
#include "net_session.h"
#include "role.h"
#include "log.h"
#include <windows.h>
#include <cstring>
#include <cstdio>

namespace net_input {

static constexpr int RING = 256;                 // power of two; >> any sane delay
// BLOB = the raw DEVICE STATE, not the engine's derived window.
// Was 44 bytes (11 derived u32 at padSlot+0x1BC). Now 12 = sizeof(XINPUT_GAMEPAD): wButtons, bLeft/RightTrigger,
// and the four thumb axes. Every byte we ship is now a byte we MEAN — the engine re-derives held/prev/press-edge/
// release/changed/repeat itself. Prediction also becomes structurally safe: repeating the last remote gamepad is
// Correct under XInput semantics (a held button legitimately repeats), and because the engine derives edges from
// its own history, a repeated level can no longer manufacture a phantom press. That was the whole original bug.
static constexpr int BLOB = 12;
// The rest of the 0x2E0 pad slot is a C++ object (vtable @+0/+0x58/+0x1F0, pointers, machine scalars) and must
// never cross processes — writing it from the remote once put the remote's vtable into the local object (null-vtable
// tick crash 0x1402595BD). Only the 12 raw bytes travel; the engine re-derives SOCD-cleaned directions and the
// command history from them. (Geometry lives in input.h for the diagnostics that still read it.)
// The queue blob, the presented state, and the wire payload are the same bytes. If any one of them drifts the
// others silently corrupt (short memcpy / mis-framed packet), so bind them at compile time rather than by comment.
static_assert(BLOB == net::NET_INPUT_SIZE,     "wire payload must be exactly the raw gamepad state");

struct QEntry { int frame; bool valid; uint8_t blob[BLOB]; };
static QEntry g_local[RING];
static QEntry g_remote[RING];
static uint8_t g_neutral[BLOB];
// last-served blob per side — the repeat-last-input prediction state (reset per match in activate())
// engine-frame -> net-frame. The two counters are independent (do_rollback speaks engine frames, the netcode speaks
// net frames), so a replay of engine frame E has to be translated before its input can be looked up.
static int     g_net_for_engine[RING];
static bool    g_efmap_ready = false;
static uint8_t g_present[2][BLOB];
static bool     g_present_valid = false;
static uint8_t g_last_local[BLOB];
static uint8_t g_last_remote[BLOB];                  // zeroed = the neutral input (also the pre-seed value)

// PREDICTION LEDGER — GGPO never waits for a late input; it predicts, advances, and rolls back when
// the guess turns out wrong. We already predict (repeat-last-input above) but we have never measured the guess, so we
// do not know how often it is wrong or how deep a corrective rollback would have to be. Without that number, wiring a
// rollback trigger is guesswork. This ledger is read-only: for every frame we serve a predicted remote input we keep
// the prediction, and when the real input arrives we compare. `mispredicts` is the rollback rate we would have paid;
// `maxdepth` is how far back the deepest correction would have reached.
static uint8_t  g_pred[RING][BLOB];
static bool     g_was_pred[RING];
static long     g_pred_used = 0, g_pred_wrong = 0, g_pred_depth_max = 0;

// EPOCH — see net_transport.h. g_epoch is the timeline we are numbering frames against; g_want is our proposal.
// Both peers converge on the MAX of the two, so neither is an authority and a lost proposal simply retries (it rides
// every input packet). Frame 0 therefore becomes an AGREEMENT rather than a local side effect.
static uint32_t g_epoch = 0;
static uint32_t g_want  = 0;
static uint32_t g_last_activate_ms = 0;                     // for the proposal debounce below
static constexpr uint32_t EPOCH_DEBOUNCE_MS = 2000;         // both match-start triggers land well inside this

static int  g_delay = 2;
static int  g_net_frame = 0;
static bool g_active = false;
static int  g_last_captured = -1;
static int  g_remote_high = -1;                  // highest remote frame stored (piggyback ack)
static long g_stalls = 0, g_sent = 0, g_recv = 0;
static int  g_peer_acked = -1;   // highest frame the PEER has confirmed receiving (from their ack_frame)

// TIMESYNC — the drift controller (GGPO timesync.cpp, adapted)
// Measured on the twin rig: one peer runs ~59.6fps and the other ~59.1, so the faster one steadily outruns its
// confirmed input, slams into the prediction barrier and burns thousands of Sleep(1) calls holding position. The
// barrier bounds the damage but is a wall, not a controller — it corrects after the fact, every single frame.
// TimeSync makes the faster peer give back a few frames voluntarily, so it never reaches the wall at all.
// Sign convention is GGPO's: advantage = estimated_remote_frame - local_frame, so POSITIVE means WE are BEHIND.
// Both peers exchange their own figure and both evaluate the same comparison; only the one that is ahead sleeps.
static constexpr int TS_RING = 40;      // ~2/3 of a second — long enough that jitter cannot trigger a correction
// Tuned for a relay, not a LAN. GGPO's 3-frame minimum and 240-frame cooldown assume a stable direct
// link where drift accumulates slowly. Measured here: one correction in 160 seconds while sitting 6 frames ahead of
// the peer — the drift re-accumulates far faster than a nudge every 4 seconds can remove it, and 6 frames of drift
// is exactly what makes the input delay break even instead of comfortable. Correct sooner and more often.
static constexpr int TS_MIN  = 2;       // a 2-frame lead already costs prediction at these delays
static constexpr int TS_MAX  = 9;       // never give back more than this at once
static int  g_ts_local[TS_RING];
static int  g_ts_remote[TS_RING];
static int  g_ts_n = 0;
static int  g_peer_adv = 0;
static long g_ts_corrections = 0, g_ts_frames_given = 0;

static inline int idx(int f) { return ((f % RING) + RING) % RING; }

// Window field map (measured with netplay disarmed): w[0]=held now, w[1]=held last frame, w[2]=press edge
// (w0&~w1), w[3]=release edge, w[4]=changed, w[5]=repeat. Under the earlier derived-window scheme, repeating a blob
// re-fired an edge on every predicted frame (the receiving side predicts almost continuously when it runs ahead),
// so the game saw a new press 60 times a second and the menu cursor flew while rendering a steady 60fps. Raw device
// state has no edge field, so that class is gone.
static uint8_t g_pred_local_buf[BLOB];
static uint8_t g_pred_remote_buf[BLOB];
// PREDICTION = REPEAT the last GAMEPAD, VERBATIM. The old version had to blank a "pressed edge" field, because
// repeating a derived edge asserted a brand-new press every frame (menus ticking insanely fast). Raw device state
// has no edge field to blank: a held button repeating IS what the hardware reports, and the engine derives the edge
// from its own history, so a repeat can only ever mean "still held". The bug class is gone, not mitigated.
static const uint8_t* predict_from(const uint8_t* last, uint8_t* scratch) {
    memcpy(scratch, last, BLOB);
    return scratch;
}

static void seed_neutral() {
    for (int i = 0; i < RING; i++) { g_local[i].valid = false; g_remote[i].valid = false; }
    // pre-seed frames [0, D): the peer never sends inputs tagged < D, so both sides must locally seed these
    // identically to neutral or frame 0 deadlocks (GGPO delay-window startup).
    for (int f = 0; f < g_delay; f++) {
        g_local[idx(f)]  = { f, true, {} };  memcpy(g_local[idx(f)].blob,  g_neutral, BLOB);
        g_remote[idx(f)] = { f, true, {} };  memcpy(g_remote[idx(f)].blob, g_neutral, BLOB);
    }
    g_net_frame = 0; g_last_captured = -1; g_remote_high = g_delay - 1;
}

static void do_reset() {
    memset(g_neutral, 0, BLOB);
    // prediction state starts neutral every match — otherwise match 2 opens by repeating whatever button was held
    // when match 1 ended (a phantom press on the first frames of the new session).
    memset(g_last_local, 0, BLOB);
    memset(g_last_remote, 0, BLOB);
    memset(g_was_pred, 0, sizeof(g_was_pred));
    g_pred_used = g_pred_wrong = g_pred_depth_max = 0;
    seed_neutral(); g_stalls = g_sent = g_recv = 0;
}

void set_delay(int d) { if (d >= 0 && d < RING/2) g_delay = d; }

// Start (or restart) the lockstep timeline ON the AGREED EPOCH. Private: local code must go through propose_epoch()
// so that no purely-local game event can ever zero the clock on one side only — that was the timeline-mismatch desync.
static void activate_epoch(int delay, uint32_t epoch) {
    if (g_active && g_epoch == epoch) return;        // already running this timeline — never re-zero it
    set_delay(delay); do_reset(); g_active = true;
    g_epoch = epoch; if (g_want < epoch) g_want = epoch;
    g_last_activate_ms = net::now_ms();
    rblog::write("NET-INPUT(%s): LOCKSTEP ACTIVE — epoch %u (delay=%d) net-frame=0. Frames are only ever matched "
                 "within this epoch; anything tagged otherwise is discarded.", role::name(), epoch, g_delay);
}

// A LOCAL trigger (char-select entry, force-seed round-start) wants a fresh timeline. It does not get to reset the
// clock by itself: it raises a proposal that rides every outgoing input packet until the peer adopts it. We only
// activate once the proposal is actually shared — either the peer echoes this epoch back, or it proposes a higher one
// and we adopt that instead.
// INPUT DELAY must cover the actual link, not a LAN guess.
// delay=2 (33ms) was fine on loopback and is IMPOSSIBLE on a real link. Measured: rtt=84ms ~= 5 frames. Our input for
// frame F leaves at F-delay and lands ~5 frames later, so with delay=2 it reaches the peer at F+3 — three frames
// after they simulated F. It gets stored for a frame they already passed and they predict instead; prediction is
// repeat-last, and the confirmations that do arrive in time are the neutral ones. Net effect measured on the peer:
// 136 of our button-frames arrived and stored, zero were ever presented. The buttons were never lost, just late.
// So derive the delay from the measured round trip: half of it is the one-way, plus a frame of slack for jitter.
// Both peers adopt the same value because the epoch handshake already carries `delay` — no new agreement needed.
// Without rollback, delay is the only defence. A mispredicted frame is not corrected here — it is simply wrong
// input, permanently. So the delay must be large enough that the peer's input has essentially always arrived before
// the frame that consumes it, rather than merely usually. On a relayed link (two hops through the box) that means a
// generous floor: 8 frames = 133ms, which covers an 84ms round trip plus jitter with room to spare. It trades felt
// input lag for inputs that actually land, which is the correct trade until rollback exists to make the trade back.
static constexpr int RELAY_MIN_DELAY = 8;

// With the rollback engine armed the delay no longer has to cover the whole trip: a late packet is repaired by
// re-simulating instead of being predicted away permanently. That is the entire reason rollback exists, and it is the
// only thing that lowers the delay on a link that cannot be hole-punched (symmetric NAT => the relay is forever).
// So: armed => run the short design delay and pay for it in rollbacks; unarmed => the delay must cover the link alone.
// (Measured at delay 2 on an 82ms relay: 100% of predictions were "not-yet-sent" — zero holes, zero aliasing — because
// the peers sat ~6 frames apart. That is a drift problem for TimeSync, not a reason to raise the delay.)

static int delay_for_link() {
    const uint32_t rtt = net::session_rtt_ms();
    const bool relayed = !net::transport_is_direct();
    if (!rtt) return relayed ? RELAY_MIN_DELAY : 2;      // unmeasured: on a relay assume the worst, not the best
    const int one_way_frames = (int)(((rtt / 2) * 60 + 999) / 1000);   // ceil(one-way in frames)
    int d = one_way_frames + 1;                          // +1 frame of jitter slack
    if (relayed && d < RELAY_MIN_DELAY) d = RELAY_MIN_DELAY;
    if (net_engine_arm::armed()) {
        // The armed delay is the design value (2), not a derived one. "Link delay minus a credit" was tried after
        // mistaking a drift problem for a latency one. Delay 2 with rollback is the correct target; it failed for a
        // different reason: the peers sat ~6 frames apart, so predictions ran ~6 deep, and every one
        // of those exceeded the rollback depth cap (then 3, now 6) and got SKIPPED — rollback never repaired the case it exists for.
        // The fix for that is drift (TimeSync), not a bigger delay. Overridable via `armed_delay.txt` so 2 vs 6 can
        // be compared on a live link without a rebuild.
        static int s_armed = -1;
        if (s_armed < 0) {
            s_armed = 2;
            char pp[MAX_PATH]; GetModuleFileNameA(NULL, pp, MAX_PATH);
            char* sl = strrchr(pp, '\\'); if (sl) sl[1] = 0; else pp[0] = 0;
            strncat(pp, "armed_delay.txt", MAX_PATH - strlen(pp) - 1);
            FILE* f = fopen(pp, "r");
            if (f) { int v = 0; if (fscanf(f, "%d", &v) == 1 && v >= 1 && v <= 12) s_armed = v; fclose(f); }
            rblog::write("NET-INPUT: armed delay = %d frame(s)%s. Rollback repairs lateness up to depth %d; if the "
                         "peers drift further apart than that, predictions exceed the cap and are NOT repaired.",
                         s_armed, s_armed == 2 ? " (design default)" : " (armed_delay.txt override)", resim::max_rollback_depth());
        }
        return s_armed;
    }
    if (d < 2) d = 2;
    if (d > 12) d = 12;                                  // past this the lag is worse than the drops
    return d;
}

void propose_epoch(int delay, bool force) {
    // The caller's value is a floor; the LINK decides the real one.
    const int link = delay_for_link();
    if (link > delay) {
        rblog::write("NET-INPUT(%s): input delay %d -> %d frames (rtt=%ums). Delay must cover the one-way trip or the "
                     "peer's input always lands AFTER the frame it belongs to and every press is predicted away.",
                     role::name(), delay, link, net::session_rtt_ms());
        delay = link;
    }
    set_delay(delay);
    // DEBOUNCE — the two local triggers (char-select entry, force-seed round-start) both fire within a
    // few frames at match start, so we were proposing epoch 1, activating, proposing 2, and activating again: two full
    // queue resets ~30ms apart. Each reset restarts prediction from neutral and re-seeds the delay window, which is a
    // burst of churn at exactly the moment the player sees "it ticks like crazy at first, then settles".
    // They are two signals for one event — entering a match — so the second must not mint a second timeline.
    if (!force && g_active && (uint32_t)(net::now_ms() - g_last_activate_ms) < EPOCH_DEBOUNCE_MS) {
        rblog::write("NET-INPUT(%s): epoch proposal IGNORED — already started epoch %u %ums ago. Char-select entry and "
                     "the round-start seed are the same match beginning, not two.",
                     role::name(), g_epoch, (unsigned)(net::now_ms() - g_last_activate_ms));
        return;
    }
    uint32_t next = (g_epoch > g_want ? g_epoch : g_want) + 1;
    g_want = next;
    rblog::write("NET-INPUT(%s): epoch %u PROPOSED (delay=%d) — waiting for the peer to adopt it before net-frame 0. "
                 "(A local event alone must never restart the timeline.)", role::name(), next, delay);
    net::Packet pk{}; pk.magic = net::NET_MAGIC; pk.type = net::MSG_EPOCH;
    pk.nonce = (uint32_t)delay; pk.stamp_ms = next;
    net::transport_send(pk);
}

// The peer told us which timeline it wants. Adopt anything NEWER than ours and start there; if ours is newer, simply
// re-announce so it adopts instead. Either way both ends converge on max(epoch) without one being the authority, and
// a lost announcement is harmless because every input packet re-states epoch/want continuously.
void on_peer_epoch(uint32_t epoch, int delay) {
    if (epoch > g_epoch) {
        activate_epoch(delay, epoch);
    } else if (g_want > epoch) {
        net::Packet pk{}; pk.magic = net::NET_MAGIC; pk.type = net::MSG_EPOCH;
        pk.nonce = (uint32_t)g_delay; pk.stamp_ms = g_want;
        net::transport_send(pk);
    }
}

uint32_t epoch() { return g_epoch; }

bool active()   { return g_active; }
int  net_frame(){ return g_net_frame; }

// PREDICTION BARRIER (GGPO parity) — how far ahead of confirmed remote input we are running.
// GGPO refuses local input entirely past `_max_prediction_frames` ("Rejecting input from emulator: reached prediction
// barrier"), which is a HARD bound: a peer physically cannot gallop ahead of the input it has. We had no such bound,
// which is how P2 reached 169 frames (2.8s) ahead and predicted on ~100% of frames. It also protects the input ring:
// entries are keyed `idx(f)=f%256` and validated by frame number, so past 256 frames of drift every lookup misses and
// the peer predicts forever with no confirmed input at all. The barrier is what makes that unreachable.
int frames_ahead() { return g_active ? (g_net_frame - g_remote_high) : 0; }

bool remote_ready() {
    if (!g_active) return true;                  // not in lockstep -> never stall
    QEntry& e = g_remote[idx(g_net_frame)];
    return e.valid && e.frame == g_net_frame;
}

// How far BEHIND the peer we are, in frames. The peer's clock is estimated from the newest input it has sent us
// plus half the round trip, because that input describes where it was one trip ago — the same estimate GGPO makes.
static int local_frame_advantage() {
    const int rtt_frames = (int)((net::session_rtt_ms() * 60) / 1000) / 2;
    // Subtract the delay. g_remote_high is the peer's newest SCHEDULED frame, which is their actual position PLUS
    // the input delay — they schedule every capture `delay` frames into the future. Using it raw inflates the
    // estimate by exactly `delay` on both peers, so both reported themselves "behind" (adv=6 / peer_adv=7 while one
    // of them was demonstrably outrunning the other by enough to hit the prediction barrier 886 times). The bias
    // cancels in the comparison so the DIRECTION stayed right, but the magnitude — which is what sizes the
    // correction — was mostly delay, so corrections came out tiny and rare against a much larger real drift.
    return (g_remote_high - g_delay + rtt_frames) - g_net_frame;
}

// Frames the LOCAL peer should voluntarily give back this frame (0 = none). Averaged over TS_RING to keep packet
// jitter from producing a correction, and deliberately conservative: half the difference, capped.
int recommend_wait() {
    if (!g_active || g_ts_n < TS_RING) return 0;
    double adv = 0, radv = 0;
    for (int i = 0; i < TS_RING; i++) { adv += g_ts_local[i]; radv += g_ts_remote[i]; }
    adv /= TS_RING; radv /= TS_RING;

    // Averaging was hiding the drift it exists to remove. Measured: instantaneous adv=-26 (twenty-six frames ahead
    // of the peer) while the 40-frame mean stayed close enough to radv that recommend_wait returned 0 — 2 corrections
    // and 4 frames given back across ~118 seconds, with ~116 opportunities. The mean is the right basis for gentle,
    // steady-state correction, but it must not veto a large current lead: by the time a 26-frame spike has worked
    // through a 40-frame window it has already cost hundreds of predicted frames. Take whichever says we are further
    // ahead — the average for the steady case, the instant for the spike.
    const double inst_adv = (double)g_ts_local[(unsigned)(g_net_frame - 1) % TS_RING];
    const double inst_radv = (double)g_peer_adv;
    if (inst_radv - inst_adv > radv - adv) { adv = inst_adv; radv = inst_radv; }

    if (adv >= radv) return 0;                       // we are the one BEHIND (or level) -> never slow down
    int sleep_frames = (int)(((radv - adv) / 2.0) + 0.5);
    if (sleep_frames < TS_MIN) return 0;
    if (sleep_frames > TS_MAX) sleep_frames = TS_MAX;
    g_ts_corrections++; g_ts_frames_given += sleep_frames;
    return sleep_frames;
}

static void send_input(int upto_frame) {
    net::InputPacket p{}; p.magic = net::NET_MAGIC; p.type = net::MSG_INPUT;
    // Everything the peer has not yet confirmed, capped at the packet's capacity. A frame stops being re-sent only
    // when they tell us they have it — so a dropped datagram costs latency, never the input itself.
    int start = (g_peer_acked >= 0) ? (g_peer_acked + 1) : (upto_frame - (net::NET_INPUT_REDUNDANCY - 1));
    if (start > upto_frame) start = upto_frame;                       // nothing outstanding: still send the newest
    if (upto_frame - start >= net::NET_INPUT_REDUNDANCY) start = upto_frame - (net::NET_INPUT_REDUNDANCY - 1);
    if (start < 0) start = 0;
    p.start_frame = start; p.count = (uint8_t)(upto_frame - start + 1);
    p.ack_frame = g_remote_high;
    // slot the LOCAL human occupies: P1 machine -> slot0, P2 machine -> slot1 (identity, not locality)
    p.cfg_hash  = dinput_probe::config_hash(role::is_p2() ? 1 : 0);
    p.frame_adv = (int16_t)local_frame_advantage();
    p.epoch = g_epoch; p.want_epoch = g_want;
    for (int i = 0; i < p.count; i++) {
        int f = start + i;
        QEntry& e = g_local[idx(f)];
        memcpy(p.blobs[i], (e.valid && e.frame == f) ? e.blob : g_neutral, BLOB);
    }
    // Wire counter: count buttons at the moment they leave. If sent-nonzero climbs while the peer's received-nonzero
    // stays 0, the loss is on the wire/parse. If sent-nonzero is also 0 while our own slot shows presses, the capture
    // and the send disagree despite both reading g_local — a ring/indexing fault.
    {
        static long s_sent_nz = 0, s_hb = 0;
        for (int i = 0; i < p.count; i++) {
            const uint16_t btn = *(const uint16_t*)p.blobs[i];      // wButtons is the first field of XINPUT_GAMEPAD
            if (btn) { s_sent_nz++; break; }
        }
        if ((++s_hb % 600) == 0)
            rblog::write("NET-WIRE(%s): packets=%ld  with-a-button-down=%ld  (counted at the moment they leave; "
                         "compare against the peer's NET-PAD nonzero for the slot we drive)",
                         role::name(), s_hb, s_sent_nz);
    }
    net::transport_send_raw(&p, sizeof(p));
    g_sent++;
}

// Re-send the newest input we have while a frame is held. The packet already carries NET_INPUT_REDUNDANCY frames of
// history, so one datagram re-states the whole recent window and the peer catches up in a single hop. Rate-limited:
// the hold loop spins every ~1ms and flooding the socket would make the congestion it is trying to escape worse.
void pump_stalled() {
    if (!g_active || g_last_captured < 0) return;
    static uint32_t s_last_ms = 0;
    const uint32_t now = net::now_ms();
    if ((uint32_t)(now - s_last_ms) < 8) return;          // ~120Hz ceiling, well above the 60Hz the peer consumes
    s_last_ms = now;
    send_input(g_last_captured + g_delay);
}


void on_frame_begin() {
    g_present_valid = false;
    if (!g_active) return;
    const int N = g_net_frame;

    // Capture the LOCAL physical pad — 12 raw bytes, straight from the device.
    // read_local_pad() calls the XInput trampoline, so it bypasses our own hook entirely. That decoupling is what
    // makes the P2 machine possible: we read the real controller on its physical index while presenting somebody
    // else's bytes to the game on that same slot.
    if (N != g_last_captured) {
        uint8_t raw[BLOB];
        if (!dinput_probe::read_local_pad(raw)) memset(raw, 0, BLOB);   // no pad => neutral, never stale
        const int sched = N + g_delay;

        // Never leave a hole in the local ring.
        // This captured exactly one frame per tick, but net-frame can advance by more than one: after a stall, after
        // a TimeSync give-back, or any frame where this function does not run. Every skipped slot stayed invalid, and
        // send_input() substitutes g_neutral for an invalid slot — so the gap went out as "button released". A hold
        // spans enough frames to survive that; a TAP can land entirely inside a gap and vanish. Measured on the last
        // session: 1784 button-frames presented locally, 1464 arrived — 320 (18%) lost exactly this way.
        // Repeat the current sample across the gap instead. We did not sample those instants, so this is a
        // reconstruction either way — but repeating a press can only ever extend it slightly, whereas emitting
        // neutral manufactures a release and a second press edge out of nothing.
        int from = (g_last_captured < 0) ? sched : (g_last_captured + g_delay + 1);
        if (from > sched)        from = sched;
        if (sched - from > 32)   from = sched - 32;     // a gap this large is a reconnect, not a hitch
        for (int f = from; f <= sched; f++) {
            g_local[idx(f)] = { f, true, {} };
            memcpy(g_local[idx(f)].blob, raw, BLOB);
        }
        if (from < sched) {
            static long s_gaps = 0;
            if (++s_gaps <= 4 || (s_gaps % 200) == 0)
                rblog::write("NET-INPUT(%s): filled a %d-frame capture gap (net-frame jumped %d -> %d). Gaps used to "
                             "ship as NEUTRAL, which is how taps went missing. total=%ld",
                             role::name(), sched - from, g_last_captured, N, s_gaps);
        }
        send_input(sched);
        g_last_captured = N;
    }

    {   // feed the drift controller: our own advantage and the peer's most recent report
        const int slot = g_net_frame % TS_RING;
        g_ts_local[slot]  = local_frame_advantage();
        g_ts_remote[slot] = g_peer_adv;
        if (g_ts_n < TS_RING) g_ts_n++;
    }

    {   // stamp the mapping every live frame so a later replay can translate back
        if (!g_efmap_ready) { for (int i = 0; i < RING; i++) g_net_for_engine[i] = -1; g_efmap_ready = true; }
        const int ef = resim::current_frame();
        if (ef >= 0) g_net_for_engine[idx(ef)] = N;
    }

    // Resolve frame N for both sides. Local is always confirmed (we scheduled it D frames ago); remote may be
    // missing, in which case we PREDICT by repeating its last input — correct under XInput semantics, see BLOB.
    const QEntry& lo = g_local[idx(N)];
    const QEntry& re = g_remote[idx(N)];
    const uint8_t* localblob;
    const uint8_t* remoteblob;

    if (lo.valid && lo.frame == N) { localblob = lo.blob;  memcpy(g_last_local, lo.blob, BLOB); }
    else                           { localblob = predict_from(g_last_local, g_pred_local_buf); }

    if (re.valid && re.frame == N) { remoteblob = re.blob; memcpy(g_last_remote, re.blob, BLOB); g_was_pred[idx(N)] = false; }
    else {
        remoteblob = predict_from(g_last_remote, g_pred_remote_buf);
        if (!g_was_pred[idx(N)]) { g_was_pred[idx(N)] = true; g_pred_used++; memcpy(g_pred[idx(N)], remoteblob, BLOB); }
        // Why did we predict? Three causes need three different fixes and a bare counter cannot tell them apart:
        // NOT-YET remote_high < N — the peer genuinely has not sent this far. A LATENCY/pacing problem.
        // ALIASED the slot holds a different frame — the ring wrapped or frames are numbered inconsistently.
        // HOLE remote_high >= N but this exact frame never arrived — a real gap the resend should have filled.
        // The code states the cause rather than leaving it to delay arithmetic.
        {
            static long s_notyet = 0, s_alias = 0, s_hole = 0, s_hb = 0;
            if (g_remote_high < N)            s_notyet++;
            else if (re.valid && re.frame != N) s_alias++;
            else                               s_hole++;
            if ((++s_hb % 600) == 0)
                rblog::write("NET-WHYPRED(%s): not-yet-sent=%ld (peer is behind us / pacing) | ring-aliased=%ld "
                             "(wrapped or mis-numbered) | hole=%ld (arrived-range covers it but this frame never came) "
                             "| N=%d remote_high=%d delay=%d",
                             role::name(), s_notyet, s_alias, s_hole, N, g_remote_high, g_delay);
        }
    }

    // Role remap — slot is PLAYER IDENTITY, never locality.
    // slot0 is the P1 human and slot1 the P2 human on both machines. The P1 box sources slot0 locally and slot1 from
    // the wire; the P2 box does the mirror image. Result: identical input on both slots on both machines, which is
    // the whole requirement for the sims to stay equal. It also means menu control (which the game gives to P1)
    // rides slot0 on both boxes, so the host drives both games' navigation — by construction, not by special case.
    if (role::is_p2()) { memcpy(g_present[0], remoteblob, BLOB); memcpy(g_present[1], localblob,  BLOB); }
    else               { memcpy(g_present[0], localblob,  BLOB); memcpy(g_present[1], remoteblob, BLOB); }
    g_present_valid = true;
}

bool pad_for_engine_frame(int slot, int engine_frame, void* out12) {
    if (!g_active || slot < 0 || slot > 1 || !out12 || engine_frame < 0 || !g_efmap_ready) return false;
    const int N = g_net_for_engine[idx(engine_frame)];
    if (N < 0) return false;                       // never lived through this engine frame under lockstep
    const QEntry& lo = g_local[idx(N)];
    const QEntry& re = g_remote[idx(N)];
    // Confirmed input if we have it — that is the POINT of the replay. Neutral only if we truly never got it.
    const uint8_t* local  = (lo.valid && lo.frame == N) ? lo.blob : g_neutral;
    const uint8_t* remote = (re.valid && re.frame == N) ? re.blob : g_neutral;
    const uint8_t* src = role::is_p2() ? (slot == 0 ? remote : local)
                                       : (slot == 0 ? local  : remote);
    memcpy(out12, src, BLOB);
    return true;
}

bool pad_present(int slot, void* out12) {
    if (!g_active || !g_present_valid || slot < 0 || slot > 1 || !out12) return false;
    memcpy(out12, g_present[slot], BLOB);
    return true;
}

// Pre-pairing hold: while armed-but-unpaired, a NEUTRAL gamepad is presented on both slots (see hk_GetState). The
// pads exist, they are connected, and nobody is pressing anything — which is exactly what is true. Zeroing the
// engine's derived window was tried first; it only made two independently running games both look idle while their
// menu state, timers and RNG drifted, and it was a no-op until the game first dispatched input.

void advance_frame() { if (g_active) g_net_frame++; else return; }

void on_recv_input(const void* pkt, int len) {
    if (len < (int)sizeof(net::InputPacket)) return;
    const net::InputPacket* p = (const net::InputPacket*)pkt;
    int cnt = p->count; if (cnt < 1 || cnt > net::NET_INPUT_REDUNDANCY) return;

    // EPOCH GATE — the fix for the timeline-mismatch desync. A frame number only means something inside its own timeline.
    // Adopt a newer timeline if the peer has moved on; DISCARD anything from an older one instead of queueing it.
    // Previously these stale frames were stored happily, so a peer numbering from 0 would sit forever waiting on a
    // frame the other side had already passed 50,000 frames ago — silent, permanent, and fatal.
    if (p->want_epoch > g_epoch) activate_epoch(g_delay, p->want_epoch);
    if (p->epoch != g_epoch) {
        static long s_drop = 0;
        if ((++s_drop % 300) == 1)
            rblog::write("NET-INPUT(%s): discarding input from epoch %u (we are on %u) — %ld dropped so far. "
                         "The peer is on a different timeline; frames across epochs are not comparable.",
                         role::name(), p->epoch, g_epoch, s_drop);
        return;
    }
    for (int i = 0; i < cnt; i++) {
        int f = p->start_frame + i;
        if (f < 0) continue;
        QEntry& e = g_remote[idx(f)];
        if (e.valid && e.frame == f) continue;    // already have it (redundancy overlap)
        e.frame = f; e.valid = true; memcpy(e.blob, p->blobs[i], BLOB);
        {   // mirror of the send-side counter: did a button survive the trip?
            static long s_recv_nz = 0, s_hb = 0;
            if (*(const uint16_t*)e.blob) s_recv_nz++;
            if ((++s_hb % 600) == 0)
                rblog::write("NET-WIRE(%s): blobs-stored=%ld  arriving-with-a-button-down=%ld", role::name(), s_hb, s_recv_nz);
        }
        if (f > g_remote_high) g_remote_high = f;

        // Verdict on the prediction: this input has arrived for a frame we already advanced past using a guess.
        // If the guess matches, the speculation was free and nothing needs undoing. If it differs, this is precisely
        // the moment GGPO rolls back to frame f and re-simulates; the trigger is below. The rate and depth are logged.
        // depth = how many frames we have to unwind.
        if (f < g_net_frame && g_was_pred[idx(f)]) {
            g_was_pred[idx(f)] = false;
            if (memcmp(g_pred[idx(f)], e.blob, BLOB) != 0) {
                g_pred_wrong++;
                long depth = (long)(g_net_frame - f);
                if (depth > g_pred_depth_max) g_pred_depth_max = depth;
                // Which BYTES actually differ — a 99.5% mispredict rate is either the payload changing every frame
                // (analog stick noise: we ship raw sThumbL/R, and a physical stick jitters +/-1-2 counts at rest, so
                // every count makes the 12 bytes differ) or a frame-accounting fault (comparing the wrong frames).
                // Those need opposite fixes, and the two are indistinguishable from a bare "wrong" counter. Decompose
                // it: buttons/triggers are DIGITAL and cannot jitter, so if only the axes move it is noise; if the
                // buttons differ with nobody pressing anything, we are comparing the wrong frames.
                {
                    struct Pad { uint16_t btn; uint8_t lt, rt; int16_t lx, ly, rx, ry; };
                    const Pad* a = (const Pad*)g_pred[idx(f)];
                    const Pad* b = (const Pad*)e.blob;
                    static long s_btn_diff = 0, s_axis_only = 0;
                    const bool btn_d  = (a->btn != b->btn) || (a->lt != b->lt) || (a->rt != b->rt);
                    const bool axis_d = (a->lx != b->lx) || (a->ly != b->ly) || (a->rx != b->rx) || (a->ry != b->ry);
                    if (btn_d) s_btn_diff++; else if (axis_d) s_axis_only++;
                    if (g_pred_wrong <= 6 || (g_pred_wrong % 200) == 0)
                        rblog::write("NET-PREDICT-WHY(%s) f%d: btn %04X->%04X  LT %u->%u RT %u->%u  "
                                     "LX %d->%d LY %d->%d RX %d->%d RY %d->%d | digital-diffs=%ld axis-only-diffs=%ld",
                                     role::name(), f, a->btn, b->btn, a->lt, b->lt, a->rt, b->rt,
                                     a->lx, b->lx, a->ly, b->ly, a->rx, b->rx, a->ry, b->ry,
                                     s_btn_diff, s_axis_only);
                }
                // The ROLLBACK TRIGGER — corrected input just arrived for a frame we already simulated with a
                // guess, and the guess was wrong. That is exactly the moment GGPO rolls back. Translate the net
                // frame to the engine frame do_rollback speaks, and request it; resim performs it at the top of the
                // next tick (never re-entrantly from inside a receive). The engine auto-arms only during a FIGHT
                // (game-flow phase 5), so this is inert in menus by construction.
                if (g_efmap_ready) {
                    for (int e = 0; e < RING; e++) {
                        if (g_net_for_engine[e] == f) { resim::request_rollback_to(e); break; }
                    }
                }
                if (g_pred_wrong <= 8 || (g_pred_wrong % 100) == 0)
                    rblog::write("NET-PREDICT(%s): MISPREDICT at frame %d (now %d, depth %ld) — a rollback would fire here. "
                                 "totals: wrong=%ld / predicted=%ld, deepest=%ld",
                                 role::name(), f, g_net_frame, depth, g_pred_wrong, g_pred_used, g_pred_depth_max);
            }
        }
    }
    // Control-scheme agreement: compare the peer's observed permutation against what WE derive for that same
    // player's slot. A mismatch means identical wire bytes become different game actions on the two machines, which
    // is a guaranteed desync — and it is far better to say so loudly than to let it look like netcode jitter.
    // Both sides must have learned enough buttons (hash 0 = still learning) before a comparison means anything.
    {
        if ((int)p->ack_frame > g_peer_acked) g_peer_acked = (int)p->ack_frame;   // stop resending what they have
        g_peer_adv = (int)p->frame_adv;
        const uint32_t theirs = p->cfg_hash;
        const uint32_t ours   = dinput_probe::config_hash(role::is_p2() ? 0 : 1);   // the REMOTE player's slot here
        static bool s_warned = false, s_okayed = false;
        if (theirs && ours) {
            if (theirs != ours && !s_warned) {
                s_warned = true;
                rblog::write("NET-CONFIG(%s): CONTROL SCHEME MISMATCH peer=0x%08X local-view=0x%08X — the two "
                             "machines map the same raw buttons to DIFFERENT game actions, so the sims WILL diverge. "
                             "Both players must be on the same scheme (wipe the save with Steam Cloud disabled, or "
                             "set them identically).", role::name(), theirs, ours);
            } else if (theirs == ours && !s_okayed) {
                s_okayed = true;
                rblog::write("NET-CONFIG(%s): control schemes AGREE (0x%08X) — raw wire bytes derive identically on "
                             "both machines.", role::name(), ours);
            }
        }
    }
    g_recv++;
}

void report() {
    if (!g_active) return;
    rblog::write("NET-PREDICT(%s): predicted=%ld wrong=%ld (%.1f%%) deepest=%ld — wrong/predicted is the rollback rate we would pay",
                 role::name(), g_pred_used, g_pred_wrong,
                 g_pred_used ? (100.0 * (double)g_pred_wrong / (double)g_pred_used) : 0.0, g_pred_depth_max);
    rblog::write("NET-TIMESYNC(%s): adv=%d peer_adv=%d corrections=%ld frames_given=%ld — the FASTER peer gives frames "
                 "back so it never reaches the prediction barrier",
                 role::name(), local_frame_advantage(), g_peer_adv, g_ts_corrections, g_ts_frames_given);
    rblog::write("NET-INPUT(%s): net-frame=%d delay=%d remote_high=%d stalls=%ld sent=%ld recv=%ld ready=%d",
                 role::name(), g_net_frame, g_delay, g_remote_high, g_stalls, g_sent, g_recv, (int)remote_ready());
}

// called by hk_main_proc when a stall actually happens (for the counter/log)
void note_stall() { g_stalls++; }

} // namespace net_input
