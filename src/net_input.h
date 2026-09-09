#pragma once
#include <cstdint>
// net_input.h — lockstep-delay input exchange. The deterministic per-frame core:
// two frame-keyed queues (local delayed by D, remote at D=0), the GetConfirmedInput-style stall gate, the
// role-based slot remap (P1 local->slot0 / P2 local->slot1). Design validated against the GGPO source.
// NOTE: this is the input MACHINERY; two sims only stay identical once match-start STATE sync (net_sync) gives
// them a common frame-0. Without it the pipe works but the sims drift.
namespace net_input {
// Epoch-agreed start. activate() is GONE as a public entry point: a purely local game event must never zero the
// lockstep clock on one side only (that produced peer-A-at-frame-55 vs peer-B-at-frame-55255, permanent + silent).
// Local triggers raise a PROPOSAL; both peers converge on max(epoch) and start together.
// `force` bypasses the duplicate-trigger debounce. The debounce exists because char-select entry and the round-start
// seed are two signals for one match beginning, and minting two timelines for them caused a burst of churn. A DELAY
// CHANGE is a different thing entirely: it is a deliberate new timeline, and it must not be mistaken for a duplicate.
void propose_epoch(int delay, bool force = false);                // a local trigger wants a fresh timeline — announce, do not act
void on_peer_epoch(uint32_t epoch, int delay);// peer announced its timeline; adopt if newer
uint32_t epoch();                             // the timeline we are numbering frames against
bool active();                               // lockstep exchange running
int  net_frame();                            // current net-frame (0 at begin)
int  frames_ahead();                          // net-frame minus highest confirmed remote frame (the prediction depth)
bool remote_ready();                         // remote input for the current net-frame present? (the STALL gate; true when inactive)
// HARDWARE EMULATION — the netcode no longer writes the engine's derived input window. It supplies
// raw 12-byte XINPUT_GAMEPAD state at the device seam and the engine derives all eleven window fields itself, from
// its own history, in its own order. That is 1:1 by construction; the old post-hoc window write never could be,
// because orig_input_dispatch derived the edges from LOCAL hardware before our write landed.
//
// Ordering matters: capture+resolve must happen before the game polls, because the poll is what consumes it.
void on_frame_begin();                        // called from hk_input_dispatch before orig: capture local, send, resolve both slots

// What 12 bytes should this SLOT show this frame? Slot is PLAYER IDENTITY, not locality: slot 0 is always the P1
// human and slot 1 always the P2 human, whichever machine they sit at. Each machine sources one slot from its own
// stick and the other from the wire, so both machines hold identical input on both slots every frame — which is the
// entire requirement for the two sims to stay equal. Returns false when the netcode is not driving the pads.
bool pad_present(int slot, void* out12);

// ROLLBACK REPLAY — what should this slot show for a SPECIFIC engine frame?
// pad_present() answers for the frame we are living in; a replay has to ask about a frame we already passed, and it
// must get the CORRECTED input (the packet that arrived late and triggered the rollback), not the guess we used the
// first time. Pure lookup: no prediction ledger, no last-input bookkeeping, no side effects — so replaying frame F
// twice yields the same bytes twice, which is the whole basis of a rollback being trustworthy.
bool pad_for_engine_frame(int slot, int engine_frame, void* out12);
void advance_frame();                        // called after a frame executes: net-frame++
void on_recv_input(const void* pkt, int len);// route an incoming MSG_INPUT datagram into remote_q
void set_delay(int d);
// Keep the wire alive while the frame is held. Every send lives inside on_frame_begin(), which only runs when the
// frame runs — so a stalled peer goes silent, and a peer that needs our input to clear ITS stall never gets it. Two
// stalled peers then deadlock, each abandon buying one more frame of drift (measured: ahead-by 9, 10, 11 against a
// barrier of 8, with the mispredict rate climbing back to 70%). Call this from every path that holds a frame.
void pump_stalled();

int  recommend_wait();                        // TimeSync: frames this peer should voluntarily give back (0 = none)
void note_stall();                           // hk_main_proc calls this when it actually stalls (counter/telemetry)
void report();                               // heartbeat: active/frame/delay/stalls/sent/recv
}
