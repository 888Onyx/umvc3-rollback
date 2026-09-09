// net_engine_arm.h — one press arms (or disarms) both engines
//
// The rollback engine used to be a local F5 toggle. In a netplay match that is wrong twice over: one peer can be
// running the engine while the other is not (their sims then diverge in how they handle a late packet), and either
// peer can switch it off mid-match, which strands the other. Auto-arming on game-flow phase==5 was tried and is
// worse — 5 latches at CHARACTER SELECT, so it armed in a menu and produced a 1756ms frame.
//
// So: keep the human trigger, make it collective. One player presses F5; both peers arm on the same net-frame. The
// frame is scheduled a little ahead so the request survives the wire, and the
// request is re-sent while pending so a dropped datagram cannot leave the two sides in different states.
#pragma once
#include <cstdint>

namespace net_engine_arm {

// F5 was pressed locally (already validated as a legal moment by the caller). Propose the arm to both peers.
void propose();

// A peer proposed an arm. `target_frame` is the net-frame both sides will arm on.
void on_peer_propose(uint32_t target_frame);

// Called every frame: sends any pending re-proposal and reports whether this frame is the arm frame.
// Returns true exactly once, on the agreed frame, so the caller can capture its baseline.
bool tick_should_arm();

// F5 toggles (there is no latch). It is still COLLECTIVE: one press flips both peers,
// because one side running the engine while the other does not is a divergence in how each handles a late packet.
// Arming is scheduled a few frames ahead so both baselines are captured on the same net-frame; DISARMING applies
// immediately on both sides, since dropping the engine is safe at any moment and delaying it only prolongs the
// mismatched window.
void propose_disarm();
void on_peer_disarm();
bool consume_disarm();   // true once when a disarm should be performed locally

bool armed();
bool pending();        // an arm is scheduled but has not landed yet
void report();

} // namespace net_engine_arm
