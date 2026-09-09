#pragma once
// net_charsel.h — lockstep opening-flow coordination. Implements the match-start
// flow: HOST drives the menus (input relay from connect → slot0=host on both machines, so P2's game follows), the
// game's own "insert P2 controller → press start" prompt joins the guest (relayed guest input rides slot1), then at
// character select device_map={0,1} makes left=host / right=guest, and the fight frame-locks (engine arms @ phase 5).
// Solves "both are P1": the game reads side S as pad_state[device_map[S]]; a solo boot leaves device_map={0,-1,-1,-1}
// (only left live) — forcing {0,1} makes the right/P2 side live and points it at slot1=guest.
namespace net_charsel {
void on_frame();          // per-frame (hk_main_proc, after session_pump): arm relay on connect, force device_map at CS. No-op unless connected.
bool in_charselect();     // true while the aChrSelect scene is current
bool in_fight();

// Match window INCLUDING the intro. Game-flow phases: 0/1 = load, 8 = character intro, 5 = active round.
// in_fight() is phase 5 only, which is far too late to start a hole-punch — by then the round is live and switching
// transport mid-round changes the timing under the players. The intro is several seconds of dead animation: exactly
// the window to establish and PROVE a direct path, so the round itself starts on a link that is already working.
bool in_match_window();

// Runs SOLO. The game-flow probes must not depend on a live session: the phase offset is a property of the game,
// not of netplay, so it is discoverable in a local match with no peer at all. on_frame() early-returns when there is
// no session, which would make the probe useless exactly when it is easiest to run.
void flow_probe_tick();          // per-frame game-flow probe: logs director/scene field changes; F9 snapshots the director
void report();
}
