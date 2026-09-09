#pragma once
#include <cstdint>
// net_sync.h — lockstep match-start FORCE-SEED. Decided by binary RE and the GGPO literature (both
// unanimous): NO state transfer (impossible cross-process — pointers + ASLR); instead force both peers' next
// round to an identical RNG seed and let the game's OWN broadcaster (FUN_1401cfa90) fan it into MAIN + stage +
// every gameplay object's per-context stream. Requires identical builds (two Steamless twins); ASLR may stay on.
// Mechanism: hook the seed choke point FUN_14000b350(matchctrl, seed) — when armed, substitute the shared seed,
// then that round-start becomes net-frame 0 and net_input lockstep activates. Reuses the engine's shipped seed path.
namespace net_sync {
void init();                        // install the FUN_14000b350 seed hook (idempotent)
void arm(uint32_t seed, int delay); // P1: force `seed` at the next round-start + MSG_BEGIN{delay,seed} to peer
void peer_arm(uint32_t seed, int delay); // P2: peer's MSG_BEGIN — force the same seed at our next round-start
bool armed();
void report();
}
