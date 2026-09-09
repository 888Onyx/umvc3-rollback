#pragma once
#include <cstdint>

namespace input {

// Input block geometry (RE-corrected): the real per-pad stride is 0x2E0 (736), confirmed all over
// the binary (imul …,0x2e0 / add rbx,0x2e0). The old 550/0x2C0 was 0x20 short of pad1's base and truncated pad1's
// command-history tail (pad+0x1e9..0x2e0) — invisible to single-machine resim (symmetric round-trip) but a
// cross-machine desync on special/command inputs. pad0 @ base+0, pad1 @ base+0x2E0.
constexpr int  PLAYER_INPUT_SIZE = 0x2E0;   // 736 — full per-pad block
constexpr int  P2_OFFSET         = 0x2E0;   // pad1 base

// Machine-specific fields inside the derived block — not a function of buttons: +0x40 (u64 engine-time
// snapshot), +0x48 (u32 time delta), +0x140..0x150 (per-machine DInput device map), +0x7a/+0x7c (counter-derived).
// They never cross the wire: only the 12-byte raw pad does, and the engine derives these locally on each peer.

void init();          // hook input dispatch
void capture(int frame);
void inject(int frame);
void stop_inject();
uintptr_t buffer_base();   // g_input_ref (0 until the first dispatch); the netplay layer reads/writes both pad slots through this

} // namespace input
