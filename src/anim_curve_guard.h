#pragma once
#include <cstdint>
// anim_curve_guard — domain-valid-or-null for the effect-node rotation-curve resolver.
//
// The CRASH (0x14087D46E, RENDER-ONLY): FUN_14087D0C0 (effect-node transform builder) resolves a keyframe/curve
// entry via FUN_140879570 (0x140879570) then reads the quaternion at rsi+0x8/+0xc/+0x10/+0x14 (`movss 0x8(%rsi)`).
// The engine's own null-guard `test rsi,rsi; je 0x14087D485` routes rsi==0 to a default-pose path — but it only
// rejects exactly 0. After a rollback, an intermediate arena pointer in the resolver's chain (rdx = *(*(r13+0x40)+
// 0x20), table = *(rdx+0x78)) is reverted/dangling, so the resolver computes a NON-NULL WILD pointer that sails
// through the guard and faults at +0x8.
//
// The FIX (by construction, binary-verified): FUN_140879570 is a pure resolver (no state writes; 0 is already its
// native rdx==0 return) with exactly two direct callers (0x14087D0C0 and, via FUN_14096D640, 0x14086E860) and NO
// indirect/vtable references — and both callers null-check the return before the identical deref (je 0x14087D485 /
// je 0x14096D837). So hooking the resolver entry and returning 0 whenever the resolved pointer is not domain-valid
// makes the resolver's contract — return ∈ {0, a committed curve entry} — hold BY CONSTRUCTION; every consumer's
// own default-pose branch then handles the 0. RENDER-ONLY (writes a stack-local xform, not entity+0x538; unhashed)
// ⇒ desync-safe, gp_crc GAMEPLAY-diverged stays 0. Same domain-valid-or-null pattern as render_subchild_guard.cpp.
namespace anim_curve_guard {
    void init();            // MH_CreateHook FUN_140879570 (resim.cpp enables MH_ALL_HOOKS once, after all inits)
    long guarded_count();   // how many wild resolver returns were coerced to 0 (diagnostic counter)
}
