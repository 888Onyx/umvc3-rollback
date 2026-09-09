#pragma once
// life_floor — LIFE-FLOOR (restore-faithful UAF closure for the render-wrapper family)
//
// The engine never UAFs on its own because a refcounted wrapper (nDraw RTV/DSV/Texture) that hits refcount 0 does
// not die immediately — the Release fork (FUN_14076f760 / FUN_140783650, vtable+0x28) compares the object's stamp
// [this+0x8] against the age counter DAT_140e1b708: aged ⇒ immediate scalar-dtor, FRESH ⇒ push to sRender's
// retirement RING (dies later, provably beyond use). During resim our render tick is suppressed, so wrapper deaths
// diverge and a holder can dereference a dead object. LIFE-FLOOR: while resim-armed, make the dying wrapper look FRESH (bump
// only its own +0x8 stamp, a render-domain field, not gp_crc-hashed, arena-reverted on rollback) so the engine's
// OWN fork routes the death to the ring instead of destroying it inside the window. RING-UNIT (resim.cpp coherent-
// full) then restores the ring coherently. No global bias (the age counter is gameplay-hashed), no .text patch.
namespace life_floor {
void init();          // MH_CreateHook the two wrapper Release forks; caller enables hooks
long long floored();  // count of deaths routed to the ring this session (measurement)
}
