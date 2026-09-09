#pragma once
// effect_splice — re-land of the proven effect-child free-time splice (old lineage clamp.cpp,
// an earlier build: 167s of active rollback, zero UAF).
//
// The engine frees an effect-child without unlinking it from the parent effect's +0x218 child list.
// The dangling +0x218 reference into the recycled slab is the confirmed root of the Unit free-list
// recip-break -> FUN_1404ca650/FUN_1404cb350 crash + 20s hang. This adds the engine's
// MISSING unlink at the free chokepoints: when a child is torn down, splice it out of its parent's
// +0x218 list (parent reached via child+0x10 = CHILD_OWNER). Ungated (live + resim) so it replays
// deterministically with the free => peer-safe by construction (mutates only the gameplay +0x218 list;
// no clock/snapshot state — the determinism invariant). Two hooks cover every path: FUN_140816670 (base
// dtor) + FUN_14080b4d0 (shared teardown — catches the type-0x19 bypass children the base dtor skips).
// VALIDATION (the existing alloc_consistency, no new probe): RECIP-BREAK -> 0, no FUN_1404ca650/FUN_1404cb350 crash/hang.
namespace effect_splice { void init(); long applied_count(); }   // applied_count: # of +0x218 unlinks (confound logging for the consume probe)
