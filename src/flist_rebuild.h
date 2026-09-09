#pragma once
#include <cstdint>

// flist_rebuild — the by-construction FALLBACK that replaces page-blind for a corrupt free-list chain.
//
// The PROBLEM (a4 free-list ratchet): resim replays multi-threaded engine code single-threaded
// (drain gate +0xa4), which reorders a4's alloc/free ops. a4's link ORDER is gameplay-invisible (gp_crc skips
// arena pointers; entity identity is positional, not address), so this passes determinism
// but drifts the free-list count. The engine's count-gated unlink (FUN_1404CAA60 @0x1404caa60; inlined
// @0x1404ca823 where the guard covers only the unlink, carve-completion after 0x1404ca861 runs unconditionally)
// then hands a block out ALLOCATED (bit0=1) while still chained = a LOST-UNLINK; a later re-free re-threads it
// (unconditional insert FUN_1404CA360 / 0x1404ca93a) into a CYCLE. FLIST-UNIT can't walk a cyclic chain, so it
// falls back to page-blind, which stitches the multi-page chain from mixed epochs => the chain is corrupt
// PERMANENTLY and grows every rollback (224 slot_invalids/session) until a consumer faults (FUN_1404ca650 0x1404CA849).
//
// The FIX: the free-list CHAIN is DERIVED state (order is coalescing-history-dependent and does not affect
// allocator correctness — first-fit FUN_1404ca650 only needs some node of sufficient size). The AUTHORITATIVE truth is
// each block's own free-bit. So when the chain is proven un-walkable, REBUILD it from the free-bit set (a linear
// pool sweep) instead of tearing it page-blind. This is "rebuild the derived structure from the authoritative
// one" (accurate-save/restore principle), not excavate-repair of gameplay state (a4 is gp-invisible).
//
// This replaces a refuted earlier rebuild (it enumerated from ctrl+0xc0, the drained RESERVE pool, collected 0
// blocks, and unconditionally committed the empty result, wiping 64 managers => the all-parked hang). This version
// differs in every way that one failed: enumerate from ctrl+0x90/+0x98 (+donated),
// a write-guard that DECLINES any implausible/empty collection (touches nothing), a narrow trigger (only the one
// (ctrl,k) FLIST-UNIT itself just proved unwalkable), and the reused, RE-verified edge_census pool-walk layout.
namespace flist_rebuild {

// Rebuild allocator `ctrl`'s per-class-`k` FREE list from the authoritative free-bit set (a pool scan).
// Call only with the allocator splice-quiescent (inside save_allocators' CS-held window) and only as the
// fallback for a chain FLIST-UNIT proved FL_CYCLE / FL_UNREADABLE.
// Returns: >=0 = # free blocks re-chained; the LIVE manager's head(+0x58)/tail(+0x60)/count(+0x68)/size-sum
// (+0x6c) and the collected nodes' +0x18/+0x20 links were rewritten to a clean walkable chain.
// -1 = DECLINED — could not derive safely (unreadable/nonsensical ground truth, or an implausible
// collection). The LIVE state was not touched; the existing page-blind fallback stands unchanged.
// out_why (optional): set to a static string naming the exact success/decline path (for the caller's log).
// out_us (optional): wall time of the pool sweep in microseconds (so a decline's cost is visible, not silent).
int rebuild_free_list_from_pool(uintptr_t ctrl, int k, const char** out_why, uint32_t* out_us);

long rebuilt_ok();        // session count of successful rebuilds
long rebuilt_declined();  // session count of declines (ground truth untrustworthy => left untouched)

// ALWAYS-ON ownership probe (caller-throttled, CS-held): walk manager (ctrl,k)'s LIVE free chain and classify where
// each free block physically lives vs what WE track — in-primary-pool [ctrl+0x90,+0x98) / in a donated region /
// IN-ARENA-BUT-UNTRACKED / OUT-OF-ARENA. Logs one summary line. Finds the "missing ownership": free blocks in memory
// the rollback doesn't own can't revert coherently (== the empty-collect: the sweep only covers what we track).
void probe_free_locations(uintptr_t ctrl, int k);

} // namespace flist_rebuild
