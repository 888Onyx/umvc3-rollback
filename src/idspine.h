#pragma once
// idspine — birth-stamp identity spine (SHADOW-only; zero game-memory writes).
//
// The problem it solves (same-type reuse of a slab within the rollback window):
// restoring a pointer "by identity" (byid) re-resolves an edge to the
// referent's current address. But the allocator frees a block and hands the same slab back out to a
// new object of the same type. Address + type are then identical to the original, so an edge would
// bind to the IMPOSTOR. byid's positional identity (IDK_EFFECT_CHILD birth-index along a list,
// IDK_SCHEDULER_SLOT chain-index) cannot tell the two apart. The missing third coordinate is when the
// object was born.
//
// idspine assigns every allocator block a monotonic birth serial in a DLL-side table (no game writes).
// byid (later) will check: does the object now at this address carry the same serial the edge captured?
// A different serial => the referent is gone and an impostor moved in => sever/rebuild, never bind.
//
// KEY = allocator BLOCK BASE (alignment-independent; same coordinate on both sides):
// birth = FUN_1404ca650 return value (its first-fit free-list walk covers REUSE; carve is the fallback)
// death = FUN_1404cb350 param_2 - *(param_2-8) (the engine's own user->block recovery, FUN_1404cb350)
// object-base (user-ptr, vtable@+0) -> block = user - *(user-8) (for byid's re-resolved addresses)
//
// Nothing here writes game memory. byid consults the stamps via stamp_of_object() (CapEdge.ref_stamp + the
// STAMP-SUB classifier); there the stamp is a shadow-logged signal, not yet a splice trigger.

#include <cstdint>


namespace idspine {

void init();                              // install birth (FUN_1404ca650) + death (FUN_1404cb350) MinHooks (SHADOW)


// --- identity queries (read-only; used by byid) ---
int64_t stamp_of_block(uintptr_t block);  // 0 if never stamped (pre-init / non-arena / unknown)
int64_t stamp_of_object(uintptr_t obj);   // obj = user-ptr; resolves block via *(obj-8), then stamp
bool    live_at(uintptr_t block);         // is the block currently allocated (not retired)?
// Full liveness lookup (read-only): fills the block's latest birth/death_frame + serial; false if never stamped.
// "alive at frame N" == (found && birth_frame <= N && N < death_frame). The dyndelete validator's substrate query.
bool    lookup(uintptr_t block, int* birth_frame, int* death_frame, int64_t* serial);

int64_t birth_counter();                  // current monotonic serial (journal snapshot/restore later)

// Read-only snapshot of currently-live allocator block bases (for the pointer-provenance recorder). Returns
// count (<= max). No locks, no game writes; tolerates concurrent mutation (a slot racing live<->dead is just
// sampled-or-not this pass — fine for a statistical recording).
int snapshot_live(uintptr_t* out, int max);

// Sized snapshot — every live block's {base, size, serial} — the substrate for the provenance index (sub-page
// object granularity). Returns count (<= max). Read-only.
int snapshot_live_sized(uintptr_t* base, uint32_t* size, int64_t* serial, int max);

// All tracked blocks (live and tombstoned) with their birth/death frames + serial — the substrate for the P4
// SHADOW epoch-rebuild validation (alive-at-frame-N = birth<=N<death, death==0x7FFFFFFF means still alive).
// Returns count (<= max). Read-only.
int snapshot_all(uintptr_t* base, int* birth, int* death, int64_t* serial, int max);

// As snapshot_all but with each block's size — the Property-4 object-granular revert substrate (RESURRECT of a
// died>N block must revert its EXTENT, so the walk needs size). Returns count (<= max). Read-only.
int snapshot_all_sized(uintptr_t* base, uint32_t* size, int* birth, int* death, int64_t* serial, int max);

// --- recent-free attribution (idspine owns the FUN_1404cb350 hook) ---
// Most-recent free of `node` (allocator block base). true if found; fills immediate caller (IDA), the first
// effect/anim-cluster return address in the chain (IDA, 0 if none), and the frame it was freed.
bool recent_free(uintptr_t node, uintptr_t* caller_ida, uintptr_t* eff_ida, int* frame);

// --- diagnostics (throttled; never per-frame) ---
void on_frame();                          // heartbeat tick: emits a stats line ~every 10s
void report();                            // emit cumulative stats now
void set_di_detect(bool on);              // arm/disarm the double-insert cause-finder (default OFF; Numpad7)
bool di_detect();

} // namespace idspine
