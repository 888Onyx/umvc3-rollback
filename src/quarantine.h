#pragma once
#include <cstdint>
// quarantine — reuse quarantine (RCU / epoch-based reclamation). A slab freed INSIDE the rollback window
// is not returned to the allocator — its free is DEFERRED (the block stays in-use) until the window passes it. So an
// address maps to one identity for the whole window, and a reference (kept-live or reverted) can never land on a
// recycled object. This is the structural fix for the slab-reuse hang/crash family.
//
// Invariant that makes it sound: GRACE >= max rollback depth. Then a flushed (really-freed) block was freed before
// any reachable rollback target, so flush agrees with the arena revert; and a block freed after the target had its
// free "rollback" on rollback (reconcile drops it; the revert already restored it in-use).
//
// Modes: 0 OFF (no-op) / 1 SHADOW (measure would-defer, still frees — validates bookkeeping at zero risk) /
// 2 DEFER (real: skip orig_free, hold the block, flush past the horizon).
// Determinism: intercepts only FREE (zero alloc/free REQUESTS added/removed/reordered); only the next alloc's
// address changes (gp_crc skips arena pointers) — identical in forward play and resim, so no save/resim or peer desync.
namespace quarantine {
void init(void (*free_fn)(int64_t, int64_t));   // idspine passes its FUN_1404cb350 orig trampoline (for flush)
bool on_free(int64_t control, int64_t user, uintptr_t block, int frame); // true => CALLER SKIPS orig_free (deferred)
void flush(int current_frame, bool safe);        // free past-horizon held blocks (safe = forward play only)
void flush_all();                                // engine-off: drain all deferred blocks + clear the table
void reconcile(int target_frame);                // rollback: drop entries freed after target (those frees rolled back)
void on_frame(int frame);                         // per-frame: flush (if safe) + throttled stats
void report();
void set_mode(long m);                            // 0 off / 1 shadow / 2 defer
void set_scope(int64_t control);                  // 0 = all scalable allocators; else only this control
long mode();
// FAIL-CLOSED: ON (default) = defer every freed slot regardless of type (the engine-wide slab-reuse prevention — stop
// guessing which objects matter). OFF = legacy fail-open (defer only positively-typed objects; skipped 99.99% of frees).
// External handles (audio voices) are still carved out to voice_pool either way. A/B toggle via quar_typed_only.flag.
void set_defer_all(bool on);
// SENTINEL FIX: on = legacy audio carve-out (skipped 0x140A6A510 = every destructed MtObject — a hole found on a 40k-frame run).
// off (default) = no carve-out, destructed objects deferred like any other. A/B toggle via quar_audio_carveout.flag.
void set_audio_carveout(bool on);

// QUARANTINE-UNIT (single-timeline construction): the held-table is ROLLBACK STATE — captured every frame in
// the same CS-held instant as the descriptor/FLIST-UNIT captures, restored wholesale at rollback. A table restored
// to frame N structurally cannot contain an entry for a free that happened after N => reconcile()'s heuristics and
// the stale-entry skip become unrepresentable, not guarded. Whole-or-nothing per slot (overflow/unlocked
// => slot invalid loudly => that rollback falls back to live-table + reconcile()).
void save_table(int frame, int slot, bool cs_held);   // called from save_allocators beside save_freelists
bool restore_table(int target_frame);                 // true = wholesale restore done (caller SKIPS reconcile)
int  held_count();                                    // current held-set size (STABILITY heartbeat)
// husk = a freed block the quarantine still holds (its slab is not yet reusable). husk SET: O(1) "is this address a held dead object?" — the engine-wide dangling-edge test (every free from
// every subsystem passes through on_free ⇒ no per-dtor/per-family coverage gaps CAN exist). Lockstep with the
// table (defer/flush/restore/reconcile) so rolled back frees correctly exit the set.
bool is_held_husk(uintptr_t user);
// DEFAULT-husk timeline set: Default/heap-zone deaths (which never pass on_free) stamped with their frame.
// note = on free (death stamp); drop = on (re)alloc (alive again); prune = on rollback (deaths after target
// rollback). is_held_husk() also consults this set. Liveness is decided by the recorded timeline — no byte/vtable inspection.
void note_default_husk(uintptr_t addr, int death_frame);
void drop_default_husk(uintptr_t addr);
void prune_default_husks(int target_frame);
void default_husk_stats(long long* add, long long* pruned, long long* drop);
}
