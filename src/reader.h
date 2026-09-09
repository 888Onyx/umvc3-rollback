#pragma once
// reader — MtScalable header-reading classifier (the READER, v2: membership-based liveness).
// A SECOND read-only shadow path inside arena::load(). Classifies every allocator block on each dirty
// page for object-granular rollback by reading the allocator's OWN structure — no birth-frame dictionary.
//
// v2 FIX (the conceptual hole in v1): the two liveness booleans come from which allocator LIST a block is
// on, captured at the right TIME — never from a block's +0x38 bit0 read out of the arena.
// in_use@now = block is on the LIVE control's ALLOC list, walked in reader::begin() at the TOP of load
// before any page-blind revert runs (so the arena is still truly live). begin() records the
// set into a rebuilt page-indexed live edge map (g_live_head/g_live_edge).
// in_use@N = block is on the FRAME-N SNAPSHOT control's ALLOC list, enumerated in compare_page() by
// walking the snapshot lists via snap_read (the descriptor's frame-N alloc/free heads).
// +0x38 bit0 is used only for SIZE ((v>>1)<<4); page-blind mutates it so it is not a liveness oracle.
//
// v1's defect: it read in_use@now from live_pg INSIDE compare_page, which runs after page-blind reverted
// the page to its frame-N image => in_use@now == in_use@N always => the VAPORIZE and RESURRECT branches
// were dead code and READER-DIFF=0 was vacuous. v2 makes both branches live and exercised.
//
// Writes only to reader-owned scratch/bitmasks in DLL .bss. Never writes game/arena memory (comparator).
//
// Requires arena::snap_read_bytes / arena::in_heap_zone / arena::base / arena::is_committed_addr /
// arena::is_arena_addr (declared in arena.h) and rblog (log.h).

#include <cstdint>
#include <windows.h>

namespace reader {

// Register the MtScalable control struct address. Call once from activate_heap_redirect() (or via
// probe_ctrl below). Idempotent after the first set; logs ctrl addr + pool_size fingerprint.
void set_ctrl(uintptr_t ctrl_addr);

// Scan [heap_zone_base, heap_zone_base+heap_zone_size) for the MtScalable control fingerprint:
// *(u32*)(candidate+0x534) == 0x20000000 (pool_size constant; FUN_1404C9200)
// *(u64*)(candidate+0x90) != 0 (pool_base set; FUN_1404C9222)
// arena::is_arena_addr(pool_base) (pool lands inside arena)
// Calls set_ctrl on first match. Returns true if found. Idempotent (no-op if ctrl already set).
bool probe_ctrl(uintptr_t heap_zone_base, size_t heap_zone_size);

// Call at the TOP of load(), before the page-blind revert loop, while the arena is still LIVE.
// Walks the LIVE control (g_ctrl) alloc lists (desc[k]+0x40 via block+0x20) and records each in-use@now
// block into a rebuilt page-indexed live edge map (g_live_head/g_live_edge — an edge on every 4KB page the
// block [B,B+size) spans). This captured set IS the in_use@now oracle used by compare_page. Bounded by the
// descriptor block count + slack, an absolute iteration guard, a self-loop guard, and the edge-pool cap; a
// truncated/corrupt list degrades to READER-GAP + a READER-GUARD-FIRE log (never a fault). Bumps the
// per-load epoch that invalidates the snapshot index. No-op if !g_active or ctrl not yet found.
void begin(int N);

// Per-dirty-page compare: after page-blind. Enumerates frame-N blocks intersecting page p by walking the
// SNAPSHOT control lists (built once per load), classifies each block by list membership (in_use@N = on the
// snapshot ALLOC list; in_use@now = present in begin()'s captured live-alloc set), computes the
// object-granular revert into an internal scratch buffer (seeded from shadow_live), and compares it
// byte-for-byte to live_pg (page-blind's result). Logs:
// READER-DIFF (covered byte disagrees with page-blind — a resolver/extent DEFECT; must be 0)
// READER-VAP (covered-VAPORIZE-body byte differs — EXPECTED; proves the VAPORIZE branch is EXERCISED)
// READER-GAP (uncovered dirty byte; main-arena = chase, heap-zone = infra, expected)
//
// p: page index (arena-relative; pg_base = arena::base() + p * 4096)
// N: rollback target frame
// ordered_slots: ring slots sorted by frame (same array as load() builds for page-blind)
// ordered_count: length of ordered_slots
// eff_bits: effective dirty-bit mask (g_dirty_bits or g_revert_bits; same as page-blind)
// shadow_live: 4KB snapshot taken before page-blind ran (= g_shadow_live in arena.cpp)
// live_pg: live arena page after page-blind ran (= frame-N image page-blind wrote)
// load_id: per-load dedup epoch (accepted for ABI symmetry; the reader keys on begin()'s epoch)
void compare_page(size_t p, int N,
                  const int* ordered_slots, int ordered_count,
                  const uint8_t* eff_bits,
                  const uint8_t* shadow_live,
                  const uint8_t* live_pg,
                  LONG load_id);

// Throttled cumulative stats line. Never per-frame — call from heartbeat / shadow_report() only.
void report();

// Arm / disarm the reader (default: true). When false, begin() and compare_page() return immediately.
extern volatile bool g_active;

} // namespace reader
