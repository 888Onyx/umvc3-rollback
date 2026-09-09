#pragma once
#include <cstdint>

namespace arena {

// Phase 1: Called from DllMain (DLL_PROCESS_ATTACH) — before game code runs.
// Reserves the 2GB arena, installs IAT hooks on VirtualAlloc/Free/HeapAlloc/Free/ReAlloc/Size.
bool early_init();

// PERF A/B switches (set in DllMain before early_init, from env var or sentinel file next to the .exe).
// nowritewatch -> reserve the arena without MEM_WRITE_WATCH (isolates the write-watch tax; rollback save fails by design)
// nohooks -> resim::init skips installing all non-essential module hooks (isolates the hook-trampoline tax)
// Both DISABLE the rollback engine (perf isolation only). Toggle: create "<name>.flag" beside the .exe, or set env UMVC3_<NAME>.
bool startup_flag(const char* env_name, const char* file_name);
void set_startup_flags(bool no_writewatch, bool no_hooks, bool no_heapredirect);
bool no_writewatch();
bool no_hooks();
bool no_heapredirect();   // 'noheapredirect' A/B: don't activate the HeapAlloc->zone redirect (game keeps its native OS heap)

// Throttled diagnostic: log the never-reuse frontier (VirtualAlloc carve high-water + HeapAlloc bump offset +
// committed page count). Monotonic growth here = the locality-collapse signature. Call ~every 10s, never per-frame.
void log_growth();

// Phase 2: Called from init thread after 5s delay.
// Activates HeapAlloc redirection to arena heap zone.
// Must wait for CRT/game init to finish so per-thread data doesn't land in arena.
void activate_heap_redirect();

// Phase 3: Called on first F5 press.
// Snapshots all committed arena pages as the baseline for delta saves.
bool capture_baseline();

// Is the arena ready for save/load?
bool is_ready();
bool has_baseline();

// Is this address inside the arena?
bool is_arena_addr(uintptr_t addr);

// Is this address on a committed page? (range + committed check)
bool is_committed_addr(uintptr_t addr);

// Read-only diag: was the page containing addr orphan-zeroed by the last load?
bool was_orphaned_last_load(uintptr_t addr);
// Read-only diag: the page's source in the last load (>=0 ring frame, -1 baseline, -2 orphan, -3 live, -100 out-of-arena)
int  last_source_frame(uintptr_t addr);
// Read-only diag: read the SAVED snapshot bytes for `frame` at arena addr (1=ring, 2=baseline, 3=supplemental, 0=absent)
int  peek_saved(int frame, uintptr_t addr, void* out, size_t len);

// Ring buffer: save current frame state, load a previous frame
bool save(int frame);
bool load(int frame);

// RE-DERIVE region exclusion (restore-by-structure invariant: minimal-restore + re-derive is the default).
// Pages within these in-arena [base, base+size) ranges are SKIPPED by load() — kept live so the resim
// re-derives them. Set per-rollback (from the schema's RE-DERIVE classification); cleared otherwise.
void set_rederive_exclusions(const uintptr_t* bases, const size_t* sizes, int n);
void clear_rederive_exclusions();
// Read-only: is this address on a page EXCLUDED from revert (PRESERVE/live region)? Out-of-arena => false.
bool is_rederive_excluded(uintptr_t addr);

// Arena base/end for range checks
uintptr_t base();
uintptr_t end();

// SUBSTRATE COHERENCE primitive: force-dirty every committed 4KB page of [base, base+min(size,cap)) via the
// proven *p=*p write-watch touch, so the next arena::save() captures the whole range as one frame-N group
// (page-revert is object-unaware; a coherence group must be captured atomically). Safe by construction (writes
// each byte to its own value — no clock/RNG/allocator state produced). Out-of-arena / uncommitted pages are skipped.
void force_dirty_range(uintptr_t base_addr, size_t size, size_t cap);

// SCOPED COHERENT RESTORE (the doubly-linked-list coherence fix): pages inside these in-arena [base,base+size)
// ranges are FULL-reverted to the target frame (every historically-dirty page restored to its target value),
// while the rest of the arena uses fast windowed restore. A linked list is a cross-page coherence group;
// windowed revert can leave some node pages live => the chain crosses frames => reciprocity breaks (the
// allocator free-list crash). Force-full just the list's pages => the whole {descriptor+nodes} group lands at
// one frame. Restore-by-STRUCTURE: the range is the list's own pool, not an arbitrary address window.
// Set per-rollback before load(); cleared otherwise.
void set_coherent_full_ranges(const uintptr_t* bases, const size_t* sizes, int n);
void clear_coherent_full_ranges();

// Heap zone offset (bump allocator watermark)
long long get_heap_zone_offset();
void set_heap_zone_offset(long long offset);

// STAGE B (heap-zone redirect): route Default malloc into the in-arena heap zone (byte-reverted by arena::load => fixes alive-at-N Default
// crashes). heap_zone_alloc_default returns a user ptr with the FUN_1404C9A00-compatible header (NULL@-0x10, size@-8),
// or NULL on zone overflow (caller falls back to CRT). in_heap_zone => is this addr a zone block (skip its CRT free).
// stage_b_crt_fallback => count of overflow-to-CRT allocs (long-run gate: should stay 0/low).
void* heap_zone_alloc_default(size_t size);
bool  in_heap_zone(uintptr_t addr);
long long stage_b_crt_fallback();
// Heap redirect (game HeapAlloc -> single-atomic bump zone). Rollback-only; toggle to A/B its cross-thread cost.
void set_heap_redirect(bool on);
void set_lean(bool v);   // NETPLAY-LEAN mirror (skip g_last_source forensics bookkeeping per rollback)
bool get_heap_redirect();

// Windowed restore A/B (perf): revert only pages written after the rollback target (default ON, state-identical).
void set_windowed_restore(bool on);
bool windowed_restore();
// DEFERRED-FOLD: move the per-save baseline fold memcpy (~1.6ms) to a bg thread (default OFF =
// synchronous, byte-identical). fold_drain() blocks (main thread) until the bg worker has flushed all jobs — must be
// called before any freeze()/baseline-byte read while defer is active. 
void set_fold_defer(bool on);
bool fold_defer();
void fold_drain();
// OWNED-HEAP master flag (default ON = all four properties). dllmain composes all 4 properties from it; here it gates the
// P1 "own all backing" capacity alarms (arena-full passthrough / heap-zone-full fallback). OFF = legacy A/B.
void set_owned_heap_active(bool on);
bool owned_heap_active();
// Per-load scheduler-chain RE diagnostic walk (DIAG-CHILD + ANIM-BVC) — default OFF.
void set_load_diag_walk(bool on);
bool load_diag_walk();
// Per-frame hook-fire counters (perf bisection). 0=scene_tree 1=MtScalable-free 2=HeapAlloc 3=effect-consume 4=SE-guard
void hook_count_inc(int i);
long hook_count_get(int i);
void hook_count_reset();

// Arena watermark (next free offset for VirtualAlloc carving)
size_t get_watermark();

// Diagnostic: entity address to trace during next load
extern uintptr_t g_diag_entity;


// Frame-N snapshot read for arbitrary in-arena addresses (used by reader.cpp).
// Resolves ring/baseline exactly as shadow_compare_page does, writing frame-N bytes into out[0..len).
// Returns false for out-of-arena. absent_out: set true if any page has no frame-N record (ABSENT).
bool snap_read_bytes(uintptr_t addr, size_t len, int N,
                     const int* ordered_slots, int ordered_count,
                     const uint8_t* eff_bits,
                     uint8_t* out, bool* absent_out);

// Throttled reader stats line (wraps reader::report()). Call from heartbeat — never per-frame.
void reader_report();
// STABILITY heartbeat: last load()'s total + oracle-walk milliseconds.
double last_restore_ms(); double last_oracle_ms();

// P1 CAPACITY DONATION (the NULL-alloc/reserve-starvation fix): DLL-carved regions donated to a starving
// MtScalable control's reserve list. carve_donation_region: reserve+commit a zeroed region from the arena
// (watermark path, under the carve CS shared with hk_VirtualAlloc) + mark pages committed. note_donated_region:
// register {ctrl,base,size} so every pool-membership consumer (alloc_invariants clause-5, reader walk terminators,
// coherent-full ranges) stays multi-region-correct. in_owned_pool: primary [ctrl+0x90,0x98) OR any donated range.
bool carve_donation_region(size_t size, uintptr_t* out_base);
void note_donated_region(uintptr_t ctrl, uintptr_t base, size_t size);
bool in_owned_pool(uintptr_t ctrl, uintptr_t addr);
int  donated_region_count();
bool donated_region_get(int i, uintptr_t* ctrl, uintptr_t* base, size_t* size);

// FORENSIC (read-only, called only on a alloc_invariants break — never per-frame): compact provenance of the page
// holding addr — which ring slots' dirty bits contain it (ascending frames), baseline/coherent-full/revert-set
// membership, and the last-load source. Separates two failure mechanisms: a break page with no dirty slot in
// [ring-horizon..target] whose coherence demands a write there = an invisible write (a write-watch miss);
// a dirty slot <= target that the source walk rejected = a source-walk bug.
void page_history(uintptr_t addr, char* out, size_t out_len);

} // namespace arena
