// idspine.cpp — birth-stamp identity spine. See idspine.h. SHADOW-only: the table lives in this DLL's
// .bss, the serial is ours, and nothing here writes game memory. It physically cannot change gameplay.
#include "idspine.h"
#include "free_probe.h"
#include "carve_orphan_probe.h"
#include "addr.h"
#include "arena.h"
#include "resim.h"
#include "quarantine.h"
#include "reader.h"
#include "log.h"
#include <MinHook.h>
#include <windows.h>
#include <intrin.h>
#include <cstdint>

namespace idspine {
namespace {

constexpr uintptr_t CARVE_IDA = 0x1404CA650;   // alloc: first-fit free-list walk (REUSE) + carve fallback; ret=block base
constexpr uintptr_t FREE_IDA  = 0x1404CB350;   // free(control, user_ptr); block = user_ptr - *(user_ptr-8)

typedef void* (*carve_fn)(int64_t, int64_t, uint64_t, int64_t);
typedef void  (*free_fn)(int64_t, int64_t);
static carve_fn orig_carve = nullptr;
static free_fn  orig_free  = nullptr;

// ---- the side table (DLL.bss; zero-init) ----
constexpr int      CAP_BITS = 18;            // 256K slots
constexpr uint32_t CAP      = 1u << CAP_BITS;
constexpr int      MAXPROBE = 128;           // bound the probe; degrade (log) rather than spin on a full table

// LIVENESS SPINE slot: serial == generation (ABA/identity), live == current alive bit, birth/death_frame answer
// "alive at frame N?" = birth_frame <= N < death_frame. death_frame==FRAME_NEVER means still alive.
static constexpr LONG FRAME_NEVER = 0x7FFFFFFF;
// last_load: per-load dedup stamp for the Phase-4a object-granular revert walk (a multi-page object reached via
// several of its dirty pages is classified/reverted exactly once). INERT until Phase 4a — pure field, no behavior here.
struct Slot { volatile LONG64 block; volatile LONG64 serial; volatile LONG live; volatile LONG birth_frame; volatile LONG death_frame; volatile LONG size; volatile LONG last_load; };
static Slot g_tab[CAP];                       // 256K * 36B (+size for sub-page provenance; +last_load for the P4 walk)

static volatile LONG64 g_ctr = 0;             // monotonic birth serial (0 reserved => "unknown / never stamped")

// cumulative stats — logged throttled, never per-frame
static volatile LONG64 g_births = 0;          // distinct blocks first-stamped
static volatile LONG64 g_deaths = 0;          // retires of a live block
static volatile LONG64 g_reuses = 0;          // re-stamps of a known block (slab handed back out)
static volatile LONG64 g_live   = 0;          // currently-live blocks (births + reuses-of-dead - deaths)
static volatile LONG64 g_distinct = 0;        // distinct blocks ever inserted (table occupancy; tombstones included)
static volatile LONG64 g_full   = 0;          // probe-run saturations (table pressure signal)

// ---- DEALLOC GUARD (read-before-write) ----
// FUN_1404cb350 frees without reading the block's allocated flag first: it unconditionally re-unlinks the active
// list and re-pushes the free-list, then clears block+0x38 bit0 (the allocated flag). So a DOUBLE-FREE (free() of a
// block whose bit0 is already 0) double-pushes the free-list => CYCLE => FUN_1404CA650's first-fit walk spins =>
// the resim hang. The guard READS block+0x38 bit0 before orig_free(); if already clear, it's a spurious double-free()
// and we skip orig_free() (the first free() already stands). Reads the ENGINE's own ground-truth bit => no false
// positives (free->realloc->free() is fine: carve re-sets bit0). This PREVENTS a corrupt write, never adds state.
static volatile LONG   g_gfg = 1;             // GLOBAL-FREE-GUARD (ported from deleted freewatch.cpp): funnel bad-header decline, ON
static volatile LONG64 g_gfg_declined = 0;
static volatile LONG   g_dealloc_guard = 1;   // ON by default (unconditionally-correct correctness guard)
static volatile LONG64 g_df_skipped    = 0;   // double-frees skipped (the cycle root, counted)

// ---- CLASS-0 DROP NET (the only corpus-proven crash-safe in-arena defender) ----
// FUN_1404cb350 computes mgr = control+0xd8 + (((*(u32*)(block+0x3c)>>2)&0x1f) - 1)*0xa8. A block whose class nibble is 0
// (a page-reverted-to-pre-carve image, alloc_consistency's "class-0 wall") => (0-1) underflow => wrong-manager
// corruption. We DROP such a free() (skip orig_free()) => bounded leak instead of corruption. Gated on engine_enabled
// (class-0 only appears after a page-revert) so baseline is untouched. Read-before-write (read class, then decide).
static volatile LONG   g_class0_net = 1;
static volatile LONG64 g_c0_dropped = 0;

// ---- LINK-COHERENCE GUARD (survival net for the during-replay free-list corruption) ----
// The live crash is FUN_1404cb350 walking a corrupt free-list link during the resim (READ -1): the page-revert + resim
// left the list around a block incoherent (a neighbor pointer is garbage/uncommitted, or reciprocity is broken =
// the lost-unlink). FUN_1404cb350 unlinks via node+0x18(prev)/+0x20(next); FUN_1404cb480 coalesce reads phys neighbors +0x28/+0x30.
// If any is corrupt, orig_free() FAULTS mid-resim — pre-empting the post-resim window where alloc_rethread would
// rebuild. This guard READS those four neighbor links + checks reciprocity before orig_free(); on corruption it
// SKIPS the free() (bounded leak) so the resim survives to PH_POST_LOAD. Skip-shaped (suppresses orig_free(), writes
// nothing) = the principle-safe class (like dealloc-guard); false positives only LEAK (never corrupt). Engine-on
// gated (only a rollback's revert produces this) so normal play is byte-identical.
static volatile LONG   g_link_guard   = 1;
static volatile LONG64 g_link_skipped = 0;

// ---- RECENT-FREE ATTRIBUTION RING (folded from freewatch — idspine already owns the FUN_1404cb350 hook; no 2nd hook) ----
// Names WHO freed a block: immediate caller + the first effect/anim-cluster return address up the (clamped) stack.
// The upstream-of-crash watch (coherence_belt) + the crash logger xref this to attribute the plant's freeing caller.
static constexpr int FR_RING = 16384;
struct FreeRec { uintptr_t node; uintptr_t caller_ida; uintptr_t eff_ida; int frame; };
static FreeRec g_fr[FR_RING];
static volatile LONG g_fr_head = 0;
static inline bool is_eff_ida(uintptr_t ida) { return ida >= 0x140800000ULL && ida < 0x1408A0000ULL; }
static void record_free(uintptr_t node) {
    uintptr_t base = addr::g_base;
    uintptr_t ret0 = (uintptr_t)__builtin_return_address(0);
    uintptr_t caller_ida = (base && ret0 > base) ? (ret0 - base + 0x140000000ULL) : ret0;
    uintptr_t eff_ida = 0;
    if (base) {                                                  // bounded stack-walk, CLAMPED to the committed top
        uintptr_t stack_top = (uintptr_t)__readgsqword(0x08);
        uintptr_t* sp = (uintptr_t*)__builtin_frame_address(0);
        for (int i = 0; i < 64; i++) {
            if ((uintptr_t)(sp + i) + sizeof(uintptr_t) > stack_top) break;
            uintptr_t v = sp[i];
            if (v > base && v < base + 0x1000000) {
                uintptr_t vida = v - base + 0x140000000ULL;
                if (is_eff_ida(vida)) { eff_ida = vida; break; }
            }
        }
    }
    LONG slot = InterlockedIncrement(&g_fr_head) - 1;
    FreeRec& r = g_fr[((unsigned long)slot) % FR_RING];
    r.node = node; r.caller_ida = caller_ida; r.eff_ida = eff_ida; r.frame = resim::current_frame();
}

static inline uint32_t hash_block(uintptr_t b) {
    uint64_t x = (uint64_t)b >> 5;            // allocator blocks are >=0x20-aligned
    x ^= x >> 33; x *= 0xff51afd7ed558ccdULL; x ^= x >> 33;
    return (uint32_t)x & (CAP - 1);
}

// SHADOW write of (block -> next serial, live=1). Lock-free() open addressing. The allocator's per-manager
// critical sections (FUN_1404cb260/FUN_1404cb0b0/FUN_1404cb350 EnterCriticalSection) already serialize free->realloc of any single
// block, so a slot is only ever revived in-place by one thread at a time.
static void put(uintptr_t block, uint32_t size) {
    uint32_t h = hash_block(block);
    for (int i = 0; i < MAXPROBE; i++) {
        uint32_t s = (h + (uint32_t)i) & (CAP - 1);
        LONG64 cur = g_tab[s].block;
        if (cur == (LONG64)block) {                                   // known slab handed back out: new serial
            g_tab[s].serial = _InterlockedIncrement64(&g_ctr);
            g_tab[s].birth_frame = resim::effective_frame();          // re-birth at this frame (replayed frame during resim)
            g_tab[s].death_frame = FRAME_NEVER;
            g_tab[s].size = (LONG)size;                               // refresh extent (reused slab may have a new size-class)
            LONG prev = _InterlockedExchange(&g_tab[s].live, 1);
            _InterlockedIncrement64(&g_reuses);
            if (!prev) _InterlockedIncrement64(&g_live);              // was retired => now live again
            return;
        }
        if (cur == 0) {
            if (_InterlockedCompareExchange64(&g_tab[s].block, (LONG64)block, 0) == 0) {  // claimed a fresh slot
                g_tab[s].serial = _InterlockedIncrement64(&g_ctr);
                g_tab[s].birth_frame = resim::effective_frame();
                g_tab[s].death_frame = FRAME_NEVER;
                g_tab[s].size = (LONG)size;                           // block extent (for sub-page provenance)
                g_tab[s].live = 1;
                _InterlockedIncrement64(&g_births);
                _InterlockedIncrement64(&g_live);
                _InterlockedIncrement64(&g_distinct);
                return;
            }
            if (g_tab[s].block == (LONG64)block) { i--; continue; }   // lost CAS to our own block => re-handle as reuse
        }
    }
    _InterlockedIncrement64(&g_full);          // saturated for this hash run — never spin, just note pressure
}

static void retire(uintptr_t block) {
    uint32_t h = hash_block(block);
    for (int i = 0; i < MAXPROBE; i++) {
        uint32_t s = (h + (uint32_t)i) & (CAP - 1);
        LONG64 cur = g_tab[s].block;
        if (cur == (LONG64)block) {
            g_tab[s].death_frame = resim::effective_frame();         // record when it died (for alive-at-frame-N)
            LONG prev = _InterlockedExchange(&g_tab[s].live, 0);     // tombstone (serial kept => reuse re-stamps it)
            if (prev) { _InterlockedIncrement64(&g_deaths); _InterlockedDecrement64(&g_live); }
            return;
        }
        if (cur == 0) return;                  // empty => block never stamped (pre-init / non-arena)
    }
}

// ---- hooks (SHADOW: read the allocator's own result, write only our table) ----
// LEAN MODE: the birth-stamp SHADOW table (put/retire/record_free()) is pure per-alloc/free() MEASUREMENT — ~7500 ops/sec
// of game alloc traffic (IDSPINE reuses=474k/79s). OFF by default. The crash GUARDS below (dealloc double-free(),
// class-0 net) read the ENGINE's OWN bits (block+0x38/+0x3c), not this table, so they stay fully functional. Arm
// g_idspine_shadow for slab-reuse RE.
static volatile LONG g_idspine_shadow = 1;   // RECORD-FROM-BOOT (coverage raise): stamp births/deaths from process
                                             // start, not just engine-on, so the free-list census is not dominated by
                                             // pre-F5 UNKNOWN blocks. LEAN path only (put/retire = O(1)); the costly
                                             // 64-deep stack walk stays gated behind g_attrib_shadow=0. Watch g_full
                                             // (saturation) in the IDSPINE report; bump CAP_BITS if it climbs.
// LIVENESS SPINE record arm: when the rollback engine is on, the spine must record continuously (it needs birth/death
// history to answer "alive at frame N"). The record is the LEAN path (put/retire = O(1) hash writes + a frame stamp).
// spine_record_on() = the arm condition.
static inline bool spine_record_on() { return g_idspine_shadow || resim::engine_enabled(); }
// ATTRIBUTION stack-walk (record_free()'s 64-deep walk) was the real cost of the old shadow (~the 7500-ops/sec tax),
// not the table write. OFF by default; the lean liveness record does not need it. Arm only for a freer-attribution RE.
static volatile LONG g_attrib_shadow = 0;
static void* hk_carve(int64_t p1, int64_t p2, uint64_t p3, int64_t p4) {
    arena::hook_count_inc(5);   // perf bisection: MtScalable carve (alloc) fires/frame
    // carve_orphan_probe callout pre-reads: idspine owns the one legal hook on FUN_1404ca650 (a 2nd MH_CreateHook fails
    // ALREADY_CREATED — an arm failure seen on an earlier run); the carve-orphan probe rides this hook. See carve_orphan_probe.h.
    uint32_t  a4p_count = 0; uintptr_t a4p_head = 0;
    if ((uintptr_t)p2 > 0x10000) { a4p_count = *(volatile uint32_t*)(p2 + 0x68); a4p_head = *(volatile uintptr_t*)(p2 + 0x58); }
    void* r = orig_carve(p1, p2, p3, p4);
    carve_orphan_probe::post_carve((void*)p2, r, p3, a4p_count, a4p_head, __builtin_return_address(0));
    uintptr_t block = (uintptr_t)r;
    if (spine_record_on() && block > 0x10000 && arena::is_arena_addr(block)) {
        // block extent from the allocator's own header: size_and_inuse@+0x38, (>>1)<<4 = bytes (incl the 0x50 hdr).
        uint32_t bsize = arena::is_committed_addr(block + 0x38)
                       ? (uint32_t)((*(uint32_t*)(block + 0x38) >> 1) << 4) : 0;
        put(block, bsize);
        // STAMP-FRAME CONFIRM (bounded): prove that during resim the spine stamps the REPLAYED frame, not the frozen
        // live counter — the load-bearing assumption the RE flagged. If these are equal, the spine is mis-keyed.
        if (resim::resim_active()) {
            static volatile LONG kc = 0; LONG n = _InterlockedIncrement(&kc);
            if (n <= 6) rblog::write("SPINE-STAMP-FRAME: carve in resim — effective_frame=%d (replayed) vs current_frame=%d (frozen live) => birth stamped at the replayed frame",
                                     resim::effective_frame(), resim::current_frame());
        }
    }
    return r;
}

// ---- DOUBLE-INSERT DETECTOR (torn-save cause-finder, read-only) ----
// Today's hang is the CYCLE/self-loop variant (canonical node+0x20 -> itself), not the map/territory-garbage
// variant. It is a DOUBLE-INSERT: a node pushed onto desc+0x58 while already on it (push X at head twice => X.next=X
// => FUN_1404CA650's guardless first-fit walk spins). The +0x38 inuse guard MISSED it (df_skipped=0) because
// list-membership is the descriptor list, a different field from +0x38. This walks the block's OWN descriptor free()
// list before the free() and reports if the block is already present (about-to-double-insert) or the list is already
// cyclic — with the bloodline (caller, frame, fsr, header coherence). Walk is UNLOCKED + per-node committed-guarded
// (the desc CS at +0x80 is itself reverted during rollback; touching it could corrupt the engine lock). Best-effort:
// a torn read just re-detects next free(). Armed only in/near the rollback window => normal play pays nothing.
static volatile LONG   g_di_detect = 0;   // DEFAULT OFF (perf discipline): the per-free() walk costs during the rollback
                                          // window (engine-on); arm it (Numpad7) only for a focused diagnostic run.
static volatile LONG64 g_di_found  = 0;
static volatile LONG   g_di_logged = 0;

static void detect_double_insert(int64_t manager, uintptr_t block, uintptr_t caller_ida) {
    if (!arena::is_committed_addr(block + 0x3c) || !arena::is_committed_addr(block + 0x38)) return;
    uint32_t flags = *(volatile uint32_t*)(block + 0x3c);
    uint32_t idx   = (flags >> 2) & 0x1f;
    if (idx == 0) return;                                   // class-0 (pre-carve image) is the class0-net's job
    uintptr_t desc = (uintptr_t)manager + 0xD8 + (uintptr_t)(idx - 1) * 0xA8;
    if (!arena::is_arena_addr(desc) || !arena::is_committed_addr(desc + 0x58) ||
        !arena::is_committed_addr(desc + 0x68)) return;     // manager/desc not sane => bail (no crash)

    uintptr_t head = *(volatile uintptr_t*)(desc + 0x58);   // free-list HEAD
    int free_count = *(volatile int32_t*)(desc + 0x68);     // free() count (sanity only)
    const int CAP = 2048;
    uintptr_t cur = head; int steps = 0; bool found = false, cyclic = false;
    while (cur > 0x10000 && arena::is_arena_addr(cur) && arena::is_committed_addr(cur + 0x20)) {
        if (cur == block) { found = true; break; }          // block already on the free() list => double-insert
        if (++steps > CAP) { cyclic = true; break; }        // longer than any real size-class list => a cycle
        cur = *(volatile uintptr_t*)(cur + 0x20);           // follow logical-next
    }
    if (!found && !cyclic) return;                          // normal free() (not yet listed) => silent

    _InterlockedIncrement64(&g_di_found);
    LONG k = _InterlockedIncrement(&g_di_logged);
    if (k <= 96) {
        uint32_t inuse    = *(volatile uint32_t*)(block + 0x38) & 1u;
        uintptr_t selfnext = arena::is_committed_addr(block + 0x20) ? *(volatile uintptr_t*)(block + 0x20) : 0;
        rblog::write("DOUBLE-INSERT[#%ld]: block=0x%llX %s (desc=0x%llX idx=%u head=0x%llX free_count=%d walked=%d) "
                     "| block+0x20(next)=0x%llX inuse(+0x38b0)=%u flags(+0x3c)=0x%X list_state=%u "
                     "| frame=%d resim=%d fsr=%d caller=0x%llX",
            k, (unsigned long long)block,
            found ? (selfnext == block ? "ALREADY-FREELISTED(self-loop)" : "ALREADY-FREELISTED") : "list-ALREADY-CYCLIC",
            (unsigned long long)desc, idx, (unsigned long long)head, free_count, steps,
            (unsigned long long)selfnext, inuse, flags, flags & 3u,
            resim::current_frame(), (int)resim::resim_active(), resim::frames_since_rollback(),
            (unsigned long long)caller_ida);
    }
}

static void hk_free(int64_t p1, int64_t p2) {
    free_probe::Scope _fps;     // free_probe: attribute heavy-dtor cost to our free() path vs cold-cache
    arena::hook_count_inc(1);   // perf bisection: MtScalable free() fires/frame
    reader::set_ctrl((uintptr_t)p1);   // READER: FUN_1404cb350 = free(control, user_ptr) — p1 IS the MtScalable control
                                       // (carve's arg1 is a per-class descriptor, not the control). Idempotent + self-validating; arms early.
    uintptr_t raw = (uintptr_t)p2;
    bool skip = false;
    // GLOBAL-FREE-GUARD (ported from freewatch.cpp on its deletion). The funnel bad-header decline at the FUN_1404cb350 free() leaf. Covers what the gates below cannot:
    // (a) in-arena adj OUT of range (a torn header) — the gates below only run when adj is sane, so a garbage
    // back-offset would fall through to orig_free() = the FUN_1404cb350 garbage-mgr AV;
    // (b) in-arena class nibble in [9,31] (CLASS0-NET only catches ==0);
    // (c) out-of-arena MEM_FREE block double-free() (XAPO/sound-wrapper family: a rollback-reinstated stale
    // refcount re-frees an already-freed OS block) — everything below is inside is_arena_addr(raw).
    // A bad-header free() is always a latent crash (vanilla never produces one); declining = bounded leak of a
    // rollback-stale output-leaf block = GGPO-safe. ctrl+0x90==0 => FUN_1404cb350 no-ops anyway (nothing to guard).
    // A declined free() does not retire()/quarantine (the block was not freed — it stays live).
    if (g_gfg && raw > 0x10000 && resim::engine_enabled() &&
        arena::is_committed_addr((uintptr_t)p1 + 0x90) && *(int64_t*)(p1 + 0x90) != 0) {
        bool decline = false; const char* why = nullptr;
        if (arena::is_arena_addr(raw)) {
            if ((raw & 0xFFF) >= 8) {                          // page-edge-safe: can we read obj-8?
                int64_t adj = *(int64_t*)(raw - 8);            // same read FUN_1404cb350 does next
                if (!(adj > 0 && adj < 0x1000)) { decline = true; why = "in-arena torn back-offset"; }
                else {
                    uint32_t cls = (*(uint32_t*)((raw - (uintptr_t)adj) + 0x3c) >> 2) & 0x1f;
                    if (cls > 8) { decline = true; why = "in-arena class nibble >8 (garbage mgr index)"; }
                    // cls==0 falls through to CLASS0-NET below (same decline, richer attribution)
                }
            }
        } else {
            MEMORY_BASIC_INFORMATION mbi;                      // out-of-arena: bounded VirtualQuery, engine-on only
            if (VirtualQuery((void*)raw, &mbi, sizeof(mbi)) && (mbi.State & MEM_COMMIT) == 0) {
                decline = true; why = "out-of-arena freed block (MEM_FREE double-free)";
            }
        }
        if (decline) {
            LONG64 n = _InterlockedIncrement64(&g_gfg_declined);
            if (n <= 32)
                rblog::write("GLOBAL-FREE-GUARD: declined free obj=0x%llX (%s) control=0x%llX fsr=%d => leak, no AV",
                             (unsigned long long)raw, why, (unsigned long long)(uintptr_t)p1,
                             resim::frames_since_rollback());
            return;                                            // no orig_free(), no retire, no quarantine
        }
    }
    // mirror freewatch's proven guard: in-arena, page-edge-safe back-offset read, sane offset.
    if (raw > 0x10000 && arena::is_arena_addr(raw) && (raw & 0xFFF) >= 8) {
        int64_t adj = *(int64_t*)(raw - 8);
        if (adj > 0 && adj < 0x1000) {
            uintptr_t block = raw - (uintptr_t)adj;
            if (arena::is_arena_addr(block)) {
                // DOUBLE-INSERT DETECTOR (torn-save cause-finder): armed only during resim + the post-rollback window
                // so steady engine-on play and all normal play pay nothing. Read-only.
                if (g_di_detect && resim::engine_enabled() &&
                    (resim::resim_active() || resim::frames_since_rollback() < 300)) {
                    uintptr_t base = addr::g_base;
                    uintptr_t ret0 = (uintptr_t)__builtin_return_address(0);   // game caller of free()
                    uintptr_t caller_ida = (base && ret0 > base) ? (ret0 - base + 0x140000000ULL) : ret0;
                    detect_double_insert(p1, block, caller_ida);
                }
                if (spine_record_on()) { retire(block); if (g_attrib_shadow) record_free(block); }   // LEAN record: retire=O(1); the costly 64-deep stack-walk (record_free()) is gated behind g_attrib_shadow
                // READ-BEFORE-WRITE: block+0x38 bit0 = engine ALLOCATED flag. Clear => already free() => DOUBLE-FREE.
                // PERF: the double-free() (free-list cycle) only arises from a rollback reinstating a freed-but-linked
                // node; pure normal play never double-frees. Gate on engine-on so this per-free() read is vanilla-free().
                if (g_dealloc_guard && resim::engine_enabled() && arena::is_committed_addr(block + 0x38) &&
                    (*(volatile uint32_t*)(block + 0x38) & 1u) == 0) {
                    skip = true;
                    LONG64 n = _InterlockedIncrement64(&g_df_skipped);
                    if (n <= 24)
                        rblog::write("DEALLOC-GUARD: skipped DOUBLE-FREE block=0x%llX (block+0x38=0x%X, bit0=0 already free) "
                                     "=> would double-push the free-list (cycle/hang root). read-before-write held.",
                                     (unsigned long long)block, *(uint32_t*)(block + 0x38));
                }
                // CLASS-0 DROP NET: a free() of a page-reverted-to-pre-carve (class-nibble 0) block underflows FUN_1404cb350's
                // mgr index => wrong-manager corruption. DROP it (bounded leak) instead. Gated on engine_enabled.
                else if (g_class0_net && resim::engine_enabled() && arena::is_committed_addr(block + 0x3c) &&
                         (((*(volatile uint32_t*)(block + 0x3c)) >> 2) & 0x1f) == 0) {
                    skip = true;
                    LONG64 n = _InterlockedIncrement64(&g_c0_dropped);
                    if (n <= 24)
                        rblog::write("CLASS0-NET: dropped free of class-0 block=0x%llX (block+0x3c=0x%X => pre-carve image; "
                                     "cb350 mgr index would underflow). bounded leak, no corruption.",
                                     (unsigned long long)block, *(uint32_t*)(block + 0x3c));
                }
                // LINK-COHERENCE GUARD: FUN_1404cb350/FUN_1404cb480 would walk a corrupt free-list neighbor (the during-replay
                // lost-unlink, the live crash). If any neighbor link is garbage/uncommitted or reciprocity is
                // broken, SKIP the free() so the resim survives (bounded leak); alloc_rethread rebuilds post-resim.
                // FORK-B FALSE-POSITIVE FIX: gated on resim_active() not engine_enabled(). These two reads
                // (block+0x18 then neighbor+0x20) are not atomic w.r.t. the per-class CS (FUN_1404cb350 acquires desc+0x80
                // four ops after entry, where our hook fires). During LIVE play, a concurrent same-class FUN_1404cb350/FUN_1404cb480
                // on another MT worker mutates a neighbor link mid-relink between our two reads => spurious reciprocity
                // break => false-positive skip (a leaked healthy block; ~24/session = the pre-rollback burst, before
                // any rollback can produce real corruption). During resim, suspend::freeze has all workers OS-frozen,
                // so the race is physically impossible and any fire is a genuine lost-unlink. Narrowing to resim_active
                // eliminates the false positives while preserving the guard exactly where the real live crash occurs.
                else if (g_link_guard && resim::resim_active() && arena::is_committed_addr(block + 0x30)) {
                    uintptr_t prev  = *(volatile uintptr_t*)(block + 0x18);
                    uintptr_t next  = *(volatile uintptr_t*)(block + 0x20);
                    uintptr_t pphys = *(volatile uintptr_t*)(block + 0x28);
                    uintptr_t nphys = *(volatile uintptr_t*)(block + 0x30);
                    bool corrupt =
                        (prev  && !arena::is_committed_addr(prev))  ||
                        (next  && !arena::is_committed_addr(next))  ||
                        (pphys && !arena::is_committed_addr(pphys)) ||
                        (nphys && !arena::is_committed_addr(nphys)) ||
                        (prev && arena::is_committed_addr(prev + 0x20) && *(volatile uintptr_t*)(prev + 0x20) != block) ||
                        (next && arena::is_committed_addr(next + 0x18) && *(volatile uintptr_t*)(next + 0x18) != block);
                    if (corrupt) {
                        skip = true;
                        LONG64 n = _InterlockedIncrement64(&g_link_skipped);
                        if (n <= 24)
                            rblog::write("LINK-GUARD: skipped free of block=0x%llX — corrupt free-list neighbor "
                                         "(prev=0x%llX next=0x%llX phys=0x%llX/0x%llX) => cb350/cb480 would walk garbage. "
                                         "bounded leak; survives resim for alloc_rethread.",
                                         (unsigned long long)block, (unsigned long long)prev, (unsigned long long)next,
                                         (unsigned long long)pphys, (unsigned long long)nphys);
                    }
                }
                // REUSE-QUARANTINE: inside the rollback window, DEFER this free() (skip orig_free(); the block
                // stays in-use) so its slab cannot be re-handed-out as a different object — the structural slab-reuse prevention.
                // SHADOW mode measures (still frees); DEFER mode holds. Returns true => we skip orig_free() here.
                if (!skip && quarantine::on_free(p1, p2, block, resim::effective_frame())) skip = true;
            }
        }
    }
    if (!skip) orig_free(p1, p2);                                       // skip only a confirmed double-free() / class-0 / quarantine-deferred
}

} // namespace

void set_di_detect(bool on) { g_di_detect = on ? 1 : 0; }   // arm/disarm the double-insert cause-finder (Numpad7)
bool di_detect() { return g_di_detect != 0; }

bool recent_free(uintptr_t node, uintptr_t* caller_ida, uintptr_t* eff_ida, int* frame) {
    LONG h = g_fr_head;
    for (LONG i = 1; i <= FR_RING; i++) {
        FreeRec& r = g_fr[((unsigned long)(h - i)) % FR_RING];
        if (r.node == node) {
            if (caller_ida) *caller_ida = r.caller_ida;
            if (eff_ida)    *eff_ida    = r.eff_ida;
            if (frame)      *frame      = r.frame;
            return true;
        }
    }
    return false;
}

int64_t stamp_of_block(uintptr_t block) {
    uint32_t h = hash_block(block);
    for (int i = 0; i < MAXPROBE; i++) {
        uint32_t s = (h + (uint32_t)i) & (CAP - 1);
        LONG64 cur = g_tab[s].block;
        if (cur == (LONG64)block) return g_tab[s].serial;
        if (cur == 0) return 0;
    }
    return 0;
}

int64_t stamp_of_object(uintptr_t obj) {
    if (obj <= 0x10000 || !arena::is_arena_addr(obj) || (obj & 0xFFF) < 8) return 0;
    int64_t adj = *(int64_t*)(obj - 8);
    if (adj <= 0 || adj >= 0x1000) return 0;
    return stamp_of_block(obj - (uintptr_t)adj);
}

bool live_at(uintptr_t block) {
    uint32_t h = hash_block(block);
    for (int i = 0; i < MAXPROBE; i++) {
        uint32_t s = (h + (uint32_t)i) & (CAP - 1);
        LONG64 cur = g_tab[s].block;
        if (cur == (LONG64)block) return g_tab[s].live != 0;
        if (cur == 0) return false;
    }
    return false;
}

// Full liveness lookup — birth/death_frame + serial for a block (latest generation). Read-only; SHADOW table only.
bool lookup(uintptr_t block, int* birth_frame, int* death_frame, int64_t* serial) {
    uint32_t h = hash_block(block);
    for (int i = 0; i < MAXPROBE; i++) {
        uint32_t s = (h + (uint32_t)i) & (CAP - 1);
        LONG64 cur = g_tab[s].block;
        if (cur == (LONG64)block) {
            if (birth_frame) *birth_frame = g_tab[s].birth_frame;
            if (death_frame) *death_frame = g_tab[s].death_frame;
            if (serial)      *serial      = g_tab[s].serial;
            return true;
        }
        if (cur == 0) return false;
    }
    return false;
}

int64_t birth_counter() { return g_ctr; }

int snapshot_live(uintptr_t* out, int max) {
    int n = 0;
    for (uint32_t i = 0; i < CAP && n < max; i++) {
        if (g_tab[i].live && g_tab[i].block) out[n++] = (uintptr_t)g_tab[i].block;
    }
    return n;
}

// Sized snapshot for the provenance index (sub-page "dig inside pages"): every live block's {base,size,serial}.
int snapshot_live_sized(uintptr_t* base, uint32_t* size, int64_t* serial, int max) {
    int n = 0;
    for (uint32_t i = 0; i < CAP && n < max; i++) {
        if (g_tab[i].live && g_tab[i].block) {
            base[n]   = (uintptr_t)g_tab[i].block;
            size[n]   = (uint32_t)g_tab[i].size;
            serial[n] = (int64_t)g_tab[i].serial;
            n++;
        }
    }
    return n;
}

// All tracked blocks (live + tombstoned) with frames+serial, for the P4 SHADOW epoch-rebuild validation.
int snapshot_all(uintptr_t* base, int* birth, int* death, int64_t* serial, int max) {
    int n = 0;
    for (uint32_t i = 0; i < CAP && n < max; i++) {
        if (g_tab[i].block) {
            base[n]   = (uintptr_t)g_tab[i].block;
            birth[n]  = (int)g_tab[i].birth_frame;
            death[n]  = (int)g_tab[i].death_frame;
            serial[n] = (int64_t)g_tab[i].serial;
            n++;
        }
    }
    return n;
}

// All tracked blocks (live + tombstoned) with SIZE — the Property-4 object-granular revert substrate. snapshot_all
// omits size, but RESURRECT (a died>N block alive at N) must revert its EXTENT, so the walk needs {base,size,birth,
// death,serial}. Parallels snapshot_live_sized minus the.live gate (tombstoned blocks included). Read-only.
int snapshot_all_sized(uintptr_t* base, uint32_t* size, int* birth, int* death, int64_t* serial, int max) {
    int n = 0;
    for (uint32_t i = 0; i < CAP && n < max; i++) {
        if (g_tab[i].block) {
            base[n]   = (uintptr_t)g_tab[i].block;
            size[n]   = (uint32_t)g_tab[i].size;
            birth[n]  = (int)g_tab[i].birth_frame;
            death[n]  = (int)g_tab[i].death_frame;
            serial[n] = (int64_t)g_tab[i].serial;
            n++;
        }
    }
    return n;
}


void on_frame() {
    static LONG s_tick = 0;
    if ((++s_tick % 600) == 0) { report(); }   // ~ every 10s @60fps; never per-frame
}

void report() {
    // live should ~= distinct - (tombstoned-and-not-reused); births+reuses-deaths is the running live count.
    rblog::write("IDSPINE: serial=%lld births=%lld reuses=%lld deaths=%lld live=%lld distinct=%lld full=%lld df_skipped=%lld class0_dropped=%lld",
        (long long)g_ctr, (long long)g_births, (long long)g_reuses, (long long)g_deaths,
        (long long)g_live, (long long)g_distinct, (long long)g_full, (long long)g_df_skipped, (long long)g_c0_dropped);
}

void init() {
    void* tc = (void*)addr::resolve(CARVE_IDA);
    void* tf = (void*)addr::resolve(FREE_IDA);
    MH_STATUS sc = MH_CreateHook(tc, (void*)&hk_carve, (void**)&orig_carve);
    MH_STATUS sf = MH_CreateHook(tf, (void*)&hk_free,  (void**)&orig_free);
    quarantine::init(orig_free);   // P4 reuse-quarantine shares this single FUN_1404cb350 owner; orig_free() = its flush trampoline
    rblog::write("IDSPINE: birth ca650 @0x%llX %s | death cb350 @0x%llX %s | table %u slots (SHADOW, 0 game writes)",
        (unsigned long long)(uintptr_t)tc, sc == MH_OK ? "OK" : "FAIL",
        (unsigned long long)(uintptr_t)tf, sf == MH_OK ? "OK" : "FAIL", CAP);
}

} // namespace idspine
