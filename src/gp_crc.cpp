// gp_crc.cpp — gameplay-state determinism oracle (the core determinism check). See gp_crc.h.
//
// v1 coverage = scalar gameplay GLOBALS only (RNG + frame counters): pointer-free,
// deterministic, and the core of gameplay determinism (if RNG/counters diverge during
// resim, the fight diverges). Per-class fighter/effect/projectile STATE ranges are added
// via register_range() once classification produces the field-map (which
// offsets are scalar STATE vs embedded pointers / render-contaminated — that exclusion
// IS the field-map). This hashes gameplay state, not render output.

#include "gp_crc.h"
#include "addr.h"
#include "arena.h"
#include "log.h"
#include <windows.h>
#include <MinHook.h>
#include <cstdio>

namespace gp_crc {
namespace {

// gameplay=true: render-UNcontaminated gameplay-logic state; divergence => real determinism break
// (counts toward the alarm CRC). gameplay=false: render/effect-contaminated (e.g. the shared RNG,
// drawn 100+/frame by the render pipeline FUN_1405d4ad0) — divergence is the EXPECTED effect
// re-derivation, logged informationally, not an alarm. (An earlier run proved the shared RNG is
// render-contaminated: first-divergent-draw caller 0x1405D4C47 = render cluster, ~130 draws/frame.)
struct Range { uintptr_t ida; size_t size; const char* label; bool gameplay; };
constexpr int MAX_RANGES = 64;
static Range g_ranges[MAX_RANGES];
static int   g_range_count = 0;

constexpr int GP_RING = 1024;            // power of two; window of recorded frames
constexpr int RNG_CALLER_CAP_FWD = 48;   // mirror of RNG_CALLER_CAP (declared below)
constexpr int NSEG = 19;                  // curated fighter gameplay ranges (the curated field-map + physics seg #19)
constexpr int NSING = 12;                 // authoritative-gameplay singleton CHANNELS (sGameEffect bisected into 0x300 chunks for contaminant localization + sAction + sCharacter)
// SACT-DIFF: raw sAction body captured per record so a diverge can be DIFFED to exact offsets (the
// sdiverge=12+ events are all-or-nothing per rollback with constant CRC pairs = a static pointer-value
// mismatch, per the watchlist "non-arena ptr in the span" prediction — this names the guilty slots
// instead of assuming +0x148). 0x8E0 x 1024 slots = ~2.3MB static; diagnostic build.
constexpr size_t SACT_SPAN = 0x8E0;
struct Slot { int frame; uint32_t crc; uint32_t per[MAX_RANGES]; uint32_t draws;
              uint32_t caller[RNG_CALLER_CAP_FWD]; int caller_n; uint32_t fseg[NSEG]; uint32_t anim_crc; uint32_t bone_crc; uint32_t override_crc; uint32_t dispatch_crc; uint32_t sseg[NSING]; bool valid;
              uint8_t sact_raw[SACT_SPAN]; bool sact_raw_ok; };
static Slot g_ring[GP_RING];

// FIGHTER-STATE coverage — the curated field-map (g_fighter_gp_ranges)
// (~832 scalar bytes, confirmed gp_crc=0). SCALAR gameplay only: FSM core, hitstun/combo
// accumulators (+0x4150), damage-scaling/HSD (+0x6370+). EXCLUDES render mirrors (+0x50/B0/F0/130/
// 18C/1B0-21F, draw_list_cleanup writes them in orig but not resim) and embedded heap pointers
// (+0x688..6A8 — arena addresses that diverge by allocator traffic, not gameplay state). A raw
// [0,0x2000) sweep wrongly included those pointers => the false seg[4] divergence + the unsafe read.
// Max offset 0x63FC (the fighter struct is ~0x8A6C). Walk: sUnit(0x140E17698) lines 7-8, +0x20, bc filter.
struct Seg { size_t a, b; };
static const Seg FIGHTER_SEGS[NSEG] = {
    {0x000,0x028},{0x02C,0x050},{0x070,0x080},{0x0A4,0x0B0},{0x0C0,0x0C8},{0x0E4,0x0F0},
    {0x100,0x130},{0x140,0x18C},{0x196,0x1B0},{0x220,0x278},{0x67C,0x680},{0x6B0,0x72E},
    {0x750,0x838},{0x40E0,0x4138},{0x4150,0x4188},{0x6370,0x6380},{0x6398,0x639C},{0x63DC,0x63E8},{0x63EC,0x63FC}
};
// SEG #19 {0x40E0,0x4138}: PHYSICS/transform integrator band (vel/accel/transform vector). RE-confirmed extent —
// contiguous read FUN_14004ec60 caller reads +0x40E0..+0x4134 as one block;
// RMW accumulator sites +0x40e0(=10), +0x40f8/+0x40fc(*=-1), +0x411c(*=-1). Authoritative-by-continuity (vel[N+1]
// integrates from vel[N]) => must RESTORE. Was the biggest oracle/seed gap: blind revert
// protected it only by accident; under revert-only-seed a momentum desync here would be silent without this channel.
// (No 0x40C0 prefix; reads start at +0x40E0.)
static long long g_fdiverge = 0;
static long long g_animdiverge = 0;   // anim-layer accumulator channel divergences
static long long g_bonediverge = 0;     // bone-state spring-quat accumulator channel
static long long g_overridediverge = 0; // override/additive-layer recurrent-id channel
static long long g_dispatchdiverge = 0; // scheduler dispatch-group count/cap channel

// AUTHORITATIVE-GAMEPLAY SINGLETONS (oracle-coverage extension).
// Each is a single-instance.data-rooted structure: deref the root, confirm vtable@+0 (identity),
// CRC the curated authoritative-scalar ranges pointer-aware. PARALLEL mechanism (own DIVERGE channel),
// not folded into the combined globals CRC. Ranges are CONSERVATIVE (embedded-pointer windows + entity
// tails carved out, deferred to runtime). Embedded ptrs inside the ranges are arena objects => the
// arena-skip in crc_range_ptr_aware handles them.
struct Singleton { const char* name; uintptr_t root_ida; uintptr_t vtable_ida; Seg ranges[3]; int nr; };
static const Singleton SINGLETONS[NSING] = {
    // sGameEffect [0,0x1D50) BISECTED into 0x300 chunks to localize the contaminant (DIVERGED=6, a
    // per-frame-derived field — not camera (RE'd): it's a transient effect-spawn-command
    // queue @[+0x140,+0x1944), a snapshot-timing artifact, not the camera. The real sCamera (root DAT_140E17930,
    // 0xD80) has NO field here and does not consume RNG.) Carve the chunk.
    { "sGE@0000", 0x140D46470ull, 0x140A87E40ull, {{0x0000,0x0300}}, 1 },
    { "sGE@0300", 0x140D46470ull, 0x140A87E40ull, {{0x0300,0x0600}}, 1 },
    { "sGE@0600", 0x140D46470ull, 0x140A87E40ull, {{0x0600,0x0900}}, 1 },
    { "sGE@0900", 0x140D46470ull, 0x140A87E40ull, {{0x0900,0x0C00}}, 1 },
    { "sGE@0C00", 0x140D46470ull, 0x140A87E40ull, {{0x0C00,0x0F00}}, 1 },
    { "sGE@0F00", 0x140D46470ull, 0x140A87E40ull, {{0x0F00,0x1200}}, 1 },
    { "sGE@1200", 0x140D46470ull, 0x140A87E40ull, {{0x1200,0x1500}}, 1 },
    { "sGE@1500", 0x140D46470ull, 0x140A87E40ull, {{0x1500,0x1800}}, 1 },
    { "sGE@1800", 0x140D46470ull, 0x140A87E40ull, {{0x1800,0x1B00}}, 1 },
    { "sGE@1B00", 0x140D46470ull, 0x140A87E40ull, {{0x1B00,0x1D50}}, 1 },
    { "sAction",  0x140D47E68ull, 0x140A92D00ull, {{0x000,0x08E0}},  1 },
    { "sCharacter",0x140D44A70ull,0x140A6FC70ull, {{0x000,0x0040},{0x600,0x2600}}, 2 },
};
static long long g_sdiverge[NSING] = {0};

// RNG-DRAW COUNTER — hooks the RNG primitive FUN_1404600f0(uint* state) (xorshift128, size 47,
// MinHook-safe) and counts draws against the MAIN RNG state (0x140D765D8 = what we hash). The
// per-frame draw count, compared orig-vs-resim, discriminates the determinism break: COUNT differs
// => resim ran a different number of RNG consumers (a resim skip dropped/added one);
// COUNT matches but value differs => a different upstream/seed. Pinpoints the cause.
typedef void (*rng_draw_t)(uint32_t* state);
static rng_draw_t       orig_rng_draw = nullptr;
static constexpr uintptr_t RNG_DRAW_IDA = 0x1404600F0ULL;
static volatile LONG    g_rng_draws = 0;        // draws to the main RNG since the last frame boundary
static uintptr_t        g_rng_state_addr = 0;   // resolved &DAT_140d765d8

// Per-frame caller capture: the IDA addr of each RNG-draw's caller (the consumer). Comparing the
// orig vs resim caller SEQUENCE pinpoints the exact consumer that runs differently in resim — the
// determinism culprit — in one run (not just "count differs").
constexpr int RNG_CALLER_CAP = RNG_CALLER_CAP_FWD;
static uint32_t g_rng_caller[RNG_CALLER_CAP];   // RVA of each RNG-draw's caller this frame
static volatile LONG g_rng_caller_n = 0;
static uintptr_t g_mod_base = 0;                // module base for IDA rebase

// DETERMINISM CANARY (always-on; GGPO-synctest / rr-match-check, adapted) — its OWN draw counter so it never
// touches gp_crc's armed path. Records forward-play RNG-draw-count per frame; re-checks during resim. A mismatch =
// resim pulled a different number of RNG draws than forward play => the replay DIVERGED at that frame (the earliest,
// cheapest signal of an ordering/nondeterminism divergence — converts a "crash 137 frames later" into "DIVERGED at
// frame N"). Cost = 1 interlocked inc/draw + 1 exchange + 1 ring write per frame. Cheap enough to leave ON forever.
static volatile LONG g_canary_draws = 0;
static volatile LONG g_canary_render_draws = 0;        // draws from the RENDER cluster (0x1405D4xxx; render-contaminated per an earlier run, confirmed by CANARY-WHO 0x1405D4C47/CBB) — EXPECTED to differ in resim => counted separately, never alarmed
static constexpr int CANARY_RING = 4096;               // frames of history (~68s @60fps) — a rollback target is always within window
static constexpr int CANARY_CALLERS = 64;              // per-frame RNG-caller RVAs (draws run 4-40/frame; cap = LOUD truncation)
static uint32_t g_canary_cur[CANARY_CALLERS];          // current frame's callers (indexed by the canary counter)
static struct { int frame; uint32_t draws; uint8_t valid; uint8_t ncall; uint32_t callers[CANARY_CALLERS]; } g_canary[CANARY_RING];
static volatile LONG64 c_canary_diverged = 0, c_canary_checks = 0;
static int g_canary_last_div_frame = -1;
// RENDER CANARY (confirmation channel) — records the render-cluster draw count per frame, compares in resim.
// NON-alarming (render is EXPECTED to diverge — pure fn of gameplay, benign, self-heals). Its purpose is to
// CONFIRM the render-divergence-debris theory: if RENDER-DIVERGED fires and the wild-pointer crashes (e.g.
// 0x1408D27C9, an in-arena-uncommitted deref in particle/trail render code) follow render-divergent frames,
// the theory is proven — and the fix is the render-algebra (make render pointers domain-valid-or-null so
// divergence stays benign), not making render deterministic.
static struct { int frame; uint32_t draws; uint8_t valid; } g_canary_r[CANARY_RING];
static volatile LONG64 c_render_diverged = 0;
static int g_render_last_div_frame = -1;

static void hk_rng_draw(uint32_t* state) {
    if ((uintptr_t)state == g_rng_state_addr) {
        uintptr_t cret = (uintptr_t)__builtin_return_address(0);
        uint32_t rva = (g_mod_base && cret >= g_mod_base) ? (uint32_t)(cret - g_mod_base) : 0xFFFFFFFFu;
        // RENDER-CLUSTER FILTER: IDA 0x1405D4000-0x1405D5000 draws are render-pipeline consumers (proven
        // render-contaminated; render runs differently during resim BY DESIGN). Excluded from the gameplay
        // canary so it measures GAMEPLAY determinism cleanly; tallied separately for visibility.
        if (rva >= 0x5D4000u && rva < 0x5D5000u) { InterlockedIncrement(&g_canary_render_draws); }
        else {
            LONG cn = InterlockedIncrement(&g_canary_draws); // gameplay-canary counter
            if (cn <= CANARY_CALLERS) g_canary_cur[cn - 1] = rva;
        }
        LONG n = InterlockedIncrement(&g_rng_draws);
        if (n <= RNG_CALLER_CAP) {
            uintptr_t ret = (uintptr_t)__builtin_return_address(0);
            g_rng_caller[n - 1] = (g_mod_base && ret >= g_mod_base)
                ? (uint32_t)(ret - g_mod_base)   // RVA; IDA = 0x140000000 + rva
                : 0xFFFFFFFFu;                    // external/unknown caller
        }
    }
    orig_rng_draw(state);
}

static long long g_record = 0, g_check = 0, g_match = 0, g_diverge = 0, g_miss = 0;
static volatile LONG64 g_rng_rederive = 0;   // render-contaminated range divergences (expected, informational)
static int g_last_div_frame = -1;
static const char* g_last_div_label = "none";

static bool readable(uintptr_t a, size_t n) {
    if (!a || !n) return false;
    MEMORY_BASIC_INFORMATION mbi;
    if (!VirtualQuery((void*)a, &mbi, sizeof(mbi))) return false;
    if (mbi.State != MEM_COMMIT) return false;
    DWORD p = mbi.Protect & 0xFF;
    if (!(p == PAGE_READONLY || p == PAGE_READWRITE || p == PAGE_EXECUTE_READ ||
          p == PAGE_EXECUTE_READWRITE || p == PAGE_WRITECOPY || p == PAGE_EXECUTE_WRITECOPY))
        return false;
    uintptr_t region_end = (uintptr_t)mbi.BaseAddress + mbi.RegionSize;
    return (a + n) <= region_end;
}

// Standard CRC-32 (poly 0xEDB88320), un-finalize/refinalize so calls chain.
static uint32_t crc32_acc(uint32_t crc, const uint8_t* data, size_t len) {
    crc = ~crc;
    for (size_t i = 0; i < len; i++) {
        crc ^= data[i];
        for (int k = 0; k < 8; k++)
            crc = (crc >> 1) ^ (0xEDB88320u & (uint32_t)(-(int32_t)(crc & 1)));
    }
    return ~crc;
}

// Combined CRC over GAMEPLAY-LOGIC ranges only (the alarm); per-range CRCs (all ranges,
// incl. render-contaminated) into per_out for diagnosis.
static uint32_t compute(uint32_t* per_out) {
    uint32_t combined = 0;
    for (int i = 0; i < g_range_count; i++) {
        uintptr_t a = addr::resolve(g_ranges[i].ida);
        uint32_t rc = readable(a, g_ranges[i].size)
                          ? crc32_acc(0, (const uint8_t*)a, g_ranges[i].size)
                          : 0u;
        per_out[i] = rc;
        if (g_ranges[i].gameplay)   // Only gameplay-logic ranges feed the alarm CRC
            combined = crc32_acc(combined, (const uint8_t*)&rc, sizeof(rc));
    }
    return combined;
}

// CRC a curated range, skipping 8-byte slots that hold an ARENA POINTER. Embedded heap pointers
// (cModel +0x100, gt_c objects +0x6B0...) diverge in resim because the ALLOCATOR is non-deterministic
// (different addresses) — that is not a gameplay break, it is the allocator-non-determinism the burn
// targets. Skipping arena-pointer slots makes the oracle measure pure scalar gameplay determinism.
// (A scalar that happens to fall in the arena range is harmlessly skipped — costs sensitivity, never
// a false alarm. Two-float slots reinterpret far above the arena range, so they are kept.)
static uint32_t crc_range_ptr_aware(uint32_t crc, uintptr_t base, size_t a, size_t b) {
    size_t off = a;
    while (off + 8 <= b) {
        uintptr_t v = *(uintptr_t*)(base + off);
        if (!arena::is_arena_addr(v))
            crc = crc32_acc(crc, (const uint8_t*)(base + off), 8);
        off += 8;
    }
    if (off < b)
        crc = crc32_acc(crc, (const uint8_t*)(base + off), b - off);
    return crc;
}

// Combined per-segment CRC over all live fighters' gameplay state (render holes + embedded pointers
// excluded). Deterministic walk (sUnit lines 7-8, +0x20 next, bone-count filter) => orig-vs-resim
// comparable. seg_out[s] chained across every fighter so a divergence in any fighter shows in segment s.
static void compute_fighter_segs(uint32_t seg_out[NSEG]) {
    for (int s = 0; s < NSEG; s++) seg_out[s] = 0;
    uintptr_t sunit_p = addr::resolve(0x140E17698);
    if (!sunit_p) return;
    uintptr_t sunit = *(uintptr_t*)sunit_p;
    if (!sunit || !arena::is_committed_addr(sunit)) return;
    for (int line = 7; line <= 8; line++) {
        uintptr_t ent = *(uintptr_t*)(sunit + 0x58 + (uintptr_t)line * 0x30);
        int walk = 0;
        while (ent && walk < 16 && arena::is_committed_addr(ent)) {
            uint32_t bc = *(uint32_t*)(ent + 0x530);   // bone count — fighter filter (1..300)
            // Guard the full curated span (offsets reach 0x63FC) across its pages before any read —
            // the prior crash was a 7.4KB sweep into raced/uncommitted memory.
            bool span_ok = arena::is_committed_addr(ent + 0x2000) && arena::is_committed_addr(ent + 0x4000) &&
                           arena::is_committed_addr(ent + 0x6000) && arena::is_committed_addr(ent + 0x63FF);
            if (bc != 0 && bc <= 300 && span_ok) {
                for (int s = 0; s < NSEG; s++)
                    seg_out[s] = crc_range_ptr_aware(seg_out[s], ent, FIGHTER_SEGS[s].a, FIGHTER_SEGS[s].b);
            }
            ent = *(uintptr_t*)(ent + 0x20);
            walk++;
        }
    }
}

// ANIM-LAYER SLOT accumulator channel (confirmed map).
// Per slot (base fighter+0x560, stride 0x180, count *(u32*)(fighter+0x554) capped 16 per FUN_1405291e0), CRC
// only the SEED ranges: SEED_SCALAR config (+0x08 gate, +0x10 mode, +0x14 crossfade-src, +0x40 dur, +0x48 weight,
// +0x54 clamp, +0x58 loop, +0x5c rate, +0x6c.. easing cfg, +0x168) and SEED_ACCUMULATOR (+0x0a/+0x0c flags,
// +0x1c last-incr, +0x44 countdown, +0x4c CURSOR). EXCLUDED (DERIVE, re-derived by one anim tick): +0x18/+0x50/
// +0x60/+0x64/+0x68/+0x80../event masks. EXCLUDED (POINTER, relocate): +0x120/+0x160/+0x170/+0x178. ptr-aware
// skips any arena ptr that slips in. The whole [0x560,0x1d60) anim region was an oracle GAP (FIGHTER_SEGS
// stop at 0x63FC and never deref). Mirrors compute_fighter_segs walk (sUnit lines 7-8, bone-count filter).
static const Seg ANIM_SEED[] = {
    {0x08,0x18},{0x1c,0x20},{0x40,0x50},{0x54,0x60},{0x6c,0x80},{0x168,0x16c}
};
static uint32_t compute_anim_crc() {
    uint32_t crc = 0;
    uintptr_t sunit_p = addr::resolve(0x140E17698);
    if (!sunit_p) return 0;
    uintptr_t sunit = *(uintptr_t*)sunit_p;
    if (!sunit || !arena::is_committed_addr(sunit)) return 0;
    for (int line = 7; line <= 8; line++) {
        uintptr_t ent = *(uintptr_t*)(sunit + 0x58 + (uintptr_t)line * 0x30);
        int walk = 0;
        while (ent && walk < 16 && arena::is_committed_addr(ent)) {
            uint32_t bc = *(uint32_t*)(ent + 0x530);   // bone count — fighter filter
            // anim slots live in [0x560, 0x1d60) for the 16-slot cap; guard the page span before reading.
            if (bc != 0 && bc <= 300 && arena::is_committed_addr(ent + 0x560) && arena::is_committed_addr(ent + 0x2000)) {
                uint32_t n = *(uint32_t*)(ent + 0x554);   // active slot count
                if (n > 16) n = 16;                        // hard cap (FUN_1405291e0)
                for (uint32_t i = 0; i < n; i++) {
                    uintptr_t slot = ent + 0x560 + (uintptr_t)i * 0x180;
                    for (size_t k = 0; k < sizeof(ANIM_SEED) / sizeof(ANIM_SEED[0]); k++)
                        crc = crc_range_ptr_aware(crc, slot, ANIM_SEED[k].a, ANIM_SEED[k].b);
                }
            }
            ent = *(uintptr_t*)(ent + 0x20);
            walk++;
        }
    }
    return crc;
}

// BONE-STATE spring-damper accumulator channel (confirmed FUN_140528d30: +0x70/+0x80/+0x90 smoothed
// quats are recurrent spring dampers that read their own prev value; +0xA0/A1/A2 control). Deref *(f+0x538), count
// *(u32*)(f+0x530) bones, stride 0xC0; CRC [0x60,0xA4) per bone (incl +0x60 source pose — class settled empirically
// by the long run: if DERIVE it re-derives clean under faithful input, if AC a mis-restore is NAMED). ptr-aware.
static uint32_t compute_bone_crc() {
    uint32_t crc = 0;
    uintptr_t sp = addr::resolve(0x140E17698); if (!sp) return 0;
    uintptr_t su = *(uintptr_t*)sp; if (!su || !arena::is_committed_addr(su)) return 0;
    for (int line = 7; line <= 8; line++) {
        uintptr_t ent = *(uintptr_t*)(su + 0x58 + (uintptr_t)line * 0x30);
        int walk = 0;
        while (ent && walk < 16 && arena::is_committed_addr(ent)) {
            uint32_t bc = *(uint32_t*)(ent + 0x530);
            if (bc != 0 && bc <= 300 && arena::is_committed_addr(ent + 0x538)) {
                uintptr_t ba = *(uintptr_t*)(ent + 0x538);
                if (ba && arena::is_committed_addr(ba) && arena::is_committed_addr(ba + (uintptr_t)bc * 0xC0 - 1)) {
                    for (uint32_t b = 0; b < bc; b++)
                        crc = crc_range_ptr_aware(crc, ba + (uintptr_t)b * 0xC0, 0x60, 0xA4);
                }
            }
            ent = *(uintptr_t*)(ent + 0x20); walk++;
        }
    }
    return crc;
}

// OVERRIDE/additive-layer recurrent-id channel (confirmed FUN_140528d30 reads entry+0x00 from the prior frame
// to match-and-invalidate; alloc FUN_1405686702). Deref *(f+0x11B0), count *(u32*)(f+0x530)&0xff, stride 0x40;
// CRC the recurrent fields entry+0x00 (layer-owner-id) + entry+0x04 (flags; bit 0x20 survives the per-frame rebuild)
// = [0x00,0x08). The +0x10..0x3F payload is per-frame DERIVE (rebuilt), excluded.
static uint32_t compute_override_crc() {
    uint32_t crc = 0;
    uintptr_t sp = addr::resolve(0x140E17698); if (!sp) return 0;
    uintptr_t su = *(uintptr_t*)sp; if (!su || !arena::is_committed_addr(su)) return 0;
    for (int line = 7; line <= 8; line++) {
        uintptr_t ent = *(uintptr_t*)(su + 0x58 + (uintptr_t)line * 0x30);
        int walk = 0;
        while (ent && walk < 16 && arena::is_committed_addr(ent)) {
            uint32_t bc = *(uint32_t*)(ent + 0x530);
            uint32_t n = bc & 0xff;
            if (bc != 0 && bc <= 300 && n && arena::is_committed_addr(ent + 0x11B0)) {
                uintptr_t ob = *(uintptr_t*)(ent + 0x11B0);
                if (ob && arena::is_committed_addr(ob) && arena::is_committed_addr(ob + (uintptr_t)n * 0x40 - 1)) {
                    for (uint32_t e = 0; e < n; e++)
                        crc = crc_range_ptr_aware(crc, ob + (uintptr_t)e * 0x40, 0x00, 0x08);
                }
            }
            ent = *(uintptr_t*)(ent + 0x20); walk++;
        }
    }
    return crc;
}

// DISPATCH-GROUP count/cap accumulator channel (confirmed FUN_14051bde0 count++ on append; only the dtor
// zeros it => true cross-frame accumulator, not a per-frame reset). scheduler+0xC50, stride 0x30, 64 groups; CRC
// group+0x8 (count) + 0xC (cap) + 0x10 (owns-flag) = [0x08,0x11). Excludes group+0x18 (entity-ptr array = BYID).
static uint32_t compute_dispatch_crc() {
    uint32_t crc = 0;
    uintptr_t sp = addr::resolve(0x140E17698); if (!sp) return 0;
    uintptr_t su = *(uintptr_t*)sp; if (!su || !arena::is_committed_addr(su)) return 0;
    if (!arena::is_committed_addr(su + 0xC50) || !arena::is_committed_addr(su + 0xC50 + 64 * 0x30 - 1)) return 0;
    for (int g = 0; g < 64; g++)
        crc = crc_range_ptr_aware(crc, su + 0xC50 + (uintptr_t)g * 0x30, 0x08, 0x11);
    return crc;
}

// Per-singleton authoritative-scalar CRC (parallel to compute_fighter_segs). For each singleton:
// resolve the .data root, deref, confirm the instance vtable@+0 (identity), guard the span, CRC the
// curated ranges pointer-aware. out[i]=0 if absent/unconfirmed (a 0->nonzero transition won't false-fire
// because both record and check see the same absence-or-presence deterministically).
static void compute_singleton_segs(uint32_t out[NSING]) {
    for (int i = 0; i < NSING; i++) {
        out[i] = 0;
        const Singleton& sg = SINGLETONS[i];
        uintptr_t rootp = addr::resolve(sg.root_ida);
        if (!rootp || !readable(rootp, 8)) continue;
        uintptr_t root = *(uintptr_t*)rootp;
        if (!root || !arena::is_committed_addr(root) || !readable(root, 8)) continue;
        if (*(uintptr_t*)root != addr::resolve(sg.vtable_ida)) continue;   // identity: vtable@+0
        size_t maxend = 0;
        for (int r = 0; r < sg.nr; r++) if (sg.ranges[r].b > maxend) maxend = sg.ranges[r].b;
        if (maxend && !arena::is_committed_addr(root + maxend - 1)) continue;  // span guard
        uint32_t c = 0;
        for (int r = 0; r < sg.nr; r++)
            c = crc_range_ptr_aware(c, root, sg.ranges[r].a, sg.ranges[r].b);
        out[i] = c;
    }
}

// sAction base via the exact same resolution+identity gates as compute_singleton_segs (index 10).
static uintptr_t resolve_saction() {
    const Singleton& sg = SINGLETONS[10];   // "sAction"
    uintptr_t rootp = addr::resolve(sg.root_ida);
    if (!rootp || !readable(rootp, 8)) return 0;
    uintptr_t root = *(uintptr_t*)rootp;
    if (!root || !arena::is_committed_addr(root) || !readable(root, 8)) return 0;
    if (*(uintptr_t*)root != addr::resolve(sg.vtable_ida)) return 0;
    if (!arena::is_committed_addr(root + SACT_SPAN - 1)) return 0;
    return root;
}

} // anonymous namespace

void register_range(uintptr_t ida, size_t size, const char* label) {
    register_range_ex(ida, size, label, true);   // default: gameplay-logic (alarming)
}
void register_range_ex(uintptr_t ida, size_t size, const char* label, bool gameplay) {
    if (g_range_count < MAX_RANGES)
        g_ranges[g_range_count++] = { ida, size, label, gameplay };
}

void init() {
    for (int i = 0; i < GP_RING; i++) { g_ring[i].frame = -1; g_ring[i].valid = false; }
    // v1: scalar gameplay globals (deterministic, pointer-free).
    // RNG is RENDER-CONTAMINATED (an earlier run: drawn ~130x/frame by the render pipeline FUN_1405d4ad0;
    // diverges by expected effect re-derivation) => gameplay=false, informational only, not an alarm.
    register_range_ex(0x140D765D8, 16, "rng[render-contaminated]", false);
    register_range_ex(0x140E1B708, 8,  "frame_counter_1", true);   // gameplay-logic
    register_range_ex(0x140E1C008, 8,  "frame_counter_2", true);   // gameplay-logic
    // TODO(field-map): add render-UNcontaminated fighter gameplay fields (logical pos/health/FSM)
    // as the true gameplay-determinism coverage. The shared RNG cannot serve (contaminated).
    // RNG-draw counter hook (MH_Initialize already done in init_thread before this).
    g_rng_state_addr = addr::resolve(0x140D765D8);
    g_mod_base = addr::g_base;   // for IDA-rebasing draw callers (IDA = 0x140000000 + RVA)
    void* t = (void*)addr::resolve(RNG_DRAW_IDA);
    if (MH_CreateHook(t, (void*)&hk_rng_draw, (void**)&orig_rng_draw) == MH_OK &&
        MH_EnableHook(t) == MH_OK) {
        rblog::write("GP-CRC: RNG-draw counter hooked @0x%llX (state=0x%llX)",
                     (unsigned long long)t, (unsigned long long)g_rng_state_addr);
    } else {
        rblog::write("GP-CRC: WARNING — RNG-draw hook failed; draw-count divergence unavailable");
    }
    rblog::write("GP-CRC: oracle init — %d scalar ranges (v1=globals; extend per-class via field-map)",
                 g_range_count);
}

static volatile bool g_off = true;      // default OFF (perf): the per-frame determinism ORACLE is a PROBE (several ms/frame); F4 arms it for RE
void set_off(bool v) { g_off = v; }
bool is_off() { return g_off; }

// CANARY — always-on, not gated by g_off. Forward play: stamp this frame's draw count + reset the boundary.
void canary_record(int frame) {
    uint32_t rdc = (uint32_t)InterlockedExchange(&g_canary_render_draws, 0);   // RENDER CANARY: record, don't just reset
    { auto& rs = g_canary_r[(unsigned)frame & (CANARY_RING - 1)]; rs.frame = frame; rs.draws = rdc; rs.valid = 1; }
    uint32_t d = (uint32_t)InterlockedExchange(&g_canary_draws, 0);
    auto& s = g_canary[(unsigned)frame & (CANARY_RING - 1)];
    s.frame = frame; s.draws = d; s.valid = 1;
    s.ncall = (uint8_t)(d < CANARY_CALLERS ? d : CANARY_CALLERS);
    for (int i = 0; i < s.ncall; i++) s.callers[i] = g_canary_cur[i];
}
// Resim: this replayed frame's draw count vs the recorded forward value. First divergence per rollback = the signal.
void canary_check(int frame) {
    uint32_t rdc = (uint32_t)InterlockedExchange(&g_canary_render_draws, 0);   // RENDER CANARY confirmation channel
    { auto& rs = g_canary_r[(unsigned)frame & (CANARY_RING - 1)];
      if (rs.valid && rs.frame == frame && rs.draws != rdc) {
          InterlockedIncrement64(&c_render_diverged);
          if (g_render_last_div_frame != frame) { g_render_last_div_frame = frame;
              bool rw = rblog::is_suppressed(); rblog::suppress(false);
              rblog::write("RENDER-DIVERGED frame=%d: resim %u render-draws vs forward %u (EXPECTED/benign — render is a pure fn of deterministic gameplay). Confirmation channel: a wild-pointer crash within ~150f of a RENDER-DIVERGED = render-divergence debris ⇒ the render-algebra fix (domain-valid-or-null pointers), NOT render determinism.",
                           frame, rdc, rs.draws);
              rblog::suppress(rw); } } }
    uint32_t d = (uint32_t)InterlockedExchange(&g_canary_draws, 0);
    auto& s = g_canary[(unsigned)frame & (CANARY_RING - 1)];
    InterlockedIncrement64(&c_canary_checks);
    if (!s.valid || s.frame != frame) return;           // no recorded original => silent (safe, like gp_crc)
    if (s.draws != d) {
        InterlockedIncrement64(&c_canary_diverged);
        if (g_canary_last_div_frame != frame) {          // once per divergent frame (first is what matters)
            g_canary_last_div_frame = frame;
            bool w = rblog::is_suppressed(); rblog::suppress(false);
            rblog::write("CANARY-DIVERGED frame=%d: resim pulled %u GAMEPLAY RNG draws, forward pulled %u (render-cluster draws filtered) — the REPLAY diverged HERE (earliest signal; a crash N frames later is downstream of THIS). The felt determinism break, localized.",
                         frame, d, s.draws);
            // The WHO: multiset-diff resim callers vs forward callers — the RVAs that drew extra/missing are the
            // divergent code site. IDA addr = 0x140000000 + rva. Compact: count per distinct RVA on each side.
            uint32_t rn = (uint32_t)(d < CANARY_CALLERS ? d : CANARY_CALLERS);
            for (uint32_t pass = 0; pass < 2; pass++) {          // pass0: resim-extra, pass1: forward-only
                const uint32_t* A  = pass ? s.callers : g_canary_cur; uint32_t an = pass ? s.ncall : rn;
                const uint32_t* B  = pass ? g_canary_cur : s.callers; uint32_t bn = pass ? rn : s.ncall;
                for (uint32_t i = 0; i < an; i++) {
                    uint32_t rva = A[i]; if (rva == 0) continue;
                    int ca = 0, cb = 0; bool first = true;
                    for (uint32_t j = 0; j < i; j++) if (A[j] == rva) { first = false; break; }
                    if (!first) continue;                        // report each distinct RVA once
                    for (uint32_t j = 0; j < an; j++) if (A[j] == rva) ca++;
                    for (uint32_t j = 0; j < bn; j++) if (B[j] == rva) cb++;
                    if (ca > cb)
                        rblog::write("  CANARY-WHO: %s caller IDA=0x%llX x%d (vs %d) — the divergent draw site",
                                     pass ? "FORWARD-only" : "RESIM-extra", 0x140000000ULL + rva, ca, cb);
                }
            }
            if (d > CANARY_CALLERS || s.draws > CANARY_CALLERS)
                rblog::write("  CANARY-WHO: caller list TRUNCATED (draws %u/%u > cap %d) — raise CANARY_CALLERS", d, s.draws, CANARY_CALLERS);
            rblog::suppress(w);
        }
    }
}
void canary_report() {
    if (!c_canary_checks) return;
    bool w = rblog::is_suppressed(); rblog::suppress(false);
    rblog::write("CANARY: checks=%lld GAMEPLAY-diverged=%lld (last f%d) | RENDER-diverged=%lld (last f%d) — GAMEPLAY 0 = sim replay deterministic (proven); RENDER>0 = render diverges (EXPECTED/benign; the wild-pointer crash class if it leaves a pointer to a dead object => render-algebra fix)",
                 (long long)c_canary_checks, (long long)c_canary_diverged, g_canary_last_div_frame,
                 (long long)c_render_diverged, g_render_last_div_frame);
    rblog::suppress(w);
}

void record(int frame) {
    if (g_off || g_range_count == 0) return;
    uint32_t per[MAX_RANGES];
    uint32_t c = compute(per);
    Slot& s = g_ring[(unsigned)frame & (GP_RING - 1)];
    s.frame = frame; s.crc = c; s.valid = true;
    compute_fighter_segs(s.fseg);   // FIGHTER-STATE snapshot
    s.anim_crc = compute_anim_crc();   // ANIM-LAYER accumulator channel (confirmed map)
    s.bone_crc = compute_bone_crc();       // bone-state spring-quat accumulator
    s.override_crc = compute_override_crc(); // override/additive-layer recurrent-id
    s.dispatch_crc = compute_dispatch_crc(); // scheduler dispatch-group count/cap
    compute_singleton_segs(s.sseg); // AUTHORITATIVE-GAMEPLAY SINGLETONS snapshot (oracle-coverage extension)
    {   // SACT-DIFF raw capture (diffed to exact offsets when the sAction channel diverges)
        uintptr_t sact = resolve_saction();
        s.sact_raw_ok = (sact != 0);
        if (sact) memcpy(s.sact_raw, (const void*)sact, SACT_SPAN);
    }
    for (int i = 0; i < g_range_count; i++) s.per[i] = per[i];
    uint32_t draws = (uint32_t)InterlockedExchange(&g_rng_draws, 0);   // RNG draws this frame; reset boundary
    s.draws = draws;
    int nc = (int)(draws < (uint32_t)RNG_CALLER_CAP ? draws : (uint32_t)RNG_CALLER_CAP);
    s.caller_n = nc;
    for (int i = 0; i < nc; i++) s.caller[i] = g_rng_caller[i];
    g_record++;
    if ((g_record % 1800) == 0) dump_stats();   // ~30s heartbeat so divergence rate is visible
}

void check(int frame) {
    if (g_off || g_range_count == 0) return;
    uint32_t per[MAX_RANGES];
    uint32_t c = compute(per);
    uint32_t resim_draws = (uint32_t)InterlockedExchange(&g_rng_draws, 0);   // RNG draws this resim frame
    g_check++;
    Slot& s = g_ring[(unsigned)frame & (GP_RING - 1)];
    if (!s.valid || s.frame != frame) { g_miss++; return; }  // no original to compare => silent (safe)
    // FIGHTER-STATE check — independent of the static-global CRC. If this stays
    // clean across a long run with rollbacks, the deterministic-sim asset is measured, not asserted.
    {
        uint32_t cur_fseg[NSEG]; compute_fighter_segs(cur_fseg);
        for (int sgi = 0; sgi < NSEG; sgi++) {
            if (cur_fseg[sgi] != s.fseg[sgi]) {
                g_fdiverge++;
                if (g_fdiverge <= 32 || (g_fdiverge % 256) == 0)
                    rblog::write("GAMEPLAY-FIGHTER-DIVERGE frame=%d seg[%d]=[0x%llX,0x%llX) orig=0x%08X resim=0x%08X (fdiverge=%lld) — fighter gameplay state diverged in resim",
                        frame, sgi, (unsigned long long)FIGHTER_SEGS[sgi].a, (unsigned long long)FIGHTER_SEGS[sgi].b,
                        s.fseg[sgi], cur_fseg[sgi], (long long)g_fdiverge);
            }
        }
    }
    // ANIM-LAYER accumulator channel — a divergence here = a slot cursor/countdown/flags accumulator that did
    // not restore coherently (the highest-stakes anim "looks-derived-but-isn't" trap). Names the channel only;
    // a clean read across the long run CONFIRMS the anim slot SEED set, an empirical no-inference check.
    {
        uint32_t cur_anim = compute_anim_crc();
        if (cur_anim != s.anim_crc) {
            g_animdiverge++;
            if (g_animdiverge <= 32 || (g_animdiverge % 256) == 0)
                rblog::write("GAMEPLAY-ANIM-DIVERGE frame=%d orig=0x%08X resim=0x%08X (animdiverge=%lld) — anim-layer slot accumulator diverged in resim",
                    frame, s.anim_crc, cur_anim, (long long)g_animdiverge);
        }
    }
    {   // BONE-STATE spring-quat accumulator
        uint32_t cur = compute_bone_crc();
        if (cur != s.bone_crc) {
            g_bonediverge++;
            if (g_bonediverge <= 32 || (g_bonediverge % 256) == 0)
                rblog::write("GAMEPLAY-BONE-DIVERGE frame=%d orig=0x%08X resim=0x%08X (bonediverge=%lld) — bone-state spring accumulator diverged in resim",
                    frame, s.bone_crc, cur, (long long)g_bonediverge);
        }
    }
    {   // OVERRIDE/additive-layer recurrent-id
        uint32_t cur = compute_override_crc();
        if (cur != s.override_crc) {
            g_overridediverge++;
            if (g_overridediverge <= 32 || (g_overridediverge % 256) == 0)
                rblog::write("GAMEPLAY-OVERRIDE-DIVERGE frame=%d orig=0x%08X resim=0x%08X (overridediverge=%lld) — override-layer recurrent-id diverged in resim",
                    frame, s.override_crc, cur, (long long)g_overridediverge);
        }
    }
    {   // scheduler DISPATCH-GROUP count/cap
        uint32_t cur = compute_dispatch_crc();
        if (cur != s.dispatch_crc) {
            g_dispatchdiverge++;
            if (g_dispatchdiverge <= 32 || (g_dispatchdiverge % 256) == 0)
                rblog::write("GAMEPLAY-DISPATCH-DIVERGE frame=%d orig=0x%08X resim=0x%08X (dispatchdiverge=%lld) — scheduler dispatch-group count/cap diverged in resim",
                    frame, s.dispatch_crc, cur, (long long)g_dispatchdiverge);
        }
    }
    // AUTHORITATIVE-GAMEPLAY SINGLETONS check (parallel channels). A new divergence here on a first
    // run is most likely a CONTAMINATED RANGE to tighten (a render-adjusted float / a non-arena ptr in
    // the span), per the false-divergence watchlist — refine the range before
    // treating it as a real sim break.
    {
        uint32_t cur_sseg[NSING]; compute_singleton_segs(cur_sseg);
        for (int i = 0; i < NSING; i++) {
            if (cur_sseg[i] != s.sseg[i]) {
                g_sdiverge[i]++;
                if (g_sdiverge[i] <= 32 || (g_sdiverge[i] % 256) == 0)
                    rblog::write("GAMEPLAY-%s-DIVERGE frame=%d orig=0x%08X resim=0x%08X (sdiverge=%lld) — authoritative gameplay singleton diverged in resim (or a contaminated range — see watchlist)",
                        SINGLETONS[i].name, frame, s.sseg[i], cur_sseg[i], (long long)g_sdiverge[i]);
                // SACT-DIFF: name the exact diverging qwords (recorded raw body vs live) + classify each
                // value (arena / out-of-arena / null) — the carrier discriminator. First 8 events only.
                if (i == 10 && s.sact_raw_ok && g_sdiverge[i] <= 8) {
                    uintptr_t sact = resolve_saction();
                    if (sact) {
                        int ndiff = 0;
                        for (size_t off = 0; off + 8 <= SACT_SPAN; off += 8) {
                            uint64_t rec = *(const uint64_t*)(s.sact_raw + off);
                            uint64_t cur = *(const uint64_t*)(sact + off);
                            if (rec != cur) {
                                ndiff++;
                                if (ndiff <= 16)
                                    rblog::write("SACT-DIFF frame=%d off=0x%03zX rec=0x%llX cur=0x%llX rec_arena=%d cur_arena=%d",
                                        frame, off, (unsigned long long)rec, (unsigned long long)cur,
                                        (int)arena::is_arena_addr((uintptr_t)rec), (int)arena::is_arena_addr((uintptr_t)cur));
                            }
                        }
                        rblog::write("SACT-DIFF frame=%d summary: %d/%zu qwords differ%s",
                                     frame, ndiff, SACT_SPAN / 8, ndiff > 16 ? " (first 16 logged)" : "");
                    }
                }
            }
        }
    }
    if (s.crc == c) {
        // Gameplay-logic CRC MATCHES (deterministic). Note any render-contaminated range that
        // diverged — informational only (expected effect re-derivation), never an alarm.
        g_match++;
        for (int i = 0; i < g_range_count; i++) {
            if (!g_ranges[i].gameplay && s.per[i] != per[i]) {
                LONG64 rr = InterlockedIncrement64(&g_rng_rederive);
                if (rr <= 16 || (rr % 512) == 0)
                    rblog::write("GP-CRC-INFO frame=%d %s diverged (orig=0x%08X resim=0x%08X, rng_draws %u->%u) — EXPECTED render/effect re-derivation, gameplay-logic CRC clean (rederive=%lld)",
                        frame, g_ranges[i].label, s.per[i], per[i], s.draws, resim_draws, (long long)rr);
            }
        }
        return;
    }
    g_diverge++;
    char buf[256]; int off = 0; buf[0] = 0;
    for (int i = 0; i < g_range_count && off < 200; i++) {
        if (s.per[i] != per[i]) {
            int w = snprintf(buf + off, sizeof(buf) - off, "%s%s(orig=0x%08X resim=0x%08X)",
                             off ? ", " : "", g_ranges[i].label, s.per[i], per[i]);
            if (w > 0) off += w;
            g_last_div_label = g_ranges[i].label;
        }
    }
    g_last_div_frame = frame;
    const char* draw_verdict = (resim_draws == s.draws)
        ? "SAME-COUNT(different value: seed/upstream divergence)"
        : "COUNT-DIFFERS(a resim skip dropped/added an RNG consumer)";
    // This divergence fires INSIDE the resim suppression window — force it through, else a run that crashes
    // before GP-CRC[EXIT] shows no divergence at all (the upstream-root verdict goes invisible).
    bool was = rblog::is_suppressed(); rblog::suppress(false);
    rblog::write("GAMEPLAY-CRC-DIVERGE frame=%d orig=0x%08X resim=0x%08X | %s | rng_draws orig=%u resim=%u => %s",
                       frame, s.crc, c, buf, s.draws, resim_draws, draw_verdict);
    rblog::suppress(was);
    // PINPOINT: first RNG-draw whose CALLER differs orig-vs-resim = the divergent consumer.
    // g_rng_caller currently holds this resim frame's callers (not yet overwritten); s.caller holds orig's.
    int rn = (int)(resim_draws < (uint32_t)RNG_CALLER_CAP ? resim_draws : (uint32_t)RNG_CALLER_CAP);
    int cmpn = (rn < s.caller_n) ? rn : s.caller_n;
    for (int i = 0; i < cmpn; i++) {
        if (g_rng_caller[i] != s.caller[i]) {
            rblog::write("GP-CRC-PINPOINT frame=%d FIRST-DIVERGENT-DRAW #%d: orig_caller=IDA 0x%llX resim_caller=IDA 0x%llX (the RNG consumer that runs differently in resim)",
                frame, i,
                (unsigned long long)(0x140000000ull + s.caller[i]),
                (unsigned long long)(0x140000000ull + g_rng_caller[i]));
            break;
        }
    }
    if (cmpn > 0 && rn != s.caller_n) {
        // sequences identical up to the shorter length but counts differ => a consumer was
        // dropped/added at the tail; the divergent caller is the first one past the short end.
        int idx = cmpn;
        uint32_t oc = (idx < s.caller_n) ? s.caller[idx] : 0xFFFFFFFFu;
        uint32_t rc2 = (idx < rn) ? g_rng_caller[idx] : 0xFFFFFFFFu;
        rblog::write("GP-CRC-PINPOINT frame=%d DRAW-COUNT TAIL DIVERGE at #%d: orig_caller=IDA 0x%llX resim_caller=IDA 0x%llX",
            frame, idx, (unsigned long long)(0x140000000ull + oc), (unsigned long long)(0x140000000ull + rc2));
    }
}

void on_rollback(int target_frame, int depth) { (void)target_frame; (void)depth; }

void dump_stats() {
    rblog::write("GP-CRC[EXIT]: ranges=%d recorded=%lld checked=%lld gameplay-matched=%lld GAMEPLAY-DIVERGED=%lld FIGHTER-DIVERGED=%lld miss=%lld | rng_rederive(expected)=%lld | last_div_frame=%d last_div=%s",
                 g_range_count, g_record, g_check, g_match, g_diverge, g_fdiverge, g_miss,
                 (long long)g_rng_rederive, g_last_div_frame, g_last_div_label);
    {
        char sb[640]; int o = 0; sb[0] = 0; long long tot = 0;
        for (int i = 0; i < NSING; i++) {
            tot += g_sdiverge[i];
            if (g_sdiverge[i]) {
                int w = snprintf(sb + o, sizeof(sb) - o, "%s%s=%lld", o ? " " : "", SINGLETONS[i].name, g_sdiverge[i]);
                if (w > 0) o += w;
            }
        }
        rblog::write("GP-CRC[EXIT] SINGLETONS: %lld total diverges / %d channels%s%s",
                     tot, NSING, tot ? " | DIVERGED: " : " (ALL CLEAN — authoritative gameplay singletons reproduce in resim)", sb);
    }
}

} // namespace gp_crc
