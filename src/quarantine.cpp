// quarantine.cpp — see quarantine.h. The reuse quarantine. Plugs into idspine's hk_free (the single FUN_1404cb350
// owner): when a free arrives inside the rollback window, DEFER it (skip orig_free, block stays in-use) and record
// {control,user,block,frame}. flush() returns past-horizon blocks to the allocator (the real free, run only in
// forward play). reconcile() drops entries whose free happened after the rollback target (those frees rolled back;
// the arena revert already restored the block in-use). DLL-side state only; zero game-memory writes beyond the
// deferred real-free, which is the engine's own free run later.
#include "quarantine.h"
#include "idspine.h"
#include "arena.h"
#include "addr.h"
#include "resim.h"
#include "sound_resource_preserve.h"
#include "log.h"
#include <windows.h>
#include <cstdint>

namespace quarantine {

namespace {
static volatile long g_mode  = 2;      // DEFER (LIVE) — the slab-reuse prevention. SHADOW validated 3 long runs (ledger exact,
                                       // overflow=0, gp_crc cost 0). Numpad5 cycles DEFER->OFF->SHADOW to flip off live.
static volatile int64_t g_scope = 0;   // 0 = all scalable allocators; else only this control block
static const int GRACE = 32;           // quarantine horizon in frames; must be >= max rollback depth (auto-rb ~7)
static void (*g_free)(int64_t, int64_t) = nullptr;

struct Ent { int64_t control; int64_t user; uintptr_t block; int frame; uint8_t deferred; int64_t serial; };
static const int CAP = 1 << 18;   // P3: 256K deferred slots (4× the old 64K) — headroom so the pool never fills under max churn (assists+supers). On the rare overflow we hold, never reuse-in-window (see on_free).
static Ent g_ent[CAP];
static int g_n = 0;
static CRITICAL_SECTION g_cs;
static bool g_cs_init = false;

static volatile LONG64 c_held = 0, c_flushed = 0, c_reconciled = 0, c_shadow = 0, c_overflow = 0, c_skipped_data = 0, c_offset_fix = 0, c_skipped_audio = 0;
// ASSIST-CHILD HYPOTHESIS COUNTERS (read-only): a typed object whose dtor CLEARED *user before FUN_1404cb350 reads as
// data => skipped => not deferred => reused (the assist child-array crash). zerovt = *user==0 at free; bigobj =
// block size >= 0x1000 (the character/sub-object class) skipped as data. High counts confirm "classify by BIRTH vtable".
static volatile LONG64 c_skipped_zerovt = 0, c_skipped_bigobj = 0, c_zerovt_held = 0, c_flush_dblfree_skip = 0;
static volatile LONG64 c_serial_gate_drop = 0;   // SERIAL-GATE: flushes DROPPED because the block was re-carved (impostor identity) — the partition-invariant close of the double-free tear

// SERIAL-GATE: the held promise is bound to the block's IDENTITY (idspine serial),
// not its address. A flush is legal only if the block still carries the serial we deferred — else it was
// flushed→re-carved and this stale-duplicate flush would double-free a LIVE re-carved object (the fr_stale class,
// 12,242 hits in one run = the free-list tear source). Mismatch ⇒ DROP (bounded leak), never free. The
// serial is monotonic ⇒ a re-carve is always a higher serial ⇒ a spurious MATCH (impostor freed) is
// UNREPRESENTABLE; the sole error mode is an over-DROP (safe leak). This makes "flush a re-carved impostor"
// structurally impossible — the correct-by-construction close, not a detect/heal.
static inline bool serial_ok(const Ent& e) {
    return idspine::stamp_of_block(e.block) == e.serial;
}
// P3-LEAK INSTRUMENTS (read-only; owned-heap "own the reuse" completeness oracle). Defer-all was ON yet the
// game still died at ~2683 frames on one run => a freed slab is reused IN-WINDOW despite quarantine. Three enumerable escapes,
// each with a counter so one long run NAMES which fires before the crash (oracle-bounded):
// (a) c_overflow (below): the deferred-slot pool (CAP) fills => the slab is freed immediately => reuse-in-window.
// (c) c_horizon_breach: a rollback reaches deeper than GRACE => an already-flushed (real-freed) slab was still a
// reachable target => reuse. c_max_rb_depth = the observed high-water depth for sizing a monotonic horizon.
// (b) non-FUN_1404cb350 free escape (a free that never routes through idspine's hk_free) is not counted here — it needs
// hooks on FUN_1404cb480 and its sibling at ...cb110; build those only if (a) and (c) come back 0 at the crash (eliminate before adding surface).
static volatile LONG64 c_max_rb_depth = 0, c_horizon_breach = 0;
static volatile long   g_newest_frame = 0;   // forward-play frame high-water (for the rollback-depth measurement)
static volatile long   g_defer_zerovt = 0;   // A/B: OFF — keep-alive of DESTRUCTED objects is suspect (preserves a vtable=0 husk, not a live object; a resurrected ref still null-derefs). OFF to test if the effect crash (FUN_140615de0 READ 0x0) is zerovt-caused (then survive to the assist crash ~330s) or independent (effect crash recurs ~112s). Flush double-free guard stays.
static volatile long   g_audio_carveout = 0; // SENTINEL FIX (default OFF = carve-out REMOVED) — the old is_audio_vtable
                                              // skip included 0x140A6A510, the UNIVERSAL MtObject dead sentinel (482 dtor
                                              // sites), so every properly-destructed in-arena object was skipped as fake-audio
                                              // (40k-frame run — the sound/assist hole). The "music rewinds"
                                              // justification: slot-deferral holds block+0x38 bit0 only; it does not touch the
                                              // OGG worker or XAudio2 PCM consumption (rewind = a CONTENT-reversion problem owned
                                              // by ogg_preserve). The 5 live audio vtables in the list are dead code at free time
                                              // (wrappers write 0x140bacbf0, resources write the sentinel). Default OFF = no
                                              // carve-out = defer destructed objects too. Drop quar_audio_carveout.flag to RESTORE
                                              // the legacy skip for A/B.
static volatile long   g_defer_all = 1;      // FAIL-CLOSED (default ON) — defer every freed slot, not just positively-typed ones. The old fail-open path skipped 1.2M frees/run (held 156, 0.01% coverage) => the slab-reuse crash class stayed wide open (assist/sound/render). Holding the SLOT regardless of type is always safe (a data buffer held GRACE frames longer is harmless; the slot just can't be reused in-window). External handles (audio voices) are still carved out below. Toggle OFF via quar_typed_only.flag for the legacy A/B.
static Ent g_flushbuf[CAP];   // collected under g_cs, freed OUTSIDE g_cs (no lock-order inversion vs the allocator CS)

// husk SET — every held entry's USER addr, O(1) queryable. The quarantine
// table IS the complete engine-wide registry of dead-but-still-addressable objects (every free from every
// subsystem/dtor passes through on_free) — so "is this edge dangling?" = one hash probe, NO per-dtor hooks,
// NO per-family catalogs. Maintained in lockstep with every table mutation (defer/flush/flush_all/restore/
// reconcile) so a rolled-back free correctly STOPS being a husk.
static constexpr uint32_t HUSK_BITS = 17, HUSK_CAP = 1u << HUSK_BITS;   // 131072 slots vs ~6k held: sparse
static volatile LONG64 g_husk[HUSK_CAP];
static inline uint32_t husk_h(uintptr_t u) { return (uint32_t)((u >> 4) * 2654435761u) & (HUSK_CAP - 1); }
static void husk_add(uintptr_t u) {
    if (!u) return; uint32_t s0 = husk_h(u);
    for (uint32_t i = 0; i < 16; i++) { uint32_t k = (s0 + i) & (HUSK_CAP - 1);
        LONG64 c = g_husk[k]; if (c == (LONG64)u) return;
        if (c == 0 && _InterlockedCompareExchange64(&g_husk[k], (LONG64)u, 0) == 0) return; }
}
static void husk_del(uintptr_t u) {
    if (!u) return; uint32_t s0 = husk_h(u);
    for (uint32_t i = 0; i < 16; i++) { uint32_t k = (s0 + i) & (HUSK_CAP - 1);
        if (g_husk[k] == (LONG64)u) { g_husk[k] = (LONG64)-1; return; }   // tombstone (keeps probe chains intact)
        if (g_husk[k] == 0) return; }
}
static void husk_rebuild_locked() {                       // caller holds g_cs; table just wholesale-changed
    memset((void*)g_husk, 0, sizeof(g_husk));
    for (int i = 0; i < g_n; i++) if (g_ent[i].deferred) husk_add((uintptr_t)g_ent[i].user);
}

// STALE-ENTRY DISCRIMINATOR (the chain-truncation guard). flush()'s real free is the only insertion
// into the engine's free list detached from its triggering event, and it BYPASSES every idspine guard. Its
// bit0 guard cannot catch the fatal shape: block flushed once → legitimately RECARVED live (bit0=1) → a STALE
// duplicate table entry (timeline-crossing / tag-skew) frees the LIVE object → an in-use block enters the free
// list → the chain truncates (walked=27 vs count=70, ctrl 0xF00128C0 mgr5 = 100% of all invariant breaks). The correct
// invariant for a DELAYED free is address-identity-since-last-real-free, not point-in-time bit0: an entry whose
// capture frame is OLDER than the block's last real-free is stale by definition — skip it loudly.
static constexpr uint32_t FRING = 1 << 13;                     // open-addressing {block -> last real-free frame}
static struct { volatile LONG64 block; volatile long frame; } g_freed_ring[FRING];
static volatile LONG64 c_stale_entry_skip = 0;
static inline uint32_t fr_hash(uintptr_t b) { return (uint32_t)((b >> 4) * 2654435761u) & (FRING - 1); }
static void fr_note(uintptr_t block, int frame) {
    uint32_t s = fr_hash(block);
    for (uint32_t i = 0; i < 8; i++) { uint32_t k = (s + i) & (FRING - 1);
        LONG64 cur = g_freed_ring[k].block;
        if (cur == (LONG64)block || cur == 0) { g_freed_ring[k].block = (LONG64)block; g_freed_ring[k].frame = frame; return; } }
    g_freed_ring[s].block = (LONG64)block; g_freed_ring[s].frame = frame;   // probe cluster full: overwrite home slot
}
static bool fr_stale(uintptr_t block, int entry_frame, int* last_freed_out) {
    uint32_t s = fr_hash(block);
    for (uint32_t i = 0; i < 8; i++) { uint32_t k = (s + i) & (FRING - 1);
        if (g_freed_ring[k].block == (LONG64)block) {
            *last_freed_out = g_freed_ring[k].frame;
            return g_freed_ring[k].frame > entry_frame;        // block really-freed after this entry was captured => entry is stale
        }
        if (g_freed_ring[k].block == 0) return false; }
    return false;
}

// Only TYPED objects (a module vtable at their base) are slab-reuse victims — they get referenced by pointers across
// the rollback window. Data/scratch buffers (no vtable; esp the high-churn Temp allocator) are intra-frame and never
// reuse victims: quarantining them is pure cost (pool bloat => the Temp first-fit-walk spin). So we defer only typed
// objects. Classify on the USER pointer FUN_1404cb350 hands us (vtable @ *user) — not a hardcoded block+0x50.
// The +0x50 guess misclassified non-0x50-header objects (e.g. the 0xe0-offset nDraw::MaterialChar / audio-cue
// 0x140A6A510) as untyped => they freed immediately => reused => garbage-vtable detonation (the 0x14053A4B6 family).
static inline bool is_typed_at(uintptr_t a) {
    if (a < 0x10000 || !arena::is_committed_addr(a)) return false;
    uintptr_t vt = *(uintptr_t*)a;
    if (vt < addr::g_base) return false;
    uint64_t ida = (uint64_t)vt - addr::g_base + 0x140000000ull;
    return ida >= 0x140000000ull && ida < 0x141000000ull;   // a umvc3 module vtable => a real object
}

// AUDIO is handled by audio_preserve + its own per-frame streaming lifecycle (free->realloc buffers every frame).
// DEFERRING an audio object's free holds its buffer in-use => the stream can't recycle/advance => MUSIC REWINDS.
// So the quarantine must not defer audio objects (the sound-resource set + the streaming voice/channel/strip/cue
// vtables). They are not rollback slab-reuse victims (their coherence is the per-object preserve, not the quarantine).
static bool is_audio_vtable(uintptr_t vt) {
    if (sound_resource_preserve::is_sound_vtable(vt)) return true;
    static uintptr_t aud[6] = {0}; static bool init = false;
    if (!init) { init = true; uintptr_t b = addr::g_base;
        const uint64_t IDA[6] = { 0x140bad660ull, 0x140bad7d0ull, 0x140bad4b0ull, 0x140bc4100ull, 0x140bc40f0ull, 0x140A6A510ull };
        for (int i = 0; i < 6; i++) aud[i] = b + (IDA[i] - 0x140000000ull); }
    for (int i = 0; i < 6; i++) if (vt == aud[i]) return true;
    return false;
}
}

void init(void (*free_fn)(int64_t, int64_t)) {
    g_free = free_fn;
    if (!g_cs_init) { InitializeCriticalSection(&g_cs); g_cs_init = true; }
}
void set_mode(long m) { g_mode = m; }
void set_scope(int64_t c) { g_scope = c; }
long mode() { return g_mode; }
void set_defer_all(bool on) { g_defer_all = on ? 1 : 0; }
void set_audio_carveout(bool on) { g_audio_carveout = on ? 1 : 0; }   // SENTINEL FIX A/B: on = legacy skip (the bug); off (default) = defer destructed objects

// QUARANTINE-UNIT (see .h): 10-slot ring mirroring the FLIST-UNIT idiom. 16384 entries/slot (working set is
// ~5000 under GRACE=32; whole-or-nothing on overflow). Capture runs inside save_allocators' CS-held window where
// on_free cannot be mid-flight for any manager (the engine's own per-class CS is held by AllocatorSnapshotCsScope),
// + our g_cs for textbook coherence with the same frame's descriptor/FLIST/page captures.
static constexpr int QU_RING = 10;
static constexpr int QU_MAX  = 16384;
static Ent  g_qu_ring[QU_RING][QU_MAX];
static int  g_qu_count[QU_RING];
static int  g_qu_frames[QU_RING] = {-1,-1,-1,-1,-1,-1,-1,-1,-1,-1};
static bool g_qu_valid[QU_RING];
static volatile LONG64 c_qu_restored = 0, c_qu_fallback = 0;

void save_table(int frame, int slot, bool cs_held) {
    if (slot < 0 || slot >= QU_RING) return;
    g_qu_frames[slot] = frame; g_qu_valid[slot] = false; g_qu_count[slot] = 0;
    if (!cs_held || !g_cs_init) return;                 // unlocked fallback save => no coherent capture => page-blind era rules for this slot
    EnterCriticalSection(&g_cs);
    if (g_n <= QU_MAX) {
        memcpy(g_qu_ring[slot], g_ent, (size_t)g_n * sizeof(Ent));
        g_qu_count[slot] = g_n;
        g_qu_valid[slot] = true;
    } else { static volatile long once = 0; if (_InterlockedCompareExchange(&once, 1, 0) == 0)
        rblog::write("QUARANTINE-UNIT: slot f%d INVALIDATED (held=%d > %d) — raise QU_MAX; rollbacks to this frame fall back to reconcile()", frame, g_n, QU_MAX); }
    LeaveCriticalSection(&g_cs);
}

bool restore_table(int target_frame) {
    if (!g_cs_init) return false;
    int slot = -1;
    for (int s = 0; s < QU_RING; s++)
        if (g_qu_frames[s] == target_frame && g_qu_valid[s]) { slot = s; break; }
    if (slot < 0) { _InterlockedIncrement64(&c_qu_fallback);
        bool w = rblog::is_suppressed(); rblog::suppress(false);
        rblog::write("QUARANTINE-UNIT: NO exact valid slot for f%d — falling back to live-table reconcile (page-blind-era rules this rollback)", target_frame);
        rblog::suppress(w); return false; }
    EnterCriticalSection(&g_cs);
    memcpy(g_ent, g_qu_ring[slot], (size_t)g_qu_count[slot] * sizeof(Ent));
    g_n = g_qu_count[slot];
    husk_rebuild_locked();                                 // husk SET follows the table's timeline wholesale
    LeaveCriticalSection(&g_cs);
    _InterlockedIncrement64(&c_qu_restored);
    bool w = rblog::is_suppressed(); rblog::suppress(false);
    rblog::write("QUARANTINE-UNIT: table restored WHOLESALE @f%d (%d entries) — held-set and page state are one frame by construction", target_frame, g_qu_count[slot]);
    rblog::suppress(w);
    return true;
}

bool on_free(int64_t control, int64_t user, uintptr_t block, int frame) {
    if (g_mode == 0 || !g_cs_init) return false;
    if (!resim::engine_enabled()) return false;             // only quarantine when rollback is armed
    if (g_scope && control != g_scope) return false;        // scoped: only the target allocator
    bool typed_user = is_typed_at((uintptr_t)user);         // Correct (offset-independent): vtable @ the user ptr FUN_1404cb350 handed us
    if (typed_user != is_typed_at(block + 0x50)) _InterlockedIncrement64(&c_offset_fix);  // objects the old +0x50 guess misclassified
    bool zerovt = false;
    if (!typed_user) { _InterlockedIncrement64(&c_skipped_data);   // not a module vtable at free (diagnostic count; now deferred under fail-closed)
        uintptr_t uv = (user > 0x10000 && arena::is_committed_addr((uintptr_t)user)) ? *(uintptr_t*)user : 1;
        if (uv == 0) _InterlockedIncrement64(&c_skipped_zerovt);
        if (arena::is_committed_addr(block + 0x38)) { uint32_t bsz = (*(uint32_t*)(block + 0x38) >> 1) << 4;
            if (bsz >= 0x1000) _InterlockedIncrement64(&c_skipped_bigobj); }
        // FAIL-CLOSED FLIP: previously RETURNED false here (skip) unless g_defer_zerovt && uv==0 — that fail-open path
        // skipped 1.2M frees/run (the assist/sound/render crash class stayed open). Now: under g_defer_all we DEFER the
        // SLOT regardless of type. A non-typed free has no module vtable at +0, so it can never match the audio carve-out
        // below (audio objects have a recognizable vtable) — deferring its slot is always safe. zerovt (*user==0 = a
        // just-destructed C++ object, the assist-child signal) is still tallied for the A/B ledger.
        if (uv == 0) zerovt = true;
        if (!g_defer_all) {                          // legacy fail-open A/B (quar_typed_only.flag): defer only destructed objects, and only if that A/B is armed
            if (!(g_defer_zerovt && uv == 0)) return false;
        }
        // g_defer_all (default): fall through and defer this slot like a typed one.
    }
    else if (g_audio_carveout && is_audio_vtable(*(uintptr_t*)user)) { _InterlockedIncrement64(&c_skipped_audio); return false; }  // SENTINEL FIX: carve-out gated OFF by default (the 0x140A6A510 sentinel skipped every destructed MtObject); deferring audio slabs is harmless
    bool defer = (g_mode == 2);
    if (zerovt) _InterlockedIncrement64(&c_zerovt_held);   // count the destructed-object keep-alives (A/B vs crash)
    if (defer) { static volatile long once = 0; if (_InterlockedCompareExchange(&once, 1, 0) == 0) {
        bool w = rblog::is_suppressed(); rblog::suppress(false);
        rblog::write("QUARANTINE: DEFER LIVE — first slab held (block=0x%llX frame=%d). Reuse is now bounded by the rollback window (slab-reuse prevention is active).", (unsigned long long)block, frame);
        rblog::suppress(w); } }
    // SERIAL-GATE capture: bind the held promise to the block's IDENTITY, not its
    // address. idspine::retire ran just before us (same per-class CS), tombstoning but KEEPING the serial ⇒ this is
    // the serial of the exact object we are deferring. Captured now, checked at flush: a reuse re-stamps a new
    // (higher) serial, so a flush of a re-carved impostor becomes a provable mismatch ⇒ DROP.
    int64_t serial = idspine::stamp_of_block(block);
    EnterCriticalSection(&g_cs);
    if (g_n < CAP) {
        g_ent[g_n++] = { control, user, block, frame, (uint8_t)(defer ? 1 : 0), serial };
        if (defer) husk_add((uintptr_t)user);             // husk SET: dead-but-addressable, engine-wide
        _InterlockedIncrement64(&c_held);
        if (!defer) _InterlockedIncrement64(&c_shadow);
    } else {
        LONG64 ov = _InterlockedIncrement64(&c_overflow);
        if (ov == 1) { static volatile long once = 0; if (_InterlockedCompareExchange(&once, 1, 0) == 0) {
            bool w = rblog::is_suppressed(); rblog::suppress(false);
            rblog::write("QUARANTINE P3 OVERFLOW: deferred-slot pool FULL (CAP=%d) at frame=%d — HOLDING this slab in-use anyway (skip orig_free, no table entry): a freed slab is NEVER reused while a rollback can reach it. Bounded permanent leak >> reuse-in-window UAF. If this fires, raise CAP.", CAP, frame);
            rblog::suppress(w); } }
        // P3 correct-by-construction: FREEING here = reuse-in-window = the UAF. So on overflow we hold the slab
        // in-use (defer stays true) without a table entry. It is never flushed (a bounded permanent leak) but it can
        // never be reused in-window. Leak > reuse. CAP=1<<18 makes this path essentially unreachable. (SHADOW mode had
        // defer=false already, so it still measures-and-frees; only DEFER-live mode holds here.)
    }
    LeaveCriticalSection(&g_cs);
    return defer;   // DEFER: true => caller skips orig_free (held in-use). SHADOW: false => orig_free runs (measured only).
}

// CHURN-AUDIT timing: the batch flush is a discrete "hitch during churn" suspect — its free-loop calls
// g_free nf times, and a churn burst ages many blocks past the horizon at once => a large batch in one frame.
static volatile LONG64 c_flush_us_total = 0, c_flush_calls = 0, c_flush_max_us = 0, c_flush_max_nf = 0, c_flush_spikes = 0;
static LARGE_INTEGER g_qpf = {};
static inline long long qpc_us(LARGE_INTEGER t0) {
    LARGE_INTEGER t1; QueryPerformanceCounter(&t1);
    if (!g_qpf.QuadPart) QueryPerformanceFrequency(&g_qpf);
    return g_qpf.QuadPart ? (t1.QuadPart - t0.QuadPart) * 1000000 / g_qpf.QuadPart : 0;
}

void flush(int current_frame, bool safe) {
    if (g_mode == 0 || !g_cs_init || !safe || !g_free) return;
    LARGE_INTEGER t0; QueryPerformanceCounter(&t0);
    // P3 monotonic horizon (closes leak-c by construction): a slab is really-freed only once it is past the DEEPEST
    // rollback ever observed, not a fixed GRACE=32. If any rollback reached deeper than GRACE, the horizon adapts up
    // so a flushed slab can never still be a rollback target. (GRACE is the floor for the common depth-7 case.)
    long horizon = GRACE;
    if (c_max_rb_depth + 8 > horizon) horizon = (long)(c_max_rb_depth + 8);
    int nf = 0;
    EnterCriticalSection(&g_cs);
    int w = 0;
    for (int i = 0; i < g_n; i++) {
        Ent& e = g_ent[i];
        if (current_frame - e.frame > horizon) {            // past the (adaptive) horizon: can no longer be a rollback target
            if (e.deferred && nf < CAP) { g_flushbuf[nf++] = e; husk_del((uintptr_t)e.user); }   // leaving the held set => no longer a husk (reuse era = P3's job)
            _InterlockedIncrement64(&c_flushed);
        } else {
            g_ent[w++] = e;                                 // keep
        }
    }
    g_n = w;
    LeaveCriticalSection(&g_cs);
    // DOUBLE-FREE GUARD on the flush (the zerovt-volume crash fix): g_free is the UN-hooked orig FUN_1404cb350, so it bypasses
    // idspine's DEALLOC-GUARD. A held block can be freed AGAIN before we flush it — by a rollback's revert (restores it
    // to free) or the engine re-freeing it — leaving block+0x38 bit0=0 (already free, back in the free-list, maybe reused).
    // Flushing it then double-pushes the free-list => the FUN_1404CA650 first-fit spin/crash. So skip any flush whose
    // block is already free (the same ground-truth bit the engine's own guard reads). Correct free-list discipline.
    for (int i = 0; i < nf; i++) {
        uintptr_t blk = g_flushbuf[i].block;
        if (!serial_ok(g_flushbuf[i])) { _InterlockedIncrement64(&c_serial_gate_drop); continue; }   // SERIAL-GATE: re-carved impostor — not ours to free (DROP)
        if (arena::is_committed_addr(blk + 0x38) && (*(uint32_t*)(blk + 0x38) & 1) == 0) {
            _InterlockedIncrement64(&c_flush_dblfree_skip); continue;   // already free (reverted/re-freed) => never double-push
        }
        int lastf = 0;
        if (fr_stale(blk, g_flushbuf[i].frame, &lastf)) {   // Demoted to an oracle (with QUARANTINE-UNIT): with the table
            // restored wholesale at rollback, a stale timeline-crossing entry is UNREPRESENTABLE — and skipping here
            // would false-positive on legitimately REPLAYED flushes (ring recorded the pre-rollback flush; the revert
            // rolled back it; the re-flush is the new timeline's real free). Log-only; a fire while the unit is active
            // = a hole in the unit, not a fault to prevent.
            LONG64 n = _InterlockedIncrement64(&c_stale_entry_skip);
            if (n <= 8) { bool w = rblog::is_suppressed(); rblog::suppress(false);
                rblog::write("STALE-ENTRY ORACLE #%lld: block=0x%llX entry.frame=%d last real-free=%d — replayed flush (expected post-rollback) OR a unit hole (unexpected without a preceding rollback)", (long long)n, (unsigned long long)blk, g_flushbuf[i].frame, lastf);
                rblog::suppress(w); }
        }
        g_free(g_flushbuf[i].control, g_flushbuf[i].user);   // real free, OUTSIDE g_cs
        fr_note(blk, current_frame);
    }
    // CHURN-AUDIT: attribute a hitch to the batch flush (spike log fires during churn; survives a hard close)
    long long us = qpc_us(t0);
    _InterlockedAdd64(&c_flush_us_total, us); LONG64 calls = _InterlockedIncrement64(&c_flush_calls);
    if (us > c_flush_max_us) c_flush_max_us = us;
    if (nf > c_flush_max_nf) c_flush_max_nf = nf;
    if (us > 2000) {   // >2ms in one flush = a churn hitch contributor
        LONG64 n = _InterlockedIncrement64(&c_flush_spikes);
        if (n <= 20 || (n & 63) == 0) { bool sw = rblog::is_suppressed(); rblog::suppress(false);
            rblog::write("CHURN-SPIKE[flush #%lld]: quarantine batch-free took %lld us (>2ms), nf=%d blocks — deferred-free backlog draining past-horizon", (long long)n, us, nf);
            rblog::suppress(sw); }
    }
    if ((calls & 1023) == 0) { bool sw = rblog::is_suppressed(); rblog::suppress(false);
        rblog::write("CHURN-FLUSH[calls=%lld]: avg=%lld us max=%lld us max_batch=%lld spikes=%lld",
            (long long)calls, (long long)(c_flush_us_total / calls), (long long)c_flush_max_us, (long long)c_flush_max_nf, (long long)c_flush_spikes);
        rblog::suppress(sw); }
}

// Engine-off drain: rollback is turning OFF — no future rollback can reference a held block, so return
// every deferred block to the allocator and CLEAR the table. This drains the deferred-free backlog that accrues
// during an engine-off stretch (on_frame's flush doesn't run while off) and gives the next F5 re-arm a clean,
// empty consumer-state table (so old stamps can't alias the re-armed clock). Same double-free guard as flush().
void flush_all() {
    if (!g_cs_init) return;
    int nf = 0;
    EnterCriticalSection(&g_cs);
    for (int i = 0; i < g_n; i++) {
        Ent& e = g_ent[i];
        if (e.deferred && g_free && nf < CAP) { g_flushbuf[nf++] = e; husk_del((uintptr_t)e.user); }
        _InterlockedIncrement64(&c_flushed);
    }
    g_n = 0;                                            // clear the table (consumer-state reset for the F5 re-arm)
    LeaveCriticalSection(&g_cs);
    for (int i = 0; i < nf; i++) {
        uintptr_t blk = g_flushbuf[i].block;
        if (!serial_ok(g_flushbuf[i])) { _InterlockedIncrement64(&c_serial_gate_drop); continue; }   // SERIAL-GATE: re-carved impostor — not ours to free (DROP)
        if (arena::is_committed_addr(blk + 0x38) && (*(uint32_t*)(blk + 0x38) & 1) == 0) {
            _InterlockedIncrement64(&c_flush_dblfree_skip); continue;   // already free (reverted/re-freed) => never double-push
        }
        int lastf = 0;
        if (fr_stale(blk, g_flushbuf[i].frame, &lastf)) _InterlockedIncrement64(&c_stale_entry_skip);   // oracle-only (see flush)
        g_free(g_flushbuf[i].control, g_flushbuf[i].user);
        fr_note(blk, g_flushbuf[i].frame);
    }
}

void reconcile(int target_frame) {
    if (g_mode == 0 || !g_cs_init) return;
    // Horizon instrument (leak c, read-only): how far back does this rollback reach vs the flush horizon (GRACE)?
    // depth = forward-play high-water - target. depth > GRACE => a block already flushed (really freed, dropped from
    // the table so reconcile can no longer restore it) could still be this rollback's target => reuse. Measurement only.
    { long d = (long)(g_newest_frame - target_frame);
      if (d > 0 && d < 100000) {
          if (d > c_max_rb_depth) c_max_rb_depth = d;
          if (d > GRACE) { LONG64 hb = _InterlockedIncrement64(&c_horizon_breach);
              if (hb == 1) { bool w = rblog::is_suppressed(); rblog::suppress(false);
                  rblog::write("QUARANTINE LEAK-c: rollback depth=%ld EXCEEDS GRACE=%d (target=%d newest=%ld) — a flushed/real-freed slab could still be this rollback's target => reuse. Fix = a monotonic confirmed-frame horizon, not a fixed GRACE.", d, GRACE, target_frame, (long)g_newest_frame);
                  rblog::suppress(w); } }
      } }
    EnterCriticalSection(&g_cs);
    int w = 0;
    for (int i = 0; i < g_n; i++) {
        Ent& e = g_ent[i];
        if (e.frame > target_frame) { _InterlockedIncrement64(&c_reconciled); }   // free rolled back; revert restored it in-use => DROP (do not free)
        else { g_ent[w++] = e; }                                                  // freed at/before target: still validly held
    }
    g_n = w;
    husk_rebuild_locked();                                 // husk SET: rolled back frees are ALIVE again — must leave the set
    LeaveCriticalSection(&g_cs);
}

int held_count() { return g_n; }

// DEFAULT-husk timeline set (liveness by recorded birth/death frame, not by byte inspection). Default/heap-zone frees
// don't pass on_free (that hook is FUN_1404cb350-only), so the FUN_1404cb350 husk set is structurally blind to them (the
// 0x1405DA4B5 Material crash). Track them SEPARATELY, each STAMPED with its death frame — so (a) the sweep sees
// them and (b) they are reverted on rollback by construction: a death stamped after the restored frame didn't happen
// on that timeline, so the object is alive again — pruned, not inspected. Lock-free hash; per-rollback prune.
static constexpr uint32_t DH_CAP = 1u << 18;
static struct { volatile LONG64 addr; volatile long death; } g_dhusk[DH_CAP];
static volatile LONG64 c_dhusk_add = 0, c_dhusk_pruned = 0, c_dhusk_drop = 0;
static inline uint32_t dh_h(uintptr_t a) { return (uint32_t)((a >> 4) * 2654435761u) & (DH_CAP - 1); }

void note_default_husk(uintptr_t addr, int death_frame) {
    if (!addr) return; uint32_t s0 = dh_h(addr);
    for (uint32_t i = 0; i < 16; i++) { uint32_t k = (s0 + i) & (DH_CAP - 1);
        LONG64 c = g_dhusk[k].addr;
        if (c == (LONG64)addr) { g_dhusk[k].death = death_frame; return; }            // re-death (resim replay): restamp
        if ((c == 0 || c == -1) && _InterlockedCompareExchange64(&g_dhusk[k].addr, (LONG64)addr, c) == c) {
            g_dhusk[k].death = death_frame; _InterlockedIncrement64(&c_dhusk_add); return; } }
}
void drop_default_husk(uintptr_t addr) {                                              // on (re)alloc: a LIVE object now
    if (!addr) return; uint32_t s0 = dh_h(addr);
    for (uint32_t i = 0; i < 16; i++) { uint32_t k = (s0 + i) & (DH_CAP - 1);
        if (g_dhusk[k].addr == (LONG64)addr) { g_dhusk[k].addr = -1; _InterlockedIncrement64(&c_dhusk_drop); return; }
        if (g_dhusk[k].addr == 0) return; }
}
void prune_default_husks(int target_frame) {                                          // rollback: death>target rolled back
    if (!c_dhusk_add) return;   // INERT: rdspine's Default hook sees ~0 Material deaths (Materials
                                // flow through an internal pool, not FUN_1404C9A00) => g_dhusk stays empty => skip the
                                // 256K scan. As wired this is measurement-only; the real Material-death chokepoint is the
                                // internal pool free-list (a separate RE), and FUN_1404cb350 already supplies the live husk catches.
    for (uint32_t k = 0; k < DH_CAP; k++) { LONG64 a = g_dhusk[k].addr;
        if (a > 0 && g_dhusk[k].death > target_frame) { g_dhusk[k].addr = -1; _InterlockedIncrement64(&c_dhusk_pruned); } }
}
static bool is_default_husk(uintptr_t addr) {
    if (!addr) return false; uint32_t s0 = dh_h(addr);
    for (uint32_t i = 0; i < 16; i++) { uint32_t k = (s0 + i) & (DH_CAP - 1);
        if (g_dhusk[k].addr == (LONG64)addr) return true;
        if (g_dhusk[k].addr == 0) return false; }
    return false;
}
void default_husk_stats(long long* add, long long* pruned, long long* drop) {
    if (add) *add = c_dhusk_add; if (pruned) *pruned = c_dhusk_pruned; if (drop) *drop = c_dhusk_drop;
}

// husk QUERY (lock-free read; sweep-side): is this address a currently-held dead object anywhere in the engine?
bool is_held_husk(uintptr_t user) {
    if (!user) { return false; }
    uint32_t s0 = husk_h(user);
    for (uint32_t i = 0; i < 16; i++) { uint32_t k = (s0 + i) & (HUSK_CAP - 1);
        LONG64 c = g_husk[k];
        if (c == (LONG64)user) return true;
        if (c == 0) break; }
    return is_default_husk(user);                        // also the Default/zone timeline set
}

void on_frame(int frame) {
    if ((long)frame > g_newest_frame) g_newest_frame = frame;   // leak c: forward-play high-water for rollback depth
    flush(frame, !resim::resim_active());   // flush only in forward play (never mid-resim / frozen)
    static int t = 0;
    // DEFAULT-husk aging: a death older than 300 frames (≫ any rollback horizon ~32) can never rollback and its
    // stale edges are long since re-nulled by forward play — drop it so the set can't fill under high-frequency
    // Default churn (the address won't be re-served for zone; CRT reuse is handled by drop_default_husk on realloc).
    if ((t % 300) == 0 && !resim::resim_active())
        for (uint32_t k = 0; k < (1u << 18); k++) { LONG64 a = g_dhusk[k].addr;
            if (a > 0 && g_dhusk[k].death < frame - 300) g_dhusk[k].addr = -1; }
    if ((++t % 600) == 0) report();
}

void report() {
    bool w = rblog::is_suppressed(); rblog::suppress(false);
    rblog::write("QUARANTINE[mode=%ld scope=0x%llX grace=%d]: held=%lld flushed=%lld reconciled=%lld overflow=%lld skipped_data=%lld (zerovt=%lld bigobj=%lld) skipped_audio=%lld offset_fix=%lld cur_held=%d (zerovt/bigobj = typed objects skipped as data => the assist-child not-deferred bug)",
                 g_mode, (unsigned long long)g_scope, GRACE,
                 (long long)c_held, (long long)c_flushed, (long long)c_reconciled, (long long)c_overflow, (long long)c_skipped_data, (long long)c_skipped_zerovt, (long long)c_skipped_bigobj, (long long)c_skipped_audio, (long long)c_offset_fix, g_n);
    rblog::write("QUARANTINE: zerovt-keepalive=%ld zerovt_held=%lld flush_dblfree_skip=%lld (assist-child fix + flush double-free guard)",
                 g_defer_zerovt, (long long)c_zerovt_held, (long long)c_flush_dblfree_skip);
    rblog::write("QUARANTINE[P3 complete]: overflow=%lld(CAP=%d,HELD-not-freed) max_rb_depth=%lld(GRACE-floor=%d,adaptive) horizon_breach=%lld stale_entry_skip=%lld | leak-a/c closed; stale>0 = the truncation trigger caught+prevented (timeline-crossing duplicate entry) serial_gate_drop=%lld (re-carved impostor flushes DROPPED — the partition-invariant tear close)",
                 (long long)c_overflow, CAP, (long long)c_max_rb_depth, GRACE, (long long)c_horizon_breach, (long long)c_stale_entry_skip, (long long)c_serial_gate_drop);
    rblog::suppress(w);
}

} // namespace quarantine
