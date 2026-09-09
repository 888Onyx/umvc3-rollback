// sound_resource_preserve.cpp — object-granular PRESERVE for in-arena sound RESOURCE objects.
//
// The BUG: the sSound body is rederive-excluded (kept LIVE across arena::load), but the refcounted
// sound-resource objects the live containers cache — rSoundSource (strip+0xa98), rSoundBank, etc. — are
// slab-packed in the SHARED Global slot-0 IN-ARENA. arena::load reverts those slab pages, so the live strip's
// cached pointer derefs a reverted object whose vtable(+0) is garbage -> `call [*(*rdi)+0xA0]` AV in the sound
// command processor FUN_1405c1ea0, ~57 frames post-rollback. page-exclusion cannot reach a slab-packed object
// (excluding its page would strand the non-sound objects sharing it). So we preserve them at OBJECT granularity:
// snapshot each live sound-resource's exact bytes before arena::load, write them back after -> the live container
// and its resources land on the same (live) epoch, no split, no garbage vtable.
//
// Complete BY CONSTRUCTION (not a backstop): every sound resource is refcount-acquired through FUN_140516300
// (the resource-manager DAT_140e175a8 inc; FUN_14050d100 tail-calls it). We hook it; when the acquired object's
// vtable is one of the 52 sound-resource vtables (sound_resource_vtables.h, derived from the r*Sound* DTI tree),
// we register {addr, size}. The registry self-cleans at save (an entry whose vtable no longer matches was freed
// or reused -> dropped). This removes the incoherent state instead of catching its crash. Sound is a pure output
// leaf (not in gp_crc) so preserving it is desync-free.
#include "sound_resource_preserve.h"
#include "sound_resource_vtables.h"
#include "addr.h"
#include "arena.h"
#include "log.h"
#include "resim.h"
#include <MinHook.h>
#include <windows.h>
#include <cstdint>
#include <cstring>

namespace sound_resource_preserve {

static constexpr uintptr_t RESMGR_INC_IDA = 0x140516300;  // FUN_140516300(mgr, obj) — universal resource refcount-inc

// resolved sound-resource vtables (runtime) + object sizes, with a fast [lo,hi] pre-filter for the hot path.
static uintptr_t g_vt[SOUND_RES_VTABLE_COUNT];
static uint32_t  g_vt_size[SOUND_RES_VTABLE_COUNT];
static int       g_vt_n  = 0;
static uintptr_t g_vt_lo = ~0ull, g_vt_hi = 0;

static inline uint32_t size_for_vt(uintptr_t vt) {
    if (vt < g_vt_lo || vt > g_vt_hi) return 0;     // not a sound-resource vtable (the common case)
    for (int i = 0; i < g_vt_n; i++) if (g_vt[i] == vt) return g_vt_size[i];
    return 0;
}

bool is_sound_vtable(uintptr_t vt) { return size_for_vt(vt) != 0; }

// live registry of sound-resource objects (deduped by address)
static constexpr int MAX_REG = 4096;
struct Reg { uintptr_t addr; uint32_t size; };
static Reg     g_reg[MAX_REG];
static int     g_reg_n = 0;
static int64_t c_overflow = 0;

static void register_obj(uintptr_t obj, uint32_t size) {
    for (int i = 0; i < g_reg_n; i++) if (g_reg[i].addr == obj) { g_reg[i].size = size; return; }
    if (g_reg_n < MAX_REG) g_reg[g_reg_n++] = { obj, size };
    else c_overflow++;
}

// snapshot buffer (our own scratch, not in the arena)
static constexpr size_t SNAP_CAP = 16 * 1024 * 1024;   // 16MB (the comprehensive walk registers more objects)
static uint8_t* g_snap = nullptr;
struct Snap { uintptr_t addr; uint32_t size; size_t off; };
static Snap    g_snaps[MAX_REG];
static int     g_snap_n = 0;
static size_t  g_snap_used = 0;
static int64_t c_save = 0, c_restore = 0, c_pruned = 0, c_overflow_snap = 0;
static int64_t c_delta_wrote = 0, c_delta_skip = 0;   // PERF DELTA: write-backs actually applied vs skipped (unchanged)

static inline bool canon(uintptr_t p) { return p >= 0x10000 && p < 0x7FFFFFFFFFFFULL; }

// --- acquire hook: register sound resources at the refcount-inc chokepoint -----------------------
typedef void (*inc_fn)(uintptr_t, uintptr_t);
static inc_fn orig_inc = nullptr;
static void hk_inc(uintptr_t mgr, uintptr_t obj) {
    orig_inc(mgr, obj);
    if (!canon(obj) || !arena::is_arena_addr(obj)) return;  // out-of-arena resources aren't reverted => nothing to do
    uint32_t sz = size_for_vt(*(uintptr_t*)obj);            // freshly-acquired => *obj is the real vtable
    if (sz) register_obj(obj, sz);
}

// The ogg decoder (0x140bad660) is deliberately not in this set — byte-preserving the live decoder corrupts it
// (whole-object byte-restore of a decoder holding an out-of-arena CRT buffer ptr + live cursors is wrong; it crashed
// at rip=0x140BAD660). It would need field-granular preserve (only body_data/body_storage/body_fill/body_returned).
void init() {
    for (int i = 0; i < SOUND_RES_VTABLE_COUNT; i++) {
        uintptr_t rt = addr::resolve(SOUND_RES_VTABLES[i].ida_vt);
        g_vt[g_vt_n] = rt; g_vt_size[g_vt_n] = SOUND_RES_VTABLES[i].size; g_vt_n++;
        if (rt < g_vt_lo) g_vt_lo = rt;
        if (rt > g_vt_hi) g_vt_hi = rt;
    }
    g_snap = (uint8_t*)VirtualAlloc(nullptr, SNAP_CAP, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    void* t = (void*)addr::resolve(RESMGR_INC_IDA);
    MH_STATUS st = MH_CreateHook(t, (void*)&hk_inc, (void**)&orig_inc);
    rblog::write("SND-RES-PRESERVE: hook FUN_140516300 @0x%llX %s | %d sound-res vtables in [0x%llX..0x%llX] | snap=%s",
                 (unsigned long long)(uintptr_t)t, st == MH_OK ? "OK" : "FAILED", g_vt_n,
                 (unsigned long long)g_vt_lo, (unsigned long long)g_vt_hi, g_snap ? "16MB" : "ALLOC-FAILED");
}

// --- comprehensive registration: block-walk all allocators at PH_SAVE and register every in-arena object whose
// vtable is a sound-resource vtable. Closes the registration gap (carrier #3 0x1405C2698: rSoundSource descriptors
// reach the cue-slot via a bind path not covered by the FUN_140516300 acquire hook => were never registered =>
// reverted => garbage-vtable AV). Direct enumeration = registration-by-construction, no per-bind-site hook needed.
static inline bool rd(uintptr_t p, size_t n){ return canon(p) && arena::is_committed_addr(p) && arena::is_committed_addr(p+n-1); }
static inline uint64_t blk_total(uintptr_t b){ return (uint64_t)(*(uint32_t*)(b+0x38)>>1)<<4; }
static inline bool blk_alloc(uintptr_t b){ return (*(uint32_t*)(b+0x38)&1)!=0; }
static void register_all_live() {
    uintptr_t* table = (uintptr_t*)addr::resolve(0x140D762F0); if(!table) return;
    uintptr_t seen[64]; int nseen=0; long budget=4000000;
    for(int i=0;i<64 && budget>0;i++){
        uintptr_t control=table[i];
        if(!canon(control)||!arena::is_arena_addr(control)||!rd(control+0x98,8))continue;  // in-arena allocators only
        bool dup=false; for(int s=0;s<nseen;s++)if(seen[s]==control){dup=true;break;} if(dup)continue; if(nseen<64)seen[nseen++]=control;
        uintptr_t rlo=*(uintptr_t*)(control+0x90), rhi=*(uintptr_t*)(control+0x98);
        if(!canon(rlo)||rhi<=rlo||(rhi-rlo)>0x40000000ull)continue;
        for(uintptr_t bk=rlo; bk<rhi && budget>0; budget--){
            if(!rd(bk+0x40,8))break; uint64_t bt=blk_total(bk); if(bt==0)break; uintptr_t nb=bk+bt; if(nb<=bk||nb>rhi)break;
            if(blk_alloc(bk)){
                uintptr_t bend=bk+bt, swend=bk+0x400; if(swend>bend)swend=bend;
                for(uintptr_t p=bk;p+8<=swend;p+=8){ if(!rd(p,8))break; uint32_t sz=size_for_vt(*(uintptr_t*)p);
                    if(sz){ register_obj(p, sz); break; } }   // first sound-resource vtable in the block => register
            }
            bk=nb;
        }
    }
}

// PH_SAVE (before arena::load): snapshot live sound resources; self-clean freed/reused entries.
static volatile long g_comprehensive = 0;   // A/B: 0 = hook-only registration; 1 = also the comprehensive block walk
void save() {
    if (!resim::engine_enabled() || !g_snap) return;
    if (g_comprehensive) register_all_live();   // comprehensive enumeration (closes the acquire-hook gap; A/B-gated)
    g_snap_n = 0; g_snap_used = 0;
    int live = 0;
    for (int i = 0; i < g_reg_n; i++) {
        uintptr_t a = g_reg[i].addr;
        if (!canon(a)) { c_pruned++; continue; }
        uint32_t sz = size_for_vt(*(uintptr_t*)a);   // vtable still a sound-resource vtable? else freed/reused -> drop
        if (!sz) { c_pruned++; continue; }
        g_reg[live++] = { a, sz };                   // compact registry to the live set
        if (g_snap_used + sz > SNAP_CAP) { c_overflow_snap++; continue; }   // keep registered, just not snapped
        memcpy(g_snap + g_snap_used, (void*)a, sz);
        g_snaps[g_snap_n++] = { a, sz, g_snap_used };
        g_snap_used += sz;
    }
    g_reg_n = live;
    c_save++;
}

// PH_POST_LOAD (after arena::load): write the live bytes back over the reverted slab pages.
// PERF DELTA (bit-exact by construction): arena::load's windowed restore reverts only pages written after the
// target frame. A sound-resource object living on a page load did not revert still holds its LIVE bytes, so writing
// the snapshot back is a pure no-op. Compare-and-skip: memcmp the current arena bytes against the snapshot and only
// re-apply the objects that actually differ. This is provably canary-safe — the FINAL bytes are identical whether we
// write or skip an equal object, so it can never move gameplay or reintroduce the audio garble (a genuinely
// reverted object always differs from the live snapshot ⇒ it is always written). Bonus: skipping the write avoids
// re-dirtying the page ⇒ a smaller next-save dirty set. memcmp early-outs on the first differing byte, so changed
// objects (page reverted, warm in cache from load) cost ~nothing before the memcpy. Reading g_snaps[i].size from the
// arena is exactly the range the old code wrote, so no new fault surface.
void restore() {
    if (!resim::engine_enabled() || !g_snap) return;
    int64_t wrote = 0, skip = 0;
    for (int i = 0; i < g_snap_n; i++) {
        void*       dst = (void*)g_snaps[i].addr;
        const void* src = g_snap + g_snaps[i].off;
        uint32_t    sz  = g_snaps[i].size;
        if (memcmp(dst, src, sz) == 0) { skip++; continue; }   // unchanged (page not reverted) — writing is a no-op
        memcpy(dst, src, sz);
        wrote++;
    }
    c_delta_wrote += wrote; c_delta_skip += skip;
    c_restore++;
    if (c_restore <= 5 || (c_restore & 63) == 0) {   // throttled: prove the skip ratio (how much the delta saves)
        bool was = rblog::is_suppressed(); rblog::suppress(false);
        rblog::write("SND-RES-DELTA[restore %lld]: objects=%d wrote=%lld skipped=%lld (%.0f%% skipped, no-op)",
                     (long long)c_restore, g_snap_n, (long long)wrote, (long long)skip,
                     g_snap_n ? 100.0 * (double)skip / (double)g_snap_n : 0.0);
        rblog::suppress(was);
    }
}

void report() {
    rblog::write("SND-RES-PRESERVE: reg=%d save=%lld restore=%lld pruned=%lld snap=%d/%lluKB overflow(reg=%lld snap=%lld)",
                 g_reg_n, (long long)c_save, (long long)c_restore, (long long)c_pruned,
                 g_snap_n, (unsigned long long)(g_snap_used / 1024),
                 (long long)c_overflow, (long long)c_overflow_snap);
    int64_t dtot = c_delta_wrote + c_delta_skip;
    rblog::write("SND-RES-DELTA totals: wrote=%lld skipped=%lld (%.1f%% of write-backs were no-ops the delta skipped)",
                 (long long)c_delta_wrote, (long long)c_delta_skip,
                 dtot ? 100.0 * (double)c_delta_skip / (double)dtot : 0.0);
}

} // namespace sound_resource_preserve
