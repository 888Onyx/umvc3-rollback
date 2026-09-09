// rtv_probe.cpp — RTV/DSV surface refcount-neutral resim FIX + live assertions.
//
// The bug (measured): the resim re-runs the engine's RTV/DSV teardown,
// re-Releasing surfaces whose matching AddRef (the ctor) was before the rollback window and is
// not replayed => the driver refcount delta lands twice => underflow => surface poisoned to -1 =>
// crash 0x140781D15. The engine assumes one driver-delta per logical destroy (it never replays);
// only OUR replay double-applies.
//
// FIX (thinnest layer that restores the engine's own invariant; same idiom as voice_pool): during
// resim, for PERSISTENT wrappers (born before the rollback target), null +0x20 at the RTV/DSV dtor
// so its +0x20!=0-guarded Release becomes a no-op, while orig still frees the 0x38 wrapper (the
// param_2&1 path = allocator coherence; no MtAllocator touched => no allocator divergence). The driver
// refcount then nets back to the real-timeline value.
//
// Per-class: A persistent-destroyed-in-window = SUPPRESS (the observed crash);
// B transient created+destroyed-in-window self-balances, the birth>tgt gate leaves it alone;
// D shared MRT = per-WRAPPER gate (per-surface keying would over/under-suppress). UNKNOWN wrappers
// default NOT-suppress (leak-safe) => every ctor is registered (RTV create/wrap + DSV ctor).
//
// LIVE ASSERTIONS:
// [OVER-REL-FIXFAIL] rel>acq on a NON-suppressed release => the fix MISSED a spurious release.
// CREATE-IN-RESIM[/CREATE] => CLASS C reachable (create-side leak).
// Read-only except the +0x20 null (the fix). Sibling residual not covered: MRT +0x48 direct Release
// in FUN_140781ac0 (its own +0x48-null when/if it surfaces).
#include "log.h"
#include "addr.h"
#include "arena.h"
#include "resim.h"
#include <MinHook.h>
#include <windows.h>
#include <cstdint>

namespace rtv_probe {

static constexpr uintptr_t RTV_DTOR_IDA   = 0x140781CF0;   // nDraw::RenderTargetView deleting-dtor
static constexpr uintptr_t RTV_CREATE_IDA = 0x140781410;   // CreateRenderTarget (new surface)
static constexpr uintptr_t RTV_WRAP_IDA   = 0x140781370;   // wrap (AddRef existing surface)
static constexpr uintptr_t RTV_VTABLE_IDA = 0x140BBEBD8;
static constexpr uintptr_t DSV_DTOR_IDA   = 0x140781C80;   // nDraw::DepthStencilView deleting-dtor
static constexpr uintptr_t DSV_CTOR_IDA   = 0x140781220;   // CreateDepthStencilSurface (new surface)
static constexpr uintptr_t DSV_VTABLE_IDA = 0x140BBEC18;
static constexpr uintptr_t TEX_CTOR_IDA   = 0x140782060;   // nDraw::Texture ctor funnel (acquires own-surface +0x48)
static constexpr uintptr_t TEX_DTOR_IDA   = 0x140781AC0;   // nDraw::Texture full-dtor (releases own-surface +0x48)

typedef void* (*dtor_fn)(void* p1, uint64_t p2);
typedef void* (*ctor3_fn)(void* p1, int64_t p2, uint32_t p3);   // RTV create + DSV ctor
typedef void* (*wrap_fn)(void* p1, void* p2, void* p3);
typedef void  (*tex_ctor_fn)(void* p1, int64_t p2, void* p3, void* p4);   // FUN_140782060
typedef void  (*tex_dtor_fn)(void* p1);                                   // FUN_140781ac0
static dtor_fn  orig_rtv_dtor = nullptr, orig_dsv_dtor = nullptr;
static ctor3_fn orig_rtv_create = nullptr, orig_dsv_ctor = nullptr;
static wrap_fn  orig_rtv_wrap = nullptr;
static tex_ctor_fn orig_tex_ctor = nullptr;
static tex_dtor_fn orig_tex_dtor = nullptr;
static uintptr_t g_rtv_vtable = 0, g_dsv_vtable = 0;
static volatile LONG g_calls = 0, g_suppress_count = 0;

static bool readable(uintptr_t p, size_t n) {
    if (p < 0x10000) return false;
    MEMORY_BASIC_INFORMATION mbi;
    if (!VirtualQuery((void*)p, &mbi, sizeof(mbi))) return false;
    if (mbi.State != MEM_COMMIT) return false;
    DWORD prot = mbi.Protect & 0xFF;
    if (!(prot==PAGE_READONLY||prot==PAGE_READWRITE||prot==PAGE_EXECUTE_READ||prot==PAGE_EXECUTE_READWRITE))
        return false;
    return (p + n) <= ((uintptr_t)mbi.BaseAddress + mbi.RegionSize);
}

// DOMAIN-VALID-OR-NULL for the native surface handle (the 0x140781D15 stale-reference-reuse close, register-
// verified). The RTV/DSV deleting-dtor releases its native surface via `mov rcx,[self+0x20]; test rcx,rcx; je;
// mov rax,[rcx]; call [rax+0x10]` (0x140781D09..0x140781D15) — a NULL-ONLY guard. The over-release path (resim
// re-Releases a pre-window array-element surface whose AddRef is never replayed) frees the surface early; its block
// is reused as a runtime resource-name widestring, so self+0x20 is non-null + readable (e.g. 0x14DC3680) but *surf
// (the surface's COM vtable) is garbage ("\Val" = 0x6C00610056005C, non-canonical) => the `call [garbage+0x10]`
// faults. A `surf==-1` test MISSES this (surf is a real heap address). The unambiguous discriminator is the SURFACE'S
// VTABLE: a live COM surface's vtable lives in a loaded MODULE IMAGE (d3d9.dll / driver); a reused heap block's first
// qword does not (non-canonical, or private-heap). Null self+0x20 on a husk => the engine's own !=0 guard skips the
// dead Release. Zero false-positive on a live surface (its vtable is always image-mapped); a false positive would only
// SKIP a Release (leak), never crash. Same domain-valid-or-null discipline as material_guard/husk_child_dtor.
static inline bool surf_husk(uintptr_t surf) {
    if (surf == 0) return false;                                  // null: engine already skips => not a husk
    if (surf == 0xFFFFFFFFFFFFFFFFULL) return true;              // -1 poisoned handle
    if (!readable(surf, 8)) return true;                         // dangling surface handle (VQ #1)
    uintptr_t vt = *(uintptr_t*)surf;                           // the surface's COM vtable (first qword)
    if (vt == 0) return true;
    MEMORY_BASIC_INFORMATION mbi;                                // VQ #2: one query yields committed + protection + type + bound
    if (!VirtualQuery((void*)vt, &mbi, sizeof(mbi))) return true;   // non-canonical / unmapped ("\Val" reuse case) => husk
    if (mbi.State != MEM_COMMIT || mbi.Type != MEM_IMAGE) return true;   // a real surface vtable is module-image, never private heap
    DWORD prot = mbi.Protect & 0xFF;
    if (!(prot==PAGE_READONLY||prot==PAGE_READWRITE||prot==PAGE_EXECUTE_READ||prot==PAGE_EXECUTE_READWRITE)) return true;
    if (vt + 0x18 > (uintptr_t)mbi.BaseAddress + mbi.RegionSize) return true;   // engine derefs [vt+0x10] — need the slot in-region
    return false;
}
static volatile LONG64 g_surf_husk_sev = 0;   // times a husk native surface was nulled (domain-valid-or-null, 0x140781D15 close)

// --- wrapper birth registry (per-wrapper persistent-vs-transient gate) -------------------------
struct RtvRec { uintptr_t obj; int birth_frame; uintptr_t birth_surf; };
static RtvRec g_reg[256];
static int g_reg_n = 0;
static CRITICAL_SECTION g_cs;
static bool g_cs_ready = false;
static void reg_put(uintptr_t obj, int frame, uintptr_t surf) {   // update-in-place (address reuse safe)
    if (!g_cs_ready) return;
    EnterCriticalSection(&g_cs);
    for (int i = 0; i < g_reg_n; i++) if (g_reg[i].obj == obj) { g_reg[i].birth_frame = frame; g_reg[i].birth_surf = surf; LeaveCriticalSection(&g_cs); return; }
    if (g_reg_n < 256) g_reg[g_reg_n++] = { obj, frame, surf };
    LeaveCriticalSection(&g_cs);
}
static bool reg_get(uintptr_t obj, RtvRec* out) {
    if (!g_cs_ready) return false;
    EnterCriticalSection(&g_cs);
    bool found = false;
    for (int i = 0; i < g_reg_n; i++) if (g_reg[i].obj == obj) { *out = g_reg[i]; found = true; break; }
    LeaveCriticalSection(&g_cs);
    return found;
}
static void reg_remove(uintptr_t obj) {   // prune a really-dead wrapper (real dtor only, not replayed-resim)
    if (!g_cs_ready) return;
    EnterCriticalSection(&g_cs);
    for (int i = 0; i < g_reg_n; i++) if (g_reg[i].obj == obj) { g_reg[i] = g_reg[--g_reg_n]; break; }
    LeaveCriticalSection(&g_cs);
}

// --- RENDER-DOMAIN PRESERVE: keep the live RTV/DSV +0x20 surface across the arena revert ----------
// One discipline with the cDraw cure: arena::load raw-reverts derived render state. For RTV/DSV the
// +0x20 native-surface word reverts to a frame-N handle whose driver surface was already released =>
// the EXEC bind / dtor hands d3d9 a dead handle => READ -1. PRESERVE = save the LIVE +0x20 before
// arena::load, restore it after (the driver surface is OUT of the arena, never reverted, so the live
// handle stays valid; render re-derives next frame = GGPO, gp-neutral). Self-gating: only a still-
// committed wrapper whose live surf is a readable driver surface is preserved (filters dead/reused
// registry entries). The dtor-null suppress (view_dtor_decide) is kept — its set (destroyed-in-window)
// is DISJOINT from the preserve set (live-at-rollback), so no leak antagonism.
static struct { uintptr_t obj; uintptr_t surf; } g_preserve[256];
static int g_preserve_n = 0;

// FRESH-FRAME GAP FIX: the ctorset suppression only fires during RESIM; preserve_restore only
// restores LIVE (g_reg) wrappers. A wrapper alive at frame N, FREED in forward play (reg_remove'd => not in g_reg),
// gets reverted-ALIVE by arena::load with a STALE +0x20 (the dead external surf), and is re-destroyed in the FRESH
// post-resim frame (resim=0 => no suppression) => Release on the dead surf => the 0x140781D15 crash. g_destroyed[]
// tracks wrappers that died in forward play; at preserve_restore we NULL their reverted +0x20 IFF it points out-of-arena
// (a stale external D3D surface). The !is_arena_addr filter is self-discriminating: an in-arena value is free-list
// residue (safe to leave); out-of-arena is the dangling COM surface (must null). Cleared each rollback. Cap 1024
// (worst case: 5-10 deaths/frame * up-to-60-frame inter-rollback window). A/B via g_rtv_destroyed_fix.
static volatile long g_rtv_destroyed_fix = 1;   // default ON; rtv_no_destroyed_fix.flag disables for A/B
void set_destroyed_fix(bool on) { g_rtv_destroyed_fix = on ? 1 : 0; }
static uintptr_t g_destroyed[1024];
static int g_destroyed_n = 0;
static volatile LONG g_destroyed_overflow = 0;
static void destroyed_push(uintptr_t obj) {       // real death (resim=0) => may be reverted-alive with a stale surf
    if (!g_cs_ready || !g_rtv_destroyed_fix || !obj) return;
    EnterCriticalSection(&g_cs);
    if (g_destroyed_n < 1024) g_destroyed[g_destroyed_n++] = obj; else InterlockedIncrement(&g_destroyed_overflow);
    LeaveCriticalSection(&g_cs);
}
static void destroyed_prune(uintptr_t obj) {      // SLOT-REUSE prune: the slot got re-created =>
    if (!g_cs_ready || !obj) return;              // it is legitimately re-owned; do not null the new wrapper's +0x20
    EnterCriticalSection(&g_cs);
    for (int i = 0; i < g_destroyed_n; i++) if (g_destroyed[i] == obj) { g_destroyed[i] = g_destroyed[--g_destroyed_n]; break; }
    LeaveCriticalSection(&g_cs);
}

void preserve_save() {
    if (!g_cs_ready) return;
    EnterCriticalSection(&g_cs);
    g_preserve_n = 0;
    for (int i = 0; i < g_reg_n && g_preserve_n < 256; i++) {
        uintptr_t obj = g_reg[i].obj;
        if (!obj || !arena::is_committed_addr(obj + 0x20)) continue;
        uintptr_t surf = *(uintptr_t*)(obj + 0x20);
        if (surf && surf != 0xFFFFFFFFFFFFFFFFULL && readable(surf, 8))   // live valid driver surface only
            g_preserve[g_preserve_n++] = { obj, surf };
    }
    LeaveCriticalSection(&g_cs);
    rblog::write("RTV-PRESERVE: saved %d live +0x20 handles (of %d registered)", g_preserve_n, g_reg_n);
}

void preserve_restore() {
    if (!g_cs_ready) return;
    EnterCriticalSection(&g_cs);
    int restored = 0;
    for (int i = 0; i < g_preserve_n; i++) {
        uintptr_t obj = g_preserve[i].obj, surf = g_preserve[i].surf;
        if (!arena::is_committed_addr(obj + 0x20)) continue;
        if (*(uintptr_t*)(obj + 0x20) != surf) { *(uintptr_t*)(obj + 0x20) = surf; restored++; }
    }
    // FRESH-FRAME GAP: null the stale +0x20 of wrappers that died in forward play (not in g_reg => the live loop
    // above misses them) but were reverted-ALIVE by arena::load with a dangling external surf. The !is_arena_addr
    // filter leaves in-arena free-list residue untouched and nulls only out-of-arena (stale COM surface) values, so
    // the fresh-frame rtv_dtor's if(+0x20!=0) guard skips the Release. Disjoint from the live loop (g_reg vs g_destroyed).
    int nulled_d = 0;
    if (g_rtv_destroyed_fix) {
        for (int i = 0; i < g_destroyed_n; i++) {
            uintptr_t obj = g_destroyed[i];
            if (!arena::is_committed_addr(obj + 0x20)) continue;
            uintptr_t rv = *(uintptr_t*)(obj + 0x20);
            if (rv == 0 || arena::is_arena_addr(rv)) continue;   // null / in-arena residue => safe to leave
            *(uintptr_t*)(obj + 0x20) = 0; nulled_d++;           // out-of-arena stale surf => sever the edge
        }
        if (g_destroyed_overflow) rblog::write("RTV-PRESERVE: WARN g_destroyed[] overflowed %ld (raise cap)", (long)g_destroyed_overflow);
        g_destroyed_n = 0; g_destroyed_overflow = 0;             // cleared per rollback (deaths re-accumulate forward)
    }
    LeaveCriticalSection(&g_cs);
    rblog::write("RTV-PRESERVE: restored %d/%d live +0x20 over reverted-frame-N | nulled %d destroyed-wrapper stale out-of-arena surfs", restored, g_preserve_n, nulled_d);
}

// --- per-surface acquire/release counters (the live over-release assertion) --------------------
struct SurfRec { uintptr_t surf; int acquire; int release; };
static SurfRec g_surf[256];
static int g_surf_n = 0;
static void surf_acquire(uintptr_t surf) {
    if (!g_cs_ready || !surf) return;
    EnterCriticalSection(&g_cs);
    for (int i = 0; i < g_surf_n; i++) if (g_surf[i].surf == surf) { g_surf[i].acquire++; LeaveCriticalSection(&g_cs); return; }
    if (g_surf_n < 256) g_surf[g_surf_n++] = { surf, 1, 0 };
    LeaveCriticalSection(&g_cs);
}
static void surf_release(uintptr_t surf, int* acq, int* rel) {
    *acq = -1; *rel = -1;
    if (!g_cs_ready || !surf) return;
    EnterCriticalSection(&g_cs);
    for (int i = 0; i < g_surf_n; i++) if (g_surf[i].surf == surf) { g_surf[i].release++; *acq = g_surf[i].acquire; *rel = g_surf[i].release; break; }
    LeaveCriticalSection(&g_cs);
}

// --- The GATE: per-resim ctor set S = wrappers whose ctor actually fired this resim ------------
// Replaces the buggy birth_frame proxy (the DLL-static reg survives arena::load and
// gets address-clobbered by slot reuse; g_frame_counter isn't advanced during resim). Membership
// in S = "this wrapper's AddRef is being replayed this resim" = the exact invariant. Frame-ordered
// replay makes within-resim slot reuse safe (a persistent holder's dtor at its earlier replay frame
// precedes any later transient ctor reusing the slot). Cleared at resim start; dedup on insert.
static uintptr_t g_ctorset[512];
static int g_ctorset_n = 0;
static volatile LONG g_ctorset_overflow = 0;
static void set_insert(uintptr_t self) {
    if (!g_cs_ready || !self) return;
    EnterCriticalSection(&g_cs);
    for (int i = 0; i < g_ctorset_n; i++) if (g_ctorset[i] == self) { LeaveCriticalSection(&g_cs); return; }  // dedup
    if (g_ctorset_n < 512) g_ctorset[g_ctorset_n++] = self; else InterlockedIncrement(&g_ctorset_overflow);
    LeaveCriticalSection(&g_cs);
}
static bool set_contains(uintptr_t self) {
    if (!g_cs_ready) return false;
    EnterCriticalSection(&g_cs);
    bool found = false;
    for (int i = 0; i < g_ctorset_n; i++) if (g_ctorset[i] == self) { found = true; break; }
    LeaveCriticalSection(&g_cs);
    return found;
}
static volatile long g_epoch_set = 0;            // FIX #2 rtv_epoch_set.flag arms it (declared here — used by on_resim_start below)
static volatile long g_rb_epoch  = 1;            // bumped once per rollback (on_resim_start)

void on_resim_start() {
    if (!g_cs_ready) return;
    EnterCriticalSection(&g_cs);
    if (g_ctorset_overflow) rblog::write("RTV-FIX: WARN ctorset overflowed %ld (raise cap)", (long)g_ctorset_overflow);
    g_ctorset_n = 0;
    g_ctorset_overflow = 0;
    _InterlockedIncrement(&g_rb_epoch);   // EPOCH-SET: one rollback = one epoch; stale entries evict by epoch age
    LeaveCriticalSection(&g_cs);
}

// ════════════════════════════════════════════════════════════════════════════════════════════════════════════
// FIX #2: EPOCH-SCOPED REFCOUNT NEUTRALITY (external-resource leaf; A/B flag rtv_epoch_set.flag, default OFF)
// RE (FUN_14076F760): the shared Release fork (32 nDraw COM-wrapper classes) atomically dec's self+0xc; at 0 it forks
// on `self+0x8 stamp vs DAT_140E1B708 (a PER-FRAME counter)` — immediate-dtor OR push to a retirement ring that a
// per-frame drain (0x14053a570) empties in an ORDINARY future frame (resim_active==false). So a persistent wrapper's
// SPURIOUS replayed Release (its AddRef was pre-window, not replayed this resim) can have its terminal dtor fire in a
// FRESH frame, where view_dtor_decide's resim_active gate misses it. The FIX: capture the neutralize-
// intent at the Release-to-0 moment (keyed on self, the stable-within-peer address; not self+0x8 which the engine
// rewrites), carried forward in a rollback-EPOCH set, and consumed at the dtor whenever it fires — so net Release is
// timeline-correct independent of which drain destroys it or when. This is a strict SUPERSET-safe net: it only nulls a
// +0x20 that a persistent-spurious Release marked, which surf_husk/the resim-suppress would (eventually) also want gone.
// (g_epoch_set / g_rb_epoch declared above on_resim_start.)
static constexpr uintptr_t VIEW_FREE_IDA = 0x14076F760ULL;   // the shared 32-class Release fork
typedef uintptr_t (*view_free_fn)(void*);        // COM Release convention (returns refcount in rax) — pass rax through verbatim
static view_free_fn orig_view_free = nullptr;
static struct { uintptr_t self; long epoch; } g_neutralize[512];
static int g_neutralize_n = 0;
static volatile LONG g_nz_overflow = 0;
static volatile LONG64 g_nz_marked = 0, g_nz_consumed = 0, g_nz_fresh_gap = 0;   // fresh_gap = consumed where resim-suppress would not have (the residual this uniquely closes)
static void neutralize_mark(uintptr_t self) {    // record a persistent-spurious Release-to-0 (CS-held by caller)
    long ep = g_rb_epoch;
    for (int i = 0; i < g_neutralize_n; i++) if (g_neutralize[i].self == self) { g_neutralize[i].epoch = ep; return; }
    if (g_neutralize_n < 512) { g_neutralize[g_neutralize_n++] = { self, ep }; _InterlockedIncrement64(&g_nz_marked); }
    else {                                        // full: evict the oldest-epoch entry (staleness discipline, like g_destroyed cap)
        int oldest = 0; for (int i = 1; i < g_neutralize_n; i++) if (g_neutralize[i].epoch < g_neutralize[oldest].epoch) oldest = i;
        g_neutralize[oldest] = { self, ep }; InterlockedIncrement(&g_nz_overflow);
    }
}
static bool neutralize_consume(uintptr_t self) { // true => this dtor must be surface-neutral (consumes the entry once)
    if (!g_cs_ready) return false;
    bool hit = false;
    EnterCriticalSection(&g_cs);
    for (int i = 0; i < g_neutralize_n; i++) if (g_neutralize[i].self == self) {
        g_neutralize[i] = g_neutralize[--g_neutralize_n]; hit = true; _InterlockedIncrement64(&g_nz_consumed); break;
    }
    LeaveCriticalSection(&g_cs);
    return hit;
}
// The shared Release fork hook (installed only when g_epoch_set). At entry, if a resim is replaying and this wrapper's
// refcount is about to hit 0 (self+0xc==1) and it is PERSISTENT (its ctor did not replay this resim => not in the
// ctorset), its Release is spurious => mark it for neutralization at whatever future dtor call destroys it. Read-only
// except the DLL-side set. rax passed through verbatim (COM Release returns the refcount).
static uintptr_t hk_view_free(void* p1) {
    uintptr_t self = (uintptr_t)p1;
    if (resim::resim_active() && self && readable(self + 0xc, 4) && *(uint32_t*)(self + 0xc) == 1 && !set_contains(self)) {
        if (g_cs_ready) { EnterCriticalSection(&g_cs); neutralize_mark(self); LeaveCriticalSection(&g_cs); }
    }
    return orig_view_free(p1);
}
// Called from the +0x20 dtors: consume a pending neutralize-intent for `self`. Returns true => null +0x20 (like suppress).
// `already` = view_dtor_decide already decided to null (so this consume is redundant-but-harmless, don't count as the gap).
static bool epoch_neutralize(uintptr_t self, bool already) {
    if (!g_epoch_set) return false;
    if (!neutralize_consume(self)) return false;
    if (!already) {                               // the fresh-frame residual this uniquely closes (resim-suppress missed it)
        LONG64 n = _InterlockedIncrement64(&g_nz_fresh_gap);
        if (n <= 8 || (n % 256) == 0)
            rblog::write("RTV-EPOCH-SET #%lld: neutralized a persistent wrapper 0x%llX's +0x20 at a dtor the resim gate MISSED "
                         "(fresh-frame ring-drain over-release; epoch-scoped refcount neutrality)", (long long)n, (unsigned long long)self);
    }
    return true;
}

// --- ctors: birth-register + CLASS-C live assertion --------------------------------------------
static void on_ctor(uintptr_t self, const char* kind, bool is_create, uintptr_t parent) {
    uintptr_t surf = readable(self + 0x20, 8) ? *(uintptr_t*)(self + 0x20) : 0;
    reg_put(self, resim::current_frame(), surf);   // kept read-only for diagnostics; no longer drives suppression
    destroyed_prune(self);   // SLOT-REUSE prune: this address is re-created => legitimately re-owned, drop any stale g_destroyed entry
    if (surf) surf_acquire(surf);
    if (resim::resim_active()) {
        set_insert(self);   // The GATE: this wrapper's ctor (its AddRef) fired this resim => its Release is a real replay, don't suppress
        // CLASS C (Lane-1 read-only probe): a fresh surface created in-window may leak. Pair this
        // CREATE vs the same-resim DTOR offline: matched => benign realloc; unpaired => a real leak.
        if (is_create) {
            uintptr_t res = (parent > 0x10000 && readable(parent + 0x48, 8)) ? *(uintptr_t*)(parent + 0x48) : 0;
            rblog::write("CREATE-IN-RESIM[%s]: this=0x%llX surf=0x%llX parent=0x%llX res+0x48=0x%llX frame=%d rb_tgt=%d (pair vs same-resim DTOR)",
                kind, (unsigned long long)self, (unsigned long long)surf,
                (unsigned long long)parent, (unsigned long long)res,
                resim::current_frame(), resim::last_rollback_target());
            rblog::flush();
        }
    }
}
static void* hk_rtv_create(void* p1, int64_t p2, uint32_t p3) { void* r = orig_rtv_create(p1,p2,p3); on_ctor((uintptr_t)p1,"RTV",true,(uintptr_t)p2);  return r; }
static void* hk_rtv_wrap  (void* p1, void* p2, void* p3)     { void* r = orig_rtv_wrap  (p1,p2,p3); on_ctor((uintptr_t)p1,"RTV",false,(uintptr_t)p2); return r; }
static void* hk_dsv_ctor  (void* p1, int64_t p2, uint32_t p3) { void* r = orig_dsv_ctor (p1,p2,p3); on_ctor((uintptr_t)p1,"DSV",true,(uintptr_t)p2);  return r; }

// --- The FIX: suppress the spurious replayed Release for persistent wrappers during resim -------
// Returns true => caller must null +0x20 before orig (so orig's guarded Release is a no-op).
static bool view_dtor_decide(uintptr_t self, uintptr_t vtable_expected, const char* kind) {
    uintptr_t vt   = readable(self, 8)        ? *(uintptr_t*)self          : 0;
    uintptr_t surf = readable(self + 0x20, 8) ? *(uintptr_t*)(self + 0x20) : 0;
    // bad = a husk native surface: -1, dangling, OR (the 0x140781D15 UAF-reuse case) readable-but-garbage vtable.
    // Widened from the old handle-only test (surf==-1 || unreadable) which MISSED the reuse case (surf is a real heap
    // addr, its *vtable* is the "\Val" widestring). A husk is nulled in both phases (domain-valid-or-null), not just
    // resim-suppressed — see the `suppress || bad` return: the engine's own +0x20!=0 guard then skips the dead Release.
    bool bad   = surf_husk(surf);
    bool resim = resim::resim_active();
    bool in_set = set_contains(self);   // did this wrapper's ctor (AddRef) fire this resim?
    // The GATE (set-membership = the exact invariant): suppress the spurious replayed Release only
    // for wrappers whose AddRef was not replayed this resim (not in S). Immune to the registry
    // clobber + the g_frame_counter-not-advanced failure modes of the old birth_frame proxy.
    bool suppress = resim && surf != 0 && !bad && !in_set;

    int acq = -1, rel = -1;
    if (!suppress && surf && !bad) surf_release(surf, &acq, &rel);   // count only actual releases
    // RESIM-phase over-release post-fix must be 0; if it fires with in_set=1 the ctor replayed yet
    // still over-released => accounting incomplete. normal-phase over=counter artifact (+0x48 hold, residual #2).
    bool over = (acq >= 0 && rel > acq);

    RtvRec rec; bool known = reg_get(self, &rec);   // diagnostics only (birth no longer drives suppression)
    int tgt = resim::last_rollback_target();
    LONG c = InterlockedIncrement(&g_calls);
    bool log_it = bad || over || c <= 8;
    if (suppress) { LONG sc = InterlockedIncrement(&g_suppress_count); if ((sc % 64) == 1) log_it = true; }
    if (log_it) {
        uintptr_t ra = (uintptr_t)__builtin_return_address(0), base = addr::g_base;
        uintptr_t ra_ida = (ra >= base && ra < base + 0x1000000ULL) ? (ra - base + 0x140000000ULL) : 0;
        rblog::write("%s-DTOR%s%s%s: this=0x%llX vt=%s surf=0x%llX phase=%s in_set=%d caller(IDA)=0x%llX "
                     "acq=%d rel=%d known=%d birth=%d rb_tgt=%d call#%ld",
            kind, bad?"[BAD-SURF]":"", over?"[OVER-REL-FIXFAIL]":"", suppress?"[SUPPRESSED]":"",
            (unsigned long long)self, (vt==vtable_expected)?"OK":"MISMATCH",
            (unsigned long long)surf, resim?"RESIM":"normal", in_set?1:0, (unsigned long long)ra_ida,
            acq, rel, known?1:0, known?rec.birth_frame:-1, tgt, (long)c);
        if (bad || over) rblog::flush();
    }
    // DOMAIN-VALID-OR-NULL (both phases): a husk surface (bad) that is not a resim-suppress must still be nulled —
    // this is the normal-play (resim=0) path the crash took. Count it distinctly so a long run shows the crash-close firing.
    if (bad && !suppress && surf != 0) {
        LONG64 c = _InterlockedIncrement64(&g_surf_husk_sev);
        if (c <= 8 || (c % 64) == 0)
            rblog::write("%s-SURF-HUSK #%lld: nulling husk native surface 0x%llX (garbage vtable) in wrapper 0x%llX +0x20 — domain-valid-or-null (0x140781D15 close) phase=%s",
                         kind, (long long)c, (unsigned long long)surf, (unsigned long long)self, resim ? "RESIM" : "normal");
    }
    return suppress || bad;   // null +0x20 on a husk surface too (not only the resim over-release suppress)
}
static void* hk_rtv_dtor(void* p1, uint64_t p2) {
    bool sup = view_dtor_decide((uintptr_t)p1, g_rtv_vtable, "RTV");
    if (sup || epoch_neutralize((uintptr_t)p1, sup)) *(uintptr_t*)((uintptr_t)p1 + 0x20) = 0;   // EPOCH-SET consumes a pending fresh-frame neutralize-intent
    if (!resim::resim_active()) { destroyed_push((uintptr_t)p1); reg_remove((uintptr_t)p1); }   // real death => track (may revert-alive w/ stale surf) + prune; replayed-resim death => keep (persistent)
    return orig_rtv_dtor(p1, p2);
}
static void* hk_dsv_dtor(void* p1, uint64_t p2) {
    bool sup = view_dtor_decide((uintptr_t)p1, g_dsv_vtable, "DSV");
    if (sup || epoch_neutralize((uintptr_t)p1, sup)) *(uintptr_t*)((uintptr_t)p1 + 0x20) = 0;   // EPOCH-SET consumes a pending fresh-frame neutralize-intent
    if (!resim::resim_active()) { destroyed_push((uintptr_t)p1); reg_remove((uintptr_t)p1); }   // real death => track + prune; replayed-resim death => keep (persistent)
    return orig_dsv_dtor(p1, p2);
}

// --- The FIX (Texture own-surface +0x48): same set-gate principle, new carrier -----
// FUN_140782060 acquires the Texture's OWN surface at +0x48 (param_1[9]) once (device-create branch,
// fresh refcount-1 surface, +0x50==0). FUN_140781ac0 releases it once via surf vtable+0x10 (COM
// Release), guarded `if(+0x50==0){ if(+0x48!=0){ Release; +0x48=0; } }`. So a PERSISTENT Texture's
// replayed dtor re-Releases the own-surface with no replayed acquire => driver refcount underflow =>
// -1 (confirmed over-release on an earlier run). Suppress = null +0x48 (orig's guarded Release
// no-ops; orig still re-stamps vtables via FUN_1407a3250 + frees the wrapper). +0x50 is EXCLUDED
// (it releases via vtable+0x28 = the source Texture's arena-domain internal +0xc refcount, reverted
// wholesale by arena::load — the double-apply pathology does not apply). Same ctor-set
// gate as the RTV/DSV +0x20 (membership re-derives per resim, no pooled state).
static void hk_tex_ctor(void* p1, int64_t p2, void* p3, void* p4) {
    orig_tex_ctor(p1, p2, p3, p4);
    uintptr_t self = (uintptr_t)p1;
    // own-surface (device-create) case only: +0x50 == 0 && +0x48 != 0
    if (readable(self + 0x50, 8) && *(uintptr_t*)(self + 0x50) == 0) {
        uintptr_t surf = readable(self + 0x48, 8) ? *(uintptr_t*)(self + 0x48) : 0;
        if (surf) {
            surf_acquire(surf);   // assertion baseline (count all acquires)
            if (resim::resim_active()) {
                set_insert(self);   // The GATE: this Texture's own-surface acquire is replayed this resim
                rblog::write("CREATE-IN-RESIM[TEX]: this=0x%llX surf=0x%llX frame=%d rb_tgt=%d (+0x48 acquire)",
                    (unsigned long long)self, (unsigned long long)surf,
                    resim::current_frame(), resim::last_rollback_target());
                rblog::flush();
            }
        }
    }
}
static volatile LONG64 g_arr_sev = 0;
// A wrapper element is DEAD (must not be Released) if its vtable is 0 (dtor'd/recycled) or out of the module's
// .rdata range (a recycled non-object: floats/garbage). At Texture-DTOR time an element is never mid-construction,
// so vtable==0 is unambiguously dead here (unlike a global sweep). Any IN-MODULE vtable = a live wrapper (kept,
// regardless of RTV subtype) ⇒ zero false-positive on valid elements.
static inline bool wrapper_dead(uintptr_t e) {
    if (!readable(e, 8)) return true;
    uintptr_t vt = *(uintptr_t*)e;
    if (vt == 0) return true;
    return (vt < addr::g_base) || ((vt - addr::g_base) >= 0x2000000ULL);
}
static void hk_tex_dtor(void* p1) {
    uintptr_t self = (uintptr_t)p1;
    // RTV/DSV ARRAY SEV (the forward-play render-wrapper close, crash 0x140781B0A): the dtor walks +0x60 (RTV*)
    // and +0x68 (DSV*) arrays (count +0x70) and Releases each via [elem]->vt+0x28 — but it null-checks only the
    // ELEMENT pointer, not the element's vtable. A wrapper that DIED in forward play (holder restored stale by a
    // rollback, then the wrapper's own lifecycle diverged and it died) is non-null with vtable=0 ⇒ crash. LIFE-FLOOR
    // covers only RESIM deaths and the Material sweep skips the 0x140bbe family — this is the uncovered gap. Null
    // each dead element so the dtor's own element-null-check skips it (a dead wrapper must not be Released anyway).
    if (readable(self + 0x70, 4)) {
        uint32_t n = *(uint32_t*)(self + 0x70); if (n > 4096) n = 0;
        uintptr_t rtv = readable(self + 0x60, 8) ? *(uintptr_t*)(self + 0x60) : 0;
        uintptr_t dsv = readable(self + 0x68, 8) ? *(uintptr_t*)(self + 0x68) : 0;
        // Two severs per element: (1) TEX-ARR-SEV — a DEAD-VTABLE wrapper: null the ARRAY SLOT so the
        // engine's element-null-check skips it (a dead wrapper must not be Released). (2) SURF-husk — a LIVE wrapper
        // (valid vtable, dispatches fine) whose native SURFACE (+0x20) is a UAF-reuse husk (garbage surface-vtable):
        // null the WRAPPER's +0x20 (not the slot) so the wrapper is still Released normally but its RTV/DSV dtor's own
        // +0x20!=0 guard skips the dead surface Release (0x140781D15). This is the guaranteed path — hk_tex_dtor runs
        // before orig_tex_dtor's array walk, independent of whether the element's vtable+0x28 Release is itself hooked.
        for (uint32_t i = 0; i < n; i++) {
            if (rtv && readable(rtv + (uintptr_t)i*8, 8)) { uintptr_t* e = (uintptr_t*)(rtv + (uintptr_t)i*8); uintptr_t w = *e;
                if (w && wrapper_dead(w)) { *e = 0; LONG64 c = _InterlockedIncrement64(&g_arr_sev);
                    if (c <= 4 || (c % 64) == 0) rblog::write("TEX-ARR-SEV #%lld: nulled a DEAD RTV in Texture 0x%llX +0x60[%u] (forward-play render-wrapper 0x140781B0A close)", (long long)c, (unsigned long long)self, i); }
                else if (w && readable(w + 0x20, 8) && surf_husk(*(uintptr_t*)(w + 0x20))) { *(uintptr_t*)(w + 0x20) = 0;
                    LONG64 c = _InterlockedIncrement64(&g_surf_husk_sev);
                    if (c <= 8 || (c % 64) == 0) rblog::write("TEX-SURF-HUSK #%lld: nulled husk native surface in LIVE RTV 0x%llX +0x20 (Texture 0x%llX +0x60[%u]) — pre-orig domain-valid-or-null (0x140781D15 close)", (long long)c, (unsigned long long)w, (unsigned long long)self, i); } }
            if (dsv && readable(dsv + (uintptr_t)i*8, 8)) { uintptr_t* e = (uintptr_t*)(dsv + (uintptr_t)i*8); uintptr_t w = *e;
                if (w && wrapper_dead(w)) { *e = 0; _InterlockedIncrement64(&g_arr_sev); }
                else if (w && readable(w + 0x20, 8) && surf_husk(*(uintptr_t*)(w + 0x20))) { *(uintptr_t*)(w + 0x20) = 0; _InterlockedIncrement64(&g_surf_husk_sev); } }
        }
    }
    bool own  = readable(self + 0x50, 8) && *(uintptr_t*)(self + 0x50) == 0;
    uintptr_t surf = (own && readable(self + 0x48, 8)) ? *(uintptr_t*)(self + 0x48) : 0;
    bool bad  = (surf == 0xFFFFFFFFFFFFFFFFULL) || (surf != 0 && !readable(surf, 8));
    bool ext  = surf > 0x10000 && !arena::is_arena_addr(surf);
    bool resim = resim::resim_active();
    bool in_set = set_contains(self);
    bool suppress = resim && surf != 0 && !bad && ext && !in_set;
    if (!suppress && own && surf && !bad) {              // count actual (non-suppressed) releases
        int acq = -1, rel = -1; surf_release(surf, &acq, &rel);
        if (acq >= 0 && rel > acq) {                     // fix missed a spurious +0x48 release
            rblog::write("TEX-DTOR[OVER-REL-FIXFAIL]: this=0x%llX surf=0x%llX phase=%s in_set=%d acq=%d rel=%d frame=%d rb_tgt=%d",
                (unsigned long long)self, (unsigned long long)surf, resim?"RESIM":"normal", in_set?1:0,
                acq, rel, resim::current_frame(), resim::last_rollback_target());
            rblog::flush();
        }
    } else if (suppress) {
        LONG sc = InterlockedIncrement(&g_suppress_count);
        if ((sc % 64) == 1)
            rblog::write("TEX-DTOR[SUPPRESSED]: this=0x%llX surf=0x%llX phase=RESIM frame=%d rb_tgt=%d",
                (unsigned long long)self, (unsigned long long)surf,
                resim::current_frame(), resim::last_rollback_target());
    }
    if (suppress) *(uintptr_t*)(self + 0x48) = 0;        // null the carrier => orig's guarded Release no-ops
    orig_tex_dtor(p1);
}

void init() {
    InitializeCriticalSection(&g_cs);
    g_cs_ready = true;
    g_rtv_vtable = addr::resolve(RTV_VTABLE_IDA);
    g_dsv_vtable = addr::resolve(DSV_VTABLE_IDA);
    struct { uintptr_t ida; void* hk; void** orig; const char* name; } hooks[] = {
        { RTV_DTOR_IDA,   (void*)&hk_rtv_dtor,   (void**)&orig_rtv_dtor,   "rtv_dtor(FIX)" },
        { DSV_DTOR_IDA,   (void*)&hk_dsv_dtor,   (void**)&orig_dsv_dtor,   "dsv_dtor(FIX)" },
        { RTV_CREATE_IDA, (void*)&hk_rtv_create, (void**)&orig_rtv_create, "rtv_create"    },
        { RTV_WRAP_IDA,   (void*)&hk_rtv_wrap,   (void**)&orig_rtv_wrap,   "rtv_wrap"      },
        { DSV_CTOR_IDA,   (void*)&hk_dsv_ctor,   (void**)&orig_dsv_ctor,   "dsv_ctor"      },
        { TEX_CTOR_IDA,   (void*)&hk_tex_ctor,   (void**)&orig_tex_ctor,   "tex_ctor"      },
        { TEX_DTOR_IDA,   (void*)&hk_tex_dtor,   (void**)&orig_tex_dtor,   "tex_dtor(FIX +0x48)" },
    };
    for (auto& h : hooks) {
        void* t = (void*)addr::resolve(h.ida);
        MH_STATUS st = MH_CreateHook(t, h.hk, h.orig);
        rblog::write("RTV-FIX: hook %s @0x%llX %s", h.name, (unsigned long long)(uintptr_t)t, st==MH_OK?"OK":"FAILED");
    }
    // FIX #2 EPOCH-SET (A/B, default OFF): install the shared Release-fork hook only when armed — it sits on a hot
    // 32-class COM Release, so it stays uninstalled (zero cost) unless rtv_epoch_set.flag opts into the A/B.
    g_epoch_set = arena::startup_flag("RTV_EPOCH_SET", "rtv_epoch_set.flag") ? 1 : 0;
    if (g_epoch_set) {
        void* t = (void*)addr::resolve(VIEW_FREE_IDA);
        MH_STATUS st = MH_CreateHook(t, (void*)&hk_view_free, (void**)&orig_view_free);
        rblog::write("RTV-EPOCH-SET: ARMED — hook shared Release fork FUN_14076F760 @0x%llX %s (epoch-scoped +0x20 neutrality; closes the fresh-frame ring-drain over-release the resim gate misses)",
            (unsigned long long)(uintptr_t)t, st==MH_OK?"OK":"FAILED");
    }
    rblog::write("RTV-FIX: refcount-neutral resim suppression ACTIVE (RTV vt 0x%llX, DSV vt 0x%llX) | epoch-set=%s",
        (unsigned long long)g_rtv_vtable, (unsigned long long)g_dsv_vtable, g_epoch_set ? "ARMED" : "off");
}

void report() {
    if (!g_nz_marked && !g_epoch_set) return;
    bool w = rblog::is_suppressed(); rblog::suppress(false);
    rblog::write("RTV-EPOCH-SET: marked=%lld consumed=%lld fresh-frame-gap-closed=%lld set_live=%d overflow=%ld "
                 "(fresh-frame-gap-closed>0 => the epoch-set caught over-releases the resim_active gate structurally misses)",
        (long long)g_nz_marked, (long long)g_nz_consumed, (long long)g_nz_fresh_gap, g_neutralize_n, (long)g_nz_overflow);
    rblog::suppress(w);
}

} // namespace rtv_probe
