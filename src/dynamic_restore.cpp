// dynamic_restore.cpp — RestoreDescriptor registry + phase driver (SKELETON).
//
// This first build RE-HOMES the existing PRESERVE / NULL-stale fixes AS descriptors
// and re-expresses their current do_rollback calls through the registry. The ops are
// THIN ADAPTERS over the existing self-enumerating fns (handle_preserve::save/restore,
// dead_vtable_unlink::validate, rtv_probe::preserve_save/restore) — the driver does not enumerate
// instances and pass them in (the existing fns self-enumerate; enumerating here would
// change behavior). Skeleton ops are whole-system adapters (inst arg unused, 0).
//
// arena::load + restore_allocators stay intact — this layer wraps/re-expresses only
// the existing PRESERVE / NULL-stale layer. The allocator REBUILD (W_REBUILD) and the
// INFERRED descriptors are oracle-gated FOLLOW-UPS and are not registered here.
//
// The field_map / Identity entries below are DOCUMENTATION of the re-homed descriptors
// (read off the shipping source). In the skeleton they are not
// driver-interpreted (the adapter ops carry the behavior). handle_preserve.cpp's g_entries[] /
// dead_vtable_unlink.cpp's walk / rtv_probe's g_reg[] remain the field-maps OF RECORD; these Field[]
// arrays DOCUMENT them (e.g. SRENDER_FIELDS documents the sRender subset; the sUnit
// CS entries that register_singleton_cs() adds live in handle_preserve.cpp, not duplicated here).
// They exist so the later (oracle-gated) by-field driver can interpret them without re-RE.

#include "dynamic_restore.h"
#include "handle_preserve.h"
#include "dead_vtable_unlink.h"
#include "rtv_probe.h"
#include "arena.h"
#include "audio_probe.h"
#include "log.h"
#include <windows.h>
#include <cstdint>

namespace dyn_restore {

// ============================================================================
// Thin adapter ops — wrap the existing self-enumerating fns. inst unused (=0).
// ============================================================================
static void op_handle_preserve_save(uintptr_t)        { handle_preserve::save(); }
static void op_handle_preserve_restore(uintptr_t)     { handle_preserve::restore(); }
static void op_rtv_preserve_save(uintptr_t)    { rtv_probe::preserve_save(); }
static void op_rtv_preserve_restore(uintptr_t) { rtv_probe::preserve_restore(); }
static void op_dead_vtable_unlink_post_load(uintptr_t)   { dead_vtable_unlink::validate(dead_vtable_unlink::POST_LOAD); }
static void op_dead_vtable_unlink_post_resim(uintptr_t)  { dead_vtable_unlink::validate(dead_vtable_unlink::POST_RESIM); }

// F_REDERIVE (PAGE layer — coarse) — exclude all of sRender (8.9MB) from the arena revert: kept LIVE, the
// resim re-renders it. Render is a deterministic function of gameplay (the resim re-renders it), and the arena reverts in-place so the body's pointers into gameplay stay valid. Wholesale region
// exclude — no per-page carve logic (pages do COARSE region verdicts only).
// The 2 authoritative gameplay-read carves (+0x6764c frame counter, +0x67648 flip bit) are a FIELD-layer
// concern, not a page concern: IF the resim's render doesn't re-derive them, they get a tiny FIELD-level
// save/restore (handle_preserve-style, 8 bytes by offset) — added only if gp_crc names them as the divergence. We do
// not pre-bake a page hack for them. handle_preserve (descriptor 1) preserves the D3D/OS handles.
// AUDIO DOMAIN PRESERVE: audio never rolls back. The dominant
// remaining crash (2 repros) = the split-epoch sound domain: arena::load reverted the IN-ARENA sSound body
// (stream read-position +0x37C / decoder-ctx ptr +0x360 per entry @ sSound+0x1756C stride 0xB30) to frame N
// while the OUT-OF-ARENA Ogg decoder (pre-redirect startup alloc, just past the arena end) kept advancing =>
// the audio thread walks the mismatched pair past end-of-stream => memcpy AV. Fix = keep the whole audio
// domain at the LIVE epoch (the sRender precedent; GGPO never rewinds audio; gameplay isolation statically
// proven — command flow is one-way into audio, no read-back; 11 clean rollbacks of empirical proof).
// NOTE: set_rederive_exclusions MEMSETs the bitmap per call => all regions must go in one call.
static void op_srender_rederive_exclude(uintptr_t) {
    audio_probe::run_once();   // read-only: DERIVE the audio domain as a type set (fires once), then proceed.
    uintptr_t mod = (uintptr_t)GetModuleHandleA("umvc3.exe");
    if (!mod) { arena::clear_rederive_exclusions(); return; }
    uintptr_t bases[80]; size_t sizes[80]; int n = 0;   // sRender + heapzone + sSound + sub + 8 voices + chan + 32 strips + resources

    uintptr_t sr = *(uintptr_t*)(mod + 0xE179A8);          // sRender singleton (verified — handle_preserve uses it)
    if (sr && arena::is_arena_addr(sr)) { bases[n] = sr; sizes[n] = 0x889838; n++; }

    // MUSIC PRESERVE — keep the HeapAlloc-redirect zone LIVE: the redirect zone (top
    // 256MB of the arena, [end-256MB, end)) holds the streaming-ogg decode BUFFERS (libvorbis malloc/realloc). It is
    // CRT/OUTPUT memory, not gameplay sim state (gameplay = MtAllocator). arena::load reverts its dirty pages =>
    // the permanent music stream's buffer rewinds under a live decoder that nothing re-triggers => the stream reads
    // incoherent data and DIES (and unlike SFX, music is never re-derived => never returns). GGPO: don't roll back
    // audio. Exclude the whole zone from revert. (If gp_crc diverges, some gameplay malloc lives here => narrow it.)
    { uintptr_t hzbase = arena::end() - (256ull * 1024 * 1024);
      if (arena::is_arena_addr(hzbase)) { bases[n] = hzbase; sizes[n] = 256ull * 1024 * 1024; n++; } }

    // Audio is no longer page-excluded here (regression fix): the streaming audio objects
    // (sSound body, ss_sub, voiceP/channel/strips/resource) are slab-packed in the SHARED Resource/Global
    // MtScalableAllocator pools. Page-excluding them kept allocator FREE-LIST nodes LIVE across the rollback
    // (srcF=-3), and in arena::load the rederive-exclude check overrides the coherent-full revert => the free-list reciprocity tore (INVARIANT-CHECK POSTLOAD breaks on ctrl 0xD544E90 Resource /
    // 0xD545BB0 Unit at the crash frame) => corrupt slab handout => the FUN_14053a250 present-walk crash. Prior RE
    // already said sound is not page-separable; needs PER-OBJECT keep-live. So those
    // objects are now kept live by audio_preserve::save/restore (capture-before-load / write-back-after, by extent) —
    // the object keeps its live epoch, the page reverts normally underneath it (allocator neighbor heals). Only the
    // two big separate regions stay page-excluded here: sRender (above) + the heap-redirect zone (below) — neither
    // overlaps the small-slab allocator pools.

    if (n == 0) { arena::clear_rederive_exclusions(); return; }
    arena::set_rederive_exclusions(bases, sizes, n);       // One call — the bitmap is rebuilt per registration
}

// ============================================================================
// DESCRIPTOR 1 — sRender persistent handles + singleton CS (re-homes handle_preserve.cpp)
// Identity: ID_SINGLETON_PTR { 0x140E179A8 } (sRender; handle_preserve also walks sUnit CS)
// Discipline: F_PRESERVE handles / F_LOCK CSes.
// handle_preserve.cpp's g_entries[] is the field-map of record; this Field[] DOCUMENTS it.
// PhaseBinding: SAVE -> handle_preserve::save; POST_LOAD -> handle_preserve::restore.
// ============================================================================
static const Field SRENDER_FIELDS[] = {
    { 0x8,      8, F_LOCK,     "+0x8 CS/heap" },
    { 0xB0,     8, F_PRESERVE, "+0xB0 D3DDevice9**" },
    { 0xC0,     8, F_PRESERVE, "+0xC0 D3D9*" },
    { 0xE8,     8, F_PRESERVE, "+0xE8 render thread HANDLE" },
    { 0xF8,     8, F_PRESERVE, "+0xF8 go_event HANDLE" },
    { 0x100,    8, F_PRESERVE, "+0x100 done_event HANDLE" },
    { 0x1A0,    8, F_PRESERVE, "+0x1A0 state obj" },
    { 0x1A8,    8, F_PRESERVE, "+0x1A8 state obj" },
    { 0x1B0,    8, F_PRESERVE, "+0x1B0 state obj" },
    { 0x1C0,    8, F_PRESERVE, "+0x1C0 state obj" },
    { 0x8897B8, 8, F_PRESERVE, "+0x8897B8 HWND primary" },
    { 0x8897C0, 8, F_PRESERVE, "+0x8897C0 SwapChain primary" },
    { 0x8897E0, 8, F_PRESERVE, "+0x8897E0 HWND secondary" },
    { 0x8897E8, 8, F_PRESERVE, "+0x8897E8 SwapChain secondary" },
    { 0x20,     8, F_LOCK,     "+0x20 sRender CS.Semaphore" },
};
static const PhaseBinding SRENDER_BINDINGS[] = {
    { PH_SAVE,      10, op_handle_preserve_save },     // do_rollback, before arena::load
    { PH_POST_LOAD, 10, op_handle_preserve_restore },  // do_rollback, after arena::load
};

// ============================================================================
// DESCRIPTOR 2 — RTV/DSV +0x20 render-domain preserve (re-homes rtv_probe preserve)
// Identity: ID_BIRTH_REGISTRY (rtv_probe g_reg[] accreted at ctor), vt RTV/DSV.
// Discipline: F_PRESERVE (external driver-surface handle out of arena).
// NOTE: the DURING_RESIM dtor-suppress (hk_rtv_dtor / hk_dsv_dtor / hk_tex_dtor)
// is not a driver walk — it fires from rtv_probe's MinHook trampolines gated by
// g_resim_active, installed at rtv_probe::init(). It is documented here as a
// PH_DURING_RESIM binding with a NULL op (the engine-side hook is the carrier).
// ============================================================================
static const Field RTV_FIELDS[] = {
    { 0x20, 8, F_PRESERVE, "+0x20 native driver surface (RTV/DSV)" },
};
static const PhaseBinding RTV_BINDINGS[] = {
    { PH_SAVE,        10, op_rtv_preserve_save },     // do_rollback, before arena::load
    { PH_POST_LOAD,   20, op_rtv_preserve_restore },  // do_rollback, after arena::load (order 20: after handle_preserve)
    { PH_DURING_RESIM, 0, nullptr },                  // dtor-suppress = MinHook trampolines (rtv_probe::init)
};

// ============================================================================
// DESCRIPTOR 3 — scheduler bad-vtable unlink (re-homes dead_vtable_unlink.cpp)
// Identity: ID_SCHEDULER_WALK (sUnit lines 0..127, +0x58+line*0x30 head, +0x20 next)
// Discipline: F_NULL_STALE — stale ptr to a gone object; unlink from all dispatch.
// PhaseBinding: POST_LOAD -> dead_vtable_unlink POST_LOAD (order 90: after all pointer restores,
// per the hard dep "NULL_STALE must follow all pointer restores"); POST_RESIM.
// ============================================================================
static const Field SCHED_FIELDS[] = {
    { 0x00, 8, F_NULL_STALE, "vtable@0 (validity predicate)" },
    { 0x18, 8, F_NULL_STALE, "+0x18 prev (unlink)" },
    { 0x20, 8, F_NULL_STALE, "+0x20 next (unlink)" },
    { 0x10, 4, F_NULL_STALE, "+0x10 flags/line_id (mark dead)" },
};
static const PhaseBinding SCHED_BINDINGS[] = {
    { PH_POST_LOAD,  90, op_dead_vtable_unlink_post_load },   // do_rollback, after all preserves (order 90)
    { PH_POST_RESIM, 10, op_dead_vtable_unlink_post_resim },  // do_rollback, post-resim
};

// ============================================================================
// DESCRIPTOR 4 — sRender render-body RE-DERIVE exclusion (the "remove pages" option; uses F_REDERIVE at last)
// Identity: ID_SINGLETON_PTR { 0x140E179A8 } (sRender). F_REDERIVE body + F_SCALAR_EXACT carve.
// PhaseBinding: PH_SAVE -> op registers the arena RE-DERIVE exclusions before arena::load.
// ============================================================================
static const Field SRENDER_REDERIVE_FIELDS[] = {
    { 0x0,     0x67000,  F_REDERIVE,     "render body (pre-carve) — re-derived by resim" },
    { 0x6764c, 4,        F_SCALAR_EXACT, "+0x6764c frame counter (authoritative gameplay-read) — carve page reverts" },
    { 0x67648, 4,        F_SCALAR_EXACT, "+0x67648 flip bit (authoritative gameplay-read) — carve page reverts" },
    { 0x68000, 0x821838, F_REDERIVE,     "render body (post-carve) — re-derived by resim" },
};
static const PhaseBinding SRENDER_REDERIVE_BINDINGS[] = {
    { PH_SAVE, 5, op_srender_rederive_exclude },   // do_rollback, before arena::load
};

// ============================================================================
// the REGISTRY
// ============================================================================
static const RestoreDescriptor g_descriptors[] = {
    {
        "sRender_persistent_handles",
        { ID_SINGLETON_PTR, 0x140E179A8, 0, 0, 0, nullptr },
        SRENDER_FIELDS, (int)(sizeof(SRENDER_FIELDS)/sizeof(SRENDER_FIELDS[0])),
        W_NONE,
        SRENDER_BINDINGS, (int)(sizeof(SRENDER_BINDINGS)/sizeof(SRENDER_BINDINGS[0])),
        CONF_HIGH, false,
        "external referents (D3D/OS handles) are never rolled back => PRESERVE; CSes => QUIESCENT-RESET",
    },
    {
        "nDraw_RenderTargetView_DepthStencilView_0x20",
        { ID_BIRTH_REGISTRY, 0x140BBEBD8, 0, 0x140BBEBD8, 0, nullptr },
        RTV_FIELDS, (int)(sizeof(RTV_FIELDS)/sizeof(RTV_FIELDS[0])),
        W_NONE,
        RTV_BINDINGS, (int)(sizeof(RTV_BINDINGS)/sizeof(RTV_BINDINGS[0])),
        CONF_HIGH, false,
        "OVER-REL-FIXFAIL=0 across a long run; preserve set disjoint from dtor-suppress set",
    },
    {
        "scheduler_bad_vtable_unlink",
        { ID_SCHEDULER_WALK, 0x140E17698, 0, 0, 0, nullptr },
        SCHED_FIELDS, (int)(sizeof(SCHED_FIELDS)/sizeof(SCHED_FIELDS[0])),
        W_NONE,
        SCHED_BINDINGS, (int)(sizeof(SCHED_BINDINGS)/sizeof(SCHED_BINDINGS[0])),
        CONF_HIGH, false,
        "no crash relocates to a dispatch over a bad-vtable entity",
    },
    {
        "sRender_body_rederive",
        { ID_SINGLETON_PTR, 0x140E179A8, 0, 0, 0x889838, nullptr },
        SRENDER_REDERIVE_FIELDS, (int)(sizeof(SRENDER_REDERIVE_FIELDS)/sizeof(SRENDER_REDERIVE_FIELDS[0])),
        W_NONE,
        SRENDER_REDERIVE_BINDINGS, (int)(sizeof(SRENDER_REDERIVE_BINDINGS)/sizeof(SRENDER_REDERIVE_BINDINGS[0])),
        CONF_HIGH, false,
        "gp_crc bit-identical across a long run (gameplay unaffected) + render re-derives to a valid frame",
    },
};
static const int G_DESCRIPTOR_COUNT = (int)(sizeof(g_descriptors)/sizeof(g_descriptors[0]));

// active(d): flag-gated descriptors run only when their flag is set. Skeleton has none.
static bool active(const RestoreDescriptor& d) {
    if (d.flag_gated) return false;   // no feature flags wired in the skeleton
    return true;
}

// ============================================================================
// DRIVER
// ============================================================================
static volatile long g_ops_fired = 0;   // re-home verification tally (logged post-suppress per rollback)

// run one descriptor's bindings for one phase, in ascending `order`.
static void run_descriptor_phase(const RestoreDescriptor& d, Phase phase) {
    if (!active(d)) return;
    // Selection sort over the (small) binding set by order, filtered to this phase.
    // Stable-enough: ties keep registry order via the < comparison.
    int idx[16];
    int n = 0;
    for (int i = 0; i < d.binding_count && n < 16; i++)
        if (d.bindings[i].phase == phase) idx[n++] = i;
    for (int a = 0; a < n; a++) {
        int best = a;
        for (int b = a + 1; b < n; b++)
            if (d.bindings[idx[b]].order < d.bindings[idx[best]].order) best = b;
        int t = idx[a]; idx[a] = idx[best]; idx[best] = t;
    }
    for (int a = 0; a < n; a++) {
        const PhaseBinding& pb = d.bindings[idx[a]];
        if (pb.op) { pb.op(0); g_ops_fired++; }   // op==0 => external-hook carrier (PH_DURING_RESIM dtor-suppress)
    }
}

void run(const char* descriptor_name, Phase phase) {
    for (int i = 0; i < G_DESCRIPTOR_COUNT; i++) {
        const RestoreDescriptor& d = g_descriptors[i];
        bool match = (d.name == descriptor_name);
        if (!match) {   // also accept value-equal names (string literals)
            const char* a = d.name; const char* b = descriptor_name;
            match = true;
            while (*a && *b) { if (*a != *b) { match = false; break; } a++; b++; }
            if (match && (*a || *b)) match = false;
        }
        if (match) { run_descriptor_phase(d, phase); return; }
    }
    rblog::write("DYN-RESTORE: run(\"%s\", phase=%d) — no such descriptor", descriptor_name, (int)phase);
}

// Grouped phase-outer walk — the DESIGN ARTIFACT (not the skeleton wire-in path).
// Becomes the wire-in path only once D3D9/RSUB/allocators/CS-reset are also descriptors.
void run_phase(Phase phase) {
    // phase-outer, descriptor-inner; within a descriptor, bindings sort by order.
    for (int i = 0; i < G_DESCRIPTOR_COUNT; i++)
        run_descriptor_phase(g_descriptors[i], phase);
}

int descriptor_count() { return G_DESCRIPTOR_COUNT; }
const RestoreDescriptor* descriptor_at(int i) {
    if (i < 0 || i >= G_DESCRIPTOR_COUNT) return nullptr;
    return &g_descriptors[i];
}
long ops_fired_and_reset() { long v = g_ops_fired; g_ops_fired = 0; return v; }

void init() {
    rblog::write("DYN-RESTORE: registry init — %d descriptors (skeleton: handle_preserve/rtv-preserve/dead_vtable_unlink)",
                 G_DESCRIPTOR_COUNT);
    for (int i = 0; i < G_DESCRIPTOR_COUNT; i++) {
        const RestoreDescriptor& d = g_descriptors[i];
        rblog::write("DYN-RESTORE:   [%d] %s  fields=%d bindings=%d conf=%d gated=%d",
                     i, d.name, d.field_count, d.binding_count, d.confidence, d.flag_gated ? 1 : 0);
    }
}

} // namespace dyn_restore
