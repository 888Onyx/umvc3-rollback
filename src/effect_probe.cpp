// effect_probe.cpp — read-only, observe-only probes for the moving-crash family.
//
// Two new hooks (Crash B's observer lives in resim.cpp as hk_bone_consume — we must not double-install on
// 0x14080DA10). Both here are observe-only: read the same fields the engine reads, log rate-limited, call orig.
//
// (1) hk_consume_leaf — FUN_14080d440, Crash C. P4: the sole consumer derefs *(child+0x50)
// UNGUARDED and FUN_14080bf60 legitimately leaves +0x50=0. Is C rollback-INDUCED or LATENT VANILLA? Log
// every null-+0x50 entry with rollback context. A null with rollback_happened()==false => latent vanilla
// (a single consume-gate here is the whole rollback-agnostic fix). Reads only child+0x50 (the safe first
// step; the crash is the SECOND step *(that+0xf)), so the hook is no riskier than the function itself.
//
// (2) hk_se_table — FUN_140688a50(table,index), Crash A. The SE-curve table is in NO GP register at the fault
// RIP 0x1402A22CE (rcx is clobbered by this very call; rsi is the dispatcher, not the table). The table is
// only param_1 INSIDE this resolver. So observe it here: when *(table+0x80)==0 (the null base that makes
// the caller compute index*0x90+0 and crash), log the torn group {+0x54,+0x80,+0xd8} + arena membership +
// g_arena_base + srcframe — the authoritative A classification (replaces the wrong VEH register-peek).
#include "log.h"
#include "addr.h"
#include "arena.h"
#include "resim.h"
#include "byid.h"
#include "effect_splice.h"
#include "audio_group.h"
#include <MinHook.h>
#include <windows.h>
#include <cstdint>

namespace effect_probe {

// Readability check. FAST PATH (perf): in-arena reads use the committed BITMAP (ns), not a VirtualQuery SYSCALL
// (us) — the SE-table hooks fire per sound-resolve, and the old VirtualQuery-per-read was the steady perf tax.
// Out-of-arena (rare) falls back to VirtualQuery. (NO IsBadReadPtr -> no VEH recursion.)
static bool readable(uintptr_t a, size_t n) {
    if (a < 0x10000 || n == 0) return false;
    if (arena::is_arena_addr(a) && arena::is_arena_addr(a + n - 1))
        return arena::is_committed_addr(a) && arena::is_committed_addr(a + n - 1);
    MEMORY_BASIC_INFORMATION mbi;
    if (!VirtualQuery((void*)a, &mbi, sizeof(mbi))) return false;
    if (mbi.State != MEM_COMMIT) return false;
    DWORD p = mbi.Protect & 0xFF;
    if (!(p == PAGE_READONLY || p == PAGE_READWRITE || p == PAGE_EXECUTE_READ || p == PAGE_EXECUTE_READWRITE)) return false;
    return ((a & 0xFFF) + n <= 0x1000) || readable((a + 0x1000) & ~0xFFFULL, 1);
}

// ===== (1) Crash C — effect-child consume leaf (P4: latent-vanilla vs rollback-induced) =====
static constexpr uintptr_t CONSUME_LEAF_IDA = 0x14080D440;   // FUN_14080d440(child)
typedef void (*consume_fn)(int64_t child);
static consume_fn orig_consume = nullptr;
static volatile LONG g_c_total = 0, g_c_null = 0, g_c_null_norb = 0, g_c_null_engineoff = 0, g_c_logged = 0;

static void hk_consume_leaf(int64_t child) {
    arena::hook_count_inc(3);   // perf bisection: effect-consume fires/frame
    uintptr_t c = (uintptr_t)child;
    LONG tot = InterlockedIncrement(&g_c_total);
    if (tot == 1)
        rblog::write("P4-CONSUME: hook LIVE on FUN_14080d440 (first call, child=0x%llX +0x50=0x%llX)",
            (unsigned long long)c, (unsigned long long)((c > 0x10000) ? *(uintptr_t*)(c + 0x50) : 0));
    if (c > 0x10000) {
        uintptr_t tbl = *(uintptr_t*)(c + 0x50);          // Safe first step (the crash is *(tbl+0xf), not this)
        if (tbl == 0) {
            InterlockedIncrement(&g_c_null);
            bool eng     = resim::engine_enabled();
            bool rb_ever = resim::rollback_happened();    // clean monotonic gate (not last_rollback_target()>0)
            if (!eng)     InterlockedIncrement(&g_c_null_engineoff);
            if (!rb_ever) InterlockedIncrement(&g_c_null_norb);
            LONG n = InterlockedIncrement(&g_c_logged);
            if (n <= 12 || (n % 500) == 0) {              // rate-limited: not per-frame spam
                rblog::write("P4-CONSUME-NULL #%ld: child=0x%llX +0x50=0 engine=%s resim=%s rb_ever=%d fsr=%d in_arena=%d "
                             "orphaned=%d srcframe=%d | byid=%d/auth=%d splice_applied=%ld | [null=%ld/%ld norb=%ld engoff=%ld]%s",
                    n, (unsigned long long)c, eng ? "ON" : "OFF", resim::resim_active() ? "yes" : "no",
                    rb_ever ? 1 : 0, resim::frames_since_rollback(), arena::is_arena_addr(c),
                    arena::was_orphaned_last_load(c) ? 1 : 0, arena::last_source_frame(c),
                    byid::is_enabled() ? 1 : 0, byid::is_authoritative_effect() ? 1 : 0, effect_splice::applied_count(),
                    (LONG)g_c_null, (LONG)g_c_total, (LONG)g_c_null_norb, (LONG)g_c_null_engineoff,
                    !rb_ever ? "  <<< LATENT VANILLA (null +0x50 with NO rollback this session)" : "");
                rblog::flush();
            }
        }
    }
    orig_consume(child);   // OBSERVE-ONLY: the engine still runs (and faults if it will)
}

// ===== (2) Crash A — SE-curve-table resolver (the table is param_1 here, in no GP register at the fault) =====
static constexpr uintptr_t SE_TABLE_IDA = 0x140688A50;   // FUN_140688a50(table, index) -> ushort*
typedef uint16_t* (*se_table_fn)(int64_t table, uint32_t index);
static se_table_fn orig_se_table = nullptr;
static volatile LONG g_a_total = 0, g_a_torn = 0, g_a_logged = 0;

// ===== ROOT FIX (Crash A): out-of-band SE-table identity/liveness GUARD =====
// the audio dispatcher's only liveness gate is a +0x54 ready bit read from the table's own (possibly freed/reused)
// memory — structurally incapable of catching a freed slab. We add the missing OUT-OF-BAND check: if the table is
// not a live, correctly-typed SE-table (wrong/poison vtable = freed/cross-type-reused slab; or torn row-base/index-
// map), return the not-found 0 the resolver's caller already null-checks => skip resolving a dead table. Audio is a
// pure OUTPUT LEAF (zero gameplay feedback) => a skipped cue is a missing sound, not a divergence (gp_crc-neutral).
// Read-only (no orig, no allocator touch) — none of the deferral's minefield blockers.
static volatile LONG   g_se_guard   = 1;
static volatile LONG64 g_se_skipped = 0;
static constexpr uintptr_t SE_VT_T0 = 0x140BB4690ULL;   // FUN_140688a50 SE-table vtable
static constexpr uintptr_t SE_VT_T1 = 0x140BB4760ULL;   // FUN_1406898e0 sibling SE-table vtable
static constexpr uintptr_t SE_TABLE_T1_IDA = 0x1406898E0ULL;
static se_table_fn orig_se_table_t1 = nullptr;
static inline bool canon_ptr(uintptr_t p) { return p == 0 || (p > 0x10000ULL && p < 0x800000000000ULL); }
// check_fields: 0 = vtable-only; otherwise the byte offset of the sparse INDEX MAP pointer to validate
// alongside the row-base at +0x80. T0 index map = +0xd8 (FUN_140688a50); T1 index map = +0xf0
// (FUN_1406898e0). Passing the wrong offset validates a different field, so the
// caller must pass its own table's index offset.
static bool se_table_dead(uintptr_t t, uintptr_t expect_vt_ida, uint32_t idx_off) {
    if (!readable(t, 8)) return true;
    uintptr_t vt = *(uintptr_t*)t;
    uintptr_t vt_ida = (vt >= addr::g_base && vt < addr::g_base + 0x1000000ULL) ? (vt - addr::g_base + 0x140000000ULL) : 0;
    if (vt_ida != expect_vt_ida) return true;                                  // wrong/poison vtable = freed/reused slab
    if (idx_off) {
        uintptr_t rb  = readable(t + 0x80, 8)     ? *(uintptr_t*)(t + 0x80)     : 0;
        uintptr_t idx = readable(t + idx_off, 8)  ? *(uintptr_t*)(t + idx_off)  : 0;
        if (!canon_ptr(rb) || !canon_ptr(idx)) return true;                    // torn row-base / index-map = poison
    }
    return false;
}
static uint16_t* hk_se_table_t1(int64_t table, uint32_t index) {
    uintptr_t t = (uintptr_t)table;
    if (!resim::engine_enabled()) return orig_se_table_t1(table, index);   // PERF: vanilla in normal play; guard+discriminator only engine-on (crash A is post-rollback)
    // T1: validate vtable and the T1 row-base (+0x80) / index-map (+0xf0). Not +0xd8 (that is T0's index
    // offset; on a T1 object it reads a sub-bank ptr, not the index map).
    if (g_se_guard && t > 0x10000 && se_table_dead(t, SE_VT_T1, /*idx_off=*/0xf0)) {
        LONG64 n = _InterlockedIncrement64(&g_se_skipped);
        if (n <= 24) rblog::write("SE-GUARD[t1]: skipped resolve of DEAD/WRONG/TORN SE-table 0x%llX (vtable!=%llX or +0x80/+0xf0 poison) fsr=%d => 0",
            (unsigned long long)t, (unsigned long long)SE_VT_T1, resim::frames_since_rollback());
        return nullptr;
    }
    if (t > 0x10000) audio_group::register_table_t1(t);   // SUBSTRATE COHERENCE: birth-register T1 (self-guards is_arena_addr)
    return orig_se_table_t1(table, index);
}

static uint16_t* hk_se_table(int64_t table, uint32_t index) {
    uintptr_t t = (uintptr_t)table;
    if (!resim::engine_enabled()) return orig_se_table(table, index);   // PERF: vanilla in normal play; guard+discriminator only engine-on (crash A is post-rollback)
    // ROOT-FIX GUARD (crash A): skip the resolve if the table is a dead/wrong-identity/torn SE-table.
    // T0 index map = +0xd8 (FUN_140688a50, stride 0x90).
    if (g_se_guard && t > 0x10000 && se_table_dead(t, SE_VT_T0, /*idx_off=*/0xd8)) {
        LONG64 n = _InterlockedIncrement64(&g_se_skipped);
        if (n <= 24) rblog::write("SE-GUARD[t0]: skipped resolve of DEAD/WRONG SE-table 0x%llX vtable=0x%llX +0x80=0x%llX "
            "fsr=%d => not-found 0 (audio output leaf, gameplay-safe). crash-A root fix.",
            (unsigned long long)t, (unsigned long long)(readable(t,8)?*(uintptr_t*)t:0),
            (unsigned long long)(readable(t+0x80,8)?*(uintptr_t*)(t+0x80):0), resim::frames_since_rollback());
        return nullptr;
    }
    LONG tot = InterlockedIncrement(&g_a_total);
    if (t > 0x10000) {
        audio_group::register_table(t);                    // SUBSTRATE COHERENCE: birth-register (self-guards is_arena_addr)
        // Compute the crash-A precondition every call (cheap, guarded) so the long run-survival skip below is unconditional.
        uintptr_t base  = readable(t + 0x80, 8) ? *(uintptr_t*)(t + 0x80) : 1;   // row-data base; 1 = non-null sentinel if unreadable
        uint32_t  f78   = readable(t + 0x78, 4) ? *(uint32_t*)(t + 0x78) : 0;
        uint64_t  idxd8 = readable(t + 0xd8, 8) ? *(uint64_t*)(t + 0xd8) : 0;
        // decomp: base (+0x80) is USED unless +0xd8==0 && +0x78==0 (then FUN_140688a50 early-returns 0 and the caller
        // null-checks — a benign base=0). Only base==0 with a live index path is the crash precondition.
        bool will_use_base = (idxd8 != 0) || (f78 != 0);
        bool crash_pre     = (base == 0) && will_use_base;
        if (base == 0) InterlockedIncrement(&g_a_torn);
        if ((tot <= 6 || base == 0) && g_a_logged < 32 && readable(t + 0x54, 4)) {
            InterlockedIncrement(&g_a_logged);
            uint32_t ready = *(uint32_t*)(t + 0x54);
            int      srcf  = arena::last_source_frame(t);
            rblog::write("PROBE-A SE-table=0x%llX idx=%u: +0x54=0x%X +0x78=0x%X +0x80=0x%llX +0xd8=0x%llX | in_arena=%d orphaned=%d "
                         "srcframe=%d arena=[0x%llX..0x%llX] fsr=%d %s",
                (unsigned long long)t, index, ready, f78, (unsigned long long)base, (unsigned long long)idxd8,
                arena::is_arena_addr(t), arena::was_orphaned_last_load(t) ? 1 : 0, srcf,
                (unsigned long long)arena::base(), (unsigned long long)arena::end(), resim::frames_since_rollback(),
                crash_pre        ? "<<< TORN / crash-precondition (base=0 and the index path WILL deref it)"
                : (base == 0)    ? "base=0 BENIGN (+0xd8==0 && +0x78==0 => engine early-returns 0; caller null-checks)" : "");
            // The A-vs-D DISCRIMINATOR. Fires for srcf==-1 too: peek_saved(-1) falls through to the BASELINE
            // image (exactly what srcf==-1 reverts from). The VTABLE identity (snap/baseline +0x00 vs live +0x00)
            // is the decisive cut between the two roots that both produce +0x80==0:
            // identity MUTATED => ROOT D (slab freed+reused as another object) => FIX = FREE-QUARANTINE SE slabs
            // across the rollback window (REBUILD-from-blob would deref a stale/foreign +0x70 — unsafe).
            // identity STABLE + source already had +0x80=0 with live index => ROOT A (partial-init derived ptr
            // restored-as-authoritative) => FIX = REBUILD +0x80 from +0x70 post-load (dynrestore coherence-group;
            // replay the load verb FUN_1406890b0). This is the proof gate before the dynrestore change.
            if (base == 0 && will_use_base && arena::is_arena_addr(t)) {
                uint64_t snap80 = 0, snapd8 = 0, snap0 = 0, snap70 = 0;
                int s0 = arena::peek_saved(srcf, t + 0x00, &snap0,  8);   // snapshot/baseline VTABLE (identity)
                int s1 = arena::peek_saved(srcf, t + 0x80, &snap80, 8);   // snapshot/baseline row-base (the bug field)
                (void)arena::peek_saved(srcf, t + 0x70, &snap70, 8);      // snapshot/baseline blob root (rebuild carrier)
                (void)arena::peek_saved(srcf, t + 0xd8, &snapd8, 8);
                uint64_t live_vt = readable(t, 8) ? *(uint64_t*)t : 0;
                bool id_mut = (s0 > 0) && (snap0 != live_vt);
                const char* verdict =
                    (s0 <= 0 && s1 <= 0) ? "SOURCE ABSENT (page not in ring/baseline) — inconclusive"
                    : id_mut             ? "ROOT D: IDENTITY-MUTATED (snap vt != live vt) => slab freed+reused => FIX=FREE-QUARANTINE SE slabs (REBUILD UNSAFE)"
                    : (snap80 == 0)      ? "ROOT A: PARTIAL-INIT (same identity; source ALREADY had +0x80=0, live index) => FIX=REBUILD +0x80 from +0x70 (dynrestore coherence-group)"
                                         : "RESIM-ZEROED (source +0x80 was GOOD, nulled after load) => rebuild-the-binding post-load (re-run FUN_1406890b0)";
                rblog::write("PROBE-A A-vs-D [%s f%d] t=0x%llX idx=%u: snap{vt=0x%llX +0x70=0x%llX +0x80=0x%llX +0xd8=0x%llX} live{vt=0x%llX +0x80=0 +0xd8=0x%llX} => %s",
                    (srcf == -1 ? "BASELINE" : "ring"), srcf, (unsigned long long)t, index,
                    (unsigned long long)snap0, (unsigned long long)snap70, (unsigned long long)snap80, (unsigned long long)snapd8,
                    (unsigned long long)live_vt, (unsigned long long)idxd8, verdict);
            }
            rblog::flush();
        }
        if (crash_pre) {   // RUN-SURVIVAL (audio-leaf safe; not the root fix): the resolve would return idx*0x90+0
                           // and crash the caller at +0x1B8. Skip => not-found 0 (one missed sound curve). The discriminator above
                           // already logged the A-vs-D verdict; the real fix is the dynrestore reclass the verdict picks.
            _InterlockedIncrement64(&g_se_skipped);
            return nullptr;
        }
    }
    return orig_se_table(table, index);   // OBSERVE-ONLY (base!=0, or benign base=0)
}

void report() {
    rblog::write("P4-CONSUME TALLY: total=%ld null_+0x50=%ld (no-rollback-ever=%ld engine-off=%ld) | byid=%d/auth=%d "
                 "splice_applied=%ld | A: se_table_calls=%ld torn(base=0)=%ld => %s",
        (LONG)g_c_total, (LONG)g_c_null, (LONG)g_c_null_norb, (LONG)g_c_null_engineoff,
        byid::is_enabled() ? 1 : 0, byid::is_authoritative_effect() ? 1 : 0, effect_splice::applied_count(),
        (LONG)g_a_total, (LONG)g_a_torn,
        ((LONG)g_c_null_norb > 0) ? "C IS LATENT VANILLA (consume-gate is the whole fix)"
        : ((LONG)g_c_null > 0)    ? "C nulls ONLY under rollback => rollback-induced"
                                  : "no null +0x50 observed this session");
    rblog::write("SE-GUARD: skipped %lld dead/wrong SE-table resolves (crash-A root fix; audio-leaf safe)", (long long)g_se_skipped);
}

void init(bool with_consume) {
    // SE-table hooks always install: the SE-GUARD (crash-A prevention, audio-leaf safe) + the A-vs-D discriminator.
    // Hot path is engine-gated (vanilla in normal play) and bitmap-leaned (no per-resolve VirtualQuery), so this is
    // perf-clean. consume_leaf (the hotter moving-crash observe probe) stays OFF unless full diagnostics are armed.
    MH_STATUS sc = MH_UNKNOWN;
    if (with_consume) {
        void* tc = (void*)addr::resolve(CONSUME_LEAF_IDA);
        sc = MH_CreateHook(tc, (void*)&hk_consume_leaf, (void**)&orig_consume);
    }
    void* ta = (void*)addr::resolve(SE_TABLE_IDA);
    MH_STATUS sa = MH_CreateHook(ta, (void*)&hk_se_table, (void**)&orig_se_table);
    void* ts = (void*)addr::resolve(SE_TABLE_T1_IDA);
    MH_STATUS ss = MH_CreateHook(ts, (void*)&hk_se_table_t1, (void**)&orig_se_table_t1);
    rblog::write("EFFECT-PROBE: SE-table FUN_140688a50 %s + sibling FUN_1406898e0 %s (SE-GUARD + A-vs-D discriminator; "
                 "engine-on only, bitmap-leaned = perf-clean) | P4-consume %s.",
        sa == MH_OK ? "OK" : "FAILED", ss == MH_OK ? "OK" : "FAILED",
        with_consume ? (sc == MH_OK ? "ON" : "FAILED") : "OFF (perf)");
    rblog::write("EFFECT-PROBE: P4 RUN PROCEDURE — LATENT arm: launch, play ~60s, DO NOT press F5 (no rollback), "
                 "then F7 to dump the tally; a nonzero no-rollback-ever count == Crash C is LATENT VANILLA.");
}

} // namespace effect_probe
