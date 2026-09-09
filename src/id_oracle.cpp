// id_oracle.cpp — see id_oracle.h. The identity/liveness substrate: one deterministic answer, fusing the
// engine-wide timeline husk set (quarantine), the identity spines (idspine/rdspine birth<=N<death), the game's
// own +0x8 generation id (ABA), and cheap domain sanity. Read-only; fail-open on doubt.
#include "id_oracle.h"
#include "addr.h"
#include "arena.h"
#include "quarantine.h"
#include "idspine.h"
#include "rdspine.h"
#include "log.h"
#include <windows.h>

namespace id_oracle {

static uintptr_t g_dead_sentinel = 0;   // engine post-dtor dead-vtable marker (0x140A6A510), rebased at init
// stats (verdict histogram + leg attribution)
static volatile LONG64 c_calls = 0, c_alive = 0, c_dead = 0, c_aba = 0, c_born = 0, c_ext = 0, c_unk = 0;
static volatile LONG64 c_by_husk = 0, c_by_sentinel = 0, c_by_garbage = 0, c_by_diedN = 0;
// migration shadow probe
static volatile long   g_probe = 0;
static volatile LONG64 c_probe_calls = 0, c_probe_disagree = 0;

bool canon(uintptr_t p) { return p >= 0x10000ULL && p < 0x0000800000000000ULL; }

bool committed(uintptr_t p, size_t need) {
    if (!canon(p)) return false;
    uintptr_t last = p + (need ? need - 1 : 0);
    if (arena::is_arena_addr(p) && arena::is_arena_addr(last))
        return arena::is_committed_addr(p) && arena::is_committed_addr(last);
    MEMORY_BASIC_INFORMATION mbi;
    if (!VirtualQuery((void*)p, &mbi, sizeof(mbi))) return false;
    if (mbi.State != MEM_COMMIT) return false;
    if (mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)) return false;
    return (p + need) <= (uintptr_t)mbi.BaseAddress + mbi.RegionSize;
}

bool is_domain_valid(uintptr_t p, size_t need) {
    return canon(p) && (p & 3u) == 0 && committed(p, need ? need : 8);
}

// rd(): our own byte-reverted domain (arena-committed). Out-of-arena => not ours => leave it (COM/CRT-safe).
static inline bool rd(uintptr_t a) { return a > 0x10000ULL && arena::is_committed_addr(a); }
bool in_our_domain(uintptr_t p) { return rd(p); }

// vtable range classification (matches material_guard is_material_vt / recycled_nonobject exactly).
static inline bool vtable_is_garbage(uintptr_t vt) {
    if (vt == 0) return false;                              // ambiguous (mid-ctor) — caller decides, not here
    if (vt < addr::g_base) return true;                    // non-module low value = float/garbage
    return (vt - addr::g_base) >= 0x2000000ULL;            // out of the module's .rdata vtable range = float/garbage
}

bool is_dead(uintptr_t p) {
    if (!rd(p)) return false;                               // not our domain
    if (quarantine::is_held_husk(p)) { _InterlockedIncrement64(&c_by_husk); return true; }   // TIMELINE (engine-wide)
    uintptr_t vt = *(uintptr_t*)p;                          // p committed => readable
    if (g_dead_sentinel && vt == g_dead_sentinel) { _InterlockedIncrement64(&c_by_sentinel); return true; }
    return false;
}

bool is_recycled_nonobject(uintptr_t p) {
    if (!rd(p)) return false;
    uintptr_t vt = *(uintptr_t*)p;
    if (vtable_is_garbage(vt)) { _InterlockedIncrement64(&c_by_garbage); return true; }
    return false;
}

bool is_husk_vtable(uintptr_t p) {
    if (!rd(p)) return false;                               // out-of-arena => not our domain (COM-safe)
    uintptr_t vt = *(uintptr_t*)p;
    if (vt == 0) return true;                               // DEAD — unambiguous only at a dtor/leaf teardown site
    if (g_dead_sentinel && vt == g_dead_sentinel) return true;
    return vtable_is_garbage(vt);
}

uint64_t capture_gen8(uintptr_t p) {
    if (!committed(p + 8, 8)) return 0;
    return *(uint64_t*)(p + 8);
}

bool gen_changed(uintptr_t p, uint64_t captured_gen8) {
    if (!captured_gen8) return false;                      // never captured => cannot prove ABA (fail-open)
    if (!committed(p + 8, 8)) return false;
    return *(uint64_t*)(p + 8) != captured_gen8;
}

Verdict liveness_at(uintptr_t p, int N) {
    if (!canon(p)) return UNKNOWN;
    int birth = 0, death = 0, in_arena = 0; int64_t serial = 0;
    // (1) rdspine keys on the USER ptr directly (the Default allocator — where nDraw::Material* et al. live).
    if (rdspine::lookup(p, &birth, &death, &serial, &in_arena)) {
        if (!in_arena) return EXTERNAL;                    // Default-CRT block: out-of-arena, not byte-reverted
        if (birth > N) return BORN_AFTER_N;
        if (death <= N) { _InterlockedIncrement64(&c_by_diedN); return DEAD; }
        return ALIVE_SAME;
    }
    // (2) idspine keys on the allocator BLOCK BASE. Resolve block = user - *(user-8) (MtScalable header convention,
    // idspine.h). Heavily guarded: on any doubt fall through to UNKNOWN — a wrong block just yields "not found",
    // never a false DEAD (fail-open by construction).
    if (committed(p - 8, 8)) {
        uintptr_t hdroff = *(uintptr_t*)(p - 8);
        if (hdroff >= 0x10ULL && hdroff < 0x10000ULL) {
            uintptr_t block = p - hdroff;
            int b2 = 0, d2 = 0; int64_t s2 = 0;
            if (idspine::lookup(block, &b2, &d2, &s2)) {
                if (b2 > N) return BORN_AFTER_N;
                if (d2 <= N) { _InterlockedIncrement64(&c_by_diedN); return DEAD; }
                return ALIVE_SAME;
            }
        }
    }
    return UNKNOWN;
}

static Verdict tally(Verdict v) {
    switch (v) {
        case ALIVE_SAME:   _InterlockedIncrement64(&c_alive); break;
        case DEAD:         _InterlockedIncrement64(&c_dead);  break;
        case ABA_RECYCLED: _InterlockedIncrement64(&c_aba);   break;
        case BORN_AFTER_N: _InterlockedIncrement64(&c_born);  break;
        case EXTERNAL:     _InterlockedIncrement64(&c_ext);   break;
        default:           _InterlockedIncrement64(&c_unk);   break;
    }
    return v;
}

Verdict check(uintptr_t p, int N) {
    _InterlockedIncrement64(&c_calls);
    if (!canon(p)) return tally(UNKNOWN);
    if (!rd(p)) return tally(committed(p, 8) ? EXTERNAL : UNKNOWN);   // out-of-arena readable = COM/driver handle
    if (is_dead(p)) return tally(DEAD);                    // is_held_husk || sentinel (timeline, everywhere-safe)
    if (is_recycled_nonobject(p)) return tally(DEAD);      // nonzero garbage vtable (everywhere-safe; excludes vt==0)
    Verdict lv = liveness_at(p, N);
    if (lv == DEAD || lv == BORN_AFTER_N) return tally(lv);
    return tally(ALIVE_SAME);                              // domain-valid, not dead, not garbage (UNKNOWN liveness => keep)
}

Verdict check_id(uintptr_t p, int N, uint64_t captured_gen8) {
    Verdict v = check(p, N);
    if (v != ALIVE_SAME) return v;
    if (captured_gen8 && gen_changed(p, captured_gen8)) { _InterlockedIncrement64(&c_aba); return ABA_RECYCLED; }
    return ALIVE_SAME;
}

Verdict check_data(uintptr_t p, int N) {
    _InterlockedIncrement64(&c_calls);
    if (!canon(p)) return tally(UNKNOWN);
    if (!rd(p)) return tally(committed(p, 8) ? EXTERNAL : DEAD);   // out-of-arena: readable handle vs genuinely unmapped (gap)
    if (quarantine::is_held_husk(p)) return tally(ALIVE_SAME);     // freed-but-DEFERRED = kept alive for this gameplay edge = safe
    Verdict lv = liveness_at(p, N);                                // NO vtable/garbage leg — data has no vtable at +0
    if (lv == DEAD || lv == BORN_AFTER_N) return tally(lv);        // genuinely gone: died<=N (and not held) / born>N
    return tally(ALIVE_SAME);                                      // committed, held-or-alive, not born-after ⇒ safe (UNKNOWN liveness => keep)
}

const char* verdict_name(Verdict v) {
    switch (v) {
        case ALIVE_SAME:   return "ALIVE_SAME";
        case DEAD:         return "DEAD";
        case ABA_RECYCLED: return "ABA_RECYCLED";
        case BORN_AFTER_N: return "BORN_AFTER_N";
        case EXTERNAL:     return "EXTERNAL";
        default:           return "UNKNOWN";
    }
}

void set_probe(bool on) { g_probe = on ? 1 : 0; }
bool probe_enabled() { return g_probe != 0; }

void probe_dead(uintptr_t p, bool local_dead, const char* family) {
    if (!g_probe) return;
    _InterlockedIncrement64(&c_probe_calls);
    bool od = is_dead(p);                 // the identical quarantine::is_held_husk + dead-sentinel legs edge_dead uses
    if (od != local_dead) {
        LONG64 n = _InterlockedIncrement64(&c_probe_disagree);
        if (n <= 32 || (n % 256) == 0) {
            bool w = rblog::is_suppressed(); rblog::suppress(false);
            rblog::write("ID-ORACLE-PROBE[%s] DISAGREE #%lld: p=0x%llX local_dead=%d oracle_is_dead=%d "
                         "(migration gate — must reach 0 before the family flips to oracle-authoritative)",
                         family, (long long)n, (unsigned long long)p, local_dead ? 1 : 0, od ? 1 : 0);
            rblog::suppress(w);
        }
    }
}

void init() {
    g_dead_sentinel = addr::resolve(0x140A6A510ULL);
    g_probe = arena::startup_flag("ID_ORACLE_PROBE", "id_oracle_probe.flag") ? 1 : 0;
    rblog::write("ID-ORACLE ARMED: unified identity/liveness substrate (dead-sentinel 0x%llX; fuses "
                 "quarantine husk-set + idspine/rdspine alive-at-N + gen-id ABA + domain sanity; fail-open on doubt) "
                 "| migration-probe=%s",
                 (unsigned long long)g_dead_sentinel, g_probe ? "ARMED (shadow)" : "off");
}

void report() {
    if (!c_calls) return;
    bool w = rblog::is_suppressed(); rblog::suppress(false);
    rblog::write("ID-ORACLE: calls=%lld verdicts{alive=%lld dead=%lld aba=%lld born=%lld ext=%lld unk=%lld} "
                 "dead-by{husk=%lld sentinel=%lld garbage=%lld died<=N=%lld}",
                 (long long)c_calls, (long long)c_alive, (long long)c_dead, (long long)c_aba, (long long)c_born,
                 (long long)c_ext, (long long)c_unk,
                 (long long)c_by_husk, (long long)c_by_sentinel, (long long)c_by_garbage, (long long)c_by_diedN);
    if (g_probe || c_probe_calls)
        rblog::write("ID-ORACLE-PROBE: calls=%lld DISAGREE=%lld (0 disagreements across a long run => the family may flip to oracle-authoritative)",
                     (long long)c_probe_calls, (long long)c_probe_disagree);
    rblog::suppress(w);
}

} // namespace id_oracle
