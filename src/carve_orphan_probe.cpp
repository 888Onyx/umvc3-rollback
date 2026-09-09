// carve_orphan_probe.cpp — see carve_orphan_probe.h. The carve-orphan detector: names the violating allocation if it is carve-side.
//
// Evidence chain (two long runs): the a4 corruption family is post-restore FREE/ALLOC
// double-membership (shared +0x18/+0x20 link fields; the alloc list had no unit-restore) — now closed by
// ALIST-UNIT. This probe stays as the independent carve-side check: immediately after every carve returns and
// still under the caller's class CS (0x1404CB2C6 EnterCS -> call -> LeaveCS; every scalable ctrl is gate=6
// CS-GUARDED per discovery), is the returned block still reachable from mgr+0x58? If yes: the carve failed to
// unlink — orphan named, caller named. ORPHAN=0 while episodes continue => non-carve writer (see A4-DIAG).
//
// Invoked as a CALLOUT from idspine's hk_carve (the one legal hook on FUN_1404CA650) — see carve_orphan_probe.h.
#include "carve_orphan_probe.h"
#include "addr.h"
#include "arena.h"
#include "resim.h"
#include "log.h"
#include <windows.h>

namespace carve_orphan_probe {

static bool g_armed = false;

static volatile LONG64 c_calls = 0;         // every carve call
static volatile LONG64 c_null = 0;          // carve returned NULL (fell through to reserve/new-slab)
static volatile LONG64 c_gate_armed = 0;    // count==0 && head!=0 at entry = the inlined count-gate skip PRECONDITION live
static volatile LONG64 c_orphan = 0;        // returned block still chained after the carve = the violating allocation
static volatile LONG64 c_orphan_resim = 0, c_orphan_fwd = 0;   // orphan split by rollback context

static inline uintptr_t va_to_ida(uintptr_t va) {
    return (addr::g_base && va >= addr::g_base) ? va - addr::g_base + 0x140000000ULL : va;
}

void post_carve(void* mgr, void* ret, unsigned long long sz, uint32_t count_in, uintptr_t head_in, void* caller) {
    if (resim::netplay_lean()) return;   // [lean] the per-carve orphan walk is census cost; ORPHAN=0 was established on long runs
    uintptr_t m = (uintptr_t)mgr;
    _InterlockedIncrement64(&c_calls);
    bool ok = m > 0x10000;
    if (ok && count_in == 0 && head_in) {
        // The inlined count-gated unlink (0x1404ca6b8/0x1404ca823) will SKIP its unlink under exactly this
        // state. Logically ruled out as the birth of the count~51 violation, but measured anyway (count_drift_census only covers
        // the standalone FUN_1404CAA60 — this closes the inlined-site gap for free).
        LONG64 nGA = _InterlockedIncrement64(&c_gate_armed);
        if (nGA <= 8 || (nGA % 100) == 0) {
            bool w = rblog::is_suppressed(); rblog::suppress(false);
            rblog::write("A4-CARVE INLINED-GATE-ARMED #%lld: carve entered with count==0 while head=0x%llX (non-empty!) mgr=0x%llX caller=0x%llX resim=%d — the inlined jbe WILL skip its unlink here",
                         (long long)nGA, (unsigned long long)head_in, (unsigned long long)m,
                         (unsigned long long)va_to_ida((uintptr_t)caller),
                         resim::resim_active() ? 1 : 0);
            rblog::suppress(w);
        }
    }
    if (!ret) { _InterlockedIncrement64(&c_null); return; }
    if (!ok) return;
    // Post-carve orphan walk. Still under the caller's class CS => the chain is splice-quiescent; a coherent
    // read, not a race. Bounded by count+2 (the walk's own cycle bound) clamped to [8, 4096].
    uint32_t  count_out = *(volatile uint32_t*)(m + 0x68);
    uintptr_t node = *(volatile uintptr_t*)(m + 0x58);
    uint32_t  cap = count_out + 2; if (cap > 4096) cap = 4096; if (cap < 8) cap = 8;
    uint32_t  pos = 0;
    while (node && pos < cap) {
        if (node < 0x10000 || !arena::is_committed_addr(node) || !arena::is_committed_addr(node + 0x40)) break;
        if (node == (uintptr_t)ret) {
            LONG64 nO = _InterlockedIncrement64(&c_orphan);
            if (resim::resim_active()) _InterlockedIncrement64(&c_orphan_resim);
            else                       _InterlockedIncrement64(&c_orphan_fwd);
            if (nO <= 8 || (nO % 50) == 0) {
                bool w = rblog::is_suppressed(); rblog::suppress(false);
                rblog::write("A4-CARVE ORPHAN #%lld: carve returned 0x%llX STILL CHAINED (pos=%u) mgr=0x%llX "
                             "entry{count=%u head=0x%llX} exit{count=%u head=0x%llX} f38=%x f18=%llx f20=%llx "
                             "sz_units=%llu caller=0x%llX resim=%d engine=%d — this carve did NOT unlink its block = the violating allocation, named",
                             (long long)nO, (unsigned long long)(uintptr_t)ret, pos, (unsigned long long)m,
                             count_in, (unsigned long long)head_in, count_out,
                             (unsigned long long)*(volatile uintptr_t*)(m + 0x58),
                             *(volatile uint32_t*)((uintptr_t)ret + 0x38),
                             (unsigned long long)*(volatile uint64_t*)((uintptr_t)ret + 0x18),
                             (unsigned long long)*(volatile uint64_t*)((uintptr_t)ret + 0x20),
                             sz,
                             (unsigned long long)va_to_ida((uintptr_t)caller),
                             resim::resim_active() ? 1 : 0, resim::engine_enabled() ? 1 : 0);
                rblog::suppress(w);
            }
            break;
        }
        node = *(volatile uintptr_t*)(node + 0x20); pos++;
    }
}

void init() {
    if (g_armed) return;
    g_armed = true;
    rblog::write("CARVE-ORPHAN-PROBE ARMED: post-carve orphan walk via idspine's hk_carve CALLOUT (a second MH hook on "
                 "FUN_1404CA650 fails ALREADY_CREATED — an arm failure seen on an earlier run, fixed) + inlined count-gate census.");
}

void report() {
    if (!g_armed || !c_calls) return;
    bool w = rblog::is_suppressed(); rblog::suppress(false);
    rblog::write("A4-CARVE: calls=%lld null=%lld gate-armed(count==0&&head!=0)=%lld ORPHAN=%lld { resim=%lld fwd=%lld } "
                 "— ORPHAN>0 = the carve-side unlink failure exists and is named at birth; 0 with episodes continuing => non-carve writer (see A4-DIAG diffs)",
                 (long long)c_calls, (long long)c_null, (long long)c_gate_armed, (long long)c_orphan,
                 (long long)c_orphan_resim, (long long)c_orphan_fwd);
    rblog::suppress(w);
}

} // namespace carve_orphan_probe
