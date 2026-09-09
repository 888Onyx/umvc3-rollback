// draw_probe.cpp — read-only probe for the cDraw-manager child-collection stale-restore UAF.
//
// This refutes the slot-0 theory: the crash FUN_140200f50+0x88 is the characteristic
// STALE-RESTORE UAF on a new structure — the cDraw manager's child collection. f50 walks 7
// inline child arrays at param_1+0x1408..+0x1438 (stride 0xbb0, counts packed as nibbles in +0x1440) and
// for each child calls (*(*(child)+0x40))(child) — i.e. vt=*(child); target=*(vt+0x40); call target.
// arena::load(N) raw-reverts the array pointers + counts to frame-N while FUN_1401ffca0 freed/realloc'd
// the blocks post-N => f50 reads a stale vt (a float ~-1.0, the observed 0xBF7FDB12) and *(vt+0x40) faults.
//
// This walks the same arrays READ-ONLY just before f50 does, detects the about-to-crash stale child
// (vt+0x40 unreadable), and logs: param_1 (to re-confirm it is the stable manager, not a slot-0 base),
// the array's page-source (in-arena / orphaned / restored-ring), the float vt, and whether the reconfig
// FUN_1401ffca0 has fired. This CONFIRMS the carrier (stable-manager + in-arena + reconfig-fired) before
// any rebuild ships. Read-only: it inspects + calls orig; it writes nothing.
#include "log.h"
#include "addr.h"
#include "arena.h"
#include "resim.h"
#include <MinHook.h>
#include <windows.h>
#include <cstdint>

namespace draw_probe {

static constexpr uintptr_t F50_IDA      = 0x140200F50;   // the crashing cDraw dispatcher
static constexpr uintptr_t RECONFIG_IDA = 0x1401FFCA0;   // the child free/realloc reconfig
static constexpr uintptr_t DLCLEAN_IDA  = 0x1405DD810;   // draw_list_cleanup — the render resource-batch teardown
typedef void (*f50_fn)(int64_t);
typedef void (*reconfig_fn)(int64_t, uint32_t*);
typedef void (*dlclean_fn)(int64_t);
static f50_fn      orig_f50 = nullptr;
static reconfig_fn orig_reconfig = nullptr;
static dlclean_fn  orig_dlclean = nullptr;
static volatile LONG g_reconfig_count = 0;   // # FUN_1401ffca0 fires (carrier: children freed/realloc'd)
static volatile LONG g_stale_logged   = 0;   // cap
// draw_list_cleanup torn count/base probe + containment
static volatile LONG g_torn_logged    = 0;   // probe log cap
static volatile LONG g_torn_repaired  = 0;   // # containment repairs this session
static volatile LONG g_dlclean_contain = 1;  // containment ON: restore engine invariant count==0 when base==0

static bool readable(uintptr_t p, size_t n) {
    if (p < 0x10000) return false;
    MEMORY_BASIC_INFORMATION mbi;
    if (!VirtualQuery((void*)p, &mbi, sizeof(mbi))) return false;
    if (mbi.State != MEM_COMMIT) return false;
    DWORD pr = mbi.Protect & 0xFF;
    if (!(pr==PAGE_READONLY||pr==PAGE_READWRITE||pr==PAGE_EXECUTE_READ||pr==PAGE_EXECUTE_READWRITE||
          pr==PAGE_WRITECOPY||pr==PAGE_EXECUTE_WRITECOPY)) return false;
    return (p + n) <= ((uintptr_t)mbi.BaseAddress + mbi.RegionSize);
}

static void hk_reconfig(int64_t p1, uint32_t* p2) {
    InterlockedIncrement(&g_reconfig_count);
    orig_reconfig(p1, p2);
}

static void hk_f50(int64_t param_1) {
    if (param_1 && g_stale_logged < 32 && readable(param_1 + 0x1440, 4)) {
        uint32_t counts = *(uint32_t*)(param_1 + 0x1440);
        for (int k = 0; k < 7; k++) {
            if (!readable(param_1 + 0x1408 + (uintptr_t)k * 8, 8)) continue;
            uintptr_t arr = *(uintptr_t*)(param_1 + 0x1408 + (uintptr_t)k * 8);
            uint32_t cnt = (counts >> (4 * k)) & 0xf;
            if (!arr || cnt == 0) continue;
            for (uint32_t i = 0; i < cnt; i++) {
                uintptr_t child = arr + (uintptr_t)i * 0xbb0;
                if (!readable(child, 8)) continue;
                uintptr_t vt = *(uintptr_t*)child;           // f50: vt = *(child)
                if (!readable(vt + 0x40, 8)) {               // f50 calls *(vt+0x40) => STALE, about to crash
                    if (InterlockedIncrement(&g_stale_logged) <= 32) {
                        const char* src = !arena::is_arena_addr(arr) ? "NOT_IN_ARENA"
                                          : (arena::was_orphaned_last_load(arr) ? "ORPHANED" : "RESTORED_RING");
                        // Did the array-POINTER field page and the CHILD-content page revert from
                        // the same ring frame? Different => skew (coherent-revert); same => partial-init (rebuild).
                        uintptr_t field = (uintptr_t)param_1 + 0x1408 + (uintptr_t)k * 8;
                        int sf_field = arena::last_source_frame(field);
                        int sf_child = arena::last_source_frame(child);
                        rblog::write("DRAW-STALE: mgr=0x%llX arr[%d]=0x%llX(%s) child[%u]=0x%llX vt=0x%llX reconfig=%ld "
                                     "| BVC field(src=%d) child(src=%d) => %s",
                            (unsigned long long)param_1, k, (unsigned long long)arr, src,
                            i, (unsigned long long)child, (unsigned long long)vt, (long)g_reconfig_count,
                            sf_field, sf_child,
                            (sf_field != sf_child) ? "DIFFERENT-SLOT (b)SKEW -> coherent-revert"
                                                   : "SAME-SLOT (c)partial-init -> rebuild");
                        rblog::flush();
                    }
                    break;
                }
            }
        }
    }
    orig_f50(param_1);
}

// draw_list_cleanup (FUN_1405DD810): the resim crash was rip+0x2C `mov eax,[base+idx*0x18]` with
// base = *(param_1+0x50) == NULL while the entry count *(param_1+0x20)&0x1ff != 0. The entry loop is guarded
// only by the count, never null-checks base. count!=0 && base==0 is a state the ENGINE never produces (its own
// teardown clears the count before nulling base) — it only arises from our rollback restore reinstating the
// count/base coherence-pair from skewed epochs (or a save-time / kept-live tear). This hook:
// (1) PROBE (read-only): on the torn state post-rollback, classify the tear via peek_saved at the page's
// restore-source frame — TORN-AT-SAVE (snapshot itself torn) vs COHERENT-AT-LOAD => TORN-DURING-RESIM vs
// KEPT-LIVE. +0x20/+0x50 share a 4KB page => the page-revert is atomic, so cross-frame load-tear is only
// possible if the two fields straddle pages (src20 != src50, also logged).
// (2) CONTAINMENT: restore the engine's own invariant (clear the low-9-bit count so the empty batch skips the
// entry loop). Render-domain write, not gp_crc/gameplay state => safe by construction. Gated to post-rollback only
// (rollback_happened) so pre-rollback normal play is byte-identical. This stops this crash (base==0) and
// is itself the experiment: if it converts the crash into clean play, the count/base desync IS the root.
static void hk_dlclean(int64_t param_1) {
    // Cheap fast-path: no rollback yet => byte-identical passthrough. After a rollback, guard the field reads
    // with the arena committed-bitmap (O(1), no VirtualQuery) — only in-arena batches can carry the restore tear.
    if (param_1 && resim::rollback_happened()
        && arena::is_committed_addr((uintptr_t)param_1 + 0x20)
        && arena::is_committed_addr((uintptr_t)param_1 + 0x50)) {
        uint32_t packed = *(uint32_t*)((uintptr_t)param_1 + 0x20);
        uint32_t cnt    = packed & 0x1ff;
        uintptr_t base  = *(uintptr_t*)((uintptr_t)param_1 + 0x50);
        if (cnt != 0 && base == 0) {
            if (InterlockedIncrement(&g_torn_logged) <= 24) {
                // DEFERRED-FOLD: this is the one live-play baseline-byte reader (F5). Drain the bg fold worker so
                // the peek reads a coherent baseline, not a page mid-fold. Free — this branch fires ≤24×/session on a
                // post-rollback torn object. (Diagnostic-only anyway: the verdict never drives a game-state write.)
                arena::fold_drain();
                int sf20 = arena::last_source_frame((uintptr_t)param_1 + 0x20);
                int sf50 = arena::last_source_frame((uintptr_t)param_1 + 0x50);
                uint32_t saved_packed = 0; uintptr_t saved_base = 0;
                int a = (sf50 >= 0) ? arena::peek_saved(sf50, (uintptr_t)param_1 + 0x20, &saved_packed, 4) : 0;
                int b = (sf50 >= 0) ? arena::peek_saved(sf50, (uintptr_t)param_1 + 0x50, &saved_base, 8) : 0;
                const char* verdict;
                if (sf50 == -3)            verdict = "KEPT-LIVE (page not restored => live tear, not from restore)";
                else if (sf50 < 0)         verdict = "src=baseline/orphan";
                else if (sf20 != sf50)     verdict = "CROSS-PAGE (src20!=src50 => load-tear possible)";
                else if (!a || !b)         verdict = "saved-not-present";
                else if ((saved_packed & 0x1ff) != 0 && saved_base == 0)
                                           verdict = "TORN-AT-SAVE (snapshot itself count!=0/base==0)";
                else if (saved_base != 0)  verdict = "COHERENT-AT-LOAD => TORN-DURING-RESIM (base nulled after load, count kept)";
                else                       verdict = "saved count==0 (snapshot was coherent-empty)";
                rblog::write("DRAWLIST-TORN: mgr=0x%llX live{cnt=%u base=NULL} tgt=%d src20=%d src50=%d "
                             "saved{cnt=%u base=0x%llX a=%d b=%d} resim=%d => %s",
                    (unsigned long long)param_1, cnt, resim::last_rollback_target(), sf20, sf50,
                    saved_packed & 0x1ff, (unsigned long long)saved_base, a, b,
                    (int)resim::resim_active(), verdict);
                rblog::flush();
            }
            if (g_dlclean_contain) {
                *(uint32_t*)((uintptr_t)param_1 + 0x20) = packed & 0xfffffe00;  // clear count, keep flags
                InterlockedIncrement(&g_torn_repaired);
            }
        }
    }
    orig_dlclean(param_1);
}

long reconfig_count() { return g_reconfig_count; }
long torn_repaired()  { return g_torn_repaired; }

void init() {
    struct { uintptr_t ida; void* hk; void** orig; const char* name; } hooks[] = {
        { F50_IDA, (void*)&hk_f50, (void**)&orig_f50, "cDraw dispatch f50 (stale probe)" },
        { RECONFIG_IDA, (void*)&hk_reconfig, (void**)&orig_reconfig, "cDraw reconfig ca0" },
    };
    for (auto& h : hooks) {
        void* t = (void*)addr::resolve(h.ida);
        MH_STATUS st = MH_CreateHook(t, h.hk, h.orig);
        rblog::write("DRAW-PROBE: hook %s @0x%llX %s", h.name,
            (unsigned long long)(uintptr_t)t, st == MH_OK ? "OK" : "FAILED");
    }
}

// Minimal init: install only the draw_list_cleanup torn-count/base probe+containment (not the heavier per-draw
// f50 stale probe). Called from resim::init before MH_EnableHook(MH_ALL_HOOKS). The hook is a no-op until the
// first rollback (rollback_happened gate) so it costs nothing in pre-rollback normal play.
void init_dlclean() {
    void* t = (void*)addr::resolve(DLCLEAN_IDA);
    MH_STATUS st = MH_CreateHook(t, (void*)&hk_dlclean, (void**)&orig_dlclean);
    rblog::write("DRAW-PROBE: hook draw_list_cleanup (torn count/base probe+contain) @0x%llX %s",
        (unsigned long long)(uintptr_t)t, st == MH_OK ? "OK" : "FAILED");
}

} // namespace draw_probe
