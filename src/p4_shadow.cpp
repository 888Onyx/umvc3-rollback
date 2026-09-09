// p4_shadow.cpp — see p4_shadow.h. The reuse quarantine's open risk is: a purge-only reconcile orphans
// ~700-900 blocks/rollback and exhausts the pool. The fix is to treat the quarantine/liveness ledger as EPOCH STATE,
// rebuilt after arena::load from the reverted arena's own in-use bits (+ idspine death records). Before we defer a
// single free, this SHADOW proves the rebuild is sound on real data: for every idspine-tracked block, idspine's
// "alive at target frame T" (birth<=T<death) must equal the arena's in-use bit at T (block+0x38 bit0, post-load,
// the allocator's own flag — set in FUN_1404ca650, cleared in FUN_1404cb350). AGREE ~= tracked => liveness is
// rebuildable from the arena => the quarantine reconcile is safe. DISAGREE>0 => an idspine/arena gap to RE first.
// Pure read-only: no writes, no defer, no allocations on any game path.
#include "p4_shadow.h"
#include "idspine.h"
#include "arena.h"
#include "log.h"
#include <windows.h>
#include <cstdint>

namespace p4_shadow {

namespace {
constexpr int MAXN = 300000;
constexpr int FRAME_NEVER = 0x7FFFFFFF;
static uintptr_t* g_b = nullptr; static int* g_birth = nullptr; static int* g_death = nullptr; static int64_t* g_ser = nullptr;
}

void validate_epoch_rebuild(int T){
    static int s_calls = 0;
    if (!g_b) {
        g_b     = (uintptr_t*)VirtualAlloc(0, (SIZE_T)MAXN*8, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
        g_birth = (int*)      VirtualAlloc(0, (SIZE_T)MAXN*4, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
        g_death = (int*)      VirtualAlloc(0, (SIZE_T)MAXN*4, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
        g_ser   = (int64_t*)  VirtualAlloc(0, (SIZE_T)MAXN*8, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
    }
    if (!g_b || !g_birth || !g_death || !g_ser) return;

    int n = idspine::snapshot_all(g_b, g_birth, g_death, g_ser, MAXN);
    long agree=0, disagree=0, unread=0, alive_ids=0, alive_arena=0, freed_in_window=0;
    long dis_ex[6]; int ndis=0;   // first few disagreeing blocks (examples)
    for (int i=0;i<n;i++) {
        uintptr_t blk = g_b[i];
        if (!arena::is_arena_addr(blk)) continue;            // only arena blocks have a revertible in-use bit
        bool ids_alive = (g_birth[i] <= T) && (T < g_death[i]);
        if (ids_alive) alive_ids++;
        if (g_death[i] != FRAME_NEVER && g_death[i] > T) freed_in_window++;   // died after T => revert should bring it back (quarantine candidate)
        if (!arena::is_committed_addr(blk + 0x38)) { unread++; continue; }
        bool arena_inuse = (*(uint32_t*)(blk + 0x38) & 1u) != 0;
        if (arena_inuse) alive_arena++;
        if (arena_inuse == ids_alive) agree++;
        else { disagree++; if (ndis < 6) dis_ex[ndis++] = (long)(uintptr_t)blk; }
    }

    if (s_calls++ >= 4) return;   // first few rollbacks (validation, not spam)
    bool was = rblog::is_suppressed(); rblog::suppress(false);
    rblog::write("P4-SHADOW[T=%d]: tracked-arena=%ld | idspine_alive=%ld arena_inuse=%ld | epoch-rebuild AGREE=%ld DISAGREE=%ld unread=%ld | freed-in-window(quarantine cand)=%ld",
                 T, (agree+disagree+unread), alive_ids, alive_arena, agree, disagree, unread, freed_in_window);
    for (int i=0;i<ndis;i++) rblog::write("P4-SHADOW: DISAGREE block=0x%lX (idspine vs arena in-use bit mismatch at T) — RE before defer", dis_ex[i]);
    rblog::write("P4-SHADOW: AGREE ~= tracked => liveness rebuildable from arena in-use bits (rebuild sound; safe to defer). DISAGREE>0 => idspine/arena gap.");
    rblog::suppress(was);
}

} // namespace p4_shadow
