// dyndelete.cpp — the lifetime/generation twin of dynrestore. SLICE 1: the READ-ONLY lie detector.
// See dyndelete.h. Free-list layout (alloc_consistency.cpp; decompilation of FUN_1404cb350): 8 size-class managers at
// control+0xd8+k*0xa8; mgr+0x70 class, +0x68 free count, +0x58 free-list head; node next-link = node+0x20; block
// class nibble = (*(u32*)(node+0x3c)>>2)&0x1f. We only READ — no link is written, no list altered, no game memory
// touched. Liveness comes from the idspine SHADOW ledger (DLL.bss), not the arena.
#include "dyndelete.h"
#include "idspine.h"
#include "arena.h"
#include "resim.h"
#include "log.h"
#include <windows.h>
#include <cstdint>

namespace dyn_delete {

static volatile LONG g_validate = 0;   // armed by the alloc-debug run (Numpad7); read-only

void set_validate(bool on) { g_validate = on ? 1 : 0; }
bool validate_on() { return g_validate != 0; }

// In-arena free-list nodes use the committed BITMAP (ns, no syscall). But the allocator CONTROL blocks are
// OUT-OF-ARENA (.data/fixed region) — a bitmap-only gate rejected control+0xd8 and validate() returned mute
// (the bug: every DYNDELETE line was swallowed). Mirror alloc_consistency::readable — bitmap fast-path for the
// in-arena common case (nodes), VirtualQuery fallback for out-of-arena (the control/mgr reads, low frequency).
static inline bool readable(uintptr_t p, size_t n) {
    if (!p || n == 0) return false;
    if (arena::is_arena_addr(p) && arena::is_arena_addr(p + n - 1))
        return arena::is_committed_addr(p) && arena::is_committed_addr(p + n - 1);
    MEMORY_BASIC_INFORMATION mbi;
    if (!VirtualQuery((void*)p, &mbi, sizeof(mbi))) return false;
    if (mbi.State != MEM_COMMIT) return false;
    if (mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)) return false;
    return (p + n) <= ((uintptr_t)mbi.BaseAddress + mbi.RegionSize);
}

void validate(uintptr_t control, int target_frame, const char* tag) {
    if (!g_validate) return;
    if (!readable(control + 0xd8, 8)) return;
    const int N = target_frame;
    // Force our lines through the rollback-window log suppression (the mute bug: alloc_consistency does this, we
    // did not — so every DYNDELETE line was being swallowed). Restore the prior suppression state at the end.
    bool _sup = rblog::is_suppressed(); rblog::suppress(false);

    int t_walked = 0, t_coherent = 0, t_stalelive = 0, t_unknown = 0, t_cycle_mgrs = 0, t_unread = 0;
    // (a)/(b) DISCRIMINATOR. For each STALE-LIVE node (ledger says alive, yet on the free list) read the ENGINE's
    // own allocated bit (+0x38 bit0). bit0=1 => engine AGREES it is alive (only the free-list MEMBERSHIP is wrong =
    // a clean LOST-UNLINK; a rebuild-from-bit0 would fix it). bit0=0 => engine says FREE, contradicting our ledger
    // (the block's contents/+0x38 were clobbered = case (b), a live-planted UAF; rebuild-from-contents does
    // nothing, the fix is type-stable segregation). This single bit decides whether a rebuild is the right fix.
    int t_stale_a = 0, t_stale_b = 0;

    for (int k = 0; k < 8; k++) {
        uintptr_t mgr = control + 0xd8 + (uintptr_t)k * 0xa8;
        if (!readable(mgr + 0x70, 4) || !readable(mgr + 0x68, 4) || !readable(mgr + 0x58, 8)) continue;
        uint32_t  claimed = *(uint32_t*)(mgr + 0x68);
        uintptr_t head    = *(uintptr_t*)(mgr + 0x58);
        uint32_t  cap     = (claimed < 65536 ? claimed : 65536) + 32;   // count + margin => a cycle trips the cap

        int coherent = 0, stalelive = 0, unknown = 0; bool cycle = false, unread = false;
        uintptr_t node = head; uint32_t walked = 0;
        while (node) {
            if (walked > cap) { cycle = true; break; }                  // longer than the class list => self-loop/cycle
            if (!readable(node + 0x20, 8)) { unread = true; break; }    // link into uncommitted/garbage => the link face
            uintptr_t next = *(uintptr_t*)(node + 0x20);

            int birth = 0, death = 0; int64_t serial = 0;
            bool found = idspine::lookup(node, &birth, &death, &serial);
            // Classify (see dyndelete.h). The ledger keeps only the LATEST generation, so birth>N = a rebirth the
            // rollback ERASES => the node was free at N => COHERENT (not a hit). Only birth<=N<death is the real
            // smoking gun: a live-at-N block sitting on the restored free list.
            bool stale = found && (birth <= N) && (N < death);
            if (!found)      unknown++;
            else if (stale)  stalelive++;
            else             coherent++;

            if (stale) {
                uint32_t b38  = readable(node + 0x38, 4) ? *(volatile uint32_t*)(node + 0x38) : 0;
                bool     bit0 = (b38 & 1u) != 0;
                if (bit0) t_stale_a++; else t_stale_b++;   // (a) lost-unlink (engine agrees alive) vs (b) clobbered
                static volatile LONG lg = 0; LONG g = _InterlockedIncrement(&lg);
                if (g <= 32) {
                    uintptr_t fc = 0, fe = 0; int ff = 0; idspine::recent_free(node, &fc, &fe, &ff);
                    rblog::write("DYNDELETE-LIE[%s] mgr%d node=0x%llX => STALE-LIVE (ledger birth=%d death=%d serial=%lld | target=%d) "
                                 "+0x38=0x%X bit0=%d[%s] page_src=%d | freed-by caller=0x%llX eff=0x%llX @f=%d",
                        tag, k, (unsigned long long)node, birth, death, (long long)serial, N,
                        b38, (int)bit0, bit0 ? "lost-unlink(a):rebuild-fixable" : "clobbered(b):needs-type-stable",
                        arena::last_source_frame(node), (unsigned long long)fc, (unsigned long long)fe, ff);
                }
            }
            node = next; walked++;
        }

        t_walked += walked; t_coherent += coherent; t_stalelive += stalelive; t_unknown += unknown;
        if (cycle)  t_cycle_mgrs++;
        if (unread) t_unread++;
        if (stalelive || cycle || unread)
            rblog::write("DYNDELETE[%s] mgr%d head=0x%llX walked=%u claimed=%u | COHERENT=%d STALE-LIVE=%d UNKNOWN=%d%s%s",
                tag, k, (unsigned long long)head, walked, claimed, coherent, stalelive, unknown,
                cycle ? " CYCLE!" : "", unread ? " UNREADABLE-LINK!" : "");
    }

    // Coverage = the fraction of walked nodes the ledger could actually classify (not UNKNOWN). A clean reading
    // only means something at high coverage; low coverage = BLIND, never "all-clear".
    int cov = t_walked ? (100 * (t_walked - t_unknown)) / t_walked : 0;
    bool sees = (t_stalelive || t_cycle_mgrs || t_unread);
    const char* verdict =
        sees ? "LEDGER SEES the incoherence (restore-instant target => a reconcile/sever is justified HERE)"
        : (cov < 50) ? "INCONCLUSIVE — LEDGER COVERAGE TOO LOW (unknown dominates): a clean reading here is BLIND, "
                       "not safe. Raise coverage (record-from-boot / OOA ledger) before trusting any all-clear."
        : "all-coherent at usable coverage => NO restore-instant target. If a crash still reproduces this rollback, "
          "it forms DURING replay (free-chokepoint altitude), NOT at the restore seam — do NOT ship a restore-seam sever.";
    rblog::write("DYNDELETE[%s]: target=%d walked=%d coverage=%d%% | COHERENT=%d STALE-LIVE=%d(a-lostunlink=%d/b-clobbered=%d) UNKNOWN=%d CYCLE_mgrs=%d UNREAD_mgrs=%d => %s%s",
        tag, N, t_walked, cov, t_coherent, t_stalelive, t_stale_a, t_stale_b, t_unknown, t_cycle_mgrs, t_unread, verdict,
        t_stalelive ? (t_stale_a >= t_stale_b ? " || (a)-DOMINANT: rebuild-from-bit0 is the right fix"
                                              : " || (b)-DOMINANT: rebuild is a no-op => type-stable segregation") : "");
    rblog::suppress(_sup);
}

} // namespace dyn_delete
