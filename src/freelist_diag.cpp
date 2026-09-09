// freelist_diag.cpp — read-only allocator free-list walker (diagnostic probe).
//
// The captured deadlock: a worker RIP-pinned in FUN_1404ca650, a first-fit walk over the Unit
// allocator's free list (head at sub_mgr+0x58 == base+0x1D8, next-link at node+0x20, NO cycle guard,
// NO cap => `}while(true)` over a reverted-incoherent (cyclic) list => never exits => deadlock).
//
// This walks that list READ-ONLY and answers: is it CYCLIC, and where do its nodes come from
// (RESTORED_RING / ORPHANED / NOT_IN_ARENA)? Used two ways:
// Half A — at the hang (head-holder = the pinned worker's rdx+0x58).
// Half B — right after restore_allocators (head-holder = alloc_base+0x1D8) => is the cycle present
// in the RESTORED image (torn-save / restore-skew) or formed later during resim (wild-write)?
//
// Floyd tortoise/hare cycle detection (O(n), O(1) — no slow visited-set scan). The walk is bounded
// purely so the WATCHDOG'S OWN walk terminates; it is never a ship fix (a cycle-cap on the engine's
// walk would only mask the bug). It writes nothing — never a link, never a node.
#include "log.h"
#include "addr.h"
#include "arena.h"
#include <windows.h>
#include <cstdint>
#include <cstdio>

namespace freelist_diag {

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
static const char* page_source(uintptr_t p) {
    if (!arena::is_arena_addr(p)) return "NOT_IN_ARENA";
    return arena::was_orphaned_last_load(p) ? "ORPHANED" : "RESTORED_RING";
}

void walk(uintptr_t head_ptr_loc, const char* tag) {
    if (!readable(head_ptr_loc, 8)) {
        rblog::write("FREELIST[%s]: head-holder 0x%llX unreadable", tag, (unsigned long long)head_ptr_loc);
        return;
    }
    uintptr_t head = *(uintptr_t*)head_ptr_loc;
    if (head <= 0x10000) {
        rblog::write("FREELIST[%s]: head=0x%llX (empty/null) — no list", tag, (unsigned long long)head);
        return;
    }
    // Floyd cycle detection over the +0x20 next-link.
    uintptr_t slow = head, fast = head; bool cyclic = false; uintptr_t meet = 0; long steps = 0;
    while (steps < 1000000) {
        if (fast <= 0x10000 || !readable(fast + 0x20, 8)) break;
        fast = *(uintptr_t*)(fast + 0x20);
        if (fast <= 0x10000 || !readable(fast + 0x20, 8)) break;
        fast = *(uintptr_t*)(fast + 0x20);
        if (slow <= 0x10000 || !readable(slow + 0x20, 8)) break;
        slow = *(uintptr_t*)(slow + 0x20);
        if (slow == fast) { cyclic = true; meet = slow; break; }
        steps++;
    }
    // Prefix page-source (first 12 nodes) — discriminates torn-save / skew / wild-write by node origin.
    char ps[640]; int pl = 0; ps[0] = 0;
    uintptr_t cur = head;
    for (int shown = 0; shown < 12 && cur > 0x10000 && readable(cur + 0x20, 8); shown++) {
        int w = snprintf(ps + pl, (int)sizeof(ps) - pl, "%s(0x%llX) ", page_source(cur), (unsigned long long)cur);
        if (w < 0 || w >= (int)sizeof(ps) - pl) break;
        pl += w;
        cur = *(uintptr_t*)(cur + 0x20);
    }
    rblog::write("FREELIST[%s]: head=0x%llX head_src=%s cyclic=%d meet=0x%llX floyd_steps=%ld | prefix: %s",
        tag, (unsigned long long)head, page_source(head), cyclic ? 1 : 0,
        (unsigned long long)meet, steps, ps);
    rblog::flush();
}

} // namespace freelist_diag
