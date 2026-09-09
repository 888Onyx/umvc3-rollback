// sound_preserve.cpp — cross-boundary-pointer fix (pointer-stale sound crash 0x1405C2698).
//
// CARRIER (objdump 0x1405c268d-98): FUN_1405c1ea0 does
// mov (%rdi),%rcx; rcx = SE/slot descriptor pointer (null-guarded, non-null)
// mov (%rcx),%rax; rax = descriptor's VTABLE (desc+0x00)
// call *0xa0(%rax); vcall — FAULTS when the vtable reverted to garbage (wild 0xF00000010)
// The crashing edge = desc+0x00 (the descriptor object's vtable). The descriptor is a GAME-side refcounted
// object (refcount +0x4c), not an XAudio2 voice. The slot array lives inside the page-EXCLUDED sSound body, so
// its slot+0x168 pointers stay LIVE while the Global-pool descriptor they point at gets REVERTED to garbage.
//
// ENUMERATION: the container is a
// FIXED 64-SLOT ARRAY: mgr = engine+0x29B0; slots at mgr+0x90, stride 0x180, count 64; busy = slot+0x18 (u8);
// descriptor = *(slot+0x168). All raw READS => freeze-safe (no engine virtuals).
//
// The detector is default-ON: capture() snapshots each busy slot's descriptor + its live vtable pre-freeze;
// restore() (post-load) re-reads and logs any descriptor whose vtable changed/reverted-to-garbage. The writeback
// (un-revert the vtable, identity-gated) is off by default (g_writeback; toggle() arms it).
#include "sound_preserve.h"
#include "arena.h"
#include "addr.h"
#include "log.h"
#include <windows.h>
#include <cstdint>

namespace sound_preserve {

static volatile LONG g_on = 1;          // detector (read-only census + revert log) — default ON
static volatile LONG g_writeback = 0;   // the FIX (un-revert desc vtable, identity-gated) — toggle() arms (no key binding currently)

bool enabled() { return InterlockedCompareExchange(&g_on, 0, 0) != 0; }
void toggle() {
    LONG v = InterlockedXor(&g_writeback, 1);   // toggles the WRITEBACK fix (detector stays on)
    rblog::write("SOUND-PRESERVE: writeback FIX %s (detector always on)", (v & 1) ? "OFF" : "ON");
}

static const uintptr_t MOD = 0x140000000ULL;
static const uintptr_t MGR_OFF = 0x29B0, SLOT0 = 0x90, STRIDE = 0x180, BUSY = 0x18, DESC = 0x168;
static const int NSLOT = 64;

static inline bool canon(uintptr_t p) { return p >= 0x10000ULL && p < 0x800000000000ULL; }
static inline bool readable8(uintptr_t p) {
    if (!canon(p)) return false;
    if (arena::is_arena_addr(p)) return arena::is_committed_addr(p);
    MEMORY_BASIC_INFORMATION mbi;
    if (!VirtualQuery((void*)p, &mbi, sizeof(mbi))) return false;
    if (mbi.State != MEM_COMMIT) return false;
    if (mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)) return false;
    return true;
}
static inline uintptr_t rd(uintptr_t p) { return readable8(p) ? *(uintptr_t*)p : 0; }
static inline bool in_image(uintptr_t p) { return p >= MOD && p < MOD + 0x1000000ULL; }  // a plausible .rdata vtable

struct Cap { uintptr_t slot; uintptr_t desc; uintptr_t vtable; };
static Cap g_cap[256];
static int g_cap_n = 0;

template <class F> static void walk_slots(F cb) {
    uintptr_t engines[2] = { rd(addr::resolve(0x140E18520)), addr::resolve(0x140D533E0) };
    for (int e = 0; e < 2; e++) {
        uintptr_t E = engines[e];
        if (!readable8(E)) continue;
        uintptr_t mgr = E + MGR_OFF;
        for (int i = 0; i < NSLOT; i++) {
            uintptr_t slot = mgr + SLOT0 + (uintptr_t)i * STRIDE;
            if (!readable8(slot + BUSY)) continue;
            if (*(volatile uint8_t*)(slot + BUSY) == 0) continue;     // raw busy flag (mirrors vt+0x30 leaf)
            uintptr_t desc = rd(slot + DESC);
            if (!canon(desc) || !readable8(desc)) continue;
            cb(slot, desc);
        }
    }
}

// PRE-FREEZE (threads live): snapshot each busy slot's descriptor + its LIVE vtable (desc+0x00).
void capture(int /*frame*/) {
    if (!enabled()) return;
    g_cap_n = 0;
    int busy = 0;
    walk_slots([&](uintptr_t slot, uintptr_t desc) {
        busy++;
        if (g_cap_n < 256) g_cap[g_cap_n++] = { slot, desc, rd(desc) };
    });
    static int s_first = 0;
    if (busy > 0 && s_first < 8) { s_first++;
        rblog::write("SOUND-PRESERVE[capture]: %d busy slots, %d descriptors snapshotted", busy, g_cap_n);
    }
}

// POST-LOAD (after arena::load): re-read; LOG any descriptor whose vtable reverted; writeback only if armed.
void restore(int /*frame*/) {
    if (!enabled()) return;
    int reverted = 0, garbage = 0, fixed = 0, logged = 0;
    bool wb = InterlockedCompareExchange(&g_writeback, 0, 0) != 0;
    for (int i = 0; i < g_cap_n; i++) {
        Cap& c = g_cap[i];
        // identity: the (preserved, in-excluded-body) slot must still be busy and still point at the same descriptor.
        if (!readable8(c.slot + BUSY) || *(volatile uint8_t*)(c.slot + BUSY) == 0) continue;
        if (rd(c.slot + DESC) != c.desc) continue;            // slot rebound => different object => skip
        if (!readable8(c.desc)) continue;
        uintptr_t cur = *(uintptr_t*)c.desc;
        if (cur == c.vtable) continue;                        // unchanged => fine
        reverted++;
        bool cur_garbage = !in_image(cur);                    // a real vtable is in-image; garbage = the crash
        if (cur_garbage) garbage++;
        if (logged < 16) { logged++;
            rblog::write("SOUND-PRESERVE[revert] slot=0x%llX desc=0x%llX vtable pre=0x%llX post=0x%llX%s%s",
                (unsigned long long)c.slot, (unsigned long long)c.desc,
                (unsigned long long)c.vtable, (unsigned long long)cur,
                cur_garbage ? " <== GARBAGE (the 0x1405C2698 crash edge)" : "",
                (wb && in_image(c.vtable)) ? " => WRITEBACK" : "");
        }
        if (wb && in_image(c.vtable)) { *(uintptr_t*)c.desc = c.vtable; fixed++; }   // FIX: un-revert the vtable
    }
    if (reverted > 0)
        rblog::write("SOUND-PRESERVE[restore]: %d desc vtables reverted (%d to garbage), %d written back (writeback=%s)",
                     reverted, garbage, fixed, wb ? "ON" : "OFF");
}

void report() {}

} // namespace sound_preserve
