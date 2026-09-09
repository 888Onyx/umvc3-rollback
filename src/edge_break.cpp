// edge_break.cpp — see edge_break.h. Complete, probe-independent cross-boundary edge detector.
#include "edge_break.h"
#include "arena.h"
#include "log.h"
#include <windows.h>
#include <cstring>

namespace edge_break {

// DEFAULT ON: this is a read-only diff over pages the revert already touches (one memcpy + a compare per qword,
// ~1-3ms against a ~150ms rollback), and the entire point is to capture the edge set on a crash we can't reproduce
// on demand. Requiring a keypress meant one forgotten key cost a whole run. Numpad / toggles it OFF if it ever costs.
static bool     g_on = true;
static uintptr_t g_mod_lo = 0, g_mod_hi = 0;

// The module span must be known before is_ooa_ptr() runs, or module-const pointers misclassify as external edges
// (false positives). set_enabled() seeds it, but with the detector default-ON that may never be called — so begin()
// seeds it too. Idempotent.
static void seed_module_range() {
    if (g_mod_lo) return;
    uintptr_t m = (uintptr_t)GetModuleHandleA("umvc3.exe");
    if (m) { g_mod_lo = m; g_mod_hi = m + 0x1000000ull; }
}

// per-rollback tallies
static long long g_changed_qwords = 0;   // every qword the revert altered (denominator)
static long long g_broke_null     = 0;   // live OOA pointer -> 0
static long long g_broke_poison   = 0;   // live OOA pointer -> 0xFFFF...FFFF (the d3d9 crash shape)
static long long g_broke_other    = 0;   // live OOA pointer -> some other value
static long long g_introduced     = 0;   // non-pointer -> OOA pointer (revert RESURRECTED an old external ptr)
static long long g_pages          = 0;

// sample ring: the first N distinct breaks, so the log names actual addresses to chase
struct Sample { uintptr_t addr; uint64_t pre, post; };
static constexpr int MAX_SAMP = 24;
static Sample g_samp[MAX_SAMP];
static int    g_nsamp = 0;

bool enabled() { return g_on; }
void set_enabled(bool on) {
    g_on = on;
    if (on) seed_module_range();
    rblog::write("EDGE-BREAK detector %s — READ-ONLY complete cross-boundary edge diff over every reverted page "
                 "(no vtable table, no sampling, no allocator scoping).", on ? "ON" : "OFF");
}

// Cheap, allocation-free "is this a pointer to memory the revert does not own?" test. Deliberately NO VirtualQuery
// (this runs per changed qword inside the frozen window). Range checks only: canonical user-space, 8-aligned, and
// outside both the arena (which reverts) and the module image (const, never stale).
static inline bool is_ooa_ptr(uint64_t v) {
    if (v < 0x10000ull) return false;                     // null / small scalar
    if (v >= 0x0000800000000000ull) return false;         // non-canonical / kernel / poison-as-scalar
    if (v & 7ull) return false;                           // object pointers are 8-aligned
    if (arena::is_arena_addr((uintptr_t)v)) return false; // in-arena: reverts coherently with its carrier
    if (g_mod_lo && v >= g_mod_lo && v < g_mod_hi) return false;   // module const
    return true;                                          // => out-of-arena heap/system memory: never reverted
}

void begin(int) {
    if (!g_on) return;
    seed_module_range();
    static bool announced = false;
    if (!announced) {
        announced = true;
        bool w = rblog::is_suppressed(); rblog::suppress(false);
        rblog::write("EDGE-BREAK detector LIVE (default-on) — complete cross-boundary edge diff over EVERY reverted "
                     "page: no vtable table, no sampling, no allocator scoping. Read-only. Numpad / toggles.");
        rblog::suppress(w);
    }
    g_changed_qwords = g_broke_null = g_broke_poison = g_broke_other = g_introduced = g_pages = 0;
    g_nsamp = 0;
}

void page(uintptr_t page_addr, const void* pre, const void* post, size_t len) {
    if (!g_on || !pre || !post) return;
    g_pages++;
    const uint64_t* a = (const uint64_t*)pre;    // live (pre-revert) bytes
    const uint64_t* b = (const uint64_t*)post;   // restored bytes now in the arena
    size_t n = len / 8;
    for (size_t i = 0; i < n; i++) {
        uint64_t x = a[i], y = b[i];
        if (x == y) continue;                    // untouched by the revert — the overwhelmingly common case
        g_changed_qwords++;
        bool px = is_ooa_ptr(x), py = is_ooa_ptr(y);
        if (!px && !py) continue;                // ordinary gameplay scalar/in-arena churn: correct to revert

        if (px) {                                // we held a live external pointer and the revert changed it
            if (y == 0) g_broke_null++;
            else if (y == 0xFFFFFFFFFFFFFFFFull) g_broke_poison++;
            else g_broke_other++;
        } else {                                 // revert WROTE an old external pointer over a non-pointer
            g_introduced++;
        }
        if (g_nsamp < MAX_SAMP) {
            g_samp[g_nsamp].addr = page_addr + i * 8;
            g_samp[g_nsamp].pre = x; g_samp[g_nsamp].post = y;
            g_nsamp++;
        }
    }
}

void report(int frame) {
    if (!g_on) return;
    long long broke = g_broke_null + g_broke_poison + g_broke_other + g_introduced;
    bool w = rblog::is_suppressed(); rblog::suppress(false);
    rblog::write("EDGE-BREAK[f%d]: %lld cross-boundary edge(s) broken by this revert | ->null=%lld ->POISON(-1)=%lld "
                 "->other=%lld resurrected=%lld | scanned %lld pages, %lld changed qwords. "
                 "(0 = the revert broke no external edge; >0 = these are live pointers to memory that never rewound.)",
                 frame, broke, g_broke_null, g_broke_poison, g_broke_other, g_introduced, g_pages, g_changed_qwords);
    for (int i = 0; i < g_nsamp; i++)
        rblog::write("   EDGE-BREAK sample @0x%llX: live=0x%llX -> restored=0x%llX%s",
                     (unsigned long long)g_samp[i].addr,
                     (unsigned long long)g_samp[i].pre, (unsigned long long)g_samp[i].post,
                     g_samp[i].post == 0xFFFFFFFFFFFFFFFFull ? "   <== POISON: the d3d9 READ 0xFFFF.. shape" : "");
    rblog::suppress(w);
}

} // namespace edge_break
