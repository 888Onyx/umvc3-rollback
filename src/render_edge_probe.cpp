// render_edge_probe.cpp — see render_edge_probe.h. Read-only parent->freed-child diagnostic.
#include "render_edge_probe.h"
#include "arena.h"
#include "addr.h"
#include "log.h"
#include <windows.h>
#include <cstdint>

namespace render_edge_probe {

namespace {
static bool committed(uintptr_t p){ return p >= 0x10000 && arena::is_committed_addr(p); }
// entry is an object ptr; valid iff its first qword is a umvc3 module vtable.
static bool is_obj(uintptr_t e){
    if (!committed(e) || !committed(e + 8)) return false;
    uintptr_t vt = *(uintptr_t*)e;
    if (vt < addr::g_base) return false;
    uint64_t ida = (uint64_t)vt - addr::g_base + 0x140000000ull;
    return ida >= 0x140000000ull && ida < 0x141000000ull;
}
static void scan(uintptr_t sr, uintptr_t arr_off, uintptr_t cnt_off, const char* name, const char* tag){
    uintptr_t cnt_a = sr + cnt_off, arr_a = sr + arr_off;
    if (!committed(cnt_a) || !committed(arr_a)) return;
    uint32_t n = *(uint32_t*)cnt_a;
    if (n > 0x100000) return;                     // sanity
    int total = 0, nullc = 0, dangling = 0;
    uintptr_t ex = 0;
    for (uint32_t i = 0; i < n; i++) {
        uintptr_t slot = arr_a + (uintptr_t)i * 8;
        if (!committed(slot)) break;
        uintptr_t e = *(uintptr_t*)slot;
        total++;
        if (e == 0) { nullc++; continue; }
        if (!is_obj(e)) { dangling++; if (!ex) ex = e; }
    }
    bool w = rblog::is_suppressed(); rblog::suppress(false);
    rblog::write("RENDER-EDGE[%s] %s: count=%u walked=%d null=%d DANGLING=%d ex=0x%llX (no-null-guard walk derefs these => the kept-live sRender crash)",
                 tag, name, n, total, nullc, dangling, (unsigned long long)ex);
    rblog::suppress(w);
}
}

void probe(const char* tag){
    static int s = 0; if (s >= 10) return; s++;
    uintptr_t mod = (uintptr_t)GetModuleHandleA("umvc3.exe"); if (!mod) return;
    uintptr_t srp = mod + (0x140E179A8ull - 0x140000000ull);   // MODULE.data slot holding the sRender ptr (not arena)
    uintptr_t sr = *(uintptr_t*)srp;                            // read directly — module's .data is always mapped
    bool w = rblog::is_suppressed(); rblog::suppress(false);
    rblog::write("RENDER-EDGE[%s] sr=0x%llX in_arena=%d committed=%d", tag, (unsigned long long)sr,
                 (int)arena::is_arena_addr(sr), (int)committed(sr));
    rblog::suppress(w);
    if (!committed(sr)) return;
    scan(sr, 0x8817b0, 0x8897b0, "present",    tag);   // FUN_14053a250 present-walk -> 0x14053A4B6
    scan(sr, 0x8677b0, 0x87a7b0, "retirement", tag);   // retirement-walk -> 0x14053A5D7
}

} // namespace render_edge_probe
