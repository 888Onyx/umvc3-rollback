// field_target_recorder.cpp — pointer-provenance recorder (the in-arena-vs-external edge-discriminator). See header.
// READ-ONLY: no game writes; off-arena target reads VirtualQuery-guarded (page-cached); throttled;.bss buffers
// (not VirtualAlloc — the arena IAT hook would redirect a heap buffer into the reverted arena).
//
// v2 fixes (the first recording captured only 3 real types, misdetected .bss globals as vtables, and hung the game):
// - object_root REQUIRES a real .rdata vtable (in the .rdata section) whose first two method slots are in .text.
// (The first version accepted any block+H pointing into the module image, so it latched .bss/global tables -> wrong roots.)
// - VirtualQuery results cached by 64KB page (cuts the per-pass VQ storm that made the game sluggish/hang).
// - lower MAX_BLOCKS + higher SAMPLE_EVERY to bound per-pass cost.
#include "field_target_recorder.h"
#include "idspine.h"
#include "arena.h"
#include "log.h"
#include <windows.h>
#include <cstdint>
#include <cstdio>

namespace field_target_recorder {

static volatile LONG g_armed = 0;
static LONG s_frame = 0;
static const int SAMPLE_EVERY = 40;     // ~1.5 sampling passes/sec @60fps (gentler than v1's 20)
static const int DUMP_EVERY   = 300;    // dump ~every 5s (feedback + a crash leaves recent data)
static const int MAX_BLOCKS   = 12000;  // bound the per-pass snapshot (v1 used 30000 — too heavy)
static const uintptr_t MAX_SCAN = 0x4000;

// module + section ranges (main exe)
static uintptr_t g_mod_base=0, g_mod_end=0, g_text_lo=0, g_text_hi=0, g_rdata_lo=0, g_rdata_hi=0;
static void init_mod() {
    if (g_mod_base) return;
    HMODULE m = GetModuleHandleA("umvc3.exe");
    if (!m) m = GetModuleHandleA(nullptr);
    if (!m) return;
    g_mod_base = (uintptr_t)m;
    auto* dos = (IMAGE_DOS_HEADER*)m;
    auto* nt = (IMAGE_NT_HEADERS*)(g_mod_base + dos->e_lfanew);
    g_mod_end = g_mod_base + nt->OptionalHeader.SizeOfImage;
    auto* sec = IMAGE_FIRST_SECTION(nt);
    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        uintptr_t lo = g_mod_base + sec[i].VirtualAddress;
        uintptr_t hi = lo + sec[i].Misc.VirtualSize;
        if (!memcmp(sec[i].Name, ".text", 5))  { g_text_lo = lo;  g_text_hi = hi; }
        else if (!memcmp(sec[i].Name, ".rdata", 6)) { g_rdata_lo = lo; g_rdata_hi = hi; }
    }
}

// VirtualQuery cache (64KB page granularity) — eliminates the per-pass VirtualQuery storm.
struct VQC { uintptr_t page; int ok; };
static VQC g_vqc[8192];
static bool committed(uintptr_t v) {
    uintptr_t pg = v >> 16;
    uint32_t i = (uint32_t)(pg * 2654435761u) & 8191;
    if (g_vqc[i].page == pg && g_vqc[i].page) return g_vqc[i].ok;
    MEMORY_BASIC_INFORMATION mbi;
    int ok = (VirtualQuery((void*)v, &mbi, sizeof(mbi)) && mbi.State == MEM_COMMIT
              && !(mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD))) ? 1 : 0;
    g_vqc[i].page = pg; g_vqc[i].ok = ok; return ok;
}

enum { R_NULL=0, R_ARENA, R_MODULE, R_EXTERNAL, R_GARBAGE, R_NOTPTR };
static inline int classify(uintptr_t v) {
    if (v == 0) return R_NULL;
    if (v < 0x10000 || v >= 0x800000000000ULL) return R_NOTPTR;
    if (arena::is_arena_addr(v)) return arena::is_committed_addr(v) ? R_ARENA : R_GARBAGE;
    if (v >= g_mod_base && v < g_mod_end) return R_MODULE;
    return committed(v) ? R_EXTERNAL : R_GARBAGE;
}

static inline bool rd8(uintptr_t p, uintptr_t* out) {
    if (arena::is_arena_addr(p)) { if (!arena::is_committed_addr(p)) return false; *out = *(uintptr_t*)p; return true; }
    if (!committed(p)) return false;
    *out = *(uintptr_t*)p; return true;
}

// resolve object root from idspine's block base. The header offset H is VARIABLE and self-described: the engine
// recovers block = user - *(user-8) (FUN_1404cb350), so the object root is at block+d where *(block+d-8) == d. Scan d,
// prefer the invariant match; fall back to the smallest d that holds a real .rdata vtable (first 2 methods in .text).
// Counters diagnose: g_invok (invariant matched) vs g_vtonly (vtable but no invariant) vs g_novt (raw buffer / not
// idspine-covered) — so the next capture tells us if H was the whole problem or some objects bypass idspine.
static LONG64 g_invok=0, g_vtonly=0, g_novt=0;
static uintptr_t object_root(uintptr_t block) {
    uintptr_t root = 0; bool inv = false, vtexist = false;
    for (uintptr_t d = 8; d <= 0x100; d += 8) {
        uintptr_t vt, m0, m1, hdr;
        if (!rd8(block + d, &vt)) continue;
        if (vt < g_rdata_lo || vt >= g_rdata_hi) continue;
        if (!rd8(vt, &m0) || m0 < g_text_lo || m0 >= g_text_hi) continue;
        if (!rd8(vt + 8, &m1) || m1 < g_text_lo || m1 >= g_text_hi) continue;
        vtexist = true;
        if (rd8(block + d - 8, &hdr) && hdr == d) { root = block + d; inv = true; break; }  // engine invariant
        if (!root) root = block + d;                                                          // fallback: smallest valid vtable
    }
    if (inv) g_invok++; else if (vtexist) g_vtonly++; else g_novt++;
    return root;
}

struct HE { LONG64 vt; uint32_t off; uint32_t used; uint32_t c[6]; uint32_t samples; };
static const uint32_t HCAP = 1u << 19;
static HE g_hist[HCAP];
static uint32_t g_hist_n = 0;
static LONG64 g_blocks_seen = 0, g_typed = 0, g_capped = 0;

static HE* hfind(LONG64 vt, uint32_t off) {
    uint64_t x = (uint64_t)vt * 0x9E3779B97F4A7C15ULL ^ ((uint64_t)off * 0x100000001B3ULL);
    uint32_t h = (uint32_t)(x >> 40) & (HCAP - 1);
    for (uint32_t i = 0; i < 256; i++) {
        HE& e = g_hist[(h + i) & (HCAP - 1)];
        if (!e.used) { if (g_hist_n >= HCAP - 1) return nullptr; e.used = 1; e.vt = vt; e.off = off; g_hist_n++; return &e; }
        if (e.vt == vt && e.off == off) return &e;
    }
    return nullptr;
}

static uintptr_t g_blkbuf_store[MAX_BLOCKS];
static void sample_pass() {
    init_mod();
    if (!g_text_lo || !g_rdata_lo) return;
    int n = idspine::snapshot_live(g_blkbuf_store, MAX_BLOCKS);
    for (int i = 0; i < n; i++) {
        uintptr_t block = g_blkbuf_store[i];
        g_blocks_seen++;
        uintptr_t root = object_root(block);
        if (!root) continue;
        g_typed++;
        uintptr_t vt; if (!rd8(root, &vt)) continue;
        LONG64 vt_ida = (LONG64)(vt - g_mod_base + 0x140000000ULL);
        for (uintptr_t off = 8; off < MAX_SCAN; off += 8) {
            uintptr_t v;
            if (!rd8(root + off, &v)) break;
            int r = classify(v);
            if (r == R_NOTPTR) continue;
            HE* e = hfind(vt_ida, (uint32_t)off);
            if (!e) { g_capped++; continue; }
            e->c[r]++; e->samples++;
        }
    }
}

static const char* PATH = "umvc3_field_targets.csv";
static void dump() {
    FILE* f = fopen(PATH, "w");
    if (!f) { rblog::write("FIELD-TARGET-REC: dump FAILED to open %s", PATH); return; }
    fprintf(f, "vtable_ida,offset,samples,null,arena,module,external,garbage\n");
    uint32_t rows = 0, vts = 0; LONG64 prevvt = -1;
    for (uint32_t i = 0; i < HCAP; i++) {
        HE& e = g_hist[i];
        if (!e.used || !e.samples) continue;
        fprintf(f, "0x%llX,0x%X,%u,%u,%u,%u,%u,%u\n", (unsigned long long)e.vt, e.off, e.samples,
                e.c[R_NULL], e.c[R_ARENA], e.c[R_MODULE], e.c[R_EXTERNAL], e.c[R_GARBAGE]);
        rows++;
    }
    fclose(f);
    char full[MAX_PATH] = {0}; GetFullPathNameA(PATH, MAX_PATH, full, nullptr);
    rblog::write("FIELD-TARGET-REC: dumped %u (vt,off) rows -> %s | blocks=%lld typed=%lld (invariant=%lld vtable-only=%lld no-vtable=%lld) capped=%lld",
                 rows, full, (long long)g_blocks_seen, (long long)g_typed,
                 (long long)g_invok, (long long)g_vtonly, (long long)g_novt, (long long)g_capped);
}

bool armed() { return InterlockedCompareExchange(&g_armed, 0, 0) != 0; }
void toggle() {
    bool on = (InterlockedXor(&g_armed, 1) & 1) == 0;   // XOR returns the old value; new state is ON iff old was 0
    rblog::write("FIELD-TARGET-REC: recording %s%s", on ? "ON (NUMPAD9)" : "OFF",
                 on ? " — sampling; dumps every ~5s to umvc3_field_targets.csv (press NUMPAD9 again to stop+dump)" : "");
    if (!on) dump();   // dump the accumulated recording when turning OFF
}

void on_frame() {
    static bool prev = false;
    bool now = (GetAsyncKeyState(VK_NUMPAD9) & 0x8000) != 0;
    if (now && !prev) toggle();
    prev = now;
    if (!armed()) return;
    if ((++s_frame % SAMPLE_EVERY) != 0) return;
    sample_pass();
    if ((s_frame % DUMP_EVERY) == 0) dump();
}

} // namespace field_target_recorder
