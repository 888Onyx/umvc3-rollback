// page_free.cpp — content-aware page correction. arena::load stays authoritative.
// This pass does only the REBUILD-SCALAR leave-live half — the safe, prescribed correction:
// a derived SCALAR (flag/counter/integrator) set after the save snapshot is reverted to its pre-init 0; the
// consumer reads 0 and may misbehave. FIX: capture its live (post-init) value before the revert, write it back
// after — IDENTITY-VALIDATED (only if the object at that address still has the same vtable + idspine birth-stamp).
// orig() re-derives it during resim anyway, so leave-live is GGPO-safe.
// It does not touch: RESTORE (role 0, page-revert is correct), EDGE (role 2 — byid owns edges, not a blind sever),
// or REBUILD-POINTER (role 3 — orig re-derives; blind leave-live of a pointer would manufacture a stale edge).
// The 0x0 non-vtable bucket is dropped from the table (no arbitrary-type fallthrough). F11 toggles; OFF = plain.
#include "page_free.h"
#include "arena.h"
#include "addr.h"
#include "idspine.h"
#include "resim.h"
#include "log.h"
#include <windows.h>
#include <cstdint>
#include <cstring>

namespace page_free {
namespace {

// role 0=RESTORE 1=REBUILD_SCALAR(leave-live) 2=EDGE(byid) 3=REBUILD_POINTER(re-derive). We act only on role 1.
#include "manifest_table.inc"

constexpr uintptr_t MOD = 0x140000000ULL;
static volatile LONG g_on = 0;
static bool g_init = false;
static volatile LONG64 g_wb = 0, g_skip_identity = 0;

static const MType* find_mtype(uintptr_t vt_ida) {
    if (!vt_ida) return nullptr;                              // never match a 0 key (0x0 dropped from table anyway)
    for (int i = 0; i < g_manifest_count; i++) if (g_manifest[i].vtable_ida == vt_ida) return &g_manifest[i];
    return nullptr;
}
static inline bool canon(uintptr_t p) { return p >= 0x10000ULL && p < 0x800000000000ULL; }
// committed8: arena -> ns bitmap; out-of-arena (module/.data singletons) -> VirtualQuery (so singletons work).
static inline bool committed8(uintptr_t p) {
    if (!canon(p)) return false;
    if (arena::is_arena_addr(p)) return arena::is_committed_addr(p);
    MEMORY_BASIC_INFORMATION mbi;
    if (!VirtualQuery((void*)p, &mbi, sizeof(mbi))) return false;
    return mbi.State == MEM_COMMIT && !(mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD));
}
static inline bool committed_span(uintptr_t p, unsigned len) {
    if (!committed8(p)) return false;
    return ((p & 0xFFF) + len <= 0x1000) || committed8(p + len - 1);
}
static uintptr_t vt_ida_of(uintptr_t obj) {
    if (!committed_span(obj, 8)) return 0;
    uintptr_t vt = *(uintptr_t*)obj;
    return (vt >= addr::g_base && vt < addr::g_base + 0x1000000ULL) ? (vt - addr::g_base + MOD) : 0;
}

template<class F> static void walk(F cb) {
    uintptr_t ss = addr::resolve(0x140E17698);
    uintptr_t sunit = committed8(ss) ? *(uintptr_t*)ss : 0;
    if (canon(sunit)) for (int line = 0; line < 128; line++) {
        uintptr_t hs = sunit + 0x58 + (uintptr_t)line * 0x30;
        if (!committed8(hs)) continue;
        uintptr_t ent = *(uintptr_t*)hs;
        for (int w = 0; canon(ent) && committed8(ent) && w < 512; w++) {
            cb(ent);
            uintptr_t nx = committed8(ent + 0x20) ? *(uintptr_t*)(ent + 0x20) : 0;
            if (nx == ent) break;
            ent = nx;
        }
    }
    static const uintptr_t SING[] = { 0x140D44A70, 0x140D47E68, 0x140D46470, 0x140D44060 };
    for (uintptr_t s : SING) { uintptr_t rs = addr::resolve(s); uintptr_t o = committed8(rs) ? *(uintptr_t*)rs : 0; if (canon(o) && committed8(o)) cb(o); }
}

// capture store: live REBUILD-SCALAR bytes + the object's identity (vtable+stamp) to validate at write-back.
constexpr int    CAP_MAX = 16384;
constexpr size_t CAP_BUF = 16u << 20;
struct Cap { uintptr_t base; uintptr_t addr; uint32_t size; uint32_t buf_off; uintptr_t vt; int64_t stamp; };
static Cap     g_cap[CAP_MAX];
static int     g_cap_n = 0;
static size_t  g_cap_used = 0;
static bool    g_cap_overflow = false;
static uint8_t g_buf[CAP_BUF];   // DLL.bss — not VirtualAlloc (the arena IAT hook redirects VirtualAlloc into the reverted arena;.bss is untouchable)

} // namespace

void init() {
    g_init = true;   // g_buf is .bss (16MB), survives the rollback untouched — the arena IAT hook cannot reach .bss
    rblog::write("PAGEFREE: content-aware page init — REBUILD-SCALAR leave-live only (EDGE owned by byid), %d types (F11; OFF=plain page-revert)",
                 g_manifest_count);
}
bool enabled() { return InterlockedCompareExchange(&g_on, 0, 0) != 0; }
void toggle() {
    LONG was = InterlockedExchange(&g_on, enabled() ? 0 : 1);
    rblog::write("PAGEFREE: correction %s (arena::load AUTHORITATIVE; REBUILD-scalar leave-live %s; EDGE=byid, not here)",
                 was ? "OFF" : "ON", was ? "disabled" : "ENABLED");
}

// Before arena::load: snapshot the live bytes + identity of every REBUILD_SCALAR (role==1) range.
void pre_load(int frame) {
    if (!g_init || !InterlockedCompareExchange(&g_on, 0, 0)) return;
    g_cap_n = 0; g_cap_used = 0; g_cap_overflow = false;
    walk([&](uintptr_t obj) {
        uintptr_t vt = vt_ida_of(obj); const MType* mt = find_mtype(vt); if (!mt) return;
        int64_t stamp = idspine::stamp_of_object(obj);
        for (int i = 0; i < mt->n; i++) {
            const MRange& r = mt->r[i];
            if (r.role != 1) continue;                        // REBUILD_SCALAR only
            if (!committed_span(obj + r.off, r.size)) continue;
            // belt-and-suspenders: never leave-live a range holding a pointer-valued qword — a pointer
            // misclassified scalar in a non-schema type would become a manufactured stale edge. Skip => page-revert keeps it.
            bool has_ptr = false;
            for (uint32_t o = 0; o + 8 <= r.size; o += 8) {
                uintptr_t v = *(uintptr_t*)(obj + r.off + o);
                if (canon(v) && (arena::is_arena_addr(v) || (v >= addr::g_base && v < addr::g_base + 0x1000000ULL))) { has_ptr = true; break; }
            }
            if (has_ptr) continue;
            if (g_cap_n >= CAP_MAX || g_cap_used + r.size > CAP_BUF) { g_cap_overflow = true; return; }
            Cap& c = g_cap[g_cap_n++];
            c.base = obj; c.addr = obj + r.off; c.size = r.size; c.buf_off = (uint32_t)g_cap_used; c.vt = vt; c.stamp = stamp;
            memcpy(g_buf + g_cap_used, (void*)(obj + r.off), r.size); g_cap_used += r.size;
        }
    });
}

// After arena::load: write the captured live values back — but only into objects whose identity is unchanged
// (same vtable and same idspine birth-stamp). If the slab was reused/orphaned during the revert, SKIP it.
void post_load(int frame) {
    if (!g_init || !InterlockedCompareExchange(&g_on, 0, 0)) return;
    LONG64 wb = 0, skip = 0;
    for (int i = 0; i < g_cap_n; i++) {
        const Cap& c = g_cap[i];
        // Identity-validate the OBJECT (base), not the field: write back only if the object at c.base is still the
        // same one we captured — same vtable and same idspine birth-stamp. If the slab was reused/orphaned during
        // the revert, the stamp/vtable differ => SKIP (never write a stale object's bytes into a new occupant).
        if (!committed8(c.base)) { skip++; continue; }
        if (vt_ida_of(c.base) != c.vt || idspine::stamp_of_object(c.base) != c.stamp) { skip++; continue; }
        if (!committed_span(c.addr, c.size)) { skip++; continue; }
        memcpy((void*)c.addr, g_buf + c.buf_off, c.size); wb++;
    }
    g_wb += wb; g_skip_identity += skip;
}

void report() {
    rblog::write("PAGEFREE: correction %s%s — REBUILD-scalar writeback=%lld, identity-skips=%lld",
                 enabled() ? "ON" : "OFF", g_cap_overflow ? " [CAP OVERFLOW — raise CAP_MAX/BUF]" : "",
                 (long long)g_wb, (long long)g_skip_identity);
}

} // namespace page_free
