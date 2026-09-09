// provenance.cpp — see provenance.h. The sub-page object index. Consumes idspine's sized live-block
// snapshot, sorts by base, and answers "what object owns this address?" by binary search. resolve_user finds the
// real user/object pointer via the allocator's back-offset invariant — for a real allocation user = block + off and
// *(user-8) == off (the engine's own free path computes block = user - *(user-8), FUN_1404cb350).
// So we scan plausible offsets for the one whose back-offset word is self-consistent, then classify by vtable. This
// replaces the hardcoded +0x50 (which read vt=0 on 9/12 samples) and the coverage ledger proves the resolver.
#include "provenance.h"
#include "idspine.h"
#include "arena.h"
#include "addr.h"
#include "log.h"
#include <windows.h>
#include <cstdint>
#include <cstring>
#include <algorithm>

namespace provenance {

namespace {

struct TgType { uint64_t vt; uint32_t size; uint16_t nptr; uint32_t ptr_base; const char* name; };
#include "audio_typegraph.inc"   // TG_NTYPES, TG_TYPES[] (sorted by vt) — for type resolution

constexpr int MAXN = 300000;
struct Rec { uintptr_t base; uint32_t size; int64_t serial; };
static Rec g_idx[MAXN];
static int g_n = 0;

static uintptr_t* g_bs = nullptr; static uint32_t* g_sz = nullptr; static int64_t* g_sr = nullptr;

// Candidate user-offsets to probe, most-common first (0x50 header is the dominant case).
static const uint16_t OFF_CANDS[] = { 0x50, 0x10, 0x20, 0x30, 0x40, 0x60, 0x70, 0x80, 0x90, 0xA0, 0xB0, 0xC0, 0xD0, 0xE0, 0xF0, 0x100 };
static const int N_OFF = (int)(sizeof(OFF_CANDS)/sizeof(OFF_CANDS[0]));

static inline uint64_t to_ida(uintptr_t vt){
    if (vt < addr::g_base) return 0;
    uint64_t ida = (uint64_t)vt - addr::g_base + 0x140000000ull;
    return (ida >= 0x140000000ull && ida < 0x141000000ull) ? ida : 0;
}
static int tg_lookup(uint64_t ida){
    int lo=0, hi=TG_NTYPES-1;
    while(lo<=hi){ int m=(lo+hi)>>1; uint64_t v=TG_TYPES[m].vt; if(v==ida)return m; if(v<ida)lo=m+1; else hi=m-1; }
    return -1;
}

// Resolve the owning object: find the self-consistent user-offset, then classify. The back-offset invariant
// *(user-8)==user_off is the allocator's own user->block recovery, so it uniquely identifies the real user ptr.
static void resolve(const Rec& r, Owner* o){
    o->base = r.base; o->size = r.size; o->serial = r.serial;
    o->user = 0; o->user_off = 0; o->kind = K_UNRESOLVED; o->vtable = 0; o->ida_vt = 0; o->type = "(unresolved)";
    for (int c = 0; c < N_OFF; c++) {
        uint16_t off = OFF_CANDS[c];
        if ((uint32_t)off + 8 > r.size) continue;
        uintptr_t u = r.base + off;
        if (off < 8 || !arena::is_committed_addr(u - 8) || !arena::is_committed_addr(u)) continue;
        if (*(uint64_t*)(u - 8) != (uint64_t)off) continue;        // back-offset self-consistency: *(user-8) == user_off
        uintptr_t vt = *(uintptr_t*)u; uint64_t ida = to_ida(vt);
        o->user = u; o->user_off = off; o->vtable = vt; o->ida_vt = ida;
        if (ida) { int ti = tg_lookup(ida); o->kind = K_TYPED; o->type = (ti >= 0) ? TG_TYPES[ti].name : "(non-reflected)"; }
        else     { o->kind = K_DATA; o->type = "(data)"; }
        return;
    }
    // no self-consistent offset => genuinely unresolved (resolver gap or non-standard block layout)
    o->user = r.base + 0x50; o->user_off = 0; o->kind = K_UNRESOLVED; o->type = "(unresolved)";
}

} // anon

void build(){
    if (!g_bs) {
        g_bs = (uintptr_t*)VirtualAlloc(0, (SIZE_T)MAXN*8, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
        g_sz = (uint32_t*) VirtualAlloc(0, (SIZE_T)MAXN*4, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
        g_sr = (int64_t*)  VirtualAlloc(0, (SIZE_T)MAXN*8, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
    }
    if (!g_bs || !g_sz || !g_sr) { g_n = 0; return; }
    int n = idspine::snapshot_live_sized(g_bs, g_sz, g_sr, MAXN);
    int k = 0;
    for (int i=0;i<n;i++) {
        if (g_bs[i] && arena::is_arena_addr(g_bs[i]) && g_sz[i] > 0 && g_sz[i] < 0x4000000) {
            g_idx[k].base=g_bs[i]; g_idx[k].size=g_sz[i]; g_idx[k].serial=g_sr[i]; k++;
        }
    }
    std::sort(g_idx, g_idx+k, [](const Rec&a,const Rec&b){ return a.base < b.base; });
    g_n = k;
}

int count(){ return g_n; }

bool object_at(int i, Owner* out){
    if (i < 0 || i >= g_n) return false;
    resolve(g_idx[i], out);
    return true;
}

bool owner_of(uintptr_t addr, Owner* out){
    int lo=0, hi=g_n-1, best=-1;
    while(lo<=hi){ int m=(lo+hi)>>1; if(g_idx[m].base<=addr){ best=m; lo=m+1; } else hi=m-1; }
    if (best<0) return false;
    if (addr < g_idx[best].base + g_idx[best].size) { resolve(g_idx[best], out); return true; }
    return false;
}

int in_range(uintptr_t lo, uintptr_t hi, Owner* out, int max){
    int l=0, h=g_n-1, loIdx=g_n;
    while(l<=h){ int m=(l+h)>>1; if(g_idx[m].base<lo) l=m+1; else { loIdx=m; h=m-1; } }
    int cnt=0;
    for (int i=(loIdx>0?loIdx-1:0); i<g_n && g_idx[i].base<hi && cnt<max; i++) {
        if (g_idx[i].base + g_idx[i].size > lo) { resolve(g_idx[i], &out[cnt]); cnt++; }
    }
    return cnt;
}

void coverage(){
    static int s_calls = 0;
    build();
    int typed=0, data=0, unres=0, reflected=0, off50=0, offOther=0;
    uint64_t tbytes=0;
    for (int i=0;i<g_n;i++) {
        Owner o; resolve(g_idx[i], &o);
        tbytes += o.size;
        if (o.kind == K_TYPED) { typed++; if (o.user_off==0x50) off50++; else offOther++; if (o.type && strcmp(o.type,"(non-reflected)")!=0) reflected++; }
        else if (o.kind == K_DATA) data++;
        else unres++;
    }
    if (s_calls++ >= 4) return;   // first few rollbacks only (validation, not per-rollback spam)
    bool was = rblog::is_suppressed(); rblog::suppress(false);
    rblog::write("PROVENANCE/coverage: %d objects, %.1f MB | typed=%d (off0x50=%d other=%d reflected=%d) data=%d UNRESOLVED=%d  [gate: UNRESOLVED ~= 0]",
                 g_n, tbytes/1048576.0, typed, off50, offOther, reflected, data, unres);
    // sample a few resolved typed objects (self-consistency holds by construction: base+user_off==user, *(user-8)==user_off)
    int shown=0, step = (g_n>10)? g_n/10 : 1;
    for (int i=0; i<g_n && shown<10; i+=step) {
        Owner o; if(!object_at(i,&o)) continue;
        if (o.kind != K_TYPED) continue;
        rblog::write("PROVENANCE/obj base=0x%llX user_off=0x%X size=0x%X serial=%lld vt=0x%llX type=%s",
            (unsigned long long)o.base, o.user_off, o.size, (long long)o.serial, (unsigned long long)o.ida_vt, o.type);
        shown++;
    }
    rblog::write("PROVENANCE/coverage: object_at()/owner_of()/in_range() ready over %d objects; serial = identity coordinate.", g_n);
    rblog::suppress(was);
}

} // namespace provenance
