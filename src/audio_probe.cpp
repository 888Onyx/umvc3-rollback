// audio_probe.cpp — see audio_probe.h. Derives the audio domain as a TYPE SET by walking the live object graph
// from the audio roots with the MtDTI type graph (precise ClassRef_ptr-following + exact extents). The probe is the
// edge-ORACLE the static graph can't be (MtDTI records ptr SLOTS but no targets); each object it reaches is typed by
// its vtable, so one walk converts "addresses seen" into "instances of these N types".
// collect() exposes the per-object region list so audio_preserve can keep each object live PER-OBJECT (by extent),
// never page-excluding — a slab is just a way to capture data; we preserve the object inside it, the page reverts.
#include "audio_probe.h"
#include "arena.h"
#include "addr.h"
#include "log.h"
#include <windows.h>
#include <cstdint>
#include <vector>
#include <algorithm>

namespace audio_probe {

namespace {

struct TgType { uint64_t vt; uint32_t size; uint16_t nptr; uint32_t ptr_base; const char* name; };
#include "audio_typegraph.inc"   // TG_NTYPES, TG_PTROFF[], TG_TYPES[] (sorted by vt, IDA addresses)

// Curated NON-REFLECTED audio leaves (IDA vtables) — the plain C++ classes MtDTI doesn't register.
struct Leaf { uint64_t vt; uint32_t size; int nedge; uint32_t edges[4]; const char* name; };
static const Leaf AUDIO_LEAVES[] = {
    {0x140bad660ull, 0x738, 1, {0x360}, "(streamVoiceP)"},   // -> rSoundSource C
    {0x140bad7d0ull, 0x370, 0, {},      "(streamChannel)"},
    {0x140bad4b0ull, 0x358, 0, {},      "(streamStrip)"},
    {0x140bc4100ull, 0x1a0, 0, {},      "(rSoundSource)"},
    {0x140bc40f0ull, 0x1a0, 0, {},      "(rSoundSource')"},
    {0x140bc3ce0ull, 0x1a0, 0, {},      "(rSoundSource'')"},
};
static const int N_LEAF = (int)(sizeof(AUDIO_LEAVES)/sizeof(AUDIO_LEAVES[0]));

static inline bool canon(uintptr_t p){ return p>=0x10000 && p<0x7FFFFFFFFFFFull; }

static bool readable(uintptr_t p, size_t n){
    if(!p || n==0) return false;
    if(arena::is_arena_addr(p) && arena::is_arena_addr(p+n-1))
        return arena::is_committed_addr(p) && arena::is_committed_addr(p+n-1);
    MEMORY_BASIC_INFORMATION mbi;
    if(!VirtualQuery((void*)p,&mbi,sizeof(mbi))) return false;
    if(mbi.State!=MEM_COMMIT) return false;
    if(mbi.Protect & (PAGE_NOACCESS|PAGE_GUARD)) return false;
    uintptr_t end=(uintptr_t)mbi.BaseAddress+mbi.RegionSize;
    return p+n<=end;
}

static inline uint64_t to_ida(uintptr_t vt){
    if(vt < addr::g_base) return 0;
    uint64_t ida = (uint64_t)vt - addr::g_base + 0x140000000ull;
    if(ida < 0x140000000ull || ida >= 0x141000000ull) return 0;
    return ida;
}
static int tg_lookup(uint64_t ida){
    int lo=0, hi=TG_NTYPES-1;
    while(lo<=hi){ int m=(lo+hi)>>1; uint64_t v=TG_TYPES[m].vt;
        if(v==ida) return m; if(v<ida) lo=m+1; else hi=m-1; }
    return -1;
}
static const Leaf* leaf_lookup(uint64_t ida){
    for(int i=0;i<N_LEAF;i++) if(AUDIO_LEAVES[i].vt==ida) return &AUDIO_LEAVES[i];
    return nullptr;
}

// Per-object walk result (parallel arrays). Shared by collect() and run_once().
static const int MAXN = 1024;
static uintptr_t g_b[MAXN]; static uint32_t g_s[MAXN]; static uint64_t g_v[MAXN]; static const char* g_nm[MAXN];
static bool g_arena[MAXN];

// BFS the live audio object graph from sSound. Fills g_b/g_s/g_v/g_nm/g_arena, returns node count.
// Records only SIZED nodes (reflected or curated leaf); unknown-vtable objects are leaf gaps (not followed, not sized).
static int do_walk(){
    int n_out = 0;
    uintptr_t pss = addr::resolve(0x140E18520);
    if(!readable(pss,8)) return 0;
    uintptr_t ss = *(uintptr_t*)pss;
    if(!ss || !canon(ss) || !readable(ss,8)) return 0;

    std::vector<uintptr_t> visited; visited.reserve(2048);
    std::vector<uintptr_t> stack;   stack.reserve(2048);
    auto enqueue=[&](uintptr_t a){
        if(!a || !canon(a) || !readable(a,8)) return;
        auto it=std::lower_bound(visited.begin(),visited.end(),a);
        if(it!=visited.end() && *it==a) return;
        visited.insert(it,a); stack.push_back(a);
    };

    // SEED: root + curated sSound structure (sSound itself may be non-reflected, so seed its known graph directly).
    enqueue(ss);
    if(readable(ss+0x38,8)){
        uintptr_t sMgr=*(uintptr_t*)(ss+0x38); enqueue(sMgr);
        if(sMgr && canon(sMgr)){
            if(readable(sMgr+0x148,8)) enqueue(*(uintptr_t*)(sMgr+0x148));         // streaming channel
            for(int i=0;i<32;i++) if(readable(sMgr+8+(uintptr_t)i*8,8)) enqueue(*(uintptr_t*)(sMgr+8+(uintptr_t)i*8)); // 32 strips
        }
    }
    for(int v=0;v<8;v++){ uintptr_t ps=ss+0x1756c+(uintptr_t)v*0xB30-0x5C;          // 8 streaming voices P
        if(readable(ps,8)) enqueue(*(uintptr_t*)ps); }

    const int CAP=12000; int total=0;
    while(!stack.empty() && total<CAP && n_out<MAXN){
        uintptr_t a=stack.back(); stack.pop_back();
        if(!readable(a,8)) continue;
        uintptr_t vt=*(uintptr_t*)a;
        uint64_t ida=to_ida(vt);
        bool arena=arena::is_arena_addr(a);
        total++;
        int ti = ida? tg_lookup(ida) : -1;
        const Leaf* lf = ida? leaf_lookup(ida) : nullptr;
        if(ti>=0){
            const TgType& T=TG_TYPES[ti];
            g_b[n_out]=a; g_s[n_out]=T.size; g_v[n_out]=ida; g_nm[n_out]=T.name; g_arena[n_out]=arena; n_out++;
            for(uint16_t k=0;k<T.nptr;k++){ uint32_t off=TG_PTROFF[T.ptr_base+k];
                if(readable(a+off,8)){ uintptr_t t=*(uintptr_t*)(a+off);
                    if(t && canon(t) && readable(t,8)){ uintptr_t tvt=*(uintptr_t*)t; if(to_ida(tvt)) enqueue(t); } } }
        } else if(lf){
            g_b[n_out]=a; g_s[n_out]=lf->size; g_v[n_out]=ida; g_nm[n_out]=lf->name; g_arena[n_out]=arena; n_out++;
            for(int k=0;k<lf->nedge;k++){ uint32_t off=lf->edges[k];
                if(readable(a+off,8)) enqueue(*(uintptr_t*)(a+off)); }
        }
        // unknown vtable: a leaf gap — cannot size/follow safely; not recorded.
    }
    return n_out;
}

} // anon

int collect(Region* out, int max_n){
    int n = do_walk();
    int k = 0;
    for(int i=0;i<n && k<max_n;i++){
        if(g_arena[i] && g_s[i]>0){ out[k].base=g_b[i]; out[k].size=g_s[i]; k++; }
    }
    return k;
}

void run_once(){
    static bool done=false; if(done) return; done=true;
    int n = do_walk();
    if(n<=0){ return; }

    struct Agg { uint64_t vt; const char* name; uint32_t size; int count; int in_arena; };
    std::vector<Agg> aggs;
    int total=n, in_arena=0, subpage_arena=0; uint64_t total_bytes=0;
    for(int i=0;i<n;i++){
        if(g_arena[i]) in_arena++;
        total_bytes += g_s[i];
        if(g_arena[i] && g_s[i]>0 && g_s[i]<0x1000) subpage_arena++;
        bool found=false;
        for(auto&g:aggs) if(g.vt==g_v[i]){ g.count++; if(g_arena[i])g.in_arena++; found=true; break; }
        if(!found) aggs.push_back({g_v[i], g_nm[i], g_s[i], 1, g_arena[i]?1:0});
    }
    std::sort(aggs.begin(),aggs.end(),[](const Agg&a,const Agg&b){ return (uint64_t)a.size*a.count > (uint64_t)b.size*b.count; });

    bool was=rblog::is_suppressed(); rblog::suppress(false);
    rblog::write("==== AUDIO-PROBE: domain derived (nodes=%d in_arena=%d distinct_types=%d subpage_in_arena=%d total_bytes=%llu) ====",
                 total, in_arena, (int)aggs.size(), subpage_arena, (unsigned long long)total_bytes);
    for(auto&g:aggs)
        rblog::write("AUDIO-PROBE/type vt=0x%llX %-26s size=0x%-6X count=%-4d in_arena=%-4d%s",
            (unsigned long long)g.vt, g.name?g.name:"?", g.size, g.count, g.in_arena,
            (g.in_arena && g.size>0 && g.size<0x1000)?" <subpage>":"");
    rblog::suppress(was);
}

} // namespace audio_probe
