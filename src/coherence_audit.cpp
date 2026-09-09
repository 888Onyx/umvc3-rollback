// coherence_audit.cpp — see coherence_audit.h. The POSTLOAD object-graph invariant-violation map.
// Crashes are just invariant-breaks we stepped on; this finds the latent ones too. For every live object (alloc-list
// walk over all 64 allocators), every ClassRef edge (typegraph ptr-slots) is checked against the referent invariants and
// aggregated by (holder_vtable, offset, invariant). Output = the worklist of coherence GAPS to close, domain-agnostic.
#include "coherence_audit.h"
#include "addr.h"
#include "arena.h"
#include "log.h"
#include <MinHook.h>
#include <windows.h>
#include <cstdint>
#include <vector>
#include <algorithm>

namespace coherence_audit {

namespace {

struct TgType { uint64_t vt; uint32_t size; uint16_t nptr; uint32_t ptr_base; const char* name; };
#include "audio_typegraph.inc"   // TG_NTYPES, TG_PTROFF[], TG_TYPES[] (sorted by vt, IDA addresses)

constexpr int TABLE_N = 64;            // (&DAT_140d762f0)[0..63] allocator table
constexpr int HOP_CAP = 300000;        // alloc-lists can hold many thousands of blocks
static volatile long g_off = 1;        // OFF: the alloc-list ENUMERATION is unreliable — live alloc-lists hold far more
                                       // blocks than the cap, so it trips [CAPPED] and reads as "corrupt" when it isn't.
                                       // alloc_invariants is the trusted allocator checker. Re-arm only with a
                                       // bounded/sampled enumeration.

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
// is addr inside any loaded module image (a real vtable lives in some module's .rdata)?
static bool in_module_image(uintptr_t p){
    MEMORY_BASIC_INFORMATION mbi;
    if(!VirtualQuery((void*)p,&mbi,sizeof(mbi))) return false;
    return mbi.State==MEM_COMMIT && mbi.Type==MEM_IMAGE;
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

enum { L_DEAD=0, L_ZEROED=1, L_BADVT=2, L_NLAW=3 };
static const char* LAW_NAME[L_NLAW] = { "REFERENT_DEAD(dangling)", "REFERENT_ZEROED(freed-in-place)", "REFERENT_BADVT(type-confusion)" };

struct Gap { uint64_t hvt; uint32_t off; int law; int count; uintptr_t ex_obj; uintptr_t ex_tgt; const char* name; };
static std::vector<Gap> g_gaps;
static void bump(uint64_t hvt,uint32_t off,int law,uintptr_t obj,uintptr_t tgt,const char* nm){
    for(auto&g:g_gaps) if(g.hvt==hvt&&g.off==off&&g.law==law){ g.count++; return; }
    if(g_gaps.size()<4096) g_gaps.push_back({hvt,off,law,1,obj,tgt,nm});
}

// ── REPAIR state ──────────────────────────────────────────────────────────────────────────────────────
static volatile long g_cont_repair  = 1;   // CONTAINER pass: ON (proven, desync-free)
static volatile long g_field_repair  = 0;   // FIELD pass: OFF (drift risk; gp_crc-watched A/B)
static int64_t c_cont_objs=0, c_cont_kids=0, c_cont_nulled=0, c_field_nulled=0, c_repair_calls=0;

// Dynamic child-array containers: holder vtable (IDA) -> {array_ptr_off, count_off, gate_off}. Element stride = 8
// (array of object pointers). A child is iterated as *(*(holder+array_off) + i*8) and ticked via child.vt+0x38,
// guarded by if(child!=0) — so NULLing an invalid child is safe + skips it. Seeded from the proven crash
// (FUN_140564110 on vt 0x140a7b2e0); EXPAND with siblings sharing this scene-node child-array layout.
struct ContDesc { uint64_t hvt; uint32_t arr_off; uint32_t cnt_off; uint32_t gate_off; };
static const ContDesc CONTAINERS[] = {
    { 0x140a7b2e0ull, 0x110, 0x118, 0x100 },   // scene-node child-array (the seed crash: parent -> zeroed child)
};
static const int N_CONT = (int)(sizeof(CONTAINERS)/sizeof(CONTAINERS[0]));

// ── CONTAINER INSTANCE REGISTRY (register-by-construction; the reliable enumeration) ──────────────────────
// The alloc-list walk caps out before reaching typed objects (objs=0/[CAPPED]) — the known unreliability that
// disabled this audit. So we find container instances the proven way (idspine/sound_resource_preserve pattern):
// hook each container type's ctor and record the instance. The repair iterates this registry (self-cleaning: an
// entry whose vtable no longer matches was freed/reused -> dropped), so it always reaches the crash container.
static constexpr int MAX_CONT_INST = 2048;
static uintptr_t g_cont_inst[MAX_CONT_INST];
static int       g_cont_inst_n = 0;
static int64_t   c_cont_inst_overflow = 0;
static void register_container(uintptr_t obj){
    for(int i=0;i<g_cont_inst_n;i++) if(g_cont_inst[i]==obj) return;       // dedupe
    if(g_cont_inst_n<MAX_CONT_INST) g_cont_inst[g_cont_inst_n++]=obj; else c_cont_inst_overflow++;
}

// ctor hook for vt 0x140a7b2e0 (installer FUN_1400ac1d0; sets *param_1=&PTR_FUN_140a7b2e0, returns param_1).
typedef uintptr_t* (*ctor_fn)(uintptr_t*);
static ctor_fn orig_ctor_a7b2e0 = nullptr;
static uintptr_t* hk_ctor_a7b2e0(uintptr_t* p){
    uintptr_t* r = orig_ctor_a7b2e0(p);
    if(r) register_container((uintptr_t)r);   // *r is the vtable now; validated at repair time
    return r;
}

// is `tgt` a valid live object (first qword = a umvc3 module vtable OR another module's vtable)?
static bool referent_valid(uintptr_t tgt, bool& readable_out){
    readable_out = canon(tgt) && readable(tgt,8);
    if(!readable_out) return false;                 // L_DEAD
    uintptr_t tvt = *(uintptr_t*)tgt;
    if(tvt==0) return false;                         // L_ZEROED
    if(to_ida(tvt)) return true;                     // umvc3 module vtable
    if(in_module_image(tvt)) return true;            // external (COM/XAudio2/D3D)
    return false;                                    // L_BADVT (garbage / reused-as-data)
}

} // anon

void set_off(bool v){ g_off=v?1:0; }
bool is_off(){ return g_off!=0; }
void set_container_repair(bool v){ g_cont_repair=v?1:0; }
void set_field_repair(bool v){ g_field_repair=v?1:0; }
bool container_repair_on(){ return g_cont_repair!=0; }
bool field_repair_on(){ return g_field_repair!=0; }

void run(const char* tag){
    if(g_off) return;
    g_gaps.clear();
    uintptr_t table = addr::resolve(0x140D762F0);
    if(!readable(table,8)) return;

    long objs=0, edges=0, external=0; int allocs=0;
    long total_seen=0; const long CAP_TOTAL=120000; bool capped=false;   // alloc-lists can go cyclic; bound the whole walk so a corrupt list can't freeze the game
    for(int i=0;i<TABLE_N && !capped;i++){
        uintptr_t ctrl = readable(table+(uintptr_t)i*8,8) ? *(uintptr_t*)(table+(uintptr_t)i*8) : 0;
        if(!ctrl || !readable(ctrl,0x650)) continue;
        int ncls = *(int*)(ctrl+0x648); if(ncls<1||ncls>8) ncls=8;
        bool any=false;
        for(int k=0;k<ncls;k++){
            uintptr_t mgr = ctrl + 0xd8 + (uintptr_t)k*0xa8;
            if(!readable(mgr+0x40,8)) continue;
            uintptr_t node = *(uintptr_t*)(mgr+0x40);   // alloc-list head (block)
            int walked=0;
            while(node && walked<HOP_CAP){
                if(++total_seen > CAP_TOTAL){ capped=true; break; }   // global bound: corrupt/cyclic lists => stop, don't freeze
                if(!readable(node,0x58)) break;          // torn alloc-list
                any=true;
                uintptr_t obj = node + 0x50;             // user object (vtable at +0)
                uintptr_t vt  = *(uintptr_t*)obj;
                uint64_t ida  = to_ida(vt);
                int ti = ida ? tg_lookup(ida) : -1;
                if(ti>=0){
                    objs++;
                    const TgType& T=TG_TYPES[ti];
                    for(uint16_t s=0;s<T.nptr;s++){
                        uint32_t off=TG_PTROFF[T.ptr_base+s];
                        if(off & 7) continue;   // skip unaligned slots — reflect_fieldmap mis-marks packed scalars/floats as ptr (false positives, e.g. uBtGaugeLife +0x1A/+0x23/+0x26)
                        if(!readable(obj+off,8)) continue;
                        uintptr_t tgt=*(uintptr_t*)(obj+off);
                        if(!tgt) continue;
                        edges++;
                        if(!canon(tgt) || !readable(tgt,8)){ bump(ida,off,L_DEAD,obj,tgt,T.name); continue; }
                        uintptr_t tvt=*(uintptr_t*)tgt;
                        if(tvt==0){ bump(ida,off,L_ZEROED,obj,tgt,T.name); continue; }
                        if(to_ida(tvt)) continue;        // umvc3 module vtable => valid object
                        if(in_module_image(tvt)){ external++; continue; }   // another module (COM/XAudio2/D3D) => EXTERNAL, ok
                        bump(ida,off,L_BADVT,obj,tgt,T.name);                // not any module's vtable => garbage/type-confusion
                    }
                }
                node = *(uintptr_t*)(node+0x20);          // next block
                walked++;
            }
            if(capped) break;
        }
        if(any){ allocs++; }
    }

    std::sort(g_gaps.begin(),g_gaps.end(),[](const Gap&a,const Gap&b){ return a.count>b.count; });
    int total_viol=0; for(auto&g:g_gaps) total_viol+=g.count;

    bool was=rblog::is_suppressed(); rblog::suppress(false);
    rblog::write("==== COHERENCE-AUDIT[%s]: %ld objs, %ld edges across %d allocators | VIOLATIONS=%d in %d gaps | external_edges=%ld%s ====",
                 tag, objs, edges, allocs, total_viol, (int)g_gaps.size(), external,
                 capped ? "  [CAPPED: alloc-lists CORRUPT/cyclic — walk bounded]" : "");
    int shown=0;
    for(auto&g:g_gaps){ if(shown++>=40) break;
        rblog::write("COH-GAP x%-4d %-28s +0x%-4X %-30s ex_obj=0x%llX -> 0x%llX",
            g.count, g.name?g.name:"?", g.off, LAW_NAME[g.law],
            (unsigned long long)g.ex_obj, (unsigned long long)g.ex_tgt);
    }
    rblog::write("==== COHERENCE-AUDIT[%s]: end (gaps shown %d/%d) ====", tag, shown, (int)g_gaps.size());
    rblog::suppress(was);
}

// container lookup (small table; linear)
static int cont_lookup(uint64_t ida){
    for(int i=0;i<N_CONT;i++) if(CONTAINERS[i].hvt==ida) return i;
    return -1;
}

// repair one container's child-array: NULL any child with an invalid vtable. Returns #children nulled, or -1 if
// the container looks freed/garbage (caller drops it from the registry). Pure on the child slots (arena ptrs).
static int repair_container(uintptr_t obj, const ContDesc& C){
    if(!readable(obj,8)) return -1;
    if(to_ida(*(uintptr_t*)obj)!=C.hvt) return -1;                  // vtable no longer matches => freed/reused
    if(!readable(obj+C.gate_off,8) || !*(uintptr_t*)(obj+C.gate_off)) return 0;   // gate clear => no children iterated
    if(!readable(obj+C.arr_off,8) || !readable(obj+C.cnt_off,4)) return 0;
    uintptr_t arr = *(uintptr_t*)(obj+C.arr_off);
    uint32_t  cnt = *(uint32_t*)(obj+C.cnt_off);
    if(!arr || !cnt || cnt>=0x100000 || !readable(arr,(size_t)cnt*8)) return 0;
    int nulled=0;
    for(uint32_t e=0;e<cnt;e++){
        uintptr_t slot=arr+(uintptr_t)e*8, child=*(uintptr_t*)slot;
        if(!child) continue;
        c_cont_kids++;
        bool rd; if(!referent_valid(child,rd)){ if(g_cont_repair){ *(uintptr_t*)slot=0; nulled++; } }
    }
    return nulled;
}

void init(){
    uintptr_t ctor = addr::resolve(0x1400ac1d0);                    // vt 0x140a7b2e0 installer (re_bundle CTOR)
    MH_STATUS st = MH_CreateHook((void*)ctor, (void*)&hk_ctor_a7b2e0, (void**)&orig_ctor_a7b2e0);
    rblog::write("COHERENCE-AUDIT: container ctor hook FUN_1400ac1d0 @0x%llX %s (register-by-construction enumeration)",
                 (unsigned long long)ctor, st==MH_OK?"OK":"FAILED");
}

// POSTLOAD edge repair (frozen, post-restore). CONTAINER pass iterates the ctor REGISTRY (reliable; the alloc-list
// walk capped before reaching objects) and nulls invalid children — the proven crash fix. FIELD pass (read-only
// discovery by default; nulls only if armed) walks the proven allocator registry with a PER-MANAGER cap + per-alloc
// diagnostics, so a big data allocator can't starve the entity allocators. Desync-free (arena ptrs, gp_crc-skipped).
void repair(int frame){
    if(!g_cont_repair && !g_field_repair) return;
    c_repair_calls++;
    LARGE_INTEGER fq,t0,t1; QueryPerformanceFrequency(&fq); QueryPerformanceCounter(&t0);

    // ── CONTAINER pass (registry-driven) ──
    int cont_nulled_now=0, cont_live=0, w=0;
    for(int i=0;i<g_cont_inst_n;i++){
        uintptr_t obj=g_cont_inst[i];
        int ci = readable(obj,8) ? cont_lookup(to_ida(*(uintptr_t*)obj)) : -1;
        int r = (ci>=0) ? repair_container(obj, CONTAINERS[ci]) : -1;
        if(r<0) continue;                                          // drop (compacted below)
        g_cont_inst[w++]=obj; cont_live++;
        if(r>0){ c_cont_nulled+=r; cont_nulled_now+=r; }
    }
    g_cont_inst_n=w;                                               // self-clean freed/reused entries
    c_cont_objs=cont_live;

    // ── FIELD pass (typegraph fixed slots; PER-MANAGER cap; discovery by default) ──
    g_gaps.clear();
    long objs=0, edges=0, external=0; int field_nulled_now=0;
    long mgr_seen_total=0;
    uintptr_t count_addr = addr::resolve(0x140D760E0), array_addr = addr::resolve(0x140D760F0);
    uint32_t nreg = readable(count_addr,4) ? *(uint32_t*)count_addr : 0; if(nreg>64) nreg=64;
    const int PER_MGR_CAP = 20000;
    for(uint32_t i=0;i<nreg;i++){
        uintptr_t ctrl = readable(array_addr+(uintptr_t)i*8,8) ? *(uintptr_t*)(array_addr+(uintptr_t)i*8) : 0;
        if(!ctrl || !readable(ctrl,0x650)) continue;
        int ncls = *(int*)(ctrl+0x648); if(ncls<1||ncls>8) ncls=8;
        for(int k=0;k<ncls;k++){
            uintptr_t mgr = ctrl + 0xd8 + (uintptr_t)k*0xa8;
            if(!readable(mgr+0x40,8)) continue;
            uintptr_t node=*(uintptr_t*)(mgr+0x40); int walked=0;
            while(node && walked<PER_MGR_CAP){                     // per-manager bound: no global starvation
                mgr_seen_total++;
                if(!readable(node,0x58)) break;
                uintptr_t obj=node+0x50; uint64_t ida=to_ida(*(uintptr_t*)obj);
                int ti = ida ? tg_lookup(ida) : -1;
                if(ti>=0){
                    objs++; const TgType& T=TG_TYPES[ti];
                    for(uint16_t s=0;s<T.nptr;s++){
                        uint32_t off=TG_PTROFF[T.ptr_base+s];
                        if(off & 7) continue;
                        if(!readable(obj+off,8)) continue;
                        uintptr_t tgt=*(uintptr_t*)(obj+off); if(!tgt) continue;
                        edges++;
                        bool rd; if(referent_valid(tgt,rd)){ if(!to_ida(*(uintptr_t*)tgt)) external++; continue; }
                        int law = !rd ? L_DEAD : (*(uintptr_t*)tgt==0 ? L_ZEROED : L_BADVT);
                        bump(ida,off,law,obj,tgt,T.name);
                        if(g_field_repair){ *(uintptr_t*)(obj+off)=0; c_field_nulled++; field_nulled_now++; }
                    }
                }
                node=*(uintptr_t*)(node+0x20); walked++;
            }
        }
    }
    QueryPerformanceCounter(&t1);
    double ms = (double)(t1.QuadPart-t0.QuadPart)*1000.0/(double)fq.QuadPart;

    std::sort(g_gaps.begin(),g_gaps.end(),[](const Gap&a,const Gap&b){ return a.count>b.count; });
    int total_viol=0; for(auto&g:g_gaps) total_viol+=g.count;
    bool was=rblog::is_suppressed(); rblog::suppress(false);
    rblog::write("==== COH-REPAIR[f%d %.1fms]: cont(live=%d kids=%lld nulled_now=%d) field(objs=%ld edges=%ld nulled_now=%d viol=%d gaps=%d) blocks=%ld ext=%ld | lifetime cont_nulled=%lld field_nulled=%lld calls=%lld ====",
                 frame, ms, cont_live, (long long)c_cont_kids, cont_nulled_now,
                 objs, edges, field_nulled_now, total_viol, (int)g_gaps.size(), mgr_seen_total, external,
                 (long long)c_cont_nulled, (long long)c_field_nulled, (long long)c_repair_calls);
    int shown=0;
    for(auto&g:g_gaps){ if(shown++>=40) break;
        rblog::write("COH-GAP x%-4d %-28s +0x%-4X %-30s ex_obj=0x%llX -> 0x%llX",
            g.count, g.name?g.name:"?", g.off, LAW_NAME[g.law],
            (unsigned long long)g.ex_obj, (unsigned long long)g.ex_tgt);
    }
    rblog::suppress(was);
}

} // namespace coherence_audit
