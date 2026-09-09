// rdspine.cpp — see rdspine.h. SHADOW-only identity spine for the "Default" allocator (DAT_140d76540). Twin of
// idspine.cpp but keyed on the USER pointer the malloc-wrapper returns (FUN_1404C9460), retired at FUN_1404C9A00.
// Zero game-memory writes: the table is this DLL's .bss, the serial is ours. Pure measurement.
#include "rdspine.h"
#include "free_probe.h"
#include "quarantine.h"
#include "addr.h"
#include "arena.h"
#include "resim.h"
#include "log.h"
#include <MinHook.h>
#include <windows.h>
#include <intrin.h>
#include <cstdint>

namespace rdspine {

namespace {
// IDA chokepoints (verified vs binary): alloc = malloc-wrapper (raw@user-0x10, size@user-8), free = free-wrapper.
static constexpr uintptr_t DMALLOC_IDA = 0x1404C9460ull;
static constexpr uintptr_t DFREE_IDA   = 0x1404C9A00ull;
static constexpr int      FRAME_NEVER  = 0x7FFFFFFF;
static constexpr uint32_t CAP_BITS = 19;            // 512K slots (Default alloc is higher-frequency than MtScalable)
static constexpr uint32_t CAP = 1u << CAP_BITS;
static constexpr int      MAXPROBE = 96;

// size: the Default block's requested extent (the int64 size arg must reach put). Property-4 REVERT/
// RESURRECT needs it to copy the right byte range. last_load: per-load dedup stamp for the Phase-4a walk (INERT here).
struct Slot { volatile LONG64 user; volatile LONG64 serial; volatile LONG live; volatile LONG birth; volatile LONG death; volatile LONG in_arena; volatile LONG size; volatile LONG last_load; };
static Slot g_tab[CAP];
static volatile LONG64 g_ctr = 0;
static volatile LONG64 g_births=0, g_reuses=0, g_deaths=0, g_live=0, g_full=0, g_distinct=0, g_in_arena=0, g_crt=0;
// Size oracle: confirm the size plumbing actually populates. g_size_zero must stay 0 (every Default block has a
// known extent for the Property-4 walk); g_size_max is the largest block seen (sanity that real sizes flow through).
static volatile LONG64 g_size_zero=0, g_size_max=0;

typedef uint64_t (*dmalloc_fn)(int64_t, int64_t, uint64_t);
typedef void     (*dfree_fn)(int64_t, int64_t);
static dmalloc_fn orig_dmalloc = nullptr;
static dfree_fn   orig_dfree   = nullptr;
static volatile LONG g_record = 1;   // record from boot (the crashing block may be alloc'd early); watch g_full

static inline uint32_t hashk(uintptr_t u){ uint64_t x=(uint64_t)u>>4; x^=x>>33; x*=0xff51afd7ed558ccdULL; x^=x>>33; return (uint32_t)x & (CAP-1); }

static void put(uintptr_t user, uint32_t size){
    if(!size) _InterlockedIncrement64(&g_size_zero);            // size oracle: a 0-size record = a gap for the walk
    if((LONG64)size > g_size_max) g_size_max = size;            // racy max — diagnostic only
    int ina = arena::is_arena_addr(user) ? 1 : 0;
    uint32_t h = hashk(user);
    for(int i=0;i<MAXPROBE;i++){
        uint32_t s=(h+(uint32_t)i)&(CAP-1);
        LONG64 cur=g_tab[s].user;
        if(cur==(LONG64)user){                                   // known user addr handed back out: new serial (reuse)
            g_tab[s].serial=_InterlockedIncrement64(&g_ctr);
            g_tab[s].birth=resim::effective_frame(); g_tab[s].death=FRAME_NEVER; g_tab[s].in_arena=ina;
            g_tab[s].size=(LONG)size;                            // refresh: a recycled addr may carry a new size class
            LONG prev=_InterlockedExchange(&g_tab[s].live,1);
            _InterlockedIncrement64(&g_reuses);
            if(!prev) _InterlockedIncrement64(&g_live);
            return;
        }
        if(cur==0){
            if(_InterlockedCompareExchange64(&g_tab[s].user,(LONG64)user,0)==0){
                g_tab[s].serial=_InterlockedIncrement64(&g_ctr);
                g_tab[s].birth=resim::effective_frame(); g_tab[s].death=FRAME_NEVER; g_tab[s].in_arena=ina; g_tab[s].size=(LONG)size; g_tab[s].live=1;
                _InterlockedIncrement64(&g_births); _InterlockedIncrement64(&g_live); _InterlockedIncrement64(&g_distinct);
                _InterlockedIncrement64(ina ? &g_in_arena : &g_crt);   // the desync gate: in-arena vs CRT split
                return;
            }
            if(g_tab[s].user==(LONG64)user){ i--; continue; }
        }
    }
    _InterlockedIncrement64(&g_full);
}
static void retire(uintptr_t user){
    uint32_t h=hashk(user);
    for(int i=0;i<MAXPROBE;i++){
        uint32_t s=(h+(uint32_t)i)&(CAP-1);
        LONG64 cur=g_tab[s].user;
        if(cur==(LONG64)user){
            g_tab[s].death=resim::effective_frame();
            LONG prev=_InterlockedExchange(&g_tab[s].live,0);
            if(prev){ _InterlockedIncrement64(&g_deaths); _InterlockedDecrement64(&g_live); }
            return;
        }
        if(cur==0) return;
    }
}

static inline bool record_on(){ return g_record || resim::engine_enabled(); }

// STAGE B (default ON): route Default malloc into the in-arena heap zone so Default blocks get byte-reverted by
// arena::load — the REVERT half the CRT heap couldn't give (fixes alive-at-N Default crashes: projectiles/materials/
// colliders). Gated on engine_enabled (only redirect while rollback is armed) + align<=0x10 (all observed callsites;
// the zone gives 16-aligned blocks). On zone overflow, heap_zone_alloc_default returns NULL => fall back to CRT
// (counter bumped). A/B via stage_b.flag (presence = OFF).
static volatile long g_stage_b = 1;

static uint64_t hk_dmalloc(int64_t ctrl, int64_t size, uint64_t align){
    if (g_stage_b && resim::engine_enabled() && size > 0 && align > 0 && align <= 0x10) {
        void* z = arena::heap_zone_alloc_default((size_t)size);
        if (z) { if(record_on()) put((uintptr_t)z, (uint32_t)size);
                 quarantine::drop_default_husk((uintptr_t)z);   // this address is a LIVE object again
                 return (uint64_t)(uintptr_t)z; }
        // zone overflow => fall through to CRT (arena bumped g_stage_b_crt_fallback)
    }
    uint64_t r = orig_dmalloc(ctrl, size, align);
    if(record_on() && r > 0x10000) { put((uintptr_t)r, (uint32_t)size); quarantine::drop_default_husk((uintptr_t)r); }
    return r;
}
static void hk_dfree(int64_t ctrl, int64_t user){
    free_probe::Scope _fps;   // free_probe: per-free cost discriminator
    // death stamp (liveness by timeline): a Default/heap-zone object's dtor ran => it is a husk. The FUN_1404cb350
    // husk set (quarantine::on_free) is structurally blind to Default frees, so stamp the death here with its frame
    // => the sweep sees it and it is rolled back on rollback (prune_default_husks drops deaths after the restored frame).
    // Zone case: memory persists (byte-reverted), but the dtor still ran => still a husk. CRT case: really freed.
    // DEFAULT-DEFER REMOVED: its own counter refuted it (calls=3 vs 42 deaths/s — the leaf frees do not
    // route through this chokepoint; the reuse is diffuse, no single free to defer). Reverted to the death-stamp only.
    if (resim::engine_enabled() && user > 0x10000)
        quarantine::note_default_husk((uintptr_t)user, resim::effective_frame());
    if (g_stage_b && arena::in_heap_zone((uintptr_t)user)) return;   // zone: never CRT-freed (byte-reverted)
    if(record_on() && user > 0x10000) retire((uintptr_t)user);
    orig_dfree(ctrl, user);
}

} // anon

void init(){
    void* a = (void*)addr::resolve(DMALLOC_IDA);
    void* f = (void*)addr::resolve(DFREE_IDA);
    MH_STATUS sa = MH_CreateHook(a, (void*)&hk_dmalloc, (void**)&orig_dmalloc);
    MH_STATUS sf = MH_CreateHook(f, (void*)&hk_dfree,   (void**)&orig_dfree);
    rblog::write("RDSPINE: hook Default alloc FUN_1404C9460@0x%llX %s + free FUN_1404C9A00@0x%llX %s (SHADOW, %u slots)",
                 (unsigned long long)(uintptr_t)a, sa==MH_OK?"OK":"FAIL",
                 (unsigned long long)(uintptr_t)f, sf==MH_OK?"OK":"FAIL", CAP);
}

bool lookup(uintptr_t user, int* birth, int* death, int64_t* serial, int* in_arena, int* size){
    uint32_t h=hashk(user);
    for(int i=0;i<MAXPROBE;i++){
        uint32_t s=(h+(uint32_t)i)&(CAP-1);
        LONG64 cur=g_tab[s].user;
        if(cur==(LONG64)user){ if(birth)*birth=g_tab[s].birth; if(death)*death=g_tab[s].death;
            if(serial)*serial=g_tab[s].serial; if(in_arena)*in_arena=g_tab[s].in_arena; if(size)*size=g_tab[s].size; return true; }
        if(cur==0) return false;
    }
    return false;
}

void set_stage_b(bool on) { g_stage_b = on ? 1 : 0; }   // STAGE B A/B (public; g_stage_b is the anon-ns global)

void report(){
    bool w=rblog::is_suppressed(); rblog::suppress(false);
    rblog::write("RDSPINE: distinct=%lld births=%lld reuses=%lld deaths=%lld live=%lld full=%lld | IN-ARENA=%lld CRT=%lld (the desync gate: CRT-in-hashed-range = unfixable by keep-alive)",
                 (long long)g_distinct,(long long)g_births,(long long)g_reuses,(long long)g_deaths,
                 (long long)g_live,(long long)g_full,(long long)g_in_arena,(long long)g_crt);
    // Map-completeness oracle: size_zero must be 0 (every Default block has a known extent for Property-4);
    // size_max sanity-checks that real sizes flow. g_full must stay 0 (table pressure would drop map entries).
    rblog::write("RDSPINE-SIZE: size_zero=%lld size_max=%lld (size_zero==0 => extent map complete for the object walk)",
                 (long long)g_size_zero,(long long)g_size_max);
    // STAGE B telemetry (long-run gate): zone occupancy (MB) + CRT-fallback count. fallback should stay 0/low; rising
    // occupancy toward 255MB => the non-recycling bump is filling => the recycling follow-on is needed.
    rblog::write("STAGE-B: enabled=%ld zone_occupancy=%lldMB crt_fallback=%lld (fallback>0 => zone overflow, Default reverted to unprotected CRT)",
                 g_stage_b, (long long)(arena::get_heap_zone_offset() >> 20), (long long)arena::stage_b_crt_fallback());
    rblog::suppress(w);
}

} // namespace rdspine
