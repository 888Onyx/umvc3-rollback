// coherent_set_repair.cpp — see header. Catalog-driven POSTLOAD coherent-set repairer.
#include "coherent_set_repair.h"
#include "addr.h"
#include "arena.h"
#include "idspine.h"
#include "rdspine.h"
#include "log.h"
#include <windows.h>
#include <cstdint>

namespace coherent_set_repair {

namespace {

// ── enums (the catalog's design) ────────────────────────────────────────────────────────────────────────
enum Enum  { ENUM_SUNIT, ENUM_SINGLETON, ENUM_FIGHTER };  // ENUM_FIGHTER: sUnit lines 7-8, bone_count filter (1..300)
enum Kind  { K_NULL_INVALID, K_CLEAR_GROUP, K_NULL_RDSPINE };  // K_NULL_RDSPINE: fixed scalar ptr via rdspine ALIVE_AT_N

// A descriptor row. ARRAY rows use {gate_off, arr_off, cnt_off}; CLEAR_GROUP rows use {gate_off, group[]}.
struct Desc {
    const char* id;
    Enum        how;
    uint64_t    holder_vt[3];     // sUnit filter (up to 3 vtables, IDA); singleton: holder_vt[0] unused
    uint64_t    singleton_ida;    // ENUM_SINGLETON: PTR slot holding the instance
    uint32_t    gate_off;         // 0 = no gate; else only act when *(holder+gate)!=0
    uint32_t    arr_off, cnt_off, stride;   // K_NULL_INVALID
    uint32_t    group[8]; uint8_t group_n;  // K_CLEAR_GROUP (zero these qwords)
    Kind        kind;
    uint8_t     proven;           // 1 = confirmed-death + verified (ships in "proven" scope)
    volatile long enabled;        // per-row gate
};

// ── the CATALOG (verified rows; only proven row #1 enabled by default) ───────────────────────────────────
// Offsets cross-checked against the decomp; CLEAR_GROUP/singleton rows stay disabled until each is verified on a long run.
static Desc g_cat[] = {
  // #1 entity_child_array — FUN_140564110 ticks child_vtable+0x38 per slot; null any slot whose object vtable is
  // invalid. The walk guards if(child!=0) so a nulled slot is skipped. ENUM via sUnit (the failed ctor hook is
  // retired). Confirmed dead on an earlier run. arena ptrs => desync-free.
  // DISABLED: 0x140a7b2e0 = uMorrigan, a uCharacter FIGHTER (audio_typegraph.inc:146, size 0x6900),
  // and FIGHTER_SEGS {0x100,0x130} (gp_crc.cpp:54) covers +0x110/+0x118 => this holder is gp_crc-hashed gameplay state.
  // Nulling its child-array buffer is UNPROVEN desync-safe (and it's been a no-op: nulled=0 every long run). FUN_140564110's
  // real carriers are also a different vtable set (holder-identity contradiction). Keep OFF until the
  // child-buffer is proven outside compute_fighter_segs/anim/bone walks.
  { "entity_child_array", ENUM_SUNIT, {0x140a7b2e0ull,0,0}, 0, 0x100, 0x110, 0x118, 8, {0},0, K_NULL_INVALID, 1, 0 },

  // #4 effect_bone_array — CLEAR {+0x208,+0x210,+0x220,+0x228}; engine re-derives on first tick (FUN_1405e0950).
  { "effect_bone_array", ENUM_SUNIT, {0x140bae1d0ull,0x140bb8e00ull,0x140bb9170ull}, 0, 0,0,0,0,
    {0x208,0x210,0x220,0x228},4, K_CLEAR_GROUP, 0, 0 },

  // #5 entity_holder_slot9 — null child-array slots (walk skips nulls); FUN_140561ce0 rebuilds from gate next tick.
  { "entity_holder_slot9", ENUM_SUNIT, {0x140b21ff0ull,0,0}, 0x100, 0x110, 0x118, 8, {0},0, K_NULL_INVALID, 0, 0 },

  // #9 uBaseModel_child_array — zero gate +0x100 so the walk exits; FUN_140561ce0 re-derives next tick.
  { "uBaseModel_child_array", ENUM_SUNIT, {0x140baa4a0ull,0,0}, 0, 0,0,0,0, {0x100},1, K_CLEAR_GROUP, 0, 0 },

  // #10 uSoftBody_child_array — null slots with non-module *slot. NEED_MORE_RE (pool identity) => disabled.
  { "uSoftBody_child_array", ENUM_SUNIT, {0x140bbb5a0ull,0,0}, 0x100, 0x110, 0x118, 8, {0},0, K_NULL_INVALID, 0, 0 },

  // #11 fighter_mplastcreateshot — uFighter+0x6428 = mpLastCreateShot (Default-malloc uShot* family).
  // Rollback rewinds arena to N; the restored shot ptr may reference a freed Default-alloc block (not
  // reverted by arena::load). rdspine (FUN_1404C9460/9A00 shadow) tracks current liveness. If the block
  // is dead (death!=RDSPINE_FRAME_NEVER, i.e. rdspine live==0) → null the field (crash prevention).
  // ENUM_FIGHTER: sUnit lines 7-8, bone_count filter (1..300) — matches gp_crc.cpp compute_fighter_segs
  // (the confirmed fighter walk; character vtables are 30+ derived types, not filterable by holder_vt[3]).
  // arr_off=0x6428 encodes scalar_off for K_NULL_RDSPINE. Desync-safe: +0x6428 is in gap 0x63FC..0x67C
  // (gp_crc.cpp confirms the last FIGHTER_SEGS ends 0x63FC, next starts 0x67C); getter FUN_14005ff30
  // is null-guarded at all 12+ call sites. gp_crc delta = zero.
  { "fighter_mplastcreateshot", ENUM_FIGHTER, {0,0,0}, 0, 0,
    0x6428/*scalar_off*/,0,8, {0},0, K_NULL_RDSPINE, 1, 1 },
};
static const int N_CAT = (int)(sizeof(g_cat)/sizeof(g_cat[0]));

static volatile long g_master = 1;     // master gate (ON)
static volatile long g_scope  = 1;     // 0 OFF, 1 proven-only, 2 all-enabled-rows
static int64_t c_runs=0, c_holders=0, c_nulled=0, c_cleared=0;
static int g_repair_N = 0;            // rollback_target (set at start of run(); available to future kernels needing N)

static inline bool canon(uintptr_t p){ return p>=0x10000 && p<0x7FFFFFFFFFFFull; }
static bool readable(uintptr_t p, size_t n){
    if(!p||n==0) return false;
    if(arena::is_arena_addr(p) && arena::is_arena_addr(p+n-1))
        return arena::is_committed_addr(p) && arena::is_committed_addr(p+n-1);
    MEMORY_BASIC_INFORMATION mbi;
    if(!VirtualQuery((void*)p,&mbi,sizeof(mbi))) return false;
    if(mbi.State!=MEM_COMMIT) return false;
    if(mbi.Protect & (PAGE_NOACCESS|PAGE_GUARD)) return false;
    return p+n <= (uintptr_t)mbi.BaseAddress+mbi.RegionSize;
}
static inline uint64_t to_ida(uintptr_t vt){
    if(vt < addr::g_base) return 0;
    uint64_t ida=(uint64_t)vt-addr::g_base+0x140000000ull;
    return (ida>=0x140000000ull && ida<0x141000000ull) ? ida : 0;
}
static bool in_module(uintptr_t p){ MEMORY_BASIC_INFORMATION mbi; return VirtualQuery((void*)p,&mbi,sizeof(mbi)) && mbi.State==MEM_COMMIT && mbi.Type==MEM_IMAGE; }
// a referent is valid iff its first qword is a umvc3 module vtable OR another loaded module's vtable
static bool referent_valid(uintptr_t tgt){
    if(!canon(tgt) || !readable(tgt,8)) return false;
    uintptr_t tvt=*(uintptr_t*)tgt;
    if(tvt==0) return false;
    return to_ida(tvt)!=0 || in_module(tvt);
}

// ── kernels ──────────────────────────────────────────────────────────────────────────────────────────────
static int k_null_invalid(uintptr_t holder, const Desc& d){
    if(d.gate_off && (!readable(holder+d.gate_off,8) || !*(uintptr_t*)(holder+d.gate_off))) return 0;
    if(!readable(holder+d.arr_off,8) || !readable(holder+d.cnt_off,4)) return 0;
    uintptr_t arr=*(uintptr_t*)(holder+d.arr_off); uint32_t cnt=*(uint32_t*)(holder+d.cnt_off);
    if(!arr||!cnt||cnt>=0x100000||!readable(arr,(size_t)cnt*d.stride)) return 0;
    int n=0;
    for(uint32_t e=0;e<cnt;e++){ uintptr_t slot=arr+(uintptr_t)e*d.stride, child=*(uintptr_t*)slot;
        if(child && !referent_valid(child)){ *(uintptr_t*)slot=0; n++; } }
    return n;
}
static int k_clear_group(uintptr_t holder, const Desc& d){
    int n=0;
    for(uint8_t g=0;g<d.group_n;g++){ uintptr_t a=holder+d.group[g];
        if(readable(a,8) && *(uintptr_t*)a){ *(uintptr_t*)a=0; n++; } }
    return n;
}
// K_NULL_RDSPINE: fixed scalar pointer, current-liveness check via rdspine. arr_off reused as scalar_off.
// Correct check for Default-malloc referents (not reverted by arena::load): the memory is valid IFF the
// block is currently live (death==RDSPINE_FRAME_NEVER). ALIVE_AT_N (birth<=N<death) would be wrong here:
// a shot freed between N and M satisfies ALIVE_AT_N (death=D, N<D) but its memory IS freed → crash.
// Rule: "if dead (live==0) null the field" — live==0 ≡ death!=RDSPINE_FRAME_NEVER.
// Slab-reuse (new shot at same addr, birth>N, currently live): kept conservatively (no crash; getter
// null-guards; field not in gp_crc; serial comparison needs a saved-at-save-time serial we don't have).
static constexpr int RDSPINE_FRAME_NEVER = 0x7FFFFFFF;
static int k_null_rdspine(uintptr_t holder, const Desc& d){
    uint32_t off = d.arr_off;    // arr_off encodes scalar_off for this kind
    if(!readable(holder+off, 8)) return 0;
    uintptr_t ptr = *(uintptr_t*)(holder+off);
    if(!ptr) return 0;           // already null — nothing to do
    if(!canon(ptr)){ *(uintptr_t*)(holder+off)=0; return 1; }  // non-canonical garbage → null immediately
    int death=RDSPINE_FRAME_NEVER;
    if(!rdspine::lookup(ptr, nullptr, &death, nullptr, nullptr)) return 0;  // unknown to rdspine → keep (conservative)
    if(death == RDSPINE_FRAME_NEVER) return 0;   // currently live → keep
    *(uintptr_t*)(holder+off) = 0;               // freed (live==0 ≡ death!=never) → null
    return 1;
}

// ── RENDER PRESENT-LIST COMPACT (the recurring render-list crash) ──────────────────────────────────────────
// FUN_14053a250 walks sRender's PERSISTENT present registry (array sRender+0x8817b0,
// count +0x8897b0) and vcalls entry->vtable[+0x20], not null-guarded. The count+array are sRender-RE-DERIVE-excluded
// (kept LIVE at frame M, see dynamic_restore.cpp) but the entry OBJECTS are in-arena, reverted to frame N => post-N
// entries become garbage. Not a race (render thread OS-frozen across resim; populator FUN_140536c40 takes the same CS).
// It is a PERSISTENT registry (added at ctor FUN_140536c40, removed at dtor) so DRAIN/zero-count would permanently
// destroy live render resources -> COMPACT instead: keep only entries that are still valid objects; resim
// deterministically RE-CREATES the dropped post-N entries (their ctors re-run during replay). Desync-free: sRender is
// not in gp_crc, render is one-way output. NO CS (a frozen worker may hold sRender CS => deadlock;
// nothing runs while frozen so the CS is unnecessary). 3 GATES (gate 3 = the +0x20 slot the probe's is_obj missed,
// which is why DANGLING=0 yet rip=0 still fired).
static int64_t c_pl_runs=0, c_pl_removed=0, c_rt_removed=0, c_id_dropped=0, c_id_miss=0;
// GATE 1-3 (vtable proxy): committed object, first qword a umvc3 module vtable, and the called vtable slot non-null.
// present walk vcalls entry->vt+0x20; retirement walk releases via entry->vt+0x0.
static bool vtable_valid(uintptr_t e, uint32_t call_slot){
    if(!canon(e) || !readable(e,8) || !readable(e+8,8)) return false;          // GATE 1: committed object (e=-1/0/garbage)
    uintptr_t vt=*(uintptr_t*)e;
    if(to_ida(vt)==0) return false;                                            // GATE 2: first qword = umvc3 module vtable
    if(!readable(vt+call_slot,8) || *(uintptr_t*)(vt+call_slot)==0) return false;  // GATE 3: the called slot is non-null
    return true;
}
// GATE 4 (IDENTITY): idspine ALIVE_AT_N. The kept-live list (forward model) holds entry->A; idspine is
// not rewound by arena::load (raw memcpy, never calls FUN_1404ca650/FUN_1404cb350), so idspine.lookup(block-at-A) returns the FORWARD
// object's birth/death — the oracle for "did this object exist at the rollback target N?". An entry whose block was
// born after N (or died at/before N) is a future/dead object the revert left dangling => DROP. The vtable proxy can't
// catch this (the reverted bytes look like a valid object); only idspine's birth does. block via the same back-offset
// idspine's stamp_of_object uses (block = user - *(user-8)). Returns: 1 alive-at-N (keep), 0 not (drop), -1 unknown (keep).
// POSTLOAD only (forward model intact). At POSTRESIM idspine is re-stamped to the replayed epoch => birth filter would
// false-drop resim-born entries, so callers pass identity=false there.
static int alive_at_n(uintptr_t e, int N){
    if(!arena::is_arena_addr(e) || (e & 0xFFF) < 8 || !readable(e-8,8)) return -1;  // match idspine::stamp_of_object guards
    int64_t off=*(int64_t*)(e-8);
    if(off<=0 || off>=0x1000) return -1;                  // not an allocator back-offset => unknown => keep
    uintptr_t block=e-(uintptr_t)off;
    int birth=0, death=0; int64_t serial=0;
    if(!idspine::lookup(block,&birth,&death,&serial)){ c_id_miss++; return -1; }  // never stamped => unknown => keep
    return (birth<=N && N<death) ? 1 : 0;
}
// Compact an sRender persistent object-list {array_off,count_off}: keep only entries passing the vtable proxy and (when
// identity gate on) idspine ALIVE_AT_N. Desync-free (sRender kept-live + not in gp_crc's FIGHTER_SEGS/SINGLETONS/globals;
// arena-ptr slots skipped by crc_range_ptr_aware). resim re-creates dropped post-N entries.
static uint32_t compact_obj_list(uintptr_t sr, uint32_t arr_off, uint32_t cnt_off, uint32_t call_slot,
                                 bool identity, int N, int frame, const char* tag, int64_t* lifetime){
    uintptr_t arr=sr+arr_off, cnta=sr+cnt_off;
    if(!readable(cnta,4) || !readable(arr,8)) return 0;
    uint32_t n=*(uint32_t*)cnta;
    if(n==0 || n>0x100000 || !readable(arr,(size_t)n*8)) return 0;
    uint32_t out=0, vt_drop=0, id_drop=0;
    for(uint32_t i=0;i<n;i++){
        uintptr_t e=*(uintptr_t*)(arr+(uintptr_t)i*8);
        bool keep = vtable_valid(e,call_slot);
        if(!keep) vt_drop++;
        else if(identity && alive_at_n(e,N)==0){ keep=false; id_drop++; c_id_dropped++; }   // future/dead object dangler
        if(keep){ *(uintptr_t*)(arr+(uintptr_t)out*8)=e; out++; }
    }
    if(out!=n){
        *(uint32_t*)cnta=out; *lifetime += (n-out);
        bool w=rblog::is_suppressed(); rblog::suppress(false);
        rblog::write("%s-COMPACT[f%d N=%d]: %u -> %u (vtable_drop=%u identity_drop=%u) | lifetime removed=%lld id_dropped=%lld",
                     tag, frame, N, n, out, vt_drop, id_drop, (long long)*lifetime, (long long)c_id_dropped);
        rblog::suppress(w);
    }
    return n-out;
}
// Both sRender object-lists a rollback can leave with stale entries. PRESENT (0x8817b0/0x8897b0, vcalls +0x20) +
// RETIREMENT (0x8677b0/0x87a7b0, frees via +0x0). identity=true at POSTLOAD (idspine ALIVE_AT_N catches the
// slab-reuse/future-object danglers the vtable proxy misses); identity=false at POSTRESIM (replayed-epoch idspine).
static void compact_srender_lists(int frame, int N, bool identity){
    uintptr_t sr = readable(addr::resolve(0x140E179A8),8) ? *(uintptr_t*)addr::resolve(0x140E179A8) : 0;
    if(!sr) return;
    compact_obj_list(sr, 0x8817b0, 0x8897b0, 0x20, identity, N, frame, "PRESENT-LIST",    &c_pl_removed);
    compact_obj_list(sr, 0x8677b0, 0x87a7b0, 0x00, identity, N, frame, "RETIREMENT-LIST", &c_rt_removed);
    c_pl_runs++;
}

// ── UNIVERSAL MTLIST LINK-COHERENCE REPAIR (the dangling-reference CLASS fix) ───────────────────────────────
// The sUnit bucketed doubly-linked MtList (holder DAT_140e17698=*(0x140E17698): head +0x50+b*0x30, tail +0x58+b*0x30,
// next node+0x18, prev node+0x20, bucket count +0xc38) is ARENA-REVERTED to frame N each rollback. A node freed +
// slab-reused (or a link reverted to torn/foreign content) across the boundary leaves a predecessor's +0x18 pointing
// at garbage/impostor; the engine's render walk FUN_14051b4c0 (reached via FUN_14051b670 vt+0x48 — both read this
// singleton's +0xc38 bucket count, verified in the decompilation) tests only `next!=0`, derefs the garbage =
// the seed crash rip=0x14051B561 READ 0x4000000000005. FIX = walk each bucket before the engine and SEVER the first
// torn link, mirroring the engine's OWN unlinker FUN_14051b9f0 (node.next=0; tail[b]=node).
// DETECTOR = STRUCTURAL only (cross-peer deterministic — reads reverted-arena bytes + binary-identical module):
// next torn iff !canon(next) || !readable(next,0x28) || (readable(next+0x20,8) && *(next+0x20)!=node [broken back-link]).
// NO idspine/alive_at_n here — verification showed the birth filter is wrong on a REVERTED list (it false-drops
// live pre-N nodes resim cannot recreate) and desync-UNSAFE (idspine is a forward, non-rolled-back.bss shadow whose
// keep/drop verdicts diverge per-peer with the mispredicted timeline). alive_at_n is sound only for the kept-live
// sRender arrays (compact_obj_list). SKIP fighter lines 7-8 (gp_crc-authoritative gameplay; run_fighter_rows owns them).
// Structural-only severing is desync-safe on the rest (both peers compute the identical post-repair topology). Runs at
// POSTLOAD + POSTRESIM (structural gates valid at both). Cap 64 (ctor FUN_14051a1f0 builds exactly 64 inline sentinels).
static int64_t c_link_runs=0, c_link_severed=0, c_head_cleared=0;
static volatile long g_link_repair = 1;   // the dangling-reference class fix; ON (structural-only => desync-safe)

static inline bool link_torn(uintptr_t next, uintptr_t node){
    if(!canon(next)) return true;                                            // non-canonical garbage (the seed)
    if(!readable(next,0x28)) return true;                                    // unmapped / decommitted
    if(readable(next+0x20,8) && *(uintptr_t*)(next+0x20)!=node) return true; // broken reciprocal back-link (impostor/stale)
    return false;
}
static void repair_sunit_mtlist_links(int frame){
    if(!g_link_repair) return;
    uintptr_t holder = readable(addr::resolve(0x140E17698),8) ? *(uintptr_t*)addr::resolve(0x140E17698) : 0;
    if(!holder || !readable(holder+0xc38,4)) return;
    uint32_t nlines=*(uint32_t*)(holder+0xc38); if(nlines>128) nlines=128;   // physical max = 128 (was 64 — the 0x14051BF71 door: ctor builds two 64-iter sentinel loops; unit_remove computes bucket=(flags>>3)&0x7F = 128-way; every sibling walker (run_sunit_rows/material_guard/gp_crc) uses 128. A revert-torn link in lines 64-127 sat in the sever's blind half — the odd scalar 0xF4FF9 at node+0x18 would have been severed by the EXISTING readable() predicate had the line been walked.)
    c_link_runs++;
    int64_t severed_this=0;
    for(uint32_t line=0; line<nlines; line++){
        if(line==7 || line==8) continue;                                     // fighter lines = gp_crc gameplay; skip
        uintptr_t headslot=holder+0x50+(uintptr_t)line*0x30, tailslot=holder+0x58+(uintptr_t)line*0x30;
        if(!readable(headslot,8)) continue;
        uintptr_t head=*(uintptr_t*)headslot;
        if(head==0) continue;
        if(!canon(head) || !readable(head,0x28)){                            // head itself torn => empty the bucket
            *(uintptr_t*)headslot=0; if(readable(tailslot,8)) *(uintptr_t*)tailslot=0;
            c_head_cleared++; severed_this++; continue;
        }
        uintptr_t node=head; int guard=0;
        while(guard++<4096){
            if(!readable(node+0x18,8)) break;                                // link slot unreadable => node is last
            uintptr_t next=*(uintptr_t*)(node+0x18);
            if(next==0) break;                                               // clean terminator
            if(link_torn(next,node)){
                *(uintptr_t*)(node+0x18)=0;                                  // sever (engine unlinker semantics)
                if(readable(tailslot,8)) *(uintptr_t*)tailslot=node;         // re-anchor tail to new last node
                c_link_severed++; severed_this++;
                { bool w=rblog::is_suppressed(); rblog::suppress(false);      // per-line attribution (confirms the previously-unwalked 64-127 half)
                  rblog::write("MTLIST-LINK-SEVER: line=%u next=0x%llX node=0x%llX (line>=64 = the previously-blind half)", line, (unsigned long long)next, (unsigned long long)node);
                  rblog::suppress(w); }
                break;
            }
            node=next;                                                       // validated node => safe to advance
        }
    }
    if(severed_this){
        bool w=rblog::is_suppressed(); rblog::suppress(false);
        rblog::write("MTLIST-LINK-REPAIR[f%d]: severed %lld this pass | total severed=%lld head_cleared=%lld runs=%lld",
                     frame, (long long)severed_this, (long long)c_link_severed, (long long)c_head_cleared, (long long)c_link_runs);
        rblog::suppress(w);
    }
}

// ── enumerators ──────────────────────────────────────────────────────────────────────────────────────────
static void apply(uintptr_t holder, const Desc& d){
    c_holders++;
    if(d.kind==K_NULL_INVALID)   c_nulled  += k_null_invalid(holder,d);
    else if(d.kind==K_NULL_RDSPINE) c_nulled += k_null_rdspine(holder,d);
    else                         c_cleared += k_clear_group(holder,d);
}
// sUnit scheduler-line walk (the verified enumeration: head sUnit+0x50+line*0x30, next node+0x18). For each row,
// match the entity vtable. One walk handles all sUnit rows.
static void run_sunit_rows(){
    uintptr_t sunit = readable(addr::resolve(0x140E17698),8) ? *(uintptr_t*)addr::resolve(0x140E17698) : 0;
    if(!sunit || !readable(sunit+0xc38,4)) return;
    uint32_t nlines=*(uint32_t*)(sunit+0xc38); if(nlines>128) nlines=128;
    for(uint32_t line=0; line<nlines; line++){
        uintptr_t node = readable(sunit+0x50+(uintptr_t)line*0x30,8) ? *(uintptr_t*)(sunit+0x50+(uintptr_t)line*0x30) : 0;
        int guard=0;
        while(canon(node) && readable(node,8) && guard++<4096){
            uint64_t ida=to_ida(*(uintptr_t*)node);
            if(ida){
                for(int r=0;r<N_CAT;r++){ const Desc& d=g_cat[r];
                    if(d.how!=ENUM_SUNIT || !d.enabled) continue;
                    if(g_scope==1 && !d.proven) continue;
                    if(ida==d.holder_vt[0] || (d.holder_vt[1]&&ida==d.holder_vt[1]) || (d.holder_vt[2]&&ida==d.holder_vt[2]))
                        apply(node,d);
                }
            }
            if(!readable(node+0x18,8)) break;
            node=*(uintptr_t*)(node+0x18);
        }
    }
}

// ENUM_FIGHTER walker: sUnit lines 7-8, TAIL(+0x50)+FORWARD(+0x18), bone_count(+0x530) filter 1..300.
// Mirrors compute_fighter_segs (gp_crc.cpp:201-216) — the confirmed fighter enumeration. Bone-count
// filter is used instead of vtable because all 30+ character types have distinct derived vtables
// (uFighter 0x140a6f100 is the BASE ctor vtable, never the live vtable of a scheduled entity).
// Max guard=16 matches gp_crc's walk<16 cap (3v3 game; ≤9 fighters live at once).
static void run_fighter_rows(){
    uintptr_t sunit = readable(addr::resolve(0x140E17698),8) ? *(uintptr_t*)addr::resolve(0x140E17698) : 0;
    if(!sunit || !readable(sunit+0xc38,4)) return;
    uint32_t nlines=*(uint32_t*)(sunit+0xc38); if(nlines>128) nlines=128;
    for(uint32_t line=7; line<=8 && line<nlines; line++){
        uintptr_t node = readable(sunit+0x50+(uintptr_t)line*0x30,8) ? *(uintptr_t*)(sunit+0x50+(uintptr_t)line*0x30) : 0;
        int guard=0;
        while(canon(node) && readable(node,8) && guard++<16){
            if(readable(node+0x530,4)){
                uint32_t bc = *(uint32_t*)(node+0x530);
                if(bc>=1 && bc<=300){
                    for(int r=0;r<N_CAT;r++){ const Desc& d=g_cat[r];
                        if(d.how!=ENUM_FIGHTER || !d.enabled) continue;
                        if(g_scope==1 && !d.proven) continue;
                        apply(node,d);
                    }
                }
            }
            if(!readable(node+0x18,8)) break;
            node=*(uintptr_t*)(node+0x18);
        }
    }
}

} // anon

void set_enabled(bool v){ g_master=v?1:0; }
bool is_enabled(){ return g_master!=0; }
void cycle_scope(){ g_scope=(g_scope+1)%3; }

void run_structural(int frame, int rollback_target, bool identity){
    if(!g_master) return;
    g_repair_N = rollback_target;
    c_runs++;
    LARGE_INTEGER fq,t0,t1; QueryPerformanceFrequency(&fq); QueryPerformanceCounter(&t0);
    compact_srender_lists(frame, rollback_target, identity);  // present+retirement compact + ALIVE_AT_N (POSTLOAD)
    repair_sunit_mtlist_links(frame);   // the dangling-reference CLASS fix: sever torn sUnit MtList links (structural, desync-safe, both timings)
    QueryPerformanceCounter(&t1);
    double ms=(double)(t1.QuadPart-t0.QuadPart)*1000.0/(double)fq.QuadPart;
    static int t=0;
    if((++t % 20)==0 || c_nulled || c_pl_removed || c_rt_removed || c_link_severed || c_head_cleared){
        bool w=rblog::is_suppressed(); rblog::suppress(false);
        rblog::write("==== CS-STRUCTURAL[f%d %.2fms id=%d N=%d]: present_rm=%lld retire_rm=%lld link_severed=%lld head_cleared=%lld ====",
                     frame, ms, identity?1:0, rollback_target,
                     (long long)c_pl_removed, (long long)c_rt_removed, (long long)c_link_severed, (long long)c_head_cleared);
        rblog::suppress(w);
    }
}

void run(int frame, int rollback_target, bool identity){
    if(!g_master) return;
    g_repair_N = rollback_target;
    LARGE_INTEGER fq,t0,t1; QueryPerformanceFrequency(&fq); QueryPerformanceCounter(&t0);
    (void)identity;
    if(g_scope!=0) run_sunit_rows();    // ENUM_SUNIT rows (staged)
    if(g_scope!=0) run_fighter_rows();  // ENUM_FIGHTER rows (lines 7-8, bone_count filter)
    QueryPerformanceCounter(&t1);
    double ms=(double)(t1.QuadPart-t0.QuadPart)*1000.0/(double)fq.QuadPart;
    static int t=0;
    if((++t % 20)==0 || c_nulled || c_cleared || c_link_severed || c_head_cleared){   // heartbeat (confirms the pass runs even with 0 removals)
        bool w=rblog::is_suppressed(); rblog::suppress(false);
        rblog::write("==== CS-REPAIR[f%d %.2fms scope=%ld id=%d N=%d]: holders=%lld nulled=%lld | present_rm=%lld retire_rm=%lld id_dropped=%lld id_miss=%lld | link_severed=%lld head_cleared=%lld ====",
                     frame, ms, g_scope, identity?1:0, rollback_target, (long long)c_holders, (long long)c_nulled,
                     (long long)c_pl_removed, (long long)c_rt_removed, (long long)c_id_dropped, (long long)c_id_miss,
                     (long long)c_link_severed, (long long)c_head_cleared);
        rblog::suppress(w);
    }
}

void report(){
    bool w=rblog::is_suppressed(); rblog::suppress(false);
    rblog::write("CS-REPAIR: runs=%lld holders=%lld nulled=%lld cleared=%lld | %d catalog rows (scope=%ld)",
                 (long long)c_runs,(long long)c_holders,(long long)c_nulled,(long long)c_cleared,N_CAT,g_scope);
    rblog::suppress(w);
}

} // namespace coherent_set_repair
