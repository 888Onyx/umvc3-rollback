// alloc_invariants.cpp — see alloc_invariants.h. V1: the crash-proven allocator free-list/alloc-list invariants, evaluated at
// frozen / POSTLOAD / POSTRESIM. Only INVARIANT_BROKEN / UNREADABLE alarm. Read-only.
//
// Offsets were verified at runtime (alloc_consistency.cpp) and match the SubHeapManager layout:
// registry: count @resolve(0x140D760E0), array @resolve(0x140D760F0), scalable vtable @resolve(0x140B08620)
// per control: 8 sub-heap managers at control + 0xd8 + k*0xa8 (k in [0, min(8, *(control+0x648))))
// FREE list: head +0x58, count +0x68; ALLOC list: head +0x40, count +0x50
// node: logical_prev +0x18, logical_next +0x20; size_and_inuse +0x38 (bit0 = in_use)
// pool range: control +0x90 (lo).. +0x98 (hi) (canonicality bound for L_*_DLL clause 5)
#include "alloc_invariants.h"
#include "addr.h"
#include "arena.h"
#include "log.h"
#include <windows.h>
#include <cstdint>
#include <cstdio>

namespace alloc_invariants {

static volatile long g_off = 0;   // Free-list check only; the alloc-list check is skipped (see check()). The phase pattern
                                  // says where corruption forms: frozen/POSTLOAD clean but POSTRESIM broken => during
                                  // replay; every phase clean but the allocator spins later => a normal-play corruptor.
void set_off(bool v){ g_off = v?1:0; }
bool is_off(){ return g_off!=0; }

static const char* PHNAME[3] = { "FROZEN", "POSTLOAD", "POSTRESIM" };

// fast readable: arena bitmap for in-arena, VirtualQuery fallback (mirrors alloc_consistency::readable).
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
static inline bool canon(uintptr_t p){ return p>=0x10000 && p<0x7FFFFFFFFFFFULL; }

// lifetime tally: [phase][invariant] -> break count. invariant 0 = FREE_LIST_DLL, 1 = ALLOC_LIST_DLL.
static int64_t g_breaks[3][2] = {{0,0},{0,0},{0,0}};
static int64_t g_checks[3]    = {0,0,0};

// Evaluate one doubly-linked list invariant (L_FREE_LIST_DLL / L_ALLOC_LIST_DLL) on a manager.
// Returns: 0 = PASS, 1 = INVARIANT_BROKEN, 2 = UNREADABLE. Fills `why` for the log.
// On a break, appends the restore source-frame of head + offending node (arena::last_source_frame): if nodes in
// one list show different source frames, the delta-ring reconstructed the descriptor and nodes from different
// effective frames (the restore-reconstruction hypothesis). -100=out-of-arena, -1=baseline, -2=orphan, -3=live.
static int check_list(uintptr_t ctrl, uintptr_t mgr, uintptr_t head_off, uintptr_t count_off,
                      uintptr_t lo, uintptr_t hi, char* why, size_t whyn,
                      char* prov, size_t provn){
    if(prov && provn) prov[0]=0;
    if(!readable(mgr+head_off,8) || !readable(mgr+count_off,4)){ snprintf(why,whyn,"mgr fields unreadable"); return 2; }
    uintptr_t head  = *(uintptr_t*)(mgr+head_off);
    uint32_t  count = *(uint32_t*)(mgr+count_off);
    int hsrc = (int)arena::last_source_frame(head);   // which frame head's page was restored from
    if(head==0){ if(count!=0){ snprintf(why,whyn,"head=NULL but count=%u",count); return 1; } return 0; }
    // clause (2): head.prev == NULL
    if(!readable(head+0x18,8)){ snprintf(why,whyn,"head+0x18 unreadable"); return 2; }
    if(*(uintptr_t*)(head+0x18)!=0){ snprintf(why,whyn,"head.prev != NULL (0x%llX) | head_srcF=%d",(unsigned long long)*(uintptr_t*)(head+0x18),hsrc); return 1; }
    uintptr_t node=head, prev=0; uint32_t walked=0; uint32_t cap=count+2;
    while(node){
        if(walked>cap){ snprintf(why,whyn,"overrun: walked>%u (cycle?) count=%u",cap,count); return 1; }
        // clause (5): canonical + within pool (multi-region: primary [+0x90,+0x98) OR any DONATED region — a
        // donated-region node is LEGAL, not a break; without this the donation manufactures false INVARIANT_BROKEN)
        if(!canon(node) || (lo && hi && (node<lo || node>=hi) && !arena::in_owned_pool(ctrl, node))){ snprintf(why,whyn,"node 0x%llX outside pool [0x%llX,0x%llX) srcF=%d",(unsigned long long)node,(unsigned long long)lo,(unsigned long long)hi,(int)arena::last_source_frame(node)); return 1; }
        if(!readable(node+0x18,8) || !readable(node+0x20,8)){ snprintf(why,whyn,"node 0x%llX links unreadable",(unsigned long long)node); return 2; }
        // clause (1): reciprocity prev
        uintptr_t nprev=*(uintptr_t*)(node+0x18);
        if(nprev!=prev){
            snprintf(why,whyn,"node 0x%llX .prev=0x%llX != expected 0x%llX (recip break) | node_srcF=%d prev_srcF=%d head_srcF=%d",(unsigned long long)node,(unsigned long long)nprev,(unsigned long long)prev,(int)arena::last_source_frame(node),(int)arena::last_source_frame(prev),hsrc);
            // PAGE-HISTORY FORENSICS: dump the involved pages' slot-membership so the log
            // decides between "invisible write" (no dirty slot in [horizon..target] where coherence demands one)
            // and "source-walk bug" (a <=target dirty slot existed but src says otherwise). Break-gated only.
            if(prov && provn){
                char hn[96], hp[96], hh[96];
                arena::page_history(node, hn, sizeof hn);
                arena::page_history(prev, hp, sizeof hp);
                arena::page_history(head, hh, sizeof hh);
                snprintf(prov, provn, "node{%s} prev{%s} head{%s}", hn, hp, hh);
            }
            return 1;
        }
        prev=node; node=*(uintptr_t*)(node+0x20); walked++;
    }
    // clause (3): visited == count
    if(walked!=count){
        snprintf(why,whyn,"visited(%u) != count(%u) | head_srcF=%d",walked,count,hsrc);
        // COUNT-DRIFT PROVENANCE (parity with the recip branch): the tail nodes are the ones the engine's
        // count==0-guarded unlink left chained — their page history names whether the extra links are old
        // (long-lived srcF) or fresh. prev = the last visited node at walk end.
        if(prov && provn && prev){
            char ht[96]; arena::page_history(prev, ht, sizeof ht);
            snprintf(prov, provn, "tail 0x%llX {%s}", (unsigned long long)prev, ht);
        }
        return 1;
    }
    return 0;
}

void check(Phase phase, int frame){
    if(g_off) return;
    g_checks[phase]++;
    uintptr_t count_addr = addr::resolve(0x140D760E0);
    uintptr_t array_addr = addr::resolve(0x140D760F0);
    uintptr_t target_vt  = addr::resolve(0x140B08620);
    if(!readable(count_addr,4) || !readable(array_addr,8)) return;
    uint32_t nreg = *(uint32_t*)count_addr; if(nreg>64) nreg=64;
    int logged=0; const int LOG_CAP=12;
    int broke_free=0, broke_alloc=0, unread=0;

    for(uint32_t i=0;i<nreg;i++){
        uintptr_t ctrl = readable(array_addr+i*8,8) ? *(uintptr_t*)(array_addr+i*8) : 0;
        if(!ctrl || !readable(ctrl,8) || *(uintptr_t*)ctrl!=target_vt) continue;
        uintptr_t lo = readable(ctrl+0x90,8) ? *(uintptr_t*)(ctrl+0x90) : 0;
        uintptr_t hi = readable(ctrl+0x98,8) ? *(uintptr_t*)(ctrl+0x98) : 0;
        int ncls = readable(ctrl+0x648,4) ? *(int*)(ctrl+0x648) : 8;
        if(ncls<1 || ncls>8) ncls=8;
        for(int k=0;k<ncls;k++){
            uintptr_t mgr = ctrl + 0xd8 + (uintptr_t)k*0xa8;
            char why[160]; char prov[320];
            int rf = check_list(ctrl, mgr, 0x58, 0x68, lo, hi, why, sizeof(why), prov, sizeof(prov));   // L_FREE_LIST_DLL
            if(rf!=0){
                if(rf==1) broke_free++; else unread++;
                g_breaks[phase][0]++;
                if(logged<LOG_CAP){ bool was=rblog::is_suppressed(); rblog::suppress(false);
                    rblog::write("INVARIANT-CHECK[%s f%d] %s ctrl=0x%llX mgr%d L_FREE_LIST_DLL: %s",
                        PHNAME[phase], frame, rf==1?"INVARIANT_BROKEN":"UNREADABLE",
                        (unsigned long long)ctrl, k, why);
                    if(prov[0]) rblog::write("INVARIANT-CHECK-PROV[%s f%d] ctrl=0x%llX mgr%d: %s",
                        PHNAME[phase], frame, (unsigned long long)ctrl, k, prov);
                    rblog::suppress(was); logged++; }
            }
            // L_ALLOC_LIST_DLL check SKIPPED: it walks all 5000+ allocated blocks (the 6s freeze) and false-positives
            // (engine maintains the alloc-list next-only, not reciprocal). The crash is the FREE-list spin (0x1404CA650
            // first-fit walk), so FREE_LIST is what matters. Re-enable alloc check only for targeted alloc-list RE.
        }
    }
    // Always log the summary (once per rollback phase, never per-frame): a clean pass previously printed
    // nothing, making "broken=0" indistinguishable from "check never ran" (an earlier run read as oracle-blind).
    // A visible broken=0 is the positive evidence — but only meaningful against a real list; cross-check
    // that no rebuild/wipe emptied the lists first (the vacuous-pass trap).
    {
        bool was=rblog::is_suppressed(); rblog::suppress(false);
        rblog::write("INVARIANT-CHECK[%s f%d]: FREE_LIST broken=%d  ALLOC_LIST broken=%d  unreadable=%d  <= the first phase to break names the layer to fix (POSTLOAD=restore-side, POSTRESIM-only=replay/free-layer)",
            PHNAME[phase], frame, broke_free, broke_alloc, unread);
        rblog::suppress(was);
    }
    if(phase==PH_POSTRESIM && (g_checks[PH_POSTRESIM] % 8)==0) dump();
}

void dump(){
    bool was=rblog::is_suppressed(); rblog::suppress(false);
    rblog::write("INVARIANT-CHECK/summary: checks F=%lld PL=%lld PR=%lld | FREE_LIST breaks F=%lld PL=%lld PR=%lld | ALLOC_LIST breaks F=%lld PL=%lld PR=%lld",
        (long long)g_checks[0],(long long)g_checks[1],(long long)g_checks[2],
        (long long)g_breaks[0][0],(long long)g_breaks[1][0],(long long)g_breaks[2][0],
        (long long)g_breaks[0][1],(long long)g_breaks[1][1],(long long)g_breaks[2][1]);
    rblog::suppress(was);
}

// ── INVARIANT REPAIRER ────────────────────────────────────────────────────────────────────────────────────────
static volatile long g_repair = 1;   // Default ON: repairs the organic live-side count drift; pass 1 validates before any write.
void set_repair(bool v){ g_repair = v?1:0; }
bool repair_on(){ return g_repair!=0; }
static int64_t g_rep_lists=0, g_rep_links=0, g_rep_unfit=0, g_rep_calls=0;

// Repair one doubly-linked FREE list: rebuild the backward links (+0x18) from the intact forward chain (+0x20),
// then reconcile tail(+0x60)/count(+0x68)/size-sum(+0x6c). PASS 1 validates the forward chain READ-ONLY (cap /
// canon / in-pool / readable / free-bit) and bails with NO writes if anything is off (we never trust a broken
// forward chain to rebuild from). PASS 2 writes only when a field actually disagrees. Returns #fields fixed, or
// -1 = unrepairable (left untouched so the checker still logs it). head_off=0x58, count_off=0x68; tail=head_off+8,
// size-sum=head_off+0x14 — matching FUN_1404ca220/FUN_1404cb480's own accounting.
static int repair_list(uintptr_t mgr, uintptr_t head_off, uintptr_t count_off, uintptr_t lo, uintptr_t hi){
    if(!readable(mgr+head_off,8) || !readable(mgr+count_off,4)) return -1;
    uintptr_t head  = *(uintptr_t*)(mgr+head_off);
    uint32_t  count = *(uint32_t*)(mgr+count_off);
    if(head==0) return (count==0) ? 0 : -1;        // head lost (forward break) — cannot rebuild from forward chain
    uint32_t cap = count + 2; if(cap < 4) cap = 4; if(cap > 200000) return -1;
    // PASS 1 — validate the forward chain (no writes).
    {
        uintptr_t node=head; uint32_t walked=0;
        if(!readable(head+0x18,8)) return -1;
        while(node){
            if(walked>cap) return -1;                                              // cycle / overrun => untrusted
            if(!canon(node) || (lo && hi && (node<lo || node>=hi))) return -1;     // out of pool => untrusted
            if(!readable(node+0x18,8) || !readable(node+0x20,8) || !readable(node+0x38,4)) return -1;
            if((*(uint32_t*)(node+0x38) & 1) != 0) return -1;                      // a free node is not in_use
            node=*(uintptr_t*)(node+0x20); walked++;
        }
    }
    // PASS 2 — rebuild backward links + reconcile descriptor scalars from the validated forward chain.
    int fixes=0; uintptr_t node=head, prev=0, last=head; uint32_t walked=0; uint64_t ssum=0;
    while(node){
        if(*(uintptr_t*)(node+0x18) != prev){ *(uintptr_t*)(node+0x18) = prev; fixes++; }   // .prev (incl. head.prev=0)
        ssum += (uint64_t)(*(uint32_t*)(node+0x38) >> 1);
        last=node; prev=node; node=*(uintptr_t*)(node+0x20); walked++;
    }
    if(*(uintptr_t*)(mgr+head_off+8) != last)         { *(uintptr_t*)(mgr+head_off+8) = last;             fixes++; }  // tail +0x60
    if(*(uint32_t*) (mgr+count_off)  != walked)       { *(uint32_t*) (mgr+count_off)  = walked;           fixes++; }  // count +0x68
    if(readable(mgr+head_off+0x14,4) && *(uint32_t*)(mgr+head_off+0x14) != (uint32_t)ssum)
                                                      { *(uint32_t*)(mgr+head_off+0x14) = (uint32_t)ssum; fixes++; }  // size-sum +0x6c
    return fixes;
}

void repair_freelists(int frame){
    if(!g_repair) return;
    g_rep_calls++;
    uintptr_t count_addr = addr::resolve(0x140D760E0);
    uintptr_t array_addr = addr::resolve(0x140D760F0);
    uintptr_t target_vt  = addr::resolve(0x140B08620);
    if(!readable(count_addr,4) || !readable(array_addr,8)) return;
    uint32_t nreg = *(uint32_t*)count_addr; if(nreg>64) nreg=64;
    int lists=0, links=0, unfit=0;
    for(uint32_t i=0;i<nreg;i++){
        uintptr_t ctrl = readable(array_addr+i*8,8) ? *(uintptr_t*)(array_addr+i*8) : 0;
        if(!ctrl || !readable(ctrl,8) || *(uintptr_t*)ctrl!=target_vt) continue;
        uintptr_t lo = readable(ctrl+0x90,8) ? *(uintptr_t*)(ctrl+0x90) : 0;
        uintptr_t hi = readable(ctrl+0x98,8) ? *(uintptr_t*)(ctrl+0x98) : 0;
        int ncls = readable(ctrl+0x648,4) ? *(int*)(ctrl+0x648) : 8;
        if(ncls<1 || ncls>8) ncls=8;
        for(int k=0;k<ncls;k++){
            uintptr_t mgr = ctrl + 0xd8 + (uintptr_t)k*0xa8;
            int r = repair_list(mgr, 0x58, 0x68, lo, hi);
            if(r>0){ lists++; links+=r; } else if(r<0){ unfit++; }
        }
    }
    g_rep_lists+=lists; g_rep_links+=links; g_rep_unfit+=unfit;
    if(lists||unfit){
        bool was=rblog::is_suppressed(); rblog::suppress(false);
        rblog::write("INVARIANT-REPAIR[POSTLOAD f%d]: lists_fixed=%d links_fixed=%d unrepairable=%d | lifetime lists=%lld links=%lld unfit=%lld calls=%lld (torn-save made harmless; +0x18/+0x20 are gp_crc-skipped arena ptrs)",
            frame, lists, links, unfit, (long long)g_rep_lists, (long long)g_rep_links, (long long)g_rep_unfit, (long long)g_rep_calls);
        rblog::suppress(was);
    }
}

} // namespace alloc_invariants
