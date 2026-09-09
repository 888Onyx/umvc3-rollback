// edge_census.cpp — READ-ONLY ground-truth edge-map builder (the owned-heap map-accuracy check).
//
// Why: the static analysis is a lower BOUND — it bucketed out-of-arena-allocator pointers as
// INTERNAL and covers only the reflected/object-touched types. The fault (proven: stale in-arena->out-of-arena
// coupling) is defined by RUNTIME RESIDENCE, which is GROUND TRUTH, not static inference. So census it directly:
// at the coherent frozen checkpoint (state live, every pointer points where it should), scan the arena, recognize
// objects by the 6064-vtable domain (census_types.h, sized via DTI+reflect+RE), and for every aligned qword in
// each object's extent classify the value's residence. Accumulate per (vtable,offset) across the long run. The
// offsets that point OUT-OF-ARENA-HEAP = the cross-boundary EDGES the owned-heap restore must reconcile.
#include "edge_census.h"
#include "census_types.h"
#include "addr.h"
#include "arena.h"
#include "log.h"
#include "resim.h"
#include <windows.h>
#include <psapi.h>
#include <cstdint>
#include <cstdio>

namespace edge_census {

static uintptr_t g_mod_lo = 0, g_mod_hi = 0;     // umvc3.exe image range (build-constants live here)
static bool g_inited = false;

static void init_once() {
    if (g_inited) return; g_inited = true;
    HMODULE m = GetModuleHandleA("umvc3.exe");
    if (m) {
        g_mod_lo = (uintptr_t)m;
        MODULEINFO mi; if (GetModuleInformation(GetCurrentProcess(), m, &mi, sizeof(mi))) g_mod_hi = g_mod_lo + mi.SizeOfImage;
    }
}

// binary search the sorted census type table; returns size or 0 if `v` is not a known vtable.
static uint32_t type_size(uint64_t v) {
    int lo = 0, hi = CENSUS_TYPE_COUNT - 1;
    while (lo <= hi) { int m = (lo + hi) >> 1; uint64_t mv = CENSUS_TYPES[m].vt;
        if (mv == v) return CENSUS_TYPES[m].size; if (mv < v) lo = m + 1; else hi = m - 1; }
    return 0;
}

// residence classes
enum { R_NOTPTR = 0, R_ARENA, R_MODULE, R_OOA };
static inline bool canon(uint64_t p) { return p >= 0x10000 && p < 0x7FFFFFFFFFFFULL; }
static int classify(uint64_t val) {
    if (!canon(val)) return R_NOTPTR;
    if (val >= g_mod_lo && val < g_mod_hi) return R_MODULE;
    if (arena::is_arena_addr((uintptr_t)val)) return R_ARENA;
    // out-of-arena candidate. must point to committed memory...
    MEMORY_BASIC_INFORMATION mbi;
    if (!VirtualQuery((void*)val, &mbi, sizeof(mbi))) return R_NOTPTR;
    if ((mbi.State & MEM_COMMIT) == 0) return R_NOTPTR;
    DWORD rw = PAGE_READONLY|PAGE_READWRITE|PAGE_EXECUTE_READ|PAGE_EXECUTE_READWRITE|PAGE_WRITECOPY|PAGE_EXECUTE_WRITECOPY;
    if ((mbi.Protect & rw) == 0 || (mbi.Protect & (PAGE_GUARD|PAGE_NOACCESS))) return R_NOTPTR;
    if (val + 8 > (uintptr_t)mbi.BaseAddress + mbi.RegionSize) return R_NOTPTR;   // *(val) read must stay in-region
    //...and point to a real OBJECT, not raw data that looks like an address. The dangerous edge (every crash)
    // is a vtable deref: field -> external object -> vtbl=*(obj) -> call *(vtbl+off). So 2-deref test, MODULE-
    // AGNOSTIC (XAudio2/D3D/COM vtables live in system DLLs, not umvc3.exe — the earlier umvc3-only check wrongly
    // dropped them, 18343->2): (1) vtbl=*(val) committed-readable, (2) *(vtbl) (first virtual method) points to
    // EXECUTABLE code. Random float/index data won't deref twice into executable memory => filtered.
    uint64_t vtbl = *(uint64_t*)val;
    if (!canon(vtbl)) return R_NOTPTR;
    MEMORY_BASIC_INFORMATION mv;
    if (!VirtualQuery((void*)vtbl, &mv, sizeof(mv)) || (mv.State & MEM_COMMIT) == 0) return R_NOTPTR;
    if ((mv.Protect & (rw)) == 0 || (mv.Protect & (PAGE_GUARD|PAGE_NOACCESS))) return R_NOTPTR;
    if (vtbl + 8 > (uintptr_t)mv.BaseAddress + mv.RegionSize) return R_NOTPTR;
    uint64_t m0 = *(uint64_t*)vtbl;                  // first virtual method
    if (!canon(m0)) return R_NOTPTR;
    MEMORY_BASIC_INFORMATION me;
    if (!VirtualQuery((void*)m0, &me, sizeof(me)) || (me.State & MEM_COMMIT) == 0) return R_NOTPTR;
    DWORD exec = PAGE_EXECUTE|PAGE_EXECUTE_READ|PAGE_EXECUTE_READWRITE|PAGE_EXECUTE_WRITECOPY;
    if ((me.Protect & exec) == 0) return R_NOTPTR;   // first method not executable => not a real vtable => not an object
    return R_OOA;
}

// per (vtable,offset) accumulator — open-addressing hash, fixed capacity (bounded RAM ~16MB).
static constexpr int CAP = 1 << 19;   // 524288 slots
struct Ent { uint64_t vt; uint32_t off; uint32_t arena, mod, ooa; };
static Ent* g_tab = nullptr;
static int g_used = 0;
static int64_t c_census = 0, c_objs = 0;

static Ent* slot_for(uint64_t vt, uint32_t off) {
    if (!g_tab) { g_tab = (Ent*)VirtualAlloc(nullptr, sizeof(Ent) * CAP, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE); if (!g_tab) return nullptr; }
    uint64_t h = (vt * 1099511628211ull) ^ (off * 2654435761u); int i = (int)(h & (CAP - 1));
    for (int n = 0; n < CAP; n++) {
        Ent& e = g_tab[(i + n) & (CAP - 1)];
        if (e.vt == 0 && e.off == 0 && e.arena == 0 && e.mod == 0 && e.ooa == 0) { e.vt = vt; e.off = off; g_used++; return &e; }
        if (e.vt == vt && e.off == off) return &e;
    }
    return nullptr;   // table full
}

// block-header helpers (verified layout): size in 16B units at +0x38>>1, allocated = +0x38&1.
static inline uint64_t blk_total(uintptr_t b) { return (uint64_t)(*(uint32_t*)(b + 0x38) >> 1) << 4; }
static inline bool     blk_alloc(uintptr_t b) { return (*(uint32_t*)(b + 0x38) & 1) != 0; }

static bool rd(uintptr_t p, size_t n) {   // committed-readable, arena-fast / VQ-fallback
    if (!canon(p)) return false;
    if (arena::is_arena_addr(p)) return arena::is_committed_addr(p) && arena::is_committed_addr(p + n - 1);
    MEMORY_BASIC_INFORMATION mbi; if (!VirtualQuery((void*)p, &mbi, sizeof(mbi))) return false;
    if ((mbi.State & MEM_COMMIT) == 0) return false;
    DWORD rw = PAGE_READONLY|PAGE_READWRITE|PAGE_EXECUTE_READ|PAGE_EXECUTE_READWRITE|PAGE_WRITECOPY|PAGE_EXECUTE_WRITECOPY;
    if ((mbi.Protect & rw) == 0 || (mbi.Protect & (PAGE_GUARD|PAGE_NOACCESS))) return false;
    return (p + n) <= (uintptr_t)mbi.BaseAddress + mbi.RegionSize;
}

// census one allocated block: a block holds an OBJECT at its payload start (vtable at +0), not an object every
// 8 bytes. So search only the small header window [b, b+0x40) for the payload vtable (typical header is 0x10);
// census that one object's fields, bounded by ITS type size. Cost = O(object), not O(block) — so 512KB blocks
// (the streamed/sound substrate) are cheap and the cursor advances. (The earlier full-interior scan stuck the
// cursor: ~3 huge blocks ate the whole budget.)
// Returns the WORK done (qwords touched) so the caller can charge budget accurately (not block size — that
// stuck the cursor on the 512KB-block allocator). Scans a bounded header window [b, b+0x400) for the payload
// vtable (covers objects whose payload sits anywhere in the first 1KB, regardless of exact header size); on the
// first known-vtable match, residence-classifies that object's fields and returns. A 512KB raw buffer costs
// <=128 qwords, not 66000.
static long census_block(uintptr_t b, uint64_t total) {
    uintptr_t bend = b + total;
    uintptr_t search_end = b + 0x400; if (search_end > bend) search_end = bend;
    long work = 0;
    for (uintptr_t p = b; p + 8 <= search_end; p += 8) {
        work++;
        if (!rd(p, 8)) return work;
        uint64_t maybe_vt = *(uint64_t*)p;
        if (maybe_vt < g_mod_lo || maybe_vt >= g_mod_hi) continue;
        uint32_t sz = type_size(maybe_vt);
        if (!sz) continue;
        c_objs++;
        uintptr_t oend = p + sz; if (oend > bend) oend = bend;
        for (uintptr_t f = p + 8; f + 8 <= oend; f += 8) {
            work++;
            if (!rd(f, 8)) break;
            int r = classify(*(uint64_t*)f);
            if (r == R_NOTPTR) continue;
            Ent* e = slot_for(maybe_vt, (uint32_t)(f - p));
            if (!e) continue;
            if (r == R_ARENA) e->arena++; else if (r == R_MODULE) e->mod++; else e->ooa++;
        }
        return work;   // one object per block (payload start) — done
    }
    return work;
}

// AMORTIZED census: a full heap walk is too heavy for one frozen suspend window (it froze the game at every
// prior attempt). So do a BOUNDED slice per rollback and RESUME next rollback via a persistent cursor. Over many
// rollbacks the whole heap is covered; each call is cheap and can never freeze. budget = qword-classifies/call.
static int       g_cur_alloc = 0;        // resume: which dedup'd allocator index
static uintptr_t g_cur_block = 0;        // resume: block address within that allocator's region (0 = region start)
static int64_t   c_full_passes = 0;

void census() {
    if (!resim::engine_enabled()) return;
    init_once();
    c_census++;
    uintptr_t* table = (uintptr_t*)addr::resolve(0x140D762F0);
    if (!table) return;
    // dedup the table into a stable allocator list (so g_cur_alloc indexes consistently across calls)
    uintptr_t allocs[64]; int na = 0;
    for (int i = 0; i < 64; i++) {
        uintptr_t c = table[i];
        if (!canon(c) || !rd(c + 0x98, 8)) continue;
        bool dup = false; for (int s = 0; s < na; s++) if (allocs[s] == c) { dup = true; break; }
        if (!dup && na < 64) allocs[na++] = c;
    }
    long budget = 200000;            // ~qword-classifies this call; tune so the frozen slice stays sub-100ms
    long blocks = 0; bool wrapped = false;
    if (g_cur_alloc >= na) { g_cur_alloc = 0; g_cur_block = 0; }
    while (budget > 0 && g_cur_alloc < na) {
        uintptr_t control = allocs[g_cur_alloc];
        uintptr_t rlo = *(uintptr_t*)(control + 0x90), rhi = *(uintptr_t*)(control + 0x98);
        if (!canon(rlo) || rhi <= rlo || (rhi - rlo) > 0x40000000ull) { g_cur_alloc++; g_cur_block = 0; continue; }
        uintptr_t bk = g_cur_block ? g_cur_block : rlo;
        if (bk < rlo || bk >= rhi) bk = rlo;
        bool region_done = true;
        for (; bk < rhi; ) {
            if (budget <= 0) { g_cur_block = bk; region_done = false; break; }   // out of budget -> resume here
            if (!rd(bk + 0x40, 8)) break;
            uint64_t bt = blk_total(bk); if (bt == 0) break;
            uintptr_t nb = bk + bt; if (nb <= bk || nb > rhi) break;
            if (blk_alloc(bk)) { budget -= census_block(bk, bt) + 2; blocks++; }  // charge actual work, not block size
            bk = nb;
        }
        if (region_done) { g_cur_alloc++; g_cur_block = 0; }   // finished this allocator -> next call starts next one
    }
    if (g_cur_alloc >= na) { g_cur_alloc = 0; g_cur_block = 0; wrapped = true; c_full_passes++; }  // full pass complete
    {
        bool was = rblog::is_suppressed(); rblog::suppress(false);
        rblog::write("EDGE-CENSUS[run %lld]: blocks=%ld objs=%lld slots=%d allocs=%d cursor=(a%d) pass=%lld%s",
                     (long long)c_census, blocks, (long long)c_objs, g_used, na, g_cur_alloc,
                     (long long)c_full_passes, wrapped ? " [FULL-PASS COMPLETE -> dump]" : "");
        rblog::suppress(was);
    }
    if (wrapped) dump();   // dump after each complete pass over the heap
}

void dump() {
    bool was0 = rblog::is_suppressed(); rblog::suppress(false);
    if (!g_tab) { rblog::write("EDGE-CENSUS: dump skipped — 0 pointer fields recorded (block-walk matched no known vtables)"); rblog::suppress(was0); return; }
    rblog::suppress(was0);
    // absolute path into the game dir (CWD may not be the game dir); mirror where the log lives.
    const char* path = "C:\\Program Files (x86)\\Steam\\steamapps\\common\\ULTIMATE MARVEL VS. CAPCOM 3\\edge_census.csv";
    FILE* fp = fopen(path, "w");
    if (!fp) fp = fopen("edge_census.csv", "w");
    if (!fp) { bool w=rblog::is_suppressed(); rblog::suppress(false); rblog::write("EDGE-CENSUS: dump fopen failed"); rblog::suppress(w); return; }
    fprintf(fp, "vtable,offset,arena,module,ooa_edge\n");
    int edges = 0, rows = 0;
    for (int i = 0; i < CAP; i++) {
        Ent& e = g_tab[i];
        if (e.vt == 0 && e.off == 0) continue;
        fprintf(fp, "0x%llx,0x%x,%u,%u,%u\n", (unsigned long long)e.vt, e.off, e.arena, e.mod, e.ooa);
        rows++; if (e.ooa) edges++;
    }
    fclose(fp);
    bool was = rblog::is_suppressed(); rblog::suppress(false);
    rblog::write("EDGE-CENSUS: dumped %d pointer-field rows, %d are OUT-OF-ARENA EDGES (census runs=%lld objs=%lld) -> edge_census.csv",
                 rows, edges, (long long)c_census, (long long)c_objs);
    rblog::suppress(was);
}

// ============================================================================================================
// EDGE-COHERENT RESTORE (shadow first). The reconcile policy:
// A) transient external, STALE, guard+recreate verified -> NULL (engine re-derives). Held (sound_edge_reconcile).
// B) external, LIVE -> preserve / no-op.
// C) session-lifetime singleton external -> EXCLUDED from the walk (owned by handle_preserve/sound_preserve).
// D) guard-UNVERIFIED carrier -> ABSTAIN: log to a worklist, no write.
// Never byte-revert an external. SHADOW (g_live=0): count would-act, write nothing, prove gp_crc unchanged + nonvacuous.
// SPEED: per-block O(1) vtable lookup (no interior scan); staleness VirtualQuery only for the few carrier instances;
// runs fully every rollback (a fix can't be amortized). This is sound_edge_reconcile generalized off its hardcoded list.
// ============================================================================================================
static volatile long g_stream_probe = 0;   // diagnostic STREAM-PROBE (carrier #2 ogg residence) — scaffold, OFF.
static volatile long g_live = 1;   // LIVE (carrier #1): null bucket-A stale voice edges (staleness-gated).
                                   // SHADOW validated non-vacuous + gp_crc=0; generalizes sound_edge_reconcile to all instances.

// Bucket A — guard-VERIFIED transient external carriers (deref-guarded + engine lazy-recreate, RE-confirmed).
// Sound channel/voice nodes: vtable -> the external voice-pointer field offsets (census + the sound-crash RE).
struct CarrierA { uint64_t vt; uint32_t offs[8]; int n; };
static const CarrierA BUCKET_A[] = {
    // sound channel node (sound-cue carrier). TRIMMED:
    // {0x18,0x20,0x28,0x30} REMOVED — fully owned by sound_edge_reconcile's stricter crash-exact voice_live()
    // test which runs first in the same frozen window (0/443 census nulls there across the 100k long run; keeping
    // them here risked census's weaker vtbl-slot-0 test overruling reconcile's keep verdict). What remains is
    // census's IRREDUCIBLE core — structurally unreachable by reconcile's fixed offs[4]: +0x8/+0x10 (read by
    // FUN_1405bee80 and passed into the same call *(vtbl+0x80) that crashes on +0x18) and +0x160 (ctor-distinct
    // external-pointer field, ooa=3 in census ground truth; 443/443 of the clean long run's nulls — the only live
    // repair of that churn). Possible follow-up: move these 3 into reconcile's O(32) slot walk, then
    // this whole-heap pass is strippable (bucket-D discovery read 0 all run).
    { 0x140bad4b0ull, {0x8,0x10,0x160}, 3 },
};
static const int BUCKET_A_N = (int)(sizeof(BUCKET_A)/sizeof(BUCKET_A[0]));

// Bucket C — session-lifetime singleton externals already owned by handle_preserve/sound_preserve/dynamic_restore: EXCLUDE.
static const uint64_t BUCKET_C_VT[] = {
    0x140b13070ull,   // sMvc3Render (kept-live / rederive-excluded; D3D handles)
    0x140b135f0ull,   // sMvc3Resource (session)
    0x140b80f20ull, 0x140b81700ull,   // nNet::sCommunity / sRanking (session/network)
    0x140b07e50ull, 0x140b0c730ull,   // sGameConfig / sLicense (session)
};
static const int BUCKET_C_N = (int)(sizeof(BUCKET_C_VT)/sizeof(BUCKET_C_VT[0]));

static const CarrierA* bucketA_of(uint64_t vt) {
    for (int i = 0; i < BUCKET_A_N; i++) if (BUCKET_A[i].vt == vt) return &BUCKET_A[i];
    return nullptr;
}
static bool bucketC(uint64_t vt) { for (int i = 0; i < BUCKET_C_N; i++) if (BUCKET_C_VT[i] == vt) return true; return false; }

static int64_t r_runs=0, r_nullA=0, r_liveB=0, r_worklistD=0, r_exclC=0;

// build the set of vtables the census recorded an OOA edge for (the carrier set), once per call from g_tab.
static int edge_vt_set(uint64_t* out, int cap) {
    int n=0; if(!g_tab) return 0;
    for (int i=0;i<CAP && n<cap;i++){
        if (g_tab[i].ooa==0) continue;
        uint64_t vt=g_tab[i].vt; bool dup=false;
        for(int j=0;j<n;j++) if(out[j]==vt){dup=true;break;}
        if(!dup) out[n++]=vt;
    }
    return n;
}
static bool in_set(const uint64_t* s,int n,uint64_t v){ for(int i=0;i<n;i++) if(s[i]==v) return true; return false; }

void coherent_restore() {
    if (!resim::engine_enabled()) return;
    init_once();
    r_runs++;
    uintptr_t* table = (uintptr_t*)addr::resolve(0x140D762F0);
    if (!table) return;
    uint64_t evt[256]; int evtn = edge_vt_set(evt, 256);   // census-flagged carrier vtables (for bucket-D worklist)
    uintptr_t seen[64]; int nseen=0;
    long nullA=0, liveB=0, worklistD=0, exclC=0, blocks=0;
    for (int i=0;i<64;i++){
        uintptr_t control=table[i];
        if(!canon(control)||!rd(control+0x98,8))continue;
        bool dup=false; for(int s=0;s<nseen;s++)if(seen[s]==control){dup=true;break;} if(dup)continue;
        if(nseen<64)seen[nseen++]=control;
        uintptr_t rlo=*(uintptr_t*)(control+0x90), rhi=*(uintptr_t*)(control+0x98);
        if(!canon(rlo)||rhi<=rlo||(rhi-rlo)>0x40000000ull)continue;
        for(uintptr_t bk=rlo; bk<rhi; ){
            if(!rd(bk+0x40,8))break;
            uint64_t bt=blk_total(bk); if(bt==0)break;
            uintptr_t nb=bk+bt; if(nb<=bk||nb>rhi)break;
            if(blk_alloc(bk)){
                blocks++;
                // find the payload vtable in the header window (stops at first match; census proved objects sit
                // within 0x400, not 0x40 — the 0x40 window made the SHADOW vacuous A=B=C=D=0). Still no interior scan.
                uintptr_t bend=bk+bt, swend=bk+0x400; if(swend>bend)swend=bend;
                for(uintptr_t p=bk;p+8<=swend;p+=8){
                    if(!rd(p,8))break;
                    uint64_t vt=*(uint64_t*)p;
                    if(vt<g_mod_lo||vt>=g_mod_hi)continue;
                    if(!type_size(vt))continue;                 // not a known object start
                    // STREAM-PROBE (diagnostic, scaffold-gated off): carrier #2 ogg residence.
                    if(g_stream_probe && vt==0x140bad660ull && rd(p+0x488,8)){
                        uint64_t bd=*(uint64_t*)(p+0x478); uint32_t bf=*(uint32_t*)(p+0x484), bs=*(uint32_t*)(p+0x480);
                        bool w=rblog::is_suppressed(); rblog::suppress(false);
                        rblog::write("STREAM-PROBE: P=0x%llX(in-arena=%d) body_data=0x%llX(in-arena=%d) body_fill=0x%x body_storage=0x%x",
                            (unsigned long long)p,(int)arena::is_arena_addr(p),(unsigned long long)bd,
                            bd?(int)arena::is_arena_addr(bd):-1,bf,bs);
                        rblog::suppress(w);
                    }
                    if(bucketC(vt)){ exclC++; break; }          // C: excluded (owned elsewhere)
                    const CarrierA* ca=bucketA_of(vt);
                    if(ca){                                      // A: guard-verified carrier -> check each edge offset
                        for(int k=0;k<ca->n;k++){
                            uintptr_t fp=p+ca->offs[k]; if(fp+8>bend||!rd(fp,8))continue;
                            uint64_t val=*(uint64_t*)fp;
                            if(val==0)continue;                  // already null
                            if(classify(val)==R_OOA){ liveB++; continue; }   // B: live external -> preserve
                            // non-null + not a valid object = STALE external edge -> bucket A action
                            nullA++;
                            // EDGE-NULL address log (instrument): a write audit named this pass a
                            // header-clobber suspect (offsets {0x8..0x30} mirror the a4 header field set; null ==
                            // the crash's +0x8=0; "in-arena => stale" is tautologically true for header fields;
                            // the split copies +0x0 verbatim — 0x1404CA86B — so vtable residue CAN sit at a block
                            // base => p==bk aliasing). Counts can't convict (A fires on clean runs too): print
                            // every nulled ADDRESS so a long run cross-references vs A4-DIAG nodes. Bounded: A is
                            // ~1-4 per rollback, not per frame. "==BLK-BASE!" in the line = the smoking gun.
                            { bool w=rblog::is_suppressed(); rblog::suppress(false);
                              rblog::write("EDGE-NULL: fp=0x%llX (p=0x%llX%s off=+0x%X) val=0x%llX vt=0x%llX blk=[0x%llX,+0x%llX) ctrl=0x%llX %s",
                                  (unsigned long long)fp,(unsigned long long)p, p==bk?" ==BLK-BASE!":"", ca->offs[k],
                                  (unsigned long long)val,(unsigned long long)vt,
                                  (unsigned long long)bk,(unsigned long long)bt,(unsigned long long)control,
                                  g_live?"NULLED":"shadow");
                              rblog::suppress(w); }
                            if(g_live) *(uint64_t*)fp = 0;       // LIVE: null it (engine re-derives); SHADOW: count only
                        }
                        break;
                    }
                    // not A/C: bucket D worklist only if the census flagged this vtable as carrying ooa edges
                    // (a guard-unverified real carrier). Normal objects (no census edge) are ignored.
                    if(in_set(evt,evtn,vt)) worklistD++;
                    break;
                }
            }
            bk=nb;
        }
    }
    r_nullA+=nullA; r_liveB+=liveB; r_worklistD+=worklistD; r_exclC+=exclC;
    bool was=rblog::is_suppressed(); rblog::suppress(false);
    rblog::write("EDGE-COHERENT[%s run %lld]: blocks=%ld | A(stale-null)=%ld B(live)=%ld C(excl)=%ld D(worklist)=%ld %s",
                 g_live?"LIVE":"SHADOW", (long long)r_runs, blocks, nullA, liveB, exclC, worklistD,
                 g_live?"(NULLED bucket-A stale)":"(shadow: would-null bucket-A stale, no write)");
    rblog::suppress(was);
}

} // namespace edge_census
