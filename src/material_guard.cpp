// material_guard.cpp — Material lifecycle discipline: holder-edge severing at the destroy event.
//
// The failure: a uBaseModel-family holder keeps a pointer to a Material that was destroyed on a different
// timeline (its dtor ran, vtable zeroed => husk); the holder's own teardown derefs it 51-144 frames after a
// rollback => 0x1405DA4B5 / 0x1408748B0. The holder's PAGE is byte-correct (srcframe=-3, cold — a unit-capture
// restores identical bytes and fixes nothing); POSTLOAD repairs expire tens of frames too early. The correct
// jurisdiction is the DESTROY EVENT itself: when a Material dies, null every known holder edge pointing at it —
// the engine's own invalidation verb (it 0xBEAF-sentinels/memsets these same tables on ITS destroy paths),
// extended to destroys the rollback timeline made cross-cutting. Same discipline class as rtv_probe/voice_pool.
//
// SCOPING (binary): the +0x110/+0x118 dynamic array and +0x278..+0x4F8 16-slot table are fields of
// one object = the sUnit-scheduled entity itself (uBaseModel base vtbl 0x140baa4a0, layout shared by >=13
// entity vtables). Enumeration root = the sUnit spine (singleton 0x140E17698, 128 lines, head=+0x50+line*0x30,
// next=node+0x18) — the same walk run_sunit_rows/gp_crc already use. gp_crc SAFETY: fighter lines 7-8 hash
// +0x100..+0x130 and +0x220..+0x278 => on lines 7-8 only the +0x278 table (in the hash gap) may be touched;
// all other lines are render/asset-domain (drift-OK, like sRender).
#include "material_guard.h"
#include "arena.h"
#include "addr.h"
#include "resim.h"
#include "quarantine.h"
#include "id_oracle.h"
#include "log.h"
#include <MinHook.h>
#include <windows.h>
#include <cstdint>

namespace material_guard {

static constexpr uintptr_t IDA_DTOR       = 0x1405DA470ULL;  // Material-variant dtor (vtbl slot 0 of 0x140badfe0)
static constexpr uintptr_t IDA_SUNIT      = 0x140E17698ULL;  // sUnit scheduler singleton
static constexpr uintptr_t IDA_VT_VARIANT = 0x140badfe0ULL;  // 0x28-byte variant {vtbl,id,+0x18 childA,+0x20 childB}
static constexpr uintptr_t IDA_VT_MAT     = 0x140badee0ULL;  // 0xE0 nDraw::Material {+0x98/+0xa0 same-class children}

static void (*orig_dtor)(void*) = nullptr;
static volatile LONG64 c_fires = 0, c_sev_table = 0, c_sev_array = 0, c_sev_child = 0, c_walk_cap = 0;
// Why an edge was severed (attribution — proves which mechanism catches which crash):
static volatile LONG64 c_by_husk = 0, c_by_uncommitted = 0, c_by_deadvt = 0;
// RENDER-ALGEBRA (domain-valid-or-null): dtor-site own-child husk nulls (the 0x1405DA4B5 close)
static volatile LONG64 c_own_nulled = 0, c_own_fe0 = 0, c_own_ee0 = 0, c_own_base2e0 = 0;
static uintptr_t g_dead_sentinel = 0;   // runtime addr of the engine's post-dtor MtObject dead-vtable (0x140A6A510)

static inline bool rd(uintptr_t a) { return a > 0x10000 && arena::is_committed_addr(a); }

// TYPE-GATE (the free-list-corruption closer): recurse into m's +0x18/+0x20/+0x98/+0xa0 only
// when m is provably a LIVE Material — its vtable (at +0) is in the nDraw::Material family [0x140bad000,0x140bae000).
// A FREED Material block has its vtable ERASED by allocator coalesce (+0 becomes free-list bookkeeping, not a code
// addr), so it fails this gate ⇒ we never read/write its +0x18/+0x20, which for a freed block are the intrusive
// free-list prev/next links. This closes the "sweep zeros a live free-list link" hazard by construction, under
// both the intrusive-layout and header-offset interpretations. Cheap: one deref + one range compare.
static inline bool is_material_vt(uintptr_t obj) {
    if (!rd(obj)) return false;
    uintptr_t vt = *(uintptr_t*)obj;
    if (vt < addr::g_base) return false;
    uintptr_t ida = vt - addr::g_base + 0x140000000ull;
    return ida >= 0x140bad000ull && ida < 0x140bae000ull;   // nDraw::Material family vtable neighborhood
}

// husk-SWEEP: walk the holder graph testing every edge against the ENGINE-WIDE
// husk set (quarantine::is_held_husk — every dead-held object from every subsystem/dtor). Nulling a husk edge lands
// on the engine's own null-check paths (the RTV logic, generalized). dying==0 => sweep mode (all husks);
// dying!=0 => legacy dtor-event mode (belt). NO per-dtor coverage gap can exist: husk-ness comes from the free
// chokepoint, not from which destructor ran.
static inline bool edge_dead(uintptr_t v, uintptr_t dying) {
    if (dying) return v == dying;                        // dtor-event belt mode
    if (!v) return false;
    // UNCOMMITTED HEURISTIC REMOVED: it fired 359,308 times in one run — a false-positive storm. On a
    // mis-typed field read it turned garbage into a destructive null; and it is the one branch that made mis-typed
    // reads harmful. Removing it makes a garbage edge_dead simply return false (nulls nothing). A genuinely
    // dangling pointer is caught by the timeline husk set (unambiguous); a wild uncommitted VALUE is not a husk we
    // can prove dead by construction — do not re-add a byte heuristic.
    // DEAD-SENTINEL check (restoring an earlier state must release what was created after it; allocator-agnostic):
    // the engine writes the dead-sentinel vtable (0x140A6A510) only after a destructor runs — it is an UNAMBIGUOUS
    // death marker (unlike vtable==0, which is also the transient mid-CONSTRUCTION state: the vtable==0 test crashed
    // the game at frame 2 of a match by nulling edges to objects being built, refuted on an earlier build, do not re-add).
    // Self-reverting: a rollback that restores the object alive restores its real vtable => not nulled.
    // MIGRATION SHADOW (default off; id_oracle_probe.flag arms it): the husk+sentinel legs here are exactly what
    // id_oracle::is_dead() wraps — cross-check them so a long run proves the oracle faithful before edge_dead flips to it.
    bool dead;
    if (quarantine::is_held_husk(v)) { _InterlockedIncrement64(&c_by_husk); dead = true; }   // FUN_1404cb350-tracked husk (timeline)
    else if (g_dead_sentinel && rd(v) && *(uintptr_t*)v == g_dead_sentinel) { _InterlockedIncrement64(&c_by_deadvt); dead = true; }
    else dead = false;
    if (id_oracle::probe_enabled()) id_oracle::probe_dead(v, dead, "material.edge_dead");
    return dead;
}

// TREE-DEEP BELT (closes the variant-tree crash, coverage half 2): variant trees nest arbitrarily; the old one-level
// child pass missed holders 2+ levels down (crash: parent 0x849853C0 deep in a tree, child destructed invisibly,
// parent's own dtor cascade walked the dead object 28f post-rollback). Recurse the tree TYPE-DISPATCHED: each family
// member's child slots read at ITS class's offsets (variant 0x28: +0x18/+0x20; full 0xE0: +0x98/+0xa0), UNKNOWN
// family vtables not descended (stricter typing than before, never looser). Depth-capped + shared node guard.
static int mat_child_offs(uintptr_t m, const int** offs) {
    static const int V[2] = { 0x18, 0x20 }, M[2] = { 0x98, 0xa0 };
    if (!rd(m)) return 0;
    uintptr_t vt = *(uintptr_t*)m;
    if (vt < addr::g_base) return 0;
    uintptr_t ida = vt - addr::g_base + 0x140000000ull;
    if (ida == 0x140badfa0ull || ida == 0x140badfe0ull) { *offs = V; return 2; }   // 0x28 variants
    if (ida == 0x140badee0ull) { *offs = M; return 2; }   // 0xE0 Material (0x140badf40 is not in this family — never interpret it)
    return 0;                                             // in-family-range but unknown layout: do not interpret
}
// GENERATION-VALIDATED SEVER (the Material ABA/reuse close).
// The husk/sentinel tests answer "is the target DEAD?" — but a pool-recycled Material slot is not dead, it's
// ALIVE AS A new OBJECT (the crash: parent's child was recycled in-place, id +0x8 bumped 0x802F→0x806B, vtable
// went 0x140badee0→0). A dead-object check can't catch "the slot you point at got replaced" — that's ABA, and the
// only correct-by-construction close is GENERATION VALIDATION (the serial-gate model, proven for the allocator).
// We validate against the GAME'S OWN identity: the object's +0x8 generation id (immutable during a life, bumped on
// every recycle). Per (parent-slot-address), remember (child, child.id); if the slot still points at the same
// child but its id changed, the slot was recycled in-place ⇒ the edge is stale ⇒ SEVER. Severs only on that exact
// signature: a legit pointer UPDATE (S: C→C2) has a different child (not the recycle case); a stable live object's
// id never changes ⇒ zero false-positive. Epoch-invalidated on rollback so a restore can't trigger a spurious
// sever (the shadow re-captures fresh over the next frames; the crash fires ~79f post-rb, ample capture window).
static constexpr uint32_t ESH_BITS = 19, ESH_CAP = 1u << ESH_BITS;   // 512K edge slots
static struct { uintptr_t slot; uintptr_t child; uint64_t id; uint32_t epoch; } g_esh[ESH_CAP];
static volatile long g_esh_epoch = 1;                                // bumped on rollback (lazy invalidate)
static volatile LONG64 c_sev_aba = 0;
void identity_on_rollback() { _InterlockedIncrement(&g_esh_epoch); } // wired at the resim rollback site
static inline bool edge_recycled(uintptr_t slot, uintptr_t child) {
    if (!rd(child) || !rd(child + 0x10)) return false;              // need the id at +0x8 readable
    uint64_t cur = *(uint64_t*)(child + 0x8);
    uint32_t ep = (uint32_t)g_esh_epoch;
    uint32_t k = (uint32_t)((slot >> 3) * 2654435761u) & (ESH_CAP - 1);
    for (uint32_t i = 0; i < 8; i++) { auto& e = g_esh[(k + i) & (ESH_CAP - 1)];
        if (e.slot == slot) {
            if (e.epoch == ep && e.child == child && e.id != cur) { e.id = cur; return true; }   // in-place recycle = ABA
            e.child = child; e.id = cur; e.epoch = ep; return false;                              // update
        }
        if (e.slot == 0 || e.epoch != ep) { e.slot = slot; e.child = child; e.id = cur; e.epoch = ep; return false; }  // claim/reclaim
    }
    return false;                                                   // cluster full: fail-open (no false sever)
}

static void sever_tree(uintptr_t m, uintptr_t dying, int depth, int* guard) {
    const int* offs; int n = mat_child_offs(m, &offs);
    if (!n || depth > 6) return;
    if (++(*guard) > 16384) { _InterlockedIncrement64(&c_walk_cap); return; }
    for (int i = 0; i < n; i++) {
        uintptr_t* ch = (uintptr_t*)(m + offs[i]);
        uintptr_t v = *ch;
        if (edge_dead(v, dying)) { *ch = 0; _InterlockedIncrement64(&c_sev_child); }
        else if (v) {
            // GENERATION VALIDATION (sweep mode only — dying==0): sever a child whose slot was recycled in-place.
            if (!dying && edge_recycled((uintptr_t)ch, v)) { *ch = 0; _InterlockedIncrement64(&c_sev_aba); continue; }
            sever_tree(v, dying, depth + 1, guard);
        }
    }
}

// RECYCLED-NON-OBJECT test (the 0x1405E4F79 close — a child that's bad AT RESTORE, no transition to detect):
// the crash child's first qword is 0x414000004360E666 (a pair of FLOATS) used as a vtable ⇒ virtual call crashes.
// A non-zero value OUTSIDE the module's vtable range is definitely a recycled non-object (floats/garbage), never a
// valid polymorphic object — unambiguous, safe to sever. vtable==0 is deliberately EXCLUDED (that's the ambiguous
// mid-construction case that broke match-start; the dead-sentinel test in edge_dead covers the post-dtor case).
static inline bool recycled_nonobject(uintptr_t child) {
    if (!rd(child)) return false;
    uintptr_t vt = *(uintptr_t*)child;
    if (vt == 0) return false;                       // mid-construction ambiguous — do not sever
    if (vt < addr::g_base) return true;              // non-module low value = garbage/float
    return (vt - addr::g_base) >= 0x2000000ull;      // out of the module's .rdata vtable range = garbage/float
}

// DOMAIN-VALID-OR-NULL (the render-algebra close — dtor-SITE variant of recycled_nonobject).
// The crash (0x1405DA4B5): a Material dtor releases its child via `mov (%rcx),%rax; call *(%rax)` (fe0 slot 0) or
// `call *0x28(%rax)` (ee0), where child is NON-NULL but its vtable is 0 — a render-timeline-destructed child the
// restored holder still points at (real-freed/coalesced husk). Every release site NULL-guards the child but none
// validate its vtable; so the fix is to make the child domain-valid-or-NULL before orig_dtor runs, so the engine's
// OWN `test rcx,rcx; je` skip-branch fires and the dead vtable is never dispatched (fault made UNREPRESENTABLE).
// KEY DISTINCTION vs the sweep's recycled_nonobject: here we INCLUDE vtable==0. At a dtor the object is unambiguously
// mid-teardown, so vtable==0 is POST-DEATH, never the mid-CONSTRUCTION ambiguity that broke match-start (an earlier build,
// which was a periodic SWEEP nulling at arbitrary graph points). Out-of-arena children are LEFT untouched (rd()==0 =>
// not our domain; an ee0 COM-like child proceeds to its real release => false-positive-free). Same predicate shape
// as the shipped rtv_probe.cpp wrapper_dead(), plus the dead-sentinel leg.
static inline bool husk_child_dtor(uintptr_t child) {
    if (!rd(child)) return false;                                 // out-of-arena => not our domain => leave it (COM-safe)
    uintptr_t vt = *(uintptr_t*)child;
    if (vt == 0) return true;                                     // DEAD — unambiguous AT A DTOR site (never mid-ctor here)
    if (g_dead_sentinel && vt == g_dead_sentinel) return true;    // engine's post-dtor dead-object marker (0x140A6A510)
    if (vt < addr::g_base) return true;                           // non-module low value = recycled garbage/float
    return (vt - addr::g_base) >= 0x2000000ull;                   // out of module's .rdata vtable range = garbage/float
}
// Pre-null SELF's OWN husk children (outgoing edges) at dtor entry. Writes only to the dying Material's own body
// (self+off) => desync-safe: Material teardown is a render/asset output leaf, structurally disjoint from every
// gp_crc range (fighter segs + named singletons), so GAMEPLAY-diverged stays 0. Cheap: 2 reads of self, O(1) — it
// does not walk the sUnit spine (that is belt/sweep). A live child (real in-module vtable) is left for orig_dtor to
// release normally; only a proven husk is nulled ⇒ zero behavior change except where a crash would otherwise fire.
static void validate_own_children(uintptr_t self, const int* offs, int n, volatile LONG64* fam) {
    if (!resim::engine_enabled() || !rd(self)) return;
    for (int i = 0; i < n; i++) {
        uintptr_t slot = self + (uintptr_t)offs[i];
        if (!rd(slot)) continue;
        uintptr_t c = *(uintptr_t*)slot;
        if (c && husk_child_dtor(c)) {
            *(uintptr_t*)slot = 0;
            _InterlockedIncrement64(&c_own_nulled);
            _InterlockedIncrement64(fam);
        }
    }
}

// EFFECT-CHILD LIST gen-validation (the K_EFFECT ABA, fixed at the site the sweep missed). The engine's own walk (0x1405E4F79: mov r8,[child]; call [r8+0xa8]) virtual-calls every child in an
// entity's +0x218 list. A recycled/dead child ⇒ crash. The sweep only checked +0x218 as a single edge; now WALK
// the list and UNLINK any child that is dead (husk/sentinel), a recycled-non-object (float-vtable), or in-place-
// recycled (gen-id changed under a stable link). Unlink = drop (skip the node), never a rebuild. Cheap:
// arena-bitset rd(), not the belt's per-node VirtualQuery (that was the belt's 400ms, not the walk itself).
static void sever_effect_list(uintptr_t node, uintptr_t dying) {
    uintptr_t prev_slot = node + 0x218;
    if (!rd(prev_slot)) return;
    uintptr_t head = *(uintptr_t*)prev_slot;
    // HEAD-RECIPROCITY GATE (the frame-2 .rdata-write regression fix): +0x218 is an effect-child
    // list head only when the head is a coherent member (head+0x10 == node). On NON-effect entities +0x218 is a
    // different field — without this gate we misread it as a list and WRITE our unlink into it, corrupting the entity
    // (crash 0x140002A7C, WRITE into .rdata). This bounds the sever to real effect-lists. (A head that is itself the
    // recycled child breaks reciprocity and is skipped — accepted: no-regression beats catching that rarer case.)
    if (!head || !rd(head) || !rd(head + 0x18) || !rd(head + 0x10) || *(uintptr_t*)(head + 0x10) != node) return;
    int hops = 0;
    uintptr_t child = head;
    while (child && rd(child) && rd(child + 0x18) && hops++ < 512) {
        uintptr_t next = *(uintptr_t*)(child + 0x18);
        if (next == child) next = 0;                 // self-loop guard
        bool bad = edge_dead(child, dying)
                 || (!dying && (recycled_nonobject(child) || edge_recycled(prev_slot, child)));
        if (bad) { *(uintptr_t*)prev_slot = next; _InterlockedIncrement64(&c_sev_aba); }   // UNLINK
        else prev_slot = child + 0x18;               // advance only when kept
        child = next;
    }
}

static void sever_all(uintptr_t dying) {
    uintptr_t sp = addr::resolve(IDA_SUNIT);
    if (!sp) return;
    uintptr_t sunit = *(uintptr_t*)sp;
    if (!rd(sunit)) return;
    int guard = 0;
    for (int line = 0; line < 128; line++) {
        bool fighter_line = (line == 7 || line == 8);            // gp_crc-hashed segs: touch only the +0x278 table here
        uintptr_t node = rd(sunit + 0x50 + (uintptr_t)line * 0x30 + 8) ? *(uintptr_t*)(sunit + 0x50 + (uintptr_t)line * 0x30) : 0;
        int hops = 0;
        while (node && rd(node) && hops++ < 512) {
            if (++guard > 16384) { _InterlockedIncrement64(&c_walk_cap); return; }   // LOUD coverage gap, never wrong writes
            // (a) the 16-slot Material table @+0x278 (0x28 stride, ptr at slot+0) — unhashed even on fighters
            if (rd(node + 0x278) && rd(node + 0x4F8 - 8)) {
                for (int s = 0; s < 16; s++) {
                    uintptr_t* slot = (uintptr_t*)(node + 0x278 + (uintptr_t)s * 0x28);
                    uintptr_t m = *slot;
                    if (edge_dead(m, dying)) { *slot = 0; _InterlockedIncrement64(&c_sev_table); continue; }
                    if (m) sever_tree(m, dying, 0, &guard);   // TREE-DEEP: full variant tree, type-dispatched offsets
                }
            }
            // (a2) entity-level holder edges the census confirmed unguarded + in gp_crc hash gaps (safe all lines):
            // +0x98/+0xa0 render sub-objects (engine dtor FUN_1405DA2E0 has NO null check — verified), +0x218
            // effect-child list head (CRASH-CONFIRMED offset). Scalar husk/wild-value checks (not list walks yet).
            { const int ent_edges[2] = { 0x98, 0xa0 };   // render sub-objects (single edges)
              for (int ei = 0; ei < 2; ei++) {
                  uintptr_t* slot = (uintptr_t*)(node + ent_edges[ei]);
                  if (rd((uintptr_t)slot) && edge_dead(*slot, dying)) { *slot = 0; _InterlockedIncrement64(&c_sev_child); }
              } }
            sever_effect_list(node, dying);   // +0x218 effect-child LIST — walk + unlink recycled/dead (0x1405E4F79 close)
            if (!fighter_line) {
                // (b) the dynamic Material* array {base@+0x110, count@+0x118} — hashed on fighters, skip there
                if (rd(node + 0x110) && rd(node + 0x118)) {
                    uintptr_t base = *(uintptr_t*)(node + 0x110);
                    uint32_t  cnt  = *(uint32_t*)(node + 0x118); if (cnt > 4096) cnt = 0;
                    if (base && rd(base) && cnt && rd(base + (uintptr_t)(cnt - 1) * 8)) {
                        for (uint32_t k = 0; k < cnt; k++) {
                            uintptr_t* e = (uintptr_t*)(base + (uintptr_t)k * 8);
                            uintptr_t m = *e;
                            if (edge_dead(m, dying)) { *e = 0; _InterlockedIncrement64(&c_sev_array); continue; }
                            if (m) sever_tree(m, dying, 0, &guard);   // TREE-DEEP: full variant tree, type-dispatched offsets
                        }
                    }
                }
            }
            node = rd(node + 0x18) ? *(uintptr_t*)(node + 0x18) : 0;
        }
    }
    // (c) node-to-node edges: the dying object's SIBLINGS in the same family may hold it via +0x18/+0x20
    // (variant) or +0x98/+0xa0 (0xE0 Material). The TREE-DEEP recursion above now covers every holder reachable
    // from an entity table/array; unreachable free-floating siblings remain out of scope (LOUD walk_cap if the
    // guard trips). Field-typed exact-equality severs are the bounded, safe scope.
}

// ALL-4 FAMILY DTORS (closes the variant-tree crash, coverage half 1): the belt hooked only the 0x140badfe0 variant
// dtor (0x1405DA470) — 3 of 4 family classes died INVISIBLY (binary slot-0 census: 0x140badfa0→0x1405DA3E0 [the
// crashing object's class], 0x140badee0→0x1405DA500, 0x140badf40→0x1405DE030). A death the belt never sees =
// no severing = a holder dereferences the dead object post-rollback. Every family death now fires the belt — synchronous,
// exact-match (edge==dying), zero rebirth/false-positive risk by timing (severed before the slot can be reused).
static void (*orig_dtor_fa0)(void*) = nullptr;   // 0x1405DA3E0 (vtbl 0x140badfa0)
static void (*orig_dtor_ee0)(void*) = nullptr;   // 0x1405DA500 (vtbl 0x140badee0)
static void (*orig_dtor_base2e0)(void*) = nullptr;   // 0x1405DA2E0 (ee0 base/D2 — 7 DISJOINT outer-class callers, verified no fe0/ee0 chain; the 0x1405DA324 crash class, invisible today)
// f40 REMOVED: 0x1405DE030 is not a Material dtor — it was called with a STACK address as arg1 (rcx ~ rsp) and
// takes >1 args (the 1-arg thunk clobbered rdx => READ 0x72A0 crash at +0x20E, frame=1, no rollback). 0x140badf40
// was never census-confirmed (0x3B30 from the 3 sibling dtors, a different slot pattern = a different class). Only
// census-proven family members get belted.
static const int OWN_FE0[2] = { 0x18, 0x20 };   // fe0 variant children (the 0x1405DA4B5 crash slot + its sibling)
static const int OWN_EE0[2] = { 0x98, 0xa0 };   // ee0 / ee0-base children (release via call *0x28(child->vt))
static inline void belt(void* self) {
    if (resim::engine_enabled() && self) { _InterlockedIncrement64(&c_fires); sever_all((uintptr_t)self); }
}
// render-algebra: validate SELF's OWN children (outgoing edges) before orig_dtor, IN ADDITION to belt's incoming sever
static void hk_dtor(void* self)     { belt(self); validate_own_children((uintptr_t)self, OWN_FE0, 2, &c_own_fe0); orig_dtor(self); }
static void hk_dtor_fa0(void* self) { belt(self); orig_dtor_fa0(self); }   // fa0: +0x18 is a 32-bit flag, +0x20 mgr-mediated — NO child validation (would false-positive)
static void hk_dtor_ee0(void* self) { belt(self); validate_own_children((uintptr_t)self, OWN_EE0, 2, &c_own_ee0); orig_dtor_ee0(self); }
// base2e0: validate-ONLY (no belt) — closes the base-dtor self-child crash (0x1405DA324) without adding a 4th
// full-spine sever_all to the effect/entity-churn path (belt is the per-death churn cost; validate is O(1) on self).
static void hk_dtor_base2e0(void* self) { validate_own_children((uintptr_t)self, OWN_EE0, 2, &c_own_base2e0); orig_dtor_base2e0(self); }

// per-frame husk-SWEEP (forward play only; the crashes fire 33-156f post-rollback in forward play — a per-frame
// sweep closes the window to <=1 frame). Cost: the sUnit walk + O(1) hash per edge; measured via STABILITY.
// The death-chokepoint hooks (composite-tail/matbase), the TAG-REG probe, and the recycler-hunt watchpoint were
// removed: the longest clean run (78k frames) was set by sweep+sentinel alone, and every mechanism added since ran
// shorter. alloc_invariants::repair_freelists is the one later addition kept.
static volatile LONG64 c_sweeps = 0;
// CHURN-AUDIT timing: the per-frame full-spine sweep grows with entity count — a per-frame churn suspect.
static volatile LONG64 c_sweep_us_total = 0, c_sweep_max_us = 0, c_sweep_spikes = 0;
static LARGE_INTEGER g_swf = {};
void sweep() {
    if (!resim::engine_enabled() || resim::resim_active()) return;
    _InterlockedIncrement64(&c_sweeps);
    LARGE_INTEGER t0; QueryPerformanceCounter(&t0);
    sever_all(0);                                          // 0 = husk-set mode (all dead-held objects, engine-wide)
    LARGE_INTEGER t1; QueryPerformanceCounter(&t1);
    if (!g_swf.QuadPart) QueryPerformanceFrequency(&g_swf);
    long long us = g_swf.QuadPart ? (t1.QuadPart - t0.QuadPart) * 1000000 / g_swf.QuadPart : 0;
    _InterlockedAdd64(&c_sweep_us_total, us);
    if (us > c_sweep_max_us) c_sweep_max_us = us;
    if (us > 2000) {   // >2ms single per-frame sweep = a churn hitch contributor
        LONG64 n = _InterlockedIncrement64(&c_sweep_spikes);
        if (n <= 20 || (n & 63) == 0) { bool sw = rblog::is_suppressed(); rblog::suppress(false);
            rblog::write("CHURN-SPIKE[sweep #%lld]: per-frame sever_all took %lld us (>2ms) — full sUnit-spine husk-sweep during churn", (long long)n, us);
            rblog::suppress(sw); }
    }
}

void init() {
    g_dead_sentinel = addr::resolve(0x140A6A510ULL);     // engine's post-dtor dead-vtable marker (rebased)
    struct { uintptr_t ida; void* hk; void** orig; const char* tag; } H[4] = {
        { IDA_DTOR,        (void*)&hk_dtor,         (void**)&orig_dtor,         "fe0/0x1405DA470" },
        { 0x1405DA3E0ULL,  (void*)&hk_dtor_fa0,     (void**)&orig_dtor_fa0,     "fa0/0x1405DA3E0" },   // the crashing object's class
        { 0x1405DA500ULL,  (void*)&hk_dtor_ee0,     (void**)&orig_dtor_ee0,     "ee0/0x1405DA500" },
        { 0x1405DA2E0ULL,  (void*)&hk_dtor_base2e0, (void**)&orig_dtor_base2e0, "ee0-base/0x1405DA2E0" },   // render-algebra: 0x1405DA324 class, validate-only
    };
    int armed = 0;
    for (int i = 0; i < 4; i++) {
        uintptr_t t = addr::resolve(H[i].ida);
        if (t && MH_CreateHook((void*)t, H[i].hk, H[i].orig) == MH_OK) armed++;
        else rblog::write("MATERIAL-GUARD: dtor %s hook FAILED", H[i].tag);
    }
    rblog::write("MATERIAL-GUARD ARMED: %d/4 family dtors (fe0+fa0+ee0+ee0-base) + TREE-DEEP sever + per-frame husk-sweep + render-algebra domain-valid-or-null own-child guard (fe0{0x18,0x20} ee0/base{0x98,0xa0}; fa0 excluded) (dead-sentinel 0x%llX) — engine_enabled-gated",
                 armed, (unsigned long long)g_dead_sentinel);
}

void report() {
    if (!c_sweeps && !c_fires) return;
    bool w = rblog::is_suppressed(); rblog::suppress(false);
    long long dadd = 0, dpruned = 0, ddrop = 0; quarantine::default_husk_stats(&dadd, &dpruned, &ddrop);
    rblog::write("HUSK-SWEEP: sweeps=%lld dtor_fires=%lld severed{table=%lld array=%lld child=%lld} walk_cap=%lld | BY{husk=%lld uncommitted=%lld deadvt=%lld} | DEFAULT-HUSK{stamped=%lld pruned=%lld realloc-dropped=%lld} ABA-recycle-severs=%lld (generation-validated: an in-place-recycled Material slot the husk/sentinel tests structurally cannot catch)",
                 (long long)c_sweeps, (long long)c_fires, (long long)c_sev_table, (long long)c_sev_array, (long long)c_sev_child, (long long)c_walk_cap,
                 (long long)c_by_husk, (long long)c_by_uncommitted, (long long)c_by_deadvt, dadd, dpruned, ddrop, (long long)c_sev_aba);
    rblog::write("OWN-CHILD-GUARD (render-algebra): nulled=%lld {fe0=%lld ee0=%lld base2e0=%lld} — dtor-site domain-valid-or-null (the 0x1405DA4B5 class made unrepresentable)",
                 (long long)c_own_nulled, (long long)c_own_fe0, (long long)c_own_ee0, (long long)c_own_base2e0);
    rblog::write("CHURN-SWEEP timing: sweeps=%lld avg=%lld us max=%lld us spikes(>2ms)=%lld — per-frame full-spine sever_all (churn-audit)",
                 (long long)c_sweeps, (long long)(c_sweeps ? c_sweep_us_total / c_sweeps : 0), (long long)c_sweep_max_us, (long long)c_sweep_spikes);
    rblog::suppress(w);
}

} // namespace material_guard
