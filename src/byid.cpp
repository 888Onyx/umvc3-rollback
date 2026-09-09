// byid.cpp — the by-identity dynamic-restore engine, SHADOW build.
// See byid.h.
//
// The SPIN-BREAKER: instead of waiting for whichever stale head happens to
// crash then probing that one head, byid SHADOW re-resolves every carrier edge against the post-arena::load
// graph every rollback and CLASSIFIES the incoherence by carrier — decoupled from which head happens to fault.
// SHADOW = zero WRITES: the arena's byte-reverted value always stands; byid only re-resolves + compares + logs.
//
// CARRIERS measured (each = a set of pointer EDGES whose referent is a live game object):
// K_EFFECT: effect +0x218 child list (parent effect -> child -> next). [clean on a long run: the splice works]
// K_ENTREF: every sUnit-pool entity's body [0x8,0x1000) -> another pool entity (the scheduler spine +0x18/+0x20
// and every internal entity->entity reference). This is the carrier the live crashes rotate in
// (FUN_1402a21f0 entity-update reading a garbage pointer).
// K_TAIL: the sCharacter [0x2600,0x4000) + sAction [0x8E0,0x2000) singleton TAILS -> pool entities
// (the pointer-dense tails gp_crc carved out and deferred to runtime — byid.h's declared scope).
//
// At save(N): walk the live graph, capture each edge = (field addr, pointer value @N, referent vtable @N, identity).
// At restore(N) (PH_POST_LOAD, before dead_vtable_unlink mutates the graph): for each saved edge, examine the byte-reverted link
// + its referent and CLASSIFY any incoherence, tagging by arena residency:
// LINK-GARBAGE: the field now holds a non-pointer (e.g. 0x480) — corrupted scalar where a pointer should be
// LINK-DIFF: the field reverted to a different (canon) value than frame N (skew / its page lost)
// CHILD-GONE: link restored, referent no longer committed
// CHILD-VT0: referent vtable reads 0 — the canonical orphan-zero signature
// VT-SUB: referent slot reused by a different type (wrong-identity-same-slot — validator-blind stale reference)
// in-arena + was_orphaned_last_load => carrier (c) (arena restore-coherence); out-of-arena => carrier (a)
// (external defer/re-acquire). Which of the two dominates is the open question.
#include "byid.h"
#include "addr.h"
#include "arena.h"
#include "log.h"
#include "idspine.h"
#include <windows.h>
#include <cstdint>

namespace byid {

// ---- carrier roots / offsets (confirmed: dead_vtable_unlink.cpp scheduler walk, effect_splice.cpp child shape, gp_crc.cpp roots) ----
static constexpr uintptr_t SCHED_ROOT_IDA = 0x140E17698ULL; // *(resolve) = sUnit pool object
static constexpr uintptr_t SCHAR_ROOT_IDA = 0x140D44A70ULL; // *(resolve) = sCharacter singleton
static constexpr uintptr_t SACT_ROOT_IDA  = 0x140D47E68ULL; // *(resolve) = sAction singleton
static constexpr int       SCHED_LINES    = 128;
static constexpr uintptr_t LINE_HEAD_OFF  = 0x58;           // sunit + 0x58 + line*0x30 = line head
static constexpr uintptr_t LINE_STRIDE    = 0x30;
static constexpr uintptr_t ENT_NEXT_OFF   = 0x20;           // scheduler entity -> next (chain within line)
static constexpr uintptr_t EFFECT_HEAD218 = 0x218;          // effect -> child-list head
static constexpr uintptr_t CHILD_OWNER    = 0x10;           // effect-child -> parent effect (back-pointer)
static constexpr uintptr_t CHILD_NEXT     = 0x18;           // effect-child -> next child
static constexpr uintptr_t ENT_SCAN_LO    = 0x08;           // K_ENTREF: scan entity body [0x8, 0x1000) for pool-ptrs
static constexpr uintptr_t ENT_SCAN_HI    = 0x1000;
static constexpr uintptr_t SCHAR_TAIL_LO  = 0x2600, SCHAR_TAIL_HI = 0x4000;
static constexpr uintptr_t SACT_TAIL_LO   = 0x08E0, SACT_TAIL_HI  = 0x2000;
static constexpr int       WALK_MAX       = 512;            // per-line / per-list cap (cycle guard)

enum Carrier { K_EFFECT = 0, K_ENTREF = 1, K_TAIL = 2, K_NCARRIER = 3 };
static const char* CARRIER_NAME[K_NCARRIER] = { "effect+0x218", "entity-ref", "singleton-tail" };

static constexpr int MAX_EDGES = 8192;   // per frame; capped + logged if exceeded
static constexpr int RING      = 64;     // >= arena ring depth (60) + slack
static constexpr int MAX_POOL  = 4096;   // sUnit-pool entity addresses captured per frame (for membership test)

struct CapEdge {
    uintptr_t src_addr;     // the field holding the link
    uintptr_t link_val;     // pointer value at save = referent addr @ frame N
    uintptr_t back_expect;  // expected referent back-pointer value (0 => no back check)
    uint32_t  ref_vtlo;     // low32(*(referent)) at save — vtable identity
    uint16_t  back_off;     // offset of the referent's back-pointer (0 => skip)
    uint8_t   carrier;      // K_EFFECT / K_ENTREF / K_TAIL
    uint32_t  id_a, id_b;   // identity for logging (e.g. line, chain/birth)
    int64_t   ref_stamp;    // idspine birth-stamp of the referent @ save — the reuse-proof when coordinate (STAMP-SUB)
};
struct FrameCap { int n; int frame; bool overflow; CapEdge e[MAX_EDGES]; };

// DLL static (.bss) — not VirtualAlloc (arena IAT-hook would redirect it into the reverted region) and not the
// game .data sandwich. byid's capture metadata must survive the rollback untouched.
static FrameCap g_cap[RING];
static uintptr_t g_pool[MAX_POOL];   // sorted sUnit-pool entity addresses (rebuilt each save; membership test)
static int       g_pool_n = 0;

static bool g_enabled = false;
static Mode g_mode = MODE_SHADOW;
static bool g_auth_effect = false;   // K_EFFECT authoritative: splice stamp-incoherent children from the reverted +0x218 (the 0x14080D44D fix; default OFF — SHADOW measures first)

// session tallies (per carrier)
static long g_save_frames, g_restore_frames;
static long g_seen[K_NCARRIER], g_match[K_NCARRIER], g_uac[K_NCARRIER], g_a[K_NCARRIER], g_c[K_NCARRIER];

static inline bool canon(uintptr_t p) { return p >= 0x10000ULL && p < 0x800000000000ULL; }
static inline bool committed8(uintptr_t p) {
    if (!canon(p)) return false;
    if (arena::is_arena_addr(p)) return arena::is_committed_addr(p);   // ns bitmap, not a VirtualQuery syscall
    MEMORY_BASIC_INFORMATION mbi;
    if (!VirtualQuery((void*)p, &mbi, sizeof(mbi))) return false;
    return mbi.State == MEM_COMMIT && !(mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD));
}
static inline uintptr_t rdptr(uintptr_t p) { return committed8(p) ? *(uintptr_t*)p : 0; }
static inline bool orphaned_c(uintptr_t a) { return arena::is_arena_addr(a) && arena::was_orphaned_last_load(a); }

// Is the captured child a COHERENT object at restore? committed + vtable + owner-reciprocity. We DELIBERATELY do
// not gate the splice on the idspine stamp: the stamp table is not rewound across rollback (orig() re-stamps slabs
// during resim), so a legitimately byte-reverted frame-N child's LIVE serial OVERSHOOTS its captured stamp => a
// stamp gate would FALSE-SPLICE genuine children. vtable+owner prove the MEMORY is the
// right object — which is what prevents the crash; the observed stale reference impostor fails the VTABLE check (its qword-0 is
// reused garbage/float). A same-type+same-owner reused child (the only case the stamp uniquely catches) walks as a
// valid child and does not crash, so keeping it is safe (worst case: minor effect drift, re-derived by orig).
// STAMP-SUB stays a SHADOW-logged signal in restore_frame for visibility, not a splice trigger.
static bool child_coherent(const CapEdge& e) {
    uintptr_t child = e.link_val;
    if (!committed8(child)) return false;
    if ((uint32_t)rdptr(child) != e.ref_vtlo) return false;
    if (e.back_off && rdptr(child + e.back_off) != e.back_expect) return false;
    return true;
}

// membership: is addr a captured pool entity? (g_pool is sorted ascending)
static bool in_pool(uintptr_t a) {
    int lo = 0, hi = g_pool_n - 1;
    while (lo <= hi) { int m = (lo + hi) >> 1; if (g_pool[m] == a) return true; if (g_pool[m] < a) lo = m + 1; else hi = m - 1; }
    return false;
}

// Build the sorted pool-entity address set (used for K_ENTREF / K_TAIL membership). Returns count.
static void build_pool_set() {
    g_pool_n = 0;
    uintptr_t slot = addr::resolve(SCHED_ROOT_IDA);
    if (!committed8(slot)) return;
    uintptr_t sunit = *(uintptr_t*)slot;
    if (!canon(sunit)) return;
    for (int line = 0; line < SCHED_LINES; line++) {
        uintptr_t hs = sunit + LINE_HEAD_OFF + (uintptr_t)line * LINE_STRIDE;
        if (!committed8(hs)) continue;
        uintptr_t ent = *(uintptr_t*)hs;
        for (int chain = 0; chain < WALK_MAX && canon(ent) && committed8(ent); chain++) {
            if (g_pool_n < MAX_POOL) g_pool[g_pool_n++] = ent;
            uintptr_t nx = rdptr(ent + ENT_NEXT_OFF);
            if (nx == ent) break;
            ent = nx;
        }
    }
    // insertion sort (pool is small, hundreds) so in_pool() can binary-search
    for (int i = 1; i < g_pool_n; i++) {
        uintptr_t v = g_pool[i]; int j = i - 1;
        while (j >= 0 && g_pool[j] > v) { g_pool[j + 1] = g_pool[j]; j--; }
        g_pool[j + 1] = v;
    }
}

// ---- the capture (save) ----
static void cap_edge(FrameCap& fc, uint8_t carrier, uintptr_t field, uintptr_t val,
                     uint16_t back_off, uintptr_t back_expect, uint32_t id_a, uint32_t id_b) {
    if (fc.n >= MAX_EDGES) { fc.overflow = true; return; }
    CapEdge& e = fc.e[fc.n++];
    e.src_addr = field; e.link_val = val; e.back_off = back_off; e.back_expect = back_expect;
    e.ref_vtlo = (uint32_t)rdptr(val); e.carrier = carrier; e.id_a = id_a; e.id_b = id_b;
    e.ref_stamp = idspine::stamp_of_object(val);   // the when of the referent @ frame N (STAMP-SUB at restore)
}

void save_frame(int frame) {
    if (!g_enabled) return;
    FrameCap& fc = g_cap[((unsigned)frame) % RING];
    fc.n = 0; fc.frame = frame; fc.overflow = false;
    build_pool_set();

    // K_EFFECT — effect +0x218 child lists (parent reached via the same scheduler-rooted walk)
    uintptr_t slot = addr::resolve(SCHED_ROOT_IDA);
    uintptr_t sunit = committed8(slot) ? *(uintptr_t*)slot : 0;
    if (canon(sunit)) {
        for (int line = 0; line < SCHED_LINES; line++) {
            uintptr_t hs = sunit + LINE_HEAD_OFF + (uintptr_t)line * LINE_STRIDE;
            if (!committed8(hs)) continue;
            uintptr_t ent = *(uintptr_t*)hs;
            for (int chain = 0; chain < WALK_MAX && canon(ent) && committed8(ent); chain++) {
                uintptr_t nextent = rdptr(ent + ENT_NEXT_OFF);
                // K_EFFECT: this entity's +0x218 child list
                uintptr_t head = rdptr(ent + EFFECT_HEAD218);
                if (canon(head) && committed8(head) && rdptr(head + CHILD_OWNER) == ent) {
                    uintptr_t field = ent + EFFECT_HEAD218, child = head;
                    for (int bi = 0; bi < WALK_MAX && canon(child) && committed8(child); bi++) {
                        cap_edge(fc, K_EFFECT, field, child, CHILD_OWNER, ent, (uint32_t)line, (uint32_t)bi);
                        uintptr_t nx = rdptr(child + CHILD_NEXT);
                        field = child + CHILD_NEXT;
                        if (nx == child) break;
                        child = nx;
                    }
                }
                // K_ENTREF: this entity's body [0x8,0x1000) -> any pool entity (spine + internal entity refs)
                for (uintptr_t off = ENT_SCAN_LO; off + 8 <= ENT_SCAN_HI; off += 8) {
                    uintptr_t f = ent + off;
                    if (!committed8(f)) { off = ((off >> 12) + 1) * 4096 - 8; continue; }   // skip uncommitted page
                    uintptr_t v = *(uintptr_t*)f;
                    if (canon(v) && in_pool(v))
                        cap_edge(fc, K_ENTREF, f, v, 0, 0, (uint32_t)line, (uint32_t)off);
                }
                if (nextent == ent) break;
                ent = nextent;
            }
        }
    }

    // K_TAIL — sCharacter / sAction singleton tails -> pool entities
    struct TailRoot { uintptr_t root_ida, lo, hi; };
    const TailRoot tails[2] = { { SCHAR_ROOT_IDA, SCHAR_TAIL_LO, SCHAR_TAIL_HI },
                                { SACT_ROOT_IDA,  SACT_TAIL_LO,  SACT_TAIL_HI } };
    for (int t = 0; t < 2; t++) {
        uintptr_t rs = addr::resolve(tails[t].root_ida);
        uintptr_t base = committed8(rs) ? *(uintptr_t*)rs : 0;
        if (!canon(base)) continue;
        for (uintptr_t off = tails[t].lo; off + 8 <= tails[t].hi; off += 8) {
            uintptr_t f = base + off;
            if (!committed8(f)) { off = ((off >> 12) + 1) * 4096 - 8; continue; }
            uintptr_t v = *(uintptr_t*)f;
            if (canon(v) && in_pool(v))
                cap_edge(fc, K_TAIL, f, v, 0, 0, (uint32_t)t, (uint32_t)off);
        }
    }
    g_save_frames++;
}

// ---- the re-resolve + classify (restore, SHADOW) ----
void restore_frame(int frame) {
    if (!g_enabled) return;
    FrameCap& fc = g_cap[((unsigned)frame) % RING];
    if (fc.frame != frame || fc.n == 0) return;   // no capture for this frame

    long seen[K_NCARRIER] = {0}, match[K_NCARRIER] = {0}, uac[K_NCARRIER] = {0}, a[K_NCARRIER] = {0}, c[K_NCARRIER] = {0};
    int logged = 0; long ss = 0;   // STAMP-SUB count — the idspine-NOT-rewound false positive (reverted==val@N); split it out of stale reference so the summary shows the RELIABLE stale-edge signal, not the noise
    for (int i = 0; i < fc.n; i++) {
        CapEdge& e = fc.e[i];
        int k = e.carrier; seen[k]++;
        bool bad = false; const char* kind = nullptr; bool ext = false; bool oz = false;

        uintptr_t reverted = committed8(e.src_addr) ? *(uintptr_t*)e.src_addr : (uintptr_t)-1;
        if (reverted != e.link_val) {
            bad = true;
            if (!canon(reverted)) { kind = "LINK-GARBAGE"; }   // field now holds a non-pointer (the 0x480 shape)
            else { kind = "LINK-DIFF"; }
            ext = !arena::is_arena_addr(e.src_addr); oz = orphaned_c(e.src_addr);
        } else {
            uintptr_t child = e.link_val;
            if (!committed8(child)) { bad = true; kind = "CHILD-GONE"; ext = !arena::is_arena_addr(child); oz = orphaned_c(child); }
            else {
                uint32_t vt = (uint32_t)rdptr(child);
                if (vt == 0) { bad = true; kind = "CHILD-VT0"; ext = !arena::is_arena_addr(child); oz = orphaned_c(child); }
                else if (vt != e.ref_vtlo) { bad = true; kind = "VT-SUB"; ext = !arena::is_arena_addr(child); oz = orphaned_c(child); }
                else if (e.back_off && rdptr(child + e.back_off) != e.back_expect) { bad = true; kind = "OWNER-BREAK"; oz = orphaned_c(child); }
                else { int64_t now = idspine::stamp_of_object(child);   // STAMP-SUB: same addr + same vtable, different birth-stamp = the slab was freed+reused (the stale reference the page-revert re-plants)
                       if (e.ref_stamp != 0 && now != 0 && now != e.ref_stamp) { bad = true; kind = "STAMP-SUB"; ss++; ext = !arena::is_arena_addr(child); oz = orphaned_c(child); } }
            }
        }

        if (!bad) { match[k]++; continue; }
        uac[k]++;
        if (ext) a[k]++; else c[k]++;
        if (g_mode == MODE_SHADOW && logged < 10) { logged++;
            // Surface the per-edge KIND through the freeze suppression window (the fix decision: CHILD-GONE/CHILD-VT0 =
            // referent gone/orphan-zeroed = safe to re-resolve/sever; VT-SUB/STAMP-SUB = referent reused by a
            // different identity = the desync-risk carrier; LINK-DIFF/GARBAGE = the field itself reverted wrong).
            bool ws = rblog::is_suppressed(); rblog::suppress(false);
            rblog::write("BYID-EDGE %s %s: field=0x%llX reverted=0x%llX val@N=0x%llX ref_vt@N=0x%08X id=(%u,0x%X) => carrier %s",
                CARRIER_NAME[k], kind, (unsigned long long)e.src_addr, (unsigned long long)reverted,
                (unsigned long long)e.link_val, e.ref_vtlo, e.id_a, e.id_b,
                ext ? "(a) EXTERNAL" : (oz ? "(c) ORPHAN-ZEROED" : "(c?) in-arena non-orphan — skew"));
            rblog::suppress(ws);
        }
    }

    // MODE_AUTHORITATIVE (K_EFFECT): re-thread each parent's +0x218 child list on the REVERTED graph, keeping
    // only stamp-coherent children — splicing out the dead/impostor child the page-revert re-planted (the
    // 0x14080D44D fix). Writes only the head field + each surviving child's +0x18 (never a dead node); clears
    // the +0x128 consume gate if the list empties. PH_POST_LOAD, threads frozen => single-threaded; pointer
    // fields only (safe by construction). Gated OFF by default (SHADOW measures the STAMP-SUB rate first).
    long spliced = 0, relisted = 0;
    if (g_auth_effect) {
        for (int i = 0; i < fc.n; i++) {
            if (fc.e[i].carrier != K_EFFECT || fc.e[i].id_b != 0) continue;   // start only at a list HEAD
            uintptr_t headfield = fc.e[i].src_addr;                            // == ent + 0x218
            uintptr_t ent = headfield - EFFECT_HEAD218;
            uintptr_t newhead = 0; int prev = -1;
            for (int j = i; j < fc.n && fc.e[j].carrier == K_EFFECT && fc.e[j].id_a == fc.e[i].id_a
                                     && fc.e[j].id_b == (uint32_t)(j - i); j++) {
                if (!child_coherent(fc.e[j])) { spliced++; continue; }         // dead/impostor => snip
                uintptr_t child = fc.e[j].link_val;
                if (prev < 0) newhead = child;
                else { uintptr_t pc = fc.e[prev].link_val; if (committed8(pc + CHILD_NEXT)) *(uintptr_t*)(pc + CHILD_NEXT) = child; }
                prev = j;
            }
            if (prev >= 0) { uintptr_t lc = fc.e[prev].link_val; if (committed8(lc + CHILD_NEXT)) *(uintptr_t*)(lc + CHILD_NEXT) = 0; }
            if (committed8(headfield)) { if (*(uintptr_t*)headfield != newhead) { *(uintptr_t*)headfield = newhead; relisted++; } }
            if (newhead == 0 && committed8(ent + 0x128)) *(uint16_t*)(ent + 0x128) = 0;   // emptied => clear the consume gate
        }
    }

    long tot_seen = 0, tot_uac = 0;
    for (int k = 0; k < K_NCARRIER; k++) {
        g_seen[k] += seen[k]; g_match[k] += match[k]; g_uac[k] += uac[k]; g_a[k] += a[k]; g_c[k] += c[k];
        tot_seen += seen[k]; tot_uac += uac[k];
    }
    g_restore_frames++;

    bool was = rblog::is_suppressed(); rblog::suppress(false);
    rblog::write("BYID-SHADOW frame %d%s: edges=%ld stale=%ld (reliable=%ld STAMP-SUB=%ld[noise:idspine-not-rewound]) | effect: %ld/%ld | entref: %ld/%ld (a%ld c%ld) | tail: %ld/%ld (a%ld c%ld)",
        frame, fc.overflow ? "(OVERFLOW)" : "", tot_seen, tot_uac, tot_uac - ss, ss,
        match[K_EFFECT], seen[K_EFFECT],
        match[K_ENTREF], seen[K_ENTREF], a[K_ENTREF], c[K_ENTREF],
        match[K_TAIL], seen[K_TAIL], a[K_TAIL], c[K_TAIL]);
    if (g_auth_effect) rblog::write("BYID-AUTH K_EFFECT: spliced %ld stamp-incoherent children, re-headed %ld lists (the 0x14080D44D fix)", spliced, relisted);
    rblog::suppress(was);
}

void report_and_reset() {
    bool was = rblog::is_suppressed(); rblog::suppress(false);
    rblog::write("BYID-SHADOW SESSION: saves=%ld restores=%ld", g_save_frames, g_restore_frames);
    for (int k = 0; k < K_NCARRIER; k++)
        rblog::write("BYID-SHADOW SESSION   %-14s edges=%ld match=%ld stale=%ld | CARRIER a(external)=%ld c(orphan/in-arena)=%ld",
            CARRIER_NAME[k], g_seen[k], g_match[k], g_uac[k], g_a[k], g_c[k]);
    rblog::suppress(was);
    g_save_frames = g_restore_frames = 0;
    for (int k = 0; k < K_NCARRIER; k++) { g_seen[k] = g_match[k] = g_uac[k] = g_a[k] = g_c[k] = 0; }
}

void set_enabled(bool on) {
    g_enabled = on;
    if (!on) report_and_reset();
    bool was = rblog::is_suppressed(); rblog::suppress(false);
    rblog::write("BYID-SHADOW %s (carriers: effect+0x218, entity-ref, singleton-tail; re-resolve+classify; ZERO writes)", on ? "ON" : "OFF");
    rblog::suppress(was);
}
bool is_enabled() { return g_enabled; }

void set_authoritative_effect(bool on) {
    g_auth_effect = on;
    bool auto_en = false;
    if (on && !g_enabled) { set_enabled(true); auto_en = true; }   // AUTH is inert without the capture/restore engine — auto-enable so F2 is never a silent no-op
    bool was = rblog::is_suppressed(); rblog::suppress(false);
    rblog::write("BYID: K_EFFECT %s — re-thread the reverted +0x218 on vtable+owner coherence (the 0x14080D44D fix)%s",
                 on ? "AUTHORITATIVE (splicing)" : "SHADOW (measure-only)", auto_en ? " [auto-enabled byid capture]" : "");
    rblog::suppress(was);
}
bool is_authoritative_effect() { return g_auth_effect; }

void init() {
    for (int i = 0; i < RING; i++) g_cap[i].frame = -1;
    rblog::write("BYID: init — by-identity SHADOW engine ready (effect+0x218, entity-ref, singleton-tail carriers); %d-frame ring, %d edges/frame, ~%zu MB static",
        RING, MAX_EDGES, (sizeof(g_cap) + sizeof(g_pool)) >> 20);
}

} // namespace byid
