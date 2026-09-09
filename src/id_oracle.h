#pragma once
#include <cstdint>
#include <cstddef>
// id_oracle — the identity/liveness SUBSTRATE.
//
// The PROBLEM: every rollback crash is a pointer/index crossing the revert boundary onto the wrong epoch or
// identity, and ~5 families each answer "is this edge safe?" with their OWN ad-hoc test:
// material_guard::edge_dead (is_held_husk|sentinel) · recycled_nonobject (garbage vtable) · edge_recycled (gen ABA)
// · byid STAMP-SUB (serial) · coherent_set_repair alive_at_n (idspine/rdspine birth<=N<death).
// Divergent tests => per-family coverage gaps and per-peer divergence (a desync landmine). This module is the one
// deterministic answer to "is pointer P a live, same-identity, dereferenceable object at frame N?" — every family
// calls it, so the predicate is uniform by construction.
//
// FAITHFUL, not LOSSY: the vt==0 case is DELIBERATELY split. vt==0 is DEAD at a dtor/teardown site but AMBIGUOUS
// (mid-construction) at an arbitrary graph point — nulling vt==0 edges during a sweep broke match-start (an earlier
// build). So is_dead()/is_recycled_nonobject() (safe everywhere)
// exclude vt==0; is_husk_vtable() (DTOR/LEAF sites only) includes it. The oracle preserves every distinction the
// families reasoned out; it does not flatten them.
//
// FAIL-OPEN BY CONSTRUCTION: the oracle returns DEAD/ABA_RECYCLED/BORN_AFTER_N only when proven. On any doubt it
// returns UNKNOWN, which every consumer treats as "keep the edge" — so migrating a family onto the oracle can never
// null a live edge (never desync, never destroy). Pure read-only: no game writes, safe to call anywhere.
namespace id_oracle {

enum Verdict {
    ALIVE_SAME   = 0,  // domain-valid, not dead, not recycled, (alive-at-N or liveness-unknown-but-live)
    DEAD         = 1,  // timeline-proven dead-held / sentineled / garbage-vtable / died<=N
    ABA_RECYCLED = 2,  // same address, +0x8 generation id changed since capture (in-place recycle)
    BORN_AFTER_N = 3,  // object at P was born after frame N (did not exist at the restore target)
    EXTERNAL     = 4,  // out-of-arena readable handle (COM/driver/CRT) — recognized, never "dead"
    UNKNOWN      = 5,  // insufficient evidence — consumers keep the edge (fail-open)
};

void init();     // resolve the dead-sentinel vtable (0x140A6A510); emit the armed line
void report();   // ID-ORACLE stats line (throttled; call from a heartbeat, never per-frame)

// --- MIGRATION SHADOW PROBE (flip a family onto the oracle only after 0 disagreements) ---
// Default OFF (arm with id_oracle_probe.flag beside the .exe). While armed, a family that still owns its own
// verdict also calls the matching oracle predicate and logs (rate-limited) any DISAGREEMENT — proving the oracle
// faithfully reproduces that family before we make the oracle authoritative. Zero behavior/perf impact when off.
void set_probe(bool on);
bool probe_enabled();
void probe_dead(uintptr_t p, bool local_dead, const char* family);   // compare a family's dead-verdict to is_dead(p)

// --- domain (the leaf-guard half — cheap, no ledger lookups) ---
bool canon(uintptr_t p);                       // 0x10000 <= p < canonical ceiling
bool committed(uintptr_t p, size_t need);      // [p, p+need) all committed & not GUARD/NOACCESS (arena bitset or VirtualQuery)
bool is_domain_valid(uintptr_t p, size_t need);// canon && committed && 4-aligned — the anim/leaf "route garbage->null" test

// --- identity legs (each maps 1:1 to an existing material_guard test; use directly when migrating) ---
bool in_our_domain(uintptr_t p);               // arena-committed (rd()); false => EXTERNAL/leave-alone (COM-safe)
bool is_dead(uintptr_t p);                     // quarantine::is_held_husk || dead-sentinel (TIMELINE; safe everywhere; excludes vt==0)
bool is_recycled_nonobject(uintptr_t p);       // NONZERO out-of-module vtable = float/garbage (safe everywhere; excludes vt==0)
bool is_husk_vtable(uintptr_t p);              // vt==0 || sentinel || garbage-range — DTOR/LEAF SITES only (vt==0 ambiguous elsewhere)
uint64_t capture_gen8(uintptr_t p);            // read the game's +0x8 generation id (0 if unreadable) — snapshot at save
bool gen_changed(uintptr_t p, uint64_t captured_gen8);  // ABA: current +0x8 != captured (captured!=0 required)

// --- alive-at-N (idspine ∪ rdspine birth<=N<death) ---
Verdict liveness_at(uintptr_t p, int N);       // ALIVE_SAME / DEAD / BORN_AFTER_N / EXTERNAL / UNKNOWN

// --- fused verdict (safe-everywhere legs — the entry point for new code) ---
Verdict check(uintptr_t p, int N);                                 // domain + is_dead + is_recycled + liveness (for OBJECTS w/ a vtable)
Verdict check_id(uintptr_t p, int N, uint64_t captured_gen8);      // + ABA (needs the captured +0x8)
// DATA variant — for a pointer to raw DATA (no vtable at +0, e.g. a bone/matrix array). SKIPS the vtable-based
// garbage/husk-vtable legs (a data block's first qword is a float, not a vtable — the object test false-flags it).
// And treats a HELD-husk referent as ALIVE_SAME: for a GAMEPLAY edge, a freed-but-quarantine-deferred block is being
// Kept ALIVE precisely so this pointer stays valid ⇒ safe, not a gap (the same is_held_husk that means "sever" for a
// leaf means "kept alive for you" for gameplay). Gap only if the referent is genuinely gone: uncommitted, born>N, or
// died<=N and not held.
Verdict check_data(uintptr_t p, int N);

const char* verdict_name(Verdict v);

} // namespace id_oracle
