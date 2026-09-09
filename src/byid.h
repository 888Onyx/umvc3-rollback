#pragma once
// byid — the by-identity dynamic-restore engine (shadow build: measures whether the stale-reference class is gone).
//
// The rule: restore a pointer by the IDENTITY of what it
// references, not by byte-reverting the raw address. A reverted raw pointer reinstates a stale reference
// when its referent moved/freed since the snapshot; an edge re-resolved to the referent's current live address
// cannot. This is "store the object it references, not the raw pointer" made real.
//
// Not null-and-drift: a stale edge is RE-RESOLVED to the correct referent, never nulled-and-hoped (drift is
// rejected). If a referent is genuinely gone, that is a SAVE-graph
// completeness bug to fix, not a null to paper over.
//
// Runs ALONGSIDE the arena, which stays as the SHADOW ORACLE. For a carrier type still in SHADOW, byid
// computes its re-resolved pointers and COMPARES to the arena's byte-reverted values (zero risk — arena's
// value stands). Once a carrier's compares match across a long run it GRADUATES to AUTHORITATIVE: byid writes the
// re-resolved pointers, overriding the arena's byte-revert for that carrier's pointer fields only.
//
// SCOPE (this build): the carrier types where restore-time stale references live —
// - entity-tails: sCharacter [0x2600,0x4000), sAction [0x8E0,0x2000) (referents = sUnit pool entities)
// - the effect graph: effect +0x218 child list + the children's owner/next pointers
// Scalar-heavy types (fighters) are not here — for them by-identity == in-place revert (no stale-reference risk), so they stay
// on the arena. Drives off RECONCILED_SCHEMA (which fields are pointers) + the dynamic_restore registry.

#include <cstdint>
#include <cstddef>

namespace byid {

// ---- identity: a token that survives free+realloc (a raw reverted address does not) ----
enum IdKind {
    IDK_NONE = 0,
    IDK_SCHEDULER_SLOT,   // sUnit pool entity: (line 0..127, chain-index) — re-resolved by walking the LIVE pool
    IDK_SINGLETON,        // fixed.data singleton (sCharacter/sAction/sGameEffect/...)
    IDK_EFFECT_CHILD,     // effect +0x218 list member: (parent-effect oid, birth-index along the list)
    IDK_EXTERNAL,         // out-of-arena referent => PRESERVE the raw handle, do not re-resolve
};
struct ObjId { uint32_t kind; uint32_t a; uint32_t b; };   // (kind, primary, secondary)

// ---- a captured pointer field: an EDGE to a referent identity (not a raw address) ----
struct Edge {
    uintptr_t src_addr;   // where the pointer lives (the field), at save time (for the shadow compare)
    uint16_t  off;        // field offset within its object
    uint16_t  size;       // 8 for a pointer
    ObjId     ref;        // the referent's identity — re-resolved to a current address at restore
};

// ---- per-carrier graduation state (shadow until proven, then authoritative) ----
enum Mode { MODE_SHADOW, MODE_AUTHORITATIVE };

// Per-frame, mirroring arena::save cadence: walk the carrier roots via the schema, capture each carrier
// object's pointer fields as edges-by-identity into the frame's snapshot.
void save_frame(int frame);

// At rollback (PH_POST_LOAD, after arena::load): for each carrier edge from `frame`, re-resolve `ref` to the
// referent's current live address. SHADOW => compare to the live (arena-reverted) value + log mismatches.
// AUTHORITATIVE => write the re-resolved address (override the arena's byte-revert for this field).
void restore_frame(int frame);

// Diagnostics: how many edges re-resolved, matched the arena (shadow), or were overridden (authoritative).
void report_and_reset();

// SHADOW build: gated ON for a measurement run (F12). save_frame/restore_frame are no-ops while OFF.
void set_enabled(bool on);
bool is_enabled();

// K_EFFECT MODE_AUTHORITATIVE (the 0x14080D44D fix): re-thread each parent's reverted +0x218 child list by
// idspine birth-stamp, splicing out the freed-and-reused impostor the page-revert re-planted. Default OFF
// (SHADOW measures the STAMP-SUB rate first). Requires byid enabled.
void set_authoritative_effect(bool on);
bool is_authoritative_effect();

void init();

} // namespace byid
