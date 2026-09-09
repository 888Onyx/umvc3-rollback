#pragma once
#include <cstdint>
#include <cstddef>

// dynamic_restore — the RestoreDescriptor registry + phase driver.
//
// This is not a new layer. It formalizes what do_rollback + handle_preserve.cpp + dead_vtable_unlink.cpp +
// rtv_probe.cpp already do by hand. The skeleton (this first build) RE-HOMES the
// existing PRESERVE / NULL-stale fixes AS the first descriptors and re-expresses
// their current calls through the registry — behavior-IDENTICAL.
//
// Sparse-override principle: arena::load's
// blind page-revert stays the default discipline. Descriptors are a sparse
// override table, registered only where the revert is wrong. Exact = no descriptor.
//
// Skeleton scope (this build): the 3 named fixes only —
// - sRender persistent handles + singleton CS (handle_preserve.cpp) F_PRESERVE / F_LOCK
// - scheduler bad-vtable unlink (dead_vtable_unlink.cpp) F_NULL_STALE
// - RTV/DSV +0x20 render-domain preserve (rtv_probe.cpp) F_PRESERVE
// The allocator REBUILD and the INFERRED descriptors are oracle-gated FOLLOW-UPS,
// not wired here. arena::load + restore_allocators stay intact.

namespace dyn_restore {

// ---- identity: how the driver finds + recognizes live instances at restore time ----
enum IdentityKind {
    ID_SINGLETON_PTR,    // *(void**)addr::resolve(ida)
    ID_VTABLE_REGISTRY,  // walk a registry array, accept slot iff *(void**)slot == vtable
    ID_BIRTH_REGISTRY,   // heap-scattered objects accreted at ctor into a runtime g_reg[]
    ID_SCHEDULER_WALK,   // walk sUnit lines 0..127, +0x58+line*0x30 head, +0x20 next
    ID_POD_REGION,       // fixed [ida, ida+size) — no live-object identity
};

struct Identity {
    IdentityKind kind;
    uintptr_t    ida;          // singleton ptr / registry array / region base
    uintptr_t    ida_count;    // ID_VTABLE_REGISTRY: count addr
    uintptr_t    vtable_ida;   // ID_VTABLE_REGISTRY / type-tag confirm (0 = none)
    size_t       region_size;  // ID_POD_REGION
    int (*enumerate)(uintptr_t* out, int cap);   // 0 => use the generic walker for `kind`
};

// ---- field_map: per-offset discipline within a recognized instance ----
enum FieldRole {
    F_SCALAR_EXACT,   // authoritative sim byte — keep the page-revert (DOCUMENT-only)
    F_POINTER_EXACT,  // pointer whose referent reverts on the same snapshot — keep page-revert
    F_PRESERVE,       // POINTER-BY-IDENTITY (external referent): save live, write back
    F_REDERIVE,       // derived/render output — exclude, engine rebuilds
    F_NULL_STALE,     // stale ptr to a gone object — null it (engine NULL-checks)
    F_LOCK,           // CRITICAL_SECTION — handle word PRESERVE, lock state QUIESCENT-RESET
    F_REBUILD,        // member of a path-dependent index recomputed from data
};

struct Field { size_t off; size_t size; FieldRole role; const char* label; };

// ---- whole-structure discipline (acts on the instance, not a single offset) ----
enum WholeDiscipline {
    W_NONE,              // field-map only
    W_CONTENT_RESTORE,   // BY-IDENTITY: save whole live struct + children, memcpy back
    W_REBUILD,           // recompute the entire index from referents
    W_QUIESCENT_RESET,   // reinit scheduling bookkeeping to clean idle state
    W_DEFER,             // PRESERVE-by-DEFER: hold external teardown across the window
    W_PRESERVE_SANDWICH, // save PRESERVE sublist -> blind region revert -> write back
};

// ---- phase: when each action runs. A descriptor contributes a SET of bindings. ----
enum Phase {
    PH_SAVE,         // Before arena::load: snapshot live externals
    PH_POST_LOAD,    // After arena::load, before resim: write-back, REBUILD, NULL-stale, lock reset
    PH_DURING_RESIM, // inside the resim loop: refcount-neutral dtor-suppress (hooks, not a driver walk)
    PH_POST_RESIM,   // after resim loop: final validation pass
};

// op receives the instance base (0 for whole-system adapters that self-enumerate).
struct PhaseBinding { Phase phase; int order; void (*op)(uintptr_t inst); };

enum Confidence { CONF_INFERRED = 1, CONF_HIGH = 2 };

struct RestoreDescriptor {
    const char*         name;          // descriptor name
    Identity            id;
    const Field*        fields;  int   field_count;
    WholeDiscipline     whole;
    const PhaseBinding*  bindings; int binding_count;   // the (phase,order,op) set
    int                 confidence;    // CONF_HIGH / CONF_INFERRED — INFERRED ships behind a flag
    bool                flag_gated;    // true => only runs when its feature flag is set
    const char*         oracle_note;   // close-condition: what proves the descriptor correct
};

// Register the skeleton descriptors (handle_preserve / dead_vtable_unlink / rtv preserve). Call from resim::init().
void init();

// ---- DRIVER (skeleton wire-in path): per-descriptor dispatch, bindings sorted by order ----
// run() executes one descriptor's bindings for one phase, in `order`. The skeleton calls
// run() in-place at the 6 current do_rollback call sites => zero reorder => behavior-identical.
void run(const char* descriptor_name, Phase phase);

// ---- DRIVER (design artifact, not the skeleton wire-in path): grouped phase-outer walk ----
// run_phase becomes the wire-in path only once D3D9/RSUB/allocators/CS-reset are also
// descriptors (the later oracle-gated steps). Built now so the structure exists; calling it
// today would reorder the still-inline ops in do_rollback, so do_rollback uses run() instead.
void run_phase(Phase phase);

// Registry accessors (diagnostics / tests).
int descriptor_count();
const RestoreDescriptor* descriptor_at(int i);
long ops_fired_and_reset();   // re-home verification: # of descriptor ops fired since last reset (logged post-suppress)

} // namespace dyn_restore
