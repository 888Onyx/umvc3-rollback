// particle_list_guard.cpp — see particle_list_guard.h. Reset an already-broken leaf particle list to empty so the
// tick's own empty-list branch runs instead of writing through a dangling tail. Domain-valid-or-null on a STRUCTURE.
#include "particle_list_guard.h"
#include "id_oracle.h"
#include "addr.h"
#include "arena.h"
#include "resim.h"
#include "log.h"
#include <MinHook.h>
#include <windows.h>
#include <cstdint>

namespace particle_list_guard {

// The 4 byte-identical sibling tick functions (one per particle "kind"), all dispatched from FUN_140839820.
static constexpr uintptr_t TICK_IDA[4] = { 0x1408366A0ULL, 0x140836AA0ULL, 0x1408368A0ULL, 0x1408364A0ULL };
static constexpr uintptr_t SRC_HEAD = 0xe0, SRC_TAIL = 0xe8;   // source (active) list
static constexpr uintptr_t DST_HEAD = 0xf0, DST_TAIL = 0xf8;   // dest (retired) list — the crash's list

typedef void (*tick_fn)(void*);   // rcx=mgr; return value ignored (dispatcher recomputes al from mgr+0xe0)
static tick_fn orig_tick[4] = { nullptr, nullptr, nullptr, nullptr };

static volatile long g_guarded = 0;

// A list pointer is unsafe to walk/write through iff it is a proven husk (address-keyed quarantine set, via the
// oracle) OR not domain-valid (uncommitted/unaligned/wild). Routes through id_oracle = the one predicate. Nodes here
// have no vtable (offsets 0/8 are the intrusive links) so only the husk-set + committed legs apply — exactly what
// is_dead()/is_domain_valid() cover for this case.
static inline bool dangling(uintptr_t p) {
    if (!p) return false;                                   // empty list = coherent, not dangling
    return !id_oracle::is_domain_valid(p, 8) || id_oracle::is_dead(p);
}

// Reset one intrusive list (head/tail pair) to empty iff it is structurally incoherent — the leaf domain-valid-or-null
// on the STRUCTURE. Two incoherence classes, both "not walkable, cannot be appended to":
// (1) HALF-FORMED PAIR (RE-PROVEN crash 0x140836876): exactly one of {head,tail} is 0. A doubly-linked list's
// hard invariant is head==0 IFF tail==0; head!=0 & tail==0 makes the tick's append `*(tail+8)=new` fault at 0x8.
// This is what the old per-pointee husk test MISSED — a NULL tail is not a "husk" (dangling(0)=false), so nothing
// caught it. A save that froze a mid-drain transient (tail cleared before the walk that clears head), replayed by
// rollback as if stable, is the likely origin (render leaf ⇒ we don't make it save-coherent, we null-if-incoherent).
// (2) husk ENDPOINT: head or tail points at a freed/wild node (the originally-designed case).
// Resetting head=tail=0 routes the tick's `cmp [mgr+head],0; jne` to its own EMPTY-LIST branch (RE-verified: it stores
// the node as both head&tail without ever dereferencing the corrupt tail). Leaf/unhashed render ⇒ desync-safe, self-heals.
static inline bool reset_if_incoherent(uintptr_t mgr, uintptr_t head_off, uintptr_t tail_off) {
    if (!arena::is_committed_addr(mgr + head_off) || !arena::is_committed_addr(mgr + tail_off)) return false;
    uintptr_t head = *(uintptr_t*)(mgr + head_off);
    uintptr_t tail = *(uintptr_t*)(mgr + tail_off);
    bool half_formed = ((head == 0) != (tail == 0));        // exactly one zero = broken head==0-iff-tail==0 invariant
    if (!half_formed && !dangling(head) && !dangling(tail)) return false;
    *(uintptr_t*)(mgr + head_off) = 0;
    *(uintptr_t*)(mgr + tail_off) = 0;
    return true;
}

static inline void guard(uintptr_t mgr, int which) {
    // Only engine-on: in clean play both lists always satisfy head==0-iff-tail==0 with live endpoints, so this is a pure
    // no-op. Reads mgr's own list fields only; writes only to reset an already-corrupt leaf list (desync-safe — mgr is
    // unhashed render). Applies the same structural invariant to both the dest (retired) list — where the crash lives —
    // and the source (active) list, which the tick also walks head-first.
    if (!resim::engine_enabled() || !arena::is_committed_addr(mgr + DST_TAIL)) return;
    bool hit = false;
    hit |= reset_if_incoherent(mgr, DST_HEAD, DST_TAIL);    // dest (retired) list — the 0x140836876 append target
    hit |= reset_if_incoherent(mgr, SRC_HEAD, SRC_TAIL);    // source (active) list — same invariant, head deref'd unguarded
    if (hit) {
        long n = InterlockedIncrement(&g_guarded);
        if (n <= 4 || (n % 2000) == 0)
            rblog::write("PARTICLE-LIST-GUARD #%ld: mgr=0x%llX (tick[%d]) had an incoherent leaf list (half-formed head/tail "
                         "or husk endpoint) -> reset to empty (routes the append to the engine's empty-list path; 0x140836876 close)",
                         n, (unsigned long long)mgr, which);
    }
}

static void hk_tick0(void* m) { guard((uintptr_t)m, 0); orig_tick[0](m); }
static void hk_tick1(void* m) { guard((uintptr_t)m, 1); orig_tick[1](m); }
static void hk_tick2(void* m) { guard((uintptr_t)m, 2); orig_tick[2](m); }
static void hk_tick3(void* m) { guard((uintptr_t)m, 3); orig_tick[3](m); }

void init() {
    void* hooks[4] = { (void*)&hk_tick0, (void*)&hk_tick1, (void*)&hk_tick2, (void*)&hk_tick3 };
    int armed = 0;
    for (int i = 0; i < 4; i++) {
        void* t = (void*)addr::resolve(TICK_IDA[i]);
        if (MH_CreateHook(t, hooks[i], (void**)&orig_tick[i]) == MH_OK) armed++;
        else rblog::write("PARTICLE-LIST-GUARD: hook tick[%d] @0x%llX FAILED", i, (unsigned long long)(uintptr_t)t);
    }
    rblog::write("PARTICLE-LIST-GUARD ARMED: %d/4 particle-tick fns (FUN_1408366a0 + 3 siblings) — husk dest/src list "
                 "pointer -> reset to empty (leaf domain-valid-or-null on the list STRUCTURE; the 0x140836876 write-crash close), engine-gated",
                 armed);
}

long guarded_count() { return g_guarded; }

} // namespace particle_list_guard
