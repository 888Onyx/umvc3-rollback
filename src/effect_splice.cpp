// effect_splice.cpp — see effect_splice.h. Re-land of the proven free-time +0x218 unlink.
#include "effect_splice.h"
#include "addr.h"
#include "arena.h"
#include "log.h"
#include "resim.h"
#include <MinHook.h>
#include <windows.h>
#include <cstdint>

namespace effect_splice {

static constexpr uint64_t BASE_DTOR_IDA   = 0x140816670ULL;  // FUN_140816670 (141B) effect-child base dtor
static constexpr uint64_t TEARDOWN_IDA    = 0x14080B4D0ULL;  // FUN_14080b4d0 (144B) shared teardown (base + 3 type-0x19)
static constexpr uint64_t CHILD_OWNER_OFF = 0x10;            // child -> parent effect (the list holder)
static constexpr uint64_t CHILD_NEXT_OFF  = 0x18;            // child -> next in the +0x218 list
static constexpr uint64_t HEAD_OFF        = 0x218;           // effect -> child-list head (singly-linked, tail-append)
static constexpr uint64_t EMPTY_MARK_OFF  = 0x128;           // low-16 zeroed when a head-splice empties the list
static constexpr int      WALK_MAX        = 512;

typedef void (*dtor_fn)(int64_t);
typedef void (*teardown_fn)(void*);
static dtor_fn     orig_base_dtor = nullptr;
static teardown_fn orig_teardown  = nullptr;

static volatile long g_applied = 0, g_emptied = 0, g_notlinked = 0, g_anomaly = 0, g_bypass = 0;
// One-shot, thread-local: the base dtor sets it so the shared-teardown hook (reached inside orig below
// on this same thread) knows this exact child was already spliced and skips it. Frees are
// same-thread-sequential => no false-skip.
static thread_local uint64_t t_base_handled = 0;

static inline bool canon(uint64_t p) { return p >= 0x10000ULL && p < 0x0000800000000000ULL; }
static bool readable(uint64_t p, size_t n) {
    if (!canon(p) || n == 0) return false;
    // FAST PATH (steady-state lag fix): effect-children + effects are arena-resident, and these hooks fire
    // on every effect-child teardown (constant during normal play). Use the arena committed BITMAP (ns)
    // instead of a VirtualQuery SYSCALL (µs) per node — same fix as alloc_consistency. Out-of-arena (rare)
    // falls back to VirtualQuery.
    if (arena::is_arena_addr((uintptr_t)p) && arena::is_arena_addr((uintptr_t)(p + n - 1)))
        return arena::is_committed_addr((uintptr_t)p) && arena::is_committed_addr((uintptr_t)(p + n - 1));
    MEMORY_BASIC_INFORMATION mbi;
    if (!VirtualQuery((void*)p, &mbi, sizeof(mbi))) return false;
    if (mbi.State != MEM_COMMIT) return false;
    if (mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)) return false;
    return (p + n) <= (uintptr_t)mbi.BaseAddress + mbi.RegionSize;
}

// Splice `child` out of `effect`'s +0x218 singly-linked child list (head / mid / tail). Proven logic.
static bool splice(uint64_t effect, uint64_t child) {
    if (!canon(effect) || !canon(child)) return false;
    if (!readable(effect + HEAD_OFF, 8)) return false;
    uint64_t head = *(uint64_t*)(effect + HEAD_OFF);
    if (head == 0) { InterlockedIncrement(&g_notlinked); return false; }
    if (head == child) {
        uint64_t next = readable(child + CHILD_NEXT_OFF, 8) ? *(uint64_t*)(child + CHILD_NEXT_OFF) : 0;
        *(uint64_t*)(effect + HEAD_OFF) = next;
        long n = InterlockedIncrement(&g_applied);
        if (next == 0 && readable(effect + EMPTY_MARK_OFF, 2)) {
            *(uint16_t*)(effect + EMPTY_MARK_OFF) = 0;   // emptied list -> dormant consume (engine's childless state)
            InterlockedIncrement(&g_emptied);
        }
        if (n <= 3 || (n % 5000) == 0)
            rblog::write("EFFECT-SPLICE #%ld (head): effect=0x%llX child=0x%llX emptied=%ld notlinked=%ld anomaly=%ld",
                n, (unsigned long long)effect, (unsigned long long)child, g_emptied, g_notlinked, g_anomaly);
        return true;
    }
    uint64_t prev = head;
    for (int i = 0; i < WALK_MAX; i++) {
        if (!readable(prev + CHILD_NEXT_OFF, 8)) { InterlockedIncrement(&g_anomaly); return false; }
        uint64_t next = *(uint64_t*)(prev + CHILD_NEXT_OFF);
        if (next == 0) { InterlockedIncrement(&g_notlinked); return false; }   // clean end, child not present
        if (next == child) {
            uint64_t after = readable(child + CHILD_NEXT_OFF, 8) ? *(uint64_t*)(child + CHILD_NEXT_OFF) : 0;
            *(uint64_t*)(prev + CHILD_NEXT_OFF) = after;   // mid/tail splice (head stays non-null)
            long n = InterlockedIncrement(&g_applied);
            if (n <= 3 || (n % 5000) == 0)
                rblog::write("EFFECT-SPLICE #%ld (mid): effect=0x%llX child=0x%llX emptied=%ld notlinked=%ld anomaly=%ld",
                    n, (unsigned long long)effect, (unsigned long long)child, g_emptied, g_notlinked, g_anomaly);
            return true;
        }
        prev = next;
    }
    InterlockedIncrement(&g_anomaly);   // hit the walk cap without terminating
    return false;
}

// PERF: the splice is the engine's missing unlink, only needed across a rollback (so resim re-walking the
// +0x218 list can't hit the freed child). During pure normal play (engine OFF) it is vanilla behavior to not
// splice (the leak is latent + harmless without rollback) — and these hooks fire on every effect-child teardown,
// a steady tax. Gate the splice on engine-on; pass straight through when off. Replays correctly during resim.
static inline bool splice_active() { return resim::engine_enabled() || resim::resim_active(); }

static void hk_base_dtor(int64_t child) {
    if (!splice_active()) { orig_base_dtor(child); return; }
    uint64_t c = (uint64_t)child;
    if (canon(c) && readable(c + CHILD_OWNER_OFF, 8)) {
        uint64_t effect = *(uint64_t*)(c + CHILD_OWNER_OFF);
        if (effect != 0) splice(effect, c);   // add the engine's missing unlink before the free
    }
    t_base_handled = c;   // shared-teardown (reached inside orig) must not re-splice this child
    orig_base_dtor(child);
}

static void hk_teardown(void* child_p) {
    if (!splice_active()) { orig_teardown(child_p); return; }
    uint64_t c = (uint64_t)child_p;
    if (t_base_handled == c) { t_base_handled = 0; orig_teardown(child_p); return; }  // base path already spliced
    // Type-0x19 BYPASS path: the base dtor did not run for this child -> splice it now.
    if (canon(c) && readable(c + CHILD_OWNER_OFF, 8)) {
        uint64_t holder = *(uint64_t*)(c + CHILD_OWNER_OFF);
        if (holder != 0) { splice(holder, c); InterlockedIncrement(&g_bypass); }
    }
    orig_teardown(child_p);
}

void init() {
    struct { uint64_t ida; void* hk; void** orig; const char* name; } H[] = {
        { BASE_DTOR_IDA, (void*)&hk_base_dtor, (void**)&orig_base_dtor, "base-dtor 140816670" },
        { TEARDOWN_IDA,  (void*)&hk_teardown,  (void**)&orig_teardown,  "teardown 14080b4d0" },
    };
    for (auto& h : H) {
        void* t = (void*)addr::resolve(h.ida);
        MH_STATUS st = MH_CreateHook(t, h.hk, h.orig);
        rblog::write("EFFECT-SPLICE: hook %s @0x%llX %s (proven free-time +0x218 unlink; ungated live+resim)",
            h.name, (unsigned long long)(uintptr_t)t, st == MH_OK ? "OK" : "FAILED");
    }
}

long applied_count() { return g_applied; }   // confound logging for the consume probe: +0x218 unlinks this session

} // namespace effect_splice
