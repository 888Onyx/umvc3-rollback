#pragma once
// free_probe — per-free cost discriminator for the heavy-dtor cost.
// The line-29/line-20 dtors burn ~26ms of main-thread cycles, but the teardown LOGIC is tiny (releases 4 sub-
// objects + one free). Two suspects: #1 the ~26ms is OUR hooked free path (arena/quarantine) running on
// each sub-object; #2 it's cold-cache/TLB stalls walking memory arena::load just reverted (hot in vanilla => why
// the game never hitches on a normal release). This probe is ARMED only around the timed dtor (near-zero cost in
// normal play — a TLS-bool read per free) and every one of our free hooks feeds it. Verdict: OUR-FREE ms ~= wall
// => suspect #1 (lighten the hook); OUR-FREE ms << wall => suspect #2 (cold-cache; not the drain's fault).
#include <windows.h>

namespace free_probe {
    extern thread_local bool               armed;    // set true only around the timed dtor
    extern thread_local long long          calls;    // our free-hook invocations while armed
    extern thread_local unsigned long long cycles;   // CPU cycles inside our free hooks (outermost, non-overlapping)
    extern thread_local int                depth;    // nesting guard so cycles don't double-count re-entrant frees

    // RAII guard — put `free_probe::Scope _fps;` at the top of every one of our free hooks.
    struct Scope {
        ULONG64 c0; bool on; bool outer;
        Scope() {
            on = armed;
            if (on) { ++calls; outer = (depth++ == 0); if (outer) QueryThreadCycleTime(GetCurrentThread(), &c0); }
        }
        ~Scope() {
            if (on) { --depth; if (outer) { ULONG64 c1; QueryThreadCycleTime(GetCurrentThread(), &c1); cycles += c1 - c0; } }
        }
    };
}
