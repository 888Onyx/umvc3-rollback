#pragma once
#include <cstdint>
// carve_orphan_probe.h — carve-orphan detector for allocator a4 (instrument-only). After every carve,
// checks whether the returned (now in-use) block is still REACHABLE from the class free chain (mgr+0x58).
// ORPHAN = this exact carve failed to unlink its block = the violating allocation, caught at birth with its caller.
// Also counts the inlined count-gate precondition (count==0 while head!=0 at entry).
//
// Not a MinHook — a CALLOUT: idspine already owns the one hook on FUN_1404CA650 (idspine.cpp; a second
// MH_CreateHook on the same target fails MH_ERROR_ALREADY_CREATED — an earlier run's arm failure). idspine's
// hk_carve reads {count,head} pre-orig and calls post_carve() after. Passive: reads + counts only.
namespace carve_orphan_probe {
void init();     // marks the callout armed (idspine must be hooked first) + logs
void post_carve(void* mgr, void* ret, unsigned long long sz_units,
                uint32_t count_in, uintptr_t head_in, void* caller);   // called by idspine::hk_carve after orig
void report();   // emit the aggregate carve census (call from the main-thread heartbeat)
}
