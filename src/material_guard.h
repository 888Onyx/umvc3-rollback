#pragma once
// material_guard — Material lifecycle discipline: null every known holder edge to a Material at its destroy
// event (the engine's own invalidation, extended to cross-timeline destroys). See the .cpp.
namespace material_guard {
void init();      // MinHook the Material-variant dtor (call from resim::init's hook sequence, before EnableHook(all))
void report();    // throttled counters (call from a heartbeat)
void sweep();     // husk-SWEEP per-frame (forward play): null every holder edge landing in the engine-wide husk set
void identity_on_rollback();   // GENERATION-VALIDATION: epoch-invalidate the edge-shadow so a restore can't spurious-sever
}
