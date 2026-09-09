#pragma once
#include <cstdint>

// handle_preserve — persistent-value preservation across arena::load.
// Saves persistent values before arena::load, restores after.
// Persistent = value stored in arena that must not be rolled back
// (OS handles, D3D devices, process-heap objects created at startup).
// arena::load would overwrite them with snapshot copies. handle_preserve puts them back.

namespace handle_preserve {

// Init: nothing to do until first rollback
void init();

// Save all known persistent values from their arena locations
void save();

// Restore saved values back into the arena after load
void restore();

// Get sRender base address (0 if not registered yet)
uintptr_t get_srender();

} // namespace handle_preserve
