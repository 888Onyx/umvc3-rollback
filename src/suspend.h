#pragma once
#include <cstdint>

namespace suspend {

// Init: record main thread ID
void init();

// Register a thread as "ours" (won't be suspended)
void whitelist(uint32_t tid);

// Suspend all process threads except main + whitelisted
void freeze();

// Resume all suspended threads EXCEPT render-domain threads held through the resim (see resume_held)
void thaw();

// Resume the render-domain thread(s) held suspended across the resim (call post-resim, world coherent)
void resume_held();

// Record the window thread's TID (called from a hook that runs ON it during normal play)
void note_window_thread(uint32_t tid);

} // namespace suspend
