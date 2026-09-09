#pragma once
// hang_detector — read-only silent-hang capture (watchdog).
namespace hang_detector {
void init();        // spawn the watchdog thread (call once, after addr::init)
void heartbeat();   // call once per main-proc frame (top of hk_main_proc)
void note_crash();  // CRASH-GAP: VEH stamps the crash time so HANG-DETECTED can be classed crash-aftermath vs independent
}
