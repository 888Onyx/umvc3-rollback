#pragma once
#include <cstdint>

namespace resim {

// Early init: find .data section, allocate ring buffers.
// Call after addr::init(), before resim::init().
void early_init();

// Init: hook main_proc to intercept frame loop, set up F5/F6 hotkeys
void init();

// True while a rollback resim is replaying (read-only, for diagnostics).
bool resim_active();

// True while the rollback ENGINE is on (F5). This is the full window in which arena::load
// can run — i.e. the only window in which deferring a destroy (to keep arena pointers valid
// across load) has any purpose. When false, deferral is pointless and actively harmful, so
// voice_pool falls through to immediate destruction. (resim_active() is too narrow — it is
// true only during a resim, not for the whole engine-on period.)
bool engine_enabled();
bool netplay_lean();   // NETPLAY-LEAN: rollback-path detectors stripped (mechanisms untouched); Numpad8

// Current frame counter, and the target frame of the most recent rollback (read-only, diagnostics).
int current_frame();
int effective_frame();   // replayed frame during resim, else current_frame — the liveness-spine birth/death stamp
int last_rollback_target();

// Ask for a rollback to an engine frame. Called from the network receive path when corrected input proves a frame
// was simulated with a wrong guess. It only RECORDS the request — the rollback itself runs at the top of the next
// frame, never re-entrantly from inside a datagram handler. Ignored unless the engine is armed (FIGHT only) and the
// target is inside the save window; the deepest outstanding request wins, since rolling back further subsumes the rest.
void request_rollback_to(int engine_frame);
int  max_rollback_depth();   // the cap request_rollback_to honours; deeper requests are skipped

// Forward frames elapsed since the last rollback's resim completed (0 during/just-after resim, grows in normal
// play). The discriminator-freshness gate: g_last_source/g_last_orphaned are frozen at load() and only
// trustworthy while this is small. Large sentinel until the first rollback. (current_frame-last_rollback_target
// is depth-biased — it starts at the rollback depth, not 0 — so it is not a substitute.)
int frames_since_rollback();

// Has any rollback happened this session? (monotonic; distinguishes "no rollback" from "rolled back to frame 0",
// which last_rollback_target()>0 cannot). The clean latent-vanilla gate for P4.
bool rollback_happened();

// OWNED-HEAP P4 gates (set by the dllmain master composition; live A/B via F1).
// control_revert ON => save/restore_allocators become no-ops so the in-arena MtScalable control reverts COHERENTLY
// via page-blind (arena::load reverts its heap-zone pages at frame N) — the 10-slot alloc-ring that caused the
// cross-ring skew is bypassed. patch_pile OFF => coherent_set_repair + alloc_invariants::repair_freelists
// + coherence_audit::repair are skipped (page-blind's coherent control leaves nothing to repair); alloc_invariants::check
// is kept as the read-only coherence oracle.
void set_owned_heap_control_revert(bool on);
bool owned_heap_control_revert();
void set_patch_pile_enabled(bool on);
bool patch_pile_enabled();

} // namespace resim
