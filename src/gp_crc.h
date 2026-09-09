#pragma once
#include <cstdint>
#include <cstddef>

// gp_crc — gameplay-state determinism oracle (the core determinism check).
//
// Hashes the SCALAR gameplay-STATE ranges (RNG, frame counters, + registered
// per-class fields) each NORMAL frame into a frame-keyed ring; during RESIM it
// recomputes and compares to the original frame's hash. A mismatch =>
// resim re-derived gameplay DIFFERENTLY => a determinism violation. This is the
// falsifier for field misclassification (DERIVED-vs-STATE) and the validator for
// any state serializer / additive null-pass. It is distinct from a render-output CRC
// (which would hash render/animation OUTPUT, not gameplay state).
//
// Safe BY DEFAULT: if a frame key ever fails to line up, check() simply finds no
// stored original and returns without comparing — it never reports a false
// divergence. Coverage starts at the scalar globals (v1) and is EXTENDED via
// register_range() as the per-class field-map lands. Pointer / render-contaminated
// offsets must be excluded (they differ by address even when gameplay is identical).

namespace gp_crc {

void init();                                   // seed registry + ring (after addr::init)
void register_range(uintptr_t ida, size_t size, const char* label);  // gameplay-logic range (alarms on divergence)
void register_range_ex(uintptr_t ida, size_t size, const char* label, bool gameplay);  // gameplay=false: render-contaminated (informational)
void record(int frame);                        // NORMAL play: store this frame's gameplay CRC
void check(int frame);                         // RESIM: recompute + compare to stored original
void on_rollback(int target_frame, int depth); // reserved (window bookkeeping)
// DETERMINISM CANARY (always-on, not gated by set_off): the cheap RNG-draw-count divergence oracle.
// GGPO-synctest / rr-match-check adapted — names the first resim frame whose draw count != forward play.
void canary_record(int frame);   // forward play, unconditional (per frame)
void canary_check(int frame);    // resim, unconditional (per replayed frame)
void canary_report();            // heartbeat summary
void set_off(bool v);                          // F11 runtime toggle (perf): skip the per-frame oracle CRC
bool is_off();
void dump_stats();                             // summary on exit / flush

} // namespace gp_crc
