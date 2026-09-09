#pragma once
// field_target_recorder — the in-arena-vs-external pointer-provenance recorder (the edge-discriminator).
//
// The static RE cannot decide whether a pointer field is an in-arena edge (RESTORE, valid by construction under
// whole-arena fixed-base revert) or an EXTERNAL edge (a voice/GPU/OS object whose plain restore is the crash).
// The running game knows: it points where it points. This recorder samples live typed objects (via idspine),
// and for every pointer-shaped field records where it actually pointed — in-arena / main-module / external /
// garbage — per (vtable, object-relative offset), accumulated across frames and scenarios.
//
// Output (CSV, dumped periodically so a crash still leaves data): vtable, offset, samples, null, arena, module,
// external, garbage. The full classify+gate run consults it: external>0 on a mutable region => EDGE; always
// arena => in-arena pointer (RESTORE); always module => build-const (RESTORE). It also confirms the defaulted
// arena_edge assumption empirically. READ-ONLY: zero game writes, all target reads VirtualQuery-guarded, armed
// by NUMPAD9 (default OFF), throttled (samples every Nth frame, never per-frame logging).
namespace field_target_recorder {
void on_frame();   // edge-detect the arm key, then (if armed) sample + periodically dump. One call site.
void toggle();     // arm/disarm recording
bool armed();
}
