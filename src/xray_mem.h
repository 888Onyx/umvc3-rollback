#pragma once
#include <cstdint>

// xray_mem — byte-level memory R/W tracer (the field-role mapping instrument).
//
// Mechanism: PAGE_GUARD on every committed arena page + a front-of-chain VEH. Every GAME access to a
// guarded page faults (EXCEPTION_GUARD_PAGE); the handler logs (frame, phase, game-RIP, arena-offset, R/W)
// then re-arms the page via a per-thread single-step. The tracer does NO aggregation — it streams raw
// accesses; the workers mine the stream OFFLINE into the per-field access pattern (read-before-write =>
// DERIVE/REBUILD; read-modify-write carried across frames => ACCUMULATOR/RESTORE; write-only-at-spawn =>
// SEED; deref-base => POINTER). That is the empirical signal the PE-only static schema cannot give.
//
// It runs the game at a crawl by design — armed for a SHORT frame window (a few live frames spanning one
// rollback), 1-2 capture runs, then offline. Not a shipping path; default dormant.
namespace xray_mem {

enum Phase : uint32_t { PH_LIVE = 0, PH_RESIM = 1 };

void init();                  // TlsAlloc + register the front VEH (dormant; no guards until arm())
void arm(int frame_window);   // open the stream, PAGE_GUARD the scoped guard-list, capture for N frames
void disarm();                // remove guards, flush + close the stream
bool armed();
void on_frame();              // call once per main frame: advances the window, auto-disarms at the end

// suspend-safety: freeze() holds the tracer's IO lock across the thread-suspend (the same drain the log lock
// gets) so no frozen worker can own it while the main thread faults into the VEH during resim => no deadlock.
bool try_lock_io();
void lock_io();
void unlock_io();

} // namespace xray_mem
