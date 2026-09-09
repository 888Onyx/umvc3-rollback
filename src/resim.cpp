// resim.cpp — The resim loop. F5/F6 handler. Status overlay.
// Hooks MAIN_PROC via MinHook. On F5: save state, load old state, resim with replayed inputs.
// No g_resimulating flag. No suppression. orig() runs identically to normal play.

#include "resim.h"
#include "arena.h"
#include "input.h"
#include "suspend.h"
#include "handle_preserve.h"
#include "dead_vtable_unlink.h"
#include "addr.h"
#include "log.h"
#include "monitor_shm.h"
#include "gp_crc.h"
#include "voice_pool.h"
#include "hang_detector.h"
#include "rtv_probe.h"
#include "effect_probe.h"
#include "freelist_diag.h"
#include "alloc_consistency.h"
#include "effect_splice.h"
#include "render_subchild_guard.h"
#include "draw_probe.h"
#include "dyndelete.h"
#include "flist_rebuild.h"
#include "dynamic_restore.h"
#include "byid.h"
#include "xray_mem.h"
#include "idspine.h"
#include "material_guard.h"
#include "id_oracle.h"
#include "anim_curve_guard.h"
#include "particle_list_guard.h"
#include "count_drift_census.h"
#include "carve_orphan_probe.h"
#include "net_session.h"
#include "net_input.h"
#include "net_sync.h"
#include "dinput_probe.h"
#include "net_charsel.h"
#include "net_engine_arm.h"
#include "role.h"
#include "gameplay_complete.h"
#include "life_floor.h"
#include "audio_leaf.h"
#include "rdspine.h"
#include "field_target_recorder.h"
#include "page_free.h"
#include "sound_preserve.h"
#include "sound_resource_preserve.h"
#include "audio_preserve.h"
#include "coherence_audit.h"
#include "coherent_set_repair.h"
#include "provenance.h"
#include "p4_shadow.h"
#include "quarantine.h"
#include "render_edge_probe.h"
#include "sound_edge_reconcile.h"
#include "edge_census.h"
#include "edge_break.h"
#include "alloc_invariants.h"
#include "audio_group.h"
#include "free_probe.h"
#include <MinHook.h>
#include <windows.h>
#include <tlhelp32.h>
#include <cstdint>
#include <cstdio>

// free_probe per-free cost TLS (declared extern in free_probe.h; defined here so no build.sh change is needed)
namespace free_probe {
    thread_local bool               armed  = false;
    thread_local long long          calls  = 0;
    thread_local unsigned long long cycles = 0;
    thread_local int                depth  = 0;
}

// Key addresses (0x140000000-based; see addr.h)
static constexpr uintptr_t MAIN_PROC_IDA = 0x1402594A0;
static constexpr uintptr_t SCENE_TREE_DISPATCH_IDA = 0x1405EA340;
static constexpr uintptr_t FRAME_PACER_IDA = 0x140521DF0;
typedef void (*orig_main_proc_fn)(int64_t param_1);
static orig_main_proc_fn orig_main_proc = nullptr;

typedef void (*scene_tree_dispatch_fn)(int64_t, int64_t, int64_t);
static scene_tree_dispatch_fn orig_scene_tree_dispatch = nullptr;

typedef void (*frame_pacer_fn)(int64_t param_1);
static frame_pacer_fn orig_frame_pacer = nullptr;

static constexpr uintptr_t RUN_AND_WAIT_IDA = 0x140521230;
typedef void (*run_and_wait_fn)(int64_t, int64_t, int);
static run_and_wait_fn orig_run_and_wait = nullptr;

// SCAFFOLDING toggle. 0 = OFF: skip the read-only diagnostics (coherence_diag,
// edge_census frozen map-builder, barrier_probe) that cost time + add walk noise. The LIVE FIX
// (edge_census::coherent_restore + sound_resource_preserve + sound_edge_reconcile) is not scaffolding and stays on.
static volatile long g_scaffold = 0;
// PERF: hot-path DIAGNOSTIC gate (default OFF) — the read-only restore-time oracles (alloc_invariants::check POSTLOAD +
// render_edge_probe) validate but never FIX (the 4 crash families are closed by construction). Off by default to
// shave the restore_steps hot path; re-arm with hotdiag.flag for a coherence-validation session.
// NETPLAY-LEAN: strips the read-only detectors from the rollback hot path (checks/oracles/census/per-frame-resim
// logs) while every mechanism (units, keep-live, repairs, guards, preserves) runs untouched. Default OFF; Numpad8
// toggles. Measures the lean rollback cost; a netplay session should run with it ON (not forced yet).
static volatile LONG g_netplay_lean = 0;
static bool g_hotdiag = (GetFileAttributesA("hotdiag.flag") != INVALID_FILE_ATTRIBUTES);
static bool g_resim_active = false;             // true during the resim replay loop
static volatile bool g_resim_singlethread = true; // F10 — ST resim (deterministic, SLOW); OFF=MT resim (FAST, workers race the allocator)
static volatile LONG g_rw_inline_count = 0;     // # engine-native inline drains forced this rollback

// Engine-native single-thread drain during resim. param_1 == scheduler singleton (DAT_140e177e8).
// +0xa4 = worker count; ==1 selects the engine's OWN inline runner (FUN_140521a40 on this thread),
// bypassing the 14-handle WaitForMultipleObjects worker barrier — the work still RUNS (same job array,
// serial on main), only the concurrent worker traffic + barrier are removed. This MIRRORS
// FUN_140521230's own save/force/restore of +0xa4 around its inline branch,
// so it is engine-native, not an imposition. param_3 is VESTIGIAL (FUN_140521230 reads only 2 args).
// SCOPED to resim with stack-local save/restore so +0xa4 reads its true value everywhere else
// (FUN_14064cb80 uses it as a per-worker partition count — must not see 1 mid-frame) and normal play
// stays byte-for-byte multi-threaded (reversible by construction).
static DWORD g_main_proc_tid = 0;   // the real main thread (captured at first hk_main_proc invocation)
static volatile LONG g_rw_alien_count = 0;
static void hk_run_and_wait(int64_t param_1, int64_t param_2, int /*param_3 vestigial*/) {
    if (g_resim_active && g_resim_singlethread && param_1) {
        // RESIM-RW-ALIEN probe: a non-main caller reaching run_and_wait mid-resim (this hook is TID-blind: it
        // recruits any caller as the inline task drainer). Behavior is unchanged — force-inline is the safe path for
        // foreign-thread callers too (the orig MT branch would SetEvent up to 13 workers mid-resim). Logged so the
        // caller is visible.
        DWORD tid = GetCurrentThreadId();
        if (g_main_proc_tid && tid != g_main_proc_tid) {
            LONG n = InterlockedIncrement(&g_rw_alien_count);
            if (n <= 8) rblog::write("RESIM-RW-ALIEN: tid=%u entered run_and_wait mid-resim (drains tasks inline; alien #%ld)", tid, n);
        }
        uint32_t* worker_count = (uint32_t*)(param_1 + 0xa4);   // smain + 0xa4
        uint32_t saved = *worker_count;
        *worker_count = 1;                       // force the engine's inline single-thread path
        InterlockedIncrement(&g_rw_inline_count);
        orig_run_and_wait(param_1, param_2, 0);
        *worker_count = saved;                   // restore — normal play untouched / fully MT
    } else {
        orig_run_and_wait(param_1, param_2, 0);  // normal play: fully multi-threaded
    }
}

static constexpr uintptr_t PARALLEL_FOR_IDA = 0x14095EC90;
typedef void (*parallel_for_fn)(int64_t*);
static parallel_for_fn orig_parallel_for = nullptr;
static volatile LONG g_pf_serial_count = 0;

// Async fork-join FUN_14095ec90: during resim, force the engine's OWN serial branch so the
// FUN_1405210e0 async worker ring does not race the allocator. The serial selector is the low byte
// of param_1[0x16] (offset +0xB0): ((char)param_1[0x16]=='\0') => serial branch (8);
// the else branch forks FUN_14051ff00. Writing only that byte preserves the +0xB4 threshold uint.
// Stack-local save/restore, gated on g_resim_active => normal play stays parallel (reversible).
static void hk_parallel_for(int64_t* param_1) {
    if (g_resim_active && g_resim_singlethread && param_1) {
        char* serial_flag = (char*)param_1 + 0xB0;   // low byte of param_1[0x16] (serial selector)
        char saved = *serial_flag;
        *serial_flag = 0;                             // force serial: inline on main, no async ring
        LONG n = InterlockedIncrement(&g_pf_serial_count);
        if (n == 1) rblog::write("PF-SERIAL: forced FUN_14095ec90 serial during resim (saved byte=0x%02X)", (unsigned char)saved);
        orig_parallel_for(param_1);
        *serial_flag = saved;
    } else {
        orig_parallel_for(param_1);
    }
}

// GO-KICK (FUN_140537080): the per-frame render kick. Its whole render-kick body is gated on the engine's
// OWN "render not in flight" flag: `if (*(char*)(sRender+0x38) == 0) {...increment +0x6764c, set +0x38=1,
// SetEvent(GO +0xf8) if threaded, set up the render ring... }`. To render only the final resim frame (and run
// the never-displayed intermediate frames gameplay-only — the engine-correct rollback cadence, confirmed from
// the binary), we suppress the kick on intermediate frames USING the ENGINE'S OWN GATE: set
// +0x38=1 before orig (so its `if(+0x38==0)` is false => the entire render-kick is skipped: no SetEvent, no
// counter bump, no ring setup), then restore +0x38=0 after (so the later JOIN FUN_140541030 sees "not in
// flight" => renders nothing, neither async on the render thread nor sync on the main thread). This skips only
// the render-kick, preserves the surrounding setup, and keeps the render thread parked across the intermediate
// frames — so it never dereferences the half-resimmed intermediate render state (where the corrupted device
// pointer / null-DebugInfo CS crash lived). On the final frame g_suppress_render_kick=false => normal kick.
static constexpr uintptr_t GO_KICK_IDA = 0x140537080;
typedef void (*go_kick_fn)(int64_t);
static go_kick_fn orig_go_kick = nullptr;
static volatile bool g_suppress_render_kick = false;   // set only around intermediate resim frames (main thread)
static volatile LONG g_go_suppress_count = 0;
static volatile int  g_replay_frame = -1;              // current resim replay frame (set by the resim loop)

// KICK-SCALAR TRAJECTORY (the invariant: recurrent accumulators follow the original trajectory during resim).
// The kick's scalar half — +0x6764c counter, +0x67648 toggle, the published globals DAT_140e1b708/70c — feeds
// the ring-slot selection (+0x6764c%3), the EXEC slot pairing (toggle), and the drain age-out (DAT_140e1b708).
// Suppressing the kick stalled them 6 frames => the frame_counter_1 gp_crc diverge + the final-frame EXEC crash
// (stale/misaligned slot => d3d9 read code-bytes-as-data). Recorded per normal frame at the arena-save site
// (RING[N] = post-frame-(N-1) values, same indexing as gp_crc::record), replayed per suppressed resim frame =>
// bit-exact trajectory, gp_crc frame_counter_1 stays a true oracle (no reclassification).
struct KickRec { int frame; uint32_t counter; uint32_t toggle; uint8_t threaded; };
static KickRec g_kick_ring[256] = {};
static volatile LONG g_kick_replay_fallbacks = 0;
static volatile bool g_kick_setup_ring = false;   // final resim frame: replica kick also does the ring setup

// The kick's ring-cursor setup functions (engine's own — called with the engine's own args at the engine's
// own callsite timing, just from the replica): +0x8676b8 = FUN_14079fa40(slotA[c%3],3); +0x8676c0 = fee0(...).
typedef uint64_t (*ring_lock_fn)(uint64_t, int);
static ring_lock_fn ring_lock_a_fn = nullptr;   // FUN_14079FA40
static ring_lock_fn ring_lock_b_fn = nullptr;   // FUN_14079FEE0
static uint64_t ring_lock_a(uint64_t slot, int n) {
    if (!ring_lock_a_fn) ring_lock_a_fn = (ring_lock_fn)addr::resolve(0x14079FA40);
    return ring_lock_a_fn(slot, n);
}
static uint64_t ring_lock_b(uint64_t slot, int n) {
    if (!ring_lock_b_fn) ring_lock_b_fn = (ring_lock_fn)addr::resolve(0x14079FEE0);
    return ring_lock_b_fn(slot, n);
}

static void apply_kick_scalars(uintptr_t sr, uint32_t counter, uint32_t toggle, uint8_t threaded) {
    *(volatile uint32_t*)(sr + 0x6764c) = counter;
    *(volatile uint32_t*)(sr + 0x67648) = toggle;
    *(volatile uint32_t*)addr::resolve(0x140E1B708) = counter;                       // the kick's publish
    *(volatile uint32_t*)addr::resolve(0x140E1B70C) = (uint32_t)(threaded != 0) + 1; // threaded-mode publish
}

static void hk_go_kick(int64_t param_1) {
    if (g_suppress_render_kick && param_1) {
        volatile uint8_t* inflight = (volatile uint8_t*)(param_1 + 0x38);
        uint8_t saved = *inflight;
        *inflight = 1;             // engine's own gate: "render in flight" => orig skips the whole render-kick
        orig_go_kick(param_1);
        *inflight = saved;         // restore (0) so the later JOIN renders nothing (no sync render either)

        // Replay the kick's SCALAR half from the recorded original trajectory (post-frame-F = RING[F+1]).
        int want = g_replay_frame + 1;
        KickRec& r = g_kick_ring[want & 255];
        if (g_replay_frame >= 0 && r.frame == want) {
            apply_kick_scalars((uintptr_t)param_1, r.counter, r.toggle, r.threaded);
        } else {
            // Fallback (frame not recorded): live-base replication — advance like a real kick would.
            uint32_t c = *(volatile uint32_t*)(param_1 + 0x6764c) + 1;
            uint32_t t = *(volatile uint32_t*)(param_1 + 0x67648) ^ 1;
            apply_kick_scalars((uintptr_t)param_1, c, t, *(volatile uint8_t*)(param_1 + 0x3d));
            LONG fb = InterlockedIncrement(&g_kick_replay_fallbacks);
            if (fb == 1) rblog::write("GO-SUPPRESS: kick-scalar ring MISS for frame %d (have %d) — live-base fallback", want, r.frame);
        }

        // FINAL resim frame only: also replicate the kick's RING SETUP (the engine's own FUN_14079fa40/fee0
        // with the replayed counter) so the BUILD that runs this frame has live cursors — its fresh commands
        // are what the first NORMAL frame's EXEC consumes (BUILD(N)/EXEC(N-1) pipeline). No +0x38, no events:
        // the JOIN sees not-in-flight and skips both async and sync EXEC — the render thread never runs
        // during the rollback window at all.
        if (g_kick_setup_ring) {
            uint32_t c = *(volatile uint32_t*)(param_1 + 0x6764c);
            *(volatile uint64_t*)(param_1 + 0x8676b8) =
                ring_lock_a((*(uint64_t*)(param_1 + 0x867688 + (uint64_t)(c % 3) * 8)), 3);
            *(volatile uint64_t*)(param_1 + 0x8676c0) =
                ring_lock_b((*(uint64_t*)(param_1 + 0x8676a0 + (uint64_t)(c % 3) * 8)), 3);
        }

        LONG n = InterlockedIncrement(&g_go_suppress_count);
        if (n == 1) rblog::write("GO-SUPPRESS: skipped render-kick on intermediate resim frame (scalar half replayed from recorded trajectory)");
    } else {
        orig_go_kick(param_1);
    }
}

// WINDOW-THREAD RENDER WITNESS (FUN_14053caf0): the window thread's draw-build chain entry — reached only via
// its loop's vtable+0x30 dispatch (no static callers). Root fault: freeze() catches the
// window thread MID-draw-build-iteration; arena::load swaps the world under it (entities reverted to frame N,
// sRender body kept live at N+depth); thaw resumes it mid-iteration into that MIXED-EPOCH world => WRITE to
// [null+0x8000] inside the chain (regs full of srcframe=-3 = F_REDERIVE-kept-live pages). A gate (flag or hook)
// only stops future iterations — the straddling one must EXIT before freeze. This hook is the positive witness:
// in_render is true exactly while an iteration is in flight, so the pre-freeze quiesce (zero the engine's own
// WndProc deactivation flags wmgr+0x38/+0x2985, then wait !in_render) knows when the thread is parked at its
// own Sleep(1) gate, holding nothing.
// Update: FUN_14053caf0 is the SHARED draw-build entry — called by the window thread's
// loop and by MAIN_PROC's per-frame subsystem tick FUN_140458320 (vtable+0x30 on 5 subsystems). The GO-kick we
// suppress on intermediate frames is also what sets up the frame's command-ring pointers (FUN_14079fa40/fee0 ->
// sRender+0x8676b8/+0x8676c0). Kick skipped + build still running = the build emits into a NULL ring cursor =>
// the WRITE [0+0x8000] root fault (MAIN_PROC -> FUN_140458320 -> here -> FUN_140638ea0). Kick and build are two
// halves of one frame's render production: "render only the final frame" must skip both. BUILD is render-only
// (CRC-verified) => skipping it cannot diverge gameplay.
static constexpr uintptr_t WINDOW_RENDER_IDA = 0x14053CAF0;
typedef void (*window_render_fn)(int64_t);
static window_render_fn orig_window_render = nullptr;
// FULL-ITERATION witness (the build-only witness had a hole): the window thread's
// active branch is [FUN_14053ede0?] -> FUN_14053d690 (device-reset handler; a real Reset takes tens of ms)
// -> vtable+0x30 (the build). Caught mid-d690-Reset, the build-only witness read false => false park =>
// freeze suspended a half-done device Reset => msvcrt fault at freeze time. Now both stages bump a shared
// depth counter, and the quiesce waits depth==0 (twice, 1ms apart) with a Reset-sized bound.
static volatile LONG g_window_iter_depth = 0;
static volatile bool g_rollback_render_block = false;  // quiesce-start.. post-resim re-arm: build no-ops
static volatile LONG g_build_skips = 0;
// The streaming-voice pump (FUN_1405cb490) is deliberately NOT suppressed during the rollback window: suppressing it
// starved the streams (~260ms gap per rollback => underrun => the engine ends the voice => permanent silence), and
// the ogg over-read it was meant to prevent fires in normal play post-rollback, not during the window. voice_pool
// blocks new voice acquire during resim (g_resim_sound_block); ongoing decode is left alone.
// Window-thread TID capture + first-N probe (which hook fires on which thread).
static volatile LONG g_wtfire_n = 0;
static void wt_fire(const char* fn) {
    DWORD t = GetCurrentThreadId();
    bool offmain = (g_main_proc_tid && t != g_main_proc_tid);
    if (offmain) suspend::note_window_thread(t);   // tag the window thread for thaw's hold-by-TID
    LONG n = InterlockedIncrement(&g_wtfire_n);
    if (n <= 12) rblog::write("WT-FIRE: %s tid=%u main=%u offmain=%d", fn, t, g_main_proc_tid, (int)offmain);
}
static void hk_window_render(int64_t param_1) {
    wt_fire("caf0");   // the build — the window loop's vtable+0x30; runs on the window thread (and main tick)
    if (g_rollback_render_block) {   // BUILD gate decoupled from the kick gate: on the FINAL resim frame the
                                     // kick stays suppressed (no EXEC) but the BUILD must run (fresh commands
                                     // for the first normal frame's EXEC — the engine's BUILD(N)/EXEC(N-1) pipeline)
        // Intermediate resim frame (kick/ring setup skipped => build must be too), or the rollback window
        // (a thread that slipped past the quiesce no-ops through the build and parks at its gate).
        LONG n = InterlockedIncrement(&g_build_skips);
        if (n == 1) rblog::write("BUILD-SUPPRESS: skipped shared draw-build (FUN_14053caf0) during rollback window");
        return;
    }
    InterlockedIncrement(&g_window_iter_depth);
    orig_window_render(param_1);
    InterlockedDecrement(&g_window_iter_depth);
}

// Device-reset handler (FUN_14053d690) — witnessed, never skipped (engine device management must run).
static constexpr uintptr_t DEVICE_RESET_CHECK_IDA = 0x14053D690;
typedef void (*device_reset_fn)(int64_t);
static device_reset_fn orig_device_reset = nullptr;
static void hk_device_reset(int64_t param_1) {
    wt_fire("d690");   // capture window TID + probe (the thread is identified by TID, not by start address)
    InterlockedIncrement(&g_window_iter_depth);
    orig_device_reset(param_1);
    InterlockedDecrement(&g_window_iter_depth);
}

// Capture path (FUN_14053ede0, 410B) — the active branch's first call (conditional on DAT_140e1a198 bits),
// running before d690. Witnessed so the quiesce gap shrinks to the flag-check->first-call instructions
// (a thread frozen in the unwitnessed pre-call gap would false-park the quiesce and thaw into the
// active branch mid-rollback).
static constexpr uintptr_t CAPTURE_PATH_IDA = 0x14053EDE0;
typedef void (*capture_path_fn)(int64_t, char, void*, int64_t);
static capture_path_fn orig_capture_path = nullptr;
static void hk_capture_path(int64_t a, char b, void* c, int64_t d) {
    wt_fire("ede0");
    InterlockedIncrement(&g_window_iter_depth);
    orig_capture_path(a, b, c, d);
    InterlockedDecrement(&g_window_iter_depth);
}

// FINALIZER-ALIEN probe (read-only): FUN_14053a250 (IDA: class1_vfunc_2 — a VIRTUAL) is the common spine of
// both drain crashes (finalizer -> FUN_14053a570 deferred-COM drain -> walks a live-epoch list entry into
// reverted arena memory). Both ran on a thread with start=FUN_14051dee0 whose wmgr flags were zero
// (RESET-DIAG) — entry path unknown (not MAIN_PROC: MAINPROC-ALIEN was silent; live caller frame =
// FUN_140259ea0, an 86-byte vfunc dispatcher). A real backtrace on off-main entry names it.
static constexpr uintptr_t FINALIZER_IDA = 0x14053A250;
typedef void (*finalizer_fn)(int64_t, int64_t, int64_t, int64_t);
static finalizer_fn orig_finalizer = nullptr;
static void hk_finalizer(int64_t a, int64_t b, int64_t c, int64_t d) {
    if (g_main_proc_tid && GetCurrentThreadId() != g_main_proc_tid) {
        static volatile LONG n_fin = 0;
        LONG n = InterlockedIncrement(&n_fin);
        if (n <= 6) {
            void* frames[24] = {};
            USHORT got = CaptureStackBackTrace(1, 24, frames, nullptr);
            uintptr_t mod = (uintptr_t)GetModuleHandleA("umvc3.exe");
            char line[512]; int o = 0;
            for (USHORT i = 0; i < got && o < 440; i++) {
                uintptr_t f = (uintptr_t)frames[i];
                if (mod && f >= mod && f < mod + 0xA00000)
                    o += snprintf(line + o, sizeof(line) - o, " 0x%llX", (unsigned long long)(f - mod + 0x140000000ULL));
                else
                    o += snprintf(line + o, sizeof(line) - o, " [ext]");
            }
            bool was = rblog::is_suppressed(); rblog::suppress(false);
            rblog::write("FINALIZER-ALIEN: tid=%u FUN_14053a250 off-main (resim=%d)! REAL chain:%s",
                         GetCurrentThreadId(), (int)g_resim_active, line);
            rblog::suppress(was);
        }
    }
    orig_finalizer(a, b, c, d);
}

// DISPATCH-ALIEN probe (read-only): FUN_14055fbc0 is the consume-and-null dispatcher at the heart of the
// garbage-vtable crash (observed on the window thread mid-resim, entry path unknown — the raw stack scan
// is untrustworthy and run_and_wait was ruled out by RESIM-RW-ALIEN silence). When it runs
// OFF-MAIN during resim, capture a PROPER backtrace (CaptureStackBackTrace) and log the real entry chain.
static constexpr uintptr_t ELEM_DISPATCH_IDA = 0x14055FBC0;
typedef void (*elem_dispatch_fn)(int64_t, int64_t, int64_t, int64_t);
static elem_dispatch_fn orig_elem_dispatch = nullptr;
static volatile LONG g_dispatch_alien_logged = 0;
static void hk_elem_dispatch(int64_t a, int64_t b, int64_t c, int64_t d) {
    if (g_resim_active && g_main_proc_tid && GetCurrentThreadId() != g_main_proc_tid) {
        LONG n = InterlockedIncrement(&g_dispatch_alien_logged);
        if (n <= 4) {
            void* frames[24] = {};
            USHORT got = CaptureStackBackTrace(1, 24, frames, nullptr);
            uintptr_t mod = (uintptr_t)GetModuleHandleA("umvc3.exe");
            char line[512]; int o = 0;
            for (USHORT i = 0; i < got && o < 440; i++) {
                uintptr_t f = (uintptr_t)frames[i];
                if (mod && f >= mod && f < mod + 0xA00000)
                    o += snprintf(line + o, sizeof(line) - o, " 0x%llX", (unsigned long long)(f - mod + 0x140000000ULL));
                else
                    o += snprintf(line + o, sizeof(line) - o, " [ext]");
            }
            rblog::write("DISPATCH-ALIEN: tid=%u FUN_14055fbc0 off-main mid-resim, REAL chain:%s", GetCurrentThreadId(), line);
        }
    }
    orig_elem_dispatch(a, b, c, d);
}

// BONE-REFERENT probe (the a-vs-c discriminator for the 0x14080DA5D crash). 0x14080DA5D is not the
// effect-child UAF; it is a referent-coherence failure: bone+0x108 -> shared-asset record R0; the bone +0x140
// gate passes (faithful restore) but *(u16*)(R0+0x6e) reads exact-0 (non-zero at frame N) => lVar10=0 =>
// *(0+0x30) crash. The fix family is referent-coherence; the open question is the carrier: (a) R0 out-of-arena/
// external vs (c) R0 in-arena but orphan-zeroed by arena::load's memset. This read-only hook fires at the crash
// precondition (gate passes, +0x6e==0) and classifies R0's page.
static constexpr uintptr_t BONE_CONSUME_IDA = 0x14080DA10;   // FUN_14080da10 (the crash fn), single caller
typedef void (*bone_consume_fn)(int64_t);
static bone_consume_fn orig_bone_consume = nullptr;
static volatile LONG g_bone_ref_logged = 0;
static void hk_bone_consume(int64_t bone) {
    // Crash-B observer. Classify R0=*(bone+0x108) at the crash precondition without a hot-path syscall and
    // without itself faulting on a float-as-pointer reused slab (orig faults at the same read, so an unguarded
    // probe read would just relocate the crash into this hook). For in-arena R0, use the arena's committed
    // bitmap (no syscall) to decide readability; for out-of-arena R0 do not read +0x6e (it is the (a) external
    // carrier regardless of content). Catches R0-NULL (the +0x39 crash B) + R0-WILD (reuse) + content-0 (+0x4D).
    // Bounded to 24 logs (all reads stop after). Observe-only — never skips orig.
    if (g_bone_ref_logged < 24 && bone > 0x10000) {
        uintptr_t lVar7 = *(uintptr_t*)(bone + 0x140);   // engine reads this; the bone is valid here
        if (lVar7) {
            uintptr_t R0  = *(uintptr_t*)(bone + 0x108);
            bool ina  = (R0 > 0x10000) && arena::is_arena_addr(R0);
            bool orph = ina && arena::was_orphaned_last_load(R0);
            const char* carrier = nullptr; int v6e = -1;
            if (R0 == 0)
                carrier = "R0-NULL (+0x39 fault: bone+0x108 reverted/reused-null)";
            else if (!ina)
                carrier = "(a)EXTERNAL (R0 out-of-arena — the revert never touched it)";
            else if (!arena::is_committed_addr(R0 + 0x6e))   // cheap bitmap (no syscall); catches float-as-ptr + orphan-memset
                carrier = orph ? "(c)ARENA-ORPHAN (R0 page memset/uncommitted)"
                               : "R0-WILD/uncommitted (reused-slab float-as-ptr)";
            else { v6e = *(uint16_t*)(R0 + 0x6e);
                if (v6e == 0) carrier = orph ? "(c)ARENA-ORPHAN-content0" : "(?)in-arena content0 (restore-stale)"; }
            if (carrier) {
                InterlockedIncrement(&g_bone_ref_logged);
                rblog::write("BONE-REF(B): bone=0x%llX R0=0x%llX +0x6e=%d in_arena=%d orphaned=%d srcframe=%d => %s",
                    (unsigned long long)bone, (unsigned long long)R0, v6e, ina?1:0, orph?1:0,
                    (R0 > 0x10000) ? arena::last_source_frame(R0) : -100, carrier);
            }
        }
    }
    orig_bone_consume(bone);   // observe-only: never skip; orig faults if it will (carrier logged first)
}

static int g_last_rollback_target = -1;        // target frame of the most recent rollback (diagnostics)
static volatile LONG g_frames_since_rollback = 1000000;  // forward frames since resim completed (large = far/never); the discriminator-freshness gate
static volatile LONG g_any_rollback = 0;       // monotonic: has any rollback happened this session (P4 latent gate)
static float g_last_normal_delta_T = 0.002f;  // safe default
static long g_reconfig_at_frame[256] = {0};   // cDraw FUN_1401ffca0 count snapshotted per saved frame (QUARANTINE-vs-TRUNCATE decider)

// No D3D device content backup (preserve rule): the D3D9 device is EXTERNAL — out-of-arena, so arena::load
// never touches it. Its +0xB0 pointer EDGE is preserved by dyn_restore (F_PRESERVE +0xB0 in SRENDER_FIELDS)
// + the sRender rederive-exclusion. A 0x8000 content memcpy over-read the device's committed extent => an
// access violation. Never copy a device's contents.

// Frame pacer hook — replay last normal-play delta_T during resim
static void hk_frame_pacer(int64_t param_1) {
    orig_frame_pacer(param_1);
    // delta_T is not pinned to 1/60: the engine is not delta-time driven. 60fps fixed timestep: sMain+0x80 = 1.0
    // always; delta_T (sMain+0x40038) is a sub-frame interpolation value (~0.002s), not the frame timestep. Forcing
    // it to 1/60 = 0.0167 writes ~8x its normal magnitude into an interpolation term — which is why the engine's own
    // heuristic below treats anything >= 0.01 as abnormal. The game is already fixed-timestep, so there is no
    // per-machine timestep divergence to fix here. Menu "fast ticking" is an input-edge problem, not a clock problem.
    if (g_resim_active) {
        float old_dt = *(float*)(param_1 + 0x40038);
        *(float*)(param_1 + 0x40038) = g_last_normal_delta_T;
        monitor_shm::log_write(
            monitor_shm::g_mon ? monitor_shm::g_mon->current_frame : 0,
            PHASE_PACER_FIX, 0,
            (uint64_t)param_1, 0xFFFF,
            *(uint64_t*)&old_dt, *(uint64_t*)(param_1 + 0x40038));
    } else {
        float dt = *(float*)(param_1 + 0x40038);
        if (dt > 0.0001f && dt < 0.01f) {
            g_last_normal_delta_T = dt;
        } else if (dt < 0.0001f && g_last_normal_delta_T > 0.0001f) {
            // QPC precision recovery — substitute last good value
            *(float*)(param_1 + 0x40038) = g_last_normal_delta_T;
        }
    }
    // 60fps limiter: UMvC3's frame cap relies on VSYNC, which two windowed Steamless twins defeat
    // → the front-end free-runs at ~2x (uncontrollable menus) and each peer at its OWN rate (incoherent relay). The
    // engine EXPECTS 60; we supply the missing hard cap in the pacer seam we already own. Netplay-armed only (solo
    // play untouched) and SKIPPED during resim (which must replay frames fast). QPC sleep-to-boundary + spin.
    if (net::session_armed() && !g_resim_active) {
        static LARGE_INTEGER s_freq = {}, s_last = {};
        if (s_freq.QuadPart == 0) { QueryPerformanceFrequency(&s_freq); QueryPerformanceCounter(&s_last); }
        const double frame_ticks = (double)s_freq.QuadPart / 60.0;
        LARGE_INTEGER now; QueryPerformanceCounter(&now);
        double elapsed = (double)(now.QuadPart - s_last.QuadPart);
        if (elapsed > 0 && elapsed < frame_ticks) {
            double remain_ms = (frame_ticks - elapsed) * 1000.0 / (double)s_freq.QuadPart;
            if (remain_ms > 1.5) Sleep((DWORD)(remain_ms - 1.0));            // sleep most of it, leave ~1ms for the spin
            do { QueryPerformanceCounter(&now); } while ((double)(now.QuadPart - s_last.QuadPart) < frame_ticks);
        }
        s_last = now;   // if we were skipped a while (resim/disarmed), elapsed >> frame_ticks → no wait, self-corrects
    }
}

// Rollback depth cap. Resim costs ~12.7ms per replayed frame against a 16.6ms budget, so depth 2 (~35ms) already
// drops ~2 frames; past the cap the correction is skipped and the divergence stands rather than freezing the match.
// An earlier cap of 3 was chosen from the resim cost alone, but the measured prediction depth on the test link is
// ~6-7, so every rollback the netcode requested was skipped — rollback was armed and structurally unable to repair
// the one thing it exists for. A depth-6 rollback costs ~86ms (about 5 dropped frames): a visible hitch, but one
// that keeps the input rather than silently discarding it.
static constexpr int MAX_ROLLBACK_DEPTH = 6;
static volatile LONG g_rb_request = -1;    // deepest requested rollback target, -1 = none
static bool g_engine_on = false;   // AUTO-ARMED (no F5), SCOPED TO the active MATCH: armed while game-flow phase==5, disarmed otherwise.
// Settle margin before arming (RE): arm only after phase has held ==5 for this many frames, so the
// baseline lands on the quiescent steady state (matches the mid-match arming the long runs used). ~30 likely enough; 60 (=1.0s)
// is the conservative floor. Runtime-calibratable (watch arena::log_growth flatten after phase->5, then lock).
static constexpr int NET_ENGINE_SETTLE_FRAMES = 60;
// RE DIAGNOSTIC hooks (gp_crc/effect_probe/byid) — pure measurement, not needed to play or to roll back. An A/B
// with the hooks off showed they are the steady normal-play tax (157 slow frames -> 6). OFF by default; re-arm
// for an RE run.
static volatile LONG g_diag_enabled = 0;
// Scene tree dispatch hook — validates child vtables before dispatching. Skips freed children (vtable outside the
// game module = allocator bookkeeping).
static void hk_scene_tree_dispatch(int64_t param_1, int64_t param_2, int64_t param_3) {
    // PERF: our freed-child-skipping reimplementation recurses through this hook for every scene-graph node
    // every frame — pure normal-play tax (a stale child link only exists after an arena::load). When the
    // rollback engine is OFF, call the engine's OWN (faster, non-reentrant) dispatch and return. The freed-
    // child guard stays active while the engine is on (covers the rollback window). Zero behavior change in
    // normal play — this is exactly what the engine did before the mod existed.
    arena::hook_count_inc(0);   // perf bisection: scene_tree dispatch invocations/frame (recurses per node)
    if (!g_engine_on && orig_scene_tree_dispatch) { orig_scene_tree_dispatch(param_1, param_2, param_3); return; }
    uintptr_t child = *(uintptr_t*)(param_1 + 0x08);
    while (child) {
        uintptr_t next = *(uintptr_t*)(child + 0x58);  // save before dispatch
        uintptr_t vt = *(uintptr_t*)child;
        uintptr_t vt_off = vt - addr::g_base;

        if (vt_off < 0xE00000) {
            // Valid vtable — dispatch through vtable+0xB0
            // Recurses through this hook for scene node children
            uintptr_t func = *(uintptr_t*)(vt + 0xB0);
            ((void(*)(int64_t, int64_t, int64_t))func)(child, param_2, param_3);
        }
        // Invalid vtable: skip (freed entity, allocator bookkeeping)

        child = next;
    }
}

// Keyframe push_front guard — prevents underflow when arena::load restores count=0
static constexpr uintptr_t KEYFRAME_PUSHFRONT_IDA = 0x140839200;
typedef void (*keyframe_pushfront_fn)(int64_t param_1, int64_t param_2);
static keyframe_pushfront_fn orig_keyframe_pushfront = nullptr;

static void hk_keyframe_pushfront(int64_t param_1, int64_t param_2) {
    uint8_t count = *(uint8_t*)(param_2 + 0x9D);
    if (count == 0) {
        *(uint8_t*)(param_2 + 0x9D) = 1;
    }
    orig_keyframe_pushfront(param_1, param_2);
}

// (g_engine_on is defined above, next to the scene-tree gate.)
static bool g_auto_rollback = false;  // F6 toggled
static bool g_alloc_rederive = false; // F8 toggled — structure-aware allocator restore (re-derive free-list counts)
static bool g_bone_forcedirty_off = false; // F9 toggled — A/B the bone-block force-dirty
// Perf gates (default OFF = the heavy diagnostic probes are off; arm individually for an RE run).
static volatile LONG g_alloc_consist  = 0;  // the %20 alloc_consistency::check x8 + AllocatorSnapshotCsScope lock-all + scheduler_save_scan (the measured ALLOC-CONSIST cluster)
static volatile LONG g_atomic_save    = 1;  // Atomic allocator save: ON. The free-list splice (FUN_1404cb480) is
                                            // a TWO-PART reciprocal write (X.next=Y; Y.prev=X) under the per-size-class
                                            // CS; a blind SuspendThread freeze can stop a worker between the two writes
                                            // => the snapshot captures a TORN list => every restore reproduces it (the
                                            // all-same-srcframe POSTLOAD reciprocity breaks, on every allocator, every
                                            // stage). Holding the alloc CSes across {save_allocators + arena::save} makes
                                            // the {descriptor,nodes} group captured with NO splice in flight = coherent.
                                            // (ALLOC-list breaks are false positives — the engine keeps the alloc list
                                            // next-only. The fault this fixes is the FREE-list reciprocal tear.
                                            // Metric = FREE_LIST PL->0.)
// FORCE-DIRTY (default OFF): the per-frame entity force-dirty walk. Its capture rationale does not hold —
// arena::load reassembles every page of an object from the same target frame, so objects are coherent by
// construction, and gp_crc shows DIVERGE=0 without it. The effect/audio substrate groups are harmful with it ON
// (+0x198/child+0x50 are REBUILD fields; restoring them recreates the +0x198 crash). The walk itself is cheap
// (~0.65ms) but it DIRTIES a page per touched entity node, inflating the per-frame save's copy (2300+ dirty
// pages/frame, worst during super churn), so it is off by default to shrink the save. gp_crc (F4) is the standing
// validation gate; Numpad3 restores the walk for A/B.
static volatile LONG g_forcedirty_off = 1;
// Per-phase profiler — measures every frame, so it is a probe: OFF by default. Arm for a perf RE run.
static volatile LONG g_prof_on = 0;
// SLOW-FRAME logger (outlier-only): silent when frames are fine, logs only frames slower than the threshold — catches the
// periodic "chug window" with zero per-frame spam. RAII so it covers every exit path of hk_main_proc (no mis-placement).
static volatile LONG g_slowframe = 0;       // default OFF: per-frame timer + growth meter; Numpad7 arms for a debug run
static const double  g_slowframe_ms = 40.0;     // log frames slower than this (~<25fps)
static LARGE_INTEGER g_prof_freq = {};
static double g_prof_acc[9] = {0,0,0,0,0,0,0,0,0};   // 0 forcedirty,1 drain,2 save_core,3 arena,4 byid,5 gp_crc,6 serializer,7 tail_misc,8 total
static int    g_prof_n = 0;
static inline double prof_ms(const LARGE_INTEGER& a, const LARGE_INTEGER& b) {
    if (!g_prof_freq.QuadPart) QueryPerformanceFrequency(&g_prof_freq);
    return (double)(b.QuadPart - a.QuadPart) * 1000.0 / (double)g_prof_freq.QuadPart;
}
// RAII slow-frame logger: ctor stamps entry, dtor logs IF this hk_main_proc frame exceeded the threshold. Covers every
// exit path; silent on smooth frames (no spam) => isolates the periodic "chug window" + its cadence.
struct SlowFrameTimer {
    LARGE_INTEGER a; DWORD tid;
    SlowFrameTimer() { tid = GetCurrentThreadId(); if (g_slowframe) { QueryPerformanceCounter(&a); arena::hook_count_reset(); } else a.QuadPart = 0; }
    ~SlowFrameTimer() {
        if (!g_slowframe || !a.QuadPart) return;
        LARGE_INTEGER b; QueryPerformanceCounter(&b);
        double ms = prof_ms(a, b);
        if (ms > g_slowframe_ms) {
            static volatile LONG n = 0; LONG k = InterlockedIncrement(&n);
            if (k <= 400)
                rblog::write("SLOWFRAME #%ld: %.1f ms (engine=%d thread=%s) | FIRES: scene_tree=%ld mtfree=%ld carve=%ld heapalloc=%ld consume=%ld",
                    k, ms, (int)g_engine_on, (tid == g_main_proc_tid ? "MAIN" : "ALIEN/window"),
                    arena::hook_count_get(0), arena::hook_count_get(1), arena::hook_count_get(5),
                    arena::hook_count_get(2), arena::hook_count_get(3));
        }
    }
};
// SUBSTRATE COHERENCE — split into two independently-toggleable halves so audio-only vs effect-only can be A/B'd.
// An A/B showed the combined fix recreates the +0x198==0 crash during resim (16 hits ON / 0 OFF): force-dirty
// RESTORES the effect's producer-derived +0x198 binding, which must be REBUILT, not restored. Audio's derived
// pointers are blob-relative (self-coherent under restore), so the two halves are not equivalent — isolate them.
// Numpad1=effect, Numpad2=audio. DEFAULT OFF.
static bool g_sc_effect = false;   // Numpad1 — effect coherence group (template/child/slab). Reverts the derived +0x198.
static bool g_sc_audio  = false;   // Numpad2 — audio coherence group (SE-table/blob/index). Self-relative.
static int g_frame_counter = 0;
static bool g_horizon_clock_armed = false;   // g_frame_counter is reset to 0 once (first activation), then free-runs across re-arms (horizon monotonicity)
static int g_rollback_depth = 7;

// OWNED-HEAP P4 gates (see resim.h). Default = legacy (control_revert OFF, pile ON); the dllmain master flips them.
static volatile bool g_oh_control_revert = false;   // ON => save/restore_allocators no-op; page-blind owns the control (no alloc-ring skew)
static volatile bool g_oh_patch_pile     = true;    // OFF => coherent_set_repair/alloc_invariants::repair/coherence_audit::repair skipped (check kept)
void set_owned_heap_control_revert(bool on) { g_oh_control_revert = on; }
bool owned_heap_control_revert()            { return g_oh_control_revert; }
void set_patch_pile_enabled(bool on)        { g_oh_patch_pile = on; }
bool patch_pile_enabled()                   { return g_oh_patch_pile; }
static int g_last_auto_frame = 0;
static constexpr int AUTO_INTERVAL = 180;  // ~3s at 60fps

// ============================================================
// PE.data section save/restore — full .data to ring buffer.
// ConcRT and CRT values preserved across restore.
// ============================================================

static uintptr_t g_data_start = 0;
static size_t g_data_size = 0;

// Curated PRESERVE list — CRT/OS fields that must survive .data restore.
// Everything else in .data gets restored (game state, constants, all of it).
struct PreserveEntry {
    uintptr_t ida_offset;  // offset from 0x140000000
    size_t    size;
};

static const PreserveEntry g_preserve_list[] = {
    // CRT security cookie + inverse
    { 0xD41D40, 16 },
    // CRT mode flags, wchar buffer, FLS index, init flag
    { 0xD420DC, 4 },
    { 0xD420E0, 8 },
    { 0xD4215C, 4 },
    { 0xD42160, 4 },
    // CRT locale pointers
    { 0xD42378, 8 },
    { 0xD42970, 8 },
    // CRT timezone data
    { 0xD42DE0, 24 },
    // Console output HANDLE
    { 0xD437A8, 8 },
    // DTI property pool CriticalSection (OS resource)
    { 0xD766F8, 40 },
    // CRT GetLastError cache
    { 0xE16AB4, 4 },
    // CRT struct tm cache
    { 0xE16E80, 40 },
    // CRT environment strings/count/pointers
    { 0xE21308, 8 },
    { 0xE2131C, 4 },
    { 0xE21320, 8 },
    { 0xE21330, 8 },
    { 0xE21338, 8 },
    // CRT lock count
    { 0xE21370, 4 },
    // Process heap handle
    { 0xE21BD0, 8 },
    // CRT signal/exception handlers (EncodePointer values)
    { 0xE21F60, 40 },
    // CRT locale buffer
    { 0xE21FB0, 8 },
    { 0xE21FB8, 4 },
    // CRT crash/security exception state
    { 0xE22070, 0x198 },
    // EncodePointer handler table
    { 0xE22600, 40 },
    // TLS encoded callbacks + slot tracking
    { 0xE22F20, 0xF8 },
    // CRT atexit handlers
    { 0xE24028, 16 },
    // GlobalAlloc handle (device array)
    { 0xE1C5F0, 8 },
};
static constexpr int PRESERVE_COUNT = sizeof(g_preserve_list) / sizeof(g_preserve_list[0]);
static uint8_t g_preserve_buf[2048];

// .data ring buffer (~1.9MB × 10 slots = ~19MB)
static constexpr int DATA_RING_SLOTS = 10;
static uint8_t* g_data_ring[DATA_RING_SLOTS] = {};
static int g_data_ring_frames[DATA_RING_SLOTS];
static int g_data_ring_head = 0;

// Heap zone offset ring
static long long g_hz_ring[DATA_RING_SLOTS] = {};
static int g_hz_ring_frames[DATA_RING_SLOTS];
static int g_hz_ring_head = 0;

static void find_data_section() {
    uintptr_t base = addr::g_base;
    auto* dos = (IMAGE_DOS_HEADER*)base;
    auto* nt = (IMAGE_NT_HEADERS*)((uint8_t*)base + dos->e_lfanew);
    auto* sec = IMAGE_FIRST_SECTION(nt);
    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++, sec++) {
        if ((sec->Characteristics & IMAGE_SCN_MEM_WRITE) &&
            !(sec->Characteristics & IMAGE_SCN_MEM_EXECUTE) &&
            sec->Misc.VirtualSize > 0x100000) {
            g_data_start = base + sec->VirtualAddress;
            g_data_size = sec->Misc.VirtualSize;
            rblog::write("DATA: .data section at 0x%llX size 0x%zX (%.1f MB)",
                        (unsigned long long)g_data_start, g_data_size,
                        (double)g_data_size / (1024.0 * 1024.0));
            break;
        }
    }
}

static void init_data_ring() {
    for (int i = 0; i < DATA_RING_SLOTS; i++) {
        g_data_ring[i] = (uint8_t*)VirtualAlloc(NULL, g_data_size,
                                                  MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        g_data_ring_frames[i] = -1;
        g_hz_ring_frames[i] = -1;
    }
    rblog::write("DATA: allocated %d ring slots (%.1f MB total)",
                DATA_RING_SLOTS, (double)(g_data_size * DATA_RING_SLOTS) / (1024.0 * 1024.0));
}

static void save_data(int frame) {
    if (!g_data_start) return;
    int slot = g_data_ring_head;
    g_data_ring_frames[slot] = frame;
    memcpy(g_data_ring[slot], (void*)g_data_start, g_data_size);
    g_data_ring_head = (g_data_ring_head + 1) % DATA_RING_SLOTS;
}

static void restore_data(int target_frame) {
    if (!g_data_start) return;
    int best = -1;
    for (int s = 0; s < DATA_RING_SLOTS; s++) {
        if (g_data_ring_frames[s] >= 0 && g_data_ring_frames[s] <= target_frame) {
            if (best < 0 || g_data_ring_frames[s] > g_data_ring_frames[best])
                best = s;
        }
    }
    if (best < 0) {
        rblog::write("DATA: no ring slot for frame %d!", target_frame);
        return;
    }

    // 1. Save PRESERVE fields (current-timeline CRT/OS state)
    size_t offset = 0;
    for (int i = 0; i < PRESERVE_COUNT; i++) {
        uintptr_t a = addr::g_base + g_preserve_list[i].ida_offset;
        size_t sz = g_preserve_list[i].size;
        memcpy(g_preserve_buf + offset, (void*)a, sz);
        offset += sz;
    }

    // 2. Restore full .data from ring slot
    memcpy((void*)g_data_start, g_data_ring[best], g_data_size);

    // 3. Write back PRESERVE fields
    offset = 0;
    for (int i = 0; i < PRESERVE_COUNT; i++) {
        uintptr_t a = addr::g_base + g_preserve_list[i].ida_offset;
        size_t sz = g_preserve_list[i].size;
        memcpy((void*)a, g_preserve_buf + offset, sz);
        offset += sz;
    }

    rblog::write("DATA: restored .data from slot %d (frame %d) for target %d, preserved %d entries (%zu bytes)",
                best, g_data_ring_frames[best], target_frame, PRESERVE_COUNT, offset);
}

static void save_heap_zone(int frame) {
    int slot = g_hz_ring_head;
    g_hz_ring_frames[slot] = frame;
    g_hz_ring[slot] = arena::get_heap_zone_offset();
    g_hz_ring_head = (g_hz_ring_head + 1) % DATA_RING_SLOTS;
}

static void restore_heap_zone(int target_frame) {
    int best = -1;
    for (int s = 0; s < DATA_RING_SLOTS; s++) {
        if (g_hz_ring_frames[s] >= 0 && g_hz_ring_frames[s] <= target_frame) {
            if (best < 0 || g_hz_ring_frames[s] > g_hz_ring_frames[best])
                best = s;
        }
    }
    if (best >= 0) {
        arena::set_heap_zone_offset(g_hz_ring[best]);
        rblog::write("HEAP-ZONE: restored offset to %lld for frame %d",
                    g_hz_ring[best], target_frame);
    }
}

// ============================================================
// Allocator metadata save/restore
// MtScalableAllocator control objects are HeapAlloc'd (redirected into the arena heap zone when owned-heap is
// on). Without owned-heap control revert, arena::load restores the blocks they manage but not the control
// objects, so we save/restore them per-frame here, skipping the CRITICAL_SECTION ranges.
// ============================================================

static constexpr int MAX_ALLOCS = 16;   // registry coverage (a bump to 40 with re-discovery coincided with an alloc-list corruption regression and was reverted)
static uintptr_t g_alloc_addrs[MAX_ALLOCS];
static int g_alloc_count = 0;
static bool g_allocs_discovered = false;

// Per-frame allocator ring buffer — synchronized with arena ring
static constexpr int ALLOC_RING_SLOTS = 10;
static uint8_t g_alloc_ring[ALLOC_RING_SLOTS][MAX_ALLOCS][0x660];
static int g_alloc_ring_frames[ALLOC_RING_SLOTS] = {-1,-1,-1,-1,-1,-1,-1,-1,-1,-1};
static int g_alloc_ring_count[ALLOC_RING_SLOTS] = {0};   // per-slot allocator count (registry GROWS => count at save != count at restore; restore only what this slot saved)
static int g_alloc_ring_head = 0;
static uint32_t g_last_reg_count = 0;                    // last seen registry entry count (re-discover when it changes)

// CS ranges within each allocator to SKIP during restore (keep live OS handles)
static constexpr struct { size_t off; size_t len; } CS_RANGES[] = {
    {0x060, 0x28}, {0x158, 0x28}, {0x200, 0x28}, {0x2A8, 0x28},
    {0x350, 0x28}, {0x3F8, 0x28}, {0x4A0, 0x28}, {0x548, 0x28},
    {0x5F0, 0x28}, {0x620, 0x28}
};

// CS KEEP-LIVE (OS state is never rolled back) + CS CANARY — the ntdll-contention class,
// Crash (an earlier long run): ntdll+0x649E6 = contended EnterCriticalSection writing DebugInfo->ContentionCount
// (`mov rax,[rbx]; cmp rax,-1; inc [rax+0x24]`) through garbage 0x20007D0, rbx=Collision ctrl+0x80. The ctrls
// live IN ARENA PAGES: restore_allocators' blob memcpy carefully SKIPS CS_RANGES, but the page-blind arena
// restore rewrites those same bytes from epoch <=T every rollback — undermining the skip. CRITICAL_SECTIONs are
// EXTERNAL/OS state ("keep external coherent"): they must pass through a
// rollback untouched. KEEP-LIVE: snapshot the live CS bytes immediately before arena::load, write them back
// right after restore_allocators — by construction no CS byte ever comes from the ring/baseline.
// +0x60-vs-+0x80 conflict resolved: the ctor chain (0x14025631d→0x140255f80→
// 0x140255f50/0x140255f10→0x140054250→InitializeCriticalSection) and the mirror dtor (0x1404ca000→0x1404c7930,
// 10 deletes in reverse order) PROVE CS_RANGES is byte-correct: real CSes = ctrl+0x60, the 8 mgr CSes, ctrl+0x620.
// ctrl+0x80 is not a CS — it is the +0x60 CS's SpinCount field, and that crash's "CS at ctrl+0x80" was
// actually the free path (0x1404cb382-3b2) deriving mgr from a CORRUPT block +0x3c (class bits 30 => 29 strides
// past the mgr array => Unit_ctrl+0x1460 == Collision+0x80) — the a4 header-scribble family, not a CS-layout bug.
// So keep-live covers exactly the ten proven CSes; the bytes at ctrl+0x88..0xA8 are pool bookkeeping and must
// stay blob/page-restored (game state).
static constexpr struct { size_t off; size_t len; } CS_KEEPLIVE[] = {
    {0x060, 0x28},                                                     // ctrl base CS (ctor-proven)
    {0x158, 0x28}, {0x200, 0x28}, {0x2A8, 0x28}, {0x350, 0x28},        // the 8 mgr CSes (mgr k = ctrl+0xd8+k*0xa8, CS at mgr+0x80)
    {0x3F8, 0x28}, {0x4A0, 0x28}, {0x548, 0x28}, {0x5F0, 0x28},
    {0x620, 0x28}                                                      // reserve-list CS (ctor-proven)
};
static constexpr int CS_KEEPLIVE_N = (int)(sizeof(CS_KEEPLIVE)/sizeof(CS_KEEPLIVE[0]));
static uint8_t g_cs_keep[MAX_ALLOCS][CS_KEEPLIVE_N][0x48];
static volatile LONG64 g_cs_keeplive_rollbacks = 0;
static void cs_keeplive_snapshot() {
    for (int i = 0; i < g_alloc_count; i++)
        for (int c = 0; c < CS_KEEPLIVE_N; c++)
            memcpy(g_cs_keep[i][c], (void*)(g_alloc_addrs[i] + CS_KEEPLIVE[c].off), CS_KEEPLIVE[c].len);
}
static void cs_keeplive_restore() {
    for (int i = 0; i < g_alloc_count; i++)
        for (int c = 0; c < CS_KEEPLIVE_N; c++)
            memcpy((void*)(g_alloc_addrs[i] + CS_KEEPLIVE[c].off), g_cs_keep[i][c], CS_KEEPLIVE[c].len);
    _InterlockedIncrement64(&g_cs_keeplive_rollbacks);
}
// CS CANARY — a CS's DebugInfo (CS+0x0) is init-stable: the -1 no-debug sentinel or a once-allocated pointer
// (proved init-exactly-once, NO reachable delete+reinit path in .text). With keep-live ON a rollback
// cannot change it, so any frame-over-frame change = a LIVE writer (scribbler), named within one frame. The former
// +0x80 slot is REMOVED: it is the +0x60 CS's SpinCount, which ntdll adjusts dynamically under contention (noise).
static constexpr size_t CS_CANARY_OFFS[] = {0x060, 0x158, 0x200, 0x2A8, 0x350, 0x3F8, 0x4A0, 0x548, 0x5F0, 0x620};
static constexpr int CS_CANARY_N = (int)(sizeof(CS_CANARY_OFFS)/sizeof(CS_CANARY_OFFS[0]));
static uint64_t g_cs_canary_prev[MAX_ALLOCS][CS_CANARY_N];
static bool g_cs_canary_init = false;
static volatile LONG64 g_cs_canary_events = 0;
static void cs_canary_check(int frame) {
    if (!g_alloc_count) return;
    for (int i = 0; i < g_alloc_count; i++)
        for (int c = 0; c < CS_CANARY_N; c++) {
            uint64_t di = *(volatile uint64_t*)(g_alloc_addrs[i] + CS_CANARY_OFFS[c]);
            if (!g_cs_canary_init) { g_cs_canary_prev[i][c] = di; continue; }
            if (di == g_cs_canary_prev[i][c]) continue;
            LONG64 nE = _InterlockedIncrement64(&g_cs_canary_events);
            bool sentinel  = (di == ~0ULL);
            bool ptr_shape = (di > 0x10000 && di < 0x00007FFFFFFFFFFFULL);
            if (nE <= 16 || (nE % 100) == 0) {
                bool w = rblog::is_suppressed(); rblog::suppress(false);
                rblog::write("CS-CANARY #%lld: a%d cs@+0x%zX DebugInfo 0x%llX -> 0x%llX f%d (%s) — init-stable OS field changed with keep-live ON => live writer or engine CS-reinit, not rollback",
                             (long long)nE, i, CS_CANARY_OFFS[c],
                             (unsigned long long)g_cs_canary_prev[i][c], (unsigned long long)di, frame,
                             sentinel ? "-1 sentinel (engine reinit?)" : ptr_shape ? "pointer-shaped" : "GARBAGE");
                rblog::suppress(w);
            }
            g_cs_canary_prev[i][c] = di;
        }
    g_cs_canary_init = true;
}

// FLIST-UNIT — the free-list joins dynrestore (correct-by-construction; eliminates the torn free-list class).
// The MtScalable free-list coherence group = {descriptor head/tail/count + every listed node's link fields}
// spans many independently-sourced 4KB pages. An earlier run showed per-page source selection can tear it
// even with atomic saves + exact descriptors + airtight fold (4 recip breaks from mixed ring/baseline/live
// sources => FUN_1404ca650 spin). Under the rule "a path-dependent structure is restored by its OWN invariant, never
// trusted as raw bytes", the group is captured as one UNIT at one instant — inside save_allocators' CS-held
// window, walking the LIVE lists (per-class mgr+0x58 chains and the ctrl+0xc0 reserve list, both walked by
// FUN_1404ca650) — and restored as one UNIT verbatim after restore_allocators. The walked structure's bytes then never
// come from the page ring at all: no pending-window write, no ring-horizon fallback, no invisible write can
// tear it. Whole-or-nothing per slot (a partial unit is a torn unit): overflow/anomaly marks the slot invalid
// with a LOUD line and the restore falls back to page-blind for that rollback (no silent cap).
struct FlistNode { uintptr_t addr; uint64_t f8, f18, f20, f28, f30; uint32_t f38, f3c; };  // f8 = slab-identity backptr: STATE the engine sets once at carve + propagates verbatim (not node&~0xFFFF — that wrong derive corrupted drifted/multi-page-slab blocks). Captured+restored, never derived.
// Cap 16384: the measured high-water is ~1644-1723 nodes and slot invalidations are UNREADABLE/CYCLE, never
// OVERFLOW, so the free-list is small and what invalidates a slot is a torn/dangling node (the a4 count-drift
// class), not capacity — a larger cap does not help (a 6x raise was tried and reverted, reclaiming ~39MB). The
// reason split + high-water meters stay. The count-drift watcher (Numpad -) separates mod-induced from
// base-game-latent drift.
static constexpr int FLIST_MAX_NODES = 16384;                 // per slot, all ctrls+classes+reserve combined
static FlistNode g_flist_ring[ALLOC_RING_SLOTS][FLIST_MAX_NODES];
static volatile long g_flist_hw_n = 0;        // session high-water: max total nodes captured in one slot
static volatile long g_flist_hw_walked = 0;   // session high-water: longest single-list walk
static int  g_flist_count[ALLOC_RING_SLOTS]  = {0};
static int  g_flist_frames[ALLOC_RING_SLOTS] = {-1,-1,-1,-1,-1,-1,-1,-1,-1,-1};
static bool g_flist_valid[ALLOC_RING_SLOTS]  = {false};
static volatile LONG64 g_flist_saved = 0, g_flist_restored = 0, g_flist_slot_invalid = 0, g_flist_unlocked_skip = 0;
static volatile LONG64 g_flist_count_healed = 0;   // count-drift HEAL count: times we re-derived a drifted mgr+0x68 from the walked chain at save
static bool g_save_cs_held = false;   // true only inside try_atomic_alloc_save's locked branch — the unit's atomicity precondition
static size_t donated_per_ctrl[MAX_ALLOCS] = {0}; static size_t donated_total = 0;   // file-scope for the STABILITY heartbeat
static int g_flist_last_n = 0;                    // last frame's captured free-list node count

// ALIST-UNIT (the dual-list completion) — an earlier run showed the a4 corruption family is
// post-restore FREE/ALLOC DOUBLE-MEMBERSHIP: the engine keeps an ALLOC (in-use) list per mgr — head mgr+0x48,
// tail mgr+0x40, count mgr+0x50, sizesum mgr+0x54, walked via +0x18 (carve-finalize 0x1404ca9c1-0x1404ca9f8:
// new->f18:= old head, old_head->f20:= new, inc [mgr+0x50]) — using the same block +0x18/+0x20 fields as the
// free list (which walks via +0x20). FLIST-UNIT restored the free list as one instant while the alloc list's
// node links stayed page-blind (mixed sources) => where the two epochs disagree about a block, engine churn on
// either list rewrites the SHARED fields under the other (observed: a half-splice — one f18 rewritten, all else
// same; and an 11-node reciprocally-linked ALLOC SEGMENT threaded into the free chain). The general point: a unit
// covering one list of a shared-field PAIR cannot guarantee the pair. This unit
// captures the alloc list in the same CS-held instant and replays it at restore (alist after flist; both
// whole-or-nothing per slot, decline->page-blind). At instant T every block is on exactly one list (the
// engine's own partition invariant) => double-membership becomes unrepresentable by construction.
// UNIT-SCOPED: capturing every ctrl's alloc lists overflows the cap on the first frame (a2/Resource alone has
// >5.5k in-use nodes per class; a0-a2 cumulatively exceed 32k) => the unit never arms. Every corruption episode
// observed lives on the "Unit" ctrl (a4 — mgr0/4/5/6), so the alist unit is scoped to Unit only: complete
// coverage where the fault
// lives, tiny walk (~1-3k nodes), huge headroom. If an episode ever appears on another ctrl, widen deliberately.
static uintptr_t g_alist_target_ctrl = 0;         // resolved at discovery by name (ctrl+0x21 == "Unit"); 0 = alist off
static const int ALIST_MAX_NODES = 32768;         // Unit-only in-use population (~1-3k expected; hw_n verifies)
static FlistNode g_alist_ring[ALLOC_RING_SLOTS][ALIST_MAX_NODES];
static int  g_alist_count[ALLOC_RING_SLOTS]  = {0};
static bool g_alist_valid[ALLOC_RING_SLOTS]  = {false};
static volatile long   g_alist_hw_n = 0;
static volatile LONG64 g_alist_saved = 0, g_alist_restored = 0, g_alist_slot_invalid = 0;
static volatile LONG64 g_dualmember_checks = 0, g_dualmember_hits = 0;   // the double-membership oracle
static volatile LONG64 g_alist_recip_seen = 0, g_alist_freeonchain_seen = 0;   // vanilla-legal-state oracles: reported, never gated

// Return reason: 0=OK, 1=CYCLE (chain longer than the mgr's own count = torn/corrupt; a bigger cap can't help),
// 2=UNREADABLE (node points off committed memory), 3=OVERFLOW (capture buffer full = list legitimately huge; a
// bigger cap does help), 4=VIOLATOR (a bit0==1 IN-USE block is reachable from this FREE chain = the a4 skipped-
// count-gated-unlink partition violator; its own +0x18/+0x20 are now alloc-list garbage so it cannot be spliced
// out — the caller rebuilds the whole class chain from the pool free-bit set, which collects bit0==0 only and so
// excludes it by construction). Always sets *walked_out to the count reached so the caller can log it.
// flag_violator=false SUPPRESSES the bit0 check (used only for the ctrl+0xc0 reserve walk: kind==2 slab +0x38 bit0
// semantics are not RE-confirmed, so a reserve bit0==1 must not be treated as a violator).
enum { FL_OK = 0, FL_CYCLE = 1, FL_UNREADABLE = 2, FL_OVERFLOW = 3, FL_VIOLATOR = 4 };
// recip_bad (optional, INSTRUMENT-ONLY): reports the first node whose successor's back-link (+0x18)
// does not point back at it — the "recip break" alloc_invariants only sees at rollback phases, now visible at every
// per-frame save. Diagnostic out-param only: does not change the return code / capture validity (behavior-frozen;
// the diagnostic dump prints the transition fingerprint).
static int flist_walk_list(uintptr_t head, uint32_t count, FlistNode* buf, int* n, uint32_t* walked_out, bool flag_violator, uintptr_t* recip_bad = nullptr) {
    uintptr_t node = head; uint32_t walked = 0;
    while (node) {
        if (walked > count + 2)                              { if (walked_out) *walked_out = walked; return FL_CYCLE; }
        if (node < 0x10000 || !arena::is_committed_addr(node) || !arena::is_committed_addr(node + 0x40))
                                                             { if (walked_out) *walked_out = walked; return FL_UNREADABLE; }
        if (*n >= FLIST_MAX_NODES)                           { if (walked_out) *walked_out = walked; return FL_OVERFLOW; }
        // PARTITION-INVARIANT (makes the a4 double-membership unrepresentable — closes 0x1405E858D and its seed consumers):
        // +0x38 bit0 is the block's OWN in-use flag (blk_free == (f38&1)==0). A node reachable from a FREE chain
        // (mgr+0x58) whose bit0==1 is the skipped count-gated-unlink VIOLATOR — the carve set bit0=1 and overwrote
        // its OWN +0x18/+0x20 with alloc-list links, yet a former neighbor's stale +0x20 still routes into it
        // (=> walked>count within the count+2 slack, so CYCLE never trips). It cannot be spliced out (its own next
        // is alloc-list garbage now); signal FL_VIOLATOR so save_freelists rebuilds this class's chain from the
        // authoritative free-bit pool set (collects bit0==0 only => the violator is excluded by construction).
        // Under the CS-held snapshot a bit0==1 free-reachable node is always a real violator, never a mid-carve
        // transient (FUN_1404CA650's carve is atomic under the same class CS the snapshot holds), so this fires only
        // on the seed. flag_violator gates it to per-class sub-blocks (bit0==free proven); the reserve passes false.
        if (flag_violator && (*(uint32_t*)(node + 0x38) & 1u)) { if (walked_out) *walked_out = walked; return FL_VIOLATOR; }
        FlistNode& e = buf[(*n)++];
        e.addr = node;
        e.f8  = *(uint64_t*)(node + 0x8);                                        // +0x8 slab-identity backptr — CAPTURE the engine's real propagated value (coalesce uses it as a merge key; a wrong value = illegitimate merge)
        e.f18 = *(uint64_t*)(node + 0x18); e.f20 = *(uint64_t*)(node + 0x20);
        e.f28 = *(uint64_t*)(node + 0x28); e.f30 = *(uint64_t*)(node + 0x30);
        e.f38 = *(uint32_t*)(node + 0x38); e.f3c = *(uint32_t*)(node + 0x3c);
        // recip diagnostic (instrument-only): successor's +0x18 must point back here. First offender recorded.
        if (recip_bad && !*recip_bad && e.f20) {
            uintptr_t nx = (uintptr_t)e.f20;
            if (nx >= 0x10000 && arena::is_committed_addr(nx) && arena::is_committed_addr(nx + 0x40) &&
                *(uint64_t*)(nx + 0x18) != node) *recip_bad = node;
        }
        node = (uintptr_t)e.f20; walked++;
    }
    if ((long)walked > g_flist_hw_walked) g_flist_hw_walked = (long)walked;   // longest single-list walk (session)
    if (walked_out) *walked_out = walked;
    return FL_OK;
}
static inline const char* flist_reason(int r) { return r == FL_CYCLE ? "CYCLE" : r == FL_OVERFLOW ? "OVERFLOW" : r == FL_VIOLATOR ? "VIOLATOR" : "UNREADABLE"; }

// A4 BREAK DIAGNOSTIC (instrument-only) — the transition fingerprint. We capture the FLIST unit every
// frame, so when a break is detected the previous frame's coherent snapshot of the same chain is already in the
// ring: diffing live vs prior names exactly which node changed which fields in the <=1-frame corruption window
// (bit0 flip = failed unlink | link rewire = half-applied splice | full clobber = foreign writer). Fired at the
// three detection sites (VIOLATOR/CYCLE pre-rebuild — before the rebuild destroys the evidence; COUNT-DRIFT heal;
// recip break) under the same CS as the capture => a coherent read. Reads + logs only; behavior-frozen.
static volatile long g_flist_diags = 0;
static volatile LONG64 g_flist_recip_seen = 0;
static void flist_diag(int i, int k, uintptr_t ctrl, uintptr_t mgr, int frame, const char* reason) {
    long fire = _InterlockedIncrement(&g_flist_diags);
    const long FULL_CAP = 12;                                        // bounded LOUD: full dumps for the first 12, then one-liners
    bool w = rblog::is_suppressed(); rblog::suppress(false);
    int ps = -1, pf = -1;                                            // newest prior valid slot (current slot is invalid mid-save)
    for (int s = 0; s < ALLOC_RING_SLOTS; s++)
        if (g_flist_valid[s] && g_flist_frames[s] > pf) { pf = g_flist_frames[s]; ps = s; }
    if (fire > FULL_CAP) {
        rblog::write("A4-DIAG #%ld (capped): %s a%d/mgr%d f%d prior=f%d", fire, reason, i, k, frame, pf);
        rblog::suppress(w); return;
    }
    uintptr_t pool0 = *(uintptr_t*)(ctrl + 0x90), pool1 = *(uintptr_t*)(ctrl + 0x98);
    rblog::write("A4-DIAG #%ld %s a%d/mgr%d f%d | live mgr{head=0x%llX tail=0x%llX count=%u sizesum=%u} | prior capture f%d (dist=%d frame(s)) | pool=[0x%llX,0x%llX)",
                 fire, reason, i, k, frame,
                 (unsigned long long)*(uintptr_t*)(mgr + 0x58), (unsigned long long)*(uintptr_t*)(mgr + 0x60),
                 *(uint32_t*)(mgr + 0x68), *(uint32_t*)(mgr + 0x6c), pf, pf >= 0 ? frame - pf : -1,
                 (unsigned long long)pool0, (unsigned long long)pool1);
    // Evidence walk: bit0-blind (walks past a violator), readability-guarded, capped. Not the capture walk.
    uintptr_t node = *(uintptr_t*)(mgr + 0x58), prev = 0;
    int pos = 0, hexdumps = 0;
    while (node && pos < 64) {
        if (node < 0x10000 || !arena::is_committed_addr(node) || !arena::is_committed_addr(node + 0x40)) {
            rblog::write("A4-DIAG   [%02d] 0x%llX UNREADABLE — walk ends", pos, (unsigned long long)node);
            break;
        }
        uint64_t f8  = *(uint64_t*)(node + 0x8),  f18 = *(uint64_t*)(node + 0x18), f20 = *(uint64_t*)(node + 0x20);
        uint32_t f38 = *(uint32_t*)(node + 0x38), f3c = *(uint32_t*)(node + 0x3c);
        char reg = (node >= pool0 && node < pool1) ? 'P' : (arena::in_owned_pool(ctrl, node) ? 'D' : '?');
        bool viol  = (f38 & 1u) != 0;
        bool recip = (prev != 0 && f18 != prev);
        char pd[224]; int po = 0; bool changed = false, in_prior = false;
        if (ps >= 0) {
            for (int j = 0; j < g_flist_count[ps]; j++) {
                const FlistNode& p = g_flist_ring[ps][j];
                if (p.addr != node) continue;
                in_prior = true;
                po = snprintf(pd, sizeof pd, "prior:");
                if (p.f38 != f38) { po += snprintf(pd + po, sizeof pd - po, " f38 %x->%x",   p.f38, f38); changed = true; }
                if (p.f8  != f8)  { po += snprintf(pd + po, sizeof pd - po, " f8 %llx->%llx",  (unsigned long long)p.f8,  (unsigned long long)f8);  changed = true; }
                if (p.f18 != f18) { po += snprintf(pd + po, sizeof pd - po, " f18 %llx->%llx", (unsigned long long)p.f18, (unsigned long long)f18); changed = true; }
                if (p.f20 != f20) { po += snprintf(pd + po, sizeof pd - po, " f20 %llx->%llx", (unsigned long long)p.f20, (unsigned long long)f20); changed = true; }
                if (p.f3c != f3c) { po += snprintf(pd + po, sizeof pd - po, " f3c %x->%x",   p.f3c, f3c); changed = true; }
                if (!changed) snprintf(pd, sizeof pd, "prior: SAME");
                break;
            }
        }
        if (!in_prior) snprintf(pd, sizeof pd, ps >= 0 ? "NOT-IN-PRIOR (new since f%d)" : "no prior slot", pf);
        rblog::write("A4-DIAG   [%02d] 0x%llX %c f38=%x(used=%d sz=%u) f3c=%x f8=%llx f18=%llx f20=%llx%s%s | %s",
                     pos, (unsigned long long)node, reg, f38, (int)(f38 & 1u), f38 >> 1, f3c,
                     (unsigned long long)f8, (unsigned long long)f18, (unsigned long long)f20,
                     viol ? " IN-USE-IN-CHAIN" : "", recip ? " RECIP-BREAK" : "", pd);
        if ((viol || recip || changed || !in_prior) && hexdumps < 4) {   // raw header of anomalous nodes (+0x0/+0x10 live outside the 7 fields — the crash showed +0x0=0xB)
            const uint64_t* q = (const uint64_t*)node;
            rblog::write("A4-DIAG        raw 0x00..0x38: %llx %llx %llx %llx %llx %llx %llx %llx",
                         (unsigned long long)q[0], (unsigned long long)q[1], (unsigned long long)q[2], (unsigned long long)q[3],
                         (unsigned long long)q[4], (unsigned long long)q[5], (unsigned long long)q[6], (unsigned long long)q[7]);
            hexdumps++;
        }
        prev = node; node = f20; pos++;
    }
    if (pos >= 64) rblog::write("A4-DIAG   ... walk capped at 64 nodes");
    if (ps >= 0) {
        // Prior-side reverse check: prior nodes of this class GONE from the live chain (the vanished-node signature).
        // Class match is binary-grounded: carve-finalize (0x1404ca99f-0x1404ca9b6) folds (mgr+0x70)<<2 into f3c bits
        // 2-6 — so (f3c & 0x7c) identifies this mgr's class; sibling classes and kind-2 reserve nodes are excluded.
        uint32_t cls_bits = ((*(uint32_t*)(mgr + 0x70)) << 2) & 0x7cu;
        int gone = 0;
        for (int j = 0; j < g_flist_count[ps] && gone < 8; j++) {
            const FlistNode& p = g_flist_ring[ps][j];
            if ((p.f3c & 0x7cu) != cls_bits) continue;
            if (!(p.addr >= pool0 && p.addr < pool1) && !arena::in_owned_pool(ctrl, p.addr)) continue;
            uintptr_t nn = *(uintptr_t*)(mgr + 0x58); int q2 = 0; bool found = false;
            while (nn && q2 < 64) {
                if (nn == p.addr) { found = true; break; }
                if (nn < 0x10000 || !arena::is_committed_addr(nn) || !arena::is_committed_addr(nn + 0x40)) break;
                nn = *(uintptr_t*)(nn + 0x20); q2++;
            }
            if (!found && arena::is_committed_addr(p.addr) && arena::is_committed_addr(p.addr + 0x40)) {
                uint32_t lf38 = *(uint32_t*)(p.addr + 0x38);
                rblog::write("A4-DIAG   GONE-FROM-CHAIN: 0x%llX (prior f38=%x) live f38=%x(used=%d) — %s",
                             (unsigned long long)p.addr, p.f38, lf38, (int)(lf38 & 1u),
                             (lf38 & 1u) ? "carved since prior (normal IF count also dropped)" : "STILL FREE but unchained = LOST-UNLINK/DROP");
                gone++;
            }
        }
    }
    rblog::suppress(w);
}

// ALIST walker — the alloc-list mirror of flist_walk_list. Walks head=*(mgr+0x48) via +0x18 (the engine's own
// direction: carve-finalize threads new->f18:= old head).
// Validation is walk-safety only: the strict model (reciprocal DLL, bit0=1-only members) fails in vanilla
// at frame 1 (28,197 declines on one run) — a complete walked==count chain carried a
// persistent non-reciprocal pair before any rollback existed. The engine legitimately tolerates such states (the
// alloc-unlink at 0x1404cb3b8 is COUNT-GATED — `cmp [mgr+0x50],0; jbe` skips the whole unlink, stranding a freed
// block on the alloc chain; vanilla carries it). Imposing a textbook model on the engine's structure is the
// byte-inspection error: a CS-held verbatim capture is coherent BY CAPTURE — the state existed live at instant T — so
// replaying it bit-for-bit is restore-faithful regardless of whether it matches a textbook DLL. Gate only on what
// impairs the WALK itself (CYCLE/UNREADABLE/OVERFLOW); recip breaks and free-on-chain nodes are captured verbatim
// and reported as ORACLES (out-params -> counters + first-N offender dumps), never declines.
static int alist_walk_list(uintptr_t head, uint32_t count, FlistNode* buf, int* n, uint32_t* walked_out,
                           uintptr_t* recip_bad, uintptr_t* freeonchain_bad) {
    uintptr_t node = head; uint32_t walked = 0;
    while (node) {
        if (walked > count + 2)                              { if (walked_out) *walked_out = walked; return FL_CYCLE; }
        if (node < 0x10000 || !arena::is_committed_addr(node) || !arena::is_committed_addr(node + 0x40))
                                                             { if (walked_out) *walked_out = walked; return FL_UNREADABLE; }
        if (*n >= ALIST_MAX_NODES)                           { if (walked_out) *walked_out = walked; return FL_OVERFLOW; }
        FlistNode& e = buf[(*n)++];
        e.addr = node;
        e.f8  = *(uint64_t*)(node + 0x8);
        e.f18 = *(uint64_t*)(node + 0x18); e.f20 = *(uint64_t*)(node + 0x20);
        e.f28 = *(uint64_t*)(node + 0x28); e.f30 = *(uint64_t*)(node + 0x30);
        e.f38 = *(uint32_t*)(node + 0x38); e.f3c = *(uint32_t*)(node + 0x3c);
        if (freeonchain_bad && !*freeonchain_bad && (e.f38 & 1u) == 0)
            *freeonchain_bad = node;                         // free node on the ALLOC chain — a VANILLA-legal state (count-gate skip); captured verbatim, reported only
        if (recip_bad && !*recip_bad && e.f18) {
            uintptr_t nx = (uintptr_t)e.f18;
            if (nx >= 0x10000 && arena::is_committed_addr(nx) && arena::is_committed_addr(nx + 0x40) &&
                *(uint64_t*)(nx + 0x20) != node) *recip_bad = node;
        }
        node = (uintptr_t)e.f18; walked++;
    }
    if (walked_out) *walked_out = walked;
    return FL_OK;
}

// Capture the whole free-list unit for all discovered allocators. Runs inside save_allocators (CS-held via
// try_atomic_alloc_save => the lists are splice-quiescent => the unit is one coherent instant by construction).
static void save_freelists(int frame, int slot) {
    cs_canary_check(frame);   // CS CANARY (read-only, every frame): DebugInfo change = the corruption event, named ±1 frame
    g_flist_frames[slot] = frame;
    g_flist_count[slot]  = 0;
    g_flist_valid[slot]  = false;
    g_alist_count[slot]  = 0;      // ALIST-UNIT shares the slot/frame indexing; valid only if every mgr captured
    g_alist_valid[slot]  = false;
    // ATOMICITY PRECONDITION: only a CS-held capture is a coherent instant. The unlocked fallback save
    // (CS-busy after retries) could walk a mid-splice list => a torn unit restored verbatim = torn by
    // construction. Skip the capture entirely there (slot stays invalid => that frame falls back to page-blind,
    // matching "a rare torn save beats stalling"). fallback=0 in practice (3421/3421 CS-held on one long run).
    if (!g_save_cs_held) { _InterlockedIncrement64(&g_flist_unlocked_skip); return; }
    int n = 0;
    int na = 0; bool alist_bad = false;   // ALIST-UNIT per-slot capture cursor + whole-or-nothing flag
    for (int i = 0; i < g_alloc_count; i++) {
        uintptr_t ctrl = g_alloc_addrs[i];
        int ncls = *(volatile int*)(ctrl + 0x648); if (ncls < 1 || ncls > 8) ncls = 8;
        for (int k = 0; k < ncls; k++) {
            uintptr_t mgr = ctrl + 0xd8 + (uintptr_t)k * 0xa8;
            // MISSING-OWNERSHIP PROBE (throttled, CS-held): classify where this class's free blocks physically live
            // vs what we track. Finds the empty-collect root without waiting for the rare cyclic ratchet to fire.
            if ((frame % 1800) == 0) flist_rebuild::probe_free_locations(ctrl, k);
            uint32_t live_count = *(uint32_t*)(mgr + 0x68), walked = 0;
            int n_before = n;
            uintptr_t recip_bad = 0;
            int fr = flist_walk_list(*(uintptr_t*)(mgr + 0x58), live_count, g_flist_ring[slot], &n, &walked, true, &recip_bad);
            // RECIP ORACLE (instrument-only): a walkable chain whose back-links disagree — the break class alloc_invariants
            // only sees at rollback phases, now caught at the per-frame save with a <=1-frame-old diff basis. The
            // capture stays valid (behavior-frozen); the diagnostic dump prints the fingerprint.
            if (fr == FL_OK && recip_bad) {
                LONG64 nR = _InterlockedIncrement64(&g_flist_recip_seen);
                if (nR <= 4 || (nR % 100) == 0)
                    rblog::write("FLIST-RECIP #%lld: a%d/mgr%d f%d first offender 0x%llX (chain walkable; capture still trusted — instrument-only)",
                                 (long long)nR, i, k, frame, (unsigned long long)recip_bad);
                flist_diag(i, k, ctrl, mgr, frame, "RECIP-BREAK");
            }
            // REBUILD-ON-UNCAPTURABLE (a4 ratchet cure): a CYCLE/UNREADABLE chain is the exact point where the
            // ratchet used to start — FLIST-UNIT can't walk it, so it tore the chain page-blind (permanent). Instead,
            // rebuild the chain from the AUTHORITATIVE free-bit set (a pool scan; order is allocator-irrelevant per
            // RE, a4 is gp-invisible), then re-walk to VERIFY it is now clean before trusting it. Runs under the same
            // CS as this capture => the allocator is splice-quiescent. CYCLE/UNREADABLE/VIOLATOR (not OVERFLOW: that
            // is a legit huge list wanting a bigger cap, not corruption). VIOLATOR = a bit0==1 in-use block reachable
            // in the free chain (the skipped-unlink partition tear): its own links are alloc-list garbage so the only
            // sound recovery is the same pool rebuild (free-bit set, violator excluded by construction). Whole-or-
            // nothing: a decline leaves the live state untouched and falls through to the existing page-blind path.
            if (fr == FL_CYCLE || fr == FL_UNREADABLE || fr == FL_VIOLATOR) {
                // Diagnostic dump before REBUILD — the rebuild rewrites every link (destroys the evidence); fingerprint first.
                flist_diag(i, k, ctrl, mgr, frame, flist_reason(fr));
                const char* rb_why = ""; uint32_t rb_us = 0;
                int rb = flist_rebuild::rebuild_free_list_from_pool(ctrl, k, &rb_why, &rb_us);
                if (rb >= 0) {
                    n = n_before;                                          // discard the partial/cyclic capture
                    uint32_t rwalked2 = 0;
                    int fr2 = flist_walk_list(*(uintptr_t*)(mgr + 0x58), *(uint32_t*)(mgr + 0x68),
                                              g_flist_ring[slot], &n, &rwalked2, true);   // verify: a rebuilt chain is bit0==0 only => VIOLATOR here => reject to page-blind
                    if (fr2 == FL_OK) {                                    // derived a clean, WALKABLE chain — verified
                        // The 0x660 descriptor blob for this ctrl was already captured (save_allocators, line ~1294)
                        // with the old head/count. Re-capture it now that the LIVE mgr is rebuilt-coherent, so this
                        // slot's descriptor and its nodes are one instant (no restore-time head-vs-nodes drift).
                        // CS-held => quiescent; the other, untouched managers copy byte-identically.
                        memcpy(g_alloc_ring[slot][i], (void*)ctrl, 0x660);
                        long nOk = flist_rebuild::rebuilt_ok();
                        if (nOk <= 8 || (nOk % 100) == 0)
                            rblog::write("FLIST-REBUILD: a%d/mgr%d chain was %s (walked=%u live=%u) => rebuilt %d free block(s) "
                                         "from pool scan in %uus; re-walk clean (n=%u). [%s | ok=%ld declined=%ld]",
                                         i, k, flist_reason(fr), walked, live_count, rb, rb_us, rwalked2, rb_why,
                                         nOk, (long)flist_rebuild::rebuilt_declined());
                        alist_bad = true;                                  // ALIST pair-honesty: this mgr's alloc side goes uncaptured this frame (rebuild path skips it) => decline the alist slot rather than replay an incomplete alloc unit
                        continue;                                          // captured clean — on to the next class
                    }
                    n = n_before;                                          // rebuilt but re-walk still bad — LOUD (the live chain is still fixed; only the capture skips)
                    rblog::write("FLIST-REBUILD ANOMALY: a%d/mgr%d rebuilt %d but re-walk=%s (rwalked=%u) — live chain fixed, capture falls to page-blind. [%s]",
                                 i, k, rb, flist_reason(fr2), rwalked2, rb_why);
                } else {
                    long nDec = flist_rebuild::rebuilt_declined();        // decline visibility
                    if (nDec <= 12 || (nDec % 100) == 0)
                        rblog::write("FLIST-REBUILD DECLINED #%ld: a%d/mgr%d in %uus — page-blind stands, live state untouched (the decline guard). reason=%s",
                                     nDec, i, k, rb_us, rb_why);
                }
            }
            if (fr != FL_OK) {
                _InterlockedIncrement64(&g_flist_slot_invalid);
                LONG64 nInv = g_flist_slot_invalid + 1;
                if (nInv <= 8 || (nInv % 100) == 0)
                    rblog::write("FLIST-UNIT: slot f%d INVALIDATED #%lld at a%d/mgr%d reason=%s (n=%d walked=%u live=%u cap=%d hw_n=%ld hw_walked=%ld). Page-blind fallback. "
                                 "[OVERFLOW=> raise cap further; CYCLE=> chain>count corruption, cap won't help]",
                                 frame, (long long)nInv, i, k, flist_reason(fr), n, walked, live_count, FLIST_MAX_NODES, g_flist_hw_n, g_flist_hw_walked);
                return;                                                // whole-or-nothing
            }
            // COUNT-DRIFT PIN + HEAL (the a4 ratchet cure): this walk runs every frame under the
            // CS. When FL_OK the walk terminated cleanly within count+2, so `walked` IS the true chain length. `count`
            // (mgr+0x68) is a pure cached chain length — verified: the only readers in the whole allocator cluster are
            // the three `cmp [mgr+0x68],0; jbe` unlink guards (FUN_1404CAA60 @0x1404caa60, inlined @0x1404ca823 /
            // @0x1404ca6b8), each testing only empty-vs-nonempty; mgr+0x6c (sizesum) is never read for any decision.
            // So a drifted count is a stale DERIVED cache and `walked` is the authoritative truth. RE-DERIVE it here
            // (the principle: rebuild derived state from the authoritative source, not a byte-revert): under
            // the already-held CS, write count:=walked + sizesum, then re-capture this ctrl's 0x660 descriptor blob
            // (already snapshotted with the old count in save_allocators) so the captured unit is count==chain-length
            // BY CONSTRUCTION. Effect: the guard can never see count==0 while a free block is still chained => the
            // lost-unlink (count==0 skip hands a still-chained block out in_use => re-free re-threads => CYCLE => the
            // crash) is UNREPRESENTABLE. Composes with: descent rebuild (acyclic capture) + POSTLOAD/POSTRESIM repair.
            if (walked != live_count) {
                // Diagnostic dump before heal — the diff vs the prior frame names exactly which nodes left/joined the
                // chain without a matching count move (the drift's mechanism, not just its magnitude).
                flist_diag(i, k, ctrl, mgr, frame, "COUNT-DRIFT");
                uint32_t ssum = 0;
                for (int j = n_before; j < n; j++) ssum += (uint32_t)(g_flist_ring[slot][j].f38 >> 1);
                static volatile long conce = 0;
                if (_InterlockedCompareExchange(&conce, 1, 0) == 0) {   // detailed seed-window pin: first fire only (page_history is not free)
                    char h1[96] = "-", h2[96] = "-";
                    if (n >= 1) arena::page_history(g_flist_ring[slot][n-1].addr, h1, sizeof h1);
                    if (n >= 2) arena::page_history(g_flist_ring[slot][n-2].addr, h2, sizeof h2);
                    bool w = rblog::is_suppressed(); rblog::suppress(false);
                    rblog::write("COUNT-DRIFT PIN: FIRST live chain!=count at SAVE f%d a%d/mgr%d walked=%u count=%u | tail node 0x%llX {%s} | prev 0x%llX {%s} — creation frame pinned ±1; HEALING count:=walked from here on",
                                 frame, i, k, walked, live_count,
                                 (unsigned long long)(n >= 1 ? g_flist_ring[slot][n-1].addr : 0), h1,
                                 (unsigned long long)(n >= 2 ? g_flist_ring[slot][n-2].addr : 0), h2);
                    rblog::suppress(w);
                }
                *(uint32_t*)(mgr + 0x68) = walked;                 // HEAL live count (derived cache -> authoritative chain length)
                *(uint32_t*)(mgr + 0x6c) = ssum;                   // HEAL live sizesum (write-only bookkeeping)
                memcpy(g_alloc_ring[slot][i], (void*)ctrl, 0x660); // re-cohere the capture: descriptor count now matches the captured nodes (one instant)
                long nH = (long)_InterlockedIncrement64(&g_flist_count_healed);
                if (nH <= 8 || (nH % 200) == 0)
                    rblog::write("COUNT-DRIFT HEAL #%ld: a%d/mgr%d count %u=>%u sizesum:=%u (f%d) — derived-cache re-derive under CS, capture re-cohered",
                                 nH, i, k, live_count, walked, ssum, frame);
            }
            // ALIST-UNIT capture (same CS-held instant as the free capture above — the PAIR is one structure).
            // Unit-scoped: only the ctrl every episode lives on (whole-ctrl capture overflowed — see g_alist_target_ctrl).
            if (!alist_bad && ctrl == g_alist_target_ctrl) {
                int na_before = na;
                uint32_t a_count = *(uint32_t*)(mgr + 0x50), a_walked = 0;
                uintptr_t a_recip = 0, a_foc = 0;
                int ar = alist_walk_list(*(uintptr_t*)(mgr + 0x48), a_count, g_alist_ring[slot], &na, &a_walked, &a_recip, &a_foc);
                // ORACLES, not gates: recip breaks + free-on-chain are VANILLA-legal states
                // (count-gated alloc-unlink skip) — captured verbatim, reported. Only an unwalkable chain declines.
                if (a_recip) {
                    LONG64 nR = _InterlockedIncrement64(&g_alist_recip_seen);
                    if (nR <= 4 || (nR % 1000) == 0) {
                        uintptr_t nx = *(uint64_t*)(a_recip + 0x18);
                        rblog::write("ALIST-ORACLE recip #%lld: a%d/mgr%d f%d node=0x%llX f18->0x%llX whose f20=0x%llX (vanilla-legal; captured verbatim) | node raw: %llx %llx %llx %llx",
                                     (long long)nR, i, k, frame, (unsigned long long)a_recip, (unsigned long long)nx,
                                     nx >= 0x10000 && arena::is_committed_addr(nx + 0x40) ? (unsigned long long)*(uint64_t*)(nx + 0x20) : 0ULL,
                                     (unsigned long long)*(uint64_t*)(a_recip + 0x18), (unsigned long long)*(uint64_t*)(a_recip + 0x20),
                                     (unsigned long long)*(uint64_t*)(a_recip + 0x38), (unsigned long long)*(uint64_t*)(a_recip + 0x8));
                    }
                }
                if (a_foc) {
                    LONG64 nF = _InterlockedIncrement64(&g_alist_freeonchain_seen);
                    if (nF <= 4 || (nF % 1000) == 0)
                        rblog::write("ALIST-ORACLE free-on-chain #%lld: a%d/mgr%d f%d node=0x%llX (the count-gate-skip strand; vanilla-legal; captured verbatim)",
                                     (long long)nF, i, k, frame, (unsigned long long)a_foc);
                }
                if (ar != FL_OK) {
                    alist_bad = true;                          // whole-or-nothing: only an UNWALKABLE chain declines to page-blind
                    LONG64 nI = _InterlockedIncrement64(&g_alist_slot_invalid);
                    if (nI <= 8 || (nI % 100) == 0)
                        rblog::write("ALIST-UNIT: slot f%d INVALIDATED #%lld at a%d/mgr%d reason=%s (na=%d walked=%u count=%u cap=%d) — chain UNWALKABLE; alloc side page-blind this frame (free unit unaffected).",
                                     frame, (long long)nI, i, k, flist_reason(ar), na, a_walked, a_count, ALIST_MAX_NODES);
                } else if ((frame % 120) == 0 && n > n_before) {
                    // DOUBLE-MEMBERSHIP ORACLE (gated, ~2s cadence): intersect this mgr's FREE segment with its
                    // ALLOC segment. At a CS-held instant the engine's partition invariant says intersection == 0;
                    // any hit = the standing corruption an earlier run fingerprinted, caught at formation.
                    _InterlockedIncrement64(&g_dualmember_checks);
                    int printed = 0;
                    for (int fj = n_before; fj < n; fj++) {
                        for (int aj = na_before; aj < na; aj++) {
                            if (g_flist_ring[slot][fj].addr != g_alist_ring[slot][aj].addr) continue;
                            // CLASSIFY: a bit0==0 node on both lists = the VANILLA count-gate strand
                            // (free block never alloc-unlinked — legal, captured verbatim). bit0==1 on the FREE
                            // chain = the underlying fault. Only the latter counts as a hit.
                            if ((g_flist_ring[slot][fj].f38 & 1u) == 0) break;   // benign strand (already counted by the free-on-chain oracle)
                            LONG64 nD = _InterlockedIncrement64(&g_dualmember_hits);
                            if (printed < 4 && (nD <= 16 || (nD % 100) == 0)) {
                                bool w = rblog::is_suppressed(); rblog::suppress(false);
                                rblog::write("DOUBLE-MEMBER #%lld: 0x%llX IN-USE yet on the FREE chain a%d/mgr%d f%d (free f38=%x, alloc f38=%x) — the underlying fault caught live",
                                             (long long)nD, (unsigned long long)g_flist_ring[slot][fj].addr, i, k, frame,
                                             g_flist_ring[slot][fj].f38, g_alist_ring[slot][aj].f38);
                                rblog::suppress(w);
                                printed++;
                            }
                        }
                    }
                }
            }
        }
        // The RESERVE pool (ctrl+0xc0 head / +0xd0 count) — FUN_1404ca650's carve-from-reserve walks it too.
        uint32_t rwalked = 0;
        int rr = flist_walk_list(*(uintptr_t*)(ctrl + 0xc0), *(uint32_t*)(ctrl + 0xd0), g_flist_ring[slot], &n, &rwalked, false);   // reserve: kind==2 bit0 unconfirmed => no violator check
        if (rr != FL_OK) {
            _InterlockedIncrement64(&g_flist_slot_invalid);
            LONG64 nInv = g_flist_slot_invalid + 1;
            if (nInv <= 8 || (nInv % 100) == 0)
                rblog::write("FLIST-UNIT: slot f%d INVALIDATED #%lld at a%d/RESERVE reason=%s (n=%d walked=%u resv_count=%u cap=%d hw_n=%ld hw_walked=%ld). Page-blind fallback.",
                             frame, (long long)nInv, i, flist_reason(rr), n, rwalked, *(uint32_t*)(ctrl + 0xd0), FLIST_MAX_NODES, g_flist_hw_n, g_flist_hw_walked);
            return;
        }
    }
    // (+0x8 slab-backptr is now captured per-node in flist_walk_list and replayed in restore_freelists — restore-faithful
    // STATE, not a derive. A per-frame node&~0xFFFF derive is the wrong value for drifted/multi-page-slab blocks
    // and corrupts the coalesce merge-key => the 0x1404CA410 reserve tear.)
    if ((long)n > g_flist_hw_n) g_flist_hw_n = (long)n;   // session high-water total nodes (sizes the real cap)
    g_flist_count[slot] = n;
    g_flist_valid[slot] = true;
    g_flist_last_n = n;
    _InterlockedExchangeAdd64(&g_flist_saved, n);
    // ALIST-UNIT commit — valid only if every scoped mgr's alloc chain captured clean this frame (whole-or-nothing).
    g_alist_count[slot] = na;
    g_alist_valid[slot] = !alist_bad && g_alist_target_ctrl != 0;
    if (!alist_bad) {
        if ((long)na > g_alist_hw_n) g_alist_hw_n = (long)na;
        _InterlockedExchangeAdd64(&g_alist_saved, na);
    }
}

// Invalidate the unit slot for a frame whose ARENA page save failed (the unit must never be "valid" for a frame
// the page ring never captured — frame-N links grafted onto stale page bytes = a mixed-epoch block header).
static void flist_invalidate_frame(int frame) {
    for (int s = 0; s < ALLOC_RING_SLOTS; s++)
        if (g_flist_frames[s] == frame) g_flist_valid[s] = false;
}

// Replay the captured unit over the just-restored arena: every listed node's 7 link/header fields (+0x8 slab-backptr,
// +0x18/+0x20 free links, +0x28/+0x30 phys neighbors, +0x38/+0x3c size|kind) land at the same instant the descriptor
// (restore_allocators) came from => the whole group is one frame by construction. Nodes not on the frame-N lists are
// untouched (page-blind owns them). Runs before alloc_invariants::check(POSTLOAD), so the oracle validates the FINAL state.
// +0x8 slab-identity backptr — CAPTURED+RESTORED, not derived. +0x8 is not a pure function
// of the node's address: the engine sets it once at carve to the exact slab pointer and PROPAGATES it verbatim through
// every split, so a block that has drifted past the first 64K page of a multi-page slab has +0x8 != (node & ~0xFFFF).
// A node&~0xFFFF derive is therefore wrong for those blocks — it overwrote correct propagated values with a
// plausible-but-wrong slab, and since coalesce (FUN_1404CB480) uses +0x8 as an identity MERGE KEY (`cmp r14,[nbr+8]`),
// a wrong value merges two unrelated blocks => the malformed block lands in ctrl+0xc0 => 0x1404CA410 reserve-walk tear.
// The original 0x1404CB613 (+0x8==0) was a page-blind stale-reference crash: FLIST-UNIT restored the 6 links from frame N while
// page-blind restored +0x8 from a different epoch. Adding +0x8 to the captured unit closes it right — restore-faithful.
static void restore_freelists(int target_frame) {
    int slot = -1;
    for (int s = 0; s < ALLOC_RING_SLOTS; s++)
        if (g_flist_frames[s] == target_frame && g_flist_valid[s]) { slot = s; break; }
    if (slot < 0) {
        bool w = rblog::is_suppressed(); rblog::suppress(false);
        rblog::write("FLIST-UNIT: NO exact valid slot for target f%d — unit restore SKIPPED (page-blind stands; if INVARIANT-CHECK breaks this rollback, this line is the reason)", target_frame);
        rblog::suppress(w);
        return;
    }
    int wrote = 0, skipped = 0;
    for (int i = 0; i < g_flist_count[slot]; i++) {
        FlistNode& e = g_flist_ring[slot][i];
        if (!arena::is_committed_addr(e.addr) || !arena::is_committed_addr(e.addr + 0x40)) { skipped++; continue; }
        *(uint64_t*)(e.addr + 0x18) = e.f18; *(uint64_t*)(e.addr + 0x20) = e.f20;
        *(uint64_t*)(e.addr + 0x28) = e.f28; *(uint64_t*)(e.addr + 0x30) = e.f30;
        *(uint64_t*)(e.addr + 0x8)  = e.f8;                                        // +0x8 = the CAPTURED slab-identity backptr (restore-faithful; closes the 0x1404CB613 stale-reference crash)
        *(uint32_t*)(e.addr + 0x38) = e.f38; *(uint32_t*)(e.addr + 0x3c) = e.f3c;
        wrote++;
    }
    _InterlockedExchangeAdd64(&g_flist_restored, wrote);
    bool w = rblog::is_suppressed(); rblog::suppress(false);
    rblog::write("FLIST-UNIT: restored %d free-list node(s) as one unit @f%d (skipped=%d uncommitted) — descriptor+nodes = one instant by construction",
                 wrote, target_frame, skipped);
    // ALIST-UNIT replay — the alloc list from the same instant, replayed after the free list (deterministic
    // last-writer; at a clean instant T the two node sets are disjoint by the engine's partition invariant, so
    // order is moot — a captured-corrupt overlap is flagged by the DOUBLE-MEMBER oracle, alist wins ties).
    // Closes the mixed-source alloc restore (descriptor memcpy + page-blind links):
    // now both lists of the shared-field pair are one CS-held instant => double-membership unrepresentable.
    if (g_alist_valid[slot]) {
        int awrote = 0, askipped = 0;
        for (int i = 0; i < g_alist_count[slot]; i++) {
            FlistNode& e = g_alist_ring[slot][i];
            if (!arena::is_committed_addr(e.addr) || !arena::is_committed_addr(e.addr + 0x40)) { askipped++; continue; }
            *(uint64_t*)(e.addr + 0x18) = e.f18; *(uint64_t*)(e.addr + 0x20) = e.f20;
            *(uint64_t*)(e.addr + 0x28) = e.f28; *(uint64_t*)(e.addr + 0x30) = e.f30;
            *(uint64_t*)(e.addr + 0x8)  = e.f8;
            *(uint32_t*)(e.addr + 0x38) = e.f38; *(uint32_t*)(e.addr + 0x3c) = e.f3c;
            awrote++;
        }
        _InterlockedExchangeAdd64(&g_alist_restored, awrote);
        rblog::write("ALIST-UNIT: restored %d alloc-list node(s) as ONE unit @f%d (skipped=%d) — the DUAL-LIST pair {free,alloc} is now one instant; mgr+0x40/48/50/54 came with the descriptor blob",
                     awrote, target_frame, askipped);
    } else {
        rblog::write("ALIST-UNIT: slot @f%d INVALID — alloc side page-blind THIS rollback (mixed-source window open; if a DOUBLE-MEMBER/violator episode follows, this line is the reason)", target_frame);
    }
    rblog::suppress(w);
}

// NULL-ALLOC TRIPWIRE (the 0x30 batch-poison root discriminator). The render-effect batch submitter
// (FUN_140650DD0) allocs its whole sort buffer via [singleton 0x140D76318]->vtbl+0x40 with zero null-check
// (0x140650F5B..F6C) and seeds a per-child dest accumulator from the return => one NULL return poisons the
// whole frame's batch as {0x0,0x10,0x20,0x30..} => the 0x14078B659 crash. Vanilla never sees a NULL here —
// WE change the pressure (P3 defer-all reuse-delay / possibly a corrupt upstream count). This hook is the
// discriminator: NULL with a SANE size + starved reserve = P3 reserve
// starvation (fix = slab-aware flush ordering in quarantine); NULL with an ABSURD size = corrupt count table
// upstream (fix = a coherence unit over the cumulative-count tables). Hot-path cost = one branch on the return.
static void* (*orig_scratch_alloc)(void*, uint64_t, uint64_t, uint64_t) = nullptr;
static volatile LONG64 g_null_alloc_fires = 0;
static void* hk_scratch_alloc(void* self, uint64_t size, uint64_t a3, uint64_t a4) {
    void* ret = orig_scratch_alloc(self, size, a3, a4);
    if (!ret && size) {
        LONG64 nth = _InterlockedIncrement64(&g_null_alloc_fires);
        if (nth <= 8) {
            uintptr_t vt = 0, rsv_cnt = 0; uint64_t rsv_units = 0;
            uintptr_t s = (uintptr_t)self;
            if (s > 0x10000) { vt = *(uintptr_t*)s;
                if (arena::is_committed_addr(s + 0xd4)) { rsv_cnt = *(uint32_t*)(s + 0xd0); rsv_units = *(uint32_t*)(s + 0xd4); } }
            bool w = rblog::is_suppressed(); rblog::suppress(false);
            rblog::write("NULL-ALLOC #%lld: scratch allocator this=0x%llX vt(IDA)=0x%llX returned NULL for size=%llu bytes (frame=%d) | reserve cnt=%llu bytes=%llu | SANE size+starved reserve => P3 reserve starvation; ABSURD size => corrupt count table (batch submitter 0x140650DD0 has no null-check — its whole frame batch is now poisoned {0,0x10,0x20,..})",
                         (long long)nth, (unsigned long long)s,
                         (unsigned long long)(vt ? vt - addr::g_base + 0x140000000ull : 0),
                         (unsigned long long)size, g_frame_counter,
                         (unsigned long long)rsv_cnt, (unsigned long long)(rsv_units << 4));
            rblog::suppress(w);
        }
    }
    return ret;
}
static void install_null_alloc_tripwire() {
    static bool done = false; if (done) return;
    uintptr_t g = addr::resolve(0x140D76318);
    uintptr_t obj = (g && *(uintptr_t*)g > 0x10000) ? *(uintptr_t*)g : 0;
    if (!obj) return;                                   // singleton not constructed yet — retry next discover/heartbeat
    uintptr_t vt = *(uintptr_t*)obj;
    uintptr_t target = *(uintptr_t*)(vt + 0x40);
    if (!target) return;
    if (MH_CreateHook((void*)target, (void*)&hk_scratch_alloc, (void**)&orig_scratch_alloc) == MH_OK &&
        MH_EnableHook((void*)target) == MH_OK) {
        done = true;
        rblog::write("NULL-ALLOC tripwire ARMED: singleton obj=0x%llX vt(IDA)=0x%llX alloc-fn(IDA)=0x%llX — fires ONLY on a NULL return (never in vanilla)",
                     (unsigned long long)obj,
                     (unsigned long long)(vt - addr::g_base + 0x140000000ull),
                     (unsigned long long)(target - addr::g_base + 0x140000000ull));
    }
}

static void discover_allocators() {
    uintptr_t count_addr = addr::resolve(0x140D760E0);
    uintptr_t array_addr = addr::resolve(0x140D760F0);
    uintptr_t target_vt = addr::resolve(0x140B08620);

    uint32_t count = *(uint32_t*)count_addr;
    g_alloc_count = 0;

    rblog::write("ALLOC: registry has %d entries", count);

    for (uint32_t i = 0; i < count && i < 64 && g_alloc_count < MAX_ALLOCS; i++) {
        uintptr_t alloc = *(uintptr_t*)(array_addr + i * 8);
        if (!alloc) continue;

        uintptr_t vt = *(uintptr_t*)alloc;
        const char* name = (const char*)(alloc + 0x21);

        if (vt == target_vt) {
            g_alloc_addrs[g_alloc_count++] = alloc;
            if (name && strcmp(name, "Unit") == 0) {
                g_alist_target_ctrl = alloc;   // ALIST-UNIT scope: the alloc-list unit covers the Unit ctrl only (see g_alist_target_ctrl)
                rblog::write("ALIST-UNIT: scoped to \"Unit\" ctrl 0x%llX (every observed a4 episode lives here; whole-ctrl alloc capture overflowed on Resource)", (unsigned long long)alloc);
            }
            int gate6 = (int)(*(volatile uint8_t*)(alloc + 0x52) & 6);   // does the engine TAKE the per-desc CS?
            int ncls  = *(volatile int*)(alloc + 0x648);                 // active descriptor count
            rblog::write("ALLOC: [%d] scalable \"%s\" at 0x%llX | gate(+0x52&6)=%d ncls(+0x648)=%d => %s",
                        i, name, (unsigned long long)alloc, gate6, ncls,
                        gate6 ? "CS-GUARDED (gate's CS-wait is meaningful here)"
                              : "LOCK-FREE (gate SKIPS — no CS to wait on; if this is a load-bearing allocator the gate is inert for it)");
        } else {
            rblog::write("ALLOC: [%d] other \"%s\" at 0x%llX vt=0x%llX",
                        i, name, (unsigned long long)alloc,
                        (unsigned long long)(vt - addr::g_base + 0x140000000ULL));
        }
    }

    g_allocs_discovered = true;
    install_null_alloc_tripwire();   // the 0x30 batch-poison root discriminator (no-op if singleton not yet built)
    rblog::write("ALLOC: saving %d scalable allocators", g_alloc_count);

    // Publish allocator count to monitor
    if (monitor_shm::g_mon) {
        monitor_shm::g_mon->alloc_count = (uint32_t)g_alloc_count;
    }
}

// ============================================================
// resim_gate — the conditional-resim precondition registry: one set of gates that must all hold before resim
// runs; new preconditions are appended to the same list rather than adding a new mechanism each time.
//
// The freeze-mid-splice root: a worker SuspendThread-frozen mid FUN_1404cb350/FUN_1404cb480 (one of the two reciprocal
// free-list link halves written, the other not) resumes on thaw and completes the splice with stale pointers
// onto the reverted list => the wild link FUN_1404ca650 later walks. The engine's two-part write IS atomic under its
// per-desc CS (desc+0x80); our freeze breaks that atomicity by suspending mid-CS-hold.
//
// Fix: do not build our own locks — OBSERVE the engine's OWN CS held-state
// (CRITICAL_SECTION.OwningThread at +0x10, confirmed by reset_cs). A held allocator CS == a worker is mid-
// two-part-write. Before freezing, WAIT (bounded spin) for every allocator free-list CS to be released — the
// engine releases in microseconds (no WaitFor*/Sleep under any allocator CS, decomp-verified) — then freeze at
// a coherent instant. We WAIT for free, we never hold (sidesteps the full-drain deadlock/syscall-under-hold
// hazards). On budget timeout we DEFER the rollback (safe: no rollback = no corruption), never freeze mid-splice.
// READ-ONLY + DEFER-ONLY: zero allocator/game mutation. The first precondition is below; append more as other
// non-atomic two-part writes surface.
// ============================================================
namespace resim_gate {
    typedef bool (*precond_fn)();                 // true == safe for this precondition
    static struct { const char* name; precond_fn fn; } g_pc[8];
    static int  g_pc_n = 0;
    static bool g_enabled = true;                 // ON by default (read-only + defer-only = safe)
    static volatile LONG64 g_waits = 0, g_defers = 0;
    static void register_precond(const char* name, precond_fn fn) {
        if (g_pc_n < 8) { g_pc[g_pc_n].name = name; g_pc[g_pc_n].fn = fn; g_pc_n++; }
    }
    static const char* first_failing() {
        for (int i = 0; i < g_pc_n; i++) if (!g_pc[i].fn()) return g_pc[i].name;
        return nullptr;
    }
    // Spin (bounded) until all preconditions hold. Returns nullptr if safe, else the blocking name (=> DEFER).
    static const char* wait_until_safe(double budget_ms) {
        const char* f = first_failing();
        if (!f) return nullptr;
        InterlockedIncrement64(&g_waits);
        LARGE_INTEGER fq, t0, tn; QueryPerformanceFrequency(&fq); QueryPerformanceCounter(&t0);
        for (;;) {
            YieldProcessor();
            f = first_failing();
            if (!f) return nullptr;
            QueryPerformanceCounter(&tn);
            if ((double)(tn.QuadPart - t0.QuadPart) * 1000.0 / (double)fq.QuadPart > budget_ms) {
                InterlockedIncrement64(&g_defers); return f;
            }
        }
    }
}

// PRECONDITION #1: no worker holds an allocator free-list CS (= mid FUN_1404cb350/FUN_1404cb480 two-part splice). Read-only;
// runtime-gated on (control+0x52)&6 (the engine actually takes the CS) + control+0x648 (active descriptor count,
// so we never read an uninitialized descriptor's CS). OwningThread (CS+0x10) != current(main) tid => a WORKER.
static bool precond_no_alloc_cs_held() {
    DWORD me = GetCurrentThreadId();
    for (int i = 0; i < g_alloc_count; i++) {
        uintptr_t ctrl = g_alloc_addrs[i];
        // The MtScalableAllocator control objects are heap objects, not arena carves, so is_committed_addr
        // (arena-only) must not gate them (it would exclude all of them and make this check inert). Trust the
        // registry-validated pointer like save_allocators/reset_cs/AllocatorSnapshotCsScope do.
        if (ctrl < 0x10000) continue;
        if (!(*(volatile uint8_t*)(ctrl + 0x52) & 6)) continue;                    // lock-free allocator: no CS held
        int ncls = *(volatile int*)(ctrl + 0x648); if (ncls < 1 || ncls > 8) ncls = 8;
        for (int c = 1; c <= ncls; c++) {                                          // per-desc CSes (skip [0]=base CS 0x060)
            uintptr_t ot = *(volatile uintptr_t*)(ctrl + CS_RANGES[c].off + 0x10); // OwningThread
            if (ot != 0 && ot != (uintptr_t)me) return false;                      // a worker is mid-splice
        }
        uintptr_t mot = *(volatile uintptr_t*)(ctrl + 0x620 + 0x10);               // mgr-wide CS
        if (mot != 0 && mot != (uintptr_t)me) return false;
    }
    return true;
}

// PRECONDITION #2: the arc/resource loader is IDLE (not mid file-load/relocation). SUBSTRATE COHERENCE only.
// The async loader (FUN_140519040) + up to 3 workers (FUN_140517f40) ReadFile + relocate resource bodies
// OUTSIDE the manager CS, so freezing mid-relocation would snapshot a half-written substrate body and the
// in-place revert would tear it. Engine-native idle test: the loader's own check FUN_140519690 uses
// (+0x2a0e8 active-flag==0 && +0x2a0a0 pending-queue==0); we add the worker dispatch ring being drained
// (consume +0x2a1a0 == produce +0x2a19c). Read-only; on busy, do_rollback DEFERS (loads finish in ms).
static bool precond_no_loader_mid_load() {
    if (!g_sc_audio) return true;                                  // only the audio/arc substrate revert needs loader quiescence
    uintptr_t body = *(uintptr_t*)addr::resolve(0x140E175A8);
    if (body < 0x10000) return true;                               // no manager yet => nothing loading
    if (*(volatile int*)(body + 0x2a0a0) != 0)  return false;      // pending-load queue non-empty
    if (*(volatile char*)(body + 0x2a0e8) != 0) return false;      // loader active flag set
    if (*(volatile uint32_t*)(body + 0x2a1a0) != *(volatile uint32_t*)(body + 0x2a19c)) return false; // worker ring not drained
    return true;
}

// ── Locked when=save reciprocity scan (the torn-save discriminator; read-only) ──
// save_allocators (memcpy 0x660) + arena::save run UNLOCKED during fully-MT normal play, so an
// unlocked snapshot can capture a free list mid-splice (between FUN_1404cb350's two reciprocal stores) and
// faithfully restore the half-splice that the guardless FUN_1404ca650 first-fit walk later amplifies.
// This scope TryEnters every per-allocator CRITICAL_SECTION (CS_RANGES) so a scan run inside it
// observes a QUIESCED list. Combined with the existing when=rollback check (alloc_consistency::check
// post-load), a long run becomes decisive:
// clean@locked-save and clean@rollback => the break was quarantine-manufactured (ship nothing)
// clean@locked-save, broken@rollback => restore artifact (coherent / frame-paired restore)
// broken@locked-save => genuine pre-save corruption (torn-save or a live writer)
// pure READ-ONLY: only acquires/releases locks; never mutates allocator state. No repair, ever.
static volatile LONG64 g_alloc_snap_last_failed_cs = 0;
static volatile LONG64 g_alloc_snap_lock_skips     = 0;
static volatile LONG64 g_alloc_snap_lock_success   = 0;

struct AllocatorSnapshotCsScope {
    static constexpr int MAX_LOCKS = MAX_ALLOCS * 10;
    CRITICAL_SECTION* locks[MAX_LOCKS];
    int count;
    bool acquired;

    AllocatorSnapshotCsScope() : locks{}, count(0), acquired(false) {
        if (!g_allocs_discovered) discover_allocators();
        for (int i = 0; i < g_alloc_count; ++i) {
            for (int c = 0; c < 10; ++c) {
                CRITICAL_SECTION* cs = (CRITICAL_SECTION*)(g_alloc_addrs[i] + CS_RANGES[c].off);
                if (count >= MAX_LOCKS || !TryEnterCriticalSection(cs)) {
                    InterlockedExchange64(&g_alloc_snap_last_failed_cs, (LONG64)(uintptr_t)cs);
                    release();
                    LONG64 n = InterlockedIncrement64(&g_alloc_snap_lock_skips);
                    if (n <= 8 || (n % 120) == 0)
                        rblog::write("ALLOC-SNAP: skipped coherent snapshot #%lld; CS busy at 0x%llX",
                                     (long long)n, (unsigned long long)(uintptr_t)cs);
                    return;
                }
                locks[count++] = cs;
            }
        }
        acquired = true;
        InterlockedIncrement64(&g_alloc_snap_lock_success);
    }
    ~AllocatorSnapshotCsScope() { release(); }
    void release() {
        while (count > 0) { LeaveCriticalSection(locks[--count]); locks[count] = nullptr; }
        acquired = false;
    }
    bool ok() const { return acquired; }
};

static void save_allocators(int frame) {
    if (owned_heap_control_revert()) { if (!g_allocs_discovered) discover_allocators(); return; }  // owned-heap: page-blind owns the in-arena control; the alloc-ring (the cross-ring skew source) is unused. Keep discovery (g_alloc_addrs feeds the read-only oracles).
    if (!g_allocs_discovered) discover_allocators();
    int slot = g_alloc_ring_head;
    g_alloc_ring_frames[slot] = frame;
    g_alloc_ring_count[slot]  = g_alloc_count;
    // P1 CAPACITY DONATION (the NULL-alloc fix, runs before the captures so a donation is part of this
    // frame's coherent captured set — descriptor counts + FLIST-UNIT reserve capture include it; rollbacks
    // restore it; resim never sees the starved state). CS-held here (AllocatorSnapshotCsScope incl ctrl+0x620,
    // the reserve list's own runtime lock). Hand-rolled ADDITIVE splice — FUN_1404caba0 is never called (it clobbers
    // ctrl+0x90/98/18/b0/b8). Region = fresh OS-zeroed arena carve => header fields already 0; write
    // only +0x38=(size>>4)<<1 (size-units*2, bit0=0 free) + +0x3c=1 (reserve tag, matches FUN_1404caba0-on-zeroed) and
    // tail-append to ctrl+0xc0/c8 (+0x18 prev/+0x20 next), +0xd0 count++, +0xd4 units+=. Trigger: reserve bytes
    // below the 16MB floor. Budget: 512KB/donation, 128MB/ctrl, 512MB global — all logged.
    if (g_save_cs_held && arena::owned_heap_active()) {
        static int last_don_frame[MAX_ALLOCS] = {0};
        for (int i = 0; i < g_alloc_count; i++) {
            uintptr_t ctrl = g_alloc_addrs[i];
          for (int topup = 0; topup < 4; topup++) {   // FLOOR: multi-donate per save until the floor holds
            uint32_t rcnt = *(uint32_t*)(ctrl + 0xd0); uint64_t rbytes = ((uint64_t)*(uint32_t*)(ctrl + 0xd4)) << 4;
            // Floor, not near-empty reaction: a near-empty trigger (<128KB && cnt<4) accepts a 64KB tail while requests
            // run 152KB+, and a cooldown blocks re-topping while heavy scenes eat 512KB in <30 frames => NULL returns
            // with budget headroom => poisoned near-null pointers get STORED => the engine later frees them =>
            // FUN_1404cb350 corrupts the ctrl's lists (count truncation, recip breaks) => FUN_1404ca650 walks the
            // flagged node => WRITE 0x10. One root, everything downstream. Maintain the reserve floor; it
            // self-limits, no cooldown.
            // The floor is 16MB (was 2MB) because of a char-select/early-fight crash (rip 0x1409A299D, WRITE 0x0):
            // this loop is FRAME-BOUNDARY work, but the reserve is drained CONTINUOUSLY by worker threads. There the
            // reserve dipped to cnt=4 bytes=327680 — 320KB, but split 4 ways, so a SANE 262144-byte request found no
            // contiguous block, got NULL, and the game's batch submitter (0x140650DD0, no null-check) poisoned the
            // frame batch {0,0x10,0x20,..} -> memcpy into 0x0. The top-up for that very frame ran 10ms later, after
            // the crash. Note the failing quantity is LARGEST CONTIGUOUS BLOCK, not total bytes — so the floor must be
            // deep enough that a mid-frame burst can never walk the reserve down to "no block >= a request". At 512KB
            // per donation a 16MB floor keeps ~32 fresh contiguous regions standing between two save points; observed
            // continuous demand is ~2MB/min, so this is a wide margin, and 16MB/ctrl is well inside the 128MB cap.
            if (rbytes >= (16ull << 20)) break;
            // Caps: 128MB/ctrl + 512MB global. Demand is CONTINUOUS (fragmentation eats ~256KB/50s of heavy play; a1
            // consumes ~2MB/min), so earlier caps of 1MB, 16MB and 64MB per ctrl each bound within minutes and ended in
            // NULL returns; the cap alarm stays as the leak-rate tripwire. If this also drains, the consumer is the next
            // question (why first-fit never serves the recycled scratch: growing request sizes vs aging fragments).
            if (donated_per_ctrl[i] >= (128ull << 20) || donated_total >= (512ull << 20)) {
                static volatile LONG64 nCap = 0; LONG64 c = _InterlockedIncrement64(&nCap);
                if (c <= 8 || (c % 200) == 0)
                    rblog::write("DONATION CAP HIT #%lld a%d (per=%zu total=%zu) — reserve still starving; raise caps or fix the growth root", (long long)c, i, donated_per_ctrl[i], donated_total);
                break;
            }
            const size_t DSZ = 512 << 10;
            uintptr_t region = 0;
            if (!arena::carve_donation_region(DSZ, &region)) break;
            *(uint32_t*)(region + 0x38) = (uint32_t)((DSZ >> 4) << 1);   // size-units*2, bit0=0 (free)
            *(uint32_t*)(region + 0x3c) = 1;                             // reserve tag (FUN_1404caba0-on-zeroed equivalent)
            uintptr_t tail = *(uintptr_t*)(ctrl + 0xc8);
            if (tail) { *(uintptr_t*)(region + 0x18) = tail; *(uintptr_t*)(tail + 0x20) = region; }
            else      { *(uintptr_t*)(region + 0x18) = 0;    *(uintptr_t*)(ctrl + 0xc0) = region; }
            *(uintptr_t*)(region + 0x20) = 0;
            *(uintptr_t*)(ctrl + 0xc8) = region;
            *(uint32_t*)(ctrl + 0xd0) = rcnt + 1;
            *(uint32_t*)(ctrl + 0xd4) = (uint32_t)((rbytes + DSZ) >> 4);
            arena::note_donated_region(ctrl, region, DSZ);
            donated_per_ctrl[i] += DSZ; donated_total += DSZ; last_don_frame[i] = frame;
            bool w = rblog::is_suppressed(); rblog::suppress(false);
            rblog::write("DONATION f%d: ctrl a%d=0x%llX reserve was cnt=%u bytes=%llu — donated 512KB region 0x%llX toward the 16MB floor (per-ctrl %zu/128MB, total %zu/512MB)",
                         frame, i, (unsigned long long)ctrl, rcnt, (unsigned long long)rbytes,
                         (unsigned long long)region, donated_per_ctrl[i], donated_total);
            rblog::suppress(w);
          }
        }
    }
    // Order: descriptor memcpy after the donation loop — descriptor blob, FLIST walk and
    // QU table all observe the identical POST-donation instant (one coherent captured set, actually delivered).
    for (int i = 0; i < g_alloc_count; i++) {
        memcpy(g_alloc_ring[slot][i], (void*)g_alloc_addrs[i], 0x660);
    }
    save_freelists(frame, slot);   // FLIST-UNIT: capture the node-link unit in the same CS-held instant as the descriptor
    quarantine::save_table(frame, slot, g_save_cs_held);   // QUARANTINE-UNIT: the held-table is rollback state — same instant, same slot cadence
    g_alloc_ring_head = (g_alloc_ring_head + 1) % ALLOC_RING_SLOTS;
}

// Atomic allocator-group save (the torn-save fix: a POSTLOAD-broken invariant = the restore reinstated a
// half-completed splice). save_allocators (descriptor 0x660) and arena::save (in-arena nodes) are two snapshots;
// run UNLOCKED they capture different micro-instants while MT workers splice the free/alloc lists => the saved
// {descriptor, nodes} coherence group is internally inconsistent (forward link updated, backward not). Hold the
// allocator CSes across both so no splice is in flight at capture => the group is captured at one coherent instant.
// AllocatorSnapshotCsScope uses TryEnter + release-all-on-fail (no hold-and-wait => deadlock-free); we retry a
// bounded number of times (workers' splices are a few instructions) and fall back to the unlocked save if a CS
// stays busy (rare; logged) — a rare torn save beats a stall. Gated A/B by g_atomic_save.
static volatile LONG g_atomic_save_ok = 0, g_atomic_save_fallback = 0;
static volatile LONG g_alloc_skew_count = 0;   // cumulative ALLOC-SKEW (descriptor frame != target) — the restore-side break source
static bool try_atomic_alloc_save(int frame, int retries) {
    for (int a = 0; a <= retries; a++) {
        AllocatorSnapshotCsScope snap;   // acquires in ctor; releases in dtor at scope exit
        if (snap.ok()) {
            g_save_cs_held = true;       // FLIST-UNIT atomicity precondition (see save_freelists)
            save_allocators(frame);      // descriptor 0x660 x N (+ the free-list node unit, same instant)
            g_save_cs_held = false;
            if (!arena::save(frame)) {   // page ring failed for this frame => a unit slot valid for a frame the
                flist_invalidate_frame(frame);   // page ring never captured would graft frame-N links onto stale
                                                 // page bytes — invalidate the unit slot too
            }
            InterlockedIncrement(&g_atomic_save_ok);
            return true;
        }
        if (a < retries) SwitchToThread();   // a worker holds a CS mid-splice; yield so it can finish, then retry
    }
    return false;
}

// ── Scheduler-line save scan (torn-at-save discriminator; read-only) ───────────────────────
// sched_line_tick FUN_14051b4c0 walks each sUnit line from the +0x50 (oldest) head via node+0x18
// (toward newest) — the FORWARD chain. byid/dead_vtable_unlink walk the other end (+0x58 via +0x20) — which is why
// they reported "unlinked 0" all session: a torn restore leaves a node on the forward chain the
// backward walk never reaches. This scan walks the same geometry the crash uses and flags any node
// that is freed/reused (vtable not in-module — the exact 0x14051B61C crash precondition), lineid-
// incoherent (its +0x10 lineid != the line it is physically carried on), or mid-teardown (state 3/4)
// AT SAVE. An anomaly here (quiesced under the engine's own unit CS at sUnit+0x08) means torn-at-save
// => drain-at-save; clean here but the crash still fires => restore-pairing artifact. Geometry
// source-verified: UNIT_REGISTER FUN_14051a6b0 (head/tail +0x58/+0x50,
// next/prev +0x18/+0x20, CS at +0x08 gated by sUnit+0x30||DAT_140e178f0). pure READ-ONLY; canon+
// readable-guarded so it can never AV, TryEnter so it never blocks a worker.
static volatile LONG64 g_sched_scan_runs = 0, g_sched_scan_anom = 0, g_sched_scan_logged = 0, g_sched_lock_skips = 0;

static inline bool sched_canon(uintptr_t p) { return p >= 0x10000ULL && p < 0x800000000000ULL; }
static inline bool sched_readable(uintptr_t p, size_t n) {
    if (!sched_canon(p)) return false;
    // FAST-PATH: scheduler nodes are arena-resident; the committed-bitmap test is a ns array read vs a
    // per-node VirtualQuery SYSCALL (the µs/node tax that made the drain-at-save every-frame line walk dominate).
    // Same safety (committed => readable). Only the rare out-of-arena pointer falls back to VirtualQuery.
    if (arena::is_arena_addr(p)) return arena::is_committed_addr(p) && arena::is_committed_addr(p + n - 1);
    MEMORY_BASIC_INFORMATION m;
    if (!VirtualQuery((void*)p, &m, sizeof(m))) return false;
    if (m.State != MEM_COMMIT || (m.Protect & (PAGE_NOACCESS | PAGE_GUARD))) return false;
    return p + n <= (uintptr_t)m.BaseAddress + m.RegionSize;
}
static inline bool sched_in_module(uintptr_t p) {
    uintptr_t b = addr::g_base;
    return b && p >= b && p < b + 0x2000000ULL;   // a real in-module vtable (0x140xxxxxxx)
}

static void scheduler_save_scan(int frame) {
    uintptr_t sunit = *(uintptr_t*)addr::resolve(0x140E17698);
    if (!sched_readable(sunit + 0xc38, 4)) return;
    LPCRITICAL_SECTION cs = (LPCRITICAL_SECTION)(sunit + 0x08);   // sUnit unit-list CS (FUN_14051a6b0)
    if (!TryEnterCriticalSection(cs)) { InterlockedIncrement64(&g_sched_lock_skips); return; }  // never block a worker
    LONG64 run = InterlockedIncrement64(&g_sched_scan_runs);
    uint32_t nlines = *(uint32_t*)(sunit + 0xc38);
    if (nlines > 128) nlines = 128;
    for (uint32_t line = 0; line < nlines; line++) {
        uintptr_t node = *(uintptr_t*)(sunit + 0x50 + (uintptr_t)line * 0x30);   // forward-chain head (oldest)
        int guard = 0;
        while (sched_canon(node) && sched_readable(node + 0x20, 8) && guard++ < 4096) {
            uintptr_t vt = *(uintptr_t*)(node + 0x00);
            uint32_t  w  = *(uint32_t*)(node + 0x10);
            int  state   = (int)(w & 7);
            int  lid     = (int)((w >> 3) & 0x7f);
            bool bad_vt  = !sched_in_module(vt);                  // freed/reused block = the crash precondition
            bool bad_lid = (lid != (int)line);                   // membership disagreement (torn)
            bool teardown = (state == 3 || state == 4);          // mid-destruction transaction
            if (bad_vt || bad_lid || teardown) {
                InterlockedIncrement64(&g_sched_scan_anom);
                if (g_sched_scan_logged < 64) {
                    InterlockedIncrement64(&g_sched_scan_logged);
                    rblog::write("SCHED-SAVE-SCAN[f=%d line=%u node=0x%llX vt=0x%llX state=%d lineid=%d | "
                        "bad_vt=%d bad_lid=%d teardown=%d]%s",
                        frame, line, (unsigned long long)node, (unsigned long long)vt, state, lid,
                        (int)bad_vt, (int)bad_lid, (int)teardown,
                        bad_vt ? " <<TORN-AT-SAVE: freed/reused block still on the forward chain = the 0x14051B61C precondition (=> drain-at-save)" : "");
                }
            }
            node = *(uintptr_t*)(node + 0x18);                    // forward chain (crash-walk direction)
        }
    }
    LeaveCriticalSection(cs);
    if (run == 1 || (run % 50) == 0)
        rblog::write("SCHED-SAVE-SCAN: alive (runs=%lld anom=%lld lock_skips=%lld) — +0x50/+0x18 forward walk under sUnit+0x08",
                     (long long)run, (long long)g_sched_scan_anom, (long long)g_sched_lock_skips);
}

// ── DRAIN INSTRUMENTATION (read-only) ─────────────────────────────────────────────────────────────
// Answers three questions with zero mutation:
// count_state4() — coherent state-4 count at a checkpoint (POSTLOAD vs per-resim-frame => where the pile forms)
// DRAIN-CENSUS — nodes completed per drain call + ms
// DRAIN-IDENTITY — same nodes re-drained every rollback? (high overlap = spurious re-destruction of the standing population)
// DRAIN-DTOR-COST — one dtor's µs (serialization vs real compute)
static int count_state4(const char* /*tag*/) {
    uintptr_t sunit = *(uintptr_t*)addr::resolve(0x140E17698);
    if (!sched_readable(sunit + 0xc38, 4)) return -1;
    LPCRITICAL_SECTION cs = (LPCRITICAL_SECTION)(sunit + 0x08);
    if (!TryEnterCriticalSection(cs)) return -2;   // never block a worker; -2 == busy
    uint32_t nlines = *(uint32_t*)(sunit + 0xc38);
    if (nlines > 128) nlines = 128;
    int n = 0;
    for (uint32_t line = 0; line < nlines; line++) {
        uintptr_t node = *(uintptr_t*)(sunit + 0x50 + (uintptr_t)line * 0x30);
        int guard = 0;
        while (sched_canon(node) && sched_readable(node + 0x20, 8) && guard++ < 4096) {
            uintptr_t vt = *(uintptr_t*)(node + 0x00);
            uint32_t  w  = *(uint32_t*)(node + 0x10);
            if ((int)(w & 7) == 4 && sched_in_module(vt) && (int)((w >> 3) & 0x7f) == (int)line) n++;
            node = *(uintptr_t*)(node + 0x18);
        }
    }
    LeaveCriticalSection(cs);
    return n;
}
// ROLLBACK-STATE4 series — where the pile forms (set in do_rollback; logged once per rollback).
static int g_s4_postload = -1;
static int g_s4_resim[16] = {0};
static int g_s4_resim_n = 0;
// DRAIN-IDENTITY — this-call vs previous-call completed-node sets (overlap => re-destroyed standing population).
static uintptr_t g_drain_ids[512];
static int       g_drain_ids_n = 0;
static uintptr_t g_prev_drain_ids[512];
static int       g_prev_drain_ids_n = 0;

// ── DRAIN-AT-SAVE (the structural fix for the scheduler-line root cause) ───────────────────────
// Right before the (unlocked) snapshot, complete every COHERENT mid-teardown node so the snapshot can
// only ever contain stable state-1/2 entities (the engine's true end-of-frame invariant). Runs the
// engine's OWN state-4 sequence (decomp FUN_14051b4c0): clear low-3 state bits, UNIT_REMOVE
// unlink (FUN_14051b9f0), then the scalar-deleting destructor via vtable[0](node,1). This is engine code
// at SAVE during LIVE play (not resim, so the "no allocator work during resim" rule does not apply) — it just
// finishes a death the engine would finish ~1 frame later, deterministically on both peers (gp_crc-
// covered). Lock order sUnit+0x08 -> allocator matches the engine's own (register/remove take sUnit
// before allocating) so no new deadlock; TryEnter => never blocks a worker. A node already garbage at
// save (vtable not in-module / lineid mismatch = freed by a NON-scheduler path) is not drained here (you
// cannot run a destructor on a recycled block) — left for SCHED-SAVE-SCAN to report. Toggle g_sched_drain.
static volatile LONG   g_sched_drain = 1;
static volatile LONG64 g_drain_count = 0, g_drain_runs = 0, g_drain_lock_skips = 0;
typedef void (*unit_remove_fn)(uintptr_t, uintptr_t);   // FUN_14051b9f0(sUnit, node)
typedef void (*deleting_dtor_fn)(uintptr_t, int);       // vtable[0](node, 1)

static void scheduler_drain_at_save() {
    if (!g_sched_drain) return;
    uintptr_t sunit = *(uintptr_t*)addr::resolve(0x140E17698);
    if (!sched_readable(sunit + 0xc38, 4)) return;
    LPCRITICAL_SECTION cs = (LPCRITICAL_SECTION)(sunit + 0x08);
    if (!TryEnterCriticalSection(cs)) { InterlockedIncrement64(&g_drain_lock_skips); return; }
    auto unit_remove = (unit_remove_fn)addr::resolve(0x14051B9F0);
    LONG64 run = InterlockedIncrement64(&g_drain_runs);
    LARGE_INTEGER _d0; QueryPerformanceCounter(&_d0);   // instrumentation: per-call census/identity/cost (read-only)
    int this_drained = 0; g_drain_ids_n = 0;
    bool timed_first = false; double first_dtor_us = 0.0;
    uint32_t nlines = *(uint32_t*)(sunit + 0xc38);
    if (nlines > 128) nlines = 128;
    for (uint32_t line = 0; line < nlines; line++) {
        uintptr_t node = *(uintptr_t*)(sunit + 0x50 + (uintptr_t)line * 0x30);   // forward head (oldest)
        int guard = 0;
        while (sched_canon(node) && sched_readable(node + 0x20, 8) && guard++ < 4096) {
            uintptr_t next = *(uintptr_t*)(node + 0x18);   // capture before we mutate/free this node
            uintptr_t vt   = *(uintptr_t*)(node + 0x00);
            uint32_t  w    = *(uint32_t*)(node + 0x10);
            int state = (int)(w & 7);
            int lid   = (int)((w >> 3) & 0x7f);
            if (state == 4 && sched_in_module(vt) && lid == (int)line) {   // coherent state-4 only
                *(uint32_t*)(node + 0x10) = w & 0xfffffff8u;               // clear low-3 state bits
                unit_remove(sunit, node);                                  // FUN_14051b9f0: unlink (recursive CS ok)
                uintptr_t dvt = sched_readable(node, 8) ? *(uintptr_t*)node : 0;
                if (sched_in_module(dvt) && sched_readable(dvt, 8)) {
                    // The drain cost is not the count (only 4-34 units) but a few dtors that are individually
                    // 60-230ms. Time every dtor (wall + CPU cycles) and, for the heavy ones, name
                    // which class (vtable, IDA-rebased) and why: cpu<<wall => BLOCKING (worker-join/lock => fixable);
                    // cpu~=wall => real COMPUTE (recursive teardown).
                    if (g_netplay_lean) {   // [lean] dtor runs untimed — the DTOR-HEAVY probe is per-dtor QPC+cycle cost
                        ((deleting_dtor_fn)(*(uintptr_t*)dvt))(node, 1);
                        InterlockedIncrement64(&g_drain_count);
                        if (g_drain_ids_n < 512) g_drain_ids[g_drain_ids_n++] = node;
                        this_drained++;
                        node = next; continue;
                    }
                    LARGE_INTEGER _f0; QueryPerformanceCounter(&_f0);
                    ULONG64 _cy0 = 0, _cy1 = 0; QueryThreadCycleTime(GetCurrentThread(), &_cy0);
                    free_probe::calls = 0; free_probe::cycles = 0; free_probe::depth = 0;   // free_probe: our-free split
                    free_probe::armed = true;
                    ((deleting_dtor_fn)(*(uintptr_t*)dvt))(node, 1);        // vtable[0](node,1): destruct + free
                    free_probe::armed = false;
                    QueryThreadCycleTime(GetCurrentThread(), &_cy1);
                    LARGE_INTEGER _f1; QueryPerformanceCounter(&_f1);
                    double wall_ms = prof_ms(_f0, _f1);
                    long long fp_calls = free_probe::calls; double fp_ms = (double)free_probe::cycles / 3.5e6;
                    if (!timed_first) { first_dtor_us = wall_ms * 1000.0; timed_first = true; }
                    if (wall_ms > 20.0) {
                        double cpu_ms = (double)(_cy1 - _cy0) / 3.5e6;   // ~3.5GHz; the ~10x gap survives the estimate
                        uintptr_t vt_ida = 0x140000000ull + (dvt - addr::g_base);
                        rblog::write("DTOR-HEAVY: node=0x%llX vt=0x%llX line=%u wall=%.1fms cpu~%.1fms | OUR-FREE calls=%lld ms=%.1f => %s",
                                     (unsigned long long)node, (unsigned long long)vt_ida, line, wall_ms, cpu_ms,
                                     fp_calls, fp_ms,
                                     (fp_ms > wall_ms * 0.5) ? "OUR HOOKS (#1 — lighten the free path)"
                                     : (fp_calls > 200)      ? "OUR HOOKS likely (#1 — many frees, cheap each)"
                                     :                         "COLD-CACHE/engine (#2 — few frees, stalls elsewhere)");
                    }
                    InterlockedIncrement64(&g_drain_count);
                    if (g_drain_ids_n < 512) g_drain_ids[g_drain_ids_n++] = node;   // instrumentation: identity set
                    this_drained++;
                }
            }
            node = next;
        }
    }
    LeaveCriticalSection(cs);
    LARGE_INTEGER _d1; QueryPerformanceCounter(&_d1);
    // DRAIN-CENSUS/IDENTITY/DTOR-COST — outlier-gated (only when this call actually completed nodes,
    // i.e. ~once per rollback) => zero per-frame spam. Names the true count, the per-unit cost, and whether the
    // same nodes are re-destroyed each rollback (overlap high => spurious re-destruction of the standing population).
    if (this_drained > 0) {
        int overlap = 0;
        for (int i = 0; i < g_drain_ids_n; i++)
            for (int j = 0; j < g_prev_drain_ids_n; j++)
                if (g_drain_ids[i] == g_prev_drain_ids[j]) { overlap++; break; }
        int overlap_pct = g_drain_ids_n ? (overlap * 100 / g_drain_ids_n) : 0;
        rblog::write("DRAIN-CENSUS: drained=%d dt=%.1fms | DTOR-COST first_us=%.1f | IDENTITY overlap_prev=%d%% (n=%d prev=%d) — high overlap = standing population re-destroyed",
                     this_drained, prof_ms(_d0, _d1), first_dtor_us, overlap_pct, g_drain_ids_n, g_prev_drain_ids_n);
        for (int i = 0; i < g_drain_ids_n; i++) g_prev_drain_ids[i] = g_drain_ids[i];
        g_prev_drain_ids_n = g_drain_ids_n;
    }
    if (run == 1 || (run % 300) == 0)
        rblog::write("SCHED-DRAIN: alive (runs=%lld drained=%lld lock_skips=%lld) — completed coherent state-4 teardowns at save",
                     (long long)run, (long long)g_drain_count, (long long)g_drain_lock_skips);
}

// ── _purecall hook: catch the game's R6025 (a virtual called on a partially-destructed object) and LIMP
// instead of the modal dialog + 77-thread hang. Logs the umvc3 caller chain (the virtual call site) for
// attribution, then RETURNS => the pure call is skipped (for the destructor-virtuals in this family that
// is leak-not-crash). Read-only diagnosis + soft mitigation. Game CRT is statically linked, so we must
// hook the game's own _purecall @0x1409a2e90 (a DLL-side _set_purecall_handler would not see it).
typedef void (*purecall_fn)(void);
static purecall_fn orig_purecall = nullptr;
static volatile LONG g_purecall_count = 0;

static void hk_purecall(void) {
    void* bt[24];
    USHORT n = RtlCaptureStackBackTrace(0, 24, bt, nullptr);
    uintptr_t b = addr::g_base;
    char chain[256]; int off = 0; int found = 0;
    for (USHORT i = 0; i < n && found < 6 && off < (int)sizeof(chain) - 20; i++) {
        uintptr_t ra = (uintptr_t)bt[i];
        if (b && ra >= b && ra < b + 0x2000000ULL) {
            off += snprintf(chain + off, sizeof(chain) - off, " 0x%llX",
                            (unsigned long long)(ra - b + 0x140000000ULL));
            found++;
        }
    }
    LONG c = InterlockedIncrement(&g_purecall_count);
    if (c <= 48) {
        bool was = rblog::is_suppressed(); rblog::suppress(false);
        rblog::write("PURECALL[#%ld]: R6025 pure-virtual (partially-destructed/recycled object) — umvc3 callers:%s => LIMP (skip, no dialog/hang)",
                     c, found ? chain : " <none in-module>");
        rblog::suppress(was);
    }
    // return (do not call orig_purecall, which _amsg_exit(8)s + dialogs) => the pure call is skipped.
}

// sCharacter [0x2600,0x4000) (the skip_crc entity-pointer region) is RESTORED, not re-derived: wholesale-zeroing it
// post-load crashed on the first rollback (READ [null+0x48] in MAIN_PROC) — the engine derefs those pointers before
// resim re-derives them.

static void restore_allocators(int target_frame) {
    if (owned_heap_control_revert()) return;   // owned-heap P4: the in-arena control's heap-zone pages were just reverted to frame N by arena::load (coherent with its slabs — one frame, no cross-ring skew). Overwriting from the 10-slot ring would reintroduce the cross-ring skew. Do nothing; page-blind's coherent revert stands.
    int best_slot = -1;
    for (int s = 0; s < ALLOC_RING_SLOTS; s++) {
        if (g_alloc_ring_frames[s] <= target_frame) {
            if (best_slot < 0 || g_alloc_ring_frames[s] > g_alloc_ring_frames[best_slot]) {
                best_slot = s;
            }
        }
    }
    if (best_slot < 0) {
        rblog::write("ALLOC: no ring slot for frame %d!", target_frame);
        alloc_consistency::note_head_frame(-2);   // heads not restored => any body-vs-head compare is moot
        return;
    }

    rblog::write("ALLOC: restoring from slot %d (frame %d) for target %d",
                best_slot, g_alloc_ring_frames[best_slot], target_frame);
    // Cross-ring skew probe: if the alloc ring has no exact slot for target_frame, the 0x660 heads come from a
    // different frame than the page-reverted slab bodies = cross-ring liveness skew. delta=0 => skew is dormant at
    // this depth; delta>0 => skew is reachable and a candidate carrier.
    bool _skew = (g_alloc_ring_frames[best_slot] != target_frame);
    if (_skew) {
        InterlockedIncrement(&g_alloc_skew_count);
        bool _sup = rblog::is_suppressed(); rblog::suppress(false);   // un-suppress: survive the frozen restore window
        rblog::write("ALLOC-SKEW: no exact alloc-ring slot for frame %d (best=%d, delta=%d) => heads/bodies from DIFFERENT frames (cross-ring liveness skew REACHABLE)",
            target_frame, g_alloc_ring_frames[best_slot], target_frame - g_alloc_ring_frames[best_slot]);
        rblog::suppress(_sup);
    }
    // ALLOC ATTRIBUTION (read-only) — every rollback, one line attributing a free-list break to its source:
    // restore-side ALLOC-SKEW (descriptor ring frame != target => 3-source reassembly) vs save-side torn snapshot
    // (atomic-save TryEnter fell back to UNLOCKED). If skew_count climbs with the breaks and fallback stays ~0 =>
    // the fix is restore-side ring-unification alone (no save barrier).
    {
        long ok = g_atomic_save_ok, fb = g_atomic_save_fallback, total = ok + fb;
        bool _sup = rblog::is_suppressed(); rblog::suppress(false);
        rblog::write("ALLOC-ATTR[target f%d]: descriptor=%s (delta=%d) | cum_skew=%ld | torn_save: ok=%ld fallback=%ld (rate=%.4f%%)",
            target_frame, _skew ? "SKEW" : "exact", target_frame - g_alloc_ring_frames[best_slot],
            (long)g_alloc_skew_count, ok, fb, total ? (100.0 * (double)fb / (double)total) : 0.0);
        rblog::suppress(_sup);
    }
    // Tell the consistency probe which frame the HEADS came from, so its post-load walk can flag any
    // node whose BODY (arena per-page revert) came from a different frame = the W2 cross-ring skew.
    alloc_consistency::note_head_frame(g_alloc_ring_frames[best_slot]);

    int rc = g_alloc_count;
    for (int i = 0; i < rc; i++) {
        uint8_t* dst = (uint8_t*)g_alloc_addrs[i];
        uint8_t* src = g_alloc_ring[best_slot][i];
        size_t pos = 0;
        for (int c = 0; c < 10; c++) {
            size_t cs_start = CS_RANGES[c].off;
            size_t cs_len = CS_RANGES[c].len;
            if (pos < cs_start) {
                memcpy(dst + pos, src + pos, cs_start - pos);
            }
            pos = cs_start + cs_len;
        }
        if (pos < 0x660) {
            memcpy(dst + pos, src + pos, 0x660 - pos);
        }
    }
    rblog::write("ALLOC: restored %d allocators (CSes preserved)", rc);
}

// ============================================================
// Overlay — small topmost window showing status
// ============================================================

static HWND g_overlay_hwnd = NULL;
static volatile bool g_overlay_ready = false;

// Shared state for overlay text (written by game thread, read by overlay WM_PAINT)
static char g_overlay_text[256] = "ROLLBACK: OFF";

// Colorkey: this exact color becomes transparent via WS_EX_LAYERED + LWA_COLORKEY
static constexpr COLORREF TRANSPARENT_KEY = RGB(1, 1, 1);

static LRESULT CALLBACK overlay_wndproc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    switch (msg) {
    case WM_PAINT: {
        PAINTSTRUCT ps;
        HDC hdc = BeginPaint(hwnd, &ps);
        // Fill with colorkey (becomes transparent)
        RECT rc;
        GetClientRect(hwnd, &rc);
        HBRUSH bg = CreateSolidBrush(TRANSPARENT_KEY);
        FillRect(hdc, &rc, bg);
        DeleteObject(bg);
        // Draw text shadow (black outline for readability)
        HFONT font = CreateFontA(16, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE,
                                  DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                                  DEFAULT_QUALITY, FIXED_PITCH | FF_MODERN, "Consolas");
        HFONT old = (HFONT)SelectObject(hdc, font);
        SetBkMode(hdc, TRANSPARENT);
        // Shadow
        RECT shadow_rc = rc;
        shadow_rc.left += 1; shadow_rc.top += 1;
        SetTextColor(hdc, RGB(0, 0, 0));
        DrawTextA(hdc, g_overlay_text, -1, &shadow_rc, DT_LEFT | DT_TOP | DT_NOPREFIX);
        // Foreground
        SetTextColor(hdc, RGB(0, 255, 0));
        DrawTextA(hdc, g_overlay_text, -1, &rc, DT_LEFT | DT_TOP | DT_NOPREFIX);
        SelectObject(hdc, old);
        DeleteObject(font);
        EndPaint(hwnd, &ps);
        return 0;
    }
    case WM_TIMER:
        InvalidateRect(hwnd, NULL, FALSE);
        return 0;
    case WM_DESTROY:
        KillTimer(hwnd, 1);
        return 0;
    }
    return DefWindowProcA(hwnd, msg, wp, lp);
}

static DWORD WINAPI overlay_thread(LPVOID) {
    // Wait for game window to exist
    Sleep(6000);

    WNDCLASSA wc = {};
    wc.lpfnWndProc = overlay_wndproc;
    wc.hInstance = GetModuleHandleA(NULL);
    wc.lpszClassName = "UMvC3RollbackOverlay";
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    RegisterClassA(&wc);

    // Find game window position
    HWND game = FindWindowA(NULL, "ULTIMATE MARVEL VS. CAPCOM 3");
    RECT game_rc = { 0, 0, 300, 40 };
    if (game) {
        GetWindowRect(game, &game_rc);
    }

    g_overlay_hwnd = CreateWindowExA(
        WS_EX_TOPMOST | WS_EX_TOOLWINDOW | WS_EX_NOACTIVATE | WS_EX_LAYERED,
        "UMvC3RollbackOverlay", "",
        WS_POPUP | WS_VISIBLE,
        game_rc.left + 8, game_rc.top + 30,  // just below title bar
        280, 50,
        NULL, NULL, GetModuleHandleA(NULL), NULL);

    if (!g_overlay_hwnd) {
        rblog::write("OVERLAY: CreateWindow failed (err=%lu)", GetLastError());
        return 1;
    }

    // Make colorkey transparent — text floats over the game
    SetLayeredWindowAttributes(g_overlay_hwnd, TRANSPARENT_KEY, 0, LWA_COLORKEY);

    // Repaint every 100ms
    SetTimer(g_overlay_hwnd, 1, 100, NULL);
    g_overlay_ready = true;
    rblog::write("OVERLAY: window created");

    // Message loop
    MSG msg;
    while (GetMessageA(&msg, NULL, 0, 0) > 0) {
        TranslateMessage(&msg);
        DispatchMessageA(&msg);
    }
    return 0;
}

static void update_overlay() {
    if (!g_overlay_ready) return;

    if (!g_engine_on) {
        snprintf(g_overlay_text, sizeof(g_overlay_text),
                 "ROLLBACK: OFF\nF5=arm  F6=rollback");
    } else if (!g_auto_rollback) {
        snprintf(g_overlay_text, sizeof(g_overlay_text),
                 "ROLLBACK: ON  frame=%d\nF6=rollback  Numpad*=auto", g_frame_counter);
    } else {
        int frames_until = AUTO_INTERVAL - (g_frame_counter - g_last_auto_frame);
        if (frames_until < 0) frames_until = 0;
        float secs = (float)frames_until / 60.0f;
        snprintf(g_overlay_text, sizeof(g_overlay_text),
                 "ROLLBACK: ON  AUTO  frame=%d\nnext rollback: %.1fs (%d frames)",
                 g_frame_counter, secs, frames_until);
    }
}

// ============================================================
// Rollback logic
// ============================================================


// DIAG: Track render sub-object addresses through force-dirty → load
static constexpr int RSUB_TRACK_MAX = 64;
struct RsubTrack { uintptr_t ent; uintptr_t anim_ctrl; uintptr_t render_sub; uintptr_t render_sub_vt; };
static RsubTrack g_rsub_track[RSUB_TRACK_MAX];
static int g_rsub_track_count = 0;

static void do_rollback(int64_t smain, int current_frame, int target_frame) {
    int depth = current_frame - target_frame;
    g_last_rollback_target = target_frame;   // expose for diagnostics (rtv_probe lifetime check)
    InterlockedExchange(&g_any_rollback, 1); // monotonic: a rollback has happened this session (P4 latent gate)
    rblog::write("ROLLBACK: frame %d -> %d (depth %d)", current_frame, target_frame, depth);
    // DEFERRED-FOLD drain (before any freeze/arena::load): flush the bg fold worker so the baseline it writes into
    // is fully coherent before load() reads it, and so freeze() never suspends the worker mid-memcpy. Runs on a
    // RUNNABLE worker (pre-freeze); the resim loop bypasses save() (F1) so no job is re-enqueued → this single drain
    // covers both freeze cycles. No-op (instant) when g_fold_defer is off or nothing is in flight.
    arena::fold_drain();
    // WMGR ACTIVATION FLAGS = a LIVE window-focus property (the main game-loop FUN_14051dee0 gates its frame on
    // wmgr+0x38/+0x2985; both 0 => Sleep(1) forever => the deadlock, worker park downstream). They are not
    // gameplay (no gp_crc reader) => EXTERNAL/PRESERVE role: capture the true live value at rollback ENTRY (before
    // any quiesce/zero) and re-assert it at EXIT, unconditionally — so arena::load reverting them or a skipped
    // quiesce can never strand the main loop. Captured here, restored at the bottom of do_rollback.
    uint8_t entry_wm38 = 0, entry_wm2985 = 0; uintptr_t wmgr_live = *(uintptr_t*)addr::resolve(0x140E17758);
    if (wmgr_live) { entry_wm38 = *(volatile uint8_t*)(wmgr_live + 0x38); entry_wm2985 = *(volatile uint8_t*)(wmgr_live + 0x2985); }
    // PHASE-TIMING (which do_rollback phase the time goes to; resim itself is ~0.09s — the rest is
    // suspend/restore + post-resim teardown). Logged at ROLLBACK-complete (un-suppressed).
    LARGE_INTEGER t_rb_start, t_rb_thaw, t_rb_preresim, t_rb_postresim, t_rb_done, t_rb_freq;
    LARGE_INTEGER t_al0={}, t_al1={}, t_cr0={}, t_cr1={}, t_belt0={}, t_belt1={};   // PERF per-phase brackets
    LARGE_INTEGER t_frz0={}, t_frz1={};   // PERF: freeze-alone bracket — splits freeze vs restore-steps in suspend+restore
    LARGE_INTEGER t_snd0={}, t_snd1={};   // PERF: sound-restore group bracket (variable, ~100ms)
    LARGE_INTEGER t_pa={}, t_pb={}, t_pd={};   // PERF: per-pass split within sound_group
    QueryPerformanceFrequency(&t_rb_freq);
    QueryPerformanceCounter(&t_rb_start);
    {   // cDraw FUN_1401ffca0-in-window: did the child reconfig fire between save(target) and now? decides QUARANTINE vs TRUNCATE
        long rc_now = draw_probe::reconfig_count();
        long rc_then = g_reconfig_at_frame[target_frame & 255];
        rblog::write("DRAW-RECONFIG: ffca0 fired %ld times in rollback window [%d,%d] (total=%ld) => %s",
            rc_now - rc_then, target_frame, current_frame, rc_now,
            (rc_now - rc_then) > 0 ? "in-window-frees => QUARANTINE applies" : "no-in-window-frees => TRUNCATE/skew");
    }

    // Signal rollback start to monitor
    if (monitor_shm::g_mon) {
        monitor_shm::g_mon->rollback_active      = 1;
        monitor_shm::g_mon->last_rollback_target = (uint32_t)target_frame;
        monitor_shm::g_mon->last_rollback_depth  = (uint32_t)depth;
    }

    // Pause voice pool flush during rollback
    voice_pool::pause_flush();

    // 1. Disable frame cap for the entire rollback sequence
    char* frame_cap = (char*)(smain + 0x7C);
    char saved_cap = *frame_cap;
    *frame_cap = 0;

    // No sync frame: the ConcRT workers are already idle after normal-play orig_main_proc returns, and the MAIN
    // render thread is already parked at do_rollback entry (in_umvc3=0, +0x38=0, cached=1) — no JOIN needed for
    // it; its intermediate-frame rendering is suppressed per-frame by hk_go_kick. The WINDOW thread is the one
    // that straddles (below).

    // WINDOW-THREAD QUIESCE (pre-freeze — the straddle fix). Zero the engine's OWN WndProc deactivation flags
    // (wmgr+0x38/+0x2985 — exactly what alt-tab does; sole readers = the window thread's loop gate, no gameplay
    // reader => gp_crc-safe), then WAIT for any in-flight draw-build iteration to EXIT (witness hook on
    // FUN_14053caf0). Only then freeze: the window thread is parked at its own Sleep(1) gate holding nothing,
    // and cannot re-enter (flags are 0) until we restore them after the resim. This is the engine's own
    // "window deactivated" state, driven to completion — not a force-suspend.
    uintptr_t wmgr = *(uintptr_t*)addr::resolve(0x140E17758);
    uint8_t saved_wm38 = 0, saved_wm2985 = 0;
    bool wmgr_parked = false;
    HANDLE held_wth = nullptr;   // window-thread full-access handle held SUSPENDED across the resim (resumed post-resim)
    if (wmgr) {
        // Deterministic window-thread ID: its CreateThread handle is stored at wmgr+0x2a98 (the thread proc is
        // FUN_14051dee0). Full-access handle (THREAD_ALL_ACCESS from CreateThread) — needed because freeze()'s
        // OpenThread(SUSPEND_RESUME, wtid) is DENIED by the window thread's ACL (otherwise it is never in the
        // suspended set, runs during the resim, and crashes).
        HANDLE wth = *(HANDLE*)(wmgr + 0x2a98);
        DWORD wtid = wth ? GetThreadId(wth) : 0;
        if (wtid) suspend::note_window_thread(wtid);
        g_rollback_render_block = true;   // build no-ops for any thread that slips past the quiesce
        saved_wm38   = *(volatile uint8_t*)(wmgr + 0x38);
        saved_wm2985 = *(volatile uint8_t*)(wmgr + 0x2985);
        *(volatile uint8_t*)(wmgr + 0x38)   = 0;
        *(volatile uint8_t*)(wmgr + 0x2985) = 0;
        wmgr_parked = true;
        // Wait for the whole in-flight iteration (d690 device-reset + build) to exit — a real device Reset
        // takes tens of ms, so the bound is Reset-sized. Park-confirm = depth 0 twice, 1ms apart (closes the
        // between-calls sampling gap). Every iteration terminates (even a failed Reset attempt), and with the
        // flags zeroed the loop then takes the Sleep branch — so this converges; the cap is a fail-open net.
        int waited_ms = 0, zero_streak = 0;
        while (zero_streak < 3 && waited_ms < 500) {
            if (g_window_iter_depth == 0) zero_streak++; else zero_streak = 0;
            Sleep(1); waited_ms++;
        }
        rblog::write("WMGR-QUIESCE: flags zeroed (+0x38 was %d, +0x2985 was %d); iteration depth=%ld %s after %d ms%s",
                     saved_wm38, saved_wm2985, (long)g_window_iter_depth,
                     (zero_streak >= 2) ? "drained" : "STILL ACTIVE",
                     waited_ms,
                     (zero_streak >= 2) ? " [parked at Sleep gate]" : " [TIMEOUT — likely mid device-Reset; freeze may straddle it]");

        // ACL-PROOF hold via the FULL-ACCESS handle (freeze's OpenThread is denied for this thread). But only
        // suspend it when it is PROVABLY lock-free: at its own Sleep(1) == ntdll!NtDelayExecution. The depth
        // witness covers only caf0/d690/ede0, so "depth==0" does not mean parked — the window thread can be
        // mid-render in an un-witnessed function holding the CRT heap lock; freezing it there deadlocks the
        // main-thread resim/log (a main-thread resim hang seen on an earlier run). So: suspend -> read RIP -> if at NtDelayExecution keep
        // (lock-free); else resume + let it run + retry (flags are 0, so it converges to Sleep). Bounded; on
        // give-up, do not hold (a possible crash beats a guaranteed hang).
        // SELF-SUSPEND GUARD (a 63s forever-hang seen on earlier runs): if wmgr+0x2a98's handle resolves to
        // the current (main) thread, then FUN_14051dee0 IS the main game thread — there is NO separate window
        // thread, and SuspendThread(wth) would self-deadlock (WT-FIRE "tid==main" is the same signal). In that
        // case the render-seam crashes are the MAIN thread inside the resim's orig_main_proc, not a holdable
        // second thread => skip the hold (no hang) and log it.
        DWORD cur_tid = GetCurrentThreadId();
        if (wth && wtid == cur_tid) {
            bool was = rblog::is_suppressed(); rblog::suppress(false);
            rblog::write("WT-HOLD: wmgr+0x2a98 handle IS the MAIN thread (tid=%u) — FUN_14051dee0 == main game thread, NO separate window thread to hold. Render-seam crashes are the MAIN thread in resim. Hold SKIPPED.", wtid);
            rblog::suppress(was);
            wth = nullptr;   // disable the hold path below
        }
        if (wth) {
            uintptr_t mod = (uintptr_t)GetModuleHandleA("umvc3.exe");
            static uintptr_t s_ntdelay = 0;
            if (!s_ntdelay) s_ntdelay = (uintptr_t)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtDelayExecution");
            bool safe = false; int tries = 0;
            for (; tries < 200; tries++) {
                DWORD prev = SuspendThread(wth);
                if (prev == (DWORD)-1) break;   // thread gone
                CONTEXT ctx; ctx.ContextFlags = CONTEXT_CONTROL;
                uintptr_t rip = GetThreadContext(wth, &ctx) ? (uintptr_t)ctx.Rip : 0;
                if (s_ntdelay && rip >= s_ntdelay && rip < s_ntdelay + 0x40) { safe = true; break; }  // at Sleep(1) = lock-free
                ResumeThread(wth);              // mid-render (maybe holding a lock) — let it run, retry
                Sleep(1);
            }
            if (safe) held_wth = wth;
            bool was = rblog::is_suppressed(); rblog::suppress(false);
            rblog::write("WT-HOLD: tid=%u %s after %d tries", wtid,
                         safe ? "SUSPENDED at NtDelayExecution (lock-free) — held through resim"
                              : "GAVE UP (never reached Sleep) — NOT held (no hang; may crash)", tries);
            rblog::suppress(was);
        }

        // WINDOW-THREAD CENSUS (once per session): both drain crashes ran on a start=FUN_14051dee0 thread
        // whose wmgr flags were zeroed — if the engine created more than one such thread (the wmgr holds
        // multiple HWNDs), parking one leaves its sibling running. Count them.
        {
            static bool censused = false;
            if (!censused) {
                censused = true;
                uintptr_t wt_start = addr::resolve(0x14051DEE0);
                typedef LONG (NTAPI *NtQIT_fn)(HANDLE, ULONG, PVOID, ULONG, PULONG);
                NtQIT_fn qit = (NtQIT_fn)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationThread");
                int found = 0; DWORD tids[8] = {};
                HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
                if (snap != INVALID_HANDLE_VALUE && qit) {
                    THREADENTRY32 te = { sizeof(te) };
                    if (Thread32First(snap, &te)) do {
                        if (te.th32OwnerProcessID != GetCurrentProcessId()) continue;
                        HANDLE h = OpenThread(THREAD_QUERY_INFORMATION, FALSE, te.th32ThreadID);
                        if (!h) continue;
                        uintptr_t start = 0;
                        qit(h, 9, &start, sizeof(start), nullptr);
                        CloseHandle(h);
                        if (start == wt_start && found < 8) tids[found++] = te.th32ThreadID;
                    } while (Thread32Next(snap, &te));
                    CloseHandle(snap);
                }
                rblog::write("WT-CENSUS: %d thread(s) with start=FUN_14051dee0: %u %u %u %u%s",
                             found, tids[0], tids[1], tids[2], tids[3],
                             found > 1 ? "  [SIBLING FOUND — an unparked second window thread]" : "");
            }
        }

        // No pre-freeze drain (RING-UNIT subsumes it): a pre-freeze drain is anti-faithful — it
        // force-destroys (vtable[0](obj,1), refcount ignored) every ring entry incl current-epoch survivors, i.e.
        // it executes deaths that happened on NO timeline, seeding the render-wrapper crash 0x140781B0A (batch-
        // destroying objects the original timeline kept, → holder dereferences the dead object). Its only job — stop the age-
        // gated drain FUN_14053a570 from reading a survivor's age field out of arena-reverted memory (0x14053A5D5)
        // — is now done correctly by RING-UNIT (coherent-full revert of the ring array+count to the exact target
        // frame ⇒ the age field is never reverted-garbage). Restore-faithful, not force-empty.
    }

    // CONDITIONAL GATE (resim_gate) — placed ADJACENT to the freeze (not at do_rollback entry: the
    // WMGR-QUIESCE + drain above take ~ms, so an entry-time check is TOCTOU-stale). Wait (bounded) for every
    // allocator free-list CS to be released by its (still-LIVE) worker — microseconds — so the freeze lands at a
    // coherent instant. Timeout => DEFER (clean: the drain above is self-contained, nothing held; freeze not yet
    // called). Read-only, never holds a CS (no deadlock).
    if (resim_gate::g_enabled) {
        LONG64 w0 = resim_gate::g_waits;
        const char* blk = resim_gate::wait_until_safe(2.0);
        rblog::write("RESIM-GATE: pre-freeze rb=%d->%d waited=%s (cum waits=%lld defers=%lld)",
            current_frame, target_frame, (resim_gate::g_waits > w0) ? "YES (a worker was mid-splice; spun for it)" : "no (clear at freeze)",
            (long long)resim_gate::g_waits, (long long)resim_gate::g_defers);
        if (blk) {
            rblog::write("RESIM-GATE: DEFER rollback %d->%d — '%s' busy past budget (worker mid-two-part-write).",
                current_frame, target_frame, blk);
            return;
        }
    }

    // Cross-boundary-pointer sound fix — PRE-FREEZE capture (threads still LIVE, == the engine's own
    // between-frame state; the one virtual next call is safe here, not during the freeze). Toggle-gated.
    sound_preserve::capture(target_frame);

    // Suppress all logging between freeze/thaw — CRT fprintf acquires
    // _HEAP_LOCK which suspended threads may hold → deadlock
    rblog::suppress(true);

    // 3. Freeze — workers should be idle after normal-play orig returned
    QueryPerformanceCounter(&t_frz0);
    suspend::freeze();
    QueryPerformanceCounter(&t_frz1);   // PERF: freeze duration alone (is the ~90ms the freeze, or the restore steps after it?)

    // COH-DIAG checkpoint frozen: are any allocator free-lists already torn right after the blind SuspendThread
    // (= a worker frozen mid free-list update)? First phase a list breaks localizes the upstream cause.
    // INVARIANT-CHECK frozen baseline: frame N is coherent + the world is OS-frozen here, so the crash-proven allocator
    // free-list/alloc-list invariants must hold. A break here means the game was already incoherent pre-rollback (not us).
    if (!g_netplay_lean) alloc_invariants::check(alloc_invariants::PH_FROZEN, current_frame);
    // EDGE-CENSUS (ground-truth map for the owned-heap restore): at this COHERENT live state, classify every pointer
    // field's residence (in-arena / module / out-of-arena-edge) across all live objects. Accumulates the
    // ground-truth cross-boundary edge set the edge-coherent restore will consume. Read-only.
    if(g_scaffold) edge_census::census();

    // POST-FREEZE RECHECK: SuspendThread is ASYNC — it can catch a worker that took an
    // allocator CS in the microsecond window after the pre-freeze all-clear. Now that workers are frozen (CS
    // state is stable, and reset_cs has not run yet so OwningThread is still authoritative), re-read: any held
    // allocator CS == a worker frozen mid-two-part-write that would corrupt the list on thaw. THAW + DEFER
    // (clean: arena::load has not run; the worker resumes and finishes its splice on the still-live list = normal
    // play, no rollback this frame). This is the sound guarantee a pre-freeze spin alone cannot give.
    if (resim_gate::g_enabled && !precond_no_alloc_cs_held()) {
        suspend::thaw();
        suspend::resume_held();
        rblog::suppress(false);
        InterlockedIncrement64(&resim_gate::g_defers);
        rblog::write("RESIM-GATE: POST-FREEZE DEFER rollback %d->%d — a worker froze mid-two-part-write (allocator CS held post-freeze); thawed+resumed, no arena::load ran. waits=%lld defers=%lld",
            current_frame, target_frame, (long long)resim_gate::g_waits, (long long)resim_gate::g_defers);
        return;
    }

    // 4. Load arena + fix persistent state
    // handle_preserve::save() runs through the dynamic-restore registry (PH_SAVE).
    dyn_restore::run("sRender_persistent_handles", dyn_restore::PH_SAVE);

    // D3D9 device: EXTERNAL => PRESERVE the edge, never copy the contents. No save here. The device lives
    // out-of-arena so arena::load leaves it untouched, and the +0xB0 device-pointer is already preserved by
    // dyn_restore (F_PRESERVE +0xB0) + the sRender body rederive-exclusion. (Removed the 0x8000 content
    // memcpy that over-read the device's committed extent — an access violation.)

    // Save render sub-object COM pointers from all scheduler entities
    static constexpr int MAX_RSUB_SAVES = 1024;
    static struct { uintptr_t ac; uintptr_t rsub; } g_rsub_saves[MAX_RSUB_SAVES];
    int rsub_save_count = 0;
    {
        uintptr_t sunit = *(uintptr_t*)addr::resolve(0x140E17698);
        if (sunit) {
            for (int line = 0; line < 128; line++) {
                uintptr_t ent = *(uintptr_t*)(sunit + 0x58 + (uintptr_t)line * 0x30);
                int walk = 0;
                while (ent && walk < 512 && arena::is_committed_addr(ent)) {
                    uintptr_t ac = *(uintptr_t*)(ent + 0x538);
                    if (ac && arena::is_committed_addr(ac)) {
                        uintptr_t rsub = *(uintptr_t*)(ac + 0x18);
                        if (rsub && rsub_save_count < MAX_RSUB_SAVES) {
                            g_rsub_saves[rsub_save_count++] = { ac, rsub };
                        }
                    }
                    ent = *(uintptr_t*)(ent + 0x20);
                    walk++;
                }
            }
            rblog::write("RSUB-PRESERVE: saved %d COM pointers from scheduler walk", rsub_save_count);
        }
    }

    // RENDER-DOMAIN PRESERVE: snapshot the live RTV/DSV +0x20 driver-surface handles before the
    // revert (they revert to frame-N handles whose driver surfaces were already released => d3d9 -1).
    // rtv_probe::preserve_save() runs through the registry (PH_SAVE).
    dyn_restore::run("nDraw_RenderTargetView_DepthStencilView_0x20", dyn_restore::PH_SAVE);

    monitor_shm::set_phase(PHASE_PRE_RESTORE, target_frame);

    // RESTORE-BY-STRUCTURE: register the sRender render-body as RE-DERIVE (exclude its pages from the revert;
    // resim re-renders it). Must run before arena::load so the exclusion bitmap is set for this load.
    dyn_restore::run("sRender_body_rederive", dyn_restore::PH_SAVE);

    // SOUND-RESOURCE OBJECT-GRANULAR PRESERVE: the sSound body is rederive-excluded (kept live), but the
    // refcounted sound-resource objects it caches (rSoundSource etc.) are slab-packed in shared Global slot-0
    // IN-ARENA, so arena::load reverts them -> live container -> garbage-vtable vcall (the sound cue/source crash). page-exclusion
    // can't reach a slab-packed object. Snapshot their live bytes now (before the revert); restore after load.
    // Complete by construction (registered at the resource refcount-inc chokepoint). See sound_resource_preserve.cpp.
    sound_resource_preserve::save();
    // PER-OBJECT AUDIO PRESERVE (the non-reflected streaming engine objects sound_resource_preserve's vtable hook
    // misses: voiceP 0x140bad660 / channel 0x140bad7d0 / 32 strips 0x140bad4b0 / resource + sSound/ss_sub containers).
    // Walk-discovered (audio_probe::collect), snapshotted live now, written back after load — keeps audio at the live
    // epoch without page-excluding (which tore the allocator free-list). Replaces the removed audio page-exclude.
    audio_preserve::save();
    // CONTENT-AWARE PAGE (F11): arena::load (page-revert) stays AUTHORITATIVE — complete + coherent + allocator/
    // lifecycle all handled. pre_load captures live REBUILD values (leave-live); post_load writes them back + severs
    // provably-stale EDGE pointers. OFF => both no-op => plain page-revert.
    // SCOPED COHERENT RESTORE: register each scalable allocator's in-arena pool [control+0x90, control+0x98) as a
    // coherence-full range so arena::load FULL-reverts those node pages to the target frame (windowed elsewhere).
    // The free/alloc lists live in these pools; windowed revert left some node pages cross-frame => the POSTLOAD
    // invariant breaks. Full-revert fixes this (0 node breaks); scoping it here keeps full speed. The out-of-arena
    // descriptor is restored to the same target frame by restore_allocators below => whole group coherent.
    {
        // RE-ENUMERATE the allocator registry LIVE each rollback (not the init-captured g_alloc_addrs): the registry
        // GROWS (per-stage/area scalable allocators created after boot, e.g. ctrl 0xD549CA0). Init capture missed
        // them => their pools got windowed mixed-epoch restore => free-list torn (INVARIANT-CHECK PL breaks) => the worker
        // free-list walker (0x1404CB) reads a reused-slab garbage next-ptr. Cover every current scalable allocator.
        static uintptr_t cf_base[80]; static size_t cf_size[80]; int cf_n = 0;
        uintptr_t reg_cnt_a = addr::resolve(0x140D760E0), reg_arr_a = addr::resolve(0x140D760F0);
        uintptr_t scal_vt   = addr::resolve(0x140B08620);
        uint32_t nreg = (reg_cnt_a) ? *(uint32_t*)reg_cnt_a : 0; if (nreg > 64) nreg = 64;
        for (uint32_t i = 0; i < nreg && cf_n < 80; i++) {
            uintptr_t ctrl = *(uintptr_t*)(reg_arr_a + (uintptr_t)i * 8);
            if (!ctrl || *(uintptr_t*)ctrl != scal_vt) continue;     // only genuine scalable allocators
            uintptr_t lo = *(uintptr_t*)(ctrl + 0x90), hi = *(uintptr_t*)(ctrl + 0x98);
            if (lo && hi > lo && (hi - lo) < 0x40000000ull) { cf_base[cf_n] = lo; cf_size[cf_n] = hi - lo; cf_n++; }
        }
        // P1 DONATION multi-region: donated regions are pool too — without this their pages lose the
        // coherent-full list-group protection the primary pool gets (the exact tear class donation must not reopen).
        for (int di = 0; di < arena::donated_region_count() && cf_n < 80; di++) {
            uintptr_t dc, db; size_t ds;
            if (arena::donated_region_get(di, &dc, &db, &ds)) { cf_base[cf_n] = db; cf_size[cf_n] = ds; cf_n++; }
        }
        // RING-UNIT (LIFE-FLOOR companion): the sRender deferred-death RETIREMENT RING lives
        // in sRender's F_REDERIVE zone — arena::load leaves those pages LIVE (unreverted), so a ring push/drain that
        // happened after the target frame does not rollback ⇒ dangling entries. But arena::save already captured
        // those pages every frame (write-watch is arena-wide, ignores rederive-exclude). So force-revert the ring
        // {array sr+0x8677b0.. count sr+0x87a7b0+4} to the target frame via the same coherent-full option the
        // allocator pools use ⇒ the ring is rolled back BY CONSTRUCTION (the FLIST-UNIT precedent), and the age field
        // restores exact — which SUBSUMES the drain crash 0x14053A5D5 (age read from reverted garbage), so no
        // pre-freeze drain is needed.
        if (cf_n < 80) {
            uintptr_t sra = addr::resolve(0x140E179A8);
            uintptr_t sr = sra ? *(uintptr_t*)sra : 0;
            if (sr && arena::is_arena_addr(sr + 0x8677b0)) { cf_base[cf_n] = sr + 0x8677b0; cf_size[cf_n] = 0x13004; cf_n++; }
        }
        arena::set_coherent_full_ranges(cf_base, cf_size, cf_n);
    }
    if (!g_netplay_lean) provenance::coverage();   // [lean-stripped] build the sub-page object index (pre-revert) + the coverage ledger (typed/data/UNRESOLVED)
    page_free::pre_load(target_frame);
    QueryPerformanceCounter(&t_al0);
    cs_keeplive_snapshot();   // CS KEEP-LIVE: capture the LIVE OS CS bytes; page-blind may now overwrite them freely — they're rewritten after restore_allocators (OS state is never rolled back)
    arena::load(target_frame);
    QueryPerformanceCounter(&t_al1);
    g_s4_postload = g_netplay_lean ? -1 : count_state4("POSTLOAD"); g_s4_resim_n = 0;   // instrumentation: coherent state-4 count right after restore (restore-seeded?)
    page_free::post_load(target_frame);
    // SOUND-RESOURCE PRESERVE (the root fix for the sound cue/source crash): write the live sound-resource bytes back over the
    // slab pages arena::load just reverted -> the live sSound container and its resources are coherent again,
    // no garbage vtable. Supersedes the partial vtable-only sound_preserve::restore below (which stays as a
    // detector). Whole-object, always-on during the engine window.
    QueryPerformanceCounter(&t_snd0);   // PERF: bracket the sound-restore group (the variable part of restore_steps)
    sound_resource_preserve::restore();
    QueryPerformanceCounter(&t_pa);   // PERF per-pass: after resource-preserve (the whole-object memcpy pass)
    // PER-OBJECT AUDIO PRESERVE write-back: re-apply the live streaming-engine object bytes over the slabs arena::load
    // just reverted (voiceP/channel/strips/resource + sSound/ss_sub). The page reverted (allocator neighbor coherent);
    // the audio object lands back at its live epoch (no garble). Pair of audio_preserve::save() above.
    audio_preserve::restore();
    QueryPerformanceCounter(&t_pb);   // PERF per-pass: after audio-preserve (36 objs — expected cheap)
    // Cue-slot detector/fix: after the revert, the (preserved, in-sSound-body) cue slot still points at its
    // Global-pool descriptor, but that descriptor's vtable (desc+0x00) may have reverted to garbage => the
    // 0x1405C2698 vcall AVs. restore() logs reverts (detector) and, when armed, writes the live vtable
    // back (identity-gated: slot still busy + still points at the same desc). Raw reads/writes only (freeze-safe).
    sound_preserve::restore(target_frame);
    QueryPerformanceCounter(&t_pd);   // PERF per-pass: after cue-slot preserve (38 slots — expected cheap)
    // SOUND-EDGE RECONCILE (the sound-container hang root fix): channel-node voice aliases (+0x18/+0x20/+0x28/+0x30)
    // restored byte-faithfully but pointing at OUT-OF-ARENA IXAudio2SourceVoice COM objects that were destroyed/
    // reused in the post-rollback window => the sound worker's `call *0x80(*(node+0x18))` (0x1405BEFE5) derefs a
    // freed-reused block's garbage vtable => AV => worker dies in the sound CS => main deadlocks on it. Null the
    // STALE (validity-checked) voice edges so FUN_1405bee80's `+0x18!=0` guard short-circuits + engine re-derives.
    sound_edge_reconcile::reconcile();
    QueryPerformanceCounter(&t_snd1);   // PERF: end of the sound-restore group
    // (INVARIANT-CHECK POSTLOAD runs after restore_allocators, below — the allocator descriptor is reverted there;
    // checking here would compare the live descriptor against reverted nodes.)
    // EDGE-COHERENT RESTORE (shadow): walk live objects, bucket each carrier edge A/B/C/D, and (LIVE only) null
    // bucket-A stale external edges so the engine re-derives. SHADOW = count would-act, write nothing,
    // confirm gp_crc unchanged + non-vacuous. The reconcile policy: A=null-stale-guarded-external,
    // B=preserve-live, C=excluded-singleton, D=abstain-worklist. Generalizes sound_edge_reconcile off its hardcoded list.
    QueryPerformanceCounter(&t_cr0);
    edge_census::coherent_restore();
    QueryPerformanceCounter(&t_cr1);
    // by-identity SHADOW: classify the effect+0x218 carrier's restore coherence on the raw arena::load output,
    // before dead_vtable_unlink (PH_POST_LOAD) unlinks bad-vtable entities (which would hide the stale reference). No-op unless F12. Zero writes.
    byid::restore_frame(target_frame);
    QueryPerformanceCounter(&t_belt0);
    QueryPerformanceCounter(&t_belt1);
    monitor_shm::set_phase(PHASE_ARENA_LOAD, target_frame);

    restore_data(target_frame);
    monitor_shm::set_phase(PHASE_DATA_RESTORE, target_frame);

    // The heap-zone offset rewind is required: disabling it breaks the zone's reclaim => fill/corruption =>
    // normal-play audio chips + crash 0xF000000B0 (sound path -> allocator deref of garbage). Gameplay HeapAllocs
    // during resim need it. The right fix for the audio side is segregation (route audio allocs OUT of the arena),
    // not fighting the heap-zone offset.
    restore_heap_zone(target_frame);
    monitor_shm::set_phase(PHASE_HEAP_ZONE_RESTORE, target_frame);

    // handle_preserve::restore() runs through the registry (PH_POST_LOAD).
    dyn_restore::run("sRender_persistent_handles", dyn_restore::PH_POST_LOAD);

    // Restore render sub-object COM pointers
    {
        int rsub_restored = 0;
        for (int i = 0; i < rsub_save_count; i++) {
            uintptr_t ac = g_rsub_saves[i].ac;
            if (arena::is_committed_addr(ac)) {
                *(uintptr_t*)(ac + 0x18) = g_rsub_saves[i].rsub;
                rsub_restored++;
            }
        }
        rblog::write("RSUB-PRESERVE: restored %d/%d COM pointers", rsub_restored, rsub_save_count);
    }

    // RENDER-DOMAIN PRESERVE: restore the live RTV/DSV +0x20 handles over the reverted-frame-N words
    // rtv_probe::preserve_restore() runs through the registry (PH_POST_LOAD).
    dyn_restore::run("nDraw_RenderTargetView_DepthStencilView_0x20", dyn_restore::PH_POST_LOAD);

    // D3D9 device restore: none (EXTERNAL/PRESERVE — see the save site). The +0xB0 edge re-bind already
    // restored the pointer; the device body was never reverted. (Removed the symmetric 0x8000 write-side overrun.)

    // Zero the VB/IB ring lock cursors (sRender+0x8676b8/+0x8676c0). They hold cursors for locks whose driver-side state no longer matches after
    // the rollback window; the final frame's real kick repopulates them fresh via FUN_14079fa40/fee0. A stale
    // cursor consumed by BUILD emits null-based vertex addresses => EXEC derefs code bytes (the d3d9 crash).
    {
        uintptr_t sr = *(uintptr_t*)addr::resolve(0x140E179A8);
        if (sr) {
            *(volatile uint64_t*)(sr + 0x8676b8) = 0;
            *(volatile uint64_t*)(sr + 0x8676c0) = 0;
        }
    }

    monitor_shm::set_phase(PHASE_PRESERVE_RESTORE, target_frame);

    restore_allocators(target_frame);
    cs_keeplive_restore();    // CS KEEP-LIVE: the live CS bytes are the last writer over the ctrl region — no CS byte ever comes from the ring/baseline (eliminates the ntdll+0x649E6 contention class by construction)
    // FLIST-UNIT (correct-by-construction; eliminates the torn free-list class): replay the CS-held-captured node-link unit
    // over the just-restored pages — descriptor (restore_allocators, same slot frame) + every listed node's links
    // = one instant. Kills the whole mixed-source tear class (pending-window, ring-horizon, invisible-write) for
    // the walked structure at once, instead of chasing per-break criminals. alloc_invariants::check(POSTLOAD) below
    // validates the final state every rollback.
    if (!owned_heap_control_revert()) restore_freelists(target_frame);
    // FREE-LIST REPAIR (rebuild derived from authoritative): the free-list count is DERIVED state. The authoritative
    // truth for frame N is the per-block ALLOCATED bit (+0x38 bit0) in the arena pages, just reverted by arena::load +
    // coherent-full. A descriptor head pointing at an allocated block (cross-ring skew: desc.head=B while B.bit0=1)
    // is the all-parked HANG root: the engine later frees B, FUN_1404cb480 head-inserts it -> B.next=B self-loop ->
    // FUN_1404ca650 first-fit spins forever holding the per-class CS. (A full rethread from the pool bit set was
    // tried and refuted — it regressed clean lists to cyclic.) repair_freelists re-derives count/tail/prev from the
    // validated forward chain (pass-1 validates read-only, bails unrepairable on any anomaly). The count-drift class
    // is organic live-side (walked!=count seen in FORWARD play with all counters clean; the restore faithfully
    // round-trips the drifted count), so this is not a torn-save workaround and runs ungated (the patch pile stays
    // OFF for the true workarounds). Safe here: still OS-frozen, touches only gp_crc-skipped link fields.
    alloc_invariants::repair_freelists(current_frame);
    // INVARIANT-CHECK POSTLOAD (the true post-restore point): nodes (arena::load) and descriptor (restore_allocators) are
    // both reverted now, still OS-frozen, resim not started. An invariant broken here (PASSing at frozen) = the restore put
    // the allocator coherence group outside V_T = a real RESTORE-SIDE defect. PASS here but break at POSTRESIM =>
    // replay/free-layer churn.
    if (g_hotdiag) alloc_invariants::check(alloc_invariants::PH_POSTLOAD, current_frame);   // PERF: read-only oracle, gated OFF (re-arm hotdiag.flag)
    // P4 SHADOW (read-only): validate the reuse-quarantine epoch-rebuild — idspine alive-at-T must match the
    // reverted arena's in-use bits (can the liveness set be rebuilt from in-use bits?).
    if (!g_netplay_lean) p4_shadow::validate_epoch_rebuild(target_frame);
    // QUARANTINE-UNIT (single-timeline construction): restore the held-table wholesale to frame N — table state
    // and page state revert from the identical coordinate, so a timeline-crossing entry is unrepresentable.
    // reconcile()'s per-entry heuristics survive only as the fallback when the target slot is invalid (unlocked
    // save / overflow — loud), mirroring FLIST-UNIT's page-blind degrade.
    if (!quarantine::restore_table(target_frame))
        quarantine::reconcile(target_frame);
    quarantine::prune_default_husks(target_frame);   // Default/zone deaths stamped after target rolled back => object alive again
    material_guard::identity_on_rollback();          // GEN-VALIDATION: invalidate the edge-shadow (restored bytes must not read as an in-place recycle)
    if (g_hotdiag) render_edge_probe::probe("POSTLOAD");   // PERF: read-only diagnostic, gated OFF (re-arm hotdiag.flag)
    // PARENT->FREED-CHILD EDGE-REPAIR + invariant-violation map: all restores complete, still OS-frozen, resim not started. One walk:
    // CONTAINER pass nulls invalid children of dynamic child-arrays (the parent->freed-child crash fix,
    // e.g. vt 0x140a7b2e0 +0x110); FIELD pass classifies every typegraph pointer slot and (armed via Numpad0) nulls
    // invalid referents; always reports the COH-GAP family for discovery. Desync-free (arena ptrs, gp_crc-skipped).
    if (patch_pile_enabled()) coherence_audit::repair(current_frame);   // owned-heap: P3 holds the slab + P4 reverts its bytes => no dangling child to null (detect-and-repair is the rejected approach)
    // COHERENT-SET REPAIR + IDENTITY (parent->freed-child + identity): present/retirement compact + idspine ALIVE_AT_N. POSTLOAD passes
    // identity=true with N=target_frame (the rollback target) — idspine's FORWARD model (not rewound by arena::load)
    // drops entries whose block was born after N / died by N (the slab-reuse danglers the vtable proxy can't see).
    coherent_set_repair::run_structural(current_frame, target_frame, /*identity=*/true);   // ungated: parent->freed-child compaction + MtList sever — render-domain, not subsumed by P3; gating them re-opened 0x1405DA4B5
    if (!g_netplay_lean) gameplay_complete::run(target_frame);   // read-only — walk the hashed gameplay strips, ask id_oracle if each edge is ALIVE_SAME at N; log any GAMEPLAY-COMPLETENESS-GAP (never null). GAP=0 => gameplay is a complete coherent cut.
    if (patch_pile_enabled()) coherent_set_repair::run(current_frame, target_frame, /*identity=*/true);   // catalog detect-and-repair rows only (still gated)
    monitor_shm::set_phase(PHASE_ALLOC_RESTORE, target_frame);

    // dead_vtable_unlink::validate(POST_LOAD) runs through the registry (PH_POST_LOAD).
    dyn_restore::run("scheduler_bad_vtable_unlink", dyn_restore::PH_POST_LOAD);

    monitor_shm::set_phase(PHASE_UNLINK_POST_LOAD, target_frame);

    // 5. Reset CS lock state — arena::load may have restored mid-lock state.
    // handle_preserve keeps DebugInfo/LockSemaphore. We reset lock fields to "unlocked."
    {
        auto reset_cs = [](uintptr_t cs_addr) {
            // Reset only a CS arena::load actually REVERTED to frame N = in-arena and not rederive-excluded.
            // Skip (a) rederive-EXCLUDED in-arena live regions (sRender/sSound — e.g. the whole sRender singleton
            // incl its CS at +0x08/+0x20) and (b) all out-of-arena CSes arena::load never touches — the Global-pool
            // boot singletons (render_scene_mgr/arc/batch/dev) and the allocator CSes. Those keep their LIVE lock
            // state; a frozen-not-quiesced worker may genuinely hold one, and zeroing the triple makes it underflow
            // on thaw (RtlLeave) -> AV/deadlock. The .data-memcpy-reverted CSes are out-of-arena so they use the
            // separate ungated path below.
            if (!arena::is_arena_addr(cs_addr) || arena::is_rederive_excluded(cs_addr)) return;
            *(int32_t*)(cs_addr + 0x08) = -1;  // LockCount = unlocked
            *(int32_t*)(cs_addr + 0x0C) = 0;   // RecursionCount = 0
            *(uintptr_t*)(cs_addr + 0x10) = 0;  // OwningThread = none
        };

        // Singleton CSes
        uintptr_t srender = handle_preserve::get_srender();
        if (srender) reset_cs(srender + 0x08);

        uintptr_t sunit = *(uintptr_t*)addr::resolve(0x140E17698);
        if (sunit) reset_cs(sunit + 0x08);

        uintptr_t render_scene_mgr = *(uintptr_t*)addr::resolve(0x140E18250);
        if (render_scene_mgr) {
            reset_cs(render_scene_mgr + 0x08);
            reset_cs(render_scene_mgr + 0x23970);
        }

        uintptr_t arc_mgr = *(uintptr_t*)addr::resolve(0x140E175A8);
        if (arc_mgr) {
            reset_cs(arc_mgr + 0x08);
            reset_cs(arc_mgr + 0x2A158);
        }

        uintptr_t batch_mgr = *(uintptr_t*)addr::resolve(0x140E193E8);
        if (batch_mgr) reset_cs(batch_mgr + 0x08);

        uintptr_t dev_mgr = *(uintptr_t*)addr::resolve(0x140E194A8);
        // The device-manager's CRITICAL_SECTION is at dev_mgr+0x08, not +0x10. Confirmed from
        // FUN_14065d410: EnterCriticalSection((LPCRITICAL_SECTION)(param_1 + 1)) where param_1 is the
        // longlong* dev_mgr => +1 == +8 bytes. A +0x10 reset would miss the real CS and corrupt its
        // OwningThread/LockSemaphore (dev_mgr+0x18/+0x20).
        if (dev_mgr) reset_cs(dev_mgr + 0x08);

        // Allocator CSes: not reset. restore_allocators deliberately skips the CS_RANGES bytes to keep these locks
        // LIVE across the rollback. Note the ctrls are HeapAlloc'd and hk_HeapAlloc redirects HeapAlloc into the
        // arena's heap zone, which arena::load has no exclusion for — page-blind rewrites those CS bytes every
        // rollback; cs_keeplive_* (snapshot pre-load, rewrite post-restore_allocators) closes that. Zeroing them
        // here would be wrong (a frozen worker may hold one; the precondition guarantees none is held at this point).

        // .data-resident CSes — reverted by the full .data memcpy (restore_data), so they carry a stale
        // RESTORED lock and must be reset. They are out-of-arena, so the (now arena-gated) reset_cs would skip
        // them — zero them directly here. EXCEPT 0x140D766F8 (DTI pool CS): it is in the .data PRESERVE list,
        // written back LIVE after the memcpy, so it is not reverted — resetting it contradicts the PRESERVE.
        static const uintptr_t DATA_CS_ADDRS[] = {
            0x140D76510,  // MtObject allocator CS
            0x140D766F8,  // DTI property pool CS
            0x140D2B448,  // Unknown (engine startup)
            0x140D2B408,  // Unknown (engine startup)
            0x140E17370,  // Singleton region CS
            0x140E1BCA0,  // Subsystem CS
            0x140E1C2A0,  // Subsystem CS
            0x140D47EB0,  // Render scene management CS
        };
        for (int i = 0; i < 8; i++) {
            if (DATA_CS_ADDRS[i] == 0x140D766F8) continue;   // .data PRESERVE-listed (live, not reverted) — skip
            uintptr_t cs = addr::resolve(DATA_CS_ADDRS[i]);
            if (!cs) continue;
            *(int32_t*)(cs + 0x08) = -1;   // .data was reverted by the memcpy => clear the stale RESTORED lock
            *(int32_t*)(cs + 0x0C) = 0;
            *(uintptr_t*)(cs + 0x10) = 0;
        }

        // Audio CSes: not reset. The sSound body (DAT_140E18520, incl. +0x1D7E0/+0x1CEC0)
        // and the NativeSystemXAudio2 sub-object (*(+0x40), incl. +0x49D0) are now F_REDERIVE-EXCLUDED —
        // kept at the LIVE epoch, never reverted. Resetting a LIVE CS that the (frozen-not-quiesced) audio
        // thread may hold would corrupt a lock it will Leave on thaw. A reset only makes sense for mid-lock
        // RESTORED state — moot once the domain is not restored.

        // DAT_140E20B90 → +0x38 (not audio — unrelated subsystem, still reverted => still reset)
        {
            uintptr_t base = *(uintptr_t*)addr::resolve(0x140E20B90);
            if (base && arena::is_committed_addr(base + 0x38)) {
                reset_cs(base + 0x38);
            }
        }
    }

    monitor_shm::set_phase(PHASE_CS_RESET, target_frame);

    // 6. Clean sMain task state — prevent stale task dispatch
    {
        uintptr_t smain_ptr = *(uintptr_t*)addr::resolve(0x140E177E8);
        if (smain_ptr) {
            *(int32_t*)(smain_ptr + 0x98) = 0;  // task count = 0
            *(int32_t*)(smain_ptr + 0x9C) = 0;  // cursor = 0
        }
    }
    monitor_shm::set_phase(PHASE_TASK_CLEANUP, target_frame);

    // 7. Thaw — all threads resume with clean state
    suspend::thaw();
    QueryPerformanceCounter(&t_rb_thaw);   // end of the suspend/restore window

    rblog::suppress(false);
    rblog::write("ROLLBACK: restored frame %d, starting %d resim frames", target_frame, depth);

    // RESET-PATH DIAG (read-only): tests the device-Reset hypothesis — that sRender+0x867734 (d3d9 device-lost/
    // reset flag) is reverted to a frame-N "lost" value, arming the window thread (gated on the window-mgr
    // singleton DAT_140e17758+0x38/+0x2985) to call d3d9::Reset = DeleteCriticalSection on the d3d9 CS mid-render.
    // sRender is F_REDERIVE-EXCLUDED (kept LIVE, not reverted) so +0x867734 should hold its LIVE value (0 unless the
    // device is genuinely lost). Logging 0 across the rollback refutes the hypothesis.
    {
        uintptr_t sr = *(uintptr_t*)addr::resolve(0x140E179A8);
        uintptr_t wm = *(uintptr_t*)addr::resolve(0x140E17758);
        uint32_t reset_flag = (sr && !IsBadReadPtr((void*)(sr + 0x867734), 4)) ? *(uint32_t*)(sr + 0x867734) : 0xDEAD;
        int wm38   = (wm && !IsBadReadPtr((void*)(wm + 0x38), 1))   ? *(unsigned char*)(wm + 0x38)   : -1;
        int wm2985 = (wm && !IsBadReadPtr((void*)(wm + 0x2985), 1)) ? *(unsigned char*)(wm + 0x2985) : -1;
        int sr38 = (sr && !IsBadReadPtr((void*)(sr + 0x38), 1)) ? *(unsigned char*)(sr + 0x38) : -1;
        int sr3d = (sr && !IsBadReadPtr((void*)(sr + 0x3d), 1)) ? *(unsigned char*)(sr + 0x3d) : -1;
        rblog::write("RESET-DIAG @restore: sRender+0x867734(device-lost)=0x%X | wmgr+0x38=%d wmgr+0x2985=%d | sRender +0x38=%d +0x3d=%d",
                     reset_flag, wm38, wm2985, sr38, sr3d);
    }

    monitor_shm::set_phase(PHASE_THAW, target_frame);

    // (freelist_diag's POSTLOAD walk is not run here — redundant with alloc_consistency::check below, which carries
    // the recip= gate. For deep free-list RE: freelist_diag::walk(ctrl + 0x1D8, tag) per allocator.)

    // Consistency probe (read-only): the test of dynamic-restore's REBUILD discipline.
    // Does each manager's byte-reverted free list agree with the blocks it threads (class nibble + count)?
    // DIVERGE => rebuild-from-headers would fix it (allocator joins dynamic restore); consistent =>
    // the deadlock forms during replay, not from restore skew (allocator stays serial-gate).
    // GATED on g_alloc_consist (default OFF): 8 free-list walks + 8 log lines every rollback is a measured
    // slice of the freeze. Numpad7 (ALLOC-DEBUG) arms it for free-list RE.
    if (g_alloc_consist) for (int i = 0; i < g_alloc_count; i++) {
        char ctag[40]; snprintf(ctag, sizeof(ctag), "a%d-f%d", i, target_frame);
        alloc_consistency::check(g_alloc_addrs[i], ctag);
    }
    // DYNDELETE validate (read-only) at PH_POST_LOAD: does the RESTORED free list contain any block the liveness
    // ledger says was ALIVE at the target frame? (self-gates on validate_on(), Numpad7). The restore-time view is
    // the baseline; STALE-LIVE here = the restore reinstated a live block as free.
    for (int i = 0; i < g_alloc_count; i++) {
        char dtag[40]; snprintf(dtag, sizeof(dtag), "POSTLOAD-a%d-f%d", i, target_frame);
        dyn_delete::validate(g_alloc_addrs[i], target_frame, dtag);
    }

    // STRUCTURE-AWARE allocator restore (F8-gated A/B): after the probe reports the raw count-mismatch,
    // re-derive each manager's free-list count from the actual list (count is bookkeeping over the list =>
    // derive it, don't byte-revert it). Tests whether the restore-side count-mismatch seeds the
    // during-replay free-list cycle. Default OFF = behavior-identical to the byte-revert baseline.
    if (g_alloc_rederive) {
        for (int i = 0; i < g_alloc_count; i++) {
            char rtag[40]; snprintf(rtag, sizeof(rtag), "a%d-f%d", i, target_frame);
            alloc_consistency::rederive_counts(g_alloc_addrs[i], rtag);
        }
    }

    // (No toggle save/restore here — the kick-scalar trajectory replay keeps +0x67648 bit-exact through the
    // resim, ending at the recorded pre-rollback value by construction. Restoring a stale copy would
    // INVERT the parity for odd depth => EXEC reads +0x867668[toggle^1] = the stale slot.)
    // 7. RESIM — all frames from target through current-1
    g_resim_active = true;
    g_rw_inline_count = 0;         // tally engine-native inline drains this rollback (shows the gate engaged)
    g_pf_serial_count = 0;         // tally async-ring serial forces this rollback
    rtv_probe::on_resim_start();   // clear the per-resim RTV/DSV ctor set (the suppression gate)
    QueryPerformanceCounter(&t_rb_preresim);   // post-thaw prep done (alloc_consistency + toggles); resim begins

    for (int i = 0; i < depth; i++) {
        int replay_frame = target_frame + i;
        input::inject(replay_frame);
        // RENDER CADENCE (the engine's BUILD(N)/EXEC(N-1) pipeline, respected across the resume seam:
        // the first EXEC after a suppressed window consumes the previous frame's buffer, so "render the final
        // resim frame" always ate a stale pre-rollback slot pointing
        // into the reverted arena). Now: NO kick dispatch and NO EXEC on any resim frame (the render thread
        // never runs during the rollback); the FINAL frame replays the kick scalars + RING SETUP and runs
        // the BUILD (fresh commands from final-resim state); the first NORMAL frame kicks naturally and its
        // EXEC consumes that fresh buffer — the engine's own standard 1-frame latency.
        g_replay_frame = replay_frame;
        g_suppress_render_kick = true;                       // all resim frames: no dispatch, scalars replayed
        g_kick_setup_ring = (i == depth - 1);                // final frame: replica kick also sets ring cursors
        g_rollback_render_block = (i < depth - 1);           // final frame: BUILD runs (no EXEC)
        orig_main_proc(smain);
        g_suppress_render_kick = false;
        g_kick_setup_ring = false;
        if (i == depth - 1) {
            // Final frame ran the real kick (incrementing from the replayed frame-(N-1) scalars). Verify it
            // landed on the recorded original trajectory; force + log if not (original skip-frame edge).
            uintptr_t sr = *(uintptr_t*)addr::resolve(0x140E179A8);
            KickRec& r = g_kick_ring[(replay_frame + 1) & 255];
            if (sr && r.frame == replay_frame + 1) {
                uint32_t c = *(volatile uint32_t*)(sr + 0x6764c);
                uint32_t t = *(volatile uint32_t*)(sr + 0x67648);
                if (c != r.counter || t != r.toggle) {
                    rblog::write("KICK-SCALAR-SKEW final frame %d: counter %u vs recorded %u, toggle %u vs %u — forcing recorded",
                                 replay_frame, c, r.counter, t, r.toggle);
                    apply_kick_scalars(sr, r.counter, r.toggle, r.threaded);
                }
            }
        }
        g_replay_frame = -1;
        gp_crc::check(replay_frame + 1);   // determinism ORACLE: resim post-frame vs orig's recorded next-frame
        gp_crc::canary_check(replay_frame + 1);   // CANARY always-on draw-count divergence (cheap, ungated)
        if (!g_netplay_lean) rblog::write("RESIM %d/%d (frame %d)", i + 1, depth, replay_frame);
        monitor_shm::set_phase(PHASE_RESIM, replay_frame);
        // PER-FRAME PHYSICAL-GRAPH SCAN (birth-frame latch). POSTLOAD was clean on the LOGICAL axis; the +0x28/
        // +0x30 physical-coalesce dimension FUN_1404cb480 trusts is UNCHECKED. If a +0x20 self-loop / phys tear is born
        // mid-replay, this names the exact frame it appeared (quiet => only logs on a real anomaly). Read-only.
        if (g_alloc_consist) for (int a = 0; a < g_alloc_count; a++) {
            char rtag[40]; snprintf(rtag, sizeof(rtag), "RESIM-f%d-a%d", replay_frame, a);
            alloc_consistency::check(g_alloc_addrs[a], rtag, /*anomalies_only=*/true);
        }
        if (!g_netplay_lean && g_s4_resim_n < 16) g_s4_resim[g_s4_resim_n++] = count_state4("RESIM");   // instrumentation: does the pile grow across resim?
    }
    // ROLLBACK-STATE4: where the coherent state-4 pile forms — postload-large ⇒ restore-seeded;
    // grows-across-resim ⇒ resim re-drives a standing population. Read-only, one line/rollback.
    if (!g_netplay_lean) {
        char b[176]; int o = 0;
        o += snprintf(b + o, sizeof(b) - o, "ROLLBACK-STATE4: postload=%d resim=[", g_s4_postload);
        for (int i = 0; i < g_s4_resim_n && o < 150; i++) o += snprintf(b + o, sizeof(b) - o, "%d ", g_s4_resim[i]);
        snprintf(b + o, sizeof(b) - o, "] (postload-large=restore-seeded; growing=resim-accumulated)");
        rblog::write("%s", b);
    }
    // Resume the render-domain thread(s) held suspended across the resim (the window thread — the parent node
    // of the render-seam crash family). World is now back at the consistent post-resim epoch, so it wakes
    // coherent. Resume before re-arming the flags so it observes them in the normal-play order.
    suspend::resume_held();
    // Resume the window thread held via its full-access handle (the ACL-proof hold). Resume before re-arming
    // the flags so it wakes to flags=0 (Sleep) then re-activates in the normal-play order.
    if (held_wth) {
        DWORD prev = ResumeThread(held_wth);
        rblog::write("WT-HOLD: resumed window thread post-resim (prev_count=%ld)", (long)prev);
        held_wth = nullptr;
    }
    // Re-arm the window thread's activation flags (quiesced pre-freeze). Post-loop = it wakes into a fully
    // consistent post-resim world and resumes its per-frame draw-builds with normal play.
    g_rollback_render_block = false;
    if (wmgr_parked) {
        *(volatile uint8_t*)(wmgr + 0x38)   = saved_wm38;
        *(volatile uint8_t*)(wmgr + 0x2985) = saved_wm2985;
        wmgr_parked = false;
    }
    g_resim_active = false;
    QueryPerformanceCounter(&t_rb_postresim);   // resim loop done; post-resim teardown begins
    // Frozen confirm (the torn-read fix). The POSTRESIM validate below runs THAWED (workers live since the
    // pre-resim thaw, window thread resumed) so a STALE-LIVE there could be a torn read of a worker mid-FUN_1404cb350. Re-
    // suspend the world and re-read at current_frame: a STALE-LIVE that survives the OS-frozen window cannot be torn
    // => real during-replay corruption (the gate for any fix). If frozen=0 while POSTRESIM>0 => it was torn-read noise.
    // Read-only (validate writes nothing). A balanced freeze/thaw/resume_held cycle (each resets its own state).
    // Gated so unarmed rollbacks / normal play pay nothing.
    // repair_on() has its OWN leg so the repairs inside (repair_freelists + run_structural) run even when lean/off
    // silences every check.
    if (alloc_invariants::repair_on() || dyn_delete::validate_on() || !alloc_invariants::is_off()) {
      // resim_gate for freeze()#2 — an unguarded POSTRESIM re-freeze is a suspend-mid-carve generator:
      // FUN_1404CA650's carve writes +0x38/+0x3c/+0x18/+0x20 across
      // many stores under one CS held the whole span, so a SuspendThread landing mid-carve snapshots a torn node).
      // Same quiesce as freeze()#1: WAIT (bounded) for every allocator CS to be released so the re-freeze lands at a
      // carve-COMPLETE instant. Unlike freeze()#1 (which DEFERS the whole rollback) the rollback already COMPLETED
      // here, so on timeout we SKIP this diagnostic+repair block (POSTLOAD repair already ran) rather than freeze a
      // worker mid-carve. WAIT-then-skip, never hold — no new lock, no deadlock.
      const char* blk2 = resim_gate::g_enabled ? resim_gate::wait_until_safe(2.0) : nullptr;
      if (blk2) {
        rblog::write("RESIM-GATE(freeze#2): SKIP re-frozen POSTRESIM validate/repair f%d — '%s' busy past budget (not freezing a worker mid-carve).",
                     current_frame, blk2);
      } else {
        suspend::freeze();
        // POST-FREEZE RECHECK (async SuspendThread window, mirrors freeze()#1's post-freeze recheck): a worker could
        // have taken a carve CS in the µs before the freeze landed. If so, thaw + SKIP — validating/repairing a
        // mid-carve-frozen list is exactly the torn-write this gate exists to prevent. Balances the freeze cleanly.
        if (resim_gate::g_enabled && !precond_no_alloc_cs_held()) {
            suspend::thaw();
            rblog::suppress(false);
            suspend::resume_held();
            rblog::write("RESIM-GATE(freeze#2): async-freeze caught a worker mid-carve f%d -> thawed, skipped validate/repair.", current_frame);
        } else {
        if (dyn_delete::validate_on()) for (int i = 0; i < g_alloc_count; i++) {
            char ftag[40]; snprintf(ftag, sizeof(ftag), "FROZEN-a%d-f%d", i, target_frame);
            dyn_delete::validate(g_alloc_addrs[i], current_frame, ftag);
        }
        // POSTRESIM REPAIR: the free-list + sRender lists re-tear during replay (POSTRESIM broken=2 seen, while
        // POSTLOAD was clean) and the POSTLOAD-only repair never reached them => FUN_1404cb350 walked the torn list / freed a
        // garbage retirement entry 3 frames into normal play (0x1404CB382 from the 0x14053a5d7 walk). Re-run the
        // restore-coherent repairs here (still OS-frozen) so normal play resumes on a coherent free-list + clean
        // present/retirement lists. Desync-free (arena ptrs / render, gp_crc-skipped). The check below verifies them.
        alloc_invariants::repair_freelists(current_frame);   // ungated (see the POSTLOAD site): organic count-drift heal, authoritative-chain re-derive
        coherent_set_repair::run_structural(current_frame, target_frame, /*identity=*/false);   // ungated (see POSTLOAD)
        if (patch_pile_enabled()) coherent_set_repair::run(current_frame, target_frame, /*identity=*/false);  // catalog rows only (gated)
        // INVARIANT-CHECK POSTRESIM (re-frozen, the torn-read fix): the world is back at resim-N. An invariant broken here
        // that PASSed at POSTLOAD = corruption formed during replay (a live store / boundary-crossing free), not
        // the restore => the fix is FREE-LAYER (quarantine reuse), not restore-side. This is the fork-decider.
        if (!g_netplay_lean) alloc_invariants::check(alloc_invariants::PH_POSTRESIM, current_frame);
        if (!g_netplay_lean) render_edge_probe::probe("POSTRESIM");   // parent->freed-child: if danglers appear here but not POSTLOAD => resim-born => sever must run post-resim
        suspend::thaw();
        // suspend::freeze() sets rblog::suppress(true); the first freeze/thaw cycle restores it above, and this
        // second cycle must too — otherwise DYN-RESTORE/RW-INLINE/PF-SERIAL/ROLLBACK-TIMING/"ROLLBACK: complete" are
        // silently eaten on every rollback. Restore before resume_held() so its own log line is visible too.
        rblog::suppress(false);
        suspend::resume_held();
        }   // end: freeze landed carve-complete -> validate/repair ran
      }     // end: else (gate clear -> we froze)
    }       // end: if (dyn_delete::validate_on() || !alloc_invariants::is_off)
    // POST-RESIM consistency scan (the during-replay bracket). Post-load is clean (restore is coherent —
    // ALLOC-SKEW=0, 0/8 DIVERGE every rollback). If the free list DIVERGEs here, the corruption formed during
    // the replay = a during-replay writer (a node coherent-at-restore is now
    // class0/recip-broken => a live store changed it, not a cross-frame revert). If still clean here but
    // FUN_1404ca650 crashes later in normal play, the corruptor is post-replay churn, not the replay. Read-only.
    if (g_alloc_consist) for (int i = 0; i < g_alloc_count; i++) {
        char ptag[40]; snprintf(ptag, sizeof(ptag), "POSTRESIM-a%d-f%d", i, target_frame);
        alloc_consistency::check(g_alloc_addrs[i], ptag);
    }
    // (A whole-arena resave-diff pass formerly ran between TEARDOWN[1] and [2]; removed. The markers stay to
    // bracket the post-resim teardown in the log.)
    { bool _w=rblog::is_suppressed(); rblog::suppress(false); rblog::write("TEARDOWN[1] post-lawcheck/pre-resavediff f%d", current_frame); rblog::suppress(_w); }
    { bool _w=rblog::is_suppressed(); rblog::suppress(false); rblog::write("TEARDOWN[2] post-resavediff f%d", current_frame); rblog::suppress(_w); }
    // DYNDELETE validate — POSTRESIM view: the post-resim free list should represent the resumed frame
    // (current_frame). A STALE-LIVE here that was COHERENT at POSTLOAD = the corruption formed during replay
    // — names whether a PH_POST_LOAD sever can even reach it.
    for (int i = 0; i < g_alloc_count; i++) {
        char dtag[40]; snprintf(dtag, sizeof(dtag), "POSTRESIM-a%d-f%d", i, target_frame);
        dyn_delete::validate(g_alloc_addrs[i], current_frame, dtag);
    }
    { bool _w=rblog::is_suppressed(); rblog::suppress(false); rblog::write("TEARDOWN[3] post-dyndelete f%d", current_frame); rblog::suppress(_w); }
    rblog::write("DYN-RESTORE: %ld descriptor ops fired this rollback", dyn_restore::ops_fired_and_reset());
    rblog::write("RW-INLINE: %ld engine-native single-thread drains this rollback (+0xa4 gate)", (long)g_rw_inline_count);
    rblog::write("PF-SERIAL: %ld async-ring serial forces this rollback (+0xB0 gate)", (long)g_pf_serial_count);
    input::stop_inject();
    voice_pool::resume_flush();
    voice_pool::on_rollback(target_frame);  // CANCEL deferred destroys rewound past (voice alive again in the
                                            // reverted timeline => never flush it => no zeroed-vtable worker AV)
    { bool _w=rblog::is_suppressed(); rblog::suppress(false); rblog::write("TEARDOWN[4] post-voicepool f%d", current_frame); rblog::suppress(_w); }

    // (toggle restore removed — see the trajectory-replay note above)
    monitor_shm::set_phase(PHASE_TOGGLE_RESTORE, target_frame + depth - 1);

    // 5. Restore frame cap
    *frame_cap = saved_cap;

    // 9. Dead-vtable unlink — post-resim validation (runs through the registry, PH_POST_RESIM).
    dyn_restore::run("scheduler_bad_vtable_unlink", dyn_restore::PH_POST_RESIM);
    { bool _w=rblog::is_suppressed(); rblog::suppress(false); rblog::write("TEARDOWN[5] post-dead_vtable_unlink f%d", current_frame); rblog::suppress(_w); }
    monitor_shm::set_phase(PHASE_UNLINK_POST_RESIM, target_frame + depth - 1);

    monitor_shm::set_phase(PHASE_ROLLBACK_COMPLETE, g_frame_counter);

    // Clear rollback-active flag in monitor
    if (monitor_shm::g_mon) {
        monitor_shm::g_mon->rollback_active = 0;
    }

    QueryPerformanceCounter(&t_rb_done);
    {
        double pm = (double)t_rb_freq.QuadPart / 1000.0;   // ticks per ms
        rblog::write("ROLLBACK-TIMING: suspend+restore=%.0fms prep=%.0fms resim=%.0fms postresim=%.0fms total=%.0fms | arena_load=%.1f coherent_restore=%.1f belt_arm=%.1f (the variable part = coherent_restore+belt_arm; per-phase instrument)",
            (double)(t_rb_thaw.QuadPart     - t_rb_start.QuadPart)     / pm,
            (double)(t_rb_preresim.QuadPart - t_rb_thaw.QuadPart)      / pm,
            (double)(t_rb_postresim.QuadPart- t_rb_preresim.QuadPart)  / pm,
            (double)(t_rb_done.QuadPart     - t_rb_postresim.QuadPart) / pm,
            (double)(t_rb_done.QuadPart     - t_rb_start.QuadPart)     / pm,
            (double)(t_al1.QuadPart   - t_al0.QuadPart)   / pm,
            (double)(t_cr1.QuadPart   - t_cr0.QuadPart)   / pm,
            (double)(t_belt1.QuadPart - t_belt0.QuadPart) / pm);
        // PERF: freeze-alone vs restore-steps (freeze from t_frz0..t_frz1; restore-steps = t_frz1..t_rb_thaw minus the timed sub-phases)
        rblog::write("ROLLBACK-TIMING2: freeze=%.1fms restore_steps=%.1fms | sound_group=%.1fms rest=%.1fms (sound = preserve passes; rest = edge_census/dead_vtable_unlink/registry/quarantine)",
            (double)(t_frz1.QuadPart - t_frz0.QuadPart) / pm,
            (double)(t_rb_thaw.QuadPart - t_frz1.QuadPart) / pm,
            (double)(t_snd1.QuadPart - t_snd0.QuadPart) / pm,
            (double)((t_rb_thaw.QuadPart - t_frz1.QuadPart) - (t_snd1.QuadPart - t_snd0.QuadPart)) / pm);
        // PERF: per-pass split of the sound_group
        rblog::write("ROLLBACK-TIMING3: sound-pass resource=%.1f audio=%.1f cue=%.1f reconcile=%.1f ms",
            (double)(t_pa.QuadPart - t_snd0.QuadPart) / pm,
            (double)(t_pb.QuadPart - t_pa.QuadPart)   / pm,
            (double)(t_pd.QuadPart - t_pb.QuadPart)   / pm,
            (double)(t_snd1.QuadPart - t_pd.QuadPart) / pm);
    }
    // WMGR FLAG PRESERVE (the deadlock fix): re-assert the live window-focus flags captured at entry, so the main
    // game loop can never be stranded at its Sleep gate by a reverted/skipped activation flag. Unconditional +
    // unsuppressed: if these read 0 here when entry was nonzero, our restore was the gap; if they read entry-value
    // here but the game still hangs, an external WndProc deactivation (focus loss during the freeze) is the cause.
    if (wmgr_live) {
        uint8_t pre38 = *(volatile uint8_t*)(wmgr_live + 0x38), pre2985 = *(volatile uint8_t*)(wmgr_live + 0x2985);
        *(volatile uint8_t*)(wmgr_live + 0x38)   = entry_wm38;
        *(volatile uint8_t*)(wmgr_live + 0x2985) = entry_wm2985;
        bool was = rblog::is_suppressed(); rblog::suppress(false);
        rblog::write("WMGR-PRESERVE: flags @exit were (+0x38=%d +0x2985=%d) -> re-asserted live entry (%d,%d)",
                     pre38, pre2985, entry_wm38, entry_wm2985);
        rblog::suppress(was);
    }
    rblog::write("ROLLBACK: complete");
    // Per-rollback oracle visibility (read-only; once per rollback, not per-frame): the READER-WALK/SHADOW-WALK
    // stats otherwise appear only on idspine's ~600-frame heartbeat, which never re-fires if the game dies shortly
    // after a rollback. One line here closes that gap.
    arena::reader_report();
    InterlockedExchange(&g_frames_since_rollback, 0);  // resim done: discriminator (g_last_source) is now FRESH; ages per forward frame
}

// Recursive scene node tree force-dirty. Walks +0x08 child chain at each level,
// siblings linked via +0x58. Depth-limited to 8.
static int g_fd_tree_count = 0;
// Per-frame node budget = CYCLE GUARD. The depth(8)+sibling(256) caps stop infinite *recursion* but not
// combinatorial explosion: a scene tree that goes CYCLIC post-rollback (+0x08/+0x58 link pointing back into
// the tree) makes the walk explore up to 256^8 paths => the main thread "hangs" (observed: 13s+, tid in
// force_dirty_scene_tree). A legit scene tree is well under 100K nodes; the budget truncates the explosion
// (the engine re-derives the rest during resim anyway). g_fd_tree_count is reset to 0 each save frame.
static const int FD_NODE_BUDGET = 200000;
static volatile LONG g_fd_budget_trips = 0;

static void force_dirty_scene_tree(uintptr_t node, int depth) {
    if (depth > 8 || !node || !arena::is_committed_addr(node)) return;
    if (g_fd_tree_count > FD_NODE_BUDGET) {              // CYCLE GUARD: cyclic scene tree => bail, don't explode
        if (InterlockedIncrement(&g_fd_budget_trips) == 1)
            rblog::write("FORCE-DIRTY: scene-tree node budget (%d) hit — a post-rollback CYCLIC scene tree "
                         "(+0x08/+0x58 loop = real liveness corruption); truncating to avoid the recursion hang", FD_NODE_BUDGET);
        return;
    }

    // Touch this node's pages
    for (uintptr_t off = 0; off < 0x7000; off += 4096) {
        if (arena::is_committed_addr(node + off)) {
            volatile uint8_t* p = (volatile uint8_t*)(node + off);
            *p = *p;
        }
    }
    g_fd_tree_count++;

    // Walk this node's +0x08 child list (next at child+0x58)
    uintptr_t child = *(uintptr_t*)(node + 0x08);
    int cwalk = 0;
    while (child && cwalk < 256 && arena::is_committed_addr(child)) {
        force_dirty_scene_tree(child, depth + 1);
        child = *(uintptr_t*)(child + 0x58);
        cwalk++;
    }
}

// (RSUB tracking globals declared above do_rollback)

// Force-dirty a scheduler entity: its own tree, embedded sub-object tree,
// and external sub-objects. Covers every dispatch path found in the RE.
static void force_dirty_entity(uintptr_t ent) {
    // Standard entity tree (+0x08 children)
    force_dirty_scene_tree(ent, 0);

    // Embedded sub-object tree at +0x3A0
    if (arena::is_committed_addr(ent + 0x3A0)) {
        uintptr_t sub_vt = *(uintptr_t*)(ent + 0x3A0);
        uintptr_t sub_vt_off = sub_vt - addr::g_base;
        if (sub_vt_off >= 0xA00000 && sub_vt_off < 0xC00000) {
            force_dirty_scene_tree(ent + 0x3A0, 0);
        }
    }

    // External sub-objects (+0x700, +0xAA0, +0x1318)
    static const uintptr_t ext_offsets[] = { 0x700, 0xAA0, 0x1318 };
    for (int i = 0; i < 3; i++) {
        uintptr_t ext_off = ext_offsets[i];
        if (arena::is_committed_addr(ent + ext_off)) {
            uintptr_t ext = *(uintptr_t*)(ent + ext_off);
            if (ext && arena::is_committed_addr(ext)) {
                force_dirty_scene_tree(ext, 0);
            }
        }
    }

    // Bone array (+0x538) — dynamic size from bone count
    // Fighters with 100+ bones exceed 7 pages (Doom = 141 bones = 10.7 pages)
    {
        uintptr_t bone_array = *(uintptr_t*)(ent + 0x538);
        if (!g_bone_forcedirty_off && bone_array && arena::is_committed_addr(bone_array)) {
            uint32_t bone_count = *(uint32_t*)(ent + 0x530);
            size_t bone_size = (size_t)bone_count * 0xC0 + 0x10;
            if (bone_size > 0x20000) bone_size = 0x20000;  // 128KB sanity cap
            for (uintptr_t off = 0; off < bone_size; off += 4096) {
                if (arena::is_committed_addr(bone_array + off)) {
                    volatile uint8_t* p = (volatile uint8_t*)(bone_array + off);
                    *p = *p;
                }
            }
        }
    }

    // Bone output buffer (+0x11B0) — dynamic size from bone count
    {
        uintptr_t bone_output = *(uintptr_t*)(ent + 0x11B0);
        if (!g_bone_forcedirty_off && bone_output && arena::is_committed_addr(bone_output)) {
            uint32_t bone_count = *(uint32_t*)(ent + 0x530);
            size_t out_size = (size_t)bone_count * 0x80 + 0x10;
            if (out_size > 0x20000) out_size = 0x20000;
            for (uintptr_t off = 0; off < out_size; off += 4096) {
                if (arena::is_committed_addr(bone_output + off)) {
                    volatile uint8_t* p = (volatile uint8_t*)(bone_output + off);
                    *p = *p;
                }
            }
        }
    }

    // Animation controller (+0x538) render sub-object and geometry pool
    uintptr_t anim_ctrl = *(uintptr_t*)(ent + 0x538);
    if (anim_ctrl && arena::is_arena_addr(anim_ctrl) && arena::is_committed_addr(anim_ctrl)) {
        // Render sub-object at anim_ctrl+0x18
        uintptr_t render_sub = *(uintptr_t*)(anim_ctrl + 0x18);
        if (render_sub && arena::is_arena_addr(render_sub) && arena::is_committed_addr(render_sub)) {
            for (uintptr_t off = 0; off < 0x1000; off += 4096) {
                if (arena::is_committed_addr(render_sub + off)) {
                    volatile uint8_t* p = (volatile uint8_t*)(render_sub + off);
                    *p = *p;
                }
            }
            // DIAG: track this render sub-object
            if (g_rsub_track_count < RSUB_TRACK_MAX) {
                auto& t = g_rsub_track[g_rsub_track_count++];
                t.ent = ent;
                t.anim_ctrl = anim_ctrl;
                t.render_sub = render_sub;
                t.render_sub_vt = *(uintptr_t*)render_sub;
            }
        }
        // Geometry pool at anim_ctrl+0x220
        uintptr_t geom_pool = *(uintptr_t*)(anim_ctrl + 0x220);
        if (geom_pool && arena::is_arena_addr(geom_pool) && arena::is_committed_addr(geom_pool)) {
            for (uintptr_t off = 0; off < 0x2000; off += 4096) {
                if (arena::is_committed_addr(geom_pool + off)) {
                    volatile uint8_t* p = (volatile uint8_t*)(geom_pool + off);
                    *p = *p;
                }
            }
        }
    }
}

// SUBSTRATE COHERENCE (effect side / crash C). Force-dirty an effect's full coherence group at SAVE
// time so the whole group reverts to frame-N atomically: page-revert is object-unaware, so a child's derived
// +0x50 (= (*p>>8)+*(template+0x78), or legitimately 0; deref'd as *(+0x50)+0xf at the consume leaf) must
// revert together with the template body it indexes and the slab it lives in — else +0x50 points into a
// different frame's content. The effect is a 0x250 scheduler-pool unit, vtable 0x140BAE1D0. Returns the
// number of +0x218 children touched. Safe by construction (force_dirty_range writes *p=*p only).
static uint32_t force_dirty_effect_group(uintptr_t ent) {
    uint32_t nchild = 0;

    // (1) effect header (+0x208 child count, +0x210 slab alloc-size, +0x218 list head, +0x220 slab base).
    arena::force_dirty_range(ent, 0x250, 0x250);

    // (2) +0x220 child ARRAY slab — sized by the RECORDED alloc byte-size at +0x210 (n*0x150 under-counts).
    {
        uintptr_t base = *(uintptr_t*)(ent + 0x220);
        if (base && arena::is_committed_addr(base)) {
            uint32_t sz = *(uint32_t*)(ent + 0x210);
            if (sz == 0 || sz > 0x40000) {
                uint16_t n = *(uint16_t*)(ent + 0x208);            // fallback: count * stride
                sz = (uint32_t)n * 0x150;
            }
            arena::force_dirty_range(base, sz, 0x40000);
        }
    }

    // (3) the template/EmDef BODY at +0x108 — the substrate child+0x50 derives from. Force-dirty its
    // header+curve region so it reverts atomically with the children that index it (committed-walk bounded).
    {
        uintptr_t tmpl = *(uintptr_t*)(ent + 0x108);
        if (tmpl && arena::is_committed_addr(tmpl)) {
            arena::force_dirty_range(tmpl, 0x4000, 0x40000);
        }
    }

    // (4) the +0x218 child linked list (head validated by child+0x10 == ent, as byid does). Each child body
    // covers +0x10 owner / +0x18 next / +0x28 slab-interior / +0x40,+0x50 derived / +0x108 template-copy.
    // Plus each child's +0x130 sub-buffer (a separate alloc with interior pointers), sized by +0x128.
    uintptr_t head = *(uintptr_t*)(ent + 0x218);
    if (head && arena::is_committed_addr(head) && *(uintptr_t*)(head + 0x10) == ent) {
        uintptr_t child = head;
        for (int bi = 0; bi < 512 && child && arena::is_committed_addr(child); bi++) {
            arena::force_dirty_range(child, 0x280, 0x280);
            uintptr_t sub = *(uintptr_t*)(child + 0x130);
            if (sub && arena::is_committed_addr(sub)) {
                uint32_t subsz = *(uint32_t*)(child + 0x128);
                arena::force_dirty_range(sub, subsz ? subsz : 0x1000, 0x4000);
            }
            nchild++;
            uintptr_t nx = *(uintptr_t*)(child + 0x18);
            if (nx == child) break;                                // self-loop guard
            child = nx;
        }
    }
    return nchild;
}

// ═══════════════════════════════════════════════════════════════════════════════════════════════════════════
// DRIFT-WATCHER (count-drift): is the recycler tally-vs-pile drift ours (the save system) or the base game's?
// Read-only, ENGINE-INDEPENDENT per-frame walk of every scalable allocator's per-class free-list, comparing the
// chain length (walked) to the manager's count field (mgr+0x68). Reports the first time each manager's mismatch
// PERSISTS for DRIFT_PERSIST consecutive frames — the real drift never self-heals, so persistence filters out
// transient mid-mutation reads (a worker thread caught between chain-edit and count-edit). Holds NO lock (so the
// watcher barely perturbs the allocator); a torn read just bails that frame (counts as "no read", not a drift).
// The DECISIVE OUTPUT: a DRIFT-WATCH event tagged engine_on=0 means the base game drifts on its OWN (our save is
// innocent; POOL-UNIT's faithful round-trip is the ceiling). Events only ever tagged engine_on=1 mean OUR save-
// system induces it (fix = narrow the snapshot at the source). Toggle: Numpad minus. Default OFF.
static volatile long g_drift_watch = 0;
static constexpr int DRIFT_PERSIST = 5;
static int  g_dw_streak[MAX_ALLOCS][8] = {};
static bool g_dw_logged[MAX_ALLOCS][8] = {};
static volatile long g_dw_on_hits = 0, g_dw_off_hits = 0; static long g_dw_ticks = 0;

// Safe read-only chain length via node+0x20; bail (-1) on any non-committed link (torn/mid-mutation read). Bounded.
static int dw_chain_len(uintptr_t head, uint32_t count) {
    uintptr_t node = head; int walked = 0; uint32_t limit = count + 64;   // slack catches the drift; hard cap breaks a cycle
    while (node && (uint32_t)walked <= limit) {
        if (node < 0x10000 || !arena::is_committed_addr(node) || !arena::is_committed_addr(node + 0x40)) return -1;
        node = *(uintptr_t*)(node + 0x20); walked++;
    }
    return walked;
}
static void drift_watch_reset() { memset(g_dw_streak, 0, sizeof g_dw_streak); memset(g_dw_logged, 0, sizeof g_dw_logged); g_dw_on_hits = 0; g_dw_off_hits = 0; }
static void drift_watch_tick() {
    if (!g_drift_watch) return;
    if (!g_allocs_discovered) discover_allocators();     // engine-OFF runs never hit the save path that discovers — do it here
    for (int i = 0; i < g_alloc_count; i++) {
        uintptr_t ctrl = g_alloc_addrs[i];
        int ncls = *(volatile int*)(ctrl + 0x648); if (ncls < 1 || ncls > 8) ncls = 8;
        for (int k = 0; k < ncls; k++) {
            uintptr_t mgr = ctrl + 0xd8 + (uintptr_t)k * 0xa8;
            uint32_t cnt = *(uint32_t*)(mgr + 0x68);
            int walked = dw_chain_len(*(uintptr_t*)(mgr + 0x58), cnt);
            if (walked < 0) { g_dw_streak[i][k] = 0; continue; }          // couldn't read cleanly => not counted
            if ((uint32_t)walked == cnt) { g_dw_streak[i][k] = 0; continue; }
            if (++g_dw_streak[i][k] >= DRIFT_PERSIST && !g_dw_logged[i][k]) {
                g_dw_logged[i][k] = true;
                bool eng = g_engine_on;
                if (eng) _InterlockedIncrement(&g_dw_on_hits); else _InterlockedIncrement(&g_dw_off_hits);
                const char* name = (const char*)(ctrl + 0x21);
                bool w = rblog::is_suppressed(); rblog::suppress(false);
                rblog::write("DRIFT-WATCH: a%d \"%s\"/mgr%d PERSISTENT drift walked=%d count=%u (%d frames) | engine_on=%d frames_since_rb=%ld any_rb=%d "
                             "=> engine_on=0 => BASE GAME drifts alone (save innocent, POOL-UNIT ceiling); engine_on=1-ONLY => OUR save induces it (narrow the snapshot)",
                             i, name ? name : "?", k, walked, cnt, DRIFT_PERSIST, (int)eng, (long)g_frames_since_rollback, (int)g_any_rollback);
                rblog::suppress(w);
            }
        }
    }
    if ((++g_dw_ticks % 600) == 0)
        rblog::write("DRIFT-WATCH[summary]: engine_on_hits=%ld engine_off_hits=%ld (off>0 => base-game-latent; on-only => mod-induced) | engine_on=%d",
                     (long)g_dw_on_hits, (long)g_dw_off_hits, (int)g_engine_on);
}

static void hk_main_proc(int64_t param_1) {
    SlowFrameTimer _sft;   // outlier-only: logs this frame only if it exceeds g_slowframe_ms (catches the chug window)
    if (!g_main_proc_tid) g_main_proc_tid = GetCurrentThreadId();   // the real main thread
    // MAINPROC-ALIEN probe: a crash stack showed MAIN_PROC's body ON the WINDOW THREAD — the engine's window
    // thread appears to pump frames itself when the main loop stalls (our ~180ms rollback). If so, that pump
    // (finalizer + drain + subsystem tick on another thread, mid-resim, across the epoch seam) is the root of
    // the window-thread executor crashes — and it means this frame-driver hook runs cross-thread (saves/counters
    // racing). Log + real backtrace, then BAIL to orig without driving the frame (the driver must never run twice
    // concurrently).
    if (GetCurrentThreadId() != g_main_proc_tid) {
        static volatile LONG n_alien = 0;
        LONG n = InterlockedIncrement(&n_alien);
        if (n <= 6) {
            void* frames[24] = {};
            USHORT got = CaptureStackBackTrace(1, 24, frames, nullptr);
            uintptr_t mod = (uintptr_t)GetModuleHandleA("umvc3.exe");
            char line[512]; int o = 0;
            for (USHORT i = 0; i < got && o < 440; i++) {
                uintptr_t f = (uintptr_t)frames[i];
                if (mod && f >= mod && f < mod + 0xA00000)
                    o += snprintf(line + o, sizeof(line) - o, " 0x%llX", (unsigned long long)(f - mod + 0x140000000ULL));
                else
                    o += snprintf(line + o, sizeof(line) - o, " [ext]");
            }
            bool was = rblog::is_suppressed(); rblog::suppress(false);
            rblog::write("MAINPROC-ALIEN: tid=%u entered MAIN_PROC off-main (resim=%d)! chain:%s",
                         GetCurrentThreadId(), (int)g_resim_active, line);
            rblog::suppress(was);
        }
        {   // PROF-NP: normal-play (engine-off) frame timer — times the game frame INCLUDING all our in-frame
            // hooks (scene_tree/idspine/witness). Confirms whether normal-play lag is our overhead. Logs avg/120.
            hang_detector::heartbeat();   // pulse the watchdog in normal play too — otherwise engine-off play falsely
                                          // trips HANG-DETECTED (self-inflicted stutter + log spam).
            LARGE_INTEGER _npa,_npb; QueryPerformanceCounter(&_npa);
            orig_main_proc(param_1);   // pass through UNDRIVEN — no saves, no counters, no rollback checks
            QueryPerformanceCounter(&_npb);
            if (g_prof_on) {
                static double s_np_acc = 0; static int s_np_n = 0;
                s_np_acc += prof_ms(_npa,_npb);
                if (++s_np_n >= 30) {   // log fast even at low fps
                    rblog::write("PROF-NP[engine-off avg ms/frame over %d]: game_frame=%.2f (incl. our in-frame hooks)", s_np_n, s_np_acc / s_np_n);
                    s_np_acc = 0; s_np_n = 0;
                }
            }
        }
        return;
    }
    hang_detector::heartbeat();   // per-frame liveness pulse for the silent-hang watchdog
    net::session_pump();          // lockstep netcode: drain packets + connection state machine + route remote inputs into the lockstep queue
    net_charsel::flow_probe_tick();   // game-flow discovery — runs solo, no session required
    net_charsel::on_frame();      // lockstep netcode: char-select coordination — force device_map={0,1} in menus/CS + arm the remap at CS-entry (solves "both are P1"). No-op unless connected.
    // No boot stall: freezing the main loop at boot skips the game's staged in-main-loop subsystem construction
    // → null-vtable tick crash (0x1402595BD). You cannot freeze the main loop without also freezing init. Sync
    // happens at char-select (loose remap) + match-start (hard lockstep), never at boot.
    // LOCKSTEP STALL: hard frame-lock only in the FIGHT (game-flow phase==5). Menus + char-select + match-load run
    // a LOOSE relay (host drives the menus; teams converge) — never a multi-second main-thread freeze, and never
    // stalling through the match-load construction (which would repeat the boot-crash class).
    // BOUNDED STALL — an unbounded stall is a guaranteed deadlock, as a live 2-player log showed: P1 entered the
    // fight (in_fight=1) while P2 was still in the menus (in_fight=0, 11s later). P1 then waited for fight inputs P2
    // would never send, spinning ~200k times/s (a full core) and never advancing again. P2 meanwhile never stalls,
    // because its in_fight is false. So any divergence — from any cause — permanently freezes whichever peer got
    // ahead, while the other runs on none the wiser.
    // A stall is only meaningful while the peer might still deliver. Past that, freezing forever is strictly worse than
    // continuing on the repeat-last-input prediction we already keep: continuing may desync (loud, visible, and the
    // digest work will catch it), whereas freezing is an unrecoverable hang that looks like a crash to the player.
    // Also Sleep(1) instead of spinning — a stalled frame should cost a millisecond, not a core.
    static int s_stall_run = 0;
    constexpr int STALL_MAX = 180;                            // 3s at 60fps — far beyond any real jitter/RTT
    // PREDICTION BARRIER (GGPO parity) — the hard bound, and it applies everywhere, not just in the fight. GGPO
    // refuses local input once the local frame runs `_max_prediction_frames` past confirmed ("Rejecting input from
    // emulator: reached prediction barrier"), so a peer physically cannot outrun the input it has. A fight-only gate
    // lets a peer sitting in MENUS gallop 169 frames (2.8s) ahead and predict on ~100% of frames. It also protects
    // the input ring: entries are keyed
    // f % 256 and validated by frame number, so beyond 256 frames of drift every lookup misses and confirmed input
    // stops arriving altogether. Bounding prediction depth makes that state unreachable by construction.
    // SERVICE A NETWORK-REQUESTED ROLLBACK — corrected input arrived for a frame we mis-simulated. Done here, at
    // the top of the frame, because a rollback must never run re-entrantly from inside the datagram handler that
    // discovered it. Gated on the engine being armed, which it only is during a FIGHT.
    if (g_engine_on) {
        const LONG want = InterlockedExchange(&g_rb_request, -1);
        if (want >= 0 && want < g_frame_counter) {
            const int depth = g_frame_counter - (int)want;
            if (depth > 0 && depth <= MAX_ROLLBACK_DEPTH) {
                rblog::write("NET-ROLLBACK(%s): corrected input for engine frame %ld (now %d, depth %d) — rolling back "
                             "and re-simulating with the input that actually arrived.",
                             role::name(), want, g_frame_counter, depth);
                do_rollback(param_1, g_frame_counter, (int)want);
            } else if (depth > MAX_ROLLBACK_DEPTH) {
                static long s_deep = 0;
                if (++s_deep <= 4 || (s_deep % 100) == 0)
                    rblog::write("NET-ROLLBACK(%s): SKIPPED depth %d (cap %d) — too far back to re-simulate inside a "
                                 "frame budget; the divergence stands. count=%ld",
                                 role::name(), depth, MAX_ROLLBACK_DEPTH, s_deep);
            }
        }
    }

    constexpr int MAX_PREDICTION = 8;                         // GGPO's default; ~133ms of speculation at 60fps

    // TIMESYNC GIVE-BACK — slow down before the wall, not at it
    // The barrier alone is a wall: the faster peer sprints into it and then burns a Sleep(1) every frame holding
    // position, which is what produced 5903-12803 stalls on one side while the other had 0. Worse, sitting at the
    // barrier means running at maximum prediction depth permanently — and depth is what makes taps feel broken:
    // prediction is repeat-last, so a held button predicts fine forever while a TAP is a transition that invalidates
    // the entire predicted run. Measured directly: depth 2 -> 1.9% mispredict, depth 7 -> 30.8%, depth 11 -> 99.5%.
    // TimeSync makes the faster peer hand back a few frames voluntarily so the pair stays close and depth stays ~1-2.
    // The decision is mutual: both peers exchange their own frame advantage and both evaluate the same comparison, so
    // exactly one concludes it is ahead. Neither is the authority and neither can make the other wait.
    // Two hazards this handles:
    //
    // (1) FEEDBACK STARVATION. The give-back below returns early, which skips orig_main_proc — and the game's input
    // dispatch lives inside it, which is where net_input::on_frame_begin() feeds the TimeSync rings. Without a
    // cooldown the averages freeze at the values that said "you are ahead", the recommendation never changes, and
    // the hold re-arms forever: the sim advances a handful of frames per second. Never gate a frame on a
    // measurement that only updates when the frame runs. The cooldown below breaks that loop — after a correction
    // we do not look again until the sim has genuinely advanced.
    //
    // (2) RATE LIMIT. GGPO recommends at most once every RECOMMENDATION_INTERVAL (240 frames / ~4s) — the
    // correction is a nudge to be applied and then left alone while its effect plays out; evaluating every tick
    // re-applies even a correct recommendation continuously instead of once.
    //
    // The hold also sleeps a real frame's worth (~16ms), not 1ms: "give back N frames" has to cost N frames of TIME
    // or it gives back nothing and the drift never actually closes.
    // 240 (GGPO's value) assumes a stable direct link. On this relay the drift re-accumulates in well under a second,
    // so one nudge per 4s left the peers 6 frames apart indefinitely — enough to make the input delay break even and
    // predict every tap away. 60 frames (~1s) still leaves each correction time to take effect before the next.
    static constexpr int TS_RECOMMEND_INTERVAL = 60;
    static int s_ts_hold = 0;
    static int s_ts_next_frame = 0;
    if (s_ts_hold == 0 && net_input::active() && net_input::net_frame() >= s_ts_next_frame) {
        const int give = net_input::recommend_wait();
        if (give > 0) {
            s_ts_hold = give;
            s_ts_next_frame = net_input::net_frame() + TS_RECOMMEND_INTERVAL;
            rblog::write("NET-TIMESYNC(%s): giving back %d frame(s) at net-frame %d — we are the faster peer. Next "
                         "correction not before net-frame %d (one nudge, then let it settle).",
                         role::name(), give, net_input::net_frame(), s_ts_next_frame);
        }
    }
    if (s_ts_hold > 0) {
        s_ts_hold--;
        net_input::pump_stalled();                            // stay audible: a silent peer is a deadlocked peer
        Sleep(16);                                            // one frame of real time, not 1ms
        net_input::note_stall();
        return;                                               // give this frame back; do not advance the sim
    }

    const bool at_barrier  = net_input::active() && net_input::frames_ahead() >= MAX_PREDICTION;
    const bool fight_wait  = net_input::active() && net_charsel::in_fight() && !net_input::remote_ready();
    if ((at_barrier || fight_wait) && s_stall_run < STALL_MAX) {
        if (++s_stall_run == 1)
            rblog::write("NET(%s): hold BEGIN @net-frame %d — %s (ahead of confirmed by %d)", role::name(),
                         net_input::net_frame(),
                         at_barrier ? "PREDICTION BARRIER: refusing to outrun confirmed input" : "in-fight: waiting on this frame",
                         net_input::frames_ahead());
        if (s_stall_run == STALL_MAX)
            rblog::write("NET(%s): STALL ABANDONED after %d frames — the peer is not delivering input for this frame. "
                         "It is almost certainly NOT in the fight (menu/state divergence), so waiting can never succeed. "
                         "Continuing on predicted input rather than hanging forever.", role::name(), STALL_MAX);
        net_input::pump_stalled();                            // keep sending while we wait — the peer very likely
                                                              // needs OUR input to clear ITS own stall; going quiet
                                                              // here is what turns two stalls into a deadlock.
        Sleep(1);                                             // never spin: a stalled frame costs 1ms, not a whole core
        net_input::note_stall();                              // freeze this tick (skip orig_main_proc + all frame work), retry next tick.
        return;                                               // session_pump already ran; the awaited datagram may arrive before the next tick.
    }
    // the peer delivered (or we gave up) — clear the run so the next genuine wait gets a full fresh budget
    if (s_stall_run) {
        if (s_stall_run < STALL_MAX)
            rblog::write("NET(%s): lockstep stall END after %d frame(s) — peer input arrived.", role::name(), s_stall_run);
        s_stall_run = 0;
    }
    { static int s_nrep = 0; if ((++s_nrep % 180) == 0) {     // netplay telemetry (engine-OFF safe): lockstep runs without F5, so report here every ~3s
        net::session_report(); net_input::report(); net_sync::report(); net_charsel::report(); } }
    xray_mem::on_frame();         // byte-tracer capture-window advance + auto-disarm (no-op unless F3-armed)
    idspine::on_frame();          // birth-stamp spine: throttled stats line ~every 10s (not per-frame)
    { static int rdt=0; if((++rdt % 600)==0) rdspine::report(); }   // Default-allocator SHADOW stats ~every 10s
    quarantine::on_frame(g_frame_counter);   // P4: flush past-horizon held blocks (self-gates to forward play only)
    material_guard::sweep();                 // husk-SWEEP: null dangling edges to dead-held objects (engine-wide class, per-frame)
    field_target_recorder::on_frame();  // pointer-provenance recorder (edge-discriminator): NUMPAD9-armed, sampled, no-op when off
    if (byid::is_enabled()) { static int s_by = 0; if ((++s_by % 600) == 0) byid::report_and_reset(); }  // a-vs-c carrier census ~every 10s (so the count surfaces even if the long run crashes before disarm)
    if (g_slowframe) { static int s_gr = 0; if ((++s_gr % 600) == 0) arena::log_growth(); }  // frontier meter — gated OFF by default (Numpad7 arms)
    // Hotkey check
    // ENGINE SCOPED TO the active MATCH: arm the rollback
    // engine only during in-match gameplay (sBattleSetting game-flow phase==5 "FIGHT"), disarm otherwise. This keeps
    // quarantine defer-all OFF during every load/teardown (phases 0/1 load, 8 intro, 4 KO) so the fixed MtScalable
    // reserve can no longer starve during the resource-decompression churn (the null-memcpy crash: our
    // defer-all blocked slab recycling through the load). The load runs engine-OFF, the condition the long runs validated.
    // Baseline is (re)captured per match on a settled frame; capture_baseline() frees+re-snapshots cleanly. Two
    // cheap derefs/frame; a torn aligned dword just re-evaluates next frame (read-only gate, no lock).
    {
        // KILL SWITCH: rollback.off — drop a file named `rollback.off` next to the exe and the engine never
        // auto-arms (no defer-all, no per-frame save, no resim) = a vanilla-behaviour run for recording/demos.
        // Delete the file to restore normal behaviour. Read once at first use (restart the game to flip it), so this
        // costs nothing per frame. Deliberately gates only the ARM EDGE — everything already running is untouched.
        static const bool s_autoarm_off = [] {
            char p[MAX_PATH]; GetModuleFileNameA(NULL, p, MAX_PATH);
            char* s = strrchr(p, '\\'); if (s) s[1] = 0; else p[0] = 0;
            strncat(p, "rollback.off", MAX_PATH - strlen(p) - 1);
            bool off = GetFileAttributesA(p) != INVALID_FILE_ATTRIBUTES;
            if (off) rblog::write("ENGINE AUTO-ARM DISABLED: rollback.off present — the rollback engine will NOT arm this run (vanilla behaviour). Delete the file to re-enable.");
            return off;
        }();

        uintptr_t bs = *(uintptr_t*)addr::resolve(0x140D50E58);              // sBattleSetting/game-flow director (FUN_140004700)
        int32_t phase = (bs && arena::is_committed_addr(bs + 0x34C)) ? *(int32_t*)(bs + 0x34C) : -1;
        bool fight = (phase == 5);                                            // 5 = active round; strictly after load(0/1)+intro(8)
        static int s_fight_run = 0;
        s_fight_run = fight ? (s_fight_run + 1) : 0;
        bool perf_iso = arena::no_writewatch() || arena::no_hooks() || arena::no_heapredirect();

        // One switch for auto-arm and auto-disarm. They are the same feature: something other than the player
        // deciding when the engine runs, keyed on game-flow phase. That field is not a reliable signal — it reads
        // 5 while sitting in CHARACTER SELECT during solo play, and 0 while fully inside a netplay match. Unattended
        // arming on it captured a baseline in a menu and produced a 1756ms frame; unattended disarming on it tore
        // the engine down ~100ms after every manual arm. With `autoarm.on` absent, nothing touches the engine
        // except F5 — which is the point of a manual trigger.
        static const bool s_autoarm_on = [] {
            char pp[MAX_PATH]; GetModuleFileNameA(NULL, pp, MAX_PATH);
            char* sl = strrchr(pp, '\\'); if (sl) sl[1] = 0; else pp[0] = 0;
            strncat(pp, "autoarm.on", MAX_PATH - strlen(pp) - 1);
            const bool on = GetFileAttributesA(pp) != INVALID_FILE_ATTRIBUTES;
            rblog::write("ENGINE: phase-based auto arm/disarm %s. %s",
                         on ? "ENABLED (autoarm.on present)" : "DISABLED (default)",
                         on ? "Phase 5 arms it — including in CHARACTER SELECT."
                            : "F5 is the ONLY thing that arms or disarms the engine.");
            return on;
        }();

        if (!g_engine_on) {
            // ARM edge (only when auto-arm is explicitly enabled).
            if (fight && s_fight_run >= NET_ENGINE_SETTLE_FRAMES && !perf_iso && !s_autoarm_off && s_autoarm_on) {
                if (arena::capture_baseline()) {                             // per-match: frees old + re-snapshots the settled arena
                    g_engine_on = true;
                    if (monitor_shm::g_mon) {
                        monitor_shm::g_mon->arena_base = (uint64_t)arena::base();
                        monitor_shm::g_mon->arena_size = (uint64_t)(arena::end() - arena::base());
                    }
                    if (!g_horizon_clock_armed) { g_frame_counter = 0; g_horizon_clock_armed = true; }  // zero once (monotonic horizon)
                    gp_crc::set_off(true);
                    g_prof_on = 1;
                    g_last_auto_frame = g_frame_counter;
                    rblog::write("ENGINE ARMED (match phase==5, settled %d frames): baseline captured — defer-all live for GAMEPLAY ONLY. [gp_crc OFF (F4), profiler ON]", s_fight_run);
                }
            }
        } else {
            // DISARM edge: left FIGHT -> KO(4)/results/menu/next-load. Drain deferred slabs before this frame's
            // teardown/load runs so recycling resumes immediately (defer-all inert while engine off). Only with
            // `autoarm.on` (see the arm edge above for why the phase field cannot be trusted unattended).
            if (!fight && s_autoarm_on) {
                g_engine_on = false;
                quarantine::flush_all();
                voice_pool::flush_all();
                rblog::write("ENGINE DISARMED (phase=%d != FIGHT, autoarm.on): quarantine + voices drained.", phase);
            }
        }
    }
    // F5: manual engine arm/disarm — the counterpart to rollback.off (which disables only the auto-arm, so the
    // engine stays out of the way for recording / vanilla-feel play until asked for). F5 PROPOSES A COLLECTIVE ARM:
    // one press arms both peers on the same net-frame, and a second press proposes a collective disarm. A netplay
    // match where one side runs the rollback engine and the other does not would diverge in how each handles a late
    // packet, and letting either player switch it off mid-match strands the other. There is no phase gate on a
    // manual arm (see below); capturing a baseline during a load/menu can still starve the reserve, so press it in
    // an actual round.
    if (GetAsyncKeyState(VK_F5) & 1) {
        if (g_engine_on) {
            net_engine_arm::propose_disarm();   // collective: drops it on both sides
        } else {
            // No phase gate on a manual arm. The phase==5 check exists for UNATTENDED auto-arming; applied to F5 it
            // is wrong, because +0x34C is not the signal it appears to be. Measured: solo arcade goes 0->5 at
            // CHARACTER SELECT and stays 5 through gameplay, while an online session sat at 0 the whole match
            // INCLUDING the character intro — so the same field reads 5 in a menu and 0 in a real fight depending on
            // mode. Gating on it refused every legitimate arm in netplay. F5 is a deliberate human action at a moment
            // only the player can identify. Trust it, and record the phase so the field's real meaning keeps
            // accumulating evidence instead of blocking the match.
            uintptr_t bsF = *(uintptr_t*)addr::resolve(0x140D50E58);
            int32_t phF = (bsF && arena::is_committed_addr(bsF + 0x34C)) ? *(int32_t*)(bsF + 0x34C) : -1;
            rblog::write("F5: arming by request — game-flow phase=%d (recorded, NOT gated on). Arming inside a load or "
                         "menu can still starve the reserve; press this in an actual round.", phF);
            net_engine_arm::propose();
        }
    }

    // Perform a requested disarm, using the same cleanup the phase edge uses — dropping the engine without draining
    // quarantine/voices leaves defer-all inert but the deferred slabs stranded, which is a slow leak, not a no-op.
    if (net_engine_arm::consume_disarm() && g_engine_on) {
        g_engine_on = false;
        quarantine::flush_all();
        voice_pool::flush_all();
        rblog::write("ENGINE DISARMED (F5 / peer request): quarantine + voices drained — defer-all OFF. F5 re-arms.");
    }

    // Perform the arm on the agreed frame (netplay), or immediately when there is no session (solo F5).
    if (!g_engine_on) {
        const bool net_says_now = net_engine_arm::tick_should_arm();
        const bool solo_f5      = !net::session_running() && net_engine_arm::pending();
        if (net_says_now || solo_f5) {
            uintptr_t bs5 = *(uintptr_t*)addr::resolve(0x140D50E58);
            int32_t ph5 = (bs5 && arena::is_committed_addr(bs5 + 0x34C)) ? *(int32_t*)(bs5 + 0x34C) : -1;
            rblog::write("ENGINE-ARM: performing the agreed arm (phase=%d, recorded not gated).", ph5);
            if (arena::capture_baseline()) {
                g_engine_on = true;
                if (monitor_shm::g_mon) {
                    monitor_shm::g_mon->arena_base = (uint64_t)arena::base();
                    monitor_shm::g_mon->arena_size = (uint64_t)(arena::end() - arena::base());
                }
                if (!g_horizon_clock_armed) { g_frame_counter = 0; g_horizon_clock_armed = true; }   // zero once
                gp_crc::set_off(true);
                g_prof_on = 1;
                g_last_auto_frame = g_frame_counter;
                rblog::write("ENGINE ARMED (F5 manual): baseline captured — defer-all live. Press F5 again to disarm.");
                // Drop the input delay now that rollback can pay for it. The delay is fixed at epoch activation and
                // cannot be changed mid-stream safely: already-scheduled frames would be re-sent with different
                // content, and the receiver SKIPS frames it already holds, so the two sides would disagree forever.
                // A fresh epoch restarts the timeline cleanly on both peers at the new delay. This lands during the
                // character intro — dead animation time — which is exactly why arming there is the right moment.
                net_input::propose_epoch(2, /*force=*/true);   // a delay change is not a duplicate trigger
            } else {
                rblog::write("F5: arm FAILED — capture_baseline() refused (arena not ready). Try again a few frames in.");
            }
        }
        // No else-disarm here: "engine is OFF and no arm is pending" is the ordinary idle case, so a disarm hung
        // off it would run every frame. Disarming is owned solely by consume_disarm().
    }
    // F7: one-shot D3D9 bone texture scan (diagnostic, no rollback needed)
    if (GetAsyncKeyState(VK_F7) & 1) {
        rblog::write("D3D9-SCAN: triggered by F7");
        uintptr_t sunit = *(uintptr_t*)addr::resolve(0x140E17698);
        if (sunit) {
            int hits = 0;
            for (int line = 0; line < 128; line++) {
                uintptr_t ent = *(uintptr_t*)(sunit + 0x58 + (uintptr_t)line * 0x30);
                int walk = 0;
                while (ent && walk < 512 && arena::is_committed_addr(ent)) {
                    uintptr_t tex0 = *(uintptr_t*)(ent + 0x12A0);
                    if (tex0) {
                        rblog::write("D3D9-SCAN: line=%d ent=0x%llX vt=0x%llX +0x12A0=0x%llX +0x12A8=0x%llX +0x12B0=0x%llX +0x12B8=0x%llX",
                            line, (unsigned long long)ent,
                            (unsigned long long)(*(uintptr_t*)ent - addr::g_base + 0x140000000ULL),
                            (unsigned long long)tex0,
                            (unsigned long long)*(uintptr_t*)(ent + 0x12A8),
                            (unsigned long long)*(uintptr_t*)(ent + 0x12B0),
                            (unsigned long long)*(uintptr_t*)(ent + 0x12B8));
                        hits++;
                    }
                    ent = *(uintptr_t*)(ent + 0x20);
                    walk++;
                }
            }
            rblog::write("D3D9-SCAN: %d entities with bone textures", hits);
        }
        effect_probe::report();   // P4: dump the consume-null tally on demand (latent-vanilla verdict for Crash C)
    }

    // NUMPAD / = EDGE-BREAK detector (read-only). Diffs every reverted page live-vs-restored and reports each
    // cross-boundary edge the revert broke. Unlike edge_census this is not vtable-gated, not sampled and not
    // allocator-scoped — it sees every reverted byte, so it names the true edge set instead of the probe's shadow.
    if (GetAsyncKeyState(VK_DIVIDE) & 1) {
        edge_break::set_enabled(!edge_break::enabled());
    }

    // NUMPAD * = periodic auto-rollback toggle: one rollback every AUTO_INTERVAL frames at depth g_rollback_depth,
    // so rollback runs continuously without touching the keyboard (demo footage, long runs). The fire site still
    // requires the engine ARMED (F5 / auto-arm) and netplay inactive, so this is safe to arm at any time.
    if (GetAsyncKeyState(VK_MULTIPLY) & 1) {
        g_auto_rollback = !g_auto_rollback;
        g_last_auto_frame = g_frame_counter;      // start the interval from now (don't fire instantly on toggle)
        rblog::write("AUTO-ROLLBACK %s (Numpad *): every %d frames (~%.1fs) at depth %d | engine_armed=%d%s",
                     g_auto_rollback ? "ON" : "OFF", AUTO_INTERVAL, AUTO_INTERVAL / 60.0, g_rollback_depth,
                     (int)g_engine_on,
                     g_engine_on ? "" : " — NOTE: engine is OFF, arm it with F5 (in a round) before this does anything");
    }

    // F6 = manual single rollback: fires one rollback now (depth g_rollback_depth) — the test tool (e.g. on a
    // menu, to probe menu determinism). Numpad * is the periodic variant.
    if (GetAsyncKeyState(VK_F6) & 1) {
        if (g_engine_on && arena::has_baseline() && !net_input::active()) {
            int target = g_frame_counter - g_rollback_depth;
            if (target >= 0) {
                rblog::write("F6: MANUAL rollback %d -> %d (depth %d)", g_frame_counter, target, g_rollback_depth);
                do_rollback(param_1, g_frame_counter, target);
                g_last_auto_frame = g_frame_counter;
            } else {
                rblog::write("F6: manual rollback skipped — only %d frames since arm (need >= %d).", g_frame_counter, g_rollback_depth);
            }
        } else {
            rblog::write("F6: manual rollback skipped (engine=%d baseline=%d lockstep=%d).", (int)g_engine_on, (int)arena::has_baseline(), (int)net_input::active());
        }
    }
    if (GetAsyncKeyState(VK_F8) & 1) {
        g_alloc_rederive = !g_alloc_rederive;
        rblog::write("ALLOC-REDERIVE %s — structure-aware allocator restore: re-derive free-list counts post-load (A/B test of the count-mismatch-seeds-the-cycle hypothesis)", g_alloc_rederive ? "ON" : "OFF");
    }
    if (GetAsyncKeyState(VK_F1) & 1) {
        // OWNED-HEAP live A/B: flip the workaround set only. restore_allocators (exact, atomic — the coherent
        // restore) stays ON both ways; defer_all ON (P3).
        bool on = !arena::owned_heap_active();
        set_patch_pile_enabled(!on);
        arena::set_owned_heap_active(on);
        rblog::write("OWNED-HEAP (F1) %s — %s", on ? "ON" : "OFF",
                     on ? "workaround set OFF (coherent restore stands alone)" : "legacy full patch pile");
    }
    if (GetAsyncKeyState(VK_F3) & 1) {
        // byte-xray sweep: each F3 press arms the next capture mode (CORE then EFFECTS, cycling) for a 12-frame
        // window covering everything a drawn frame reads in-arena, then auto-disarms.
        xray_mem::arm(12);
    }
    if (GetAsyncKeyState(VK_F11) & 1) {
        // CONTENT-AWARE PAGE toggle: ON = EDGE-sever + REBUILD-leave-live corrections layered on arena::load; OFF = plain.
        // A/B vs the page-revert baseline; gp_crc scores it + crash behavior names any miss.
        page_free::toggle();
        page_free::report();   // surface cumulative EDGE/REBUILD counts (outside the freeze/thaw suppression window)
    }
    if (GetAsyncKeyState(VK_NUMPAD8) & 1) {
        g_netplay_lean = !g_netplay_lean;
        arena::set_lean(g_netplay_lean != 0);
        rblog::write("NETPLAY-LEAN %s (Numpad8) — rollback-path detectors %s (checks/oracles/census/RESIM-logs); "
                     "ALL mechanisms (units/keep-live/repairs/guards/preserves) unchanged. Compare ROLLBACK-TIMING.",
                     g_netplay_lean ? "ON" : "OFF", g_netplay_lean ? "STRIPPED" : "active");
    }
    if (GetAsyncKeyState(VK_F9) & 1) {
        g_bone_forcedirty_off = !g_bone_forcedirty_off;
        rblog::write("BONE-FORCEDIRTY %s — A/B the bone-block force-dirty necessity (OFF = skip bone-array/output force-dirty; watch FIGHTER-DIVERGED + bone crashes)", g_bone_forcedirty_off ? "OFF (skipping)" : "ON (default)");
    }
    if (GetAsyncKeyState(VK_F4) & 1) {
        gp_crc::set_off(!gp_crc::is_off());
        rblog::write("GP-CRC ORACLE %s (F4 perf toggle; keep ON to validate the content-aware page)", gp_crc::is_off() ? "OFF (smoother)" : "ON");
    }
    if (GetAsyncKeyState(VK_F12) & 1) {
        byid::set_enabled(!byid::is_enabled());   // by-identity SHADOW carrier classifier (effect+0x218); the spin-breaker measurement
    }
    if (GetAsyncKeyState(VK_F2) & 1) {
        // Effect authoritative splice (the 0x14080D44D fix) — re-thread the reverted +0x218 by birth-stamp.
        // Requires byid ON (F12). Flip ON only after an F12 SHADOW run confirms STAMP-SUB dominates the carrier.
        byid::set_authoritative_effect(!byid::is_authoritative_effect());
    }
    if (GetAsyncKeyState(VK_F10) & 1) {
        g_resim_singlethread = !g_resim_singlethread;
        rblog::write("RESIM-THREADING %s — %s", g_resim_singlethread ? "SINGLE (default, deterministic, SLOW)" : "MULTI (FAST replay)",
            g_resim_singlethread ? "clean allocator validation" : "FAST iteration — workers race the allocator, may crash/diverge; switch back to ST (F10) for clean validation");
    }
    if (GetAsyncKeyState(VK_NUMPAD1) & 1) {
        g_sc_effect = !g_sc_effect;
        rblog::write("SUBSTRATE-COHERENCE(effect) %s (Numpad1) — force-dirty effect template/child/slab. An A/B "
            "showed this recreates +0x198==0 in resim (reverts the derived binding). Watch INSTR-BINDING.",
            g_sc_effect ? "ON" : "OFF");
    }
    if (GetAsyncKeyState(VK_NUMPAD2) & 1) {
        g_sc_audio = !g_sc_audio;
        rblog::write("SUBSTRATE-COHERENCE(audio) %s (Numpad2) — force-dirty SE-table/blob/index (self-relative, "
            "likely safe). Watch crash A (0x1402A22CE / +0x80==0) with this ON vs OFF.",
            g_sc_audio ? "ON" : "OFF");
    }
    if (GetAsyncKeyState(VK_NUMPAD3) & 1) {
        g_forcedirty_off = !g_forcedirty_off;
        rblog::write("FORCE-DIRTY WALK %s (Numpad3) — the per-frame entity force-dirty walk. OFF=fast (the capture rationale "
            "does not hold; restoring derived fields is harmful). A/B with gp_crc(F4) armed: watch GAMEPLAY/FIGHTER-DIVERGE + fps.",
            g_forcedirty_off ? "OFF" : "ON (walking)");
    }
    if (GetAsyncKeyState(VK_NUMPAD4) & 1) {
        bool on = !arena::get_heap_redirect();
        arena::set_heap_redirect(on);
        rblog::write("HEAP-REDIRECT %s (Numpad4) — game HeapAlloc -> single-atomic bump zone. A/B the cross-thread "
            "contention: toggle OFF during normal play; if the chug clears, the bump-zone atomic is the perf bust.", on ? "ON" : "OFF (real heap)");
    }

    if (GetAsyncKeyState(VK_NUMPAD5) & 1) {
        // P4 REUSE-QUARANTINE mode toggle (the slab-reuse prevention). Cycle 1 SHADOW -> 2 DEFER (live) -> 0 OFF -> 1...
        // Live-reversible (no rebuild): if DEFER ever crashes/desyncs, press again to advance to OFF. A/B with F4 (gp_crc).
        long m = quarantine::mode();
        long nm = (m == 1) ? 2 : (m == 2) ? 0 : 1;
        quarantine::set_mode(nm);
        rblog::write("QUARANTINE mode -> %ld (Numpad5) [0=OFF 1=SHADOW 2=DEFER-live]. DEFER = slab-reuse prevention; arm F4 gp_crc to A/B determinism.", nm);
    }

    if (GetAsyncKeyState(VK_NUMPAD0) & 1) {
        // COHERENT-SET REPAIR scope (catalog-driven): cycle OFF -> proven-rows-only (#1 entity_child_array) ->
        // ALL-enabled-rows -> OFF. Live-reversible; A/B with F4 gp_crc. Each table row also has its own ship gate.
        coherent_set_repair::cycle_scope();
        rblog::write("CS-REPAIR scope cycled (Numpad0) [0=OFF 1=proven-only 2=all-enabled-rows]. Catalog-driven "
                     "structure repair (entity child-arrays, etc.); arm F4 gp_crc to A/B determinism.");
    }

    if (GetAsyncKeyState(VK_NUMPAD6) & 1) {
        // TORN-SAVE FIX A/B (INVARIANT-REPAIR): toggle the POSTLOAD free-list reciprocal-link rebuild. Live-reversible
        // (no rebuild). ON = restore-coherent (torn save made harmless); OFF = rely on the fragile atomic-save.
        // A/B with F4 (gp_crc) to prove desync-free, and watch INVARIANT-CHECK[POSTLOAD] FREE_LIST broken -> 0 with it ON.
        bool on = !alloc_invariants::repair_on();
        alloc_invariants::set_repair(on);
        rblog::write("INVARIANT-REPAIR %s (Numpad6) — POSTLOAD free-list link rebuild (the torn-save fix). "
                     "Watch INVARIANT-CHECK[POSTLOAD] FREE_LIST broken drop to 0; A/B determinism with F4 gp_crc.",
                     on ? "ON" : "OFF");
    }

    if (GetAsyncKeyState(VK_NUMPAD7) & 1) {
        // ALLOCATOR DEBUG INSTRUMENTS — default OFF (perf discipline). One key arms the diagnostic run:
        // the double-insert detector (per-free walk in the rollback window) + the per-frame slow-frame timer
        // + the arena-growth meter. Leave OFF for play / online; arm only to reproduce the torn-save hang.
        bool on = !idspine::di_detect();
        idspine::set_di_detect(on);
        g_slowframe = on ? 1 : 0;
        g_alloc_consist = on ? 1 : 0;          // arm the pre/post free-list consistency walks with the long run
        arena::set_load_diag_walk(on);         // arm the per-load scheduler-chain RE walk with the long run
        dyn_delete::set_validate(on);          // arm the DYNDELETE lie detector (free-list vs liveness ledger)
        byid::set_enabled(on);                 // arm the a-vs-c CARRIER census (out-of-arena 'a' vs in-arena-orphan 'c')
        if (!on) byid::report_and_reset();     // on disarm, dump the session a-vs-c tally
        rblog::write("ALLOC-DEBUG %s (Numpad7) — double-insert detector + slow-frame timer + growth meter + "
                     "free-list consistency walks + load-diag scheduler walk + DYNDELETE lie-detector %s. "
                     "OFF is the perf-clean default; this only arms for a focused torn-save diagnostic run.",
                     on ? "ARMED" : "OFF", on ? "ON" : "off");
    }

    if (GetAsyncKeyState(VK_NUMPAD9) & 1) {
        bool on = !arena::windowed_restore();
        arena::set_windowed_restore(on);
        rblog::write("WINDOWED-RESTORE %s (Numpad9) — %s. State-identical A/B; ON reverts only pages written "
                     "after the rollback target (the arena::load speed fix).",
                     on ? "ON" : "OFF", on ? "windowed (fast)" : "FULL cumulative revert (old/slow)");
    }

    if (GetAsyncKeyState(VK_ADD) & 1) {
        // DEFERRED-FOLD A/B (Numpad +): move the per-save baseline fold memcpy (~1.35ms measured) to the bg worker.
        // Default OFF = synchronous, byte-identical proven path. Determinism-safe by construction (immutable src);
        // drain-before-freeze guarantees freeze-safety. A/B with F4 (gp_crc): ON must keep GAMEPLAY-diverged=0 and
        // drop the ARENA-SAVE-SPLIT fold term to ~0. Live-reversible: press again to fall back instantly.
        bool on = !arena::fold_defer();
        arena::set_fold_defer(on);
        rblog::write("DEFERRED-FOLD %s (Numpad +) — baseline fold %s. Watch ARENA-SAVE-SPLIT fold=~0 when ON; "
                     "gate: gp_crc(F4) GAMEPLAY-diverged stays 0, no FOLD-DROP regression, no FOLD-DRAIN STALL.",
                     on ? "ON" : "OFF", on ? "-> bg worker (off critical path)" : "synchronous (proven baseline)");
    }

    if (GetAsyncKeyState(VK_SUBTRACT) & 1) {
        // DRIFT-WATCH A/B (Numpad -): count-drift experiment. Turn ON, then play a heavy match. Run once without F5
        // (engine off) and once with F5 (engine on). Read DRIFT-WATCH: engine_on=0 event => base game drifts alone;
        // events only ever engine_on=1 => our save-system induces it. Resets its state on each toggle-on.
        g_drift_watch = !g_drift_watch;
        if (g_drift_watch) drift_watch_reset();
        rblog::write("DRIFT-WATCH %s (Numpad -) — recycler tally-vs-pile watcher (read-only, engine-independent). "
                     "Play heavy; engine_on=0 hit => BASE GAME; engine_on-only => OUR save. (run once F5-off, once F5-on)",
                     g_drift_watch ? "ON" : "OFF");
    }

    drift_watch_tick();   // Track 2: runs every frame regardless of engine state (must tick with F5 off)

    if (g_engine_on) {
        LARGE_INTEGER _pt0,_pt1,_pt2,_pt3,_pt4,_pt5;  // profiler timestamps
        QueryPerformanceCounter(&_pt0);
        // Force-dirty all entity pages so GetWriteWatch captures complete entities.
        // [OFF by default — g_forcedirty_off: the capture rationale does not hold (arena::load is coherent by
        // construction) and the substrate groups RESTORE derived fields, which is harmful. gp_crc (F4) gates
        // correctness; Numpad3 restores the walk for A/B.]
        if (!g_forcedirty_off) {
            uint32_t fd_ents = 0;
            uint32_t child218 = 0;
            g_fd_tree_count = 0;
            g_rsub_track_count = 0;
            uintptr_t sunit = *(uintptr_t*)addr::resolve(0x140E17698);
            uintptr_t effect_vt = g_sc_effect ? addr::resolve(0x140BAE1D0) : 0;  // effect unit vtable
            if (sunit) {
                for (int line = 0; line < 128; line++) {
                    uintptr_t ent = *(uintptr_t*)(sunit + 0x58 + (uintptr_t)line * 0x30);
                    int walk = 0;
                    while (ent && walk < 512) {
                        if (!arena::is_committed_addr(ent)) break;
                        force_dirty_entity(ent);
                        fd_ents++;
                        // SUBSTRATE COHERENCE: effect coherence group (template/child/slab). Gated.
                        if (effect_vt && *(uintptr_t*)ent == effect_vt)
                            child218 += force_dirty_effect_group(ent);
                        ent = *(uintptr_t*)(ent + 0x20);
                        walk++;
                    }
                }

                // Publish force-dirty counts to monitor
                if (monitor_shm::g_mon) {
                    monitor_shm::g_mon->force_dirty_count = fd_ents;
                    monitor_shm::g_mon->child08_count     = (uint32_t)(g_fd_tree_count - fd_ents);
                    monitor_shm::g_mon->child218_count    = child218;
                }

                // Force-dirty sUnit's scheduler line HEAD pointer pages.
                // Touch HEAD (+0x58) directly, not descriptor (+0x38) — on line 85+
                // the descriptor and HEAD cross a 4KB page boundary.
                for (int line = 0; line < 128; line++) {
                    volatile uint8_t* p = (volatile uint8_t*)(sunit + 0x58 + (uintptr_t)line * 0x30);
                    *p = *p;
                }
            }

            // Force-dirty sMain's dispatch infrastructure pages
            uintptr_t smain = *(uintptr_t*)addr::resolve(0x140E177E8);
            if (smain) {
                for (uintptr_t off = 0; off < 0x2000; off += 4096) {
                    volatile uint8_t* p = (volatile uint8_t*)(smain + off);
                    *p = *p;
                }
            }

            // SUBSTRATE COHERENCE: audio SE-table coherence groups (header/blob/index). Gated.
            if (g_sc_audio) {
                uint32_t se = audio_group::force_dirty_all();
                if (monitor_shm::g_mon) monitor_shm::g_mon->se_table_count = se;
            }
        }

        // Locked-save discriminator: scan each allocator's free list under its own CS hold, at save time, before the
        // snapshot runs. A recip-break seen here (quiesced) is already-present corruption — torn-save is ruled out
        // because the list isn't being torn under the lock. Read against the when=rollback check, this resolves
        // torn-save vs restore-artifact vs live-writer. Throttled; pure read-only (no repair).
        // Drain-at-save: complete coherent mid-teardown scheduler nodes before the snapshot, every save, so the
        // snapshot can never contain a state-3/4 freed-but-linked node.
        QueryPerformanceCounter(&_pt1);   // force-dirty done
        scheduler_drain_at_save();
        // PROBE (default OFF): the %20 alloc-consistency cluster — up to 4.2M free-list node hops
        // + forced unsuppressed disk I/O (the measured ~570ms ALLOC-CONSIST spike) + the 160-CS lock-all +
        // the per-node-VirtualQuery sched scan. Read-only oracle; arm g_alloc_consist for allocator/torn-save RE.
        if (g_alloc_consist && (g_frame_counter % 20) == 0) {
            AllocatorSnapshotCsScope snap;
            if (snap.ok()) {
                for (int i = 0; i < g_alloc_count; i++)
                    alloc_consistency::check(g_alloc_addrs[i], "save");
            }
            // SCHED torn-at-save discriminator: walk the sUnit scheduler lines on the FORWARD chain
            // (the direction the crash walks; dead_vtable_unlink/byid walk the reciprocal end and miss it). Read-only,
            // under the sUnit unit-CS (TryEnter, never blocks). Separates torn-at-save from restore-pairing.
            scheduler_save_scan(g_frame_counter);
        }

        QueryPerformanceCounter(&_pt2);   // drain + %20 block done
        save_data(g_frame_counter);
        save_heap_zone(g_frame_counter);
        QueryPerformanceCounter(&_pt3);   // save_core (data/heap) done
        // Atomic ALLOCATOR-GROUP SAVE (torn-save fix, A/B g_atomic_save): capture {descriptor, in-arena nodes}
        // under the allocator CSes so no MT splice is in flight => the saved coherence group is internally
        // consistent (alloc_invariants POSTLOAD should flip broken->clean). Fall back to the unlocked save if a CS
        // stays busy past the retry budget (rare; a rare torn save beats stalling the main thread).
        bool _atomic = false;
        if (g_atomic_save) _atomic = try_atomic_alloc_save(g_frame_counter, 64);
        if (!_atomic) {                                  // unlocked fallback (the pre-atomic-save behavior)
            if (g_atomic_save) InterlockedIncrement(&g_atomic_save_fallback);
            save_allocators(g_frame_counter);
            arena::save(g_frame_counter);
        }
        if (g_atomic_save && (g_frame_counter % 600) == 0) {
            rblog::write("ATOMIC-SAVE: coherent=%ld fallback(CS-busy)=%ld (the {descriptor,nodes} group is captured under the alloc CSes)",
                (long)g_atomic_save_ok, (long)g_atomic_save_fallback);
            rblog::write("FLIST-UNIT: saved=%lld restored=%lld slot_invalid=%lld unlocked_skip=%lld recip=%lld diags=%ld | hw_n=%ld/%d hw_walked=%ld (hw_n vs cap = headroom; hw_n hitting cap => raise it; hw_walked>>hw_n => cycle)",
                (long long)g_flist_saved, (long long)g_flist_restored, (long long)g_flist_slot_invalid, (long long)g_flist_unlocked_skip,
                (long long)g_flist_recip_seen, (long)g_flist_diags,
                g_flist_hw_n, FLIST_MAX_NODES, g_flist_hw_walked);
            rblog::write("ALIST-UNIT(Unit-scoped): saved=%lld restored=%lld slot_invalid=%lld | hw_n=%ld/%d | DUAL-MEMBER checks=%lld hits=%lld | oracles{recip=%lld free-on-chain=%lld: vanilla-legal, captured verbatim}",
                (long long)g_alist_saved, (long long)g_alist_restored, (long long)g_alist_slot_invalid,
                g_alist_hw_n, ALIST_MAX_NODES, (long long)g_dualmember_checks, (long long)g_dualmember_hits,
                (long long)g_alist_recip_seen, (long long)g_alist_freeonchain_seen);
            rblog::write("CS-KEEPLIVE: rollbacks=%lld | CS-CANARY events=%lld (OS CS objects pass through restore untouched by construction; canary change = live scribbler or engine CS-reinit)",
                (long long)g_cs_keeplive_rollbacks, (long long)g_cs_canary_events);
            // STABILITY heartbeat — one grep-able endurance line (every 600 frames = ~10s): every monotonic
            // metric that could break an hours-long session. Mine with: grep "STABILITY:" on the log.
            material_guard::report();
            id_oracle::report();
            { long ag = anim_curve_guard::guarded_count();
              if (ag) rblog::write("ANIM-CURVE-GUARD: coerced %ld wild resolver returns -> default-pose (0x14087D46E made unrepresentable)", ag); }
            { long pg = particle_list_guard::guarded_count();
              if (pg) rblog::write("PARTICLE-LIST-GUARD: reset %ld husk retired-lists -> empty-path (0x140836876 made unrepresentable)", pg); }
            gameplay_complete::report();
            count_drift_census::report();       // count-drift: the guard-skip split (resim/forward/engine-off × main/worker)
            carve_orphan_probe::report();     // A4-CARVE: post-carve orphan census (the violating allocation, caller-named)
            net::session_report();  // lockstep netcode: connection state + RTT (no-op solo)
            net_input::report();    // lockstep netcode: lockstep frame/delay/stall/exchange counts (no-op unless lockstep active)
            net_sync::report();     // lockstep netcode: force-seed hook state
            dinput_probe::config_report();  // control-scheme fingerprint: the determinism gate
            dinput_probe::report(); // input seam: per-device format + poll counts (observation only)
            rtv_probe::report();
            gp_crc::canary_report();
            rblog::write("STABILITY: f=%d flist=%d qu_held=%d donated=%zuMB wm=%zuMB hz=%lldMB restore=%.1fms oracle=%.1fms idspine_serial=%lld",
                g_frame_counter, g_flist_last_n, quarantine::held_count(),
                donated_total >> 20, arena::get_watermark() >> 20,
                arena::get_heap_zone_offset() >> 20,
                arena::last_restore_ms(), arena::last_oracle_ms(), (long long)idspine::birth_counter());
            // COVERAGE TRIPWIRE (discovery is once-only + capped at MAX_ALLOCS): a vtable-valid
            // MtScalable control in the LIVE registry that is not in g_alloc_addrs gets NO unit/descriptor
            // protection (the documented post-boot-allocator risk class). Name it loudly instead of failing silent.
            {
                uintptr_t count_addr = addr::resolve(0x140D760E0), array_addr = addr::resolve(0x140D760F0);
                uintptr_t target_vt  = addr::resolve(0x140B08620);
                uint32_t nreg = *(uint32_t*)count_addr; if (nreg > 64) nreg = 64;
                for (uint32_t i = 0; i < nreg; i++) {
                    uintptr_t c = *(uintptr_t*)(array_addr + i * 8);
                    if (!c || *(uintptr_t*)c != target_vt) continue;
                    bool known = false;
                    for (int j = 0; j < g_alloc_count; j++) if (g_alloc_addrs[j] == (uintptr_t)c) { known = true; break; }
                    if (!known) { static volatile LONG64 nGap = 0; LONG64 g = _InterlockedIncrement64(&nGap);
                        if (g <= 8 || (g % 100) == 0)
                        rblog::write("FLIST-UNIT COVERAGE GAP #%lld: registry[%u] ctrl=0x%llX vtable-valid but NOT in the discovered set — NO unit/descriptor protection.", (long long)g, i, (unsigned long long)c); }
                }
            }
        }
        LARGE_INTEGER _ptb,_ptg,_pts;
        QueryPerformanceCounter(&_pt4);   // alloc-group save done
        byid::save_frame(g_frame_counter); // by-identity SHADOW (PROBE): 8192-edge transitive walk when enabled
        QueryPerformanceCounter(&_ptb);
        gp_crc::record(g_frame_counter);   // determinism ORACLE (PROBE): snapshot gameplay+fighter state (pre-orig)
        gp_crc::canary_record(g_frame_counter);   // CANARY always-on draw-count stamp (cheap, ungated)
        QueryPerformanceCounter(&_ptg);
        QueryPerformanceCounter(&_pts);
        g_reconfig_at_frame[g_frame_counter & 255] = draw_probe::reconfig_count();   // cDraw FUN_1401ffca0 count @ this save
        {   // kick-scalar trajectory recording: RING[N] = post-frame-(N-1) kick scalars (pre-orig site,
            // same indexing as gp_crc::record) — replayed per suppressed resim frame in hk_go_kick
            uintptr_t sr = *(uintptr_t*)addr::resolve(0x140E179A8);
            if (sr) {
                KickRec& r = g_kick_ring[g_frame_counter & 255];
                r.frame    = g_frame_counter;
                r.counter  = *(volatile uint32_t*)(sr + 0x6764c);
                r.toggle   = *(volatile uint32_t*)(sr + 0x67648);
                r.threaded = *(volatile uint8_t*)(sr + 0x3d);
            }
        }
        voice_pool::on_frame(g_frame_counter);

        if (g_prof_on) {   // profiler: accumulate per-phase, dump avg ms/phase per 30 saves
            QueryPerformanceCounter(&_pt5);
            g_prof_acc[0] += prof_ms(_pt0,_pt1);   // force-dirty walk
            g_prof_acc[1] += prof_ms(_pt1,_pt2);   // sched_drain + %20 probe block
            g_prof_acc[2] += prof_ms(_pt2,_pt3);   // save_data/heap/alloc
            g_prof_acc[3] += prof_ms(_pt3,_pt4);   // arena::save (dirty-page copy)
            g_prof_acc[4] += prof_ms(_pt4,_ptb);   // byid SHADOW
            g_prof_acc[5] += prof_ms(_ptb,_ptg);   // gp_crc oracle
            g_prof_acc[6] += prof_ms(_ptg,_pts);   // serializer oracle
            g_prof_acc[7] += prof_ms(_pts,_pt5);   // tail misc (draw_probe/kick/voice)
            g_prof_acc[8] += prof_ms(_pt0,_pt5);   // total save-block
            // CHURN-FRAME outlier: the 30-save average SMEARS the one super-teardown frame. Log this single frame's
            // split when it blows past threshold — names drain (engine teardown) vs arena (copy, fixable) for the
            // exact super hitch. Outlier-only => no per-frame spam.
            {
                double this_total = prof_ms(_pt0,_pt5);
                if (this_total > 20.0) {
                    static volatile LONG cf = 0; LONG k = InterlockedIncrement(&cf);
                    if (k <= 200)
                        rblog::write("CHURN-FRAME #%ld: TOTAL=%.1f ms | drain=%.1f arena=%.1f forcedirty=%.1f save_core=%.1f misc=%.1f (drain=engine teardown, arena=copy)",
                            k, this_total, prof_ms(_pt1,_pt2), prof_ms(_pt3,_pt4), prof_ms(_pt0,_pt1),
                            prof_ms(_pt2,_pt3), prof_ms(_pts,_pt5));
                }
            }
            if (++g_prof_n >= 30) {   // log fast even at low fps
                double n = (double)g_prof_n;
                rblog::write("PROF[avg ms/save over %d]: forcedirty=%.2f drain=%.2f save_core=%.2f arena=%.2f byid=%.2f gp_crc=%.2f serializer=%.2f misc=%.2f | TOTAL=%.2f",
                    g_prof_n, g_prof_acc[0]/n, g_prof_acc[1]/n, g_prof_acc[2]/n, g_prof_acc[3]/n,
                    g_prof_acc[4]/n, g_prof_acc[5]/n, g_prof_acc[6]/n, g_prof_acc[7]/n, g_prof_acc[8]/n);
                for (int i=0;i<9;i++) g_prof_acc[i]=0;
                g_prof_n = 0;
            }
        }

        // Auto-rollback every ~180 frames (3s at 60fps)
        if (g_auto_rollback && !net_input::active() && (g_frame_counter - g_last_auto_frame) >= AUTO_INTERVAL) {
            int target = g_frame_counter - g_rollback_depth;
            if (target >= 0) {
                do_rollback(param_1, g_frame_counter, target);
                g_last_auto_frame = g_frame_counter;
            }
        }

        g_frame_counter++;
        if (g_frames_since_rollback < 1000000) InterlockedIncrement(&g_frames_since_rollback);  // forward frame: age the discriminator-freshness window

        // Update monitor frame counter and ring head
        if (monitor_shm::g_mon) {
            monitor_shm::g_mon->frame_counter = (uint32_t)g_frame_counter;
            monitor_shm::g_mon->ring_head     = (uint32_t)g_data_ring_head;
        }
    }

    // Periodic arena watermark check
    {
        static int s_wm_log = 0;
        if (g_engine_on && (++s_wm_log % 60) == 0) {
            rblog::write("ARENA-WM: watermark=0x%zX / 0x%zX (%.1f%% of the arena)",
                        arena::get_watermark(),
                        (size_t)(arena::end() - arena::base()),
                        (double)arena::get_watermark() / (double)(arena::end() - arena::base()) * 100.0);
        }
    }

    // Update overlay text
    update_overlay();

    // Run the real frame
    orig_main_proc(param_1);
    if (net_input::active()) net_input::advance_frame();   // LOCKSTEP: net-frame advances only when a frame actually executed

    // EKG: track state changes after each normal-play frame
    if (g_engine_on) {
        // Capture input after orig — buffer now has this frame's actual input
        // (input_dispatch inside orig read hardware into the buffer)
        input::capture(g_frame_counter - 1);

        monitor_shm::set_phase(PHASE_NORMAL, g_frame_counter - 1);
    }
}

namespace resim {

// OWNED-HEAP P4 gates — public API (resim.h); forwards to the file-scope state defined near g_rollback_depth so the
// internal restore-path calls and the dllmain composition share one flag pair.
void set_owned_heap_control_revert(bool on) { ::set_owned_heap_control_revert(on); }
bool owned_heap_control_revert()            { return ::owned_heap_control_revert(); }
void set_patch_pile_enabled(bool on)        { ::set_patch_pile_enabled(on); }
bool patch_pile_enabled()                   { return ::patch_pile_enabled(); }

void early_init() {
    find_data_section();
    init_data_ring();

    // Log preserve list total size
    size_t total = 0;
    for (int i = 0; i < PRESERVE_COUNT; i++) total += g_preserve_list[i].size;
    rblog::write("DATA: using curated PRESERVE list (%d entries, %zu bytes total)", PRESERVE_COUNT, total);
}

// True while a rollback resim is replaying — lets diagnostics distinguish a resim-phase
// teardown from a first-post-rollback-normal-frame teardown.
bool resim_active() { return g_resim_active; }
bool engine_enabled() { return g_engine_on; }
bool netplay_lean() { return g_netplay_lean != 0; }
int current_frame() { return g_frame_counter; }
// The frame the liveness spine must stamp births/deaths with. During resim, g_frame_counter is frozen at the live
// pre-rollback value (it only advances on the forward path), so a carve/free during replay must be stamped with the
// REPLAYED frame (g_replay_frame), not current_frame() — else birth-frame keying is wrong.
int effective_frame() { return (g_resim_active && g_replay_frame >= 0) ? g_replay_frame : g_frame_counter; }
void request_rollback_to(int engine_frame) {
    if (engine_frame < 0) return;
    for (;;) {
        const LONG cur = g_rb_request;
        if (cur >= 0 && cur <= engine_frame) return;          // an equal-or-deeper rollback is already pending
        if (InterlockedCompareExchange(&g_rb_request, engine_frame, cur) == cur) return;
    }
}

int last_rollback_target() { return g_last_rollback_target; }
int max_rollback_depth() { return MAX_ROLLBACK_DEPTH; }
int frames_since_rollback() { return (int)g_frames_since_rollback; }
bool rollback_happened() { return g_any_rollback != 0; }

void init() {
    // Hook MAIN_PROC (MH_Initialize already called by dllmain init_thread)
    void* target = (void*)addr::resolve(MAIN_PROC_IDA);
    MH_STATUS status = MH_CreateHook(target, (void*)&hk_main_proc, (void**)&orig_main_proc);
    if (status != MH_OK) {
        rblog::write("RESIM: MH_CreateHook MAIN_PROC failed (%d)", status);
        return;
    }
    rblog::write("RESIM: hooked MAIN_PROC at 0x%llX", (unsigned long long)(uintptr_t)target);

    // Hook SCENE_TREE_DISPATCH — validates child vtables before dispatching
    {
        void* st_target = (void*)addr::resolve(SCENE_TREE_DISPATCH_IDA);
        MH_STATUS st_status = MH_CreateHook(st_target, (void*)&hk_scene_tree_dispatch,
                                             (void**)&orig_scene_tree_dispatch);
        if (st_status != MH_OK) {
            rblog::write("RESIM: MH_CreateHook SCENE_TREE_DISPATCH failed (%d)", st_status);
        } else {
            rblog::write("RESIM: hooked SCENE_TREE_DISPATCH at 0x%llX",
                        (unsigned long long)(uintptr_t)st_target);
        }
    }

    // Hook FRAME_PACER — fix delta_T during resim
    {
        void* fp_target = (void*)addr::resolve(FRAME_PACER_IDA);
        MH_STATUS fp_status = MH_CreateHook(fp_target, (void*)&hk_frame_pacer,
                                             (void**)&orig_frame_pacer);
        if (fp_status != MH_OK) {
            rblog::write("RESIM: MH_CreateHook FRAME_PACER failed (%d)", fp_status);
        } else {
            rblog::write("RESIM: hooked FRAME_PACER at 0x%llX",
                        (unsigned long long)(uintptr_t)fp_target);
        }
    }


    // Full-session single-threaded ConcRT dispatch
    {
        void* rw_target = (void*)addr::resolve(RUN_AND_WAIT_IDA);
        MH_STATUS rw_status = MH_CreateHook(rw_target, (void*)&hk_run_and_wait,
                                             (void**)&orig_run_and_wait);
        if (rw_status != MH_OK)
            rblog::write("RESIM: RUN_AND_WAIT hook failed (%d)", rw_status);
        else
            rblog::write("RESIM: hooked RUN_AND_WAIT at 0x%llX (resim-scoped single-thread, +0xa4 gate)",
                        (unsigned long long)(uintptr_t)rw_target);
    }

    // Async fork-join — resim-scoped serial force (parks the FUN_1405210e0 worker ring)
    {
        void* pf_target = (void*)addr::resolve(PARALLEL_FOR_IDA);
        MH_STATUS pf_status = MH_CreateHook(pf_target, (void*)&hk_parallel_for, (void**)&orig_parallel_for);
        if (pf_status != MH_OK)
            rblog::write("RESIM: PARALLEL_FOR hook failed (%d)", pf_status);
        else
            rblog::write("RESIM: hooked FUN_14095ec90 at 0x%llX (resim-scoped serial, +0xB0 gate)",
                        (unsigned long long)(uintptr_t)pf_target);
    }

    // GO-kick — render-cadence control: suppress the per-frame render kick on intermediate resim frames
    // (render only the final frame). Engine-correct standard-rollback cadence.
    {
        void* gk_target = (void*)addr::resolve(GO_KICK_IDA);
        MH_STATUS gk_status = MH_CreateHook(gk_target, (void*)&hk_go_kick, (void**)&orig_go_kick);
        if (gk_status != MH_OK)
            rblog::write("RESIM: GO_KICK hook failed (%d)", gk_status);
        else
            rblog::write("RESIM: hooked GO_KICK (FUN_140537080) at 0x%llX (intermediate-resim render suppression)",
                        (unsigned long long)(uintptr_t)gk_target);
    }

    // _purecall hook — catch the game's R6025 (virtual on a partially-destructed object) and LIMP +
    // attribute, instead of the modal dialog + 77-thread hang. Game CRT is static, so hook ITS _purecall.
    {
        void* pc_target = (void*)addr::resolve(0x1409A2E90);
        MH_STATUS pc_status = MH_CreateHook(pc_target, (void*)&hk_purecall, (void**)&orig_purecall);
        rblog::write("RESIM: _purecall hook (FUN_1409a2e90) %s — R6025 attribution + limp",
                     pc_status == MH_OK ? "OK" : "FAILED");
    }

    // Window-thread draw-build witness + gate — for the pre-freeze quiesce (the straddle fix)
    {
        void* wr_target = (void*)addr::resolve(WINDOW_RENDER_IDA);
        MH_STATUS wr_status = MH_CreateHook(wr_target, (void*)&hk_window_render, (void**)&orig_window_render);
        if (wr_status != MH_OK)
            rblog::write("RESIM: WINDOW_RENDER witness hook failed (%d)", wr_status);
        else
            rblog::write("RESIM: hooked FUN_14053caf0 at 0x%llX (shared draw-build witness+gate)",
                        (unsigned long long)(uintptr_t)wr_target);
    }

    // Device-reset handler witness (FUN_14053d690, 1254 bytes) — the active branch's pre-build stage; a real
    // Reset takes tens of ms and must be drained before freeze (witnessed only, never skipped).
    {
        void* dr_target = (void*)addr::resolve(DEVICE_RESET_CHECK_IDA);
        MH_STATUS dr_status = MH_CreateHook(dr_target, (void*)&hk_device_reset, (void**)&orig_device_reset);
        if (dr_status != MH_OK)
            rblog::write("RESIM: DEVICE_RESET witness hook failed (%d)", dr_status);
        else
            rblog::write("RESIM: hooked FUN_14053d690 at 0x%llX (device-reset witness)",
                        (unsigned long long)(uintptr_t)dr_target);
    }

    // Capture-path witness (FUN_14053ede0, 410 bytes) — the active branch's first call; closes the
    // pre-d690 quiesce gap (witnessed only, never skipped).
    {
        void* cp_target = (void*)addr::resolve(CAPTURE_PATH_IDA);
        MH_STATUS cp_status = MH_CreateHook(cp_target, (void*)&hk_capture_path, (void**)&orig_capture_path);
        if (cp_status != MH_OK)
            rblog::write("RESIM: CAPTURE_PATH witness hook failed (%d)", cp_status);
        else
            rblog::write("RESIM: hooked FUN_14053ede0 at 0x%llX (capture-path witness)",
                        (unsigned long long)(uintptr_t)cp_target);
    }

    // LEAN MODE: BONE-REFERENT / DISPATCH-ALIEN / FINALIZER-ALIEN are pure RE backtrace probes (they only LOG stack
    // chains, 0 stability effect) and put MinHook trampolines on HOT functions (bone-consume / element-dispatch /
    // finalizer). Not INSTALLED by default. Un-comment to arm for a specific off-main backtrace RE question.
    // { MH_CreateHook(resolve(BONE_CONSUME_IDA), &hk_bone_consume, &orig_bone_consume); }
    // { MH_CreateHook(resolve(ELEM_DISPATCH_IDA), &hk_elem_dispatch, &orig_elem_dispatch); }
    // { MH_CreateHook(resolve(FINALIZER_IDA), &hk_finalizer, &orig_finalizer); }
    rblog::write("RESIM: LEAN MODE — bone/dispatch/finalizer backtrace RE probes NOT installed (re-enable in init to arm)");

    // Keyframe push_front guard
    {
        void* kf_target = (void*)addr::resolve(KEYFRAME_PUSHFRONT_IDA);
        MH_STATUS kf_status = MH_CreateHook(kf_target, (void*)&hk_keyframe_pushfront,
                                             (void**)&orig_keyframe_pushfront);
        if (kf_status != MH_OK)
            rblog::write("RESIM: keyframe guard hook failed (%d)", kf_status);
        else
            rblog::write("RESIM: hooked keyframe push_front at 0x%llX",
                        (unsigned long long)(uintptr_t)kf_target);
    }

    // PERF A/B 'nohooks': skip all non-essential module hooks (idspine/effect/gp_crc/alloc/sound/splice/voice/etc.)
    // to isolate the hook-trampoline + body tax on engine-off normal play. Core hooks (MAIN_PROC, scene_tree,
    // frame_pacer, worker-dispatch, render, keyframe) stay installed. Rollback engine is disabled in this mode.
    if (arena::no_hooks()) {
        rblog::write("RESIM: NO-HOOKS A/B ACTIVE — skipping all non-essential module hooks (perf isolation; rollback disabled)");
    } else {
    // Voice retention pool — hooks all DestroyVoice call sites
    voice_pool::init();

    // Sound-resource object-granular preserve — hooks the resource refcount-inc to register slab-packed
    // in-arena sound resources (rSoundSource etc.), preserved across arena::load (closes the sound cue/source crash).
    sound_resource_preserve::init();

    // ID-ORACLE: the identity/liveness substrate — no hooks, just resolves the dead-sentinel. Init before
    // every consumer (material_guard / anim guard / rtv_probe / migrations) so the one unified predicate is ready.
    id_oracle::init();

    // RTV probe — read-only hook on the nDraw::RenderTargetView dtor (the single blocker)
    material_guard::init();
    life_floor::init();       // LIFE-FLOOR: route render-wrapper deaths to the engine retirement ring during resim (RING-UNIT restores it)
    audio_leaf::init();       // AUDIO-LEAF: suppress the audio 3D-sync trunk during resim (render-output consumer boundary completion)
    rtv_probe::init();

    // Dynamic restore engine — registry of RestoreDescriptors. The handle_preserve / rtv-preserve /
    // dead_vtable_unlink fixes are registered as descriptors; do_rollback invokes them in-place through
    // dyn_restore::run().
    dyn_restore::init();
    resim_gate::register_precond("no-alloc-cs-held", precond_no_alloc_cs_held);  // never freeze a worker mid-two-part-write
    resim_gate::register_precond("no-loader-mid-load", precond_no_loader_mid_load); // SUBSTRATE COHERENCE: never freeze mid resource-load/relocation (gated; no-op when fix OFF)
    audio_group::init();         // SUBSTRATE COHERENCE: arm the SE-table registry (registers via the read-only SE resolver hook)
    rblog::write("RESIM-GATE: conditional-resim precondition registry ON (%d precond) — rollback waits for a coherent instant before freeze (defer on timeout)", resim_gate::g_pc_n);
    if (g_diag_enabled) byid::init();   // [DIAG, off] by-identity SHADOW engine (effect+0x218 carrier); F12 arms it for a measurement run
    idspine::init();          // birth-stamp identity spine: FUN_1404ca650 birth + FUN_1404cb350 death, keyed by block base.
    rdspine::init();          // Default-allocator SHADOW twin (FUN_1404C9460/9A00): measures in-arena vs CRT,
                              // births==deaths, coverage for the Default-malloc chokepoint. Read-only (0 game
                              // writes); the third identity coordinate byid needs.

    // Effect probe: read-only observe-only probes for the effect crash family (R0 is is_readable-guarded before
    // any deref, so the probe cannot fault on a float-as-pointer reused slab). Includes the consume-leaf
    // FUN_14080d440 observer — is crash C latent-vanilla (null +0x50 with rollback OFF) or rollback-induced.
    effect_probe::init(g_diag_enabled != 0);   // SE-table SE-GUARD + A-vs-D discriminator always (engine-gated, bitmap-leaned = perf-clean); consume_leaf only under full diag

    // Diagnostic probes default OFF (hot-function hooks: RNG draw, allocator alloc/free, f50, FUN_1401ffca0)
    // so play is perf-clean; each is re-armed individually for an RE run.
    gp_crc::init();           // determinism ORACLE always installed (rng hook is cheap); per-frame CRC stays gated by
                              // g_off (F4 arms) so play is perf-clean and the validation long run is one keypress away.
    // draw_probe::init(); // PERF: OFF for the splice-validation long run — per-draw cDraw f50 hook, not
                              // needed to validate the splice (recip=0 + no-crash). Re-enable for cDraw RE.
    draw_probe::init_dlclean();  // draw_list_cleanup torn count/base probe + containment (no-op until first
                                 // rollback; the render count(+0x20)/base(+0x50) desync that crashed FUN_1405DD810)

    xray_mem::init();         // byte-level R/W tracer (F3 arms a scoped 4-frame capture); VEH registered last = frontmost
    page_free::init();        // manifest-driven STRUCTURAL restore (the page-level restore); F11 toggles (default OFF=arena::load)
    alloc_invariants::set_repair(true);  // restore-coherent free-list link rebuild at POSTLOAD. Numpad6 A/B; F4 gp_crc
                                  // checks desync-free.
    coherence_audit::init();  // (field-pass discovery only; the ctor-hook container pass is retired)
    coherence_audit::set_container_repair(false);  // superseded by coherent_set_repair's verified sUnit enumeration
    effect_splice::init();     // The free-time +0x218 unlink fix (base-dtor + teardown)
    render_subchild_guard::init();  // render walk FUN_140615de0: null +0x60 sub-child -> callee's intended param_2==0 path (the effect/render death class)
    anim_curve_guard::init();       // anim family: curve resolver FUN_140879570 wild return -> 0 -> engine default-pose (the 0x14087D46E close; RENDER-ONLY, desync-safe)
    particle_list_guard::init();    // particle-tick FUN_1408366a0 +3 siblings — husk retired-list tail -> reset to empty (the 0x140836876 write-crash close; leaf domain-valid-or-null on a STRUCTURE)
    count_drift_census::init();                 // count-drift experiment: passive census of the native count-gated-unlink guard-skip (FUN_1404CAA60) — the split settles resim-induced vs vanilla-latent for the a4 count-drift seed
    carve_orphan_probe::init();               // A4-CARVE orphan detector: post-carve still-chained check (FUN_1404CA650) — names the violating allocation + its caller; also measures the inlined count-gate precondition
    net::session_init();            // lockstep netcode: arm UDP session if netplay.flag present (role-driven ports 7100/7101); no-op solo
    net_sync::init();               // lockstep netcode: install the force-seed hook (FUN_14000b350) for deterministic match-start

    // (The FUN_140781ac0 +0x48 Texture detector lives in rtv_probe as the active Texture suppress.)
    rblog::write("RESIM: RE DIAGNOSTICS %s (gp_crc/effect_probe/byid). "
                 "Rollback mechanisms installed (voice_pool/rtv/dyn_restore/audio_group/idspine/page_free/effect_splice).",
                 g_diag_enabled ? "ENABLED (diagnostic run)" : "OFF (perf default)");
    }   // end if (!arena::no_hooks)

    // Enable all hooks
    status = MH_EnableHook(MH_ALL_HOOKS);
    if (status != MH_OK) {
        rblog::write("RESIM: MH_EnableHook failed (%d)", status);
        return;
    }

    // Launch overlay window on its own thread
    CreateThread(NULL, 0, overlay_thread, NULL, 0, NULL);

    hang_detector::init();   // read-only silent-hang capture (samples all threads on a >2s main stall)

    rblog::write("RESIM: initialized (F5=arm/disarm, F6=manual rollback, depth=%d)", g_rollback_depth);
}


} // namespace resim
