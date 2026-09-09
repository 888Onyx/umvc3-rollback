// voice_pool.cpp — Deferred IXAudio2SourceVoice destruction.
// When the game destroys a voice, we stop it and hold it in a pool.
// Actually destroy after rollback_depth + 2 frames.
// This keeps arena pointers to voice objects valid across arena::load.

#include "voice_pool.h"
#include "addr.h"
#include "arena.h"
#include "log.h"
#include "resim.h"
#include <MinHook.h>
#include <windows.h>
#include <intrin.h>
#include <cstdint>
#include <cstring>

namespace voice_pool {

static constexpr int MAX_RETAINED = 256;
static constexpr int FLUSH_DELAY = 9;  // rollback_depth(7) + 2

struct Entry {
    uintptr_t voice;
    uint32_t destroy_frame;   // flush timer (re-stamped on rollback to extend the resim-window reprieve)
};

static Entry g_pool[MAX_RETAINED];
static int g_pool_count = 0;
static int g_current_frame = 0;
static bool g_flush_paused = false;

// ============================================================
// Core pool operations
// ============================================================

static void actually_destroy_voice(uintptr_t voice) {
    if (!voice) return;
    uintptr_t vt = *(uintptr_t*)voice;
    if (vt) {
        // DestroyVoice = IXAudio2Voice vtable+0x90
        auto destroy_fn = (void(*)(uintptr_t))(*(uintptr_t*)(vt + 0x90));
        destroy_fn(voice);
    }
}

static void defer_destroy_voice(uintptr_t voice) {
    if (!voice) return;

    // Deferral only earns its keep inside the rollback-engine window (the only time arena::load
    // can rewind a pointer onto a voice object). With the engine off there is nothing to protect
    // against, and a held-but-Stopped voice starves the engine's own audio drain — so destroy now.
    if (!resim::engine_enabled()) { actually_destroy_voice(voice); return; }

    // Stop the voice (silence it) — IXAudio2SourceVoice::Stop = vtable+0xA0
    uintptr_t vt = *(uintptr_t*)voice;
    if (vt) {
        auto stop_fn = (int32_t(*)(uintptr_t, uint32_t, uint32_t))(*(uintptr_t*)(vt + 0xA0));
        stop_fn(voice, 0, 0);  // flags=0, operationSet=XAUDIO2_COMMIT_NOW
    }

    if (g_pool_count < MAX_RETAINED) {
        g_pool[g_pool_count++] = { voice, (uint32_t)g_current_frame };
    } else {
        // Pool full — force-flush oldest
        actually_destroy_voice(g_pool[0].voice);
        memmove(&g_pool[0], &g_pool[1], (MAX_RETAINED - 1) * sizeof(Entry));
        g_pool[MAX_RETAINED - 1] = { voice, (uint32_t)g_current_frame };
    }

    rblog::write("VOICE-POOL: deferred destroy of voice 0x%llX (pool=%d)",
                 (unsigned long long)voice, g_pool_count);
}

// Helper: defer and null a voice pointer field
static void defer_and_null(uintptr_t addr) {
    // Engine off => the pool serves no purpose. Do nothing and let the hooked orig() run its
    // full stock destroy on this field. (Pre-nulling here would make orig skip its own teardown
    // bookkeeping — so the no-op must leave the field untouched.)
    if (!resim::engine_enabled()) return;

    uintptr_t voice = *(uintptr_t*)addr;
    if (voice) {
        defer_destroy_voice(voice);
        *(uintptr_t*)addr = 0;
    }
}

// Canonical-pointer guard. The sAudio singleton (*(0x140E18520)) and its sub-pointers can be
// transiently POISONED (~-1) during the engine's own audio teardown at a scene transition — a
// non-null garbage value that a plain `if (ptr)` check lets through, then deref AVs (the 0x14350D8EB
// crash: mov [sAudio+0x38] with sAudio=0xFFFFFFFFFFFFFFC7). Validate canonical range before walking.
static inline bool canon(uintptr_t p) { return p >= 0x10000 && p < 0x7FFFFFFFFFFFULL; }

// --- Channel-manager poison guard -----------------------
// Three play-path functions double-deref the channel-mgr ptr at *(sSound+0x38) with NO canon check:
// FUN_1405be310, FUN_1405d43f0 (per-tick), FUN_1405d4380 (NULL-only guard, no canon). A poison sMgr
// (~-1) during scene-transition teardown / post-rollback => (**(code**)(**(mgr)+8))(...) AVs (the
// 0x14350D8EB family). The guard returns each function's OWN "no channel acquired" result — the
// dormant path it already takes when the resolved channel is null — so a poison window yields
// SILENCE, never an AV. Audio is a pure output leaf, so a skipped channel re-derives on the next
// normal frame (GGPO-correct). It also gates orig() in the batch/shutdown hooks, whose orig
// double-derefs sMgr too. No-op in vanilla (canon passes => orig runs identically); diverges only on
// a poison ptr that would otherwise crash. No key bound — flip g_chanmgr_guard to A/B.
static volatile LONG   g_chanmgr_guard = 1;
// RESIM SOUND GATE: sound is a pure output leaf and the sSound body is PRESERVE-WHOLE (never rewound). But the resim
// replays frames N..now and only RENDER is suppressed — audio is not, so every sound re-fires (and, sound being
// un-rewound, double-fires) on each rollback (GGPO-incorrect stutter), and the chanmgr churns channel state that
// references soon-freed XAudio2 objects during the replay. Block channel ACQUIRE/UPDATE during resim; sound re-derives
// on the first normal frame. Determinism-safe (sound not in gp_crc). Default ON; flip to A/B.
static volatile LONG   g_resim_sound_block = 1;
static volatile LONG64 c_be310_skip = 0, c_d43f0_skip = 0, c_d4380_skip = 0, c_batch_skip = 0;

// sSound and its channel-mgr pointer both canonical => safe to dispatch through *(sSound+0x38).
static inline bool chanmgr_ok() {
    uintptr_t sAudio = *(uintptr_t*)addr::resolve(0x140E18520);
    return canon(sAudio) && canon(*(uintptr_t*)(sAudio + 0x38));
}

// ============================================================
// Hook typedefs and originals
// ============================================================

typedef void (*fn_param1)(uintptr_t);
typedef void (*fn_void)(void);
typedef uint64_t (*fn_u64_p1)(uintptr_t);

static fn_param1 orig_1405d5810 = nullptr;  // single voice dtor
static fn_param1 orig_1405c1340 = nullptr;  // voice recreate
static fn_param1 orig_1405c7040 = nullptr;  // bank0 channel destroy
static fn_void   orig_1405cd300 = nullptr;  // bank0 batch
static fn_param1 orig_1405c6c10 = nullptr;  // shutdown
static fn_param1 orig_1405c70a0 = nullptr;  // bank1 channel destroy
static fn_void   orig_1405cd3a0 = nullptr;  // bank1 batch
static fn_param1 orig_1405cd440 = nullptr;  // bank1 extended
static fn_param1 orig_1405be310 = nullptr;  // chanmgr: bank acquire (void, state==5)
static fn_u64_p1 orig_1405d43f0 = nullptr;  // chanmgr: per-tick channel update (u64)
static fn_u64_p1 orig_1405d4380 = nullptr;  // chanmgr: channel acquire (u64, NULL->canon)

// ============================================================
// Hooks
// ============================================================

// FUN_1405d5810 — single voice at param_1+0x18
static void hk_1405d5810(uintptr_t param_1) {
    defer_and_null(param_1 + 0x18);
    orig_1405d5810(param_1);
}

// FUN_1405c1340 — destroy voice at +0x18, then create new one
static void hk_1405c1340(uintptr_t param_1) {
    defer_and_null(param_1 + 0x18);
    orig_1405c1340(param_1);  // original creates new voice into +0x18
}

// FUN_1405c7040 — bank0 channel: destroy +0x20, +0x28, +0x30
static void hk_1405c7040(uintptr_t param_1) {
    defer_and_null(param_1 + 0x20);
    defer_and_null(param_1 + 0x28);
    defer_and_null(param_1 + 0x30);
    orig_1405c7040(param_1);
}

// FUN_1405cd300 — batch: 32 bank0 channels, destroy +0x20/28/30 each
static void hk_1405cd300(void) {
    // poison sMgr => the pre-walk and orig() both double-deref it and AV; skip both (nothing valid to destroy)
    if (g_chanmgr_guard && !chanmgr_ok()) { _InterlockedIncrement64(&c_batch_skip); return; }
    uintptr_t sAudio = *(uintptr_t*)addr::resolve(0x140E18520);
    if (canon(sAudio)) {
        uintptr_t sMgr = *(uintptr_t*)(sAudio + 0x38);
        if (canon(sMgr)) {
            for (int i = 0; i < 32; i++) {
                uintptr_t ch = *(uintptr_t*)(sMgr + 0x08 + i * 8);
                if (!canon(ch)) continue;
                defer_and_null(ch + 0x20);
                defer_and_null(ch + 0x28);
                defer_and_null(ch + 0x30);
            }
        }
    }
    orig_1405cd300();
}

// FUN_1405c6c10 — shutdown. Calls 1405cd300, 1405cd3a0, 1405cd440 (all hooked).
// Only need to handle voices it destroys directly: extra channel +0x18, param_1+0x40.
static void hk_1405c6c10(uintptr_t param_1) {
    // Extra channel: sMgr+0x148 → +0x18
    uintptr_t sAudio = *(uintptr_t*)addr::resolve(0x140E18520);
    if (canon(sAudio)) {
        uintptr_t sMgr = *(uintptr_t*)(sAudio + 0x38);
        if (canon(sMgr)) {
            uintptr_t extra = *(uintptr_t*)(sMgr + 0x148);
            if (canon(extra)) {
                defer_and_null(extra + 0x18);
            }
        }
    }
    // param_1[8] = *(param_1 + 0x40) — master voice (sMgr-independent, keep it)
    defer_and_null(param_1 + 0x40);
    // orig double-derefs *(sSound+0x38); skip on poison sMgr (incomplete-but-alive teardown beats an AV)
    if (g_chanmgr_guard && !chanmgr_ok()) { _InterlockedIncrement64(&c_batch_skip); return; }
    orig_1405c6c10(param_1);
}

// FUN_1405c70a0 — bank1 channel: destroy +0x20, +0x28, +0x30
static void hk_1405c70a0(uintptr_t param_1) {
    defer_and_null(param_1 + 0x20);
    defer_and_null(param_1 + 0x28);
    defer_and_null(param_1 + 0x30);
    orig_1405c70a0(param_1);
}

// FUN_1405cd3a0 — batch: 8 bank1 channels, destroy +0x20/28/30 each
static void hk_1405cd3a0(void) {
    // poison sMgr => the pre-walk and orig() both double-deref it and AV; skip both
    if (g_chanmgr_guard && !chanmgr_ok()) { _InterlockedIncrement64(&c_batch_skip); return; }
    uintptr_t sAudio = *(uintptr_t*)addr::resolve(0x140E18520);
    if (canon(sAudio)) {
        uintptr_t sMgr = *(uintptr_t*)(sAudio + 0x38);
        if (canon(sMgr)) {
            for (int i = 0; i < 8; i++) {
                uintptr_t ch = *(uintptr_t*)(sMgr + 0x108 + i * 8);
                if (!canon(ch)) continue;
                defer_and_null(ch + 0x20);
                defer_and_null(ch + 0x28);
                defer_and_null(ch + 0x30);
            }
        }
    }
    orig_1405cd3a0();
}

// FUN_1405cd440 — bank1 extended: 16 at +0x88, 4 at +0x108, 4 at +0x68, +0x60, +0x58
static void hk_1405cd440(uintptr_t param_1) {
    // 16 voices at +0x88 through +0x100 (4×4 grid, stride 8)
    for (int i = 0; i < 16; i++)
        defer_and_null(param_1 + 0x88 + i * 8);
    // 4 voices at +0x108 through +0x120
    for (int i = 0; i < 4; i++)
        defer_and_null(param_1 + 0x108 + i * 8);
    // 4 voices at +0x68 through +0x80
    for (int i = 0; i < 4; i++)
        defer_and_null(param_1 + 0x68 + i * 8);
    // +0x60, +0x58
    defer_and_null(param_1 + 0x60);
    defer_and_null(param_1 + 0x58);
    orig_1405cd440(param_1);
}

// ---- Channel-manager poison guards (the 3 genuinely-unguarded play-path double-deref sites) ----

// FUN_1405be310 (void): plVar1 = (**(mgr+8))(mgr,1,id);... dispatch +0x88/+0x90. NO guard at all.
static void hk_1405be310(uintptr_t param_1) {
    if (g_resim_sound_block && resim::resim_active()) return;   // GGPO: silence the replay; sound re-derives on the first normal frame
    if (g_chanmgr_guard && !chanmgr_ok()) {
        LONG64 n = _InterlockedIncrement64(&c_be310_skip);
        if (n <= 8) rblog::write("CHANMGR-GUARD: skipped FUN_1405be310 (poison sMgr) — silence, no AV");
        return;  // matches the function's own plVar1==0 dormant path
    }
    orig_1405be310(param_1);
}

// FUN_1405d43f0 (u64, PER-TICK): plVar1 = (**(mgr+8))(mgr,0,id);... NO guard. Returns 1 ok / 0 none.
static uint64_t hk_1405d43f0(uintptr_t param_1) {
    if (g_resim_sound_block && resim::resim_active()) return 0;   // GGPO: no channel during the replay
    if (g_chanmgr_guard && !chanmgr_ok()) {
        LONG64 n = _InterlockedIncrement64(&c_d43f0_skip);
        if (n <= 8) rblog::write("CHANMGR-GUARD: skipped FUN_1405d43f0 (poison sMgr) — return 0 (no channel)");
        return 0;  // its own "no channel acquired" result
    }
    return orig_1405d43f0(param_1);
}

// FUN_1405d4380 (u64): NULL-guards DAT_140e18520 but not *(sSound+0x38). Returns 1 ok / 0 none.
static uint64_t hk_1405d4380(uintptr_t param_1) {
    if (g_resim_sound_block && resim::resim_active()) return 0;   // GGPO: no channel acquire during the replay
    if (g_chanmgr_guard && !chanmgr_ok()) {
        LONG64 n = _InterlockedIncrement64(&c_d4380_skip);
        if (n <= 8) rblog::write("CHANMGR-GUARD: skipped FUN_1405d4380 (poison sMgr) — return 0 (no channel)");
        return 0;
    }
    return orig_1405d4380(param_1);
}

// ============================================================
// Public API
// ============================================================

void init() {
    struct HookDef {
        uintptr_t ida_addr;
        void* hook;
        void** orig;
        const char* name;
    };

    HookDef hooks[] = {
        { 0x1405D5810, (void*)hk_1405d5810, (void**)&orig_1405d5810, "voice_dtor_single" },
        { 0x1405C1340, (void*)hk_1405c1340, (void**)&orig_1405c1340, "voice_recreate" },
        { 0x1405C7040, (void*)hk_1405c7040, (void**)&orig_1405c7040, "bank0_ch_destroy" },
        { 0x1405CD300, (void*)hk_1405cd300, (void**)&orig_1405cd300, "bank0_batch" },
        { 0x1405C6C10, (void*)hk_1405c6c10, (void**)&orig_1405c6c10, "shutdown" },
        { 0x1405C70A0, (void*)hk_1405c70a0, (void**)&orig_1405c70a0, "bank1_ch_destroy" },
        { 0x1405CD3A0, (void*)hk_1405cd3a0, (void**)&orig_1405cd3a0, "bank1_batch" },
        { 0x1405CD440, (void*)hk_1405cd440, (void**)&orig_1405cd440, "bank1_extended" },
        // channel-mgr poison guards — the 3 unguarded *(sSound+0x38) double-deref sites
        { 0x1405BE310, (void*)hk_1405be310, (void**)&orig_1405be310, "chanmgr_be310" },
        { 0x1405D43F0, (void*)hk_1405d43f0, (void**)&orig_1405d43f0, "chanmgr_d43f0" },
        { 0x1405D4380, (void*)hk_1405d4380, (void**)&orig_1405d4380, "chanmgr_d4380" },
    };

    int hook_count = 0;
    for (auto& h : hooks) {
        auto target = (LPVOID)addr::resolve(h.ida_addr);
        MH_STATUS st = MH_CreateHook(target, h.hook, h.orig);
        if (st == MH_OK) {
            hook_count++;
            rblog::write("VOICE-POOL: hooked %s at 0x%llX", h.name,
                         (unsigned long long)h.ida_addr);
        } else {
            rblog::write("VOICE-POOL: FAILED to hook %s (err=%d)", h.name, st);
        }
    }

    rblog::write("VOICE-POOL: initialized, %d hooks active", hook_count);
}

void on_frame(int frame) {
    g_current_frame = frame;
    if (g_flush_paused) return;

    int keep = 0;
    int flushed = 0;
    for (int i = 0; i < g_pool_count; i++) {
        if ((int)(frame - (int)g_pool[i].destroy_frame) <= FLUSH_DELAY) {
            g_pool[keep++] = g_pool[i];
        } else {
            actually_destroy_voice(g_pool[i].voice);
            flushed++;
        }
    }
    if (flushed > 0) {
        rblog::write("VOICE-POOL: flushed %d voices, retained %d", flushed, keep);
    }
    g_pool_count = keep;
}

void pause_flush() { g_flush_paused = true; }
void resume_flush() { g_flush_paused = false; }

// Re-stamp only. A cancel-future-destroys variant (drop entries whose game-destroy frame is past the target,
// keeping the voice alive) stopped the 0x1405BEFE5 crash but kept STALE voices alive in the XAudio2 graph; normal
// play then re-pumped them => garbled audio. Sound is an output leaf — leaking live voices into the graph breaks
// it. So: extend the flush timer across the resim window; voices still get destroyed on the timer, no leak. The
// stale-voice crash is handled by sound_edge_reconcile instead.
void on_rollback(int target_frame) {
    (void)target_frame;
    for (int i = 0; i < g_pool_count; i++)
        g_pool[i].destroy_frame = (uint32_t)g_current_frame;   // re-stamp only (original refresh_all behavior)
    if (g_pool_count > 0)
        rblog::write("VOICE-POOL: on_rollback re-stamped %d entries", g_pool_count);
}

// Immediately destroy everything still pooled. Called when the rollback engine goes OFF —
// any voice held for the (now-closed) rollback window must be released so it does not strand
// the engine's audio drain in the engine-off period.
void flush_all() {
    int n = g_pool_count;
    for (int i = 0; i < g_pool_count; i++)
        actually_destroy_voice(g_pool[i].voice);
    g_pool_count = 0;
    if (n > 0)
        rblog::write("VOICE-POOL: flush_all destroyed %d pooled voices (engine off)", n);
}

} // namespace voice_pool
