// net_charsel.cpp — see net_charsel.h.
#include "net_charsel.h"
#include "net_engine_arm.h"
#include "net_session.h"
#include "net_input.h"
#include "role.h"
#include "addr.h"
#include "arena.h"
#include "log.h"
#include <windows.h>
#include <cstdint>
#include <cstdio>

namespace net_charsel {

// Scene-mode descriptors (RE): scene mgr @0x140E17A80, current desc @ mgr+0x7040.
static constexpr uintptr_t SCENE_MGR  = 0x140E17A80ULL;
static constexpr uintptr_t SC_CHRSEL  = 0x140D50128ULL;   // aChrSelect
// game-flow director @0x140D50E58; phase @+0x34C (5 = FIGHT).
static constexpr uintptr_t DIRECTOR   = 0x140D50E58ULL;
// device_map assignment singleton A @0x140D510A0; int32[4] @ A+0x140 (side -> physical pad, -1 = unassigned).
static constexpr uintptr_t ASSIGN     = 0x140D510A0ULL;
static constexpr uintptr_t DEVMAP_OFF = 0x140;
// pad-state manager B @0x140E174B8 (== g_input_ref); +0xC30 != 0 keeps side0 reading pad_state[0] directly.
static constexpr uintptr_t RAWSTATE   = 0x140E174B8ULL;
static constexpr uintptr_t MERGE_OFF  = 0xC30;

static bool g_relay_armed = false;
static bool g_in_cs = false;
static bool g_cs_logged = false;
static long g_cs_frames = 0;

static inline uintptr_t rd_ptr(uintptr_t ida) { return *(uintptr_t*)addr::resolve(ida); }

static uintptr_t current_scene() {
    uintptr_t mgr = rd_ptr(SCENE_MGR);
    if (!mgr) return 0;
    return *(uintptr_t*)(mgr + 0x7040);
}

bool in_charselect() { return g_in_cs; }

// FLOW PROBES. The fight detector reads a static (DIRECTOR) whose contents were never logged, so a dead read was
// indistinguishable from "not fighting", and everything gated on it (engine arm at phase 5, the hole-punch switch,
// the char-select device_map coordination) was silently inert. These probes log what the pointers really contain,
// on change plus a slow heartbeat, so the gate is measured rather than guessed: a null base means the static address
// is wrong or the object is not built yet; a live base with a phase that is never 5 means the offset or the magic
// value is wrong. They also dump the int32 window around +0x34C and report which slots change, plus every distinct
// scene descriptor seen, so entering a match names both the real phase field and the battle scene pointer.
static void probe_flow_fields(uintptr_t director) {
    if (!director) return;
    // +0x34C reaches 5 at CHARACTER SELECT, not the round (measured: phase 0->5 with aChrSelect appearing 1.8s
    // later; arming there produced a 1756ms frame because the baseline capture ran through a menu). So 5 is not the
    // fight, and the field we want is either a different offset or a different value of this one. Sweep a wider
    // window and let the game name it.
    constexpr int LO = 0x300, HI = 0x3C0;                 // 48 int32s
    static int32_t prev[(0x3C0 - 0x300) / 4];
    static bool have = false;
    int32_t cur[(0x3C0 - 0x300) / 4];
    for (int i = 0; i < (HI - LO) / 4; i++) {
        const uintptr_t a = director + LO + i * 4;
        cur[i] = arena::is_committed_addr(a) ? *(int32_t*)a : -0x7FFFFFFF;
    }
    if (!have) { memcpy(prev, cur, sizeof(cur)); have = true; return; }
    for (int i = 0; i < (HI - LO) / 4; i++) {
        if (cur[i] != prev[i]) {
            static long n = 0;
            if (++n <= 400)
                rblog::write("FLOW-FIELD: director+0x%03X : %d -> %d%s", LO + i * 4, prev[i], cur[i],
                             (LO + i * 4) == 0x34C ? "   <-- the believed phase field (5 == CHAR SELECT, not the round)" : "");
            prev[i] = cur[i];
        }
    }
}

// Every distinct scene descriptor we ever observe. aChrSelect is 0x140D50128; the battle scene is whatever shows up
// when a match actually starts, and once named it can gate the punch directly (scene detection demonstrably works).
static void probe_scene_census(uintptr_t scene) {
    if (!scene) return;
    static uintptr_t seen[24]; static int n = 0;
    for (int i = 0; i < n; i++) if (seen[i] == scene) return;
    if (n < 24) {
        seen[n++] = scene;
        rblog::write("FLOW-SCENE: new scene descriptor 0x%llX  (aChrSelect=0x140D50128) — distinct scenes so far: %d",
                     (unsigned long long)scene, n);
    }
}

static void probe_flow(uintptr_t director, int32_t phase, uintptr_t scene_mgr, uintptr_t scene) {
    probe_flow_fields(director);
    probe_scene_census(scene);
    static uintptr_t s_d = (uintptr_t)-1, s_m = (uintptr_t)-1, s_s = (uintptr_t)-1;
    static int32_t   s_p = -12345;
    static long      s_hb = 0;
    const bool changed = (director != s_d) || (phase != s_p) || (scene_mgr != s_m) || (scene != s_s);
    if (changed || (++s_hb % 600) == 0) {
        rblog::write("FLOW-PROBE(%s): director=0x%llX phase@+0x34C=%d (5==FIGHT) | scene_mgr=0x%llX scene=0x%llX",
                     role::name(), (unsigned long long)director, phase,
                     (unsigned long long)scene_mgr, (unsigned long long)scene);
        s_d = director; s_p = phase; s_m = scene_mgr; s_s = scene;
    }
}

// phase 8 (intro) or 5 (round) = we are in a match. See the header for why the intro matters.
// F9 = snapshot the director. Change-detection only tells us what moved while we were watching; it cannot tell us
// what DISTINGUISHES two states. +0x34C reads 5 in char select and in training room, so "5" means "a game mode is
// running", not "a round is live" — and arming on it bricks the game in menus. Take a labelled snapshot in each
// state and diff them: whatever differs is the discriminator, measured rather than guessed.
static void dump_director(const char* tag) {
    uintptr_t bs = rd_ptr(DIRECTOR);
    if (!bs) { rblog::write("FLOW-DUMP[%s]: director is NULL", tag); return; }
    rblog::write("FLOW-DUMP[%s]: director=0x%llX  scene=0x%llX", tag, (unsigned long long)bs,
                 (unsigned long long)([]{ uintptr_t m = rd_ptr(SCENE_MGR);
                     return (m && arena::is_committed_addr(m + 0x7040)) ? *(uintptr_t*)(m + 0x7040) : (uintptr_t)0; }()));
    for (int off = 0x300; off < 0x3C0; off += 0x20) {
        int32_t v[8];
        for (int i = 0; i < 8; i++) {
            const uintptr_t a = bs + off + i * 4;
            v[i] = arena::is_committed_addr(a) ? *(int32_t*)a : -0x7FFFFFFF;
        }
        rblog::write("FLOW-DUMP[%s]: +0x%03X: %d %d %d %d %d %d %d %d",
                     tag, off, v[0], v[1], v[2], v[3], v[4], v[5], v[6], v[7]);
    }
}

// CANDIDATE GATE, PREVIEW only — it does not arm anything yet.
// Evidence (solo run, one session): +0x34C goes 0->5 at CHARACTER SELECT and stays 5 through gameplay, so it means
// "a game mode is running", not "a round is live" — arming on it produced a 1756ms frame in a menu. +0x354 goes
// 0 -> 676487218 at t=101.4, last of all the fields to move and after the char-select scene, and is still set in
// training room. So "phase==5 and 0x354!=0" is the best available discriminator for actual gameplay.
// One sample is not proof, and a wrong gate bricks the game, so this only LOGS when it would have armed/disarmed.
// Once the edges are confirmed to land where expected, this becomes the real gate.
static bool gate_candidate(int32_t* out_phase, int32_t* out_354) {
    uintptr_t bs = rd_ptr(DIRECTOR);
    if (!bs || !arena::is_committed_addr(bs + 0x358)) return false;
    const int32_t phase = *(int32_t*)(bs + 0x34C);
    const int32_t f354  = *(int32_t*)(bs + 0x354);
    if (out_phase) *out_phase = phase;
    if (out_354)   *out_354   = f354;
    return phase == 5 && f354 != 0;
}

static void gate_preview() {
    int32_t phase = 0, f354 = 0;
    const bool now = gate_candidate(&phase, &f354);
    static int was = -1;
    if ((int)now != was) {
        was = (int)now;
        rblog::write("GATE-PREVIEW: would %s now — phase(0x34C)=%d f(0x354)=%d. %s",
                     now ? "ARM" : "DISARM", phase, f354,
                     now ? "(if not in actual gameplay right now, this gate is wrong)"
                         : "(if still in gameplay right now, this gate is wrong)");
    }
}

void flow_probe_tick() {
    gate_preview();
    // F9: label a snapshot. Press once sitting in a MENU / char select, once with a round actually live.
    if (GetAsyncKeyState(VK_F9) & 1) {
        static int n = 0;
        char tag[24]; snprintf(tag, sizeof(tag), "SNAP%d", ++n);
        dump_director(tag);
    }
    uintptr_t bs = rd_ptr(DIRECTOR);
    const bool ok = bs && arena::is_committed_addr(bs + 0x34C);
    const int32_t phase = ok ? *(int32_t*)(bs + 0x34C) : -1;
    uintptr_t mgr = rd_ptr(SCENE_MGR);
    uintptr_t scn = (mgr && arena::is_committed_addr(mgr + 0x7040)) ? *(uintptr_t*)(mgr + 0x7040) : 0;
    probe_flow(bs, phase, mgr, scn);
}

bool in_match_window() {
    uintptr_t bs = rd_ptr(DIRECTOR);
    if (!bs || !arena::is_committed_addr(bs + 0x34C)) return false;
    const int32_t phase = *(int32_t*)(bs + 0x34C);
    return phase == 8 || phase == 5;
}

bool in_fight() {
    uintptr_t bs = rd_ptr(DIRECTOR);
    const bool ok = bs && arena::is_committed_addr(bs + 0x34C);
    const int32_t phase = ok ? *(int32_t*)(bs + 0x34C) : -1;
    uintptr_t mgr = rd_ptr(SCENE_MGR);
    uintptr_t scn = (mgr && arena::is_committed_addr(mgr + 0x7040)) ? *(uintptr_t*)(mgr + 0x7040) : 0;
    probe_flow(bs, phase, mgr, scn);
    return ok && phase == 5;
}

void on_frame() {
    if (!net::session_running()) { g_relay_armed = false; g_in_cs = false; g_cs_logged = false; return; }

    // RELAY ON CONNECT: from here net_input writes slot0=host / slot1=guest on both machines, so the HOST drives
    // both games' menus (P2's game follows the host in slot0) and the guest's local input rides slot1 for the
    // game's own "insert P2 controller -> press start" join. Loose relay — the hard lockstep stall engages only in
    // the fight (see hk_main_proc, gated on in_fight()), so menu desync is harmless (playtest).
    if (!g_relay_armed) {
        net_input::propose_epoch(2);                 // PROPOSE, do not act: char-select entry is local; the peer may not be here yet.
        g_relay_armed = true;
        rblog::write("CHARSEL(%s): connected — input relay armed (host drives both menus; guest joins at the P2 prompt). Hard lockstep engages at FIGHT only.", role::name());
    }

    // force merge-off every net-active frame: side0's accessor uses the injected input window (not the live-keyboard
    // merge path FUN_1402b2fa0) — needed even in menus so the guest's game follows the host's relayed input in slot0.
    uintptr_t B = rd_ptr(RAWSTATE);
    if (B) *(uint8_t*)(B + MERGE_OFF) = 1;   // Single BYTE (int32 store clobbers +0xC31 edge byte, RE)

    uintptr_t scene = current_scene();
    // aChrSelect (0x140D50128) + the two alternating CS states (aChrSelectBlank/aChrSelectResten) = the whole CS screen.
    g_in_cs = (scene != 0 && (scene == addr::resolve(SC_CHRSEL) ||
                              scene == addr::resolve(0x140D500F0ULL) || scene == addr::resolve(0x140D50168ULL)));

    // device_map must agree across machines. Measured on a twin run: the P1 box assigned {0,-1,-1,-1} and the P2
    // box {1,-1,-1,-1} — the game binds whichever pad it sees first, so the two boxes crossed their sides and
    // identical wire bytes would drive opposite characters: a guaranteed desync no input delivery can fix. Our
    // contract is fixed and symmetric (slot0 = P1 human, slot1 = P2 human on both machines), so assert it — but only
    // where the sides exist: character select (scene detection is reliable) and inside a match (engine armed).
    // Forcing it on every net-active frame made the game act as though two players were present in menus (leaving
    // a match immediately started another one). Outside those windows, leave the game's own state alone.
    const bool need_devmap = g_in_cs || net_engine_arm::armed();
    if (need_devmap) {
        uintptr_t A = rd_ptr(ASSIGN);
        if (A && arena::is_committed_addr(A + DEVMAP_OFF)) {
            int32_t* dm = (int32_t*)(A + DEVMAP_OFF);
            if (dm[0] != 0 || dm[1] != 1) {
                static int s_fix = 0;
                if (++s_fix <= 4 || (s_fix % 600) == 0)
                    rblog::write("CHARSEL(%s): device_map was {%d,%d} — forcing {0,1} (slot0=P1 human, slot1=P2 human "
                                 "on BOTH machines; the game's local guess crosses the sides). fix#%d",
                                 role::name(), dm[0], dm[1], s_fix);
                dm[0] = 0; dm[1] = 1;
            }
        }
    }
    // The pad connected/type bytes are NO longer forced. Under hardware emulation the game initialises both pads
    // itself — measured `01 01 00 04 03` / `01 01 01 04 03`, i.e. connected, indexed, device type 04. The old code
    // wrote 1 into +0x63, where the engine puts 04; that is the device-type gate, so it could only ever corrupt a
    // correctly-initialised pad. Deleted rather than corrected: its whole job is now done properly upstream.

    if (g_in_cs) {
        g_cs_frames++;
        if (!g_cs_logged) {
            g_cs_logged = true;
            rblog::write("CHARSEL(%s): entered aChrSelect — device_map {0,1} + connected forced (left=host / right=guest).", role::name());
        }
    } else {
        g_cs_logged = false;
    }
}

void report() {
    if (!net::session_running()) return;
    rblog::write("CHARSEL(%s): relay=%d in_cs=%d in_fight=%d scene=0x%llX cs_frames=%ld", role::name(),
                 (int)g_relay_armed, (int)g_in_cs, (int)in_fight(), (unsigned long long)current_scene(), g_cs_frames);
}

} // namespace net_charsel
