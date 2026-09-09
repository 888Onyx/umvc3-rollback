// input.cpp — the input dispatch hook. Captures the per-pad input blocks (0x2E0 bytes each) per frame into a
// ring; on replay it either re-injects the captured block (solo) or lets the engine re-derive from the XInput seam
// (netplay). Also hosts the opt-in ground-truth dumps used to reverse-engineer the input window.

#include "input.h"
#include "net_input.h"
#include "dinput_probe.h"
#include "addr.h"
#include "arena.h"
#include "net_session.h"
#include "addr.h"
#include "log.h"
#include <MinHook.h>
#include <windows.h>
#include <cstring>
#include <cstdint>

namespace {

// Geometry now lives in input.h (RE-corrected to 0x2E0 stride) — was a wrong 550/0x2C0 that
// truncated pad1's command-history tail; harmless to single-machine resim, a cross-machine desync for netplay.
using input::PLAYER_INPUT_SIZE;
using input::P2_OFFSET;

// Ring buffer
constexpr int RING_SIZE = 128;

struct FrameInput {
    uint8_t p1[PLAYER_INPUT_SIZE];
    uint8_t p2[PLAYER_INPUT_SIZE];
    int     frame;
};

static FrameInput g_ring[RING_SIZE];
static uintptr_t  g_input_ref = 0;      // Game's input buffer base address
static bool        g_injecting = false;  // True during resim inject mode

// Hook for INPUT_DISPATCH (0x1402B41B0)
static constexpr uintptr_t INPUT_DISPATCH_IDA = 0x1402B41B0;
typedef void (*input_dispatch_fn)(int64_t param_1);
static input_dispatch_fn orig_input_dispatch = nullptr;

static void hk_input_dispatch(int64_t param_1) {
    // Capture input buffer address on first call
    if (!g_input_ref) {
        g_input_ref = (uintptr_t)param_1;
        rblog::write("INPUT: buffer captured at 0x%llX", (unsigned long long)param_1);
    }

    if (g_injecting) {
        // Under HARDWARE EMULATION, REPLAY must RE-DERIVE, not RE-INJECT.
        // Legacy behaviour (still used when netplay is disarmed): skip orig and let inject()'s saved 736-byte pad
        // block stand. That replays the input WE CAPTURED LOCALLY the first time — i.e. the mispredicted guess — which
        // makes a rollback faithfully reproduce the wrong frame. It is also the derived-window injection we removed
        // from the live path, so live and replay would derive their edges by different mechanisms.
        // With netplay armed we instead let orig run: our XInput hook serves the CORRECTED bytes for the replayed
        // frame (see pad_for_engine_frame) and the engine derives held/prev/press-edge/etc from them exactly as it
        // does live. Same code path forward and backward, which is the only version worth trusting.
        // The original reason for skipping — "avoids consuming OS input events" — is measurably obsolete: this game
        // polls immediate-mode only (GetDeviceData=0 across 11,125 polls), so there is no event queue to consume.
        if (!net::session_armed()) return;
    }

    // Catch XINPUT1_3.dll the frame it loads — it is LoadLibrary'd lazily and the game enumerates pad slots once,
    // early. Hooking it from the 10s reporter meant we first saw it 76s in, far too late to influence that
    // enumeration, which is exactly what the substitution hook must do. One bool test per frame once hooked.
    dinput_probe::poll_xinput();

    // ORDER IS LOAD-BEARING: capture + resolve must run before the game polls, because the poll is what CONSUMES
    // them. The old code ran after orig_input_dispatch and wrote the derived window post-hoc, which is precisely why
    // the engine kept deriving its edges from LOCAL hardware instead of from the network input.
    net_input::on_frame_begin();

    // Now let the game read input. Its XInput poll lands in our hook, which serves the bytes just resolved.
    orig_input_dispatch(param_1);

    // GROUND-TRUTH WINDOW DUMP — runs even with netplay DISARMED, which is the whole point.
    // The netplay dump can only ever show a MIXTURE of the engine's derivation and our own previous injection, so it
    // can never establish what the fields mean. RE narrowed the exposed fields to exactly three — u32[0] @+0x1BC,
    // u32[2] @+0x1C4, u32[5] @+0x1D0, each with a per-pad and an OR-across-all-pads accessor — but not their
    // semantics, and a static search for the writer hit a false trail (0x140254640 turned out to be the button-config
    // screen writing a different object at the same offset).
    // So: measure. With no injection, hold one button and watch which of the three moves and for how long. The field
    // that stays hot for the whole hold is the LEVEL; one that fires for a single frame is the PRESS edge; one that
    // fires only on let-go is RELEASE. Opt-in via `window_dump.txt` beside the exe so normal runs stay quiet.
    {
        static int s_on = -1;
        if (s_on < 0) {
            char p[MAX_PATH]; GetModuleFileNameA(NULL, p, MAX_PATH);
            char* sl = strrchr(p, '\\'); if (sl) sl[1] = 0; else p[0] = 0;
            strncat(p, "window_dump.txt", MAX_PATH - strlen(p) - 1);
            s_on = (GetFileAttributesA(p) != INVALID_FILE_ATTRIBUTES) ? 1 : 0;
            if (s_on) rblog::write("WINDOW-DUMP armed — logging pad0/pad1 input windows every frame they change "
                                   "(works with netplay disarmed; this is the uncontaminated ground truth).");
        }
        if (s_on && g_input_ref) {
            const uint32_t* w0 = (const uint32_t*)(g_input_ref + 0x1BC);
            const uint32_t* w1 = (const uint32_t*)(g_input_ref + 0x2E0 + 0x1BC);
            static uint32_t prev0[11] = {0}, prev1[11] = {0};
            static long frame = 0; frame++;
            if (memcmp(prev0, w0, 44) != 0 || memcmp(prev1, w1, 44) != 0) {
                rblog::write("WINDOW f%ld pad0: %08X %08X %08X %08X %08X %08X %08X %08X %08X %08X %08X",
                             frame, w0[0],w0[1],w0[2],w0[3],w0[4],w0[5],w0[6],w0[7],w0[8],w0[9],w0[10]);
                rblog::write("WINDOW f%ld pad1: %08X %08X %08X %08X %08X %08X %08X %08X %08X %08X %08X",
                             frame, w1[0],w1[1],w1[2],w1[3],w1[4],w1[5],w1[6],w1[7],w1[8],w1[9],w1[10]);
                memcpy(prev0, w0, 44); memcpy(prev1, w1, 44);
            }
        }
    }
    // Feed the passive control-scheme detector: we know the raw bits we presented on each slot, and the engine has
    // just derived that pad's window. The difference between them IS this machine's button config, observed. Always
    // on and read-only — it never writes and never synthesizes input; it only learns from single-button frames.
    if (g_input_ref) {
        for (int slot = 0; slot < 2; slot++) {
            uintptr_t pad = g_input_ref + (uintptr_t)slot * PLAYER_INPUT_SIZE;
            if (!arena::is_committed_addr(pad + 0x1BC)) continue;
            dinput_probe::observe_mapping(slot, dinput_probe::presented_buttons(slot),
                                          *(const uint32_t*)(pad + 0x1BC));
        }
    }

    // PAD-LANE AUDIT — dumps the three lanes between XInput and gameplay side by side, so a lost button can be
    // placed rather than argued about:
    // (1) XInput -> pad-state array. Does pad-state[1]'s input window actually carry the buttons we synthesized?
    // If w[0] moves for pad1 when you press a button, this lane is fine.
    // (2) The per-pad CONNECTED/type bytes (B + i*0x2E0 + 0x60 / +0x63). net_charsel force-writes these at
    // char-select precisely because the game's own join usually sets them — if pad1's are clear, the game does
    // not consider that pad present even though XInput says it is.
    // (3) device_map int32[4] @ ASSIGN+0x140: side -> physical pad, -1 = UNASSIGNED. This is the likeliest break:
    // the "press START to join" prompt exists to WRITE this table, and if entry [1] stays -1 then P2 has no
    // pad bound and its Start can never be read regardless of how perfectly we answer XInput.
    // Opt-in via `pad_audit.txt`; logs only on CHANGE (plus a slow heartbeat) so it can never spam per frame.
    {
        static int s_on = -1;
        if (s_on < 0) {
            char p[MAX_PATH]; GetModuleFileNameA(NULL, p, MAX_PATH);
            char* sl = strrchr(p, '\\'); if (sl) sl[1] = 0; else p[0] = 0;
            strncat(p, "pad_audit.txt", MAX_PATH - strlen(p) - 1);
            s_on = (GetFileAttributesA(p) != INVALID_FILE_ATTRIBUTES) ? 1 : 0;
            if (s_on) rblog::write("PAD-AUDIT armed — dumping device_map + per-pad connected/type + input window on change.");
        }
        if (s_on) {
            static constexpr uintptr_t ASSIGN_IDA = 0x140D510A0ULL, DEVMAP = 0x140;
            uintptr_t A = *(uintptr_t*)addr::resolve(ASSIGN_IDA);
            uintptr_t B = g_input_ref;
            struct Snap { int32_t dm[4]; uint8_t hdr[4][8]; uint32_t w0[4]; uint32_t win[2][6]; } cur;
            memset(&cur, 0, sizeof(cur));
            if (A && arena::is_committed_addr(A + DEVMAP)) memcpy(cur.dm, (const void*)(A + DEVMAP), sizeof(cur.dm));
            else for (int i = 0; i < 4; i++) cur.dm[i] = -999;                 // -999 = singleton not resolvable
            if (B) for (int i = 0; i < 4; i++) {
                uintptr_t pad = B + (uintptr_t)i * 0x2E0;
                if (!arena::is_committed_addr(pad + 0x1BC)) continue;
                memcpy(cur.hdr[i], (const void*)(pad + 0x60), 8);
                cur.w0[i] = *(const uint32_t*)(pad + 0x1BC);
                // Level vs EDGE: w0=held, w1=held-last-frame, w2=press edge, w3=release, w4=changed, w5=repeat.
                // A join prompt almost certainly triggers on the press EDGE, not the level. If pad1 receives w0 but
                // its w2 stays 0, the engine is not DERIVING edges for that pad and no amount of correct level data
                // will ever fire the join — which would make the assignment failure a derivation problem, not a
                // policy one. Dump both pads' first six fields so level and edge are directly comparable.
                if (i < 2) memcpy(cur.win[i], (const void*)(pad + 0x1BC), sizeof(cur.win[i]));
            }
            static Snap prev; static bool have = false; static long hb = 0;
            bool changed = !have || memcmp(&prev, &cur, sizeof(cur)) != 0;
            if (changed || (++hb % 1800) == 0) {
                rblog::write("PAD-AUDIT device_map[side->pad] = {%d, %d, %d, %d}   (-1 = UNASSIGNED, -999 = singleton null)",
                             cur.dm[0], cur.dm[1], cur.dm[2], cur.dm[3]);
                for (int i = 0; i < 4; i++)
                    rblog::write("PAD-AUDIT pad%d: +0x60..67 = %02X %02X %02X %02X %02X %02X %02X %02X   held(w0)=%08X",
                                 i, cur.hdr[i][0], cur.hdr[i][1], cur.hdr[i][2], cur.hdr[i][3],
                                 cur.hdr[i][4], cur.hdr[i][5], cur.hdr[i][6], cur.hdr[i][7], cur.w0[i]);
                for (int i = 0; i < 2; i++)
                    rblog::write("PAD-AUDIT pad%d WINDOW: held=%08X prev=%08X PRESS-EDGE=%08X release=%08X changed=%08X repeat=%08X",
                                 i, cur.win[i][0], cur.win[i][1], cur.win[i][2], cur.win[i][3], cur.win[i][4], cur.win[i][5]);
                prev = cur; have = true;
            }
        }
    }

    // Pre-pairing neutral input and the netplay pad substitution both happen at the device seam (dinput_probe);
    // nothing is written into the input block here.
}

} // anonymous namespace

namespace input {

void init() {
    for (int i = 0; i < RING_SIZE; i++) {
        g_ring[i].frame = -1;
    }

    // Install MinHook on INPUT_DISPATCH
    void* target = (void*)addr::resolve(INPUT_DISPATCH_IDA);
    MH_STATUS status = MH_CreateHook(target, (void*)&hk_input_dispatch,
                                      (void**)&orig_input_dispatch);
    if (status != MH_OK) {
        rblog::write("INPUT: MH_CreateHook failed on INPUT_DISPATCH (%d)", status);
        return;
    }
    // Hook is enabled later by MH_EnableHook(MH_ALL_HOOKS) in resim::init()

    rblog::write("INPUT: initialized (ring=%d slots, %d bytes/player)", RING_SIZE, PLAYER_INPUT_SIZE);
}

void capture(int frame) {
    if (!g_input_ref) return;
    int slot = frame % RING_SIZE;
    g_ring[slot].frame = frame;
    memcpy(g_ring[slot].p1, (const void*)g_input_ref, PLAYER_INPUT_SIZE);
    memcpy(g_ring[slot].p2, (const void*)(g_input_ref + P2_OFFSET), PLAYER_INPUT_SIZE);
}

void inject(int frame) {
    if (!g_input_ref) return;
    int slot = frame % RING_SIZE;
    if (g_ring[slot].frame != frame) {
        rblog::write("INPUT: WARNING — inject frame %d not in ring (slot has frame %d)",
                    frame, g_ring[slot].frame);
        return;
    }
    // Write saved input into game buffer before orig runs
    memcpy((void*)g_input_ref, g_ring[slot].p1, PLAYER_INPUT_SIZE);
    memcpy((void*)(g_input_ref + P2_OFFSET), g_ring[slot].p2, PLAYER_INPUT_SIZE);
    g_injecting = true;
}

void stop_inject() {
    g_injecting = false;
}

uintptr_t buffer_base() { return g_input_ref; }

} // namespace input
