// dinput_probe.cpp — the input seam: DirectInput observation plus the XInput device-emulation hook.
//
// Why the seam is at the device
// An earlier design wrote the engine's DERIVED 44-byte input window at padSlot+0x1BC after orig_input_dispatch had
// run. The engine derives w[1..5] (prev-held, press edge, release edge, changed, autorepeat) from the HARDWARE read
// inside that call, so a post-hoc write lands too late: the press edge the game acts on is the one the local
// controller produced, not the one the network sent. That is a write-ORDERING defect, not a field-selection one, and
// no field mask can fix it. The fix is one layer lower: present synthetic device state where the engine reads the
// hardware, and let it derive all eleven window fields itself, in its own order. 1:1 by construction.
//
// Where the device actually enters
// The static import table shows only DirectInput8Create from DINPUT8.dll and no XInput at all, which suggested
// DirectInput was the only gamepad path. Observation disproved that: DirectInput opens GUID_SysMouse and
// GUID_SysKeyboard and nothing else. The binary carries "XINPUT1_3.dll" with no XInput function-name strings — the
// signature of LoadLibrary + GetProcAddress by ordinal. The pad enters through XInput ordinal 2 (XInputGetState) and
// 100 (XInputGetStateEx); that is the seam the netcode drives (xin::present below).
//
// The DirectInput half of this file stays observation-only: it patches vtables to log what the game asks for
// (data format, immediate vs buffered, device count, calls per frame) and forwards every call untouched.
//
// Implementation note: we patch the object's VTABLE rather than writing wrapper COM objects. A wrapper would mean
// reimplementing ~32 methods twice (A and W variants); a vtable patch is a few slots and is shared by every instance
// of the class, which is exactly what we want. Vtables live in read-only data, hence VirtualProtect.
#include "dinput_probe.h"
#include "log.h"
#include "role.h"
#include "resim.h"
#include "net_input.h"
#include "net_session.h"
#include <windows.h>
#include <MinHook.h>
#include <cstdint>
#include <cstring>
#include <cstdio>

namespace dinput_probe {
namespace {

// ---- vtable slot indices (IUnknown occupies 0..2 in both interfaces) ----
// IDirectInput8: 3 CreateDevice
// IDirectInputDevice8: 7 Acquire · 9 GetDeviceState · 10 GetDeviceData · 11 SetDataFormat · 13 SetCooperativeLevel · 25 Poll
constexpr int VT_CREATEDEVICE      = 3;
constexpr int VT_ACQUIRE           = 7;
constexpr int VT_GETDEVICESTATE    = 9;
constexpr int VT_GETDEVICEDATA     = 10;
constexpr int VT_SETDATAFORMAT     = 11;
constexpr int VT_SETCOOPLEVEL      = 13;
constexpr int VT_POLL              = 25;

// x64 has a single calling convention, so plain function pointers suffice — no __stdcall/__cdecl juggling.
typedef HRESULT (*CreateDevice_t)(void* self, const GUID* rguid, void** ppDevice, void* pUnkOuter);
typedef HRESULT (*Acquire_t)(void* self);
typedef HRESULT (*GetDeviceState_t)(void* self, DWORD cbData, void* lpvData);
typedef HRESULT (*GetDeviceData_t)(void* self, DWORD cbObjectData, void* rgdod, DWORD* pdwInOut, DWORD dwFlags);
typedef HRESULT (*SetDataFormat_t)(void* self, const void* lpdf);
typedef HRESULT (*SetCoopLevel_t)(void* self, HWND hwnd, DWORD dwFlags);
typedef HRESULT (*Poll_t)(void* self);

// ORIGINALS are PER-VTABLE, not GLOBAL. A single global is only safe if every device shares one vtable — and
// dinput8 does not guarantee that: SysKeyboard, SysMouse and a joystick can be distinct COM classes with distinct
// vtables. The second CreateDevice would then patch a different vtable and overwrite the global with ITS original,
// after which device #1's calls forward into device #2's implementation. That is a silent input corruption (or a
// crash) that would look exactly like "the netcode broke my controller". Key the originals by vtable instead.
struct VT {
    void**           vt;
    CreateDevice_t   cd;
    Acquire_t        ac;
    GetDeviceState_t gs;
    GetDeviceData_t  gd;
    SetDataFormat_t  sdf;
    SetCoopLevel_t   scl;
    Poll_t           poll;
};
constexpr int MAX_VT = 8;
static VT  g_vt[MAX_VT];
static int g_nvt = 0;

static VT* vt_of(void* obj) {
    if (!obj) return nullptr;
    void** vt = *(void***)obj;
    for (int i = 0; i < g_nvt; i++) if (g_vt[i].vt == vt) return &g_vt[i];
    return nullptr;
}
static VT* vt_intern(void* obj) {
    if (!obj) return nullptr;
    VT* e = vt_of(obj);
    if (e) return e;
    if (g_nvt >= MAX_VT) return nullptr;
    e = &g_vt[g_nvt++];
    memset(e, 0, sizeof(*e));
    e->vt = *(void***)obj;
    return e;
}

// ---- device bookkeeping: which object is which, so the log can name them ----
constexpr int MAX_DEV = 8;
struct DevInfo {
    void* obj;
    GUID  guid;
    DWORD fmt_size;      // DIDATAFORMAT::dwDataSize — 272=DIJOYSTATE2, 80=DIJOYSTATE, 256=keyboard, 16/20=mouse
    long  state_calls;
    long  data_calls;
    DWORD last_cb;
};
static DevInfo g_dev[MAX_DEV];
static int     g_ndev = 0;
static SRWLOCK g_lk = SRWLOCK_INIT;

static const char* fmt_name(DWORD n) {
    switch (n) {
        case 272: return "DIJOYSTATE2 (gamepad)";
        case 80:  return "DIJOYSTATE (gamepad)";
        case 256: return "keyboard (256 keys)";
        case 16:  return "DIMOUSESTATE";
        case 20:  return "DIMOUSESTATE2";
        default:  return "unknown";
    }
}

static DevInfo* find(void* obj) {
    for (int i = 0; i < g_ndev; i++) if (g_dev[i].obj == obj) return &g_dev[i];
    return nullptr;
}

// Patch one vtable slot. Returns the original pointer (or null if already patched / failed).
static void* patch_slot(void* obj, int index, void* hook) {
    if (!obj) return nullptr;
    void** vt = *(void***)obj;
    if (!vt) return nullptr;
    void* orig = vt[index];
    if (orig == hook) return nullptr;                  // already ours
    DWORD old;
    if (!VirtualProtect(&vt[index], sizeof(void*), PAGE_READWRITE, &old)) return nullptr;
    vt[index] = hook;
    VirtualProtect(&vt[index], sizeof(void*), old, &old);
    return orig;
}

// ---- the hooks: forward untouched, record shape ----

static HRESULT hk_SetDataFormat(void* self, const void* lpdf) {
    VT* e = vt_of(self); if (!e || !e->sdf) return E_FAIL;
    HRESULT hr = e->sdf(self, lpdf);
    // DIDATAFORMAT: dwSize@0 dwObjSize@4 dwFlags@8 dwDataSize@12 dwNumObjs@16
    DWORD dsize = lpdf ? *(const DWORD*)((const uint8_t*)lpdf + 12) : 0;
    DWORD nobjs = lpdf ? *(const DWORD*)((const uint8_t*)lpdf + 16) : 0;
    AcquireSRWLockExclusive(&g_lk);
    DevInfo* d = find(self);
    if (d) d->fmt_size = dsize;
    ReleaseSRWLockExclusive(&g_lk);
    rblog::write("DI-PROBE(%s): SetDataFormat dev=%p dataSize=%u objs=%u -> %s  hr=0x%08lX",
                 role::name(), self, (unsigned)dsize, (unsigned)nobjs, fmt_name(dsize), (unsigned long)hr);
    return hr;
}

static HRESULT hk_SetCoopLevel(void* self, HWND hwnd, DWORD dwFlags) {
    VT* e = vt_of(self); if (!e || !e->scl) return E_FAIL;
    HRESULT hr = e->scl(self, hwnd, dwFlags);
    rblog::write("DI-PROBE(%s): SetCooperativeLevel dev=%p hwnd=%p flags=0x%lX hr=0x%08lX",
                 role::name(), self, (void*)hwnd, (unsigned long)dwFlags, (unsigned long)hr);
    return hr;
}

static HRESULT hk_Acquire(void* self) {
    VT* e = vt_of(self); if (!e || !e->ac) return E_FAIL;
    HRESULT hr = e->ac(self);
    static long n = 0;
    if (++n <= 8) rblog::write("DI-PROBE(%s): Acquire dev=%p hr=0x%08lX", role::name(), self, (unsigned long)hr);
    return hr;
}

// The SEAM — the DirectInput device side. Substitution happens on the XInput side (present()); here it only counts.
// Deliberately not logged per call: at 60fps this fires every frame per device, and per-frame logging is how you turn
// a diagnostic into a performance bug and an unreadable log. First few calls in full, then silence; report() has totals.
static HRESULT hk_GetDeviceState(void* self, DWORD cbData, void* lpvData) {
    VT* e = vt_of(self); if (!e || !e->gs) return E_FAIL;
    HRESULT hr = e->gs(self, cbData, lpvData);
    AcquireSRWLockExclusive(&g_lk);
    DevInfo* d = find(self);
    long n = 0;
    if (d) { d->state_calls++; d->last_cb = cbData; n = d->state_calls; }
    ReleaseSRWLockExclusive(&g_lk);
    if (n > 0 && n <= 3)
        rblog::write("DI-PROBE(%s): GetDeviceState dev=%p cb=%u (%s) hr=0x%08lX  [call #%ld]",
                     role::name(), self, (unsigned)cbData, fmt_name(cbData), (unsigned long)hr, n);
    return hr;
}

static HRESULT hk_GetDeviceData(void* self, DWORD cbObjectData, void* rgdod, DWORD* pdwInOut, DWORD dwFlags) {
    VT* e = vt_of(self); if (!e || !e->gd) return E_FAIL;
    HRESULT hr = e->gd(self, cbObjectData, rgdod, pdwInOut, dwFlags);
    AcquireSRWLockExclusive(&g_lk);
    DevInfo* d = find(self);
    long n = 0;
    if (d) { d->data_calls++; n = d->data_calls; }
    ReleaseSRWLockExclusive(&g_lk);
    if (n > 0 && n <= 3)
        rblog::write("DI-PROBE(%s): GetDeviceData dev=%p cbObj=%u count=%lu flags=0x%lX hr=0x%08lX  [call #%ld] "
                     "— BUFFERED mode is in use on this device",
                     role::name(), self, (unsigned)cbObjectData,
                     (unsigned long)(pdwInOut ? *pdwInOut : 0), (unsigned long)dwFlags, (unsigned long)hr, n);
    return hr;
}

static HRESULT hk_Poll(void* self) { VT* e = vt_of(self); return (e && e->poll) ? e->poll(self) : E_FAIL; }

static HRESULT hk_CreateDevice(void* self, const GUID* rguid, void** ppDevice, void* pUnkOuter) {
    VT* fac = vt_of(self); if (!fac || !fac->cd) return E_FAIL;
    HRESULT hr = fac->cd(self, rguid, ppDevice, pUnkOuter);
    if (FAILED(hr) || !ppDevice || !*ppDevice) {
        rblog::write("DI-PROBE(%s): CreateDevice FAILED hr=0x%08lX", role::name(), (unsigned long)hr);
        return hr;
    }
    void* dev = *ppDevice;

    AcquireSRWLockExclusive(&g_lk);
    bool known = find(dev) != nullptr;
    int slot = -1;
    if (!known && g_ndev < MAX_DEV) {
        slot = g_ndev++;
        g_dev[slot].obj = dev;
        if (rguid) g_dev[slot].guid = *rguid; else memset(&g_dev[slot].guid, 0, sizeof(GUID));
        g_dev[slot].fmt_size = 0; g_dev[slot].state_calls = 0; g_dev[slot].data_calls = 0; g_dev[slot].last_cb = 0;
    }
    ReleaseSRWLockExclusive(&g_lk);

    // Intern this device's vtable and patch it once. A second device of the same class finds the entry already
    // populated and patch_slot returns null (the slot is already ours) — we keep the stored original. A device of a
    // different class gets its own entry, which is the whole point of keying by vtable.
    VT* e = vt_intern(dev);
    if (e) {
        void* p;
        if ((p = patch_slot(dev, VT_GETDEVICESTATE, (void*)&hk_GetDeviceState))) e->gs   = (GetDeviceState_t)p;
        if ((p = patch_slot(dev, VT_GETDEVICEDATA,  (void*)&hk_GetDeviceData)))  e->gd   = (GetDeviceData_t)p;
        if ((p = patch_slot(dev, VT_SETDATAFORMAT,  (void*)&hk_SetDataFormat)))  e->sdf  = (SetDataFormat_t)p;
        if ((p = patch_slot(dev, VT_SETCOOPLEVEL,   (void*)&hk_SetCoopLevel)))   e->scl  = (SetCoopLevel_t)p;
        if ((p = patch_slot(dev, VT_ACQUIRE,        (void*)&hk_Acquire)))        e->ac   = (Acquire_t)p;
        if ((p = patch_slot(dev, VT_POLL,           (void*)&hk_Poll)))           e->poll = (Poll_t)p;
    } else {
        rblog::write("DI-PROBE(%s): WARNING vtable table full — device %p left UNPATCHED (forwarded natively).",
                     role::name(), dev);
    }

    const GUID g = rguid ? *rguid : GUID{};
    rblog::write("DI-PROBE(%s): CreateDevice #%d dev=%p guid={%08lX-%04X-%04X-%02X%02X%02X%02X%02X%02X%02X%02X}",
                 role::name(), slot, dev, (unsigned long)g.Data1, g.Data2, g.Data3,
                 g.Data4[0], g.Data4[1], g.Data4[2], g.Data4[3], g.Data4[4], g.Data4[5], g.Data4[6], g.Data4[7]);
    return hr;
}


// ============================================================================================================
// XINPUT SEAM
//
// XInput1_3 exports XInputGetState as ordinal 2 and the undocumented XInputGetStateEx (reports the Guide button) as
// ordinal 100; games that want Guide resolve 100 and fall back to 2. XINPUT_STATE is a documented 16-byte struct
// (a 4-byte packet counter + a 12-byte XINPUT_GAMEPAD), so the netplay payload is 12 bytes/player/frame and the
// engine derives every downstream field itself.
//
// This block detects whether the module is loaded, hooks the ordinals, logs the state they return, and substitutes
// state in present() below.
namespace xin {

#pragma pack(push, 1)
struct XINPUT_GAMEPAD { unsigned short wButtons; unsigned char bLeftTrigger, bRightTrigger;
                        short sThumbLX, sThumbLY, sThumbRX, sThumbRY; };            // 12 bytes
struct XINPUT_STATE   { unsigned long dwPacketNumber; XINPUT_GAMEPAD Gamepad; };    // 16 bytes
#pragma pack(pop)
static_assert(sizeof(XINPUT_GAMEPAD) == 12, "XINPUT_GAMEPAD must be 12 bytes");
static_assert(sizeof(XINPUT_STATE)   == 16, "XINPUT_STATE must be 16 bytes");

// A device is described by more than one API.
// We answer XInputGetState(1) with ERROR_SUCCESS, but XInputGetCapabilities(1) still goes to the real XInput1_3,
// which correctly reports ERROR_DEVICE_NOT_CONNECTED — there is no physical pad in slot 1. So the game can see a
// controller that simultaneously exists and does not exist. Titles commonly gate "is this pad allowed to JOIN /
// confirm / press Start" on capabilities rather than on state, which fits the symptom exactly: the stick moves
// (state) but Start does nothing (join gate). An emulated device has to be COHERENT across every API that describes
// it, not just the one we substitute — otherwise we are not emulating hardware, only spoofing one call.
#pragma pack(push, 1)
struct XINPUT_VIBRATION    { unsigned short wLeftMotorSpeed, wRightMotorSpeed; };                  // 4
struct XINPUT_CAPABILITIES { unsigned char Type, SubType; unsigned short Flags;
                             XINPUT_GAMEPAD Gamepad; XINPUT_VIBRATION Vibration; };                // 20
#pragma pack(pop)
static_assert(sizeof(XINPUT_CAPABILITIES) == 20, "XINPUT_CAPABILITIES must be 20 bytes");

typedef DWORD (WINAPI* XInputGetState_t)(DWORD dwUserIndex, XINPUT_STATE* pState);
typedef DWORD (WINAPI* XInputGetCaps_t)(DWORD dwUserIndex, DWORD dwFlags, XINPUT_CAPABILITIES* pCaps);
typedef DWORD (WINAPI* XInputSetState_t)(DWORD dwUserIndex, XINPUT_VIBRATION* pVib);
static XInputGetState_t o_GetState   = nullptr;   // ordinal 2
static XInputGetState_t o_GetStateEx = nullptr;   // ordinal 100
static XInputGetCaps_t  o_GetCaps    = nullptr;   // ordinal 4
static XInputSetState_t o_SetState   = nullptr;   // ordinal 3
static volatile LONG    g_caps_calls[4] = {0, 0, 0, 0};
static volatile LONG g_calls = 0, g_connected = 0;
static bool  g_hooked = false;
static HMODULE g_mod = nullptr;
static const char* g_modname = nullptr;

static void btn_names(unsigned short b, char* out, size_t n);

// Read the real pad, bypassing our own hook (o_GetState is the trampoline, so this cannot recurse).
// read_first_connected() below is how the netplay path captures LOCAL input; the physical pad's index is
// independent of the GAME slot it drives, which differs by role.
static bool read_pad(int idx, XINPUT_GAMEPAD* out12) {
    if (!o_GetState || !out12) return false;
    XINPUT_STATE st;
    memset(&st, 0, sizeof(st));
    if (o_GetState((DWORD)idx, &st) != ERROR_SUCCESS) return false;
    {   // physical-side trace: distinguishes "Start never reached us" from "Start reached us and we lost it"
        static unsigned short s_phys_prev = 0;
        if (st.Gamepad.wButtons != s_phys_prev) {
            char nb[160]; btn_names(st.Gamepad.wButtons, nb, sizeof(nb));
            rblog::write("XINPUT-BTN(%s): PHYSICAL pad%d raw 0x%04X [%s]%s", role::name(), idx,
                         st.Gamepad.wButtons, nb,
                         (st.Gamepad.wButtons & 0x0010) ? "   START held on the real stick" : "");
            s_phys_prev = st.Gamepad.wButtons;
        }
    }
    memcpy(out12, &st.Gamepad, sizeof(XINPUT_GAMEPAD));
    return true;
}

static void log_state(const char* which, DWORD idx, DWORD rc, const XINPUT_STATE* st) {
    LONG n = InterlockedIncrement(&g_calls);
    if (rc == ERROR_SUCCESS) InterlockedExchange(&g_connected, 1);
    // PER-SLOT CAP, not a global one: a global cap is exhausted by slot 0 within a few frames, leaving slot 1 — the
    // only slot whose behaviour is in question — logged exactly once. That makes "the game polled slot 1 once and
    // dropped it" indistinguishable from "the game polls slot 1 every frame", which is the whole measurement.
    static volatile LONG s_logged[4] = {0, 0, 0, 0};
    LONG sn = (idx < 4) ? InterlockedIncrement(&s_logged[idx]) : 999;
    if (sn <= 4 && st)
        rblog::write("XINPUT(%s): %s(user=%lu) rc=%lu pkt=%lu btn=0x%04X LT=%u RT=%u LX=%d LY=%d RX=%d RY=%d [#%ld]",
                     role::name(), which, (unsigned long)idx, (unsigned long)rc,
                     (unsigned long)st->dwPacketNumber, st->Gamepad.wButtons,
                     st->Gamepad.bLeftTrigger, st->Gamepad.bRightTrigger,
                     st->Gamepad.sThumbLX, st->Gamepad.sThumbLY, st->Gamepad.sThumbRX, st->Gamepad.sThumbRY, sn);
}

// ============================ HARDWARE EMULATION — the substitution seam ============================
// Instead of patching the ELEVEN fields the engine computed from the local stick, we present a synthetic CONTROLLER
// and let the engine compute all eleven itself. 1:1 by construction.
//
// Two facts from the observation run drive the design:
// 1. The game polls only slot 0, because slots 1-3 answer ERROR_DEVICE_NOT_CONNECTED. A second player therefore
// needs a slot that reports CONNECTED — the game will not poll a slot it believes is empty.
// 2. XINPUT_STATE carries `dwPacketNumber`, XInput's OWN change counter. Callers use it to skip work when input is
// unchanged, so a frozen or arbitrary value can make the engine ignore perfectly good input. We therefore bump
// it if and only if the 12 gamepad bytes actually changed — the real API's exact semantics.
//
// MIRROR MODE (`xinput_mirror.txt` beside the exe) is the proof-of-seam, runnable SOLO with one controller: report
// both slot 0 and slot 1 connected and feed both from the one physical pad. The decisive measurement is not how the
// game feels — it is whether the game STARTS POLLING SLOT 1 at frame cadence. If it does, the enumeration accepted
// our synthetic pad and every remaining piece is just choosing what bytes to hand it. If it never polls slot 1, we
// hooked too late for the game's one-shot enumeration and must catch the module at LoadLibrary instead.
static bool           s_mirror = false;
static bool           s_mirror_read = false;
static unsigned long  s_pkt[4]  = {0, 0, 0, 0};
static XINPUT_GAMEPAD s_last[4];
static volatile LONG  s_slot_calls[4] = {0, 0, 0, 0};

// slot1 feed: NEUTRAL by default, DUPLICATE only if the flag file says so.
// Why neutral is the default: duplicating pad 0 onto both slots means pressing Start sends Start to P1 and P2 on
// the same FRAME. Two simultaneous Starts in a menu is a state this game was almost certainly never tested against,
// and real netplay never produces it (the two pads always carry different input). A present-but-IDLE second pad is
// both the safer probe and the honest model of what netplay looks like before inputs start flowing.
// Put the word "duplicate" in xinput_mirror.txt to get the old copy-pad-0-to-both behaviour.
// Modes, chosen by a keyword in xinput_mirror.txt:
// (default) slot0 = physical pad, slot1 = NEUTRAL — safe baseline: does a present-but-idle pad break anything?
// "duplicate" slot0 = physical pad, slot1 = same input — both pads act together (double-Start confound)
// "swap" slot0 = NEUTRAL, slot1 = physical pad — the DECISIVE TEST: your stick drives only the emulated
// pad, so if P2 responds to Start the synthetic device is fully accepted, with nothing else pressing
// Start on the same frame to muddy it.
// "join" slot0 = physical pad VERBATIM, slot1 = neutral EXCEPT its START mirrors your physical back button.
// This is the test that actually works: you keep full P1 control to navigate to the P2 join prompt,
// and tapping back makes the emulated pad — and only it — press START. No double-Start confound, and
// nothing is remapped on P1. (swap left you with no P1 input at all, so you could not even reach the
// prompt.)
static bool s_dup  = false;
static bool s_swap = false;
// "full" slot0 and slot1 both carry the physical pad VERBATIM — every button including START and back, both
// triggers, both sticks, no remapping anywhere. This is the exact shape the network test will run in:
// slot 1 is fed a complete, unmodified 12-byte gamepad that simply comes from somewhere else. Testing
// with START remapped would leave the one button that gates joining/pausing unproven on the real
// control, which is exactly what must not be discovered during a network test.
static bool s_join = false;
static bool s_full = false;

static bool mirror_on() {
    if (!s_mirror_read) {
        char p[MAX_PATH]; GetModuleFileNameA(NULL, p, MAX_PATH);
        char* sl = strrchr(p, '\\'); if (sl) sl[1] = 0; else p[0] = 0;
        strncat(p, "xinput_mirror.txt", MAX_PATH - strlen(p) - 1);
        s_mirror = (GetFileAttributesA(p) != INVALID_FILE_ATTRIBUTES);
        if (s_mirror) {
            FILE* f = fopen(p, "r");
            if (f) { char buf[256] = {0}; size_t n = fread(buf, 1, sizeof(buf) - 1, f); buf[n] = 0; fclose(f);
                     s_dup  = (strstr(buf, "duplicate") != nullptr);
                     s_swap = (strstr(buf, "swap") != nullptr);
                     s_join = (strstr(buf, "join") != nullptr);
                     s_full = (strstr(buf, "full") != nullptr);
                     if (s_full) s_join = true; }
        }
        s_mirror_read = true;
        if (s_mirror)
            rblog::write("XINPUT(%s): VIRTUAL PAD ARMED — slot 0 = physical pad, slot 1 = SYNTHETIC and reports "
                         "CONNECTED, fed %s. Watch for the game to poll slot 1; that is the proof the seam drives it.",
                         role::name(), s_full ? "the FULL physical pad (all buttons, triggers and both sticks), with "
                                                "START driven by your BACK button so the join stays clean and pause "
                                                "cannot double-fire — the local stand-in for the network feed"
                                     : s_join ? "START ONLY, mirrored from your physical BACK button, while slot 0 "
                                                "keeps FULL normal control (join: navigate as P1, tap BACK to make "
                                                "the emulated P2 pad press START)"
                                     : s_swap ? "the PHYSICAL pad while slot 0 goes NEUTRAL (swap: your stick drives "
                                                "ONLY the emulated pad — the clean can-it-press-Start test)"
                                     : s_dup ? "a DUPLICATE of pad 0 (two Starts on one frame — menu-risky)"
                                             : "NEUTRAL (present but idle — the safe default)");
    }
    return s_mirror;
}

// Present `g` on `slot`, honouring XInput's packet-number contract (bump only on actual change).
// XINPUT_GAMEPAD button bits, for readable logs.
static void btn_names(unsigned short b, char* out, size_t n) {
    struct { unsigned short m; const char* s; } T[] = {
        {0x0001,"UP"},{0x0002,"DOWN"},{0x0004,"LEFT"},{0x0008,"RIGHT"},{0x0010,"START"},{0x0020,"BACK"},
        {0x0040,"LTHUMB"},{0x0080,"RTHUMB"},{0x0100,"LB"},{0x0200,"RB"},{0x0400,"GUIDE"},
        {0x1000,"A"},{0x2000,"B"},{0x4000,"X"},{0x8000,"Y"} };
    out[0] = 0;
    for (auto& t : T) if (b & t.m) { if (out[0]) strncat(out, "|", n - strlen(out) - 1);
                                     strncat(out, t.s, n - strlen(out) - 1); }
    if (!out[0]) strncpy(out, "-", n);
}

// Log on CHANGE of the button mask: one line per press and per release, bounded by how fast a human can move, so it
// can never become per-frame spam. (A first-N-calls cap only ever showed startup frames with nothing held.)
static void log_btn_change(int slot, const char* tag, unsigned short before, unsigned short after) {
    if (before == after) return;
    char nb[160], na[160];
    btn_names(before, nb, sizeof(nb));
    btn_names(after,  na, sizeof(na));
    rblog::write("XINPUT-BTN(%s): slot%d %s  0x%04X [%s]  ->  0x%04X [%s]%s",
                 role::name(), slot, tag, before, nb, after, na,
                 ((after & 0x0010) && !(before & 0x0010)) ? "   START PRESSED" : "");
}

// dwPacketNumber must be a pure function of the input history, not a mutable counter
//
// XInput's contract: the packet number rises when the state changes and stays put when it does not, so callers can
// skip work on unchanged input. A naive `if (changed) ++counter` satisfies that during forward play and BREAKS under
// rollback: replaying frame N would see a counter that has already advanced past N, hand the engine a different
// number than it saw the first time, and let it take a different branch on identical input. That is a divergence
// manufactured by the netcode itself — the exact class of bug we removed from the input path.
//
// So the packet number is DEFINED as a running change-count over the input stream:
// pkt(N) = pkt(N-1) + (pad(N) != pad(N-1) ? 1: 0)
// keyed on resim::effective_frame(), which returns the REPLAYED frame during resim. Replaying N recomputes from the
// same N-1 entry and yields the same value, every time. It is monotonic, it moves only on change, and it is the
// honest XInput semantic rather than an approximation of it.
//
// Rollback subtlety: a replay may carry CORRECTED remote input, so frame N's bytes can legitimately differ from the
// first pass. We therefore serve the cached entry only when the bytes match, and recompute from the predecessor when
// they do not — so the chain re-derives correctly as the replay walks forward.
constexpr int PKT_RING = 256;
struct PktEnt { int frame; XINPUT_GAMEPAD pad; unsigned long pkt; bool valid; };
static PktEnt s_pring[2][PKT_RING];

static void present(XINPUT_STATE* dst, int slot, const XINPUT_GAMEPAD* g) {
    if (slot < 0 || slot > 1) { dst->dwPacketNumber = 0; dst->Gamepad = *g; return; }

    const int f = resim::effective_frame();
    PktEnt& cur = s_pring[slot][(unsigned)f & (PKT_RING - 1)];

    if (!(cur.valid && cur.frame == f && memcmp(&cur.pad, g, sizeof(*g)) == 0)) {
        const PktEnt& prev = s_pring[slot][(unsigned)(f - 1) & (PKT_RING - 1)];
        const bool have_prev = prev.valid && prev.frame == f - 1;
        const bool changed   = !have_prev || memcmp(&prev.pad, g, sizeof(*g)) != 0;
        log_btn_change(slot, "presented", have_prev ? prev.pad.wButtons : 0, g->wButtons);
        cur.frame = f; cur.pad = *g; cur.valid = true;
        cur.pkt = (have_prev ? prev.pkt : 0) + (changed ? 1u : 0u);
    }
    dst->dwPacketNumber = cur.pkt;
    dst->Gamepad        = cur.pad;
}

static DWORD WINAPI hk_GetState(DWORD idx, XINPUT_STATE* st) {
    if (idx < 4) InterlockedIncrement(&s_slot_calls[idx]);

    // Heartbeat from this hook, not from the periodic reporter. report() runs on the MAIN thread, so when the main
    // thread parks on a lock the slot totals stop printing — exactly when we most need them. Emitting from here means
    // the counts survive a hang, and a frozen count is itself the diagnosis (input polling stopped vs kept running).
    {
        static volatile LONG s_hb = 0;
        if ((InterlockedIncrement(&s_hb) % 600) == 0)
            rblog::write("XINPUT-HB(%s): slotPolls 0=%ld 1=%ld 2=%ld 3=%ld  mirror=%d (emitted from the input hook, "
                         "so it keeps ticking even if the main thread is stuck)",
                         role::name(), s_slot_calls[0], s_slot_calls[1], s_slot_calls[2], s_slot_calls[3], (int)s_mirror);
        if ((s_hb % 600) == 0)
            rblog::write("XINPUT-HB(%s): capsQueries 0=%ld 1=%ld 2=%ld 3=%ld (a nonzero slot-1 count means the game "
                         "DOES validate pads by capability — the likely Start gate)", role::name(),
                         g_caps_calls[0], g_caps_calls[1], g_caps_calls[2], g_caps_calls[3]);
    }

    // The first time the game asks about slot 1, it has accepted a controller we invented.
    if (idx == 1 && s_slot_calls[1] == 1)
        rblog::write("XINPUT(%s): GAME POLLED SLOT 1 — the synthetic second pad was accepted by the enumeration. "
                     "This is the seam that replaces the derived-window injection.", role::name());

    // Netplay owns both pads. While armed we present slot 0 and slot 1 as connected on both machines, so each side joins locally through the
    // game's own flow. Before pairing we present NEUTRAL: the pads exist, connected, nobody pressing anything —
    // which is exactly what is true, and it holds both games at the title without pretending to "synchronise" them.
    // Once running, net_input resolves each slot by PLAYER IDENTITY (slot0 = P1 human, slot1 = P2 human), sourcing
    // one from this machine's stick and the other from the wire.
    if (net::session_armed() && idx <= 1 && st) {
        XINPUT_GAMEPAD g;
        memset(&g, 0, sizeof(g));
        // During a replay, answer for the replayed frame, not the live one. The whole point of rolling back is to
        // re-run frame F with the input that arrived LATE. Serving the live frame's input here would replay the
        // present onto the past and produce a different-but-still-wrong frame.
        const bool replaying = resim::resim_active();
        const bool resolved  = replaying
            ? net_input::pad_for_engine_frame((int)idx, resim::effective_frame(), &g)
            : (net::session_both_running() && net_input::pad_present((int)idx, &g));
        // Count how many frames each slot served real network input vs neutral, and whether that input was non-zero.
        // resolved==0 means the netcode is not driving the pads at all; resolved high but nonzero==0 means neutral
        // bytes are being delivered, which is a capture problem, not a transport one. (A per-call log cap only ever
        // showed the unpaired startup state.)
        if (idx < 2) {
            static volatile LONG s_res[2] = {0,0}, s_neu[2] = {0,0}, s_nz[2] = {0,0};
            InterlockedIncrement(resolved ? &s_res[idx] : &s_neu[idx]);
            if (resolved && (g.wButtons || g.bLeftTrigger || g.bRightTrigger)) InterlockedIncrement(&s_nz[idx]);
            static volatile LONG s_hb = 0;
            if ((InterlockedIncrement(&s_hb) % 600) == 0)
                rblog::write("NET-PAD(%s): slot0 resolved=%ld neutral=%ld nonzero=%ld | slot1 resolved=%ld neutral=%ld "
                             "nonzero=%ld  (resolved=frames served from the WIRE; nonzero=frames where that input "
                             "actually had a button down)",
                             role::name(), s_res[0], s_neu[0], s_nz[0], s_res[1], s_neu[1], s_nz[1]);
        }
        present(st, (int)idx, &g);
        log_state(resolved ? (idx == 0 ? "NET>slot0(P1)" : "NET>slot1(P2)")
                           : (idx == 0 ? "NET>slot0(neutral,unpaired)" : "NET>slot1(neutral,unpaired)"),
                  idx, ERROR_SUCCESS, st);
        return ERROR_SUCCESS;
    }

    if (mirror_on() && idx <= 1 && st) {
        XINPUT_GAMEPAD g;
        memset(&g, 0, sizeof(g));
        const char* tag;
        if (s_join) {
            if (idx == 0) { if (!read_pad(0, &g)) memset(&g, 0, sizeof(g)); tag = "VPAD>slot0(phys)"; }
            else {         // slot1
                XINPUT_GAMEPAD hw; memset(&hw, 0, sizeof(hw));
                const bool have = read_pad(0, &hw);
                if (s_full && have) {
                    g = hw;                                  // VERBATIM — every control, START and back included
                } else if (have && (hw.wButtons & 0x0020)) {
                    g.wButtons |= 0x0010;                    // join-only mode: back becomes START, nothing else
                }
                tag = s_full ? "VPAD>slot1(VERBATIM)" : "VPAD>slot1(START<-BACK)";
            }
        } else {
            const bool feed = s_swap ? (idx == 1) : (idx == 0 || s_dup);
            if (feed) { if (!read_pad(0, &g)) memset(&g, 0, sizeof(g)); }
            tag = feed ? (idx == 0 ? "VPAD>slot0(phys)" : "VPAD>slot1(PHYS)")
                       : (idx == 0 ? "VPAD>slot0(neutral)" : "VPAD>slot1(neutral)");
        }
        present(st, (int)idx, &g);
        log_state(tag, idx, ERROR_SUCCESS, st);
        return ERROR_SUCCESS;
    }

    DWORD rc = o_GetState ? o_GetState(idx, st) : ERROR_DEVICE_NOT_CONNECTED;
    log_state("XInputGetState", idx, rc, st);
    return rc;
}
static DWORD WINAPI hk_GetStateEx(DWORD idx, XINPUT_STATE* st) {
    DWORD rc = o_GetStateEx ? o_GetStateEx(idx, st) : ERROR_DEVICE_NOT_CONNECTED;
    log_state("XInputGetStateEx", idx, rc, st);
    return rc;
}

// Report the virtual pad's capabilities by copying the real pad's rather than hand-authoring a struct: whatever
// the physical controller claims to support, the synthetic one claims identically. That is the most faithful thing we
// can say, and it cannot drift from what a real device on this machine reports. Only if there is no physical pad at
// all do we fall back to describing a plain wired gamepad.
static DWORD WINAPI hk_GetCaps(DWORD idx, DWORD flags, XINPUT_CAPABILITIES* caps) {
    if (idx < 4) InterlockedIncrement(&g_caps_calls[idx]);
    if ((mirror_on() || net::session_armed()) && idx == 1 && caps) {
        DWORD rc = o_GetCaps ? o_GetCaps(0, flags, caps) : ERROR_DEVICE_NOT_CONNECTED;   // clone slot 0's answer
        if (rc != ERROR_SUCCESS) {
            memset(caps, 0, sizeof(*caps));
            caps->Type = 1; caps->SubType = 1;              // XINPUT_DEVTYPE_GAMEPAD / XINPUT_DEVSUBTYPE_GAMEPAD
            caps->Gamepad.wButtons = 0xF3FF;                // every standard button present
            caps->Gamepad.bLeftTrigger = caps->Gamepad.bRightTrigger = 0xFF;
            caps->Gamepad.sThumbLX = caps->Gamepad.sThumbLY = (short)0xFFC0;
            caps->Gamepad.sThumbRX = caps->Gamepad.sThumbRY = (short)0xFFC0;
            caps->Vibration.wLeftMotorSpeed = caps->Vibration.wRightMotorSpeed = 0xFF;
        }
        if (g_caps_calls[1] <= 3)
            rblog::write("XINPUT(%s): GetCapabilities(user=1) -> SUCCESS (%s) — the virtual pad now answers the "
                         "CAPABILITY query too, not just state. [#%ld]", role::name(),
                         rc == ERROR_SUCCESS ? "cloned from physical pad 0" : "synthesized standard gamepad",
                         g_caps_calls[1]);
        return ERROR_SUCCESS;
    }
    DWORD rc = o_GetCaps ? o_GetCaps(idx, flags, caps) : ERROR_DEVICE_NOT_CONNECTED;
    if (idx < 4 && g_caps_calls[idx] <= 2)
        rblog::write("XINPUT(%s): GetCapabilities(user=%lu) rc=%lu [#%ld]", role::name(),
                     (unsigned long)idx, (unsigned long)rc, g_caps_calls[idx]);
    return rc;
}

// Rumble to a pad that does not physically exist must SUCCEED silently; an error here is another way for the game to
// conclude the device is bogus.
static DWORD WINAPI hk_SetState(DWORD idx, XINPUT_VIBRATION* vib) {
    if ((mirror_on() || net::session_armed()) && idx == 1) return ERROR_SUCCESS;
    return o_SetState ? o_SetState(idx, vib) : ERROR_DEVICE_NOT_CONNECTED;
}

// First-connected scan — see read_local_pad() in the header for why assuming index 0 is a trap.
static int  s_local_idx = -1;
static bool read_first_connected(XINPUT_GAMEPAD* out) {
    if (s_local_idx >= 0 && read_pad(s_local_idx, out)) return true;   // cached, still alive
    for (int i = 0; i < 4; i++) {
        if (read_pad(i, out)) {
            if (s_local_idx != i) {
                rblog::write("XINPUT(%s): local physical pad found on index %d%s.", role::name(), i,
                             s_local_idx >= 0 ? " (moved — re-scanned after the previous index went away)" : "");
                s_local_idx = i;
            }
            return true;
        }
    }
    if (s_local_idx != -1) { rblog::write("XINPUT(%s): local physical pad LOST — sending neutral.", role::name());
                             s_local_idx = -1; }
    return false;
}

// Called from report(); cheap no-op once hooked. The module is loaded lazily by the game, so we cannot do this at
// DllMain time — we poll for it instead.
static void try_hook() {
    if (g_hooked) return;
    static const char* CANDIDATES[] = { "XINPUT1_3.dll", "xinput1_4.dll", "xinput9_1_0.dll", "XINPUT1_2.dll", "XINPUT1_1.dll" };
    for (const char* c : CANDIDATES) { if ((g_mod = GetModuleHandleA(c))) { g_modname = c; break; } }
    if (!g_mod) return;

    // Resolved BY ORDINAL, matching how the game itself resolves them (no name strings exist in the export-consumer).
    void* p2   = (void*)GetProcAddress(g_mod, MAKEINTRESOURCEA(2));     // XInputGetState
    void* p100 = (void*)GetProcAddress(g_mod, MAKEINTRESOURCEA(100));   // XInputGetStateEx (undocumented)
    rblog::write("XINPUT(%s): module %s LOADED base=%p ordinal2=%p ordinal100=%p — this is the real pad seam.",
                 role::name(), g_modname, (void*)g_mod, p2, p100);

    if (p2 && MH_CreateHook(p2, (void*)&hk_GetState, (void**)&o_GetState) == MH_OK && MH_EnableHook(p2) == MH_OK)
        rblog::write("XINPUT(%s): hooked ordinal 2 (XInputGetState).", role::name());
    if (p100 && p100 != p2 &&
        MH_CreateHook(p100, (void*)&hk_GetStateEx, (void**)&o_GetStateEx) == MH_OK && MH_EnableHook(p100) == MH_OK)
        rblog::write("XINPUT(%s): hooked ordinal 100 (XInputGetStateEx).", role::name());

    void* p4 = (void*)GetProcAddress(g_mod, MAKEINTRESOURCEA(4));   // XInputGetCapabilities
    void* p3 = (void*)GetProcAddress(g_mod, MAKEINTRESOURCEA(3));   // XInputSetState (vibration)
    if (p4 && MH_CreateHook(p4, (void*)&hk_GetCaps, (void**)&o_GetCaps) == MH_OK && MH_EnableHook(p4) == MH_OK)
        rblog::write("XINPUT(%s): hooked ordinal 4 (XInputGetCapabilities) — the device-validity gate.", role::name());
    if (p3 && MH_CreateHook(p3, (void*)&hk_SetState, (void**)&o_SetState) == MH_OK && MH_EnableHook(p3) == MH_OK)
        rblog::write("XINPUT(%s): hooked ordinal 3 (XInputSetState) — rumble to the virtual pad must not error.",
                     role::name());
    g_hooked = true;
}

static bool hooked() { return g_hooked && o_GetState != nullptr; }

static void report() {
    if (!g_mod) { rblog::write("XINPUT(%s): module NOT loaded — the pad does not come through XInput.", role::name()); return; }
    rblog::write("XINPUT(%s): %s calls=%ld padConnected=%ld mirror=%d  slotPolls: 0=%ld 1=%ld 2=%ld 3=%ld",
                 role::name(), g_modname, g_calls, g_connected, (int)s_mirror,
                 s_slot_calls[0], s_slot_calls[1], s_slot_calls[2], s_slot_calls[3]);
}

} // namespace xin

} // namespace

void install(void* idi8, const void* riid) {
    if (!idi8) return;
    const GUID* r = (const GUID*)riid;
    VT* e = vt_intern(idi8);
    void* p = e ? patch_slot(idi8, VT_CREATEDEVICE, (void*)&hk_CreateDevice) : nullptr;
    if (p && e) e->cd = (CreateDevice_t)p;
    rblog::write("DI-PROBE(%s): installed on IDirectInput8 %p riid={%08lX-%04X-%04X-...} CreateDevice %s. "
                 "DirectInput side = observation only; every call is forwarded untouched.",
                 role::name(), idi8,
                 r ? (unsigned long)r->Data1 : 0UL, r ? r->Data2 : 0, r ? r->Data3 : 0,
                 p ? "patched" : "ALREADY patched");
}

void poll_xinput() { xin::try_hook(); }

bool read_local_pad(void* out12) {
    if (!out12) return false;
    xin::XINPUT_GAMEPAD g; memset(&g, 0, sizeof(g));
    const bool ok = xin::read_first_connected(&g);
    memcpy(out12, &g, sizeof(g));      // neutral on failure, never stale
    return ok;
}

bool seam_ready() { return xin::hooked(); }

// ---- passive control-scheme detector (see header) ----
namespace cfg {
static unsigned int  g_map[2][16];          // XInput bit index -> engine window bits
static bool          g_known[2][16];
static int           g_learned[2] = {0, 0};
static unsigned int  g_hash[2] = {0, 0};
static bool          g_logged[2] = {false, false};

// Learn only from frames where exactly one button is held: that sample names one bit's mapping unambiguously.
// Multi-button frames are ORs and would need solving; single presses happen constantly in normal play, so the table
// fills on its own without ever synthesizing input or touching the game's config memory.
static void observe(int slot, unsigned short raw, unsigned int win) {
    if (slot < 0 || slot > 1 || raw == 0) return;
    if (raw & (raw - 1)) return;                                  // more than one bit -> ambiguous, skip
    int b = 0; while (b < 16 && !(raw & (1u << b))) b++;
    if (b >= 16) return;
    if (g_known[slot][b] && g_map[slot][b] == win) return;        // already known and stable
    if (g_known[slot][b] && g_map[slot][b] != win) {
        rblog::write("CONFIG(%s): slot%d bit%d mapping CHANGED 0x%X -> 0x%X — the control scheme was edited mid-session; "
                     "the two machines no longer agree.", role::name(), slot, b, g_map[slot][b], win);
    } else {
        g_learned[slot]++;
    }
    g_map[slot][b] = win; g_known[slot][b] = true;
    unsigned int h = 2166136261u;                                  // FNV-1a over (bit, mapping) pairs, order-stable
    for (int i = 0; i < 16; i++) if (g_known[slot][i]) {
        h = (h ^ (unsigned)i) * 16777619u;
        h = (h ^ g_map[slot][i]) * 16777619u;
    }
    g_hash[slot] = h;
    if (g_learned[slot] >= 8 && !g_logged[slot]) {
        g_logged[slot] = true;
        rblog::write("CONFIG(%s): slot%d scheme fingerprint 0x%08X after %d buttons learned.",
                     role::name(), slot, g_hash[slot], g_learned[slot]);
    }
}
} // namespace cfg

void observe_mapping(int slot, unsigned short raw, unsigned int win) { cfg::observe(slot, raw, win); }
unsigned int config_hash(int slot) { return (slot >= 0 && slot < 2) ? cfg::g_hash[slot] : 0; }
unsigned short presented_buttons(int slot) {
    return (slot >= 0 && slot < 2) ? xin::s_last[slot].wButtons : (unsigned short)0;
}
void config_report() {
    for (int s = 0; s < 2; s++)
        rblog::write("CONFIG(%s): slot%d learned=%d/16 hash=0x%08X", role::name(), s, cfg::g_learned[s], cfg::g_hash[s]);
}

void report() {
    xin::report();
    AcquireSRWLockShared(&g_lk);
    int n = g_ndev;
    ReleaseSRWLockShared(&g_lk);
    if (!n) { rblog::write("DI-PROBE(%s): no DirectInput devices created yet.", role::name()); return; }
    for (int i = 0; i < n; i++) {
        rblog::write("DI-PROBE(%s): dev#%d %p fmt=%u (%s) GetDeviceState=%ld GetDeviceData=%ld lastCb=%u",
                     role::name(), i, g_dev[i].obj, (unsigned)g_dev[i].fmt_size, fmt_name(g_dev[i].fmt_size),
                     g_dev[i].state_calls, g_dev[i].data_calls, (unsigned)g_dev[i].last_cb);
    }
}

} // namespace dinput_probe
