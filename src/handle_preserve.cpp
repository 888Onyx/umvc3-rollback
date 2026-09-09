// handle_preserve.cpp — Save/restore persistent values that arena::load overwrites.
// Persistent = value in arena that must not be rolled back (OS handles, D3D devices).
// These are created once at startup and never change. arena::load restores them
// to snapshot copies (same value), but handle_preserve guarantees it.

#include "handle_preserve.h"
#include "addr.h"
#include "arena.h"
#include "log.h"
#include <windows.h>
#include <cstdint>

// sRender singleton pointer (dereference to get struct base)
static constexpr uintptr_t SRENDER_PTR_IDA = 0x140E179A8;

// 14 persistent value offsets within sRender (from the render-system audit)
static constexpr uintptr_t SRENDER_OFFSETS[] = {
    0x8,       // CS / heap object
    0xB0,      // IDirect3DDevice9**
    0xC0,      // IDirect3D9*
    0xE8,      // render thread HANDLE
    0xF8,      // go_event HANDLE
    0x100,     // done_event HANDLE
    0x1A0,     // state object (process heap)
    0x1A8,     // state object (process heap)
    0x1B0,     // state object (process heap)
    0x1C0,     // state object (process heap)
    0x8897B8,  // HWND primary window
    0x8897C0,  // IDirect3DSwapChain9* primary
    0x8897E0,  // HWND secondary window
    0x8897E8,  // IDirect3DSwapChain9* secondary
};
static constexpr int SRENDER_OFFSET_COUNT = sizeof(SRENDER_OFFSETS) / sizeof(SRENDER_OFFSETS[0]);

struct PreserveEntry {
    uintptr_t* location;     // address in arena where the value lives
    uintptr_t  saved_value;  // live value before arena::load
    const char* name;        // for logging
};

static PreserveEntry g_entries[512] = {};
static int g_entry_count = 0;
static bool g_registered = false;

static void register_srender() {
    uintptr_t srender_ptr_addr = addr::resolve(SRENDER_PTR_IDA);
    uintptr_t srender = *(uintptr_t*)srender_ptr_addr;

    if (!srender) {
        rblog::write("HANDLE-PRESERVE: sRender is NULL — cannot register");
        return;
    }

    rblog::write("HANDLE-PRESERVE: sRender at 0x%llX", (unsigned long long)srender);

    static const char* names[] = {
        "+0x8 CS/heap", "+0xB0 D3DDevice", "+0xC0 D3D9", "+0xE8 thread",
        "+0xF8 go_event", "+0x100 done_event", "+0x1A0 state0", "+0x1A8 state1",
        "+0x1B0 state2", "+0x1C0 state3", "+0x8897B8 HWND1", "+0x8897C0 SwapChain1",
        "+0x8897E0 HWND2", "+0x8897E8 SwapChain2"
    };

    for (int i = 0; i < SRENDER_OFFSET_COUNT; i++) {
        if (g_entry_count >= 512) break;
        g_entries[g_entry_count].location = (uintptr_t*)(srender + SRENDER_OFFSETS[i]);
        g_entries[g_entry_count].saved_value = 0;
        g_entries[g_entry_count].name = names[i];
        g_entry_count++;
    }

    g_registered = true;
    rblog::write("HANDLE-PRESERVE: registered %d sRender persistent values", SRENDER_OFFSET_COUNT);
}

// sRender CS LockSemaphore and sUnit CS — persistent OS handles in arena
static void register_singleton_cs() {
    // sRender CS LockSemaphore at +0x20 (DebugInfo at +0x08 already covered by sRender entries)
    uintptr_t srender_ptr_addr = addr::resolve(0x140E179A8);
    uintptr_t srender = *(uintptr_t*)srender_ptr_addr;
    if (srender && arena::is_arena_addr(srender) && g_entry_count < 510) {
        g_entries[g_entry_count].location = (uintptr_t*)(srender + 0x20);
        g_entries[g_entry_count].saved_value = 0;
        g_entries[g_entry_count].name = "sRender CS.Semaphore";
        g_entry_count++;
    }

    // sUnit CS at +0x08
    uintptr_t sunit = *(uintptr_t*)addr::resolve(0x140E17698);
    if (sunit && arena::is_arena_addr(sunit) && g_entry_count < 510) {
        g_entries[g_entry_count].location = (uintptr_t*)(sunit + 0x08);
        g_entries[g_entry_count].saved_value = 0;
        g_entries[g_entry_count].name = "sUnit CS.DebugInfo";
        g_entry_count++;
        g_entries[g_entry_count].location = (uintptr_t*)(sunit + 0x20);
        g_entries[g_entry_count].saved_value = 0;
        g_entries[g_entry_count].name = "sUnit CS.Semaphore";
        g_entry_count++;
        rblog::write("HANDLE-PRESERVE: registered sUnit CS persistent values");
    }
}

namespace handle_preserve {

void init() {
    // Registration deferred to first save() — sRender may not exist yet at init time.
}

void save() {
    if (!g_registered) {
        register_srender();
        register_singleton_cs();
    }

    for (int i = 0; i < g_entry_count; i++) {
        g_entries[i].saved_value = *g_entries[i].location;
    }

    { static long n; n++; if (n <= 5 || (n % 64) == 0) rblog::write("HANDLE-PRESERVE: saved %d persistent values [x%ld]", g_entry_count, n); }
}

void restore() {
    int restored = 0;
    for (int i = 0; i < g_entry_count; i++) {
        uintptr_t current = *g_entries[i].location;
        if (current != g_entries[i].saved_value) {
            *g_entries[i].location = g_entries[i].saved_value;
            restored++;
        }
    }

    { static long n; n++; if (n <= 5 || (n % 64) == 0) rblog::write("HANDLE-PRESERVE: restored %d/%d persistent values [x%ld]", restored, g_entry_count, n); }
}

uintptr_t get_srender() {
    if (!g_registered) return 0;
    // sRender base = location of first entry minus its offset (+0x8)
    return (uintptr_t)g_entries[0].location - SRENDER_OFFSETS[0];
}

} // namespace handle_preserve
