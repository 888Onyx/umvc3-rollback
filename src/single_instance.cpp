// single_instance.cpp — see single_instance.h.
#include "single_instance.h"
#include "role.h"
#include "log.h"
#include <windows.h>
#include <cstring>
#include <cstdio>

namespace single_instance {

typedef HANDLE (WINAPI *CreateMutexA_t)(LPSECURITY_ATTRIBUTES, BOOL, LPCSTR);
typedef HWND   (WINAPI *FindWindowW_t)(LPCWSTR, LPCWSTR);

static CreateMutexA_t s_real_CreateMutexA = nullptr;
static FindWindowW_t  s_real_FindWindowW  = nullptr;

// CreateMutexA stub: uniquify the name with a per-ROLE suffix (".P1"/".P2") so each netplay twin's
// single-instance mutex lands in a DISTINCT namespace — CreateMutex never returns ERROR_ALREADY_EXISTS, so the
// guard's "another copy exists" branch is never taken on either twin (both get suffixed → neither sees the other).
// Unnamed mutexes (name==NULL) pass straight through untouched.
static HANDLE WINAPI hk_CreateMutexA(LPSECURITY_ATTRIBUTES sa, BOOL initialOwner, LPCSTR name) {
    if (name && *name) {
        char buf[512];
        snprintf(buf, sizeof(buf), "%s.%s", name, role::name());   // ".P1" or ".P2" — distinct per twin
        return s_real_CreateMutexA(sa, initialOwner, buf);
    }
    return s_real_CreateMutexA(sa, initialOwner, name);
}

// FindWindowW stub: the guard's other leg is FindWindow for the game's OWN window title. Return NULL for a
// self-referential search (title contains "MARVEL") so P2 doesn't "find" P1's window; every other FindWindowW
// (Steam overlay, IME, etc.) passes through untouched. Belt-and-suspenders to the mutex uniquify above.
static HWND WINAPI hk_FindWindowW(LPCWSTR cls, LPCWSTR title) {
    if (title) {
        for (const wchar_t* p = title; *p; ++p) {
            if ((p[0] == L'M' || p[0] == L'm') && (p[1] == L'A' || p[1] == L'a') &&
                (p[2] == L'R' || p[2] == L'r') && (p[3] == L'V' || p[3] == L'v')) {
                static long n = 0;
                if (++n <= 4) rblog::write("SINGLE-INSTANCE: FindWindowW self-search suppressed (P2) — returned NULL");
                return NULL;
            }
        }
    }
    return s_real_FindWindowW(cls, title);
}

// Patch one imported function in the main exe's IAT: walk the import descriptors, match by name, swap the slot.
// Returns the original thunk (to call through) or nullptr if not found. Loader-lock-safe (VirtualProtect + write).
static void* patch_iat(const char* fn_name, void* stub) {
    uintptr_t base = (uintptr_t)GetModuleHandleA(NULL);
    if (!base) return nullptr;
    auto* dos = (IMAGE_DOS_HEADER*)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return nullptr;
    auto* nt = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return nullptr;
    auto& dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (!dir.VirtualAddress) return nullptr;
    auto* imp = (IMAGE_IMPORT_DESCRIPTOR*)(base + dir.VirtualAddress);
    for (; imp->Name; ++imp) {
        auto* ilt = (IMAGE_THUNK_DATA*)(base + (imp->OriginalFirstThunk ? imp->OriginalFirstThunk : imp->FirstThunk));
        auto* iat = (IMAGE_THUNK_DATA*)(base + imp->FirstThunk);
        for (; ilt->u1.AddressOfData; ++ilt, ++iat) {
            if (ilt->u1.Ordinal & IMAGE_ORDINAL_FLAG) continue;   // imported by ordinal, no name
            auto* ibn = (IMAGE_IMPORT_BY_NAME*)(base + ilt->u1.AddressOfData);
            if (strcmp((const char*)ibn->Name, fn_name) != 0) continue;
            void* orig = (void*)iat->u1.Function;
            DWORD old;
            if (VirtualProtect(&iat->u1.Function, sizeof(void*), PAGE_READWRITE, &old)) {
                iat->u1.Function = (ULONGLONG)(uintptr_t)stub;
                VirtualProtect(&iat->u1.Function, sizeof(void*), old, &old);
                return orig;
            }
            return nullptr;
        }
    }
    return nullptr;   // not imported by this exe (delay-load / GetProcAddress path — would need a different hook)
}

// A netplay instance = netplay.flag next to the exe. Both twins have it, so both bypass the guard (role-suffixed
// mutex + self-FindWindow null) and coexist. A solo instance (no flag) keeps the real single-instance mutex
// (harmless — it's alone). This replaces the old P2-only gate, which would have terminated a P3 twin at 26ms.
static bool netplay_instance() {
    char path[MAX_PATH]; GetModuleFileNameA(NULL, path, MAX_PATH);
    char* slash = strrchr(path, '\\'); if (slash) slash[1] = 0; else path[0] = 0;
    strncat(path, "netplay.flag", MAX_PATH - strlen(path) - 1);
    return GetFileAttributesA(path) != INVALID_FILE_ATTRIBUTES;
}

void install() {
    if (!netplay_instance()) {
        rblog::write("SINGLE-INSTANCE: no netplay.flag (role=%s) — guard bypass NOT installed (solo keeps the real named mutex).", role::name());
        return;
    }
    s_real_CreateMutexA = (CreateMutexA_t)patch_iat("CreateMutexA", (void*)&hk_CreateMutexA);
    s_real_FindWindowW  = (FindWindowW_t) patch_iat("FindWindowW",  (void*)&hk_FindWindowW);
    rblog::write("SINGLE-INSTANCE(%s): guard bypass installed — CreateMutexA=%s FindWindowW=%s "
                 "(mutex suffixed .%s; self FindWindow returns NULL) => this twin coexists with the other.",
                 role::name(), s_real_CreateMutexA ? "patched" : "NOT-FOUND", s_real_FindWindowW ? "patched" : "NOT-FOUND", role::name());
}

} // namespace single_instance
