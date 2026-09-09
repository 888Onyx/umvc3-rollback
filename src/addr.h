#pragma once
#include <cstdint>
#include <windows.h>

// addr — rebases addresses from the analysis convention (image base 0x140000000, as in the Ghidra
// project) to the live module base. Every hardcoded engine address in this codebase is written in that
// convention and resolved through here at runtime.
namespace addr {

inline uintptr_t g_base = 0;

inline void init() {
    g_base = (uintptr_t)GetModuleHandleA("umvc3.exe");
}

inline uintptr_t resolve(uintptr_t ida_addr) {
    return g_base + (ida_addr - 0x140000000ULL);
}

} // namespace addr
