#pragma once
#include <cstdint>
// Read-only allocator free-list walker (diagnostic probe).
// Half A (hang): hang_detector calls walk(rdx+0x58,...) for the FUN_1404ca650-pinned worker.
// Half B (post-load): resim calls walk(alloc_base+0x1D8,...) right after restore_allocators.
// Floyd cycle-detect over the +0x20 next-link + per-node page-source. Read-only.
namespace freelist_diag { void walk(uintptr_t head_ptr_loc, const char* tag); }
