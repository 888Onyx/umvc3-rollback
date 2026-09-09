// arena.cpp — the 2GB contiguous arena with GetWriteWatch dirty tracking: IAT hooks on VirtualAlloc/Free and
// Heap*, the heap zone, the ring save/load, and the baseline.
//
// All game VirtualAlloc/VirtualFree calls land in the arena.
// All game HeapAlloc/Free/ReAlloc/Size calls redirect to the heap zone (after activation).
// GetWriteWatch gives us kernel-tracked dirty pages at zero CPU cost.

#include "arena.h"
#include "free_probe.h"
#include "log.h"
#include "resim.h"   // read-only: current_frame()/resim_active() for the SITE-4 phase tag
#include "reader.h"  // READER: second shadow path — MtScalable header-reading classifier
#include "edge_break.h" // complete cross-boundary edge diff over the reverted set (probe-independent)
#include "addr.h"    // resolve(): sRender base for the REGION-SPLIT save telemetry (measurement-only)
#include <windows.h>
#include <intrin.h>  // _Interlocked*64 for the shadow-walk stat counters
#include <cstring>
#include <cstdint>
#include <cstdio>    // snprintf (page_history forensic)

namespace arena {
uintptr_t g_diag_entity = 0;
}

// MinGW may not define this
#ifndef WRITE_WATCH_FLAG_RESET
#define WRITE_WATCH_FLAG_RESET 0x01
#endif

namespace {

// --- Arena geometry ---
constexpr uintptr_t PREFERRED_ADDR    = 0x30000000ULL;
constexpr uintptr_t FALLBACK_ADDR     = 0x40000000ULL;
constexpr size_t    ARENA_SIZE        = 2ULL << 30;              // 2 GB (grown from 1GB to close the passthrough leak: the streamed-resource substrate spills OUT-OF-ARENA when reserves exceed usable. Reserve is cheap — only committed+dirty pages cost RAM; the 60-slot ring stores dirty pages dynamically; MAX_PAGES-sized bitmaps just double to a few MB)
constexpr size_t    PAGE_SIZE         = 4096;
constexpr size_t    ALLOC_GRANULARITY = 64 * 1024;               // 64 KB (VirtualAlloc alignment)
constexpr size_t    MAX_PAGES         = ARENA_SIZE / PAGE_SIZE;  // 262144

// Heap zone: 256MB bump allocator for HeapAlloc redirection
constexpr size_t HEAP_ZONE_SIZE   = 256ULL * 1024 * 1024;
constexpr size_t HEAP_ZONE_PAGES  = HEAP_ZONE_SIZE / PAGE_SIZE;
// OGG OVER-READ GUARD (B — make the crash harmless): the autonomous sound worker's ogg sync/body buffers are
// bump-allocated in this zone; a decode compaction can read a few KB past a buffer near the zone top and fall off
// the committed end (0xFFFF0000) => AV (0x1409A2A04). The bug is unfixable at the seam (concurrent autonomous
// decoder + rolled-back bump offset), but sound is pure OUTPUT — a few-byte over-read into committed memory is a
// momentary audio glitch, which GGPO already tolerates across a rollback. Reserve the top GUARD bytes of the
// (fully-committed) zone as NEVER-ALLOCATED headroom: any in-zone block ends <= SIZE-GUARD, so an over-read of up
// to GUARD bytes (>> the ~64KB max ogg page) stays inside committed memory and reads zeros instead of faulting.
constexpr size_t HEAP_ZONE_GUARD  = 1ULL * 1024 * 1024;   // 1 MB committed guard tail (>> max ogg over-read ~64KB)
constexpr size_t HEAP_HEADER_SIZE = 16;  // 8-byte size + 8-byte padding (16-byte alignment)

// Ring buffer
constexpr int RING_SLOTS = 60;

inline size_t align_up(size_t val, size_t alignment) {
    return (val + alignment - 1) & ~(alignment - 1);
}

// --- Arena state ---
uintptr_t g_arena_base     = 0;
size_t    g_watermark      = 0;       // Next free offset for MEM_RESERVE carving
size_t    g_watermark_peak = 0;       // high-water of g_watermark (measures real headroom before the passthrough leak)
uint8_t*  g_committed      = nullptr; // Bitset: which 4KB pages are committed
int       g_committed_count = 0;
bool      g_ready          = false;

// Heap zone state
uintptr_t        g_heap_zone_base   = 0;
volatile long long g_heap_zone_offset = 0;  // Bump allocator offset (atomic)
volatile bool    g_owned_heap       = true; // OWNED-HEAP master (default ON = all four properties) — gates the P1 "own all backing" capacity alarms here (arena-full passthrough / heap-zone-full fallback = an out-of-arena escape = an un-revertable slab). dllmain composes the rest of the properties from this.
volatile bool    g_heap_redirect_active = false;
volatile long long g_stage_b_crt_fallback = 0;  // STAGE B telemetry: Default allocs that overflowed the zone -> CRT (unprotected). Long-run gate: should stay 0/low.

// PERF A/B switches (see arena.h). True-global storage (this region is inside the file's anonymous namespace,
// so the accessor FUNCTIONS live in the real `namespace arena` block near early_init, not here).
bool g_no_writewatch_flag  = false;
bool g_no_hooks_flag       = false;
bool g_no_heapredirect_flag = false;

// Re-entrancy guard (thread-local)
static thread_local bool g_in_our_alloc = false;

// --- Committed bitset helpers ---
inline bool is_committed(size_t page_idx) {
    return (g_committed[page_idx / 8] >> (page_idx % 8)) & 1;
}
inline void set_committed(size_t page_idx) {
    g_committed[page_idx / 8] |= (1 << (page_idx % 8));
}

// --- Reservation tracking ---
struct Reservation { size_t offset; size_t size; };
static Reservation g_reservations[4096];
static int g_reservation_count = 0;

static int find_reservation(size_t offset) {
    for (int i = 0; i < g_reservation_count; i++) {
        if (g_reservations[i].offset == offset) return i;
    }
    return -1;
}

static void remove_reservation(int idx) {
    if (idx < 0 || idx >= g_reservation_count) return;
    g_reservations[idx] = g_reservations[--g_reservation_count];
}

// --- Free list ---
struct FreeBlock { size_t offset; size_t size; };
static FreeBlock g_free_list[4096];
static int g_free_count = 0;
// CARVE CS (donation prerequisite): hk_VirtualAlloc's watermark/free-list carve had zero synchronization —
// tolerable while game threads were the only carvers, racy once the DLL donates from save-time. One CS, both paths.
static CRITICAL_SECTION g_carve_cs;
static bool g_carve_cs_init = false;

// P1 CAPACITY DONATION registry (see arena.h): {ctrl, base, size} per donated region. Read by alloc_invariants /
// reader / coherent-full via in_owned_pool + the enumerator. Small, append-only, loud-capped.
static constexpr int MAX_DONATIONS = 1024;   // 101 donations overflowed 64 in one long run => 37 regions lost multi-region awareness (false "outside pool" breaks + real cf/reader coverage holes)
static struct { uintptr_t ctrl, base; size_t size; } g_donated[MAX_DONATIONS];
static volatile LONG g_donated_n = 0;

static size_t alloc_from_free_list(size_t aligned_size) {
    for (int i = 0; i < g_free_count; i++) {
        if (g_free_list[i].size >= aligned_size) {
            size_t offset = g_free_list[i].offset;
            if (g_free_list[i].size == aligned_size) {
                g_free_list[i] = g_free_list[--g_free_count];
            } else {
                g_free_list[i].offset += aligned_size;
                g_free_list[i].size   -= aligned_size;
            }
            return offset;
        }
    }
    return (size_t)-1;
}

static void add_to_free_list(size_t offset, size_t size) {
    if (g_free_count < 4096) {
        g_free_list[g_free_count++] = { offset, size };
    }
}

// --- Original function pointers ---
typedef LPVOID (WINAPI *VirtualAlloc_fn)(LPVOID, SIZE_T, DWORD, DWORD);
typedef BOOL   (WINAPI *VirtualFree_fn)(LPVOID, SIZE_T, DWORD);
typedef LPVOID (WINAPI *HeapAlloc_fn)(HANDLE, DWORD, SIZE_T);
typedef BOOL   (WINAPI *HeapFree_fn)(HANDLE, DWORD, LPVOID);
typedef LPVOID (WINAPI *HeapReAlloc_fn)(HANDLE, DWORD, LPVOID, SIZE_T);
typedef SIZE_T (WINAPI *HeapSize_fn)(HANDLE, DWORD, LPCVOID);

static VirtualAlloc_fn  g_real_VirtualAlloc  = nullptr;
static VirtualFree_fn   g_real_VirtualFree   = nullptr;
static HeapAlloc_fn     g_real_HeapAlloc     = nullptr;
static HeapFree_fn      g_real_HeapFree      = nullptr;
static HeapReAlloc_fn   g_real_HeapReAlloc   = nullptr;
static HeapSize_fn      g_real_HeapSize      = nullptr;

// --- Heap zone helpers ---
inline bool is_heap_zone_addr(uintptr_t addr) {
    return addr >= g_heap_zone_base && addr < g_heap_zone_base + HEAP_ZONE_SIZE;
}

static LPVOID heap_zone_alloc(SIZE_T size) {
    size_t total = align_up(size, 16) + HEAP_HEADER_SIZE;
    long long offset = InterlockedAdd64(&g_heap_zone_offset, (long long)total) - (long long)total;
    if ((size_t)offset + total > HEAP_ZONE_SIZE - HEAP_ZONE_GUARD) {
        if (g_owned_heap) { static volatile long once = 0; if (_InterlockedCompareExchange(&once, 1, 0) == 0)
            rblog::write("OWNED-HEAP P1 BREACH (heap zone full): offset=0x%llX of 0x%llX — Default alloc falling back to the OS heap. This backing is out-of-arena and never reverts. Own-all-backing broken; raise HEAP_ZONE_SIZE.", (unsigned long long)offset, (unsigned long long)HEAP_ZONE_SIZE); }
        // Within GUARD of the top — fall back to real heap so the top HEAP_ZONE_GUARD bytes stay committed-but-
        // unallocated. A block near the zone top whose ogg decode over-reads a few KB then reads this committed
        // guard (zeros) instead of faulting off the end at 0xFFFF0000. (Was: > HEAP_ZONE_SIZE.)
        return g_real_HeapAlloc(GetProcessHeap(), 0, size);
    }
    uintptr_t block = g_heap_zone_base + (size_t)offset;
    *(SIZE_T*)block = size;  // Store requested size in header
    return (LPVOID)(block + HEAP_HEADER_SIZE);
}

// --- IAT patching ---
static bool iat_patch(const char* dll_name, const char* func_name,
                      void* hook_fn, void** orig_out) {
    uintptr_t base = (uintptr_t)GetModuleHandleA(nullptr);
    auto* dos = (IMAGE_DOS_HEADER*)base;
    auto* nt  = (IMAGE_NT_HEADERS*)((uint8_t*)base + dos->e_lfanew);
    auto& imp_dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (!imp_dir.VirtualAddress) return false;

    auto* imp = (IMAGE_IMPORT_DESCRIPTOR*)(base + imp_dir.VirtualAddress);
    for (; imp->Name; imp++) {
        const char* name = (const char*)(base + imp->Name);
        if (_stricmp(name, dll_name) != 0) continue;

        auto* thunk      = (IMAGE_THUNK_DATA*)(base + imp->FirstThunk);
        auto* orig_thunk = (IMAGE_THUNK_DATA*)(base + imp->OriginalFirstThunk);
        for (; orig_thunk->u1.AddressOfData; thunk++, orig_thunk++) {
            if (orig_thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG) continue;
            auto* hint = (IMAGE_IMPORT_BY_NAME*)(base + orig_thunk->u1.AddressOfData);
            if (strcmp(hint->Name, func_name) != 0) continue;

            *orig_out = (void*)thunk->u1.Function;
            DWORD old_protect;
            VirtualProtect(&thunk->u1.Function, sizeof(void*), PAGE_READWRITE, &old_protect);
            thunk->u1.Function = (uintptr_t)hook_fn;
            VirtualProtect(&thunk->u1.Function, sizeof(void*), old_protect, &old_protect);
            return true;
        }
    }
    return false;
}

// ============================================================
// Hook implementations
// ============================================================

static LPVOID WINAPI hk_VirtualAlloc(LPVOID lpAddress, SIZE_T dwSize,
                                      DWORD flAllocationType, DWORD flProtect) {
    if (g_in_our_alloc || !g_ready) {
        return g_real_VirtualAlloc(lpAddress, dwSize, flAllocationType, flProtect);
    }

    // Only intercept PAGE_READWRITE
    if (flProtect != PAGE_READWRITE) {
        return g_real_VirtualAlloc(lpAddress, dwSize, flAllocationType, flProtect);
    }

    // Case 1: New allocation (addr == NULL, RESERVE and/or COMMIT)
    if (lpAddress == nullptr && (flAllocationType & (MEM_RESERVE | MEM_COMMIT))) {
        size_t aligned_size = align_up(dwSize, ALLOC_GRANULARITY);

        if (g_carve_cs_init) EnterCriticalSection(&g_carve_cs);   // CARVE CS: shared with carve_donation_region
        size_t offset = alloc_from_free_list(aligned_size);
        if (offset == (size_t)-1) {
            offset = align_up(g_watermark, ALLOC_GRANULARITY);
            if (offset + aligned_size > ARENA_SIZE - HEAP_ZONE_SIZE) {
                if (g_carve_cs_init) LeaveCriticalSection(&g_carve_cs);
                // OUT-OF-ARENA LIVENESS probe: this span is out-of-arena — its liveness is never reverted by any
                // ring, so its in-band free/alloc links survive the rewind stale. Capture the OS addr + type so we
                // can tell whether the passthrough is a live carrier at our depth (vs dormant).
                void* pass = g_real_VirtualAlloc(lpAddress, dwSize, flAllocationType, flProtect);
                rblog::write("ARENA-PASSTHROUGH: FULL (watermark=0x%zX, need=0x%zX) => OS addr=0x%llX type=0x%lX "
                            "[OUT-OF-ARENA: liveness not reverted]",
                            g_watermark, aligned_size, (unsigned long long)(uintptr_t)pass, (unsigned long)flAllocationType);
                if (g_owned_heap) { static volatile long once = 0; if (_InterlockedCompareExchange(&once, 1, 0) == 0)
                    rblog::write("OWNED-HEAP P1 BREACH (arena full): VirtualAlloc passthrough to the OS at 0x%llX. This slab is out-of-arena and will never revert. Own-all-backing broken; raise ARENA_SIZE or close the leak.", (unsigned long long)(uintptr_t)pass); }
                return pass;
            }
            g_watermark = offset + aligned_size;
            if (g_watermark > g_watermark_peak) {
                size_t usable = ARENA_SIZE - HEAP_ZONE_SIZE;
                if (g_watermark_peak / (128ull*1024*1024) != g_watermark / (128ull*1024*1024))  // log each new 128MB high-water (not per-alloc)
                    rblog::write("ARENA-WATERMARK: peak=0x%zX of usable=0x%zX (%zu%%) — measure headroom before the passthrough leak",
                                 g_watermark, usable, (g_watermark * 100) / usable);
                g_watermark_peak = g_watermark;
            }
        }

        // Track reservation
        if (g_reservation_count < 4096) {
            g_reservations[g_reservation_count++] = { offset, aligned_size };
        }
        if (g_carve_cs_init) LeaveCriticalSection(&g_carve_cs);

        uintptr_t result_addr = g_arena_base + offset;

        if (flAllocationType & MEM_COMMIT) {
            g_in_our_alloc = true;
            LPVOID committed = g_real_VirtualAlloc((LPVOID)result_addr, dwSize,
                                                    MEM_COMMIT, PAGE_READWRITE);
            g_in_our_alloc = false;
            if (!committed) {
                rblog::write("arena: MEM_COMMIT failed at 0x%llX size=0x%zX err=%lu",
                            (unsigned long long)result_addr, dwSize, GetLastError());
                return nullptr;
            }
            size_t page_start = offset / PAGE_SIZE;
            size_t page_count = align_up(dwSize, PAGE_SIZE) / PAGE_SIZE;
            for (size_t p = 0; p < page_count; p++) {
                if (!is_committed(page_start + p)) {
                    set_committed(page_start + p);
                    g_committed_count++;
                }
            }
        }

        return (LPVOID)result_addr;
    }

    // Case 2: Commit within arena (addr != NULL, MEM_COMMIT only)
    if ((flAllocationType == MEM_COMMIT) && lpAddress != nullptr) {
        uintptr_t addr = (uintptr_t)lpAddress;
        if (addr >= g_arena_base && addr < g_arena_base + ARENA_SIZE) {
            g_in_our_alloc = true;
            LPVOID committed = g_real_VirtualAlloc(lpAddress, dwSize, MEM_COMMIT, PAGE_READWRITE);
            g_in_our_alloc = false;
            if (!committed) return nullptr;
            size_t off = addr - g_arena_base;
            size_t page_start = off / PAGE_SIZE;
            size_t page_count = align_up(dwSize, PAGE_SIZE) / PAGE_SIZE;
            for (size_t p = 0; p < page_count; p++) {
                if (!is_committed(page_start + p)) {
                    set_committed(page_start + p);
                    g_committed_count++;
                }
            }
            return committed;
        }
    }

    // Pass through
    return g_real_VirtualAlloc(lpAddress, dwSize, flAllocationType, flProtect);
}

static BOOL WINAPI hk_VirtualFree(LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType) {
    if (g_in_our_alloc || !g_ready) {
        return g_real_VirtualFree(lpAddress, dwSize, dwFreeType);
    }

    uintptr_t addr = (uintptr_t)lpAddress;
    if (addr < g_arena_base || addr >= g_arena_base + ARENA_SIZE) {
        return g_real_VirtualFree(lpAddress, dwSize, dwFreeType);
    }

    size_t offset = addr - g_arena_base;

    if (dwFreeType == MEM_DECOMMIT) {
        // Don't actually decommit — zero pages instead (keeps them committed for snapshot)
        size_t page_start = offset / PAGE_SIZE;
        size_t page_count = align_up(dwSize, PAGE_SIZE) / PAGE_SIZE;
        for (size_t p = 0; p < page_count; p++) {
            if (is_committed(page_start + p)) {
                memset((void*)(g_arena_base + (page_start + p) * PAGE_SIZE), 0, PAGE_SIZE);
            }
        }
        return TRUE;
    }

    if (dwFreeType == MEM_RELEASE) {
        int res_idx = find_reservation(offset);
        if (res_idx < 0) {
            return TRUE;  // Pretend success — orphaned reservation
        }
        size_t res_size = g_reservations[res_idx].size;

        size_t page_start = offset / PAGE_SIZE;
        size_t page_end   = (offset + res_size) / PAGE_SIZE;
        for (size_t p = page_start; p < page_end; p++) {
            if (is_committed(p)) {
                memset((void*)(g_arena_base + p * PAGE_SIZE), 0, PAGE_SIZE);
            }
        }

        add_to_free_list(offset, res_size);
        remove_reservation(res_idx);
        return TRUE;
    }

    return g_real_VirtualFree(lpAddress, dwSize, dwFreeType);
}

static LPVOID WINAPI hk_HeapAlloc(HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes) {
    arena::hook_count_inc(2);   // perf bisection: HeapAlloc fires/frame
    if (g_in_our_alloc || !g_ready || !g_heap_redirect_active) {
        return g_real_HeapAlloc(hHeap, dwFlags, dwBytes);
    }

    LPVOID result = heap_zone_alloc(dwBytes);
    if (result && (dwFlags & HEAP_ZERO_MEMORY)) {
        memset(result, 0, dwBytes);
    }
    return result;
}

// SITE-4 read-only XAPO double-free probe (real-heap frees only). Decides the XAPO crash family:
// 2nd free during resim => SUPPRESS (the resim re-ran the free, same class as the RTV fix);
// 2nd free NORMAL post-rollback (1st free straddling the boundary) => DEFER;
// no same-addr double-free (the fault is neighbor _HEAP_ENTRY corruption) => CORRUPTED-NEIGHBOR (a different class).
// Read-only: logs, never alters the free. Targeted to the XAPO vtable (0x140BAD1F0) to bound noise.
static void site4_probe(uintptr_t a, uintptr_t ra) {
    if (a < 0x10000) return;
    static uintptr_t s_addr[8192];
    static int       s_frame[8192];
    static uint8_t   s_phase[8192];   // 1 = freed during resim
    static uint8_t   s_xapo[8192];    // 1 = freed block's first qword == the XAPO vtable
    static uintptr_t s_mb = 0, s_xapo_vt = 0;
    if (!s_mb) { s_mb = (uintptr_t)GetModuleHandleA("umvc3.exe"); s_xapo_vt = s_mb + (0x140BAD1F0ULL - 0x140000000ULL); }
    uintptr_t vt = *(uintptr_t*)a;          // freed block's first qword (vtable for a COM object)
    bool is_xapo = (vt == s_xapo_vt);
    int idx = (int)((a >> 4) & 8191);
    int fr = resim::current_frame();
    bool rs = resim::resim_active();
    if (s_addr[idx] == a && s_xapo[idx]) {  // an XAPO previously freed at this slot, now freed again
        uintptr_t ra_ida = (ra >= s_mb && ra < s_mb + 0x1000000ULL) ? (ra - s_mb + 0x140000000ULL) : 0;
        rblog::write("SITE4-XAPO-DBLFREE: addr=0x%llX vt=0x%llX prev{frame=%d phase=%s} this{frame=%d phase=%s} ra=0x%llX(IDA 0x%llX)",
            (unsigned long long)a, (unsigned long long)vt,
            s_frame[idx], s_phase[idx] ? "resim" : "normal",
            fr, rs ? "resim" : "normal",
            (unsigned long long)ra, (unsigned long long)ra_ida);
        rblog::flush();
    }
    s_addr[idx] = a; s_frame[idx] = fr; s_phase[idx] = rs ? 1 : 0; s_xapo[idx] = is_xapo ? 1 : 0;
}

static volatile LONG g_site4_probe = 0;   // LEAN: SITE-4 XAPO double-free PROBE runs on every real-heap free (per-free hash + rblog::flush on hit). OFF by default; arm for XAPO double-free RE.
static BOOL WINAPI hk_HeapFree(HANDLE hHeap, DWORD dwFlags, LPVOID lpMem) {
    free_probe::Scope _fps;   // free_probe: per-free cost discriminator (read-only)
    if (g_in_our_alloc || !g_ready) {
        return g_real_HeapFree(hHeap, dwFlags, lpMem);
    }
    uintptr_t addr = (uintptr_t)lpMem;
    // No-op for heap zone and arena addresses (snapshot handles cleanup)
    if (is_heap_zone_addr(addr)) return TRUE;
    if (addr >= g_arena_base && addr < g_arena_base + ARENA_SIZE) return TRUE;
    if (g_site4_probe) site4_probe(addr, (uintptr_t)__builtin_return_address(0));   // SITE-4 read-only XAPO double-free probe (off in lean mode)
    return g_real_HeapFree(hHeap, dwFlags, lpMem);
}

static LPVOID WINAPI hk_HeapReAlloc(HANDLE hHeap, DWORD dwFlags, LPVOID lpMem, SIZE_T dwBytes) {
    if (g_in_our_alloc || !g_ready) {
        return g_real_HeapReAlloc(hHeap, dwFlags, lpMem, dwBytes);
    }
    if (is_heap_zone_addr((uintptr_t)lpMem)) {
        // Allocate new, copy old, leak old (snapshot handles cleanup)
        SIZE_T old_size = *(SIZE_T*)((uint8_t*)lpMem - HEAP_HEADER_SIZE);
        LPVOID new_mem = heap_zone_alloc(dwBytes);
        if (new_mem && lpMem) {
            memcpy(new_mem, lpMem, old_size < dwBytes ? old_size : dwBytes);
        }
        return new_mem;
    }
    return g_real_HeapReAlloc(hHeap, dwFlags, lpMem, dwBytes);
}

static SIZE_T WINAPI hk_HeapSize(HANDLE hHeap, DWORD dwFlags, LPCVOID lpMem) {
    if (g_in_our_alloc || !g_ready) {
        return g_real_HeapSize(hHeap, dwFlags, lpMem);
    }
    if (is_heap_zone_addr((uintptr_t)lpMem)) {
        return *(SIZE_T*)((uint8_t*)lpMem - HEAP_HEADER_SIZE);
    }
    return g_real_HeapSize(hHeap, dwFlags, lpMem);
}

// ============================================================
// Snapshot Ring Buffer
// ============================================================

struct RingSlot {
    int      frame;
    int      dirty_page_count;
    uint8_t* dirty_bits;       // MAX_PAGES / 8 bytes
    uint8_t* page_data;        // packed dirty page data
    int      page_data_capacity;
    uint32_t* page_map;        // page_idx -> data index
    bool     valid;
    // DEFERRED-FOLD: dense list of the page_idx values stored this save (copy-loop order), so the
    // fold iterates O(dirty) instead of scanning MAX_PAGES=262144 bits. Populated for free in the copy loop; read by
    // both the synchronous fold (fold_into_baseline) and the deferred fold_assign. dirty_stored = valid entries.
    uint32_t* dirty_idx_list;  // [0..dirty_stored) = page_idx values with a stored page this frame
    int      dirty_stored;
};

static RingSlot  g_ring[RING_SLOTS];
static int       g_ring_head = 0;

// GetWriteWatch output buffer
static PVOID*    g_watch_buf = nullptr;
static ULONG_PTR g_watch_capacity = 0;

// Global dirty bits (union of all ring slot dirty bits)
static uint8_t*  g_dirty_bits = nullptr;

// F_REDERIVE page exclusions (the restore-by-structure invariant: minimal-restore + re-derive is the DEFAULT).
// Pages in a registered RE-DERIVE region are SKIPPED by load() — they keep their LIVE value and the resim
// re-derives them (rendering/audio are a deterministic function of gameplay). Set per-rollback by
// dynamic_restore (PH_SAVE) from the schema's RE-DERIVE classification. This is how we "remove pages".
static uint8_t*  g_rederive_excluded = nullptr;   // bit p = skip reverting page p (RE-DERIVE region)
static bool      g_have_exclusions   = false;

// Baseline: full snapshot of all committed pages at F5 press
static uint8_t*  g_baseline      = nullptr;
static uint8_t*  g_baseline_bits = nullptr;  // which pages are in baseline
static uint32_t* g_baseline_map  = nullptr;  // page_idx -> baseline buffer index
static size_t    g_baseline_pages = 0;
static bool      g_has_baseline  = false;
static uint8_t   g_last_orphaned[MAX_PAGES / 8];  // bit p = page p was orphan-zeroed by the last load (read-only diag)
static int32_t*  g_last_source = nullptr;          // per-page source of the last load: >=0 ring frame, -1 baseline, -2 orphan, -3 live/not-restored

// WINDOWED RESTORE (perf): revert only pages written after the target frame, not the cumulative g_dirty_bits
// (which spans the whole ring window, ~60 frames). A depth-D rollback only needs to undo D frames of writes;
// every other page already holds its target value (its last write was <= target => live == target). The
// revert set = OR(per-slot dirty_bits where slot.frame > target); the SOURCE walk is unchanged (slots <= target
// + baseline). Provably state-identical to the full revert, just touches ~D/60 of the pages. This is the
// arena::load 700ms->~70ms fix. A/B toggle via set_windowed_restore (default ON).
static bool      g_windowed_restore = true;    // FAST windowed restore (default) — full revert proved the allocator list breaks are revert-scope, now fixed surgically by set_coherent_full_ranges (scoped full-revert of just the list pool pages). Windowed handles the rest at speed.
static uint8_t*  g_revert_bits      = nullptr;     // scratch: pages written after target (built per load)
static double    g_last_restore_ms = 0, g_last_oracle_ms = 0;   // STABILITY heartbeat
// Per-load scheduler-chain RE walks (DIAG-CHILD + ANIM-BVC). Pure read-only diagnostics that walk 128 sched
// lines x up to 512 entities x 64 children every rollback. Off by default — they were a measured slice of the
// rollback freeze. Re-arm (Numpad-gated in resim) only for stale-vtable RE.
static volatile LONG g_load_diag_walk = 0;

// Supplemental baseline for post-baseline pages
static uint8_t*  g_supplemental       = nullptr;
static size_t    g_supplemental_count = 0;
constexpr size_t SUPPLEMENTAL_MAX     = 200000;  // pages

// REGION-SPLIT telemetry (measurement-only): how much of the per-frame save copy + baseline fold is the
// sRender render body — the region arena::load already leaves live (load-side F_REDERIVE). If it dominates the dirty
// mass, a save-side skip of it collapses both the copy and the fold; if not, the fold-defer is the
// safer option. Pure counters. Body = [sr, sr+0x67000) ∪ [sr+0x68000, sr+0x867000); sr=*(0x140E179A8). sr==0 pre-ctor.
static long long g_fold_total_pages = 0;   // pages the fold actually memcpy'd this reporting window
static long long g_fold_body_pages  = 0;   // of those, ones in the sRender body range
static inline uintptr_t sr_base() { return addr::g_base ? *(uintptr_t*)addr::resolve(0x140E179A8) : 0; }
static inline bool in_sr_body(uintptr_t a, uintptr_t sr) {
    return sr && ((a >= sr && a < sr + 0x67000) || (a >= sr + 0x68000 && a < sr + 0x867000));
}

// Resolve the baseline destination pointer for arena page `p` (existing baseline slot, existing supplemental slot,
// or a freshly-committed supplemental page). Returns nullptr if the page must be dropped (supplemental full).
// MAIN-THREAD only: mutates g_baseline_map / g_baseline_bits / g_supplemental_count and may VirtualAlloc — the
// deferred bg fold worker must never call this (it only memcpies into the dst this returns). Shared verbatim by the
// synchronous fold (fold_into_baseline) and the deferred fold_assign so both produce byte-identical baselines.
static void* resolve_fold_dst(size_t p) {
    uint32_t bl_idx = g_baseline_map[p];
    if (bl_idx != 0xFFFFFFFF) {
        if (bl_idx & 0x80000000) {
            size_t supp_idx = bl_idx & 0x7FFFFFFF;
            return (g_supplemental && supp_idx < g_supplemental_count) ? g_supplemental + supp_idx * PAGE_SIZE : nullptr;
        }
        return g_baseline + (size_t)bl_idx * PAGE_SIZE;
    }
    if (g_supplemental && g_supplemental_count < SUPPLEMENTAL_MAX) {
        g_in_our_alloc = true;
        void* committed = VirtualAlloc(g_supplemental + g_supplemental_count * PAGE_SIZE,
                                       PAGE_SIZE, MEM_COMMIT, PAGE_READWRITE);
        g_in_our_alloc = false;
        if (committed) {
            g_baseline_map[p] = (uint32_t)(g_supplemental_count | 0x80000000);
            g_baseline_bits[p / 8] |= (1 << (p % 8));
            g_supplemental_count++;
            return committed;
        }
    }
    static int s_dropped = 0;
    if (++s_dropped <= 5 || (s_dropped % 100) == 0)
        rblog::write("FOLD-DROP: page %zu dropped (supplemental full, count=%zu/%zu, total dropped=%d)",
                     p, g_supplemental_count, (size_t)SUPPLEMENTAL_MAX, s_dropped);
    return nullptr;
}

// --- Fold evicted ring slot into baseline (SYNCHRONOUS: g_fold_defer OFF, the proven baseline path) ---
// Now iterates the dense dirty_idx_list instead of scanning MAX_PAGES bits. Byte-identical result.
static void fold_into_baseline(RingSlot& slot) {
    if (!slot.valid || !g_baseline_map) return;
    const uintptr_t _fsr = sr_base();
    for (int k = 0; k < slot.dirty_stored; k++) {
        size_t p = slot.dirty_idx_list[k];
        uint32_t data_idx = slot.page_map[p];
        if (data_idx == 0xFFFFFFFF) continue;
        g_fold_total_pages++;                                                  // measurement: a page the fold copies
        if (in_sr_body(g_arena_base + p * PAGE_SIZE, _fsr)) g_fold_body_pages++;
        void* dst = resolve_fold_dst(p);
        if (dst) memcpy(dst, slot.page_data + (size_t)data_idx * PAGE_SIZE, PAGE_SIZE);
    }
}

// ============================================================
// DEFERRED FOLD — one persistent bg thread does the baseline memcpy off the critical path (optional, default OFF).
// The fold reads an IMMUTABLE buffer (a slot snapshotted ~60 frames ago) → when it runs cannot change what it
// produces → determinism-safe by construction. Destination assignment + all allocation stay on the main thread
// (fold_assign); the bg worker does pure memcpy only (no lock, no alloc, no log) → a freeze SuspendThread landing
// on it strands nothing (holds no heap/loader/CS lock). Two strict SPSC rings: submit (main→bg) + return (bg→main).
// Default OFF (g_fold_defer). 
// ============================================================
struct FoldJob { uint8_t* src_page_data; int src_capacity; void** dst_list; int count; long long seq; };
static const int FOLD_RING = 8;                          // > max in-flight (~1); power of two
static FoldJob   g_submit[FOLD_RING] = {};
static volatile long g_submit_head = 0, g_submit_tail = 0;   // main produces head, bg consumes tail (SPSC)
static void**    g_dstlist_store[FOLD_RING] = {};       // per-submit-slot dst_list backing (grown on main only)
static int       g_dstlist_cap[FOLD_RING]   = {};
struct RetBuf { uint8_t* ptr; int cap; };
static RetBuf    g_return[FOLD_RING] = {};
static volatile long g_return_head = 0, g_return_tail = 0;   // bg produces head, main consumes tail (SPSC)
static HANDLE    g_fold_thread = nullptr;
static HANDLE    g_fold_wake   = nullptr;               // auto-reset event
static volatile long g_fold_exit = 0;
static volatile long long g_fold_submitted = 0;         // main-only writer (monotonic)
static volatile long long g_fold_completed = 0;         // bg-only writer (monotonic)
static volatile long g_fold_defer = 0;                  // A/B: 1 = defer fold to bg thread; 0 = synchronous (default)

// bg→main return ring (single producer = bg). Non-blocking; if momentarily full, drop the buffer (main VirtualAllocs
// a fresh one next eviction — rare, safe, never a leak that grows without bound since the ring self-limits).
static void push_return(uint8_t* ptr, int cap) {
    long head = g_return_head;
    if (head - g_return_tail >= FOLD_RING) return;      // full → drop (buffer is freed with the arena at shutdown)
    g_return[head & (FOLD_RING - 1)] = { ptr, cap };
    MemoryBarrier();
    g_return_head = head + 1;
}
// main→ pop a returned buffer to reuse as a slot's fresh page_data (single consumer = main). {null,0} if empty.
static RetBuf pop_return() {
    if (g_return_tail == g_return_head) return { nullptr, 0 };
    RetBuf b = g_return[g_return_tail & (FOLD_RING - 1)];
    MemoryBarrier();
    g_return_tail++;
    return b;
}
// main-thread: grow submit-slot ri's dst_list backing to hold >= need pointers. Returns false on alloc failure.
static bool ensure_dstlist_cap(int ri, int need) {
    if (g_dstlist_cap[ri] >= need && g_dstlist_store[ri]) return true;
    int newcap = need + need / 4 + 64;
    if (g_dstlist_store[ri]) { g_in_our_alloc = true; VirtualFree(g_dstlist_store[ri], 0, MEM_RELEASE); g_in_our_alloc = false; }
    g_in_our_alloc = true;
    g_dstlist_store[ri] = (void**)VirtualAlloc(nullptr, (size_t)newcap * sizeof(void*), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    g_in_our_alloc = false;
    g_dstlist_cap[ri] = g_dstlist_store[ri] ? newcap : 0;
    return g_dstlist_store[ri] != nullptr;
}
// main-thread: build the deferred job for the evicted slot. Resolves every destination (allocating supplemental pages
// here), zeroing gap entries so the bg worker skips them. Reads dirty_idx_list/page_map + baseline metadata only —
// never the page_data BYTES (those the bg worker reads from the detached src). dst_list is indexed by data_idx so the
// worker's memcpy(dst_list[i], src + i*PAGE_SIZE) lands the right page.
static void fold_assign(RingSlot& slot, FoldJob& job) {
    const uintptr_t _fsr = sr_base();
    int count = slot.dirty_page_count;
    for (int i = 0; i < count; i++) job.dst_list[i] = nullptr;      // gaps (out-of-range pages) stay null
    for (int k = 0; k < slot.dirty_stored; k++) {
        size_t p = slot.dirty_idx_list[k];
        uint32_t data_idx = slot.page_map[p];
        if (data_idx == 0xFFFFFFFF || (int)data_idx >= count) continue;
        g_fold_total_pages++;                                       // measurement (same counters as sync fold)
        if (in_sr_body(g_arena_base + p * PAGE_SIZE, _fsr)) g_fold_body_pages++;
        job.dst_list[data_idx] = resolve_fold_dst(p);               // main-thread alloc; bg memcpies src[data_idx]→dst
    }
    job.count = count;
}
// the background fold worker: pure memcpy, forever parked until woken. Holds NO lock at any point (freeze-safe).
static DWORD WINAPI fold_worker(LPVOID) {
    for (;;) {
        WaitForSingleObject(g_fold_wake, INFINITE);
        if (g_fold_exit) return 0;
        while (g_submit_tail != g_submit_head) {                    // SPSC consume, FIFO (newest-wins preserved)
            FoldJob& j = g_submit[g_submit_tail & (FOLD_RING - 1)];
            for (int i = 0; i < j.count; i++)
                if (j.dst_list[i])
                    memcpy(j.dst_list[i], j.src_page_data + (size_t)i * PAGE_SIZE, PAGE_SIZE);
            long long done = j.seq;
            uint8_t* src = j.src_page_data; int cap = j.src_capacity;
            MemoryBarrier();
            g_submit_tail++;                                        // publish consume after the memcpy
            push_return(src, cap);                                  // hand the src buffer back to main's spare pool
            g_fold_completed = done;                               // release: seq handshake for fold_drain
        }
    }
}

// --- Rebuild g_dirty_bits from valid ring slots ---
static void rebuild_dirty_bits() {
    memset(g_dirty_bits, 0, MAX_PAGES / 8);
    for (int i = 0; i < RING_SLOTS; i++) {
        if (!g_ring[i].valid) continue;
        for (size_t j = 0; j < MAX_PAGES / 8; j++) {
            g_dirty_bits[j] |= g_ring[i].dirty_bits[j];
        }
    }
}

} // anonymous namespace

// ============================================================
// Public API
// ============================================================

namespace arena {

// PERF A/B switch accessors (storage is g_no_*_flag at file scope above; see arena.h).
bool no_writewatch()   { return g_no_writewatch_flag; }
bool no_hooks()        { return g_no_hooks_flag; }
bool no_heapredirect() { return g_no_heapredirect_flag; }
void set_startup_flags(bool nww, bool nh, bool nhr) { g_no_writewatch_flag = nww; g_no_hooks_flag = nh; g_no_heapredirect_flag = nhr; }

// Throttled never-reuse frontier meter. Monotonic growth of these = the locality-collapse signature.
void log_growth() {
    rblog::write("ARENA-GROWTH: vmark=%zuMB peak=%zuMB committed=%dMB heapzone=%lldMB/%dMB (frontier; monotonic rise => never-reuse locality tax)",
                 g_watermark >> 20, g_watermark_peak >> 20, (int)((size_t)g_committed_count * PAGE_SIZE >> 20),
                 (long long)(g_heap_zone_offset >> 20), (int)(HEAP_ZONE_SIZE >> 20));
}
bool startup_flag(const char* env_name, const char* file_name) {
    char buf[16];
    if (GetEnvironmentVariableA(env_name, buf, sizeof(buf)) > 0) return true;   // env var present (any value)
    char path[MAX_PATH];
    DWORD n = GetModuleFileNameA(NULL, path, MAX_PATH);                          // the game .exe path
    if (n > 0 && n < MAX_PATH) {
        char* slash = strrchr(path, '\\');
        if (slash && (size_t)(slash + 1 - path) + strlen(file_name) + 1 < MAX_PATH) {
            strcpy(slash + 1, file_name);                                        // sentinel beside the .exe
            if (GetFileAttributesA(path) != INVALID_FILE_ATTRIBUTES) return true;
        }
    }
    return false;
}

bool early_init() {
    // Allocate committed bitset (32KB for 262144 pages)
    if (!g_carve_cs_init) { InitializeCriticalSection(&g_carve_cs); g_carve_cs_init = true; }
    g_in_our_alloc = true;
    g_committed = (uint8_t*)VirtualAlloc(nullptr, MAX_PAGES / 8,
                                          MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    g_in_our_alloc = false;
    if (!g_committed) {
        rblog::write("arena: failed to allocate committed bitset");
        return false;
    }
    memset(g_committed, 0, MAX_PAGES / 8);

    // RE-DERIVE exclusion bitmap (one bit per page; inert until dynamic_restore registers regions)
    g_in_our_alloc = true;
    g_rederive_excluded = (uint8_t*)VirtualAlloc(nullptr, MAX_PAGES / 8,
                                                 MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    g_in_our_alloc = false;
    if (g_rederive_excluded) memset(g_rederive_excluded, 0, MAX_PAGES / 8);

    // Reserve the arena with MEM_WRITE_WATCH. PERF A/B: 'nowritewatch' drops the flag so the game's
    // working set runs on plain committed memory — isolates the write-watch per-write tax (rollback disabled).
    const DWORD WW = g_no_writewatch_flag ? 0u : (DWORD)MEM_WRITE_WATCH;
    if (g_no_writewatch_flag)
        rblog::write("arena: NO-WRITE-WATCH A/B ACTIVE — arena reserved WITHOUT MEM_WRITE_WATCH (rollback save disabled; perf isolation only)");
    g_in_our_alloc = true;
    void* arena_ptr = VirtualAlloc((void*)PREFERRED_ADDR, ARENA_SIZE,
                                    MEM_RESERVE | WW, PAGE_READWRITE);
    if (!arena_ptr) {
        arena_ptr = VirtualAlloc((void*)FALLBACK_ADDR, ARENA_SIZE,
                                  MEM_RESERVE | WW, PAGE_READWRITE);
    }
    if (!arena_ptr) {
        arena_ptr = VirtualAlloc(nullptr, ARENA_SIZE,
                                  MEM_RESERVE | WW, PAGE_READWRITE);
    }
    g_in_our_alloc = false;

    if (!arena_ptr) {
        rblog::write("arena: FATAL — could not reserve the arena (err=%lu)", GetLastError());
        return false;
    }

    g_arena_base = (uintptr_t)arena_ptr;
    g_watermark = 0;
    g_committed_count = 0;

    rblog::write("arena: reserved %zuMB at 0x%llX (usable=%zuMB before passthrough; placement=%s) — log base so we know if the substrate lands in or below the arena",
                 ARENA_SIZE >> 20, (unsigned long long)g_arena_base, (ARENA_SIZE - HEAP_ZONE_SIZE) >> 20,
                 (g_arena_base == PREFERRED_ADDR) ? "PREFERRED" : (g_arena_base == FALLBACK_ADDR ? "FALLBACK" : "OS-PLACED-low"));

    // Allocate watch buffer
    g_in_our_alloc = true;
    g_watch_capacity = MAX_PAGES;
    g_watch_buf = (PVOID*)VirtualAlloc(nullptr, g_watch_capacity * sizeof(PVOID),
                                        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    g_in_our_alloc = false;
    if (!g_watch_buf) {
        rblog::write("arena: failed to allocate watch buffer");
        return false;
    }

    // Allocate global dirty bits
    g_in_our_alloc = true;
    g_dirty_bits = (uint8_t*)VirtualAlloc(nullptr, MAX_PAGES / 8,
                                           MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    g_in_our_alloc = false;
    if (!g_dirty_bits) {
        rblog::write("arena: failed to allocate dirty bits");
        return false;
    }
    memset(g_dirty_bits, 0, MAX_PAGES / 8);

    // Allocate windowed-revert scratch bitmap (pages written after the rollback target)
    g_in_our_alloc = true;
    g_revert_bits = (uint8_t*)VirtualAlloc(nullptr, MAX_PAGES / 8,
                                           MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    g_in_our_alloc = false;
    if (!g_revert_bits) {
        rblog::write("arena: failed to allocate revert bits");
        return false;
    }
    memset(g_revert_bits, 0, MAX_PAGES / 8);

    // Allocate baseline map
    g_in_our_alloc = true;
    g_baseline_map = (uint32_t*)VirtualAlloc(nullptr, MAX_PAGES * sizeof(uint32_t),
                                              MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    g_in_our_alloc = false;
    if (!g_baseline_map) {
        rblog::write("arena: failed to allocate baseline map");
        return false;
    }
    memset(g_baseline_map, 0xFF, MAX_PAGES * sizeof(uint32_t));

    // Commit heap zone (last 256MB of arena)
    g_heap_zone_base = g_arena_base + ARENA_SIZE - HEAP_ZONE_SIZE;
    g_in_our_alloc = true;
    void* hz = VirtualAlloc((void*)g_heap_zone_base, HEAP_ZONE_SIZE,
                             MEM_COMMIT, PAGE_READWRITE);
    g_in_our_alloc = false;
    if (hz) {
        size_t page_start = (ARENA_SIZE - HEAP_ZONE_SIZE) / PAGE_SIZE;
        for (size_t p = 0; p < HEAP_ZONE_PAGES; p++) {
            if (!is_committed(page_start + p)) {
                set_committed(page_start + p);
                g_committed_count++;
            }
        }
        rblog::write("arena: heap zone committed at 0x%llX (%zu MB)",
                    (unsigned long long)g_heap_zone_base, HEAP_ZONE_SIZE / (1024 * 1024));
    } else {
        rblog::write("arena: WARNING — heap zone commit failed (err=%lu)", GetLastError());
    }
    g_heap_zone_offset = 0;

    // Initialize ring slots
    for (int i = 0; i < RING_SLOTS; i++) {
        g_ring[i].frame = -1;
        g_ring[i].dirty_page_count = 0;
        g_ring[i].page_data = nullptr;
        g_ring[i].page_data_capacity = 0;
        g_ring[i].valid = false;
        g_ring[i].dirty_stored = 0;

        g_in_our_alloc = true;
        g_ring[i].dirty_bits = (uint8_t*)VirtualAlloc(nullptr, MAX_PAGES / 8,
                                    MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        g_ring[i].page_map = (uint32_t*)VirtualAlloc(nullptr, MAX_PAGES * sizeof(uint32_t),
                                    MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        // dirty_idx_list sized to MAX_PAGES once (never grows): dirty count can never exceed total pages. 1MB/slot,
        // parallels page_map — trades ~60MB commit for zero growth-path complexity (perf option, memory is cheap here).
        g_ring[i].dirty_idx_list = (uint32_t*)VirtualAlloc(nullptr, MAX_PAGES * sizeof(uint32_t),
                                    MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        g_in_our_alloc = false;

        if (!g_ring[i].dirty_bits || !g_ring[i].page_map || !g_ring[i].dirty_idx_list) {
            rblog::write("arena: failed to pre-allocate ring slot %d", i);
            return false;
        }
    }

    g_in_our_alloc = true;
    g_last_source = (int32_t*)VirtualAlloc(nullptr, MAX_PAGES * sizeof(int32_t),
                                MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    g_in_our_alloc = false;
    if (!g_last_source) { rblog::write("arena: failed to allocate g_last_source"); return false; }

    // Install IAT hooks on game exe
    void* orig_va = nullptr;
    void* orig_vf = nullptr;
    if (!iat_patch("KERNEL32.dll", "VirtualAlloc", (void*)&hk_VirtualAlloc, &orig_va))
        iat_patch("kernel32.dll", "VirtualAlloc", (void*)&hk_VirtualAlloc, &orig_va);
    if (!iat_patch("KERNEL32.dll", "VirtualFree", (void*)&hk_VirtualFree, &orig_vf))
        iat_patch("kernel32.dll", "VirtualFree", (void*)&hk_VirtualFree, &orig_vf);

    g_real_VirtualAlloc = orig_va ? (VirtualAlloc_fn)orig_va :
        (VirtualAlloc_fn)GetProcAddress(GetModuleHandleA("kernel32.dll"), "VirtualAlloc");
    g_real_VirtualFree = orig_vf ? (VirtualFree_fn)orig_vf :
        (VirtualFree_fn)GetProcAddress(GetModuleHandleA("kernel32.dll"), "VirtualFree");

    rblog::write("arena: IAT VirtualAlloc=%s VirtualFree=%s",
                orig_va ? "OK" : "FAIL", orig_vf ? "OK" : "FAIL");

    // Heap hooks (not active until activate_heap_redirect)
    void* orig_ha = nullptr;
    void* orig_hf = nullptr;
    void* orig_hra = nullptr;
    void* orig_hs = nullptr;
    if (!iat_patch("KERNEL32.dll", "HeapAlloc", (void*)&hk_HeapAlloc, &orig_ha))
        iat_patch("kernel32.dll", "HeapAlloc", (void*)&hk_HeapAlloc, &orig_ha);
    if (!iat_patch("KERNEL32.dll", "HeapFree", (void*)&hk_HeapFree, &orig_hf))
        iat_patch("kernel32.dll", "HeapFree", (void*)&hk_HeapFree, &orig_hf);
    if (!iat_patch("KERNEL32.dll", "HeapReAlloc", (void*)&hk_HeapReAlloc, &orig_hra))
        iat_patch("kernel32.dll", "HeapReAlloc", (void*)&hk_HeapReAlloc, &orig_hra);
    if (!iat_patch("KERNEL32.dll", "HeapSize", (void*)&hk_HeapSize, &orig_hs))
        iat_patch("kernel32.dll", "HeapSize", (void*)&hk_HeapSize, &orig_hs);

    g_real_HeapAlloc = orig_ha ? (HeapAlloc_fn)orig_ha :
        (HeapAlloc_fn)GetProcAddress(GetModuleHandleA("kernel32.dll"), "HeapAlloc");
    g_real_HeapFree = orig_hf ? (HeapFree_fn)orig_hf :
        (HeapFree_fn)GetProcAddress(GetModuleHandleA("kernel32.dll"), "HeapFree");
    g_real_HeapReAlloc = orig_hra ? (HeapReAlloc_fn)orig_hra :
        (HeapReAlloc_fn)GetProcAddress(GetModuleHandleA("kernel32.dll"), "HeapReAlloc");
    g_real_HeapSize = orig_hs ? (HeapSize_fn)orig_hs :
        (HeapSize_fn)GetProcAddress(GetModuleHandleA("kernel32.dll"), "HeapSize");

    rblog::write("arena: IAT HeapAlloc=%s HeapFree=%s HeapReAlloc=%s HeapSize=%s",
                orig_ha ? "OK" : "FAIL", orig_hf ? "OK" : "FAIL",
                orig_hra ? "OK" : "FAIL", orig_hs ? "OK" : "FAIL");

    g_ready = true;
    rblog::write("arena: ready (base=0x%llX, %d committed pages, %d ring slots)",
                (unsigned long long)g_arena_base, g_committed_count, RING_SLOTS);

    // DEFERRED-FOLD: start the persistent bg fold worker (parked on g_fold_wake until g_fold_defer enqueues a job).
    // Not whitelisted in suspend — freeze() auto-catches it via NtGetNextThread and it holds nothing when suspended
    // (drain-before-freeze guarantees it is idle across both rollback freezes). Precedent: the hang_detector watchdog.
    g_fold_wake = CreateEventA(nullptr, FALSE, FALSE, nullptr);   // auto-reset, initially non-signaled
    if (g_fold_wake) g_fold_thread = CreateThread(nullptr, 0, fold_worker, nullptr, 0, nullptr);
    rblog::write("arena: deferred-fold worker=%s (g_fold_defer=%ld, default OFF — A/B via set_fold_defer)",
                g_fold_thread ? "started" : "FAILED", g_fold_defer);

    // EARLY HEAP REDIRECT — arm the HeapAlloc redirect here (end of early_init = DLL_PROCESS_ATTACH), not deferred to
    // init_thread. The engine batch-builds its MtScalable/* allocator CONTROL descriptors via malloc->HeapAlloc during
    // early startup; if the redirect arms only later (the old Sleep(5000) window), those controls land on the real
    // low-address process heap (0xD5...) = OUT-of-arena => the control/pool split => the L_FREE_LIST_DLL tear + the
    // alloc-ring/coherent-full scaffolding. Arming now lands every control in the captured heap zone, one in-arena unit
    // with its slabs => the free-list can't tear. Gated by no_heapredirect() (the A/B safety fallback / native-heap mode).
    if (!no_heapredirect()) activate_heap_redirect();

    return true;
}

void activate_heap_redirect() {
    g_heap_redirect_active = true;
    rblog::write("arena: HeapAlloc redirect ACTIVE (heap zone at 0x%llX, %zu MB)",
                (unsigned long long)g_heap_zone_base, HEAP_ZONE_SIZE / (1024 * 1024));
    // READER: probe heap zone for the MtScalable control fingerprint now that all game statics
    // (including MtScalable controls) have been HeapAlloc'd into the zone. If probe fails, reader
    // silently skips all pages (g_ctrl==0 guard in compare_page); a delayed re-probe is acceptable.
    reader::probe_ctrl(g_heap_zone_base, HEAP_ZONE_SIZE);
}

bool capture_baseline() {
    if (!g_ready) return false;

    // Get all written pages since arena creation (atomic get+reset)
    ULONG_PTR count = g_watch_capacity;
    DWORD granularity = 0;
    UINT result = GetWriteWatch(WRITE_WATCH_FLAG_RESET, (PVOID)g_arena_base, ARENA_SIZE,
                                 g_watch_buf, &count, &granularity);
    if (result != 0) {
        rblog::write("arena: GetWriteWatch failed in capture_baseline (err=%lu)", GetLastError());
        return false;
    }

    rblog::write("arena: capture_baseline: %llu dirty pages, %d committed total",
                (unsigned long long)count, g_committed_count);

    // Free old baseline
    if (g_baseline) {
        g_in_our_alloc = true;
        VirtualFree(g_baseline, 0, MEM_RELEASE);
        g_in_our_alloc = false;
        g_baseline = nullptr;
    }
    if (g_baseline_bits) {
        g_in_our_alloc = true;
        VirtualFree(g_baseline_bits, 0, MEM_RELEASE);
        g_in_our_alloc = false;
        g_baseline_bits = nullptr;
    }

    size_t baseline_bytes = (size_t)g_committed_count * PAGE_SIZE;
    if (baseline_bytes == 0) {
        rblog::write("arena: capture_baseline: no committed pages");
        g_baseline_pages = 0;
        g_has_baseline = true;
        return true;
    }

    g_in_our_alloc = true;
    g_baseline = (uint8_t*)VirtualAlloc(nullptr, baseline_bytes,
                                         MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    g_baseline_bits = (uint8_t*)VirtualAlloc(nullptr, MAX_PAGES / 8,
                                              MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    g_in_our_alloc = false;

    if (!g_baseline || !g_baseline_bits) {
        rblog::write("arena: capture_baseline: allocation failed (need %zu MB)",
                    baseline_bytes / (1024 * 1024));
        return false;
    }

    memset(g_baseline_bits, 0, MAX_PAGES / 8);
    memset(g_baseline_map, 0xFF, MAX_PAGES * sizeof(uint32_t));

    // Allocate supplemental baseline
    if (g_supplemental) {
        g_in_our_alloc = true;
        VirtualFree(g_supplemental, 0, MEM_RELEASE);
        g_in_our_alloc = false;
    }
    g_in_our_alloc = true;
    g_supplemental = (uint8_t*)VirtualAlloc(nullptr, SUPPLEMENTAL_MAX * PAGE_SIZE,
                                             MEM_RESERVE, PAGE_READWRITE);
    g_in_our_alloc = false;
    g_supplemental_count = 0;

    // Copy all committed pages to baseline
    size_t bl_idx = 0;
    for (size_t p = 0; p < MAX_PAGES && bl_idx < (size_t)g_committed_count; p++) {
        if (is_committed(p)) {
            memcpy(g_baseline + bl_idx * PAGE_SIZE,
                   (void*)(g_arena_base + p * PAGE_SIZE), PAGE_SIZE);
            g_baseline_bits[p / 8] |= (1 << (p % 8));
            g_baseline_map[p] = (uint32_t)bl_idx;
            bl_idx++;
        }
    }
    g_baseline_pages = bl_idx;

    // Clear dirty bits — next save starts clean
    memset(g_dirty_bits, 0, MAX_PAGES / 8);

    // Invalidate all ring slots
    for (int i = 0; i < RING_SLOTS; i++) {
        g_ring[i].valid = false;
        g_ring[i].frame = -1;
    }
    g_ring_head = 0;

    g_has_baseline = true;
    rblog::write("arena: captured baseline: %zu pages (%.1f MB)",
                g_baseline_pages, (double)(g_baseline_pages * PAGE_SIZE) / (1024.0 * 1024.0));
    return true;
}

bool is_ready() { return g_ready; }
bool has_baseline() { return g_has_baseline; }

bool is_arena_addr(uintptr_t addr) {
    return addr >= g_arena_base && addr < g_arena_base + ARENA_SIZE;
}

bool is_committed_addr(uintptr_t addr) {
    if (addr < g_arena_base || addr >= g_arena_base + ARENA_SIZE) return false;
    size_t page_idx = (addr - g_arena_base) / PAGE_SIZE;
    return is_committed(page_idx);
}

// SUBSTRATE COHERENCE primitive (see arena.h). Generalizes the bone-array force-dirty loop
// (resim.cpp force_dirty_entity): touch each committed page so GetWriteWatch harvests it at save().
void force_dirty_range(uintptr_t base_addr, size_t size, size_t cap) {
    if (cap && size > cap) size = cap;
    for (uintptr_t off = 0; off < size; off += PAGE_SIZE) {
        if (is_committed_addr(base_addr + off)) {
            volatile uint8_t* p = (volatile uint8_t*)(base_addr + off);
            *p = *p;
        }
    }
}

// Register the RE-DERIVE regions whose pages load() should SKIP reverting (kept live -> resim re-derives).
// Only in-arena ranges are accepted; called per-rollback by dynamic_restore from the schema classification.
void set_rederive_exclusions(const uintptr_t* bases, const size_t* sizes, int n) {
    if (!g_rederive_excluded) { g_have_exclusions = false; return; }
    memset(g_rederive_excluded, 0, MAX_PAGES / 8);
    int regions = 0; size_t total_pages = 0;
    for (int i = 0; i < n; i++) {
        uintptr_t base = bases[i]; size_t size = sizes[i];
        if (!base || !size) continue;
        if (base < g_arena_base || base >= g_arena_base + ARENA_SIZE) continue;   // in-arena only
        uintptr_t end = base + size;
        if (end > g_arena_base + ARENA_SIZE) end = g_arena_base + ARENA_SIZE;
        size_t p0 = (base - g_arena_base) / PAGE_SIZE;
        size_t p1 = (end - g_arena_base + PAGE_SIZE - 1) / PAGE_SIZE;             // round up to whole pages
        for (size_t p = p0; p < p1 && p < MAX_PAGES; p++) {
            g_rederive_excluded[p / 8] |= (uint8_t)(1u << (p % 8));
            total_pages++;
        }
        regions++;
    }
    g_have_exclusions = (regions > 0);
    rblog::write("arena: RE-DERIVE exclusions set — %d/%d regions in-arena, %zu pages (%.1f MB) will skip revert",
                 regions, n, total_pages, (double)total_pages * PAGE_SIZE / (1024.0 * 1024.0));
}

void clear_rederive_exclusions() { g_have_exclusions = false; }

// SCOPED COHERENT RESTORE — pages whose bit is set here are FULL-reverted (to target) even under windowed mode.
static uint8_t* g_coherent_full = nullptr;   // bit p = force-full-revert page p (a list coherence-group page)
static bool     g_have_cfull    = false;
void set_coherent_full_ranges(const uintptr_t* bases, const size_t* sizes, int n) {
    if (!g_coherent_full) {
        g_coherent_full = (uint8_t*)VirtualAlloc(nullptr, MAX_PAGES / 8, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!g_coherent_full) { g_have_cfull = false; return; }
    }
    memset(g_coherent_full, 0, MAX_PAGES / 8);
    int regions = 0; size_t total_pages = 0;
    for (int i = 0; i < n; i++) {
        uintptr_t base = bases[i]; size_t size = sizes[i];
        if (!base || !size) continue;
        if (base < g_arena_base || base >= g_arena_base + ARENA_SIZE) continue;   // in-arena only
        uintptr_t end = base + size;
        if (end > g_arena_base + ARENA_SIZE) end = g_arena_base + ARENA_SIZE;
        size_t p0 = (base - g_arena_base) / PAGE_SIZE;
        size_t p1 = (end - g_arena_base + PAGE_SIZE - 1) / PAGE_SIZE;
        for (size_t p = p0; p < p1 && p < MAX_PAGES; p++) {
            g_coherent_full[p / 8] |= (uint8_t)(1u << (p % 8));
            total_pages++;
        }
        regions++;
    }
    g_have_cfull = (regions > 0);
}
void clear_coherent_full_ranges() { g_have_cfull = false; }

// Read-only query: was this address's page EXCLUDED from the revert (a PRESERVE/live region — e.g. sRender/
// sSound)? Mirrors the load() check at the revert loop. Out-of-arena => false (not in the arena revert set).
// Used by the CS-reset scar fix: never zero a CS the revert didn't touch (it's a live lock the engine holds).
bool is_rederive_excluded(uintptr_t addr) {
    if (!g_have_exclusions || !g_rederive_excluded) return false;
    if (addr < g_arena_base || addr >= g_arena_base + ARENA_SIZE) return false;
    size_t p = (addr - g_arena_base) / PAGE_SIZE;
    if (p >= MAX_PAGES) return false;
    return ((g_rederive_excluded[p / 8] >> (p % 8)) & 1) != 0;
}

uintptr_t base() { return g_arena_base; }
uintptr_t end()  { return g_arena_base + ARENA_SIZE; }

// Read-only diag: was the page containing addr orphan-zeroed (memset 0) by the last load?
// (globally-dirty, no ring slot <= target, no baseline entry). True => the page was zeroed rather than restored.
bool was_orphaned_last_load(uintptr_t addr) {
    if (addr < g_arena_base || addr >= g_arena_base + ARENA_SIZE) return false;
    size_t p = (addr - g_arena_base) / PAGE_SIZE;
    return (g_last_orphaned[p / 8] >> (p % 8)) & 1;
}

// PEEK-SAVED (read-only diag): read bytes from the SAVED snapshot for `frame` at arena address `addr`
// (single page only — len clamped to the page end). The partial-init discriminator: at a crash on a
// restored object, compare the snapshot bytes the load wrote vs the live bytes — snapshot already holding
// the bad value => the SAVE captured a mid-lifecycle transient (engine-legit partial-init class);
// snapshot holding a valid value => a post-restore writer corrupted it (different class entirely).
// Returns: 1 = ring slot[frame], 2 = baseline, 3 = supplemental baseline, 0 = not present.
int peek_saved(int frame, uintptr_t addr, void* out, size_t len) {
    if (!g_arena_base || addr < g_arena_base || addr >= g_arena_base + ARENA_SIZE) return 0;
    size_t p   = (addr - g_arena_base) / PAGE_SIZE;
    size_t off = addr & (PAGE_SIZE - 1);
    if (off + len > PAGE_SIZE) len = PAGE_SIZE - off;
    for (int i = 0; i < RING_SLOTS; i++) {
        const RingSlot& s = g_ring[i];
        if (!s.valid || s.frame != frame) continue;
        if (!((s.dirty_bits[p / 8] >> (p % 8)) & 1)) break;       // page not dirty that frame -> baseline
        uint32_t di = s.page_map[p];
        if (di == 0xFFFFFFFF) break;
        memcpy(out, s.page_data + (size_t)di * PAGE_SIZE + off, len);
        return 1;
    }
    if (g_baseline_map) {
        uint32_t bl = g_baseline_map[p];
        if (bl != 0xFFFFFFFF) {
            if (bl & 0x80000000) {
                size_t si = bl & 0x7FFFFFFF;
                if (g_supplemental && si < g_supplemental_count) {
                    memcpy(out, g_supplemental + si * PAGE_SIZE + off, len);
                    return 3;
                }
            } else if (g_baseline) {
                memcpy(out, g_baseline + (size_t)bl * PAGE_SIZE + off, len);
                return 2;
            }
        }
    }
    return 0;
}

// The source of this page in the last load: >=0 ring frame, -1 baseline, -2 orphan, -3 live/not-restored,
// -100 out-of-arena. Same value for two pages => same source frame (coherent).
int last_source_frame(uintptr_t addr) {
    if (!g_last_source || addr < g_arena_base || addr >= g_arena_base + ARENA_SIZE) return -100;
    return g_last_source[(addr - g_arena_base) / PAGE_SIZE];
}

// P1 CAPACITY DONATION (see arena.h). carve: same reservation logic as hk_VirtualAlloc case-1, CS-held,
// committed immediately (fresh pages are OS-zeroed — the donation block-format relies on that), g_committed marked
// (=> write-watched, snapshot-covered, FLIST-covered like any engine region).
bool carve_donation_region(size_t size, uintptr_t* out_base) {
    if (!g_ready || !out_base || !size) return false;
    size_t aligned_size = align_up(size, ALLOC_GRANULARITY);
    if (g_carve_cs_init) EnterCriticalSection(&g_carve_cs);
    size_t offset = alloc_from_free_list(aligned_size);
    if (offset == (size_t)-1) {
        offset = align_up(g_watermark, ALLOC_GRANULARITY);
        if (offset + aligned_size > ARENA_SIZE - HEAP_ZONE_SIZE) {
            if (g_carve_cs_init) LeaveCriticalSection(&g_carve_cs);
            rblog::write("DONATION FAILED: arena watermark full (0x%zX + 0x%zX) — arena-full condition", g_watermark, aligned_size);
            return false;
        }
        g_watermark = offset + aligned_size;
        if (g_watermark > g_watermark_peak) g_watermark_peak = g_watermark;
    }
    if (g_reservation_count < 4096) g_reservations[g_reservation_count++] = { offset, aligned_size };
    if (g_carve_cs_init) LeaveCriticalSection(&g_carve_cs);
    uintptr_t base = g_arena_base + offset;
    g_in_our_alloc = true;
    LPVOID committed = g_real_VirtualAlloc((LPVOID)base, aligned_size, MEM_COMMIT, PAGE_READWRITE);
    g_in_our_alloc = false;
    if (!committed) return false;
    size_t page_start = offset / PAGE_SIZE, page_count = aligned_size / PAGE_SIZE;
    for (size_t p = 0; p < page_count; p++)
        if (!is_committed(page_start + p)) { set_committed(page_start + p); g_committed_count++; }
    *out_base = base;
    return true;
}
void note_donated_region(uintptr_t ctrl, uintptr_t base, size_t size) {
    LONG i = InterlockedIncrement(&g_donated_n) - 1;
    if (i >= MAX_DONATIONS) { g_donated_n = MAX_DONATIONS;
        rblog::write("DONATION registry FULL (%d) — region 0x%llX UNREGISTERED: invariant-check/reader/cf lose multi-region awareness for it", MAX_DONATIONS, (unsigned long long)base);
        return; }
    g_donated[i].ctrl = ctrl; g_donated[i].base = base; g_donated[i].size = size;
}
bool in_owned_pool(uintptr_t ctrl, uintptr_t addr) {
    if (ctrl > 0x10000) {
        uintptr_t lo = *(uintptr_t*)(ctrl + 0x90), hi = *(uintptr_t*)(ctrl + 0x98);
        if (lo && addr >= lo && addr < hi) return true;
    }
    LONG n = g_donated_n; if (n > MAX_DONATIONS) n = MAX_DONATIONS;
    for (LONG i = 0; i < n; i++)
        if (g_donated[i].ctrl == ctrl && addr >= g_donated[i].base && addr < g_donated[i].base + g_donated[i].size) return true;
    return false;
}
int donated_region_count() { LONG n = g_donated_n; return n > MAX_DONATIONS ? MAX_DONATIONS : n; }
bool donated_region_get(int i, uintptr_t* ctrl, uintptr_t* base, size_t* size) {
    if (i < 0 || i >= donated_region_count()) return false;
    if (ctrl) *ctrl = g_donated[i].ctrl; if (base) *base = g_donated[i].base; if (size) *size = g_donated[i].size;
    return true;
}

// FORENSIC (see arena.h): compact page provenance for alloc_invariants breaks. Read-only; break-gated, never per-frame.
void page_history(uintptr_t addr, char* out, size_t out_len) {
    if (!out || !out_len) return;
    if (addr < g_arena_base || addr >= g_arena_base + ARENA_SIZE) { snprintf(out, out_len, "out-of-arena"); return; }
    size_t p = (addr - g_arena_base) / PAGE_SIZE;
    int frames[RING_SLOTS]; int nf = 0;
    for (int i = 0; i < RING_SLOTS; i++) {
        if (!g_ring[i].valid) continue;
        if ((g_ring[i].dirty_bits[p / 8] >> (p % 8)) & 1) frames[nf++] = g_ring[i].frame;
    }
    for (int i = 1; i < nf; i++) { int k = frames[i], j = i - 1;   // ascending (slots are round-robin ordered)
        while (j >= 0 && frames[j] > k) { frames[j + 1] = frames[j]; j--; } frames[j + 1] = k; }
    char fl[160]; size_t off = 0; fl[0] = 0;
    for (int i = 0; i < nf; i++) {
        if (nf > 10 && i == 5) { off += (size_t)snprintf(fl + off, sizeof(fl) - off, "..(%d)..", nf - 10); i = nf - 5; }
        off += (size_t)snprintf(fl + off, sizeof(fl) - off, "%s%d", i ? "," : "", frames[i]);
        if (off >= sizeof(fl) - 16) break;
    }
    bool bl = g_baseline_bits && ((g_baseline_bits[p / 8] >> (p % 8)) & 1);
    bool cf = g_have_cfull && g_coherent_full && ((g_coherent_full[p / 8] >> (p % 8)) & 1);
    bool rv = g_revert_bits && ((g_revert_bits[p / 8] >> (p % 8)) & 1);
    snprintf(out, out_len, "p=%zu slots{%s} bl=%d cf=%d rv=%d src=%d",
             p, nf ? fl : "-", bl ? 1 : 0, cf ? 1 : 0, rv ? 1 : 0,
             g_last_source ? g_last_source[p] : -100);
}

long long get_heap_zone_offset() { return g_heap_zone_offset; }
void set_heap_zone_offset(long long offset) { g_heap_zone_offset = offset; }
void set_heap_redirect(bool on) { g_heap_redirect_active = on; }
// NETPLAY-LEAN (mirror of resim's flag; set from the Numpad8 toggle): skips the per-rollback g_last_source
// forensics bookkeeping (1MB memset + per-page provenance writes — consumed only by crash-time forensics, which
// degrade to "stale provenance" under lean). Mechanisms untouched.
static volatile LONG g_lean = 0;
void set_lean(bool v) { g_lean = v ? 1 : 0; }

// STAGE B — route Default malloc (FUN_1404C9460) into the in-arena heap zone so its blocks get BYTE-REVERTED by
// arena::load (the REVERT half the CRT heap could never give). Default's free FUN_1404C9A00 reads _Memory=*(user-0x10)
// then free(_Memory), and size=*(user-8) for stats. We write user-0x10 = NULL (free(NULL)=no-op; rdspine::hk_dfree
// skips it anyway for zone addrs) and user-0x8 = size (stats stay correct). Returns the user ptr (block+0x10, 16-aligned),
// or NULL on zone overflow => caller falls back to CRT (g_stage_b_crt_fallback bumped = the long-run gate). The bump offset
// goes through handle_preserve (get/set_heap_zone_offset) so it reverts on rollback and the deterministic resim re-bumps the same addresses.
// NON-recycling bump: capacity is measured via the fallback counter + zone occupancy; horizon-gated recycling is the
// data-driven follow-on IF the counter fires.
void* heap_zone_alloc_default(size_t size) {
    size_t total = align_up(HEAP_HEADER_SIZE + size, 16);
    long long offset = InterlockedAdd64(&g_heap_zone_offset, (long long)total) - (long long)total;
    if ((size_t)offset + total > HEAP_ZONE_SIZE - HEAP_ZONE_GUARD) {
        InterlockedIncrement64(&g_stage_b_crt_fallback);
        return nullptr;   // overflow => signal the caller to use the real CRT allocator (unprotected, but logged)
    }
    uintptr_t block = g_heap_zone_base + (size_t)offset;
    *(void**)block        = nullptr;          // user-0x10 = _Memory => free(_Memory)=free(NULL)=no-op
    *(int64_t*)(block + 8) = (int64_t)size;   // user-0x8 = requested size => FUN_1404C9A00 stat math stays correct
    void* user = (void*)(block + HEAP_HEADER_SIZE);
    memset(user, 0, size);                    // FUN_1404C9460 zero-fills; match it
    return user;
}
long long stage_b_crt_fallback() { return g_stage_b_crt_fallback; }
bool in_heap_zone(uintptr_t addr) { return addr >= g_heap_zone_base && addr < g_heap_zone_base + HEAP_ZONE_SIZE; }

// WINDOWED RESTORE A/B: ON (default) reverts only pages written after the rollback target; OFF reverts the
// full cumulative dirty set (the old behavior). State-identical; ON is ~depth/window faster.
void set_windowed_restore(bool on) { g_windowed_restore = on; }
bool windowed_restore()            { return g_windowed_restore; }

// DEFERRED-FOLD public API. set_fold_defer flips the A/B (default OFF = synchronous, proven path).
// fold_drain must be called on the main thread before any freeze()/baseline-byte read while defer may be active; it
// spins (bounded, <2ms; holds no lock) until the bg worker has flushed every enqueued job. No re-enqueue happens
// during do_rollback (F1: the resim loop bypasses save()), so one drain at rollback entry covers both freeze cycles.
void set_fold_defer(bool on) { g_fold_defer = on ? 1 : 0; }
bool fold_defer()            { return g_fold_defer != 0; }
void fold_drain() {
    long long target = g_fold_submitted;                 // stable: only the main thread enqueues, and it is us
    unsigned long long spins = 0;
    while (g_fold_completed < target) {
        YieldProcessor();
        if ((++spins & 0x3FFFFFFFull) == 0)              // ~1e9 spins ≫ any real <2ms fold: surface a stall, keep waiting
            rblog::write("FOLD-DRAIN STALL: completed=%lld < submitted=%lld (bg fold worker not progressing?)",
                         (long long)g_fold_completed, target);
    }
    MemoryBarrier();
}
// Arm the per-load scheduler-chain RE walk (DIAG-CHILD + ANIM-BVC). Off by default — pure diagnostic.
void set_load_diag_walk(bool on)   { g_load_diag_walk = on ? 1 : 0; }
bool load_diag_walk()              { return g_load_diag_walk != 0; }
bool get_heap_redirect() { return g_heap_redirect_active; }

// Per-frame hook-fire counters (perf bisection): which of our hooks is hammered on a chug frame.
// 0=scene_tree 1=MtScalable-free 2=HeapAlloc 3=effect-consume 4=SE-guard 5=spare
static volatile LONG g_hookcount[6] = {0,0,0,0,0,0};
void hook_count_inc(int i) { if ((unsigned)i < 6) InterlockedIncrement(&g_hookcount[i]); }
long hook_count_get(int i) { return ((unsigned)i < 6) ? g_hookcount[i] : 0; }
void hook_count_reset() { for (int i = 0; i < 6; i++) g_hookcount[i] = 0; }

size_t get_watermark() { return g_watermark; }

bool save(int frame) {
    if (!g_ready || !g_has_baseline) return false;

    // PERF SPLIT: the PROF `arena` phase (6-8ms/frame) is two costs — GetWriteWatch scanning the whole 2GB
    // reserve, vs the per-page memcpy. They want OPPOSITE fixes (shrink the scan range vs parallelize the copy),
    // so time them apart and report the dirty count. Throttled (~every 64 saves), not per-frame.
    static LARGE_INTEGER s_qf = {};
    if (!s_qf.QuadPart) QueryPerformanceFrequency(&s_qf);
    static double s_gww_ms = 0, s_copy_ms = 0, s_fold_ms = 0; static long long s_pages = 0, s_copy_body_pages = 0; static int s_n = 0;
    LARGE_INTEGER _g0; QueryPerformanceCounter(&_g0);

    // SCAN CLAMP: GetWriteWatch cost is proportional to the REGION SIZE scanned, not the dirty count — scanning
    // the full 2GB reserve every frame was a flat ~2.5ms of pure waste. Every allocation is carved below g_watermark
    // (the reserve frontier, bumped in hk_VirtualAlloc before the game can write the page), so NO dirty page can lie
    // above it. Clamp the scan to [base, watermark) rounded up to a page. Correct by construction (a page above the
    // frontier is unreserved => unwritable), ~O(committed) instead of O(2GB).
    size_t scan_size = g_watermark ? ((g_watermark + PAGE_SIZE - 1) & ~((size_t)PAGE_SIZE - 1)) : ARENA_SIZE;
    if (scan_size > ARENA_SIZE) scan_size = ARENA_SIZE;

    // Get dirty pages since last reset (atomic get+reset)
    ULONG_PTR count = g_watch_capacity;
    DWORD granularity = 0;
    UINT result = GetWriteWatch(WRITE_WATCH_FLAG_RESET, (PVOID)g_arena_base, scan_size,
                                 g_watch_buf, &count, &granularity);
    if (result != 0) {
        rblog::write("arena: GetWriteWatch failed in save (err=%lu)", GetLastError());
        return false;
    }
    LARGE_INTEGER _g1; QueryPerformanceCounter(&_g1);
    s_gww_ms += (double)(_g1.QuadPart - _g0.QuadPart) * 1000.0 / (double)s_qf.QuadPart;
    static size_t s_scan_size = 0; s_scan_size = scan_size;

    // Get ring slot — fold evicted slot into baseline. FOLD-SPLIT brackets the fold cost.
    // DEFERRED-FOLD (g_fold_defer): when armed, do the dst-resolution on this thread (fold_assign, ~0.05ms) and
    // hand the immutable src buffer to the bg worker for the ~1.6ms memcpy — off the critical path. Default OFF =
    // the synchronous fold_into_baseline (byte-identical proven path).
    int slot = g_ring_head;
    RingSlot& rs = g_ring[slot];
    LARGE_INTEGER _f0; QueryPerformanceCounter(&_f0);
    if (rs.valid) {
        bool deferred = false;
        if (g_fold_defer && g_fold_thread) {
            if (g_submit_head - g_submit_tail >= FOLD_RING) fold_drain();   // ring full → drain (never inline-fold while bg active)
            int ri = g_submit_head & (FOLD_RING - 1);
            if (ensure_dstlist_cap(ri, rs.dirty_page_count)) {
                long long seq = _InterlockedIncrement64(&g_fold_submitted);
                FoldJob& job = g_submit[ri];
                job.dst_list      = g_dstlist_store[ri];
                job.src_page_data = rs.page_data;              // the immutable byte source (this slot's ~60-frame-old data)
                job.src_capacity  = rs.page_data_capacity;
                fold_assign(rs, job);                          // resolve every dst on MAIN (allocs supplemental on MAIN); job.seq below
                job.seq = seq;
                RetBuf sb = pop_return();                      // detach: give the slot a spare buffer (null → realloc allocs fresh)
                rs.page_data          = sb.ptr;
                rs.page_data_capacity = sb.cap;
                MemoryBarrier();
                g_submit_head++;                               // publish job after it is fully built and the slot is detached
                SetEvent(g_fold_wake);
                deferred = true;
            }
        }
        if (!deferred) fold_into_baseline(rs);                 // synchronous (flag off, or dst_list alloc failed → safe fallback)
    }
    LARGE_INTEGER _f1; QueryPerformanceCounter(&_f1);
    s_fold_ms += (double)(_f1.QuadPart - _f0.QuadPart) * 1000.0 / (double)s_qf.QuadPart;
    g_ring_head = (g_ring_head + 1) % RING_SLOTS;

    rs.frame = frame;
    rs.dirty_page_count = (int)count;
    rs.valid = false;
    memset(rs.dirty_bits, 0, MAX_PAGES / 8);
    // PERF: dropped the 1MB `memset(page_map,0xFF,...)`/frame. Every reader (fold, peek, load) gates
    // on dirty_bits first, then reads page_map; the copy loop sets page_map[idx] for exactly the pages it sets
    // dirty_bits[idx] for => a page_map entry is never read unless freshly written this frame. The 0xFFFFFFFF
    // sentinel checks in the readers remain as belt-and-suspenders. (Saves a 1MB memset every save().)

    // Reallocate page_data if needed
    if ((int)count > rs.page_data_capacity) {
        if (rs.page_data) {
            g_in_our_alloc = true;
            VirtualFree(rs.page_data, 0, MEM_RELEASE);
            g_in_our_alloc = false;
            rs.page_data = nullptr;
        }
        int alloc_pages = (int)count + (int)count / 4 + 64;
        g_in_our_alloc = true;
        rs.page_data = (uint8_t*)VirtualAlloc(nullptr, (size_t)alloc_pages * PAGE_SIZE,
                                               MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        g_in_our_alloc = false;
        if (!rs.page_data) {
            rblog::write("arena: save(%d) alloc failed (need %d pages)", frame, alloc_pages);
            rs.page_data_capacity = 0;
            return false;
        }
        rs.page_data_capacity = alloc_pages;
    }

    // Copy dirty pages
    const uintptr_t _csr = sr_base();   // REGION-SPLIT: resolve sRender body bounds once, then bucket per page below
    uint32_t nstored = 0;               // DENSE LIST: dense count of stored (in-range) pages this save
    LARGE_INTEGER _c0; QueryPerformanceCounter(&_c0);
    for (ULONG_PTR i = 0; i < count; i++) {
        uintptr_t page_addr = (uintptr_t)g_watch_buf[i];
        size_t page_idx = (page_addr - g_arena_base) / PAGE_SIZE;
        if (page_idx >= MAX_PAGES) continue;

        rs.dirty_bits[page_idx / 8] |= (1 << (page_idx % 8));
        g_dirty_bits[page_idx / 8]  |= (1 << (page_idx % 8));
        memcpy(rs.page_data + i * PAGE_SIZE, (void*)page_addr, PAGE_SIZE);
        rs.page_map[page_idx] = (uint32_t)i;
        rs.dirty_idx_list[nstored++] = (uint32_t)page_idx;     // dense list for the O(dirty) fold
        if (in_sr_body(page_addr, _csr)) s_copy_body_pages++;   // measurement: sRender-body share of the copy
    }
    rs.dirty_stored = (int)nstored;
    LARGE_INTEGER _c1; QueryPerformanceCounter(&_c1);
    s_copy_ms += (double)(_c1.QuadPart - _c0.QuadPart) * 1000.0 / (double)s_qf.QuadPart;
    s_pages += (long long)count;
    if (++s_n >= 64) {   // ~1s cadence: names scan-bound vs copy-bound vs fold-bound + the real dirty volume
        double avg_pages = (double)s_pages / s_n;
        double avg_cbody = (double)s_copy_body_pages / s_n;
        double avg_ftot  = (double)g_fold_total_pages / s_n;
        double avg_fbody = (double)g_fold_body_pages / s_n;
        rblog::write("ARENA-SAVE-SPLIT[avg/%d]: getwritewatch=%.2f copy=%.2f fold=%.2f ms | dirty=%.0f pages (%.1f MB/frame) | scan=%zuMB (was 2048)",
                     s_n, s_gww_ms / s_n, s_copy_ms / s_n, s_fold_ms / s_n, avg_pages, avg_pages * 4096.0 / (1024.0*1024.0), s_scan_size >> 20);
        // REGION-SPLIT (measurement-only): what share of the copy + fold IS the sRender body (the load-side F_REDERIVE region
        // we already never restore). High % => a save-side skip collapses both terms; low % => the fold-defer wins.
        rblog::write("REGION-SPLIT[avg/%d]: copy sRender-body=%.0f/%.0f pg (%.0f%%, %.1f MB/f) | fold sRender-body=%.0f/%.0f pg (%.0f%%) => skip-body would drop copy≈%.0f%% + fold≈%.0f%%",
                     s_n, avg_cbody, avg_pages, avg_pages > 0 ? 100.0 * avg_cbody / avg_pages : 0.0, avg_cbody * 4096.0 / (1024.0*1024.0),
                     avg_fbody, avg_ftot, avg_ftot > 0 ? 100.0 * avg_fbody / avg_ftot : 0.0,
                     avg_pages > 0 ? 100.0 * avg_cbody / avg_pages : 0.0, avg_ftot > 0 ? 100.0 * avg_fbody / avg_ftot : 0.0);
        s_gww_ms = 0; s_copy_ms = 0; s_fold_ms = 0; s_pages = 0; s_copy_body_pages = 0; s_n = 0;
        g_fold_total_pages = 0; g_fold_body_pages = 0;
    }

    rs.valid = true;

    // Periodically rebuild dirty bits
    static int s_rebuild_countdown = RING_SLOTS;
    if (--s_rebuild_countdown <= 0) {
        rebuild_dirty_bits();
        s_rebuild_countdown = RING_SLOTS;
    }

    // Log periodically
    static int s_save_count = 0;
    s_save_count++;
    if (s_save_count <= 3 || (s_save_count % 60) == 0) {
        rblog::write("arena: save(%d) slot %d — %d pages (%.1f MB)",
                    frame, slot, (int)count,
                    (double)count * PAGE_SIZE / (1024.0 * 1024.0));
    }
    if (s_save_count % 60 == 0) {
        rblog::write("ARENA-SUPP: supplemental %zu/%zu pages used (%.1f MB / %.1f MB)",
                    g_supplemental_count, (size_t)SUPPLEMENTAL_MAX,
                    (double)(g_supplemental_count * PAGE_SIZE) / (1024.0 * 1024.0),
                    (double)(SUPPLEMENTAL_MAX * PAGE_SIZE) / (1024.0 * 1024.0));
    }

    return true;
}

// ============================================================
// OWNED-HEAP object-granular revert — the DUAL-RUN SHADOW
// ============================================================
// Page-blind revert (in load() below) still DRIVES the real arena. In parallel, for each dirty page we compute
// what an OBJECT-GRANULAR revert would produce into a scratch buffer and compare it to page-blind's result byte
// for byte, logging every disagreement NAMED by object + every uncovered dirty byte. Zero writes to the arena —
// this proves the walk correct + complete before we ever flip (g_object_revert_active). 
static volatile bool g_reader_compare_active = false;   // default OFF — reader.cpp g_active is false (no runtime arm exists), so the per-dirty-page g_shadow_live memcpy fed a dead consumer (the headline rollback tax). Re-arm = flip this + reader.cpp g_active together (recompile).
static constexpr int SHADOW_GRACE = 32;                 // == quarantine GRACE; belt-skip a dead edge past horizon


// OWNED-HEAP master flag (see g_owned_heap def near the top). Default ON = all four properties on; dllmain composes the
// property setters from it, and the P1 capacity alarms gate on it. OFF (owned_heap_off.flag) = legacy A/B.
void set_owned_heap_active(bool on) { g_owned_heap = on; }
bool owned_heap_active()            { return g_owned_heap; }

static uint8_t g_shadow_live[PAGE_SIZE];       // pre-revert live page (captured before page-blind overwrites it)
static uint8_t g_obj_scratch[PAGE_SIZE];       // the object-walk result for one page
static uint8_t g_obj_covered[PAGE_SIZE / 8];   // 1 bit/byte: covered by some object
static uint8_t g_obj_vaporized[PAGE_SIZE / 8]; // 1 bit/byte: zeroed by a VAPORIZE (expected divergence)
static volatile LONG64 g_sh_pages=0, g_sh_diff=0, g_sh_vap=0, g_sh_gap=0, g_sh_gap_r1=0, g_sh_diff_logged=0;

// Independent frame-N page source (mirrors the page-blind walk in load(); REVERT uses this, so a SHADOW-DIFF proves
// the resolver rather than trivially matching page-blind's own output). Returns nullptr img for LIVE/ABSENT.
struct PageSrc { const uint8_t* img; int kind; };  // kind: 0 LIVE, 1 RING, 2 BASELINE, 3 ABSENT
static PageSrc shadow_resolve_src(size_t p, int N, const int* ordered_slots, int ordered_count, const uint8_t* eff_bits) {
    if (!((eff_bits[p / 8] >> (p % 8)) & 1)) return { nullptr, 0 };      // LIVE (not written after N)
    for (int si = ordered_count - 1; si >= 0; si--) {
        int s = ordered_slots[si];
        if (g_ring[s].frame > N) continue;
        if ((g_ring[s].dirty_bits[p / 8] >> (p % 8)) & 1) {
            uint32_t di = g_ring[s].page_map[p];
            if (di != 0xFFFFFFFF) return { g_ring[s].page_data + (size_t)di * PAGE_SIZE, 1 };   // RING
        }
    }
    if ((g_baseline_bits[p / 8] >> (p % 8)) & 1) {
        uint32_t bl = g_baseline_map[p];
        if (bl != 0xFFFFFFFF)
            return { (bl & 0x80000000) ? g_supplemental + (size_t)(bl & 0x7FFFFFFF) * PAGE_SIZE
                                       : g_baseline     + (size_t)bl * PAGE_SIZE, 2 };           // BASELINE
    }
    return { nullptr, 3 };   // ABSENT (page-blind memsets 0)
}


double last_restore_ms() { return g_last_restore_ms; }
double last_oracle_ms()  { return g_last_oracle_ms; }

void reader_report() { reader::report(); }   // thin wrapper for callers that only want the reader line

// Frame-N snapshot read for arbitrary in-arena addresses (reader.cpp). Resolves each spanned page via
// shadow_resolve_src (LIVE/RING/BASELINE/ABSENT) and copies the frame-N bytes — handles page-straddling reads.
bool snap_read_bytes(uintptr_t addr, size_t len, int N,
                     const int* ordered_slots, int ordered_count,
                     const uint8_t* eff_bits,
                     uint8_t* out, bool* absent_out) {
    if (absent_out) *absent_out = false;
    if (!g_arena_base || !out || !len) return false;
    if (addr < g_arena_base || addr + len > g_arena_base + ARENA_SIZE) return false;
    for (size_t done = 0; done < len; ) {
        uintptr_t cur = addr + done;
        size_t p   = (cur - g_arena_base) / PAGE_SIZE;
        size_t off = cur & (PAGE_SIZE - 1);
        size_t chunk = PAGE_SIZE - off; if (chunk > len - done) chunk = len - done;
        PageSrc src = shadow_resolve_src(p, N, ordered_slots, ordered_count, eff_bits);
        switch (src.kind) {
            case 0: memcpy(out + done, (const uint8_t*)(g_arena_base + p * PAGE_SIZE) + off, chunk); break;
            case 1: /* fall through */
            case 2: memcpy(out + done, src.img + off, chunk); break;
            case 3: memset(out + done, 0, chunk); if (absent_out) *absent_out = true; break;
        }
        done += chunk;
    }
    return true;
}

bool load(int frame) {
    if (!g_ready || !g_has_baseline) return false;

    // Find target ring slot
    int target_slot = -1;
    for (int i = 0; i < RING_SLOTS; i++) {
        if (g_ring[i].valid && g_ring[i].frame == frame) {
            target_slot = i;
            break;
        }
    }
    if (target_slot < 0) {
        rblog::write("arena: load(%d) — frame not in ring, restoring from baseline", frame);
    }

    // Build ordered list of valid slots sorted by frame
    int ordered_slots[RING_SLOTS];
    int ordered_count = 0;
    for (int i = 0; i < RING_SLOTS; i++) {
        if (g_ring[i].valid) ordered_slots[ordered_count++] = i;
    }
    for (int i = 0; i < ordered_count - 1; i++) {
        for (int j = i + 1; j < ordered_count; j++) {
            if (g_ring[ordered_slots[j]].frame < g_ring[ordered_slots[i]].frame) {
                int tmp = ordered_slots[i];
                ordered_slots[i] = ordered_slots[j];
                ordered_slots[j] = tmp;
            }
        }
    }

    // WINDOWED REVERT SET (perf): the pages to undo = those written after the target frame, i.e. the OR of the
    // per-slot dirty_bits for slots with frame > target. Every other page already holds its target value (its
    // last write was <= target, so the live arena == target there) and is skipped. This is provably
    // state-identical to reverting the cumulative g_dirty_bits, but touches ~depth/window of the pages.
    LARGE_INTEGER qf, q0, q1; QueryPerformanceFrequency(&qf); QueryPerformanceCounter(&q0);
    long long shadow_ticks = 0;   // restore_ms decomposition: oracle-walk share vs page-blind share
    uint8_t* eff_bits = g_dirty_bits;
    int window_slots = 0, pending_merged = 0;
    if (g_windowed_restore && g_revert_bits) {
        memset(g_revert_bits, 0, MAX_PAGES / 8);
        for (int si = 0; si < ordered_count; si++) {
            int s = ordered_slots[si];
            if (g_ring[s].frame <= frame) continue;   // <= target: those writes belong to the target state, keep
            window_slots++;
            for (size_t w = 0; w < MAX_PAGES / 8; w++) g_revert_bits[w] |= g_ring[s].dirty_bits[w];
        }
        // PENDING-WINDOW MERGE (closes the observed mgr6 srcF=-3 break): writes landed after the
        // last save() are in NO slot's dirty bits => invisible to the revert set => the page stays LIVE and
        // smuggles a post-target mutation (e.g. a free-list splice) into the restored state. Query the current
        // write-watch set NON-DESTRUCTIVELY (flags=0 — a RESET here would eat the bits the next save needs,
        // making those pages vanish from the ring = the stale-source class) and OR it into the revert set.
        // Threads are frozen (do_rollback) => stable snapshot. Merged pages flow through the normal source walk:
        // ring/baseline (fold-airtight => exact <=target bytes) or orphan-zero (fresh commit = correct rollback).
        if (g_watch_buf) {
            ULONG_PTR wcount = g_watch_capacity; DWORD wgran = 0;
            if (GetWriteWatch(0, (PVOID)g_arena_base, ARENA_SIZE, g_watch_buf, &wcount, &wgran) == 0) {
                for (ULONG_PTR i = 0; i < wcount; i++) {
                    size_t wp = ((uintptr_t)g_watch_buf[i] - g_arena_base) / PAGE_SIZE;
                    if (wp < MAX_PAGES && !((g_revert_bits[wp / 8] >> (wp % 8)) & 1)) {
                        g_revert_bits[wp / 8] |= (uint8_t)(1u << (wp % 8));
                        pending_merged++;
                    }
                }
            }
        }
        // SCOPED COHERENT RESTORE: for pages in a coherence-full range (a list's own pool), add every
        // historically-dirty page (cumulative g_dirty_bits), not just post-target ones. The source-walk below
        // then restores each to its target-frame value => the whole list group lands at one frame, even the
        // node pages windowed would have left live. This is the proven full-revert, scoped to the list's pages.
        if (g_have_cfull && g_coherent_full) {
            int cf_pages = 0;
            for (size_t w = 0; w < MAX_PAGES / 8; w++) {
                uint8_t add = g_coherent_full[w] & g_dirty_bits[w] & ~g_revert_bits[w];
                if (add) { g_revert_bits[w] |= add; for (int bb=0;bb<8;bb++) if (add&(1<<bb)) cf_pages++; }
            }
            if (cf_pages) { bool _w = rblog::is_suppressed(); rblog::suppress(false);   // force through the frozen-window suppression — per-rollback, not per-frame
                rblog::write("arena: coherent-full added %d list-group page(s) to the revert set (windowed elsewhere)", cf_pages);
                rblog::suppress(_w); }
        }
        eff_bits = g_revert_bits;
    }

    // READER modes: COMPARE (read-only 2nd shadow, flag OFF) vs DRIVE (the FLIP — object-granular revert writes
    // the arena, flag ON). page-blind still writes the frame-N baseline in both; DRIVE re-asserts the vaporize
    // (born-after-N live) bodies afterward. reader::begin() (captures the pre-revert live-alloc set) and the
    // per-page g_shadow_live capture must run in both modes.
    bool reader_compare = g_reader_compare_active;          // read-only compare (default OFF)
    bool reader_on      = reader_compare;
    bool need_shadow_live = reader_compare;

    // READER (v2): capture the LIVE (in_use@now) alloc set before the page-blind loop touches the arena.
    // Liveness comes from LIST MEMBERSHIP captured pre-revert, not a post-revert +0x38 header bit. Must
    // precede the revert loop below (else the "live" reads are already frame-N and the earlier dead-code hole returns).
    if (reader_on)
        reader::begin(frame);

    // For each page to revert, find best source
    int restored_baseline = 0, restored_ring = 0, orphaned = 0, rederive_skipped = 0, cfull_override = 0;
    memset(g_last_orphaned, 0, sizeof(g_last_orphaned));   // reset the orphan-zero map for this load
    if (g_last_source && !g_lean) memset(g_last_source, 0xFF, MAX_PAGES * sizeof(int32_t));   // -1 default [lean: skipped; forensics read stale provenance]

    edge_break::begin(frame);   // EDGE-BREAK reset per-rollback tallies before the revert loop
    for (size_t p = 0; p < MAX_PAGES; p++) {
        bool in_baseline = (g_baseline_bits[p / 8] >> (p % 8)) & 1;
        bool globally_dirty = (eff_bits[p / 8] >> (p % 8)) & 1;
        if (!globally_dirty) {   // not written after target => windowed restore LEAVES IT LIVE (== current frame)
            if (g_last_source && !g_lean) g_last_source[p] = -3;   // mark LIVE (was defaulting to -1=baseline => ambiguous)
            continue;
        }

        // RE-DERIVE EXCLUSION (restore-by-structure invariant): skip reverting pages in a registered RE-DERIVE
        // region. The page keeps its LIVE value and the resim re-derives it. This is the "remove pages"
        // option — render/audio/resource regions the schema classified as deterministic-function-of-gameplay.
        if (g_have_exclusions && ((g_rederive_excluded[p / 8] >> (p % 8)) & 1)) {
            // A+B (coherent-full WINS over rederive-exclude): a page that is both rederive-excluded and in a
            // coherent-full range is an allocator pool/list-group page that overlaps a kept-live region. Its list
            // COHERENCE beats the keep-live optimization — leaving it live tears the free-list (the control reverts
            // to frame N while this node stays at frame M). REVERT it. Any off-frame-written payload sharing the page
            // (audio/ogg) is re-overlaid after arena::load by its per-object preserve (audio_preserve/ogg_preserve),
            // so the node links land @N and the payload stays @M — both correct. (Safe only because those per-object
            // re-overlays run post-load; without them this would re-corrupt the payload.)
            bool coherent = g_have_cfull && g_coherent_full && ((g_coherent_full[p / 8] >> (p % 8)) & 1);
            if (!coherent) {
                rederive_skipped++;
                if (g_last_source && !g_lean) g_last_source[p] = -3;   // live/not-restored = the RE-DERIVE source
                continue;
            }
            cfull_override++;   // coherent-full allocator page overlapped a kept-live region => revert anyway (coherence wins)
        }

        if (globally_dirty) {
            // OWNED-HEAP shadow: capture the PRE-revert live page before page-blind overwrites it (so an uncovered
            // dirty byte visibly differs from page-blind's frame-N result => a coverage hole is detectable).
            // EDGE-BREAK reuses this same capture: the pre-revert bytes are exactly one half of the cross-boundary
            // edge diff, so the complete detector costs one already-needed memcpy plus a compare per qword.
            bool eb_live = edge_break::enabled();
            if (need_shadow_live || eb_live) memcpy(g_shadow_live, (void*)(g_arena_base + p * PAGE_SIZE), PAGE_SIZE);
            // Walk ring backwards — most recent slot at or before target frame
            bool found = false;
            for (int si = ordered_count - 1; si >= 0; si--) {
                int s = ordered_slots[si];
                if (g_ring[s].frame > frame) continue;
                if ((g_ring[s].dirty_bits[p / 8] >> (p % 8)) & 1) {
                    uint32_t data_idx = g_ring[s].page_map[p];
                    if (data_idx != 0xFFFFFFFF) {
                        memcpy((void*)(g_arena_base + p * PAGE_SIZE),
                               g_ring[s].page_data + (size_t)data_idx * PAGE_SIZE,
                               PAGE_SIZE);
                        restored_ring++;
                        if (g_last_source && !g_lean) g_last_source[p] = g_ring[s].frame;   // sourced from this ring frame
                        found = true;
                        break;
                    }
                }
            }
            if (!found && in_baseline) {
                uint32_t bl_map = g_baseline_map[p];
                if (bl_map != 0xFFFFFFFF) {
                    if (bl_map & 0x80000000) {
                        size_t sup_idx = bl_map & 0x7FFFFFFF;
                        memcpy((void*)(g_arena_base + p * PAGE_SIZE),
                               g_supplemental + sup_idx * PAGE_SIZE, PAGE_SIZE);
                    } else {
                        memcpy((void*)(g_arena_base + p * PAGE_SIZE),
                               g_baseline + (size_t)bl_map * PAGE_SIZE, PAGE_SIZE);
                    }
                    restored_baseline++;
                    if (g_last_source && !g_lean) g_last_source[p] = -1;   // sourced from baseline
                } else {
                    memset((void*)(g_arena_base + p * PAGE_SIZE), 0, PAGE_SIZE);
                    orphaned++; g_last_orphaned[p / 8] |= (uint8_t)(1u << (p % 8)); if (g_last_source && !g_lean) g_last_source[p] = -2;
                }
            } else if (!found) {
                memset((void*)(g_arena_base + p * PAGE_SIZE), 0, PAGE_SIZE);
                orphaned++; g_last_orphaned[p / 8] |= (uint8_t)(1u << (p % 8));
            }
            // OWNED-HEAP shadow: page-blind has now written the frame-N image; compute the object-granular result
            // into scratch and compare (reads only; never writes the arena). Names any resolver/coverage defect.
            // READER: COMPARE (read-only 2nd shadow). QPC bracket only when the oracle actually runs
            // (two unconditional QPC calls per dirty page were measurable for a no-op).
            if (reader_compare) {
                LARGE_INTEGER _sw0; QueryPerformanceCounter(&_sw0);
                reader::compare_page(p, frame, ordered_slots, ordered_count, eff_bits,
                                     g_shadow_live,
                                     (const uint8_t*)(g_arena_base + p * PAGE_SIZE),
                                     0);
                LARGE_INTEGER _sw1; QueryPerformanceCounter(&_sw1); shadow_ticks += _sw1.QuadPart - _sw0.QuadPart;
            }
            // EDGE-BREAK: the page-blind write is done, so g_shadow_live (live) and the arena page (restored) are
            // the two halves of the diff. Every reverted byte gets examined — this is the probe-independent census.
            if (eb_live)
                edge_break::page(g_arena_base + p * PAGE_SIZE, g_shadow_live,
                                 (const void*)(g_arena_base + p * PAGE_SIZE), PAGE_SIZE);
        }
    }

    QueryPerformanceCounter(&q1);
    double restore_ms = (double)(q1.QuadPart - q0.QuadPart) * 1000.0 / (double)qf.QuadPart;
    // Force the per-load diagnostic lines through the frozen-window suppression (per-rollback, not per-frame):
    // baseline/orphan counts are the tripwire for the ring-source fallback hole — they must be visible every long run.
    // (NOTE the tripwire's honest limit: it catches "no ring/baseline source found" fallbacks; a page whose dirty
    // bit was MISSED entirely takes the early LIVE path and shows nothing here — that save→freeze race stays an
    // OPEN hypothesis, fingerprint = an INVARIANT-CHECK POSTLOAD break with these counters clean.) All four lines
    // share one suppression wrap.
    { bool _w = rblog::is_suppressed(); rblog::suppress(false);
      g_last_restore_ms = restore_ms; g_last_oracle_ms = (double)shadow_ticks * 1000.0 / (double)qf.QuadPart;
      rblog::write("arena: load(%d) restore=%.1f ms (oracle-walks=%.1f ms of that) — %s (window_slots=%d, ring=%d baseline=%d orphan=%d pending=%d)",
                   frame, restore_ms, (double)shadow_ticks * 1000.0 / (double)qf.QuadPart, g_windowed_restore ? "WINDOWED" : "FULL",
                   window_slots, restored_ring, restored_baseline, orphaned, pending_merged);
      if (g_have_exclusions)
          rblog::write("arena: load(%d) RE-DERIVE skipped %d pages (kept live for resim)", frame, rederive_skipped);
      edge_break::report(frame);   // EDGE-BREAK what this revert did to every external edge
      if (cfull_override)
          rblog::write("arena: load(%d) A+B COHERENT-FULL OVERRIDE reverted %d allocator page(s) a kept-live region would have stranded (free-list-coherence fix; 0 = the override was never the cause => free-list break is a cf-coverage gap, extend the range)", frame, cfull_override);
      rblog::suppress(_w); }

    // DIAG-CHILD: walk scheduler child chains after restore, find corrupted vtables.
    // Read-only RE diagnostic — gated OFF by default (it walked 128 lines x 512 ents x 64 children every load,
    // a measured slice of the rollback freeze). Arm g_load_diag_walk for stale-vtable RE only.
    if (g_load_diag_walk) {
        uintptr_t base = (uintptr_t)GetModuleHandleA("umvc3.exe");
        uintptr_t sunit = *(uintptr_t*)(base + 0xE17698);
        if (sunit && sunit >= g_arena_base && sunit < g_arena_base + ARENA_SIZE) {
            for (int line = 0; line < 128; line++) {
                uintptr_t ent = *(uintptr_t*)(sunit + 0x58 + (uintptr_t)line * 0x30);
                int ewalk = 0;
                while (ent && ewalk < 512 && ent >= g_arena_base && ent < g_arena_base + ARENA_SIZE) {
                    uintptr_t child = *(uintptr_t*)(ent + 0x08);
                    int cwalk = 0;
                    while (child && cwalk < 64 && child >= g_arena_base && child < g_arena_base + ARENA_SIZE) {
                        uintptr_t cvt = *(uintptr_t*)child;
                        if (cvt == 0x100000000ULL || cvt < 0x10000) {   // 0x1_00000000 OR null-ish (the vt=0 stale signature)
                            size_t dp = (child - g_arena_base) / PAGE_SIZE;
                            size_t off = (child - g_arena_base) % PAGE_SIZE;
                            bool gd = (g_dirty_bits[dp / 8] >> (dp % 8)) & 1;
                            bool ib = g_baseline_bits ? ((g_baseline_bits[dp / 8] >> (dp % 8)) & 1) : false;

                            rblog::write("DIAG-CHILD: parent=0x%llX line=%d child=0x%llX page=%zu +0x%zX dirty=%d baseline=%d",
                                (unsigned long long)ent, line, (unsigned long long)child, dp, off, (int)gd, (int)ib);

                            for (int i = 0; i < RING_SLOTS; i++) {
                                if (!g_ring[i].valid) continue;
                                bool has = (g_ring[i].dirty_bits[dp / 8] >> (dp % 8)) & 1;
                                uint32_t didx = g_ring[i].page_map[dp];
                                if (has && didx != 0xFFFFFFFF) {
                                    uintptr_t ring_vt = *(uintptr_t*)(g_ring[i].page_data + (size_t)didx * PAGE_SIZE + off);
                                    rblog::write("DIAG-CHILD:   ring[%d] frame=%d vt=0x%llX %s",
                                        i, g_ring[i].frame, (unsigned long long)ring_vt,
                                        g_ring[i].frame <= frame ? "<= TARGET" : "> target");
                                }
                            }

                            uint32_t blm = g_baseline_map[dp];
                            if (blm != 0xFFFFFFFF) {
                                uint8_t* src = (blm & 0x80000000) ?
                                    g_supplemental + (size_t)(blm & 0x7FFFFFFF) * PAGE_SIZE :
                                    g_baseline + (size_t)blm * PAGE_SIZE;
                                uintptr_t bl_vt = *(uintptr_t*)(src + off);
                                rblog::write("DIAG-CHILD:   baseline vt=0x%llX (supp=%d)",
                                    (unsigned long long)bl_vt, (int)((blm & 0x80000000) != 0));
                            } else {
                                rblog::write("DIAG-CHILD:   baseline: NOT PRESENT");
                            }
                        }
                        child = *(uintptr_t*)(child + 0x58);
                        cwalk++;
                    }
                    ent = *(uintptr_t*)(ent + 0x20);
                    ewalk++;
                }
            }

            // ANIM-BVC: the LIVE crash (FUN_14051b4c0 run_a_group_of_top_anims, READ 0x28) walks the
            // sched-line ANIM node list at *(sunit + 0x50 + line*0x30) (node vtable at +0, next at +0x18).
            // For a stale node (null-ish vtable), compare the ring slot that sourced the NODE-content page
            // vs the REFERENCING-FIELD page: different => (b) cross-page/ring skew => COHERENT-REVERT cure;
            // Same => (c) partial-init (node was vt=0 at frame N) => REBUILD/PRESERVE cure. pure READ-ONLY.
            {
                auto src_frame = [&](uintptr_t a) -> int {
                    if (a < g_arena_base || a >= g_arena_base + ARENA_SIZE) return -3;
                    size_t pp = (a - g_arena_base) / PAGE_SIZE;
                    bool gd = (g_dirty_bits[pp / 8] >> (pp % 8)) & 1;
                    bool ib = g_baseline_bits ? ((g_baseline_bits[pp / 8] >> (pp % 8)) & 1) : false;
                    if (gd) {
                        for (int si = ordered_count - 1; si >= 0; si--) {
                            int s = ordered_slots[si];
                            if (g_ring[s].frame > frame) continue;
                            if (((g_ring[s].dirty_bits[pp / 8] >> (pp % 8)) & 1) && g_ring[s].page_map[pp] != 0xFFFFFFFF)
                                return g_ring[s].frame;          // sourced from this ring slot
                        }
                        if (ib && g_baseline_map[pp] != 0xFFFFFFFF) return -1;  // baseline
                        return -2;                               // orphan-zeroed
                    }
                    if (ib) return -1;
                    return -3;                                   // not restored (live page)
                };
                int anim_logged = 0;
                for (int line = 0; line < 128 && anim_logged < 16; line++) {
                    uintptr_t field = sunit + 0x50 + (uintptr_t)line * 0x30;   // referencing-field address
                    uintptr_t node = *(uintptr_t*)field;
                    int nwalk = 0;
                    while (node && nwalk < 64 && node >= g_arena_base && node < g_arena_base + ARENA_SIZE) {
                        uintptr_t vt = *(uintptr_t*)node;
                        if (vt < 0x10000) {                      // null-ish vtable = the FUN_14051b4c0 stale signature
                            int sf_n = src_frame(node), sf_f = src_frame(field);
                            rblog::write("ANIM-BVC: line=%d field=0x%llX(src=%d) node=0x%llX(src=%d) vt=0x%llX => %s",
                                line, (unsigned long long)field, sf_f, (unsigned long long)node, sf_n,
                                (unsigned long long)vt,
                                (sf_n != sf_f) ? "DIFFERENT-SLOT (b)SKEW -> coherent-revert"
                                               : "SAME-SLOT (c)partial-init -> rebuild/preserve");
                            anim_logged++;
                            break;
                        }
                        node = *(uintptr_t*)(node + 0x18);       // next node (plVar8[3])
                        nwalk++;
                    }
                }
            }
        }
    }

    // Rebuild dirty bits for target frame
    memset(g_dirty_bits, 0, MAX_PAGES / 8);
    for (int si = 0; si < ordered_count; si++) {
        int s = ordered_slots[si];
        if (g_ring[s].frame > frame) break;
        for (size_t i = 0; i < MAX_PAGES / 8; i++) {
            g_dirty_bits[i] |= g_ring[s].dirty_bits[i];
        }
    }

    // Reset write watch
    ResetWriteWatch((PVOID)g_arena_base, ARENA_SIZE);

    rblog::write("arena: loaded frame %d (slot %d): %d baseline, %d ring, %d orphaned",
                frame, target_slot, restored_baseline, restored_ring, orphaned);
    return true;
}

} // namespace arena
