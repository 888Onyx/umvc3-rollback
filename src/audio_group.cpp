#include "audio_group.h"
#include "arena.h"
#include "addr.h"
#include "log.h"
#include <windows.h>

namespace audio_group {

static const int        MAX_TABLES = 256;
static const uintptr_t  SE_VTABLE_IDA = 0x140BB4690;   // T0 SE-curve-table vtable (FUN_140688a50; stride 0x90, index +0xd8)
static const uintptr_t  SE_VTABLE_T1_IDA = 0x140BB4760; // T1 SE-table vtable (FUN_1406898e0; stride 0x98, index +0xf0/+0xf8)
static const uint32_t   COUNT_SANITY  = 0x40000;       // 256K rows is already absurd; above => garbage (reused slab)
static uintptr_t        g_se_vtable = 0;               // resolved runtime T0 vtable
static uintptr_t        g_se_vtable_t1 = 0;            // resolved runtime T1 vtable
static volatile uintptr_t g_tables[MAX_TABLES];   // 0 == empty slot (T0)
static volatile LONG  g_count = 0;                // high-water append index, T0 (lock-free publish)
static volatile uintptr_t g_tables_t1[MAX_TABLES];// 0 == empty slot (T1)
static volatile LONG  g_count_t1 = 0;             // high-water append index, T1
static bool           g_armed = false;
static volatile LONG  g_diag_logged = 0;          // bounded one-shot DIAG (blob-size visibility, worst case mitigation)
static volatile LONG  g_pruned_reuse = 0;         // entries dropped because the slab was freed/reused (vtable mismatch)

// Is `t` still a live SE-table (not a freed+reused slab)? Re-checked every save — a registered pointer can
// become a different object after free (the slab-reuse fault). vtable identity is the discriminator.
static bool is_live_se_table(uintptr_t t) {
    if (!t || !arena::is_committed_addr(t)) return false;
    if (g_se_vtable && *(uintptr_t*)t != g_se_vtable) return false;   // freed+reused slab — not our table
    if (*(uintptr_t*)(t + 0x70) == 0) return false;                  // unloaded (FUN_140688820 zeroes +0x70)
    if (*(uint32_t*)(t + 0x78) > COUNT_SANITY) return false;         // garbage count => not a real table
    return true;
}

// T1 (FUN_1406898e0) liveness. Same blob-root/count gates, but its OWN vtable (0x140BB4760). T1 unloader
// FUN_1406895c0 zeroes +0x70 (and +0x80/+0x78), so +0x70==0 == unloaded.
static bool is_live_se_table_t1(uintptr_t t) {
    if (!t || !arena::is_committed_addr(t)) return false;
    if (g_se_vtable_t1 && *(uintptr_t*)t != g_se_vtable_t1) return false; // freed+reused slab — not a T1 table
    if (*(uintptr_t*)(t + 0x70) == 0) return false;                  // unloaded (FUN_1406895c0 zeroes +0x70)
    if (*(uint32_t*)(t + 0x78) > COUNT_SANITY) return false;         // garbage count => not a real table
    return true;
}

void init() {
    for (int i = 0; i < MAX_TABLES; i++) { g_tables[i] = 0; g_tables_t1[i] = 0; }
    g_count = 0;
    g_count_t1 = 0;
    g_se_vtable    = addr::resolve(SE_VTABLE_IDA);
    g_se_vtable_t1 = addr::resolve(SE_VTABLE_T1_IDA);
    g_armed = true;
    rblog::write("AUDIO-GROUP: SE-table coherence registry armed (cap %d, T0 vtable=0x%llX, T1 vtable=0x%llX) — registers on the read-only SE resolver hooks",
                 MAX_TABLES, (unsigned long long)g_se_vtable, (unsigned long long)g_se_vtable_t1);
}

uint32_t live_count() {
    LONG n = g_count; if (n > MAX_TABLES) n = MAX_TABLES;
    uint32_t live = 0;
    for (int i = 0; i < n; i++) if (g_tables[i]) live++;
    LONG n1 = g_count_t1; if (n1 > MAX_TABLES) n1 = MAX_TABLES;
    for (int i = 0; i < n1; i++) if (g_tables_t1[i]) live++;
    return live;
}

// Lock-free publish. May be called from any thread (the SE resolver runs on whatever thread touches audio).
// is_arena_addr is lock-free + thread-safe. De-dup is best-effort (a benign duplicate just force-dirties twice).
void register_table(uintptr_t table) {
    if (!g_armed || table < 0x10000 || !arena::is_arena_addr(table)) return;
    if (g_se_vtable && *(uintptr_t*)table != g_se_vtable) return;    // not an SE-table (the resolver also sees other args)
    LONG n = g_count; if (n > MAX_TABLES) n = MAX_TABLES;
    for (int i = 0; i < n; i++) if (g_tables[i] == table) return;   // already registered
    LONG slot = InterlockedIncrement(&g_count) - 1;
    if (slot < MAX_TABLES) {
        g_tables[slot] = table;                                     // single writer per slot
    } else {
        InterlockedDecrement(&g_count);                             // full — drop (registry overflow logged by live_count)
    }
}

// T1 sibling birth-registry. Called from the (read-only) T1 resolver hook hk_se_table_t1 with the table arg.
void register_table_t1(uintptr_t table) {
    if (!g_armed || table < 0x10000 || !arena::is_arena_addr(table)) return;
    if (g_se_vtable_t1 && *(uintptr_t*)table != g_se_vtable_t1) return; // not a T1 table (resolver also sees other args)
    LONG n = g_count_t1; if (n > MAX_TABLES) n = MAX_TABLES;
    for (int i = 0; i < n; i++) if (g_tables_t1[i] == table) return;    // already registered
    LONG slot = InterlockedIncrement(&g_count_t1) - 1;
    if (slot < MAX_TABLES) {
        g_tables_t1[slot] = table;
    } else {
        InterlockedDecrement(&g_count_t1);
    }
}

// Force-dirty one SE-table's coherence group. All three ranges land in the same save frame.
// Returns true if the table was live (blob root present) and touched.
static bool force_dirty_se_table(uintptr_t t) {
    if (!t || !arena::is_committed_addr(t)) return false;

    // (1) table header [t, t+0xE8): +0x54 ready, +0x70 blob root, +0x78 count, +0x80 row base (crash-A),
    // +0x88..+0xb4 derived sub-array ptrs/counts, +0xd8 index map ptr, +0xe0 index count.
    arena::force_dirty_range(t, 0xE8, 0xE8);

    // (2) blob body at *(t+0x70). No stored size; bound by header(0x48) + rows(count*0x90) + slack for the
    // sub-arrays the relocator threads after the rows. Committed-walk stops at the first uncommitted page,
    // so over-cap only truncates, never over-reads. DIAG-log the first few so the cap can be tuned.
    uintptr_t blob = *(uintptr_t*)(t + 0x70);
    if (blob && arena::is_committed_addr(blob)) {
        uint32_t count = *(uint32_t*)(t + 0x78);
        if (count > COUNT_SANITY) count = 0;                       // defense-in-depth: never trust a garbage count
        size_t   sz    = 0x48 + (size_t)count * 0x90 + 0x20000;   // rows + 128KB slack for sub-arrays
        if (sz > 0x100000) sz = 0x100000;                          // 1MB sanity cap
        arena::force_dirty_range(blob, sz, 0x100000);
        if (g_diag_logged < 8) {
            InterlockedIncrement(&g_diag_logged);
            rblog::write("AUDIO-GROUP DIAG: table=0x%llX blob=0x%llX count=%u derived_sz=0x%llX (cap 0x100000)",
                         (unsigned long long)t, (unsigned long long)blob, count, (unsigned long long)sz);
        }
    }

    // (3) sparse index map at *(t+0xd8), sized by *(uint16_t*)(t+0xe0)*2 + 16.
    uintptr_t idx = *(uintptr_t*)(t + 0xd8);
    if (idx && arena::is_committed_addr(idx)) {
        uint16_t n = *(uint16_t*)(t + 0xe0);
        arena::force_dirty_range(idx, (size_t)n * 2 + 16, 0x10000);
    }
    return true;
}

// Force-dirty one T1 SE-table's coherence group (FUN_1406898e0 / vtable 0x140BB4760).
// T1 layout DIFFERS from T0: header 0x100 (not 0xE8), row stride 0x98 (not 0x90), sparse index at
// +0xf0/+0xf8 (not +0xd8/+0xe0), and an extra named-entry array at +0xb0 (stride 0x40, count +0xb8).
// All bases are blob-relative, so the blob at +0x70 is the master anchor. The index map at +0xf0 and rows at
// +0x80 are MUTUALLY DERIVED by FUN_140689410 — tearing one against the other yields an out-of-bounds row deref
// in FUN_1406898e0's indexed path. Dirtying the whole group in one save frame keeps them coherent.
static bool force_dirty_se_table_t1(uintptr_t t) {
    if (!t || !arena::is_committed_addr(t)) return false;

    // (1) table header [t, t+0x100): +0x70 blob root, +0x78 count, +0x80 rows@0x98, +0xb0 named-entry
    // array, +0xb8 count, +0xc0/+0xc8/+0xd0/+0xd8 sub-banks, +0xf0 index map, +0xf8 index count.
    arena::force_dirty_range(t, 0x100, 0x100);

    // (2) serialized blob body at *(t+0x70) ('STSR' magic, ver 4). No stored total length; bound by
    // header(0x48) + rows(count*0x98) + slack for the sub-arrays the relocator threads after rows.
    // Committed-walk truncates at the first uncommitted page => over-cap never over-reads.
    uintptr_t blob = *(uintptr_t*)(t + 0x70);
    if (blob && arena::is_committed_addr(blob)) {
        uint32_t count = *(uint32_t*)(t + 0x78);
        if (count > COUNT_SANITY) count = 0;                       // defense-in-depth: never trust a garbage count
        size_t   sz    = 0x48 + (size_t)count * 0x98 + 0x20000;   // T1 stride 0x98 + 128KB slack for sub-arrays
        if (sz > 0x100000) sz = 0x100000;                          // 1MB sanity cap
        arena::force_dirty_range(blob, sz, 0x100000);
        if (g_diag_logged < 8) {
            InterlockedIncrement(&g_diag_logged);
            rblog::write("AUDIO-GROUP DIAG[t1]: table=0x%llX blob=0x%llX count=%u derived_sz=0x%llX (cap 0x100000)",
                         (unsigned long long)t, (unsigned long long)blob, count, (unsigned long long)sz);
        }
    }

    // (3) sparse index map at *(t+0xf0), sized by *(uint16_t*)(t+0xf8)*2 + 16 (T1: +0xf0/+0xf8, not +0xd8/+0xe0).
    uintptr_t idx = *(uintptr_t*)(t + 0xf0);
    if (idx && arena::is_committed_addr(idx)) {
        uint16_t n = *(uint16_t*)(t + 0xf8);
        arena::force_dirty_range(idx, (size_t)n * 2 + 16, 0x10000);
    }

    // (4) named-entry array at *(t+0xb0): allocated count*0x40+8 with a count header at [base-8]; rows
    // carry a backref row+0x90 = base + idx*0x40. Stride 0x40, count +0xb8.
    uintptr_t ent = *(uintptr_t*)(t + 0xb0);
    if (ent && arena::is_committed_addr(ent - 8)) {
        uint32_t ec = *(uint32_t*)(t + 0xb8);
        if (ec > COUNT_SANITY) ec = 0;
        arena::force_dirty_range(ent - 8, (size_t)ec * 0x40 + 8, 0x40000);
    }
    return true;
}

uint32_t force_dirty_all() {
    uint32_t touched = 0;
    LONG n = g_count; if (n > MAX_TABLES) n = MAX_TABLES;
    for (int i = 0; i < n; i++) {
        uintptr_t t = g_tables[i];
        if (!t) continue;
        if (!is_live_se_table(t)) {                                // freed / unloaded / reused-slab — prune, do not force-dirty
            g_tables[i] = 0;
            InterlockedIncrement(&g_pruned_reuse);
            continue;
        }
        if (force_dirty_se_table(t)) touched++;
    }
    // T1 sibling registry — same pass, T1 layout (stride 0x98, index +0xf0, named-entry +0xb0).
    LONG n1 = g_count_t1; if (n1 > MAX_TABLES) n1 = MAX_TABLES;
    for (int i = 0; i < n1; i++) {
        uintptr_t t = g_tables_t1[i];
        if (!t) continue;
        if (!is_live_se_table_t1(t)) {
            g_tables_t1[i] = 0;
            InterlockedIncrement(&g_pruned_reuse);
            continue;
        }
        if (force_dirty_se_table_t1(t)) touched++;
    }
    return touched;
}

} // namespace audio_group
