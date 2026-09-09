#pragma once
// monitor_shm.h — Shared memory layout for UMvC3 Rollback Monitor.
// DLL writes this; monitor.exe reads it via OpenFileMapping.
// Must be kept in sync with monitor.cpp in monitor/.

#include <windows.h>
#include <cstdint>

// Named shared memory region accessible to monitor.exe
static constexpr const char* MONITOR_SHM_NAME = "UMvC3RollbackMonitor";

// Write-log entry — every DLL-side state modification gets an entry
struct WriteLogEntry {
    uint32_t sequence;      // monotonic, matches phase_sequence at time of write
    uint32_t frame;         // game frame number
    uint8_t  phase_id;      // which phase (see PhaseID enum)
    uint8_t  rule_id;       // for the unlink pass: which rule (0=NULL-SAFE, 1=GATE, 2=UNLINK, 3=RULE1,..., 7=RULE5)
    uint16_t offset;        // field offset within entity (e.g. 0x530, 0x11B0)
    uint64_t entity;        // entity address
    uint64_t old_val;       // value before write
    uint64_t new_val;       // value after write
};

// Phase IDs — every boundary in do_rollback + normal play
enum PhaseID : uint8_t {
    PHASE_NORMAL = 0,        // after orig() during normal play
    PHASE_PRE_RESTORE,       // before arena::load (snapshot current state)
    PHASE_ARENA_LOAD,        // after arena::load
    PHASE_DATA_RESTORE,      // after.data restore
    PHASE_HEAP_ZONE_RESTORE, // after heap zone offset restore
    PHASE_PRESERVE_RESTORE,       // after handle_preserve restore
    PHASE_ALLOC_RESTORE,     // after allocator restore
    PHASE_UNLINK_POST_LOAD,     // after dead_vtable_unlink POST_LOAD
    PHASE_CS_RESET,          // after CS lock state reset
    PHASE_TASK_CLEANUP,      // after sMain task state cleanup
    PHASE_THAW,              // after thread thaw
    PHASE_RESIM,             // after each resim orig() call
    PHASE_TOGGLE_RESTORE,    // after triple-buffer toggle restore
    PHASE_UNLINK_POST_RESIM,    // after dead_vtable_unlink POST_RESIM
    PHASE_ROLLBACK_COMPLETE, // rollback done, returning to normal play
    PHASE_PACER_FIX,         // frame pacer hook wrote delta_T
    PHASE_COUNT
};

static constexpr const char* PHASE_NAMES[] = {
    "NORMAL", "PRE-RESTORE", "ARENA-LOAD", "DATA-RESTORE", "HEAP-ZONE",
    "PRESERVE-RESTORE", "ALLOC-RESTORE", "UNLINK-POST-LOAD", "CS-RESET",
    "TASK-CLEANUP", "THAW", "RESIM", "TOGGLE-RESTORE", "UNLINK-POST-RESIM",
    "ROLLBACK-COMPLETE", "PACER-FIX"
};

// Unlink-pass rule IDs for write-log attribution (historical set; only UR_UNLINK is emitted today)
enum UnlinkRuleID : uint8_t {
    UR_NULL_SAFE = 0,
    UR_GATE = 1,
    UR_UNLINK = 2,
    UR_RULE1_BONE_ARR = 3,   // bone array NULL → zero count
    UR_RULE2_BONE_IDX = 4,   // bone index NULL → zero count
    UR_RULE3_IK_FLAGS = 5,   // IK table/model NULL → clear blend flags
    UR_RULE4_BIT29 = 6,      // bone output NULL → clear bit 29
    UR_RULE5_BONE_COUNT = 7, // bone output NULL → zero bone count (gated)
};

// Write-log ring buffer — DLL writes, monitor reads
static constexpr int WRITELOG_SIZE = 4096;  // entries, not bytes

struct MonitorData {
    // === Existing fields (must not move — monitor.exe reads by offset) ===
    uint64_t arena_base;
    uint64_t arena_size;
    uint32_t frame_counter;
    uint32_t ring_head;
    uint32_t rollback_active;       // 1 during do_rollback
    uint32_t last_rollback_target;
    uint32_t last_rollback_depth;
    uint32_t entities_scanned;      // from the dead-vtable unlink post-load scan
    uint32_t entities_nulled;       // entities unlinked by that pass
    uint32_t entities_unknown;      // unrecognized vtables
    uint32_t anim_fixed;            // anim pointers fixed (historical; always 0)
    uint32_t force_dirty_count;     // scheduler entities force-dirtied
    uint32_t child08_count;         // +0x08 chain children force-dirtied
    uint32_t child218_count;        // +0x218 chain children force-dirtied
    uint32_t se_table_count;        // SE-curve tables force-dirtied (audio coherence group)
    uint32_t alloc_count;           // allocators in registry
    char     last_crash[256];       // last VEH crash info (null-terminated)

    // === Phase tracking (new) ===
    volatile uint32_t phase_sequence;  // monotonic counter, bumped at every boundary
    volatile uint8_t  current_phase;   // PhaseID of current phase
    uint8_t  pad1[3];
    uint32_t current_frame;            // frame number for current phase

    // === Write-log ring buffer (new) ===
    volatile uint32_t writelog_head;    // next write position (DLL increments)
    volatile uint32_t writelog_tail;    // last read position (monitor increments)
    WriteLogEntry     writelog[WRITELOG_SIZE];
};

namespace monitor_shm {

// Call from DllMain (DLL_PROCESS_ATTACH). Creates the shared memory region.
void init();

// Global pointer — null until init() succeeds. Write to this from anywhere.
extern MonitorData* g_mon;

// Signal a phase transition — bumps sequence, sets phase + frame
void set_phase(PhaseID phase, uint32_t frame);

// Log a write to the ring buffer
void log_write(uint32_t frame, PhaseID phase, uint8_t rule_id,
               uint64_t entity, uint16_t offset,
               uint64_t old_val, uint64_t new_val);

} // namespace monitor_shm
