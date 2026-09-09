// monitor.cpp — UMvC3 Rollback External State Monitor
// Reads game memory via ReadProcessMemory. No injection. No hooks. No perf impact.
// Polls every 100ms. TUI via Windows console API.
//
// Build: see build.sh

#include <windows.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <cmath>
#include <algorithm>

// ============================================================
// Shared memory layout — must match dllmain.cpp exactly
// ============================================================

// Write-log entry — every DLL-side state modification gets an entry
struct WriteLogEntry {
    uint32_t sequence;
    uint32_t frame;
    uint8_t  phase_id;
    uint8_t  rule_id;
    uint16_t offset;
    uint64_t entity;
    uint64_t old_val;
    uint64_t new_val;
};

enum PhaseID : uint8_t {
    PHASE_NORMAL = 0, PHASE_PRE_RESTORE, PHASE_ARENA_LOAD, PHASE_DATA_RESTORE,
    PHASE_HEAP_ZONE_RESTORE, PHASE_PRESERVE_RESTORE, PHASE_ALLOC_RESTORE,
    PHASE_UNLINK_POST_LOAD, PHASE_CS_RESET, PHASE_TASK_CLEANUP, PHASE_THAW,
    PHASE_RESIM, PHASE_TOGGLE_RESTORE, PHASE_UNLINK_POST_RESIM,
    PHASE_ROLLBACK_COMPLETE, PHASE_PACER_FIX, PHASE_COUNT
};

static const char* PHASE_NAMES[] = {
    "NORMAL", "PRE-RESTORE", "ARENA-LOAD", "DATA-RESTORE", "HEAP-ZONE",
    "PRESERVE-RESTORE", "ALLOC-RESTORE", "UNLINK-POST-LOAD", "CS-RESET",
    "TASK-CLEANUP", "THAW", "RESIM", "TOGGLE-RESTORE", "UNLINK-POST-RESIM",
    "ROLLBACK-COMPLETE", "PACER-FIX"
};

enum UnlinkRuleID : uint8_t {
    UR_NULL_SAFE = 0, UR_GATE = 1, UR_UNLINK = 2,
    UR_RULE1_BONE_ARR = 3, UR_RULE2_BONE_IDX = 4, UR_RULE3_IK_FLAGS = 5,
    UR_RULE4_BIT29 = 6, UR_RULE5_BONE_COUNT = 7,
};

static const char* UNLINK_RULE_NAMES[] = {
    "NULL-SAFE", "GATE", "UNLINK", "RULE1-BONE-ARR", "RULE2-BONE-IDX",
    "RULE3-IK-FLAGS", "RULE4-BIT29", "RULE5-BONE-COUNT"
};

static constexpr int WRITELOG_SIZE = 4096;

struct MonitorData {
    // === Existing fields ===
    uint64_t arena_base;
    uint64_t arena_size;
    uint32_t frame_counter;
    uint32_t ring_head;
    uint32_t rollback_active;
    uint32_t last_rollback_target;
    uint32_t last_rollback_depth;
    uint32_t entities_scanned;
    uint32_t entities_nulled;
    uint32_t entities_unknown;
    uint32_t anim_fixed;
    uint32_t force_dirty_count;
    uint32_t child08_count;
    uint32_t child218_count;
    uint32_t alloc_count;
    char     last_crash[256];

    // === Phase tracking ===
    volatile uint32_t phase_sequence;
    volatile uint8_t  current_phase;
    uint8_t  pad1[3];
    uint32_t current_frame;

    // === Write-log ring buffer ===
    volatile uint32_t writelog_head;
    volatile uint32_t writelog_tail;
    WriteLogEntry     writelog[WRITELOG_SIZE];
};

// ============================================================
// Game module base (no ASLR on umvc3.exe)
// ============================================================
static constexpr uint64_t GAME_BASE = 0x140000000ULL;
static constexpr uint64_t GAME_SIZE = 0xE00000ULL;   // ~14MB .text + sections

// IDA-relative offsets
static constexpr uint64_t OFF_SUNIT_PTR      = 0xE17698;
static constexpr uint64_t OFF_SMAIN_PTR      = 0xE177E8;
static constexpr uint64_t OFF_SRENDER_PTR    = 0xE179A8;
static constexpr uint64_t OFF_ALLOC_COUNT    = 0xD760E0;
static constexpr uint64_t OFF_ALLOC_ARRAY    = 0xD760F0;
static constexpr uint64_t OFF_RNG_STATE      = 0xD765D8;
static constexpr uint64_t OFF_FRAME1         = 0xE1B708;
static constexpr uint64_t OFF_FRAME2         = 0xE1C008;
static constexpr uint64_t OFF_TIMER          = 0xD2B430;
static constexpr uint64_t OFF_THREADING      = 0xE178F0;

static constexpr int SCHED_LINES   = 128;
static constexpr int MAX_ENTITIES  = 1024;
static constexpr int MAX_ALLOCS    = 64;
static constexpr int MAX_BAD       = 32;

// ============================================================
// Data structures for polled state
// ============================================================

struct EntityInfo {
    uint64_t addr;
    uint64_t vtable;
    uint32_t flags;
    int      line;
    bool     bad_vtable;
};

struct ChildInfo {
    uint64_t addr;
    uint64_t vtable;
    uint64_t parent_addr;
    uint64_t parent_vtable;
    int      parent_line;
    int      chain;    // 0 = +0x08, 1 = +0x218
    bool     bad_vtable;
};

struct AllocInfo {
    uint64_t addr;
    char     name[64];
    uint32_t total_alloc;
    uint32_t total_free;
    uint32_t live;
    bool     valid;
};

struct LineInfo {
    int      count;
    uint64_t head;
    uint64_t tail;
    int      state_counts[8];   // state bits 0-2
    bool     has_bad;
};

struct PollState {
    bool     game_found;
    bool     shm_found;

    // .data globals
    uint32_t rng[4];
    uint32_t frame1;
    uint32_t frame2;
    float    timer_secs;
    uint8_t  threading;

    // Scheduler
    LineInfo  lines[SCHED_LINES];
    int       total_entities;
    int       total_unknown;
    int       total_bad_vtable;

    // Entities flat list (only non-empty lines)
    EntityInfo entities[MAX_ENTITIES];
    int        entity_count;

    // Children
    ChildInfo bad_children[MAX_BAD];
    int       bad_child_count;
    int       child08_total;
    int       child218_total;

    // Allocators
    AllocInfo allocs[MAX_ALLOCS];
    int       alloc_count;

    // DLL shared memory
    MonitorData shm;
    bool        shm_ok;

    // Ring slots (from shared memory + DLL info)
    // We show ring_head and frame_counter from shm
};

// ============================================================
// File logging — verbose, timestamped, dated
// ============================================================

static FILE* g_log = nullptr;
static FILE* g_writelog_file = nullptr;  // dedicated write-log output
static uint32_t g_last_logged_frame = 0xFFFFFFFF;
static PollState g_prev_state = {};
static bool g_prev_valid = false;
static uint32_t g_last_phase_seq = 0;
static uint32_t g_local_tail = 0;  // our read position in the write-log ring
static int g_log_tick = 0;

static void log_init() {
    // Create logs directory next to monitor.exe (absolute path)
    char exe_path[MAX_PATH];
    GetModuleFileNameA(NULL, exe_path, MAX_PATH);
    char* last_slash = strrchr(exe_path, '\\');
    if (last_slash) *(last_slash + 1) = '\0';

    char log_dir[MAX_PATH];
    snprintf(log_dir, sizeof(log_dir), "%slogs", exe_path);
    CreateDirectoryA(log_dir, NULL);

    // Dated log file
    SYSTEMTIME st;
    GetLocalTime(&st);
    char path[MAX_PATH];
    snprintf(path, sizeof(path), "%slogs\\monitor_%04d-%02d-%02d_%02d%02d%02d.log",
             exe_path, st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    g_log = fopen(path, "w");
    if (g_log) {
        fprintf(g_log, "=== UMvC3 Rollback Monitor Log ===\n");
        fprintf(g_log, "=== Started %04d-%02d-%02d %02d:%02d:%02d ===\n\n",
                st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
        fflush(g_log);
    }

    // Write-log output file — every DLL-side write with full attribution
    char wl_path[MAX_PATH];
    snprintf(wl_path, sizeof(wl_path), "%slogs\\writelog_%04d-%02d-%02d_%02d%02d%02d.log",
             exe_path, st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    g_writelog_file = fopen(wl_path, "w");
    if (g_writelog_file) {
        fprintf(g_writelog_file, "=== UMvC3 Write-Log — Every DLL-Side State Modification ===\n");
        fprintf(g_writelog_file, "=== Started %04d-%02d-%02d %02d:%02d:%02d ===\n",
                st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
        fprintf(g_writelog_file, "=== Format: [seq] frame=N PHASE RULE entity+offset: old -> new ===\n\n");
        fflush(g_writelog_file);
    }
}

static void log_timestamp() {
    if (!g_log) return;
    SYSTEMTIME st;
    GetLocalTime(&st);
    fprintf(g_log, "[%02d:%02d:%02d.%03d] ", st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
}

static void log_full_state(const PollState& s) {
    if (!g_log) return;

    log_timestamp();
    fprintf(g_log, "FRAME %u (frame2=%u)\n", s.frame1, s.frame2);

    // .data globals
    fprintf(g_log, "  RNG: %08X %08X %08X %08X\n", s.rng[0], s.rng[1], s.rng[2], s.rng[3]);
    fprintf(g_log, "  Timer: %.3fs  Threading: %s\n", s.timer_secs, s.threading ? "ON" : "OFF");

    // Scheduler summary
    fprintf(g_log, "  SCHEDULER: %d entities, %d bad vtables\n", s.total_entities, s.total_bad_vtable);
    for (int line = 0; line < SCHED_LINES; line++) {
        if (s.lines[line].count == 0) continue;
        fprintf(g_log, "    line %3d: %3d ents (states:", line, s.lines[line].count);
        for (int st = 0; st < 8; st++) {
            if (s.lines[line].state_counts[st] > 0)
                fprintf(g_log, " %d×s%d", s.lines[line].state_counts[st], st);
        }
        fprintf(g_log, ")%s\n", s.lines[line].has_bad ? " *** BAD VTABLE ***" : "");
    }

    // Every entity
    fprintf(g_log, "  ENTITIES (%d):\n", s.entity_count);
    for (int i = 0; i < s.entity_count; i++) {
        const EntityInfo& e = s.entities[i];
        fprintf(g_log, "    [%3d] line=%3d ent=0x%llX vt=0x%llX flags=0x%08X state=%d%s\n",
                i, e.line, (unsigned long long)e.addr,
                (unsigned long long)e.vtable, e.flags, e.flags & 7,
                e.bad_vtable ? " *** BAD ***" : "");
    }

    // Children
    fprintf(g_log, "  CHILDREN: +0x08=%d, +0x218=%d\n", s.child08_total, s.child218_total);

    // Bad children
    if (s.bad_child_count > 0) {
        fprintf(g_log, "  BAD CHILDREN (%d):\n", s.bad_child_count);
        for (int i = 0; i < s.bad_child_count; i++) {
            const ChildInfo& c = s.bad_children[i];
            fprintf(g_log, "    child=0x%llX vt=0x%llX parent=0x%llX (line %d, vt=0x%llX) chain=+0x%s\n",
                    (unsigned long long)c.addr, (unsigned long long)c.vtable,
                    (unsigned long long)c.parent_addr, c.parent_line,
                    (unsigned long long)c.parent_vtable,
                    c.chain == 0 ? "08" : "218");
        }
    }

    // Allocators
    fprintf(g_log, "  ALLOCATORS (%d):\n", s.alloc_count);
    for (int i = 0; i < s.alloc_count; i++) {
        const AllocInfo& a = s.allocs[i];
        if (!a.valid) continue;
        fprintf(g_log, "    [%d] \"%s\" at 0x%llX: alloc=%u free=%u live=%u\n",
                i, a.name, (unsigned long long)a.addr, a.total_alloc, a.total_free, a.live);
    }

    // DLL shared memory
    if (s.shm_ok) {
        fprintf(g_log, "  DLL: arena=0x%llX ring_head=%u rollback=%s\n",
                (unsigned long long)s.shm.arena_base, s.shm.ring_head,
                s.shm.rollback_active ? "ACTIVE" : "idle");
        fprintf(g_log, "  DLL: scanned=%u nulled=%u unknown=%u anim_fix=%u\n",
                s.shm.entities_scanned, s.shm.entities_nulled,
                s.shm.entities_unknown, s.shm.anim_fixed);
        fprintf(g_log, "  DLL: force_dirty=%u ch08=%u ch218=%u allocs=%u\n",
                s.shm.force_dirty_count, s.shm.child08_count,
                s.shm.child218_count, s.shm.alloc_count);
        if (s.shm.last_crash[0])
            fprintf(g_log, "  DLL CRASH: %s\n", s.shm.last_crash);
    }

    fprintf(g_log, "\n");
    fflush(g_log);
}

static void log_changes(const PollState& cur, const PollState& prev) {
    if (!g_log) return;

    // Frame change
    if (cur.frame1 != prev.frame1) {
        log_timestamp();
        fprintf(g_log, "TICK %u → %u\n", prev.frame1, cur.frame1);
    }

    // Entity count changes
    if (cur.total_entities != prev.total_entities) {
        log_timestamp();
        fprintf(g_log, "ENTITIES: %d → %d\n", prev.total_entities, cur.total_entities);
    }

    // Bad vtable appeared
    if (cur.total_bad_vtable > 0 && prev.total_bad_vtable == 0) {
        log_timestamp();
        fprintf(g_log, "*** BAD VTABLE APPEARED: %d bad entities ***\n", cur.total_bad_vtable);
        // Full dump on bad vtable appearance
        log_full_state(cur);
    }

    // Bad children appeared
    if (cur.bad_child_count > 0 && prev.bad_child_count == 0) {
        log_timestamp();
        fprintf(g_log, "*** BAD CHILD APPEARED: %d bad children ***\n", cur.bad_child_count);
        log_full_state(cur);
    }

    // Rollback started
    if (cur.shm_ok && prev.shm_ok && cur.shm.rollback_active && !prev.shm.rollback_active) {
        log_timestamp();
        fprintf(g_log, ">>> ROLLBACK START: target=%u depth=%u <<<\n",
                cur.shm.last_rollback_target, cur.shm.last_rollback_depth);
        log_full_state(cur);
    }

    // Rollback ended
    if (cur.shm_ok && prev.shm_ok && !cur.shm.rollback_active && prev.shm.rollback_active) {
        log_timestamp();
        fprintf(g_log, ">>> ROLLBACK END <<<\n");
        log_full_state(cur);
    }

    // Crash appeared
    if (cur.shm_ok && cur.shm.last_crash[0] &&
        (!prev.shm_ok || strcmp(cur.shm.last_crash, prev.shm.last_crash) != 0)) {
        log_timestamp();
        fprintf(g_log, "!!! CRASH: %s !!!\n", cur.shm.last_crash);
        log_full_state(cur);
    }

    // RNG changed (log periodically, not every frame)
    if (memcmp(cur.rng, prev.rng, 16) != 0 && (g_log_tick % 60) == 0) {
        log_timestamp();
        fprintf(g_log, "RNG: %08X%08X%08X%08X → %08X%08X%08X%08X\n",
                prev.rng[0], prev.rng[1], prev.rng[2], prev.rng[3],
                cur.rng[0], cur.rng[1], cur.rng[2], cur.rng[3]);
    }

    // Per-line entity count changes
    for (int line = 0; line < SCHED_LINES; line++) {
        if (cur.lines[line].count != prev.lines[line].count) {
            log_timestamp();
            fprintf(g_log, "LINE %d: %d → %d entities\n", line, prev.lines[line].count, cur.lines[line].count);
        }
        if (cur.lines[line].has_bad && !prev.lines[line].has_bad) {
            log_timestamp();
            fprintf(g_log, "LINE %d: *** BAD VTABLE APPEARED ***\n", line);
        }
    }
}

static void log_periodic(const PollState& s) {
    // Full state dump every 10 seconds (100 ticks at 100ms)
    if ((g_log_tick % 100) == 0) {
        log_timestamp();
        fprintf(g_log, "--- PERIODIC DUMP (tick %d) ---\n", g_log_tick);
        log_full_state(s);
    }
}

// ============================================================
// Console TUI state
// ============================================================

static HANDLE g_con_out = INVALID_HANDLE_VALUE;
static HANDLE g_con_in  = INVALID_HANDLE_VALUE;
static int    g_con_w   = 80;
static int    g_con_h   = 50;

// We build the frame into a buffer, then blit it once.
static constexpr int MAX_ROWS = 80;
static constexpr int MAX_COLS = 120;

struct Cell {
    WCHAR  ch;
    WORD   attr;
};

static Cell g_frame[MAX_ROWS][MAX_COLS];
static int  g_rows = 0;
static int  g_cols = 0;

static void tui_init() {
    g_con_out = GetStdHandle(STD_OUTPUT_HANDLE);
    g_con_in  = GetStdHandle(STD_INPUT_HANDLE);

    // Disable quick-edit so mouse doesn't pause output
    DWORD mode = 0;
    GetConsoleMode(g_con_in, &mode);
    SetConsoleMode(g_con_in, mode & ~ENABLE_QUICK_EDIT_MODE);

    // Hide cursor
    CONSOLE_CURSOR_INFO ci = { 1, FALSE };
    SetConsoleCursorInfo(g_con_out, &ci);

    // Set title
    SetConsoleTitleA("UMvC3 Rollback Monitor");

    // Get size
    CONSOLE_SCREEN_BUFFER_INFO csbi;
    if (GetConsoleScreenBufferInfo(g_con_out, &csbi)) {
        g_con_w = csbi.srWindow.Right - csbi.srWindow.Left + 1;
        g_con_h = csbi.srWindow.Bottom - csbi.srWindow.Top + 1;
    }

    g_cols = std::min(g_con_w, MAX_COLS);
    g_rows = std::min(g_con_h, MAX_ROWS);
}

static void frame_clear() {
    for (int r = 0; r < g_rows; r++)
        for (int c = 0; c < g_cols; c++) {
            g_frame[r][c].ch   = L' ';
            g_frame[r][c].attr = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE;
        }
}

// Attribute shortcuts
static constexpr WORD ATTR_NORMAL  = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE;
static constexpr WORD ATTR_BOLD    = ATTR_NORMAL | FOREGROUND_INTENSITY;
static constexpr WORD ATTR_RED     = FOREGROUND_RED | FOREGROUND_INTENSITY;
static constexpr WORD ATTR_GREEN   = FOREGROUND_GREEN | FOREGROUND_INTENSITY;
static constexpr WORD ATTR_YELLOW  = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY;
static constexpr WORD ATTR_CYAN    = FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY;
static constexpr WORD ATTR_MAGENTA = FOREGROUND_RED | FOREGROUND_BLUE | FOREGROUND_INTENSITY;
static constexpr WORD ATTR_HEADER  = BACKGROUND_BLUE | FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY;
static constexpr WORD ATTR_DIM     = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE;  // same as normal, no intensity

static void frame_put(int row, int col, WCHAR ch, WORD attr) {
    if (row < 0 || row >= g_rows || col < 0 || col >= g_cols) return;
    g_frame[row][col].ch   = ch;
    g_frame[row][col].attr = attr;
}

static void frame_str(int row, int col, const char* s, WORD attr) {
    for (int i = 0; s[i]; i++) {
        frame_put(row, col + i, (WCHAR)(unsigned char)s[i], attr);
    }
}

static int frame_printf(int row, int col, WORD attr, const char* fmt, ...) {
    char buf[512];
    va_list va;
    va_start(va, fmt);
    int len = vsnprintf(buf, sizeof(buf), fmt, va);
    va_end(va);
    frame_str(row, col, buf, attr);
    return len;
}

// Draw a horizontal box line
static void frame_hline(int row, int col, int width, WCHAR left, WCHAR fill, WCHAR right, WORD attr) {
    frame_put(row, col, left, attr);
    for (int i = 1; i < width - 1; i++) frame_put(row, col + i, fill, attr);
    frame_put(row, col + width - 1, right, attr);
}

// Draw left/right border chars on a row (content row)
static void frame_border(int row, int col, int width, WORD attr) {
    frame_put(row, col, L'\x2551', attr);           // ║
    frame_put(row, col + width - 1, L'\x2551', attr);
}

static void frame_flush() {
    // Blit entire frame in one WriteConsoleOutputW call
    COORD buf_size  = { (SHORT)g_cols, (SHORT)g_rows };
    COORD buf_coord = { 0, 0 };
    SMALL_RECT rect = { 0, 0, (SHORT)(g_cols - 1), (SHORT)(g_rows - 1) };

    // Convert our Cell array to CHAR_INFO array
    static CHAR_INFO ci[MAX_ROWS * MAX_COLS];
    for (int r = 0; r < g_rows; r++) {
        for (int c = 0; c < g_cols; c++) {
            ci[r * g_cols + c].Char.UnicodeChar = g_frame[r][c].ch;
            ci[r * g_cols + c].Attributes       = g_frame[r][c].attr;
        }
    }
    WriteConsoleOutputW(g_con_out, ci, buf_size, buf_coord, &rect);
}

// ============================================================
// ReadProcessMemory helpers
// ============================================================

static HANDLE g_proc = INVALID_HANDLE_VALUE;

static bool rpm(uint64_t addr, void* dst, size_t sz) {
    if (g_proc == INVALID_HANDLE_VALUE) return false;
    SIZE_T got = 0;
    return ReadProcessMemory(g_proc, (LPCVOID)addr, dst, sz, &got) && got == sz;
}

static uint64_t rpm_ptr(uint64_t addr) {
    uint64_t val = 0;
    rpm(addr, &val, 8);
    return val;
}

static uint32_t rpm_u32(uint64_t addr) {
    uint32_t val = 0;
    rpm(addr, &val, 4);
    return val;
}

static uint8_t rpm_u8(uint64_t addr) {
    uint8_t val = 0;
    rpm(addr, &val, 1);
    return val;
}

static inline uint64_t resolve(uint64_t ida_addr) {
    return ida_addr;  // game base IS 0x140000000, ida addresses are absolute
}

// ============================================================
// Process finding
// ============================================================

static DWORD find_game_pid() {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32W pe = {};
    pe.dwSize = sizeof(pe);
    DWORD pid = 0;
    if (Process32FirstW(snap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, L"umvc3.exe") == 0) {
                pid = pe.th32ProcessID;
                break;
            }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return pid;
}

static bool open_game_process() {
    if (g_proc != INVALID_HANDLE_VALUE) {
        // Check if still alive
        DWORD code = 0;
        if (GetExitCodeProcess(g_proc, &code) && code == STILL_ACTIVE)
            return true;
        CloseHandle(g_proc);
        g_proc = INVALID_HANDLE_VALUE;
    }

    DWORD pid = find_game_pid();
    if (!pid) return false;

    g_proc = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
    return g_proc != INVALID_HANDLE_VALUE;
}

// ============================================================
// Shared memory
// ============================================================

// PER-INSTANCE SHM (netplay infrastructure): the DLL publishes "UMvC3RollbackMonitor.P1"/".P2" (role-suffixed;
// the unqualified shared name made two instances stomp one region). Pass the role as argv[1]; default P1.
static char g_shm_name[64] = "UMvC3RollbackMonitor.P1";

static HANDLE       g_shm_handle = NULL;
static MonitorData* g_shm        = nullptr;

static bool open_shm() {
    if (g_shm) return true;
    g_shm_handle = OpenFileMappingA(FILE_MAP_ALL_ACCESS, FALSE, g_shm_name);
    if (!g_shm_handle) return false;
    g_shm = (MonitorData*)MapViewOfFile(g_shm_handle, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(MonitorData));
    return g_shm != nullptr;
}

static void close_shm() {
    if (g_shm)        { UnmapViewOfFile(g_shm); g_shm = nullptr; }
    if (g_shm_handle) { CloseHandle(g_shm_handle); g_shm_handle = nullptr; }
}

// ============================================================
// Write-log consumer — drains the DLL's ring buffer
// ============================================================

static void drain_writelog() {
    if (!g_shm || !g_writelog_file) return;

    uint32_t head = g_shm->writelog_head;
    if (head == g_local_tail) return;

    int drained = 0;
    while (g_local_tail != head) {
        uint32_t idx = g_local_tail % WRITELOG_SIZE;
        const WriteLogEntry& e = g_shm->writelog[idx];

        const char* phase_name = (e.phase_id < PHASE_COUNT) ? PHASE_NAMES[e.phase_id] : "UNKNOWN";
        const char* rule_name = (e.rule_id < 8) ? UNLINK_RULE_NAMES[e.rule_id] : "";

        bool is_unlink = (e.phase_id == PHASE_UNLINK_POST_LOAD || e.phase_id == PHASE_UNLINK_POST_RESIM);

        if (is_unlink) {
            fprintf(g_writelog_file, "[%u] frame=%u %s UNLINK-%s ent=0x%llX +0x%03X: 0x%llX -> 0x%llX\n",
                e.sequence, e.frame, phase_name, rule_name,
                (unsigned long long)e.entity, e.offset,
                (unsigned long long)e.old_val, (unsigned long long)e.new_val);
        } else if (e.phase_id == PHASE_PACER_FIX) {
            float old_dt, new_dt;
            memcpy(&old_dt, &e.old_val, 4);
            memcpy(&new_dt, &e.new_val, 4);
            fprintf(g_writelog_file, "[%u] frame=%u PACER-FIX sMain+0x40038: %.6f -> %.6f\n",
                e.sequence, e.frame, old_dt, new_dt);
        } else {
            fprintf(g_writelog_file, "[%u] frame=%u %s ent=0x%llX +0x%03X: 0x%llX -> 0x%llX\n",
                e.sequence, e.frame, phase_name,
                (unsigned long long)e.entity, e.offset,
                (unsigned long long)e.old_val, (unsigned long long)e.new_val);
        }

        g_local_tail++;
        drained++;
        if (drained >= WRITELOG_SIZE) break;
    }

    if (drained > 0) {
        fflush(g_writelog_file);

        if (g_log) {
            uint32_t new_seq = g_shm->phase_sequence;
            if (new_seq != g_last_phase_seq) {
                const char* pname = (g_shm->current_phase < PHASE_COUNT) ?
                    PHASE_NAMES[g_shm->current_phase] : "UNKNOWN";
                log_timestamp();
                fprintf(g_log, "PHASE: seq=%u %s frame=%u (drained %d writes)\n",
                    new_seq, pname, g_shm->current_frame, drained);
                fflush(g_log);
                g_last_phase_seq = new_seq;
            }
        }
    }
}

// ============================================================
// Poll logic
// ============================================================

static void poll_data(PollState& st) {
    memset(&st, 0, sizeof(st));

    st.game_found = open_game_process();
    if (!st.game_found) return;

    // --- .data globals ---
    rpm(resolve(GAME_BASE + OFF_RNG_STATE), st.rng, 16);
    st.frame1    = rpm_u32(resolve(GAME_BASE + OFF_FRAME1));
    st.frame2    = rpm_u32(resolve(GAME_BASE + OFF_FRAME2));
    st.threading = rpm_u8(resolve(GAME_BASE + OFF_THREADING));

    // Timer: 16 bytes — first float is seconds (double actually; use double)
    {
        double timer_val = 0.0;
        rpm(resolve(GAME_BASE + OFF_TIMER), &timer_val, 8);
        st.timer_secs = (float)timer_val;
        if (!std::isfinite(st.timer_secs) || st.timer_secs < 0.0f || st.timer_secs > 1e7f)
            st.timer_secs = 0.0f;
    }

    // --- Shared memory ---
    st.shm_ok = open_shm();
    if (st.shm_ok && g_shm) {
        memcpy(&st.shm, g_shm, sizeof(MonitorData));
        st.shm_found = true;
    }

    // --- sUnit scheduler ---
    uint64_t sunit = rpm_ptr(resolve(GAME_BASE + OFF_SUNIT_PTR));
    if (!sunit || sunit < 0x10000) goto skip_sched;

    {
        // Read all 128 line head/tail pointers in one batch: each line is 0x30 bytes,
        // head is at +0x58, tail at +0x50 within sUnit (relative to sunit base).
        // Lines start at sunit + 0x38. Line N: head at sunit + 0x58 + N*0x30
        // We read the entire scheduler header block (128 * 0x30 = 0x1800 bytes)
        static uint8_t sched_block[128 * 0x30];
        uint64_t sched_addr = sunit + 0x38;
        bool got_sched = rpm(sched_addr, sched_block, sizeof(sched_block));
        if (!got_sched) goto skip_sched;

        for (int line = 0; line < SCHED_LINES; line++) {
            // Within block: line * 0x30, head ptr at +0x20 (= sunit+0x58), tail at +0x18
            uint8_t* ldata = sched_block + line * 0x30;
            uint64_t head, tail;
            memcpy(&tail, ldata + 0x18, 8);
            memcpy(&head, ldata + 0x20, 8);

            st.lines[line].head = head;
            st.lines[line].tail = tail;
            st.lines[line].count = 0;
            st.lines[line].has_bad = false;

            if (!head || head < 0x10000) continue;

            // Walk the entity linked list via +0x20 (next)
            uint64_t ent = head;
            int walk = 0;
            while (ent && walk < 512) {
                // Read entity header: 0x230 bytes covers all fields we need
                static uint8_t ent_buf[0x230];
                if (!rpm(ent, ent_buf, sizeof(ent_buf))) break;

                uint64_t vtable, next;
                uint32_t flags;
                memcpy(&vtable, ent_buf + 0x00, 8);
                memcpy(&flags,  ent_buf + 0x10, 4);
                memcpy(&next,   ent_buf + 0x20, 8);

                bool bad_vt = (vtable < GAME_BASE || vtable >= GAME_BASE + GAME_SIZE);

                if (st.entity_count < MAX_ENTITIES) {
                    EntityInfo& ei = st.entities[st.entity_count++];
                    ei.addr       = ent;
                    ei.vtable     = vtable;
                    ei.flags      = flags;
                    ei.line       = line;
                    ei.bad_vtable = bad_vt;
                }

                int state = flags & 0x7;
                if (state >= 0 && state < 8)
                    st.lines[line].state_counts[state]++;

                if (bad_vt) {
                    st.lines[line].has_bad = true;
                    st.total_bad_vtable++;
                }

                st.lines[line].count++;
                st.total_entities++;

                // Walk child chains while we have the entity buffer
                // Chain 1: +0x08 → next at child+0x58
                {
                    uint64_t child;
                    memcpy(&child, ent_buf + 0x08, 8);
                    int cwalk = 0;
                    while (child && child > 0x10000 && cwalk < 256) {
                        static uint8_t cbuf[0x60];
                        if (!rpm(child, cbuf, sizeof(cbuf))) break;
                        uint64_t cvt, cnext;
                        memcpy(&cvt,   cbuf + 0x00, 8);
                        memcpy(&cnext, cbuf + 0x58, 8);
                        st.child08_total++;

                        bool cbad = (cvt < GAME_BASE || cvt >= GAME_BASE + GAME_SIZE);
                        if (cbad && st.bad_child_count < MAX_BAD) {
                            ChildInfo& ci = st.bad_children[st.bad_child_count++];
                            ci.addr        = child;
                            ci.vtable      = cvt;
                            ci.parent_addr = ent;
                            ci.parent_vtable = vtable;
                            ci.parent_line = line;
                            ci.chain       = 0;
                            ci.bad_vtable  = true;
                        }

                        child = cnext;
                        cwalk++;
                    }
                }

                // Chain 2: +0x218 → next at child+0x18
                {
                    uint64_t child;
                    memcpy(&child, ent_buf + 0x218, 8);
                    int cwalk = 0;
                    while (child && child > 0x10000 && cwalk < 256) {
                        static uint8_t cbuf[0x20];
                        if (!rpm(child, cbuf, sizeof(cbuf))) break;
                        uint64_t cvt, cnext;
                        memcpy(&cvt,   cbuf + 0x00, 8);
                        memcpy(&cnext, cbuf + 0x18, 8);
                        st.child218_total++;

                        bool cbad = (cvt < GAME_BASE || cvt >= GAME_BASE + GAME_SIZE);
                        if (cbad && st.bad_child_count < MAX_BAD) {
                            ChildInfo& ci = st.bad_children[st.bad_child_count++];
                            ci.addr        = child;
                            ci.vtable      = cvt;
                            ci.parent_addr = ent;
                            ci.parent_vtable = vtable;
                            ci.parent_line = line;
                            ci.chain       = 1;
                            ci.bad_vtable  = true;
                        }

                        child = cnext;
                        cwalk++;
                    }
                }

                ent = next;
                walk++;
            }
        }
    }

skip_sched:

    // --- Allocators ---
    {
        uint32_t alloc_reg_count = rpm_u32(resolve(GAME_BASE + OFF_ALLOC_COUNT));
        uint64_t alloc_array     = resolve(GAME_BASE + OFF_ALLOC_ARRAY);

        if (alloc_reg_count > 64) alloc_reg_count = 64;
        st.alloc_count = 0;

        // Read all 64 pointers in one batch
        static uint64_t alloc_ptrs[64];
        if (rpm(alloc_array, alloc_ptrs, alloc_reg_count * 8)) {
            for (uint32_t i = 0; i < alloc_reg_count && st.alloc_count < MAX_ALLOCS; i++) {
                uint64_t aptr = alloc_ptrs[i];
                if (!aptr || aptr < 0x10000) continue;

                AllocInfo& ai = st.allocs[st.alloc_count];
                memset(&ai, 0, sizeof(ai));
                ai.addr  = aptr;
                ai.valid = true;

                // Read name at +0x21 (32 chars)
                static uint8_t abuf[0x700];
                if (rpm(aptr, abuf, sizeof(abuf))) {
                    // Name at +0x21 (null-terminated)
                    strncpy(ai.name, (char*)(abuf + 0x21), 63);
                    ai.name[63] = 0;

                    // MtScalableAllocator stats are not decoded here — only the name and address are shown.
                    // If the name is blank/garbage, mark invalid.
                    if (ai.name[0] == 0 || (unsigned char)ai.name[0] < 0x20)
                        ai.valid = false;
                } else {
                    ai.valid = false;
                }

                if (ai.valid) st.alloc_count++;
            }
        }
    }
}

// ============================================================
// TUI rendering
// ============================================================

static void draw_frame(const PollState& st) {
    frame_clear();

    const WORD bdr   = ATTR_BOLD;
    const WORD hdr   = ATTR_CYAN;
    const WORD nrm   = ATTR_NORMAL;
    const WORD red   = ATTR_RED;
    const WORD grn   = ATTR_GREEN;
    const WORD yel   = ATTR_YELLOW;
    const WORD mag   = ATTR_MAGENTA;
    const WORD dim   = ATTR_DIM;

    int width = g_cols;
    int row   = 0;

    auto hline_top = [&](int r) {
        frame_put(r, 0, L'\x2554', bdr);
        for (int c = 1; c < width - 1; c++) frame_put(r, c, L'\x2550', bdr);
        frame_put(r, width - 1, L'\x2557', bdr);
    };
    auto hline_mid = [&](int r) {
        frame_put(r, 0, L'\x2560', bdr);
        for (int c = 1; c < width - 1; c++) frame_put(r, c, L'\x2550', bdr);
        frame_put(r, width - 1, L'\x2563', bdr);
    };
    auto hline_bot = [&](int r) {
        frame_put(r, 0, L'\x255A', bdr);
        for (int c = 1; c < width - 1; c++) frame_put(r, c, L'\x2550', bdr);
        frame_put(r, width - 1, L'\x255D', bdr);
    };
    auto content_row = [&](int r) {
        frame_put(r, 0, L'\x2551', bdr);
        frame_put(r, width - 1, L'\x2551', bdr);
    };

    // ── Title bar ──
    hline_top(row++);
    content_row(row);
    {
        const char* title = "UMvC3 Rollback Monitor";
        frame_str(row, 2, title, hdr);
        if (!st.game_found) {
            frame_str(row, width - 22, "  [WAITING FOR GAME]  ", red);
        } else {
            char fc[40];
            snprintf(fc, sizeof(fc), "Frame: %u", st.frame1);
            frame_str(row, width - (int)strlen(fc) - 2, fc, grn);
        }
    }
    row++;

    // ── Scheduler section ──
    hline_mid(row++);
    content_row(row);
    frame_str(row++, 2, "SCHEDULER", hdr);

    // Only print non-empty lines
    int printed_lines = 0;
    for (int line = 0; line < SCHED_LINES; line++) {
        if (st.lines[line].count == 0) continue;
        if (row >= g_rows - 10) {
            content_row(row);
            frame_str(row++, 4, "  ... (more lines) ...", dim);
            break;
        }

        content_row(row);
        // Build state summary
        char state_buf[80] = "";
        bool has_states = false;
        for (int s = 0; s < 8; s++) {
            if (st.lines[line].state_counts[s] > 0) {
                char tmp[20];
                snprintf(tmp, sizeof(tmp), "%s%d\xC3\x97%d",
                         has_states ? ", " : "(states: ",
                         st.lines[line].state_counts[s], s);
                strncat(state_buf, tmp, sizeof(state_buf) - strlen(state_buf) - 1);
                has_states = true;
            }
        }
        if (has_states) strncat(state_buf, ")", sizeof(state_buf) - strlen(state_buf) - 1);

        // Fighter lines: 13 is known to be fighters
        const char* annot = (line == 13) ? " (FIGHTERS)" : "";

        char line_buf[120];
        int llen = snprintf(line_buf, sizeof(line_buf),
                            "  Line %3d: %3d entities%s",
                            line, st.lines[line].count, annot);

        WORD line_attr = nrm;
        if (st.lines[line].has_bad) {
            line_attr = red;
            // Append bad vtable warning
            char bad_buf[40];
            snprintf(bad_buf, sizeof(bad_buf), "  !! BAD VTABLE !!");
            strncat(line_buf, bad_buf, sizeof(line_buf) - strlen(line_buf) - 1);
        }

        frame_str(row, 2, line_buf, line_attr);
        printed_lines++;
        row++;
    }

    // Total line
    if (row < g_rows - 10) {
        content_row(row);
        char total_buf[80];
        snprintf(total_buf, sizeof(total_buf),
                 "  Total: %d entities, %d bad vtables",
                 st.total_entities, st.total_bad_vtable);
        frame_str(row++, 2, total_buf, st.total_bad_vtable > 0 ? red : grn);
    }

    // ── Children section ──
    if (row < g_rows - 10) {
        hline_mid(row++);
        content_row(row);
        frame_str(row++, 2, "CHILDREN", hdr);

        content_row(row);
        char ch_buf[100];
        snprintf(ch_buf, sizeof(ch_buf),
                 "  +0x08 chains:  %5d children across %d parents",
                 st.child08_total, st.total_entities);
        frame_str(row++, 2, ch_buf, nrm);

        if (row < g_rows - 8) {
            content_row(row);
            snprintf(ch_buf, sizeof(ch_buf),
                     "  +0x218 chains: %5d children across %d parents",
                     st.child218_total, st.total_entities);
            frame_str(row++, 2, ch_buf, nrm);
        }

        // Bad children
        for (int i = 0; i < st.bad_child_count && row < g_rows - 6; i++) {
            const ChildInfo& ci = st.bad_children[i];
            content_row(row);
            char bad_buf[120];
            snprintf(bad_buf, sizeof(bad_buf),
                     "  !! BAD child 0x%llX vt=0x%llX (chain +0x%s, parent line %d)",
                     (unsigned long long)ci.addr,
                     (unsigned long long)ci.vtable,
                     ci.chain == 0 ? "08" : "218",
                     ci.parent_line);
            frame_str(row++, 2, bad_buf, red);

            if (row < g_rows - 5) {
                content_row(row);
                char par_buf[120];
                snprintf(par_buf, sizeof(par_buf),
                         "    Parent: 0x%llX vt=0x%llX",
                         (unsigned long long)ci.parent_addr,
                         (unsigned long long)ci.parent_vtable);
                frame_str(row++, 2, par_buf, red);
            }
        }
    }

    // ── Allocators section ──
    if (row < g_rows - 8) {
        hline_mid(row++);
        content_row(row);
        {
            char al_hdr[60];
            snprintf(al_hdr, sizeof(al_hdr), "ALLOCATORS (%d registered)", st.alloc_count);
            frame_str(row++, 2, al_hdr, hdr);
        }

        for (int i = 0; i < st.alloc_count && row < g_rows - 6; i++) {
            const AllocInfo& ai = st.allocs[i];
            if (!ai.valid) continue;
            content_row(row);
            char al_buf[120];
            snprintf(al_buf, sizeof(al_buf),
                     "  [%2d] %-32s  @ 0x%llX",
                     i, ai.name, (unsigned long long)ai.addr);
            frame_str(row++, 2, al_buf, nrm);
        }
    }

    // ── .data section ──
    if (row < g_rows - 8) {
        hline_mid(row++);
        content_row(row);
        frame_str(row++, 2, ".DATA", hdr);

        if (row < g_rows - 7) {
            content_row(row);
            char rng_buf[80];
            snprintf(rng_buf, sizeof(rng_buf),
                     "  RNG: %08X %08X %08X %08X",
                     st.rng[0], st.rng[1], st.rng[2], st.rng[3]);
            frame_str(row++, 2, rng_buf, nrm);
        }

        if (row < g_rows - 6) {
            content_row(row);
            char fr_buf[80];
            snprintf(fr_buf, sizeof(fr_buf),
                     "  Frame: %u / %u    Timer: %.3fs",
                     st.frame1, st.frame2, st.timer_secs);
            frame_str(row++, 2, fr_buf, nrm);
        }

        if (row < g_rows - 5) {
            content_row(row);
            char th_buf[40];
            snprintf(th_buf, sizeof(th_buf),
                     "  Threading: %s", st.threading ? "ON" : "OFF");
            frame_str(row++, 2, th_buf, st.threading ? grn : yel);
        }
    }

    // ── Arena section (from DLL shared memory) ──
    if (st.shm_ok && row < g_rows - 8) {
        hline_mid(row++);
        content_row(row);
        frame_str(row++, 2, "ARENA  (via DLL shared memory)", hdr);

        if (row < g_rows - 7) {
            content_row(row);
            char ar_buf[100];
            uint64_t arena_mb = st.shm.arena_size / (1024 * 1024);
            snprintf(ar_buf, sizeof(ar_buf),
                     "  Base: 0x%llX    Size: %llu MB",
                     (unsigned long long)st.shm.arena_base,
                     (unsigned long long)arena_mb);
            frame_str(row++, 2, ar_buf, nrm);
        }

        if (row < g_rows - 6) {
            content_row(row);
            char rb_buf[100];
            snprintf(rb_buf, sizeof(rb_buf),
                     "  Ring head: %u    Frame: %u",
                     st.shm.ring_head, st.shm.frame_counter);
            frame_str(row++, 2, rb_buf, nrm);
        }

        if (row < g_rows - 5) {
            content_row(row);
            char sc_buf[120];
            snprintf(sc_buf, sizeof(sc_buf),
                     "  Force-dirty: %u ents + %u ch08 + %u ch218",
                     st.shm.force_dirty_count,
                     st.shm.child08_count,
                     st.shm.child218_count);
            frame_str(row++, 2, sc_buf, nrm);
        }

        if (row < g_rows - 4) {
            content_row(row);
            char tav_buf[120];
            snprintf(tav_buf, sizeof(tav_buf),
                     "  HANDLE-PRESERVE: scanned=%u nulled=%u unknown=%u",
                     st.shm.entities_scanned,
                     st.shm.entities_nulled,
                     st.shm.entities_unknown);
            frame_str(row++, 2, tav_buf, nrm);
        }
    }

    // ── Last rollback ──
    if (row < g_rows - 4) {
        if (st.shm_ok) {
            hline_mid(row++);
            content_row(row);

            if (st.shm.rollback_active) {
                frame_str(row++, 2, "ROLLBACK: ACTIVE", yel);
            } else if (st.shm.last_rollback_depth > 0) {
                content_row(row);
                char rb2_buf[120];
                snprintf(rb2_buf, sizeof(rb2_buf),
                         "LAST ROLLBACK: frame %u -> %u (depth %u)",
                         st.shm.last_rollback_target + st.shm.last_rollback_depth,
                         st.shm.last_rollback_target,
                         st.shm.last_rollback_depth);
                frame_str(row++, 2, rb2_buf, grn);
            } else {
                frame_str(row++, 2, "LAST ROLLBACK: none yet", dim);
            }

            // Crash info
            if (row < g_rows - 3 && st.shm.last_crash[0] != 0) {
                content_row(row);
                char crash_buf[120];
                snprintf(crash_buf, sizeof(crash_buf), "LAST CRASH: %.110s", st.shm.last_crash);
                frame_str(row++, 2, crash_buf, red);
            } else if (row < g_rows - 3) {
                content_row(row);
                frame_str(row++, 2, "LAST CRASH: none", dim);
            }
        } else {
            hline_mid(row++);
            content_row(row);
            frame_str(row++, 2, "DLL SHARED MEMORY: not available (DLL not loaded?)", yel);
        }
    }

    // Bottom border — fill remaining rows with content borders then close
    while (row < g_rows - 1) {
        content_row(row++);
    }
    if (row < g_rows) {
        hline_bot(row++);
    }

    frame_flush();
}

static void draw_waiting() {
    frame_clear();
    int row = 0;
    const int w = g_cols;

    frame_put(row, 0, L'\x2554', ATTR_BOLD);
    for (int c = 1; c < w - 1; c++) frame_put(row, c, L'\x2550', ATTR_BOLD);
    frame_put(row, w - 1, L'\x2557', ATTR_BOLD);
    row++;

    frame_put(row, 0, L'\x2551', ATTR_BOLD);
    frame_put(row, w - 1, L'\x2551', ATTR_BOLD);
    frame_str(row, 2, "UMvC3 Rollback Monitor", ATTR_CYAN);
    row++;

    frame_put(row, 0, L'\x2551', ATTR_BOLD);
    frame_put(row, w - 1, L'\x2551', ATTR_BOLD);
    frame_str(row, 2, "Waiting for umvc3.exe ... (press Q to quit)", ATTR_YELLOW);
    row++;

    while (row < g_rows - 1) {
        frame_put(row, 0, L'\x2551', ATTR_BOLD);
        frame_put(row, w - 1, L'\x2551', ATTR_BOLD);
        row++;
    }
    frame_put(row, 0, L'\x255A', ATTR_BOLD);
    for (int c = 1; c < w - 1; c++) frame_put(row, c, L'\x2550', ATTR_BOLD);
    frame_put(row, w - 1, L'\x255D', ATTR_BOLD);

    frame_flush();
}

// ============================================================
// Main loop
// ============================================================


int main(int argc, char** argv) {
    if (argc > 1) snprintf(g_shm_name, sizeof(g_shm_name), "UMvC3RollbackMonitor.%s", argv[1]);
    // Force UTF-16 console output (for box-drawing chars)
    SetConsoleOutputCP(CP_UTF8);

    tui_init();
    log_init();

    DWORD last_tick = GetTickCount();

    while (true) {
        // Check for Q to quit
        if (GetAsyncKeyState('Q') & 1) break;
        if (GetAsyncKeyState(VK_ESCAPE) & 1) break;

        DWORD now = GetTickCount();
        if ((now - last_tick) < 100) {
            Sleep(10);
            continue;
        }
        last_tick = now;

        if (!open_game_process()) {
            draw_waiting();
            continue;
        }

        // Drain write-log ring buffer (high priority — don't lose entries)
        drain_writelog();

        PollState st;
        memset(&st, 0, sizeof(st));
        poll_data(st);
        draw_frame(st);

        // Logging
        if (g_prev_valid) {
            log_changes(st, g_prev_state);
        } else {
            // First poll — full dump
            if (g_log) {
                log_timestamp();
                fprintf(g_log, "=== GAME CONNECTED ===\n");
                log_full_state(st);
            }
        }
        log_periodic(st);

        g_prev_state = st;
        g_prev_valid = true;
        g_log_tick++;
    }

    // Cleanup
    drain_writelog();  // final drain
    if (g_writelog_file) {
        fprintf(g_writelog_file, "\n=== WRITE-LOG SHUTDOWN ===\n");
        fclose(g_writelog_file);
        g_writelog_file = nullptr;
    }
    if (g_log) {
        log_timestamp();
        fprintf(g_log, "=== MONITOR SHUTDOWN ===\n");
        fclose(g_log);
        g_log = nullptr;
    }
    close_shm();
    if (g_proc != INVALID_HANDLE_VALUE) {
        CloseHandle(g_proc);
        g_proc = INVALID_HANDLE_VALUE;
    }

    // Restore cursor
    CONSOLE_CURSOR_INFO ci = { 10, TRUE };
    SetConsoleCursorInfo(g_con_out, &ci);

    return 0;
}
