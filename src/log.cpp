#include "log.h"
#include <cstdio>
#include <cstdarg>
#include <windows.h>

static FILE* g_log = nullptr;
static LARGE_INTEGER g_start_qpc;
static double g_qpc_freq;
static CRITICAL_SECTION g_log_cs;

namespace rblog {

void init(const char* filepath) {
    // Keep the previous SESSION'S LOG. Opening "w" truncates, so relaunching destroys the run you were about to
    // diagnose. In a two-machine test that is fatal to the workflow: the peer sends their log, you relaunch to try
    // again, and your own half of the failing session is already gone. Three separate netplay failures were analysed
    // from one side only for exactly this reason. Rotate to.prev first — one extra file, no cost, and the last run
    // is always recoverable.
    {
        char prev[1024];
        snprintf(prev, sizeof(prev), "%s.prev", filepath);
        remove(prev);
        rename(filepath, prev);        // silently does nothing on the first run
    }
    g_log = fopen(filepath, "w");
    LARGE_INTEGER freq;
    QueryPerformanceFrequency(&freq);
    g_qpc_freq = (double)freq.QuadPart;
    QueryPerformanceCounter(&g_start_qpc);
    InitializeCriticalSection(&g_log_cs);
    if (g_log) {
        fprintf(g_log, "=== UMvC3 Rollback Beta Log ===\n");
        fflush(g_log);
    }
}

static bool g_suppressed = false;
void suppress(bool on) { g_suppressed = on; }
bool is_suppressed() { return g_suppressed; }

void write(const char* fmt, ...) {
    if (!g_log || g_suppressed) return;
    EnterCriticalSection(&g_log_cs);

    LARGE_INTEGER now;
    QueryPerformanceCounter(&now);
    double elapsed = (double)(now.QuadPart - g_start_qpc.QuadPart) / g_qpc_freq;

    fprintf(g_log, "[%10.3f] ", elapsed);
    va_list args;
    va_start(args, fmt);
    vfprintf(g_log, fmt, args);
    va_end(args);
    fprintf(g_log, "\n");
    fflush(g_log);

    LeaveCriticalSection(&g_log_cs);
}

void flush() {
    if (g_log) fflush(g_log);
}

// Suspend-safety: a worker may be mid-write (holding g_log_cs + the CRT FILE lock) when the rollback
// suspends it; main's next log then blocks on g_log_cs FOREVER (the recurring stall). suspend::freeze()
// brackets its SuspendThread loop with lock()/unlock() so no thread can be frozen while owning the lock.
// try_lock() reports whether a thread held it at that instant (the would-have-deadlocked case = the proof).
bool try_lock() { return TryEnterCriticalSection(&g_log_cs) != 0; }
void lock()     { EnterCriticalSection(&g_log_cs); }
void unlock()   { LeaveCriticalSection(&g_log_cs); }

} // namespace rblog
