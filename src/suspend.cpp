#include "suspend.h"
#include "log.h"
#include "xray_mem.h"
#include <windows.h>
#include <tlhelp32.h>

static uint32_t g_main_tid = 0;
static uint32_t g_whitelist[16] = {};
static int g_whitelist_count = 0;

static HANDLE g_cached_handles[256] = {};
static DWORD  g_cached_tids[256] = {};
static int    g_cached_count = 0;
static bool   g_cache_valid = false;

static HANDLE g_suspended[256] = {};
static int g_suspended_count = 0;

// HOLD-THROUGH-RESIM: the window thread (Win32 start = FUN_14051dee0) is the SECOND render driver. Its flag-gate
// (wmgr+0x38/+0x2985) does not by itself hold it (crashes recurred on it with flags=0), and every render traversal
// it might run mid-resim cannot be enumerated (drain, dispatch, 0x14080C1D0, ...). So instead of probing each leaf,
// we hold the PARENT NODE down: freeze() suspends it; thaw() SKIPS it (keeps it suspended through the resim);
// resume_held() resumes it after the resim, when the arena is back at the consistent post-resim epoch. The main
// thread builds the final frame, so holding this thread does not starve rendering.
// The thread is identified by the TID captured from its OWN hooks (hk_device_reset / hk_capture_path run ON it
// during normal play), not by start address (NtQueryInformationThread on the limited cached handle never returned
// 0x14051DEE0, only worker starts 0x1405210C0).
static volatile DWORD g_window_tid = 0;   // set via suspend::note_window_thread (defined in the namespace below)

static HANDLE g_held[16] = {};
static DWORD  g_suspended_tids[256] = {};
static int    g_held_count = 0;

// Render-thread freeze() diagnostic (read-only): captures where the render thread was when freeze caught it.
static DWORD     g_diag_rtid = 0;
static int       g_diag_cached = 0;
static uintptr_t g_diag_rip = 0;
static uintptr_t g_diag_rip_ida = 0;
static bool      g_diag_in_umvc3 = false;
static int       g_diag_flag38 = -2;
static int       g_diag_flag3d = -2;
static int       g_diag_flag3e = -2;

static bool is_whitelisted(uint32_t tid) {
    if (tid == g_main_tid) return true;
    for (int i = 0; i < g_whitelist_count; i++) {
        if (g_whitelist[i] == tid) return true;
    }
    return false;
}

namespace suspend {

void init() {
    g_main_tid = GetCurrentThreadId();
}

void note_window_thread(uint32_t tid) { g_window_tid = tid; }

void whitelist(uint32_t tid) {
    if (g_whitelist_count < 16) {
        g_whitelist[g_whitelist_count++] = tid;
    }
}

// PERF: NtGetNextThread walks only our process's ~81 threads (sub-ms), replacing
// CreateToolhelp32Snapshot which snapshots every thread on the SYSTEM then filters to ours (~77ms — the entire
// suspend+restore dominant, run 2×/rollback = ~154ms). Same quiescence pattern SlimDetours ships for suspend-
// before-patch. Zero determinism change: only how the thread set is obtained, not when/how it's suspended.
// A process has full access to its own threads, so the requested rights never fail within GetCurrentProcess().
typedef LONG (NTAPI *NtGetNextThread_t)(HANDLE, HANDLE, ACCESS_MASK, ULONG, ULONG, PHANDLE);
static NtGetNextThread_t p_NtGetNextThread = (NtGetNextThread_t)-1;   // -1 = unresolved

static void build_cache_toolhelp(DWORD pid, DWORD caller_tid) {   // FALLBACK (pre-Win6 / NtGetNextThread absent)
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) return;
    THREADENTRY32 te = { sizeof(te) };
    if (Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID != pid || te.th32ThreadID == caller_tid) continue;
            if (is_whitelisted(te.th32ThreadID) || g_cached_count >= 256) continue;
            HANDLE h = OpenThread(THREAD_SUSPEND_RESUME, FALSE, te.th32ThreadID);
            if (h) { g_cached_handles[g_cached_count] = h; g_cached_tids[g_cached_count] = te.th32ThreadID; g_cached_count++; }
        } while (Thread32Next(snap, &te));
    }
    CloseHandle(snap);
}

static void build_cache() {
    // Rebuilt every freeze: close prior handles, re-enumerate. A one-time cache is a SUSPEND GAP — a thread
    // that starts after the first rollback is missed (render thread mid-D3D on torn state -> stack overflow).
    // NtGetNextThread re-enumerates cheaply so we keep re-enumerating (catches late threads) without the 77ms tax.
    for (int i = 0; i < g_cached_count; i++) if (g_cached_handles[i]) CloseHandle(g_cached_handles[i]);
    g_cached_count = 0;
    DWORD pid = GetCurrentProcessId();
    DWORD caller_tid = GetCurrentThreadId();

    if (p_NtGetNextThread == (NtGetNextThread_t)-1)
        p_NtGetNextThread = (NtGetNextThread_t)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtGetNextThread");

    if (p_NtGetNextThread) {
        const ACCESS_MASK acc = THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_QUERY_LIMITED_INFORMATION;
        HANDLE prev = nullptr; bool prev_stored = false;
        for (;;) {
            HANDLE next = nullptr;
            LONG st = p_NtGetNextThread(GetCurrentProcess(), prev, acc, 0, 0, &next);
            if (prev && !prev_stored) CloseHandle(prev);   // throwaway cursor (caller/whitelisted) — done as cursor
            if (st != 0 || !next) break;                   // STATUS_NO_MORE_ENTRIES (or error) ends the walk
            DWORD tid = GetThreadId(next);
            if (tid == caller_tid || is_whitelisted(tid) || g_cached_count >= 256) {
                prev = next; prev_stored = false;          // keep open only as the next call's cursor
                continue;
            }
            g_cached_handles[g_cached_count] = next;
            g_cached_tids[g_cached_count] = tid;
            g_cached_count++;
            prev = next; prev_stored = true;               // stored (kept open) and serves as cursor
        }
    }
    if (g_cached_count == 0) build_cache_toolhelp(pid, caller_tid);   // safety: never freeze with an empty set

    g_cache_valid = true;
    rblog::write("SUSPEND: cached %d thread handles (%s)", g_cached_count, p_NtGetNextThread ? "NtGetNextThread" : "toolhelp");
}

void freeze() {
    build_cache();   // rebuild every freeze — a one-time cache misses threads started since (the suspend gap)

    // SUSPEND-SAFETY (the recurring-stall fix): a worker may be mid-rblog::write right now, owning
    // g_log_cs (+ the CRT FILE lock). If we SuspendThread it there, main's next log blocks on g_log_cs
    // forever (the recurring multi-second stall; only the watchdog's resume-all unsticks it). Hold the
    // log lock across the suspend loop so no frozen thread can own it. try_lock() tells us if a thread
    // held it at this instant — the would-have-deadlocked case = direct proof of the mechanism.
    bool log_contended = !rblog::try_lock();
    if (log_contended) rblog::lock();   // wait for the in-flight logger to finish, then we own it

    // Same drain for the byte-tracer's IO lock: a worker may be mid-emit() inside the xray VEH owning g_cs. If
    // we freeze it there, the main thread's resim faults into the VEH -> emit() -> blocks forever on g_cs. Hold
    // it across the suspend so no frozen worker can own it. (No-op cost when the tracer is disarmed/uncontended.)
    bool xray_contended = !xray_mem::try_lock_io();
    if (xray_contended) xray_mem::lock_io();

    g_suspended_count = 0;
    for (int i = 0; i < g_cached_count; i++) {
        DWORD result = SuspendThread(g_cached_handles[i]);
        if (result != (DWORD)-1) {
            g_suspended_tids[g_suspended_count] = g_cached_tids[i];   // TID parallel to the held set
            g_suspended[g_suspended_count++] = g_cached_handles[i];
        }
        // If SuspendThread fails (thread died), handle is stale — skip it
    }
    xray_mem::unlock_io();   // workers frozen now; main faults into the VEH freely the rest of the rollback
    rblog::unlock();   // workers frozen now (can't re-acquire); main logs freely the rest of the rollback

    // RENDER DIAG (read-only): with all workers frozen, look at where the render thread (sRender+0xE8) was
    // caught. RIP inside umvc3 render-exec (~0x14053A000..0x140541000) = frozen MID-RENDER (the bug: thawed,
    // it continues a D3D dispatch against the reverted arena). RIP outside umvc3 (in ntdll) = parked in a
    // wait (safe — the engine's own idle point). Also dump the candidate in-flight flag bytes to validate
    // which offset actually tracks "render busy", so the quiesce can target the right one if +0x100 isn't it.
    {
        uintptr_t mod = (uintptr_t)GetModuleHandleA("umvc3.exe");
        uintptr_t sr = mod ? *(uintptr_t*)(mod + 0xE179A8) : 0;
        g_diag_flag38 = (sr && !IsBadReadPtr((void*)(sr+0x38),1)) ? *(unsigned char*)(sr+0x38) : -2;
        g_diag_flag3d = (sr && !IsBadReadPtr((void*)(sr+0x3d),1)) ? *(unsigned char*)(sr+0x3d) : -2;
        g_diag_flag3e = (sr && !IsBadReadPtr((void*)(sr+0x3e),1)) ? *(unsigned char*)(sr+0x3e) : -2;
        HANDLE rh = (sr && !IsBadReadPtr((void*)(sr+0xE8),8)) ? *(HANDLE*)(sr+0xE8) : nullptr;
        g_diag_rtid = rh ? GetThreadId(rh) : 0;
        g_diag_cached = 0;
        for (int i = 0; i < g_cached_count; i++) if (g_cached_tids[i] == g_diag_rtid) { g_diag_cached = 1; break; }
        g_diag_rip = 0; g_diag_rip_ida = 0; g_diag_in_umvc3 = false;
        if (g_diag_rtid) {
            HANDLE h = OpenThread(THREAD_GET_CONTEXT, FALSE, g_diag_rtid);
            if (h) {
                CONTEXT ctx; ctx.ContextFlags = CONTEXT_CONTROL;
                if (GetThreadContext(h, &ctx)) {
                    g_diag_rip = (uintptr_t)ctx.Rip;
                    if (mod && g_diag_rip >= mod && g_diag_rip < mod + 0xA00000) {
                        g_diag_in_umvc3 = true;
                        g_diag_rip_ida = g_diag_rip - mod + 0x140000000ULL;
                    }
                }
                CloseHandle(h);
            }
        }
    }

    // Force these through do_rollback's log suppression (the freeze loop already drained g_log_cs, so no
    // frozen thread owns it — forcing is deadlock-safe here).
    rblog::suppress(false);
    rblog::write("SUSPEND: froze %d/%d threads (main=%u)%s",
                 g_suspended_count, g_cached_count, g_main_tid,
                 log_contended ? " [LOGLOCK-CONTENDED at freeze — a thread held g_log_cs; this is the stall mechanism, now averted]" : "");
    rblog::write("SUSPEND-RENDER-DIAG: rtid=%u cached=%d frozen_RIP=0x%llX in_umvc3=%d IDA=0x%llX | flags +0x38=%d +0x3d=%d +0x3e=%d"
                 "  [in_umvc3=1 & IDA in 0x14053A000..0x140541000 => frozen MID-RENDER = the bug; in_umvc3=0 => parked in a wait = safe]",
                 g_diag_rtid, g_diag_cached, (unsigned long long)g_diag_rip, (int)g_diag_in_umvc3,
                 (unsigned long long)g_diag_rip_ida, g_diag_flag38, g_diag_flag3d, g_diag_flag3e);
    rblog::suppress(true);
}

void thaw() {
    // Identify the render-domain thread(s) to hold through the resim (skip resuming them now). Done here,
    // after freeze suspended everyone, using THREAD_QUERY-capable cached handles. Each held thread keeps its
    // single suspend count from freeze() (no extra SuspendThread => no count bug) until resume_held().
    g_held_count = 0;
    int resumed = 0, held = 0;
    DWORD wt = g_window_tid;
    for (int i = 0; i < g_suspended_count; i++) {
        bool hold = (wt != 0 && g_suspended_tids[i] == wt);
        if (hold && g_held_count < 16) {
            g_held[g_held_count++] = g_suspended[i];   // leave SUSPENDED across the resim
            held++;
        } else {
            ResumeThread(g_suspended[i]);
            resumed++;
        }
        // DON'T CloseHandle — handles are cached for reuse
    }
    // FORCE through do_rollback's suppress window so the held count is visible.
    bool was = rblog::is_suppressed(); rblog::suppress(false);
    rblog::write("SUSPEND: thawed %d, HELD %d window-thread (tid=%u, of %d suspended)",
                 resumed, held, wt, g_suspended_count);
    rblog::suppress(was);
    g_suspended_count = 0;
}

// Resume the render-domain threads held across the resim — called post-resim, arena back at the consistent
// frame-N+depth epoch, so they wake into a coherent world (same addresses; in-place revert kept them valid).
void resume_held() {
    for (int i = 0; i < g_held_count; i++) ResumeThread(g_held[i]);
    rblog::write("SUSPEND: resume_held — %d held render-domain thread(s) resumed post-resim", g_held_count);
    g_held_count = 0;
}

} // namespace suspend
