// hang_detector.cpp — read-only silent-hang capture (watchdog).
//
// The crash logger alone gives no data on a deadlock — the log just stops. This watches a per-frame heartbeat
// from the main proc; if the main thread stops advancing for >2s, it suspends
// every thread in the process and logs where each one is parked (RIP -> IDA +
// module + key regs) so the deadlock graph is visible (who holds, who waits).
//
// Diagnostic only. Read-only: suspends a thread only long enough to read its
// context, then resumes it; never mutates game state. Not an abort/skip — it
// captures the hang, it does not "recover" from it. Never suspends itself.
#include "log.h"
#include "addr.h"
#include "freelist_diag.h"
#include <windows.h>
#include <tlhelp32.h>
#include <cstdint>
#include <cstdio>
#include <cstring>

namespace hang_detector {

static volatile LONG64 g_hb_qpc = 0;   // last main-proc heartbeat (QPC ticks)
static LONG64 g_qpc_freq = 1;
static DWORD  g_self_tid = 0;          // watchdog thread — never suspend self
static DWORD  g_main_tid = 0;          // the heartbeating (main) thread
static volatile LONG64 g_last_crash_qpc = 0;   // CRASH-GAP: the VEH stamps this when it logs a crash; the
                                               // watchdog reads it to classify HANG-DETECTED as crash-aftermath vs a
                                               // POTENTIAL independent HANG. Both observed hangs were crash-aftermath
                                               // (the kernel-sync hang has never fired) — this names it in one line.

// Called by the VEH (dllmain crash_logger) the instant it logs a crash. Read-only stamp; no other state touched.
void note_crash() { LARGE_INTEGER c; QueryPerformanceCounter(&c); g_last_crash_qpc = c.QuadPart; }

void heartbeat() {
    LARGE_INTEGER c; QueryPerformanceCounter(&c);
    g_hb_qpc = c.QuadPart;
    if (g_main_tid == 0) g_main_tid = GetCurrentThreadId();
}

// Resolve a RIP to its owning module's basename + base (for IDA mapping).
static const char* module_of(uintptr_t rip, uintptr_t* out_base) {
    static char buf[64];
    HMODULE hmod = nullptr;
    if (GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                           GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                           (LPCSTR)rip, &hmod) && hmod) {
        char path[MAX_PATH];
        if (GetModuleFileNameA(hmod, path, MAX_PATH)) {
            const char* b = strrchr(path, '\\');
            b = b ? b + 1 : path;
            snprintf(buf, sizeof(buf), "%s", b);
            if (out_base) *out_base = (uintptr_t)hmod;
            return buf;
        }
    }
    if (out_base) *out_base = 0;
    return "?";
}

// Sample every other thread's RIP. Two PASSES: pass 1 suspends each thread only long
// enough to copy its context, then RESUMES it immediately (storing the snapshot); pass 2
// logs after all threads are running again. This is mandatory — logging (CRT fprintf) while
// any thread is suspended deadlocks the watchdog if that thread holds the stdio/CRT lock
// (this once produced zero samples). No thread is ever held across a write.
struct ThreadSnap { DWORD tid; uintptr_t rip, rsp, rbp, rbx, rcx, rdx, r8, r9, r12; bool ctx_ok; };

// PRE-OPENED THREAD-HANDLE TABLE (the sampler-deadlock fix). The old sampler called CreateToolhelp32Snapshot + OpenThread
// AT HANG TIME — both ALLOCATE from the process heap, so when the hang holds the heap/loader lock the watchdog
// self-deadlocks inside the snapshot and writes nothing (exactly what an earlier run produced: HANG-DETECTED then silence).
// Instead we enumerate + OpenThread on HEALTHY watchdog ticks (safe, the process is running) and cache the handles;
// at hang time sample_all_threads touches only the cached handles (SuspendThread/GetThreadContext/ResumeThread) —
// Zero allocation, zero toolhelp, cannot block on a game lock. refresh and sample both run on the watchdog thread
// (never concurrently), so the table needs no locking.
static HANDLE g_th[256];
static DWORD  g_tt[256];
static volatile LONG g_tn = 0;

static void refresh_thread_table() {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) return;
    HANDLE nh[256]; DWORD nt[256]; int n = 0;
    DWORD pid = GetCurrentProcessId();
    THREADENTRY32 te; te.dwSize = sizeof(te);
    for (BOOL r = Thread32First(snap, &te); r && n < 256; r = Thread32Next(snap, &te)) {
        if (te.dwSize < FIELD_OFFSET(THREADENTRY32, th32OwnerProcessID) + sizeof(DWORD)) continue;
        if (te.th32OwnerProcessID != pid) continue;
        DWORD tid = te.th32ThreadID;
        if (tid == g_self_tid) continue;   // never suspend the watchdog itself
        HANDLE h = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT, FALSE, tid);
        if (!h) continue;
        nh[n] = h; nt[n] = tid; n++;
    }
    CloseHandle(snap);
    // Publish: close the prior set, swap in the new one. Same thread does sampling, so no reader can observe a
    // half-built table (g_tn is only read by sample_all_threads, also on this thread).
    LONG old = g_tn; g_tn = 0;
    for (LONG i = 0; i < old; i++) if (g_th[i]) { CloseHandle(g_th[i]); g_th[i] = nullptr; }
    for (int i = 0; i < n; i++) { g_th[i] = nh[i]; g_tt[i] = nt[i]; }
    g_tn = n;
}

static bool rd_ok(uintptr_t p, size_t n);   // fwd (defined below)
static void sample_all_threads(const char* tag) {
    static ThreadSnap snaps[256];
    int n = 0;
    LONG tn = g_tn;
    // PASS 1 — collect (suspend → getcontext → resume each, one at a time, NO logging, NO allocation).
    // Uses only the pre-opened cached handles. A handle for a since-dead thread fails SuspendThread => skipped.
    for (LONG idx = 0; idx < tn && n < 256; idx++) {
        HANDLE h = g_th[idx];
        if (!h) continue;
        ThreadSnap s; ZeroMemory(&s, sizeof(s)); s.tid = g_tt[idx];
        if (SuspendThread(h) != (DWORD)-1) {
            CONTEXT ctx; ZeroMemory(&ctx, sizeof(ctx));
            ctx.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;
            if (GetThreadContext(h, &ctx)) {
                s.ctx_ok = true; s.rip = ctx.Rip; s.rsp = ctx.Rsp; s.rbp = ctx.Rbp;
                s.rbx = ctx.Rbx; s.rcx = ctx.Rcx; s.rdx = ctx.Rdx; s.r8 = ctx.R8; s.r9 = ctx.R9; s.r12 = ctx.R12;
            }
            ResumeThread(h);   // RESUME before we ever log
        }
        snaps[n++] = s;
    }
    // PASS 2 — all threads running again; safe to take the CRT/stdio lock to log.
    for (int i = 0; i < n; i++) {
        ThreadSnap& s = snaps[i];
        if (!s.ctx_ok) { rblog::write("HANG-SAMPLE[%s]: tid=%lu ctx=fail", tag, s.tid); continue; }
        uintptr_t modbase = 0;
        const char* mod = module_of(s.rip, &modbase);
        uintptr_t ida = (modbase != 0 && modbase == addr::g_base)
                      ? (s.rip - addr::g_base + 0x140000000ULL) : 0;
        rblog::write("HANG-SAMPLE[%s]: tid=%lu%s rip=0x%llX ida=0x%llX mod=%s "
                     "rsp=0x%llX rbp=0x%llX rbx=0x%llX rcx=0x%llX rdx=0x%llX r8=0x%llX r9=0x%llX r12=0x%llX",
            tag, s.tid, (s.tid == g_main_tid ? "(MAIN)" : ""),
            (unsigned long long)s.rip, (unsigned long long)ida, mod,
            (unsigned long long)s.rsp, (unsigned long long)s.rbp, (unsigned long long)s.rbx,
            (unsigned long long)s.rcx, (unsigned long long)s.rdx,
            (unsigned long long)s.r8, (unsigned long long)s.r9, (unsigned long long)s.r12);
    }
    rblog::write("HANG-SAMPLE[%s]: sampled=%d threads (main=tid %lu)", tag, n, g_main_tid);

    // WAIT-XRAY: decode what MAIN is blocked on (the recurring NtWaitForMultipleObjects(3) INFINITE hang). rcx=Count,
    // rdx=Handles[] on main's stack. Read the handles, query each (Event/Mutex/Sem + signaled), and scan the worker/
    // sound singletons to NAME the barrier + offset. The runoff theory: this is a count<->kernel-event coherence gap (in-arena Count reverted, events not).
    for (int i = 0; i < n; i++) {
        ThreadSnap& s = snaps[i];
        if (s.tid != g_main_tid || !s.ctx_ok) continue;
        // GATE: WAIT-XRAY is only valid when main is genuinely in NtWaitForMultipleObjects (rcx=Count, rdx=Handles[]).
        // For WaitOnAddress (NtWaitForAlertByThreadId = CS/SRWLock contention) those regs are not count/handles, so
        // decoding stack garbage as handles AV'd the watchdog (rip DINPUT8+0x12210, deref 0xC000A) before the lock
        // resolver could run. Skip cleanly; HANG-ALLOCCS/HANG-MAINLOCK handle the lock-contention case.
        {
            HMODULE _nt = GetModuleHandleA("ntdll.dll");
            uintptr_t _fm = _nt ? (uintptr_t)GetProcAddress(_nt, "NtWaitForMultipleObjects") : 0;
            if (!(_fm && s.rip >= _fm && s.rip < _fm + 0x40)) {
                rblog::write("WAIT-XRAY: main not in NtWaitForMultipleObjects (rip=0x%llX) => WaitOnAddress/lock contention; see HANG-ALLOCCS/HANG-MAINLOCK", (unsigned long long)s.rip);
                break;
            }
        }
        uint64_t cnt = s.rcx, harr = s.rdx;
        if (cnt < 1 || cnt > 64) { rblog::write("WAIT-XRAY: main Count=%llu out of range (not a multi-wait)", (unsigned long long)cnt); break; }
        typedef LONG (NTAPI *NtQO_t)(HANDLE,int,void*,ULONG,ULONG*);
        typedef LONG (NTAPI *NtQE_t)(HANDLE,int,void*,ULONG,ULONG*);
        static NtQO_t NtQO=nullptr; static NtQE_t NtQE=nullptr;
        HMODULE nt=GetModuleHandleA("ntdll.dll");
        if(!NtQO) NtQO=(NtQO_t)GetProcAddress(nt,"NtQueryObject");
        if(!NtQE) NtQE=(NtQE_t)GetProcAddress(nt,"NtQueryEvent");
        const uint64_t SINGLETONS[3] = { 0x140E177E8ull/*sMain*/, 0x140E175A8ull/*arc_mgr*/, 0x140E18520ull/*sSound*/ };
        const char* SNAMES[3] = { "sMain", "arc_mgr", "sSound" };
        auto committed=[](uint64_t p,size_t len)->bool{ if(p<0x10000) return false; MEMORY_BASIC_INFORMATION m;
            if(!VirtualQuery((void*)p,&m,sizeof(m))||(m.State&MEM_COMMIT)==0) return false;
            return (m.Protect&(PAGE_READONLY|PAGE_READWRITE|PAGE_EXECUTE_READ|PAGE_EXECUTE_READWRITE|PAGE_WRITECOPY))!=0; };
        if(!committed(harr, cnt*8)) { rblog::write("WAIT-XRAY: main Handles[]=0x%llX not readable", (unsigned long long)harr); break; }
        for (uint64_t k = 0; k < cnt; k++) {
            HANDLE hh = *(HANDLE*)(harr + k*8);
            char tn[64]={0}; ULONG rl=0; int sig=-1;
            if(NtQO){ struct { wchar_t* b; USHORT l,m; } un; char buf[256]; if(NtQO(hh,2/*ObjectTypeInformation*/,buf,sizeof(buf),&rl)>=0){
                wchar_t* nm=*(wchar_t**)buf; if(nm){ int j=0; for(;j<63&&nm[j];j++) tn[j]=(char)nm[j]; tn[j]=0; } } }
            if(NtQE){ struct{int t;LONG st;}eb; ULONG r2=0; if(NtQE(hh,0,&eb,sizeof(eb),&r2)>=0) sig=eb.st?1:0; }
            // identify owner: scan each singleton's body for this handle value
            const char* owner="?"; uint64_t off=0;
            for(int si=0; si<3 && owner[0]=='?'; si++){ uint64_t base=*(uint64_t*)addr::resolve(SINGLETONS[si]);
                if(base<0x10000||!committed(base,8)) continue;
                for(uint64_t o=0;o<0x40000;o+=8){ if(!committed(base+o,8))break; if(*(uint64_t*)(base+o)==(uint64_t)hh){ owner=SNAMES[si]; off=o; break; } } }
            rblog::write("WAIT-XRAY: main handle[%llu]=0x%llX type=%s signaled=%d owner=%s+0x%llX",
                (unsigned long long)k,(unsigned long long)(uintptr_t)hh, tn[0]?tn:"?", sig, owner, (unsigned long long)off);
        }
        break;
    }
    // PASS 3 — half A: any thread RIP-pinned in the Unit-allocator first-fit walk FUN_1404ca650 is the
    // deadlock holdout. Walk its free list READ-ONLY (head-holder = sub_mgr rdx + 0x58) to prove the
    // cycle (Floyd) + each node's page-source. This converts "cyclic" from INFERRED to proven.
    for (int i = 0; i < n; i++) {
        ThreadSnap& s = snaps[i];
        if (!s.ctx_ok) continue;
        uintptr_t mb = 0; module_of(s.rip, &mb);
        uintptr_t ida = (mb != 0 && mb == addr::g_base) ? (s.rip - addr::g_base + 0x140000000ULL) : 0;
        if (ida >= 0x1404CA650 && ida < 0x1404CA750) {
            char wtag[48]; snprintf(wtag, sizeof(wtag), "HANG-tid%lu", s.tid);
            rblog::write("FREELIST-WALKER: tid=%lu pinned in FUN_1404ca650 (ida=0x%llX) rbx=0x%llX rdx=0x%llX rcx=0x%llX — walking rdx+0x58",
                s.tid, (unsigned long long)ida, (unsigned long long)s.rbx,
                (unsigned long long)s.rdx, (unsigned long long)s.rcx);
            freelist_diag::walk(s.rdx + 0x58, wtag);
        }
    }

    // PASS 4 — LOCK-COHERENCE resolver (the NtWaitForAlertByThreadId hang = CS/SRWLock contention, not a multi-wait).
    // A lock is a coherence group {in-arena CS bytes, live OS wait-state, owner thread}; a rollback can leave it
    // GHOST-OWNED (owner parked while holding it) or 0x01-CORRUPT (slab reused/reverted). Main then waits forever.
    {
        rblog::write("HANG-RESOLVER: lock-coherence pass (begin)");
        ThreadSnap* ms = nullptr;
        for (int i = 0; i < n; i++) if (snaps[i].tid == g_main_tid && snaps[i].ctx_ok) { ms = &snaps[i]; break; }
        HMODULE nt = GetModuleHandleA("ntdll.dll");
        uintptr_t f_addr  = nt ? (uintptr_t)GetProcAddress(nt, "NtWaitForAlertByThreadId") : 0;
        uintptr_t f_multi = nt ? (uintptr_t)GetProcAddress(nt, "NtWaitForMultipleObjects") : 0;
        if (ms) {
            const char* flavor = "other";
            if (f_addr  && ms->rip >= f_addr  && ms->rip < f_addr  + 0x40) flavor = "WaitOnAddress (CRITICAL_SECTION/SRWLock contention)";
            else if (f_multi && ms->rip >= f_multi && ms->rip < f_multi + 0x40) flavor = "WaitForMultipleObjects (worker dispatch)";
            rblog::write("HANG-WAITKIND: main rip=0x%llX => %s", (unsigned long long)ms->rip, flavor);
        }
        // (a) allocator CSes — the atomic-save suspects. control + each CS_RANGES offset.
        static const uintptr_t ACS[] = {0x060,0x158,0x200,0x2A8,0x350,0x3F8,0x4A0,0x548,0x5F0,0x620};
        uintptr_t cnt_a=addr::resolve(0x140D760E0), arr_a=addr::resolve(0x140D760F0), avt=addr::resolve(0x140B08620);
        int held=0, ghost=0;
        if (rd_ok(cnt_a,4) && rd_ok(arr_a,8)) {
            uint32_t na=*(uint32_t*)cnt_a; if(na>64)na=64;
            for (uint32_t ai=0; ai<na; ai++) {
                uintptr_t ctrl = rd_ok(arr_a+ai*8,8) ? *(uintptr_t*)(arr_a+ai*8) : 0;
                if (!ctrl || !rd_ok(ctrl,8) || *(uintptr_t*)ctrl != avt) continue;
                char anm[32] = {0};   // BOUNDED copy — never pass raw memory to %s (a corrupt name runs off-page => watchdog AV)
                for (int z=0; z<31 && rd_ok(ctrl+0x21+z,1); z++) { anm[z]=*(char*)(ctrl+0x21+z); if(!anm[z]) break; }
                for (int c=0;c<10;c++) {
                    uintptr_t cs = ctrl + ACS[c];
                    if (!rd_ok(cs+0x18,8)) continue;
                    int32_t  lock  = *(int32_t*)(cs+0x08);
                    uintptr_t owner= *(uintptr_t*)(cs+0x10);
                    if (owner == 0) continue;                 // free
                    held++;
                    bool corrupt = (owner==0x0101010101010101ull) || ((uint32_t)lock==0x01010101u);
                    uintptr_t orip=0; bool oparked=false;
                    for (int j=0;j<n;j++) if((uintptr_t)snaps[j].tid==owner && snaps[j].ctx_ok){ orip=snaps[j].rip; oparked=true; break; }
                    if (oparked) ghost++;
                    rblog::write("HANG-ALLOCCS[%s] cs=0x%llX off=0x%llX LockCount=%d OwningThread=%lu%s ownerRIP=0x%llX %s",
                        anm, (unsigned long long)cs, (unsigned long long)ACS[c], lock, (unsigned long)owner,
                        corrupt?" [0x01-CORRUPT]":"", (unsigned long long)orip,
                        oparked ? "(owner PARKED while holding => GHOST/deadlock holder)" : "(owner not in sample)");
                }
            }
        }
        rblog::write("HANG-ALLOCCS: %d held allocator CS(es), %d ghost-owned (parked-while-holding)", held, ghost);
        // (b) main-stack resolve — the held CS main is actually stranded on (owner must be a known tid => real CS).
        if (ms) {
            int found=0;
            for (uintptr_t p=ms->rsp; p < ms->rsp + 0x1200 && found < 6; p+=8) {
                if (!rd_ok(p,8)) break;
                uintptr_t v = *(uintptr_t*)p;
                if (v < 0x10000 || !rd_ok(v+0x18,8)) continue;
                uintptr_t owner = *(uintptr_t*)(v+0x10);
                if (owner == 0) continue;
                bool owner_known=false; for(int j=0;j<n;j++) if((uintptr_t)snaps[j].tid==owner){ owner_known=true; break; }
                if (!owner_known) continue;                   // a real CS owner is a live tid
                int32_t lock = *(int32_t*)(v+0x08);
                uintptr_t orip=0; for(int j=0;j<n;j++) if((uintptr_t)snaps[j].tid==owner&&snaps[j].ctx_ok){ orip=snaps[j].rip; break; }
                rblog::write("HANG-MAINLOCK: main_stack@0x%llX -> CS=0x%llX LockCount=%d OwningThread=%lu ownerRIP=0x%llX (candidate: the lock main is stranded on)",
                    (unsigned long long)p,(unsigned long long)v,lock,(unsigned long)owner,(unsigned long long)orip);
                found++;
            }
            if (!found) rblog::write("HANG-MAINLOCK: no owned-CS pointer on main stack (likely SRWLock/keyed-event, not a classic CRITICAL_SECTION)");
        }
    }
}

// On a hang, dump the lock state of the key CRITICAL_SECTIONs (the render family + sUnit/sRender singletons).
// CRITICAL_SECTION: +0x08 LockCount(-1=free), +0x0C Recursion, +0x10 OwningThread(tid).
// A CS with OwningThread != 0 while every thread is parked = a stuck lock holding the deadlock.
// All free => not a CS deadlock. Pure read-only (VirtualQuery-guarded).
static bool rd_ok(uintptr_t p, size_t n) {
    if (p < 0x10000) return false;
    MEMORY_BASIC_INFORMATION mbi;
    if (!VirtualQuery((void*)p, &mbi, sizeof(mbi))) return false;
    if (mbi.State != MEM_COMMIT || (mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD))) return false;
    return (p + n) <= ((uintptr_t)mbi.BaseAddress + mbi.RegionSize);
}
static void dump_key_cs() {
    struct CSE { const char* name; uintptr_t ida; uintptr_t off; };
    static const CSE list[] = {
        {"srender", 0x140E179A8, 0x08}, {"sunit", 0x140E17698, 0x08},
        {"scene_mgr", 0x140E18250, 0x08}, {"scene_mgr+0x23970", 0x140E18250, 0x23970},
        {"arc_mgr", 0x140E175A8, 0x08}, {"arc_mgr+0x2A158", 0x140E175A8, 0x2A158},
        {"batch_mgr", 0x140E193E8, 0x08}, {"dev_mgr", 0x140E194A8, 0x08},
    };
    for (const CSE& c : list) {
        uintptr_t pp = addr::resolve(c.ida);
        if (!rd_ok(pp, 8)) continue;
        uintptr_t base = *(uintptr_t*)pp;            // singleton object ptr
        if (!rd_ok(base + c.off + 0x18, 8)) continue;
        uintptr_t cs = base + c.off;
        int32_t lock = *(int32_t*)(cs + 0x08);
        uintptr_t owner = *(uintptr_t*)(cs + 0x10);
        bool held = (owner != 0);                    // OwningThread set => held
        bool owner_live = false;
        for (LONG i = 0; i < g_tn; i++) if ((uintptr_t)g_tt[i] == owner) { owner_live = true; break; }
        rblog::write("HANG-CS[%s] cs=0x%llX LockCount=%d OwningThread=%lu %s%s", c.name,
            (unsigned long long)cs, lock, (unsigned long)owner,
            held ? "HELD" : "free", held ? (owner_live ? " (owner is a live thread)" : " (owner NOT in thread table = GONE/stuck)") : "");
    }
}

// ROBUST held-lock verdict — read the allocator CSes directly (no thread suspend, no stack walk), so it runs and
// flushes before the heavier sample_all_threads (which can itself hang/crash on a corrupt-state hang). Allocator CSes
// (control + each CS_RANGES offset; the +0x158.. ones are mgr_k+0x80 splice locks) are the atomic-save suspects.
// CRITICAL_SECTION: +0x08 LockCount, +0x0C RecursionCount, +0x10 OwningThread(tid). owner!=0 => held; at hang, a held
// allocator CS = the lock main is stranded on, and its owner tid = who left it locked (rollback ghost / mid-splice).
static void dump_held_locks() {
    static const uintptr_t ACS[] = {0x060,0x158,0x200,0x2A8,0x350,0x3F8,0x4A0,0x548,0x5F0,0x620};
    uintptr_t cnt_a=addr::resolve(0x140D760E0), arr_a=addr::resolve(0x140D760F0), avt=addr::resolve(0x140B08620);
    if (!rd_ok(cnt_a,4) || !rd_ok(arr_a,8)) { rblog::write("HANG-LOCKS: allocator registry unreadable"); rblog::flush(); return; }
    uint32_t na=*(uint32_t*)cnt_a; if(na>64)na=64;
    int held=0;
    for (uint32_t ai=0; ai<na; ai++) {
        uintptr_t ctrl = rd_ok(arr_a+ai*8,8) ? *(uintptr_t*)(arr_a+ai*8) : 0;
        if (!ctrl || !rd_ok(ctrl,8) || *(uintptr_t*)ctrl != avt) continue;
        char anm[32]={0}; for(int z=0;z<31 && rd_ok(ctrl+0x21+z,1);z++){ anm[z]=*(char*)(ctrl+0x21+z); if(!anm[z])break; }
        for (int c=0;c<10;c++) {
            uintptr_t cs = ctrl + ACS[c];
            if (!rd_ok(cs+0x18,8)) continue;
            int32_t  lock = *(int32_t*)(cs+0x08), rec = *(int32_t*)(cs+0x0C);
            uintptr_t owner = *(uintptr_t*)(cs+0x10);
            if (owner == 0) continue;                       // not held
            held++;
            bool corrupt = (owner==0x0101010101010101ull) || ((uint32_t)lock==0x01010101u);
            rblog::write("HANG-LOCKS[%s] cs=0x%llX off=0x%llX LockCount=%d Recursion=%d OwningThread=%lu%s",
                anm, (unsigned long long)cs, (unsigned long long)ACS[c], lock, rec, (unsigned long)owner,
                corrupt ? " [0x01-CORRUPT]" : "");
        }
    }
    rblog::write("HANG-LOCKS: %d held allocator CS(es) (owner!=0). A held one whose owner is a parked worker = the deadlock root.", held);
    rblog::flush();
}

static DWORD WINAPI watchdog_thread(LPVOID) {
    g_self_tid = GetCurrentThreadId();
    const double STALL_MS = 2000.0;     // main not advancing this long = a hang
    int suppress_ticks = 0;             // after a capture, wait before re-capturing
    int refresh_ctr = 0;
    for (;;) {
        Sleep(250);
        if (suppress_ticks > 0) { suppress_ticks--; continue; }
        LONG64 hb = g_hb_qpc;
        LARGE_INTEGER now; QueryPerformanceCounter(&now);
        double elapsed_ms = hb ? (double)(now.QuadPart - hb) * 1000.0 / (double)g_qpc_freq : 0.0;
        bool hung = (hb != 0 && elapsed_ms > STALL_MS);
        if (!hung) {
            // HEALTHY tick (incl. pre-heartbeat startup): refresh the pre-opened handle table ~every 1s. This is
            // the only place toolhelp/OpenThread (which allocate) run — safe because the process is running. At
            // hang time the capture uses these cached handles with zero allocation, so it can't self-deadlock on a
            // lock the hang holds (the old sampler wrote nothing for exactly that reason).
            if ((refresh_ctr++ & 3) == 0) refresh_thread_table();
            continue;
        }
        rblog::suppress(false);         // a hang may strike inside a freeze/thaw-suppressed window — force the capture through
        rblog::write("HANG-DETECTED: main thread (tid %lu) no heartbeat for %.0f ms — sampling %ld pre-opened threads (alloc-free)", g_main_tid, elapsed_ms, (long)g_tn);
        // CRASH-GAP CLASSIFICATION: if a crash was logged in the last 10s, this hang is crash-aftermath
        // (the faulting thread died holding a lock / stopped heartbeating) — not the independent kernel-sync hang.
        { LONG64 lc = g_last_crash_qpc;
          if (lc != 0 && (now.QuadPart - lc) * 1000.0 / (double)g_qpc_freq < 10000.0)
              rblog::write("HANG-CLASS: CRASH PRECEDED HANG BY %.0f ms => crash-aftermath, NOT an independent hang (fix the crash)",
                           (double)(now.QuadPart - lc) * 1000.0 / (double)g_qpc_freq);
          else
              rblog::write("HANG-CLASS: no crash in the last 10s => POTENTIAL INDEPENDENT HANG (the kernel-sync case — investigate the sample below)"); }
        dump_held_locks();              // ROBUST first: held allocator CSes (flushed) before the fragile sampler
        dump_key_cs();                  // ROBUST first: singleton CSes too (was after sample => lost when sample hung)
        rblog::flush();
        sample_all_threads("HANG");     // thread sample + PASS-4 owner-RIP enrichment (may hang/crash on corrupt state; verdict already captured above)
        rblog::flush();
        suppress_ticks = 16;            // ~4s before another capture (one dump per hang)
    }
}

void init() {
    LARGE_INTEGER f; QueryPerformanceFrequency(&f);
    g_qpc_freq = f.QuadPart ? f.QuadPart : 1;
    CreateThread(NULL, 0, watchdog_thread, NULL, 0, NULL);
    rblog::write("HANG-DETECTOR: watchdog spawned (stall threshold %.0f ms, read-only)", 2000.0);
}

} // namespace hang_detector
