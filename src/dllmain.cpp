// dllmain.cpp — DLL entry, dinput8 proxy, init sequence.
//
// DLL_PROCESS_ATTACH:
// 1. Init logging
// 2. Load real dinput8.dll (proxy)
// 3. arena::early_init() — must happen before game code runs (IAT hooks VA/VF/Heap*)
// 4. Spawn init thread (deferred hook install after game unpacks)
//
// Init thread (after 5s):
// 1. addr::init() — resolve ASLR base
// 2. arena::activate_heap_redirect() — HeapAlloc starts going to arena
// 3. suspend/handle_preserve/dead_vtable_unlink/input init
// 4. resim::init() — MH_Initialize + hook MAIN_PROC + INPUT_DISPATCH + MH_EnableHook(all)

#include "addr.h"
#include "log.h"
#include "arena.h"
#include "quarantine.h"
#include "hang_detector.h"
#include "rtv_probe.h"
#include "rdspine.h"
#include "idspine.h"
#include "rdspine.h"
#include "input.h"
#include "suspend.h"
#include "handle_preserve.h"
#include "dead_vtable_unlink.h"
#include "resim.h"
#include "monitor_shm.h"
#include "role.h"
#include "dinput_probe.h"
#include "single_instance.h"
#include <MinHook.h>
#include <windows.h>
#include <objbase.h>  // IUnknown for LPUNKNOWN
#include <cstdio>

// ============================================================
// VEH — read-only crash diagnostics. Logs and dies. No skips.
// ============================================================

static bool is_readable(uintptr_t addr, size_t len) {
    MEMORY_BASIC_INFORMATION mbi;
    if (!VirtualQuery((void*)addr, &mbi, sizeof(mbi))) return false;
    if (mbi.State != MEM_COMMIT) return false;
    DWORD prot = mbi.Protect & 0xFF;
    if (!(prot == PAGE_READONLY || prot == PAGE_READWRITE ||
          prot == PAGE_EXECUTE_READ || prot == PAGE_EXECUTE_READWRITE)) return false;
    // CROSS-PAGE: a `len` read near a page end must verify the next page too, else a probe straddling into an
    // unmapped page AVs INSIDE the VEH. Covers probe_field/PROBE-A/STALE-REF-FORENSIC/ANIM at once.
    return ((addr & 0xFFF) + len <= 0x1000) || is_readable((addr + 0x1000) & ~0xFFFULL, 1);
}

// PROBE-FIELD: peek a specific field at its snapshot frame vs live — was the
// bad value already in the SAVE (fix-at-save) or written post-load (fix-at-restore / slab-reuse)? Read-only.
static void probe_field(const char* tag, uintptr_t obj, int foff) {
    if (obj <= 0x10000 || !is_readable(obj + foff, 16)) {
        rblog::write("PROBE-FIELD %s: obj=0x%llX+0x%X UNREADABLE", tag, (unsigned long long)obj, foff);
        return;
    }
    int srcf = arena::last_source_frame(obj);
    bool orph = arena::was_orphaned_last_load(obj);
    const uint64_t* live = (const uint64_t*)(obj + foff);
    uint64_t snap[2] = {};
    int s = (arena::is_arena_addr(obj) && srcf >= 0) ? arena::peek_saved(srcf, obj + foff, snap, 16) : 0;
    rblog::write("PROBE-FIELD %s: obj=0x%llX +0x%X in_arena=%d srcframe=%d orphaned=%d | snap(s=%d) %016llX %016llX | live %016llX %016llX %s",
        tag, (unsigned long long)obj, foff, arena::is_arena_addr(obj) ? 1 : 0, srcf, orph ? 1 : 0, s,
        snap[0], snap[1], live[0], live[1],
        (s > 0 && (snap[0] == live[0] && snap[1] == live[1])) ? "[snap==live]"
        : (s > 0) ? "[snap!=live: post-load writer or reuse]" : "");
}

static LONG WINAPI crash_logger(EXCEPTION_POINTERS* ep) {
    if (ep->ExceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION ||
        ep->ExceptionRecord->ExceptionCode == EXCEPTION_ILLEGAL_INSTRUCTION ||
        ep->ExceptionRecord->ExceptionCode == EXCEPTION_INT_DIVIDE_BY_ZERO ||
        ep->ExceptionRecord->ExceptionCode == EXCEPTION_STACK_OVERFLOW ||
        ep->ExceptionRecord->ExceptionCode == 0xC0000409 ||   // STATUS_STACK_BUFFER_OVERRUN = RaiseFailFastException / __fastfail (heap-corruption, /GS) — terminates without a crash record
        ep->ExceptionRecord->ExceptionCode == 0xC0000374) {   // STATUS_HEAP_CORRUPTION

        rblog::suppress(false);   // force crash logs through even inside the rollback restore's suppress window (resim.cpp 562-773)
        hang_detector::note_crash();   // CRASH-GAP: stamp the crash time so a following HANG-DETECTED is classed crash-aftermath

        // VEH reentrancy guard: if a fault occurs INSIDE our own logging, bail to the next
        // handler instead of recursing/cascading. Cleared at the end of this pass so a later distinct crash logs.
        static volatile LONG g_in_veh = 0;
        if (InterlockedCompareExchange(&g_in_veh, 1, 0) != 0) return EXCEPTION_CONTINUE_SEARCH;

        uintptr_t rip = (uintptr_t)ep->ContextRecord->Rip;
        uintptr_t base = (uintptr_t)GetModuleHandleA("umvc3.exe");
        uintptr_t ida = rip - base + 0x140000000ULL;

        rblog::write("CRASH: code=0x%08X rip=0x%llX (IDA 0x%llX) tid=%u",
                    ep->ExceptionRecord->ExceptionCode,
                    (unsigned long long)rip,
                    (unsigned long long)ida,
                    GetCurrentThreadId());

        // Identify the owning module of the crash rip — driver/system-DLL crashes have rip
        // outside umvc3.exe (e.g. d3d9.dll / the GPU UMD); name it so we know where it died.
        {
            HMODULE hm = nullptr;
            if (GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                                   GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                                   (LPCSTR)rip, &hm) && hm) {
                char mp[MAX_PATH];
                if (GetModuleFileNameA(hm, mp, MAX_PATH)) {
                    const char* mb = mp; for (const char* s = mp; *s; ++s) if (*s == '\\') mb = s + 1;
                    rblog::write("CRASH: module=%s+0x%llX (modbase 0x%llX)",
                                mb, (unsigned long long)(rip - (uintptr_t)hm),
                                (unsigned long long)(uintptr_t)hm);
                }
            } else {
                rblog::write("CRASH: module=UNKNOWN (rip in no loaded module)");
            }
        }

        if (ep->ExceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION &&
            ep->ExceptionRecord->NumberParameters >= 2) {
            rblog::write("CRASH: %s address 0x%llX",
                        ep->ExceptionRecord->ExceptionInformation[0] ? "WRITE" : "READ",
                        (unsigned long long)ep->ExceptionRecord->ExceptionInformation[1]);
        }

        rblog::write("CRASH: rax=0x%llX rbx=0x%llX rcx=0x%llX rdx=0x%llX",
                    ep->ContextRecord->Rax, ep->ContextRecord->Rbx,
                    ep->ContextRecord->Rcx, ep->ContextRecord->Rdx);
        rblog::write("CRASH: rsi=0x%llX rdi=0x%llX rsp=0x%llX rbp=0x%llX",
                    ep->ContextRecord->Rsi, ep->ContextRecord->Rdi,
                    ep->ContextRecord->Rsp, ep->ContextRecord->Rbp);
        rblog::write("CRASH: r8=0x%llX r9=0x%llX r10=0x%llX r11=0x%llX",
                    ep->ContextRecord->R8, ep->ContextRecord->R9,
                    ep->ContextRecord->R10, ep->ContextRecord->R11);

        // === PROBE-P0: discriminator-freshness window + arena base ===
        // g_last_source is frozen at the last arena::load(); g_dirty_bits is re-OR'd by every post-load
        // save(). So the srcframe/orphaned values below are only TRUSTWORTHY within a few frames of the
        // rollback — read them with this verdict. arena=[base..end] settles whether a sub-0x30000000 object
        // (e.g. Crash A's 0x841E0A0) is even in the arena under this run's (possibly OS-placed) base.
        {
            int  fsr     = resim::frames_since_rollback();   // Real counter (0 at resim-complete, +1/frame) — not current_frame-target (depth-biased)
            bool rb_ever = resim::rollback_happened();
            bool fresh   = resim::resim_active() || (rb_ever && fsr <= 3);
            rblog::write("PROBE-P0: arena=[0x%llX..0x%llX] frame=%d rb_tgt=%d frames_since_rb=%d resim=%d DISCRIMINATOR=%s",
                (unsigned long long)arena::base(), (unsigned long long)arena::end(),
                resim::current_frame(), resim::last_rollback_target(), fsr, resim::resim_active() ? 1 : 0,
                (!rb_ever) ? "N/A (no rollback this session => crash is rollback-UNRELATED)"
                : fresh    ? "FRESH (srcframe/orphaned below trustworthy)"
                           : "STALE (srcframe/orphaned below UNRELIABLE at this frame distance)");
        }

        // FAULT-FORENSIC (fire-once, read-only): identify (1) what the faulted address is (VirtualQuery:
        // state/type/alloc-base — heap? image? reserved gap? our arena?), (2) WHO the faulting thread is
        // (Win32 start address resolved to a module => game fn / d3d9 / XAudio / ours), (3) where the faulting
        // code + key registers live (module names). Built for the freeze-time msvcrt!memcpy crash (READ at a
        // 0x4CCxF000 page boundary, seen on 2 of 4 long runs) — names the producer/consumer pair.
        // REENTRANCY FIX: the CRASH-STACK walker's IsBadReadPtr probes AV internally; the
        // VEH sees those nested (handled) AVs and the fire-once captured the PROBE (addr=0x580AA000 MEM_FREE =
        // the stack top) instead of the real fault. Skip probe AVs: rip inside kernelbase/kernel32 = not ours.
        {
            static volatile bool g_ff_done = false;
            uintptr_t kb  = (uintptr_t)GetModuleHandleA("kernelbase.dll");
            uintptr_t k32 = (uintptr_t)GetModuleHandleA("kernel32.dll");
            bool probe_av = (kb  && rip >= kb  && rip < kb  + 0x400000) ||
                            (k32 && rip >= k32 && rip < k32 + 0x200000);
            if (!g_ff_done && !probe_av && ep->ExceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION &&
                ep->ExceptionRecord->NumberParameters >= 2) {
                g_ff_done = true;
                uintptr_t fa = (uintptr_t)ep->ExceptionRecord->ExceptionInformation[1];
                MEMORY_BASIC_INFORMATION mbi = {};
                if (fa > 0x10000 && VirtualQuery((void*)fa, &mbi, sizeof(mbi))) {
                    char mod[MAX_PATH] = "";
                    HMODULE hm = nullptr;
                    if (mbi.Type == MEM_IMAGE &&
                        GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                                           GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, (LPCSTR)fa, &hm) && hm)
                        GetModuleFileNameA(hm, mod, MAX_PATH);
                    rblog::write("FAULT-FORENSIC: addr=0x%llX state=0x%lX protect=0x%lX type=0x%lX allocbase=0x%llX regionsz=0x%llX in_arena=%d %s",
                                 (unsigned long long)fa, (unsigned long)mbi.State, (unsigned long)mbi.Protect,
                                 (unsigned long)mbi.Type, (unsigned long long)(uintptr_t)mbi.AllocationBase,
                                 (unsigned long long)mbi.RegionSize, (int)arena::is_arena_addr(fa), mod);
                }
                // The OBJECT being walked (rcx is the this/base pointer in member-walk faults): its region
                // identity is the stale-reference carrier question — in-arena (reverted) vs out-of-arena (untracked alloc).
                uintptr_t obj = (uintptr_t)ep->ContextRecord->Rcx;
                MEMORY_BASIC_INFORMATION omi = {};
                if (obj > 0x10000 && VirtualQuery((void*)obj, &omi, sizeof(omi))) {
                    int srcf = arena::last_source_frame(obj);
                    rblog::write("FAULT-FORENSIC: rcx-object=0x%llX state=0x%lX protect=0x%lX type=0x%lX allocbase=0x%llX in_arena=%d srcframe=%d",
                                 (unsigned long long)obj, (unsigned long)omi.State, (unsigned long)omi.Protect,
                                 (unsigned long)omi.Type, (unsigned long long)(uintptr_t)omi.AllocationBase,
                                 (int)arena::is_arena_addr(obj), srcf);
                    // PARTIAL-INIT DISCRIMINATOR: snapshot-vs-live header of the object. Snapshot already
                    // holding the bad value (e.g. vtable=0x64900000) => the SAVE captured a mid-lifecycle
                    // transient (engine-legit partial-init / engine-side transient-failure class). Snapshot holding a valid
                    // vtable => a post-restore writer corrupted it (a different class entirely).
                    if (arena::is_arena_addr(obj) && srcf >= 0 && is_readable(obj, 0x30)) {
                        uint64_t snap[6] = {};
                        int src = arena::peek_saved(srcf, obj, snap, 0x30);
                        const uint64_t* live = (const uint64_t*)obj;
                        rblog::write("FAULT-FORENSIC: snap(src=%d,frame=%d) %016llX %016llX %016llX %016llX %016llX %016llX",
                                     src, srcf, snap[0], snap[1], snap[2], snap[3], snap[4], snap[5]);
                        rblog::write("FAULT-FORENSIC: live              %016llX %016llX %016llX %016llX %016llX %016llX",
                                     live[0], live[1], live[2], live[3], live[4], live[5]);
                    }
                }
                // WHO-FREED-IT (UNIVERSAL liveness attribution): scan the GP registers; any that point at a
                // recently-freed in-arena block name the freeing caller = the carrier, for whatever crash fired.
                {
                    struct { const char* n; uintptr_t v; } regs[] = {
                        {"rax",(uintptr_t)ep->ContextRecord->Rax},{"rbx",(uintptr_t)ep->ContextRecord->Rbx},
                        {"rcx",(uintptr_t)ep->ContextRecord->Rcx},{"rdx",(uintptr_t)ep->ContextRecord->Rdx},
                        {"rsi",(uintptr_t)ep->ContextRecord->Rsi},{"rdi",(uintptr_t)ep->ContextRecord->Rdi},
                        {"r8",(uintptr_t)ep->ContextRecord->R8},{"r9",(uintptr_t)ep->ContextRecord->R9},
                    };
                    for (auto& r : regs) {
                        if (r.v <= 0x10000 || !arena::is_arena_addr(r.v)) continue;
                        uintptr_t block = r.v;
                        if ((r.v & 0xFFF) >= 8 && is_readable(r.v - 8, 8)) {
                            int64_t a = *(int64_t*)(r.v - 8); if (a > 0 && a < 0x1000) block = r.v - (uintptr_t)a;
                        }
                        uintptr_t caller = 0, eff = 0; int ff = -1;
                        if (idspine::recent_free(r.v, &caller, &eff, &ff) ||
                            (block != r.v && idspine::recent_free(block, &caller, &eff, &ff)))
                            rblog::write("FAULT-FORENSIC: %s=0x%llX (block 0x%llX) was RECENTLY FREED @f=%d caller=0x%llX eff_rip=0x%llX "
                                "=> freed-but-referenced (the liveness root); the freeing caller names the carrier",
                                r.n, (unsigned long long)r.v, (unsigned long long)block, ff,
                                (unsigned long long)caller, (unsigned long long)eff);
                    }
                }
                // Faulting thread's origin: Win32 start address -> module
                typedef LONG (NTAPI *NtQIT_fn)(HANDLE, ULONG, PVOID, ULONG, PULONG);
                NtQIT_fn qit = (NtQIT_fn)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationThread");
                uintptr_t start = 0;
                if (qit) qit(GetCurrentThread(), 9 /*ThreadQuerySetWin32StartAddress*/, &start, sizeof(start), nullptr);
                char smod[MAX_PATH] = "<unknown>";
                HMODULE shm = nullptr;
                if (start && GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                                                GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, (LPCSTR)start, &shm) && shm)
                    GetModuleFileNameA(shm, smod, MAX_PATH);
                uintptr_t umvc3 = (uintptr_t)GetModuleHandleA("umvc3.exe");
                rblog::write("FAULT-FORENSIC: thread tid=%u start=0x%llX (%s+0x%llX)%s",
                             GetCurrentThreadId(), (unsigned long long)start, smod,
                             (unsigned long long)(shm ? start - (uintptr_t)shm : 0),
                             (umvc3 && start >= umvc3 && start < umvc3 + 0xA00000)
                                 ? "" : " [non-game thread]");
                // Key register owners (which DLL's code/data the regs point into)
                struct { const char* n; uintptr_t v; } RR[] = {
                    {"rax",(uintptr_t)ep->ContextRecord->Rax},{"rcx",(uintptr_t)ep->ContextRecord->Rcx},
                    {"rdx",(uintptr_t)ep->ContextRecord->Rdx},{"r10",(uintptr_t)ep->ContextRecord->R10},
                    {"r11",(uintptr_t)ep->ContextRecord->R11},
                };
                for (auto& r : RR) {
                    HMODULE rm = nullptr;
                    if (r.v > 0x10000 &&
                        GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                                           GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, (LPCSTR)r.v, &rm) && rm) {
                        char rmod[MAX_PATH];
                        GetModuleFileNameA(rm, rmod, MAX_PATH);
                        rblog::write("FAULT-FORENSIC: %s=0x%llX -> %s+0x%llX", r.n,
                                     (unsigned long long)r.v, rmod, (unsigned long long)(r.v - (uintptr_t)rm));
                    }
                }
            }
        }

        // CRASH-STACK (resim-fault origin): when the fault recurses inside ntdll/msvcrt to a stack overflow,
        // the original game-code instruction that triggered it is BURIED. Walk the faulting thread's stack
        // upward from rsp and log the umvc3.exe code return-addresses (rebased to IDA) — the resim call chain
        // into the recursing system function. Fires once per process (the recursion cascade would spam it).
        {
            static volatile bool g_crash_walked = false;
            if (!g_crash_walked) {
                g_crash_walked = true;
                uintptr_t sp = (uintptr_t)ep->ContextRecord->Rsp;
                uintptr_t code_lo = base + 0x1000, code_hi = base + 0xA00000;   // umvc3.exe.text span
                int logged = 0;
                rblog::write("CRASH-STACK: walking from rsp=0x%llX (umvc3 return addrs, IDA)", (unsigned long long)sp);
                for (uintptr_t p = sp; p < sp + 0x100000 && logged < 60; p += 8) {
                    if (IsBadReadPtr((void*)p, 8)) break;            // hit the stack base / guard page
                    uintptr_t v = *(uintptr_t*)p;
                    if (v >= code_lo && v < code_hi) {
                        rblog::write("CRASH-STACK:   [rsp+0x%llX] umvc3 0x%llX (IDA 0x%llX)",
                                    (unsigned long long)(p - sp), (unsigned long long)v,
                                    (unsigned long long)(v - base + 0x140000000ULL));
                        logged++;
                    }
                }
                rblog::write("CRASH-STACK: %d umvc3 frames found", logged);
            }
        }

        // Write crash info to shared memory for monitor
        if (monitor_shm::g_mon) {
            snprintf(monitor_shm::g_mon->last_crash,
                     sizeof(monitor_shm::g_mon->last_crash),
                     "code=%08X rip=%llX (IDA %llX)",
                     ep->ExceptionRecord->ExceptionCode,
                     (unsigned long long)rip,
                     (unsigned long long)ida);
        }

        // Bone dispatch crash: log the entity's actual vtable
        if (ida == 0x14056FC70 && ep->ContextRecord->Rcx > 0x10000) {
            uintptr_t entity = ep->ContextRecord->Rcx;
            uintptr_t vt = *(uintptr_t*)entity;
            uintptr_t vt_ida = vt - base + 0x140000000ULL;
            rblog::write("CRASH-ENTITY: ent=0x%llX vt=0x%llX count=%d arr=0x%llX",
                (unsigned long long)entity, (unsigned long long)vt_ida,
                *(uint32_t*)(entity + 0x530),
                (unsigned long long)*(uintptr_t*)(entity + 0x538));
        }

        // === ANIM PARAM-RESOLVER crash (FUN_14080c1d0 family, the 0x1408xxxx anim/effect cluster) ===
        // The deferred stale-reference carrier: the resolver got a NULL binding descriptor (param_2). param_1(rcx)
        // is the skeleton/anim context; *(rcx+0x58) is the curve-buffer base. DECISIVE SPLIT:
        // *(rcx+0x58)==0 -> the +0x58 reference itself is dangling/null (the +0x58 caller path)
        // *(rcx+0x58)!=0 -> base + a 16-bit offset can't sum to 0, so a direct-descriptor caller
        // passed a NULL list entry instead.
        // frames_since_rb proves the deferral; srcframe (per-page revert source) exposes cross-page skew.
        if (ida >= 0x140800000ULL && ida < 0x140900000ULL) {
            uintptr_t p1 = ep->ContextRecord->Rcx;
            rblog::write("ANIM-CRASH: resim_active=%d frame=%d rb_tgt=%d frames_since_rb=%d",
                resim::resim_active(), resim::current_frame(), resim::last_rollback_target(),
                resim::current_frame() - resim::last_rollback_target());
            if (p1 > 0x10000 && is_readable(p1, 0x60)) {
                uintptr_t vt         = *(uintptr_t*)p1;
                uintptr_t curve_base = *(uintptr_t*)(p1 + 0x58);   // The discriminator
                uintptr_t parent     = *(uintptr_t*)(p1 + 0x10);
                rblog::write("ANIM-CRASH: p1(rcx)=0x%llX vt=0x%llX(IDA 0x%llX) in_arena=%d srcframe=%d",
                    (unsigned long long)p1, (unsigned long long)vt,
                    (unsigned long long)(vt > base ? vt - base + 0x140000000ULL : vt),
                    arena::is_arena_addr(p1), arena::last_source_frame(p1));
                rblog::write("ANIM-CRASH: *(p1+0x58) curve_base=0x%llX in_arena=%d committed=%d srcframe=%d "
                    "<== ==0:dangling +0x58 ref (+0x58 caller) | !=0:direct-descriptor caller passed NULL",
                    (unsigned long long)curve_base, arena::is_arena_addr(curve_base),
                    arena::is_committed_addr(curve_base), arena::last_source_frame(curve_base));
                rblog::write("ANIM-CRASH: *(p1+0x10) parent=0x%llX in_arena=%d srcframe=%d",
                    (unsigned long long)parent, arena::is_arena_addr(parent),
                    arena::last_source_frame(parent));
            } else {
                rblog::write("ANIM-CRASH: p1(rcx)=0x%llX UNREADABLE (not the skeleton, or itself reverted-dead)",
                    (unsigned long long)p1);
            }
        }

        // === MOVING-CRASH PROBE: the exact null FIELD per crash A/B/C ===
        // Keyed on the precise RIP so it fires once per real crash (the ntdll cascade has a different ida).
        // peek the specific faulting field at its snapshot frame vs live to place the carrier.
        {
            uintptr_t rcx = (uintptr_t)ep->ContextRecord->Rcx;
            if (ida == 0x14080D44D) {                 // Crash C: child+0x50 (REBUILD_POINTER) NULL
                probe_field("C/child+0x00", rcx, 0x00);   // child header — is the child itself coherent?
                probe_field("C/child+0x50", rcx, 0x50);   // the null binding: 0 in SAVE (legit/latent) or post-load?
            } else if (ida == 0x14080DA49) {          // Crash B: R0=*(bone+0x108) NULL
                probe_field("B/bone+0x00",  rcx, 0x00);   // bone header: float (curve-reuse) vs pointer (live)?
                probe_field("B/bone+0x100", rcx, 0x100);  // +0x108 = R0 (the null); +0x100 the effect ptr
                probe_field("B/bone+0x140", rcx, 0x140);  // the consume gate (tear = gate set yet R0 null)
                if (is_readable(rcx + 0x108, 8)) {        // if R0 is mapped (the +0x4D content-0 variant), peek its +0x6e
                    uintptr_t R0 = *(uintptr_t*)(rcx + 0x108);
                    if (R0 > 0x10000) probe_field("B/R0+0x60", R0, 0x60);   // +0x60..+0x6f covers the +0x6e content read
                }
            }
            // Crash A (0x1402A22CE): the SE table is in NO GP register at the fault RIP (rcx is clobbered by the
            // FUN_140688a50 call; rsi is the dispatcher, not the table). It is observed AT ITS SOURCE by
            // effect_probe::hk_se_table (hook on FUN_140688a50) — see the "PROBE-A SE-table=" log lines, not here.
        }

        // === GENERAL STALE-REFERENCE FORENSICS — any AV touching a tiny (null+offset) address ===
        // The stale-reference signature is a NULL/near-null base dereferenced at +offset. For each register that is
        // a plausible pointer, report arena membership + the per-page SOURCE FRAME the revert used.
        // Different source frames across the pointers of one crash = cross-page skew (the revert stitched
        // pages from different frames into one logical object).
        if (ep->ExceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION &&
            ep->ExceptionRecord->NumberParameters >= 2 &&
            ep->ExceptionRecord->ExceptionInformation[1] < 0x10000) {
            struct { const char* n; uintptr_t v; } R[] = {
                {"rax",(uintptr_t)ep->ContextRecord->Rax},{"rbx",(uintptr_t)ep->ContextRecord->Rbx},
                {"rcx",(uintptr_t)ep->ContextRecord->Rcx},{"rdx",(uintptr_t)ep->ContextRecord->Rdx},
                {"rsi",(uintptr_t)ep->ContextRecord->Rsi},{"rdi",(uintptr_t)ep->ContextRecord->Rdi},
                {"r8",(uintptr_t)ep->ContextRecord->R8},{"r9",(uintptr_t)ep->ContextRecord->R9},
                {"r10",(uintptr_t)ep->ContextRecord->R10},{"r11",(uintptr_t)ep->ContextRecord->R11},
                {"r12",(uintptr_t)ep->ContextRecord->R12},{"r13",(uintptr_t)ep->ContextRecord->R13},
                {"r14",(uintptr_t)ep->ContextRecord->R14},{"r15",(uintptr_t)ep->ContextRecord->R15},
            };
            static volatile LONG g_uac_done = 0;
            if (InterlockedCompareExchange(&g_uac_done, 1, 0) == 0)   // fire-once: the cascade storm must not re-run the heavier peeks
            for (auto& r : R) {
                if (r.v <= 0x10000) continue;
                bool ina = arena::is_arena_addr(r.v);
                if (!ina && !is_readable(r.v, 8)) continue;   // arena ptrs, or readable heap ptrs only
                if (!ina) { rblog::write("STALE-REF-FORENSIC: %s=0x%llX in_arena=0 (OUT-OF-ARENA: revert never touched it)", r.n, (unsigned long long)r.v); continue; }
                // orphan + cross-register frame-skew (compare srcframe across regs) + save-vs-live, one line.
                int  srcf = arena::last_source_frame(r.v);
                bool orph = arena::was_orphaned_last_load(r.v);
                if (srcf >= 0 && is_readable(r.v, 0x18)) {
                    uint64_t snap[3] = {}; int s = arena::peek_saved(srcf, r.v, snap, 0x18);
                    const uint64_t* live = (const uint64_t*)r.v;
                    bool eq = (snap[0]==live[0] && snap[1]==live[1] && snap[2]==live[2]);
                    rblog::write("STALE-REF-FORENSIC: %s=0x%llX in_arena=1 srcframe=%d orphaned=%d | snap(s=%d) %016llX %016llX %016llX | live %016llX %016llX %016llX %s",
                        r.n, (unsigned long long)r.v, srcf, orph?1:0, s, snap[0],snap[1],snap[2], live[0],live[1],live[2],
                        eq ? "[snap==live: bad value already in SAVE]" : "[snap!=live: post-load writer or slab-reuse]");
                } else {
                    rblog::write("STALE-REF-FORENSIC: %s=0x%llX in_arena=1 srcframe=%d orphaned=%d (snap %s)",
                        r.n, (unsigned long long)r.v, srcf, orph?1:0, srcf<0?"absent: srcframe<0 — see PROBE-P0+orphaned":"unreadable");
                }
                // IDSPINE ESCAPE-PATH DISCRIMINATOR (read-only): was the faulting object's
                // block freed via FUN_1404cb350 (=> quarantine-reachable: if so, why wasn't it deferred — skipped/overflow/flushed?)
                // or is there NO FUN_1404cb350 free-record (=> ESCAPE PATH: a non-FUN_1404cb350 free the quarantine never sees)? + the
                // idspine identity (birth/death/serial) = is it dead / reused (serial advanced past the resurrected ref).
                {
                    uintptr_t blk = r.v;
                    if (is_readable(r.v - 8, 8)) { int64_t off = *(int64_t*)(r.v - 8); if (off > 0 && off < 0x1000) blk = r.v - (uintptr_t)off; }
                    uintptr_t caller=0, eff=0; int ff=0;
                    bool rf = idspine::recent_free(blk, &caller, &eff, &ff);
                    int birth=0, death=0; int64_t serial=0;
                    bool known = idspine::lookup(blk, &birth, &death, &serial);
                    if (rf || known)
                        rblog::write("STALE-REF-IDSPINE: %s block=0x%llX recent_free=%d(cb350 caller=0x%llX eff=0x%llX frame=%d) idspine=%d(birth=%d death=%d serial=%lld) => %s",
                            r.n, (unsigned long long)blk, rf?1:0, (unsigned long long)caller, (unsigned long long)eff, ff,
                            known?1:0, birth, death, (long long)serial,
                            rf ? "FREED-via-cb350 (quarantine-reachable: why not held?)" : "NO cb350 free-record (ESCAPE PATH / non-cb350 free)");
                    // RDSPINE check (Default-allocator SHADOW): is the faulting object Default-malloc'd, and IN-ARENA
                    // or CRT? Resolves the open in-arena-vs-CRT question (decides desync-safety of a Default-allocator keep-alive).
                    { int rb=0, rd=0, rina=-1; int64_t rser=0;
                      if (rdspine::lookup(r.v, &rb, &rd, &rser, &rina))
                        rblog::write("STALE-REF-RDSPINE: %s=0x%llX DEFAULT-ALLOC'd (birth=%d death=%d serial=%lld in_arena=%d) => %s",
                            r.n, (unsigned long long)r.v, rb, rd, (long long)rser, rina,
                            rina ? "in-arena (arena-reverted; crc skips the ptr => keep-alive desync-safe)"
                                 : "CRT (non-arena; ptr HASHED-by-value if in a gp_crc range => keep-alive NOT enough)");
                    }
                }
            }
        }

        // CS-FORENSIC: a tiny WRITE address (e.g. [DebugInfo+0x24]=ContentionCount, +0x24) means a
        // CRITICAL_SECTION with a null/garbage DebugInfo was entered under contention. Identify which cs
        // (the cs ptr is in rcx/rbx/r9 for RtlEnterCriticalSection), its OWNING MODULE, and its fields — so
        // we know if it's the D3D9 device cs, a d3d9-internal cs, or a game render cs. Fire-once (recursion).
        if (ep->ExceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION &&
            ep->ExceptionRecord->NumberParameters >= 2 &&
            ep->ExceptionRecord->ExceptionInformation[1] < 0x100) {
            static volatile bool g_cs_forensic_done = false;
            if (!g_cs_forensic_done) {
                g_cs_forensic_done = true;
                uintptr_t cand[] = {
                    (uintptr_t)ep->ContextRecord->Rcx, (uintptr_t)ep->ContextRecord->Rbx,
                    (uintptr_t)ep->ContextRecord->R9,  (uintptr_t)ep->ContextRecord->Rdi,
                    (uintptr_t)ep->ContextRecord->Rsi, (uintptr_t)ep->ContextRecord->R8,
                };
                for (uintptr_t cs : cand) {
                    if (cs < 0x10000 || !is_readable(cs, 0x28)) continue;
                    uintptr_t dbg = *(uintptr_t*)(cs + 0x00);
                    int32_t  lock = *(int32_t*)(cs + 0x08);
                    int32_t  rec  = *(int32_t*)(cs + 0x0C);
                    uintptr_t own = *(uintptr_t*)(cs + 0x10);
                    uintptr_t sem = *(uintptr_t*)(cs + 0x18);
                    char modname[MAX_PATH] = "<not-in-a-module>";
                    HMODULE hmod = nullptr;
                    if (GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                                           GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                                           (LPCSTR)cs, &hmod) && hmod) {
                        GetModuleFileNameA(hmod, modname, MAX_PATH);
                    } else {
                        MEMORY_BASIC_INFORMATION mbi;
                        if (VirtualQuery((void*)cs, &mbi, sizeof(mbi)))
                            snprintf(modname, sizeof(modname), "<private state=0x%lX type=0x%lX allocbase=0x%llX>",
                                     (unsigned long)mbi.State, (unsigned long)mbi.Type,
                                     (unsigned long long)mbi.AllocationBase);
                    }
                    // Offset within the owning module — STABLE across runs => a real fixed CS (ours/CRT/MinHook);
                    // VARIES across runs => a wild/corrupted pointer landing in our image by ASLR coincidence.
                    long long off_in_mod = hmod ? (long long)(cs - (uintptr_t)hmod) : -1;
                    // Which thread faulted? Compare to the render thread (sRender+0xE8) + third/window thread
                    // (sRender+0x2A98) so we know if suppression must extend to another render consumer.
                    DWORD cur_tid = GetCurrentThreadId();
                    uintptr_t srr = (uintptr_t)GetModuleHandleA("umvc3.exe");
                    uintptr_t sr2 = srr ? *(uintptr_t*)(srr + 0xE179A8) : 0;
                    DWORD rtid = (sr2 && !IsBadReadPtr((void*)(sr2+0xE8),8) && *(HANDLE*)(sr2+0xE8)) ? GetThreadId(*(HANDLE*)(sr2+0xE8)) : 0;
                    DWORD ttid = (sr2 && !IsBadReadPtr((void*)(sr2+0x2A98),8) && *(HANDLE*)(sr2+0x2A98)) ? GetThreadId(*(HANDLE*)(sr2+0x2A98)) : 0;
                    rblog::write("CS-FORENSIC: cs=0x%llX off_in_mod=0x%llX DebugInfo=0x%llX LockCount=%d Recursion=%d Owner=0x%llX Sem=0x%llX module=%s",
                                 (unsigned long long)cs, (unsigned long long)off_in_mod, (unsigned long long)dbg, lock, rec,
                                 (unsigned long long)own, (unsigned long long)sem, modname);
                    rblog::write("CS-FORENSIC: faulting_tid=%u | render_thread_tid=%u third/window_thread_tid=%u (which consumer hit the wild CS)",
                                 cur_tid, rtid, ttid);
                }
            }
        }

        // DTI property setter crash — dump descriptor fields
        {
            uintptr_t dti_start_ida = 0x140465380;
            uintptr_t dti_end_ida   = 0x140465380 + 142;
            uintptr_t dti_start = base + (dti_start_ida - 0x140000000ULL);
            uintptr_t dti_end   = base + (dti_end_ida - 0x140000000ULL);

            if (rip >= dti_start && rip < dti_end) {
                rblog::write("DTI-CRASH: inside FUN_140465380, scanning registers for descriptor");

                uintptr_t regs[] = {
                    ep->ContextRecord->Rcx, ep->ContextRecord->Rdx,
                    ep->ContextRecord->Rdi, ep->ContextRecord->Rsi,
                    ep->ContextRecord->R8,  ep->ContextRecord->R9,
                    ep->ContextRecord->R12, ep->ContextRecord->R13,
                    ep->ContextRecord->R14, ep->ContextRecord->R15,
                    ep->ContextRecord->Rbp
                };
                const char* rnames[] = {
                    "rcx","rdx","rdi","rsi","r8","r9","r12","r13","r14","r15","rbp"
                };

                for (int i = 0; i < 11; i++) {
                    uintptr_t desc = regs[i];
                    if (desc < 0x10000) continue;
                    if (!is_readable(desc, 0x50)) continue;

                    uint32_t type_flags = *(uint32_t*)(desc + 0x08);
                    uint16_t type_val = (uint16_t)(type_flags & 0xFFFF);
                    uint16_t flags2   = (uint16_t)((type_flags >> 16) & 0xFFFF);
                    uintptr_t data_base = *(uintptr_t*)(desc + 0x18);
                    uint32_t index      = *(uint32_t*)(desc + 0x38);

                    if (type_val != 0x0E) continue;

                    uintptr_t name_ptr = *(uintptr_t*)(desc + 0x00);
                    uintptr_t owner    = *(uintptr_t*)(desc + 0x10);

                    char name_buf[64] = "<unreadable>";
                    if (name_ptr > 0x10000 && is_readable(name_ptr, 64)) {
                        memcpy(name_buf, (void*)name_ptr, 63);
                        name_buf[63] = 0;
                    }

                    rblog::write("DTI-CRASH: reg=%s desc=0x%llX name=\"%s\" type=0x%X flags2=0x%X",
                        rnames[i], (unsigned long long)desc, name_buf, type_val, flags2);
                    rblog::write("DTI-CRASH: owner=0x%llX data_base=0x%llX index=%u",
                        (unsigned long long)owner, (unsigned long long)data_base, index);

                    uintptr_t slot_addr = data_base + (uintptr_t)index * 8;
                    if (is_readable(slot_addr, 8)) {
                        uintptr_t slot_val = *(uintptr_t*)slot_addr;
                        rblog::write("DTI-CRASH: slot=0x%llX val=0x%llX",
                            (unsigned long long)slot_addr, (unsigned long long)slot_val);
                    } else {
                        rblog::write("DTI-CRASH: slot=0x%llX UNREADABLE", (unsigned long long)slot_addr);
                    }

                    if (owner > 0x10000 && is_readable(owner, 8)) {
                        uintptr_t ovt = *(uintptr_t*)owner;
                        uintptr_t ovt_ida = ovt - base + 0x140000000ULL;
                        rblog::write("DTI-CRASH: owner_vt=0x%llX (IDA 0x%llX)",
                            (unsigned long long)ovt, (unsigned long long)ovt_ida);
                    }

                    rblog::write("DTI-CRASH: in_arena=%d in_committed=%d",
                        arena::is_arena_addr(data_base),
                        arena::is_committed_addr(data_base));
                }

                uintptr_t rsp = ep->ContextRecord->Rsp;
                if (is_readable(rsp, 0x200)) {
                    rblog::write("DTI-CRASH: scanning stack at rsp=0x%llX", (unsigned long long)rsp);
                    for (int off = 0; off < 0x200; off += 8) {
                        uintptr_t val = *(uintptr_t*)(rsp + off);
                        if (val == 0xFFFFFFFFFFFFFFFFULL) {
                            rblog::write("DTI-CRASH: stack[+0x%X] = -1 (0xFFFFFFFFFFFFFFFF)", off);
                        }
                    }
                }
            }
        }

        rblog::flush();
        InterlockedExchange(&g_in_veh, 0);   // end of pass: a later distinct crash may log again
    }

    // Always continue search. We log. We do not handle. We do not skip.
    return EXCEPTION_CONTINUE_SEARCH;
}

// dinput8.dll proxy
static HMODULE g_real_dinput8 = NULL;

typedef HRESULT(WINAPI* DirectInput8Create_t)(HINSTANCE, DWORD, REFIID, LPVOID*, LPUNKNOWN);
static DirectInput8Create_t g_real_DirectInput8Create = nullptr;

extern "C" __declspec(dllexport) HRESULT WINAPI DirectInput8Create(
    HINSTANCE hinst, DWORD dwVersion, REFIID riidltf, LPVOID* ppvOut, LPUNKNOWN punkOuter) {
    if (!g_real_DirectInput8Create) return E_FAIL;
    HRESULT hr = g_real_DirectInput8Create(hinst, dwVersion, riidltf, ppvOut, punkOuter);
    // DirectInput8Create is the game's DirectInput entry point; we forward it and install the observation probe.
    // The gamepad itself enters through XInput — see dinput_probe.cpp.
    if (SUCCEEDED(hr) && ppvOut && *ppvOut) dinput_probe::install(*ppvOut, &riidltf);
    return hr;
}

// Decrypt-detection — replaces a fixed Sleep(5000). The protection is SteamStub: the .bind stub decrypts .text
// in-place at runtime on the packed Steam exe; on a Steamless'd exe .text is plaintext from disk. Poll the known
// first-16-bytes signature of decrypted .text at base+0x1000 instead of guessing a fixed 5s — instant on a Steamless
// exe, precise on the packed exe (no too-short race that reads encrypted garbage, no wasted wait). 12s timeout =
// best-effort proceed (logged). Signature lifted from umvc3_unpacked.exe .text[0x400].
// True iff `p` is in a committed, EXECUTABLE, non-guard page — exactly the predicate MinHook's
// IsExecutableAddress uses to gate MH_CreateHook. This is the property that matters, not "bytes decrypted":
// SteamStub VirtualProtects .text to RW, decrypts in place, then flips it back to EXECUTE_READ as its FINAL
// step before jumping to OEP. During that RW window the bytes are already decrypted+readable but the page is
// not executable, so hooking there returns MH_ERROR_NOT_EXECUTABLE(7). Gate on exec, not on the signature.
static bool addr_is_exec(uintptr_t p) {
    MEMORY_BASIC_INFORMATION mbi;
    if (!VirtualQuery((void*)p, &mbi, sizeof(mbi))) return false;
    if (mbi.State != MEM_COMMIT) return false;
    const DWORD X = PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;
    if (!(mbi.Protect & X)) return false;
    if (mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS)) return false;
    return true;
}

static bool wait_for_text_decrypt(int timeout_ms) {
    static const unsigned char SIG[16] =
        {0x88,0x11,0x44,0x88,0x41,0x01,0x44,0x88,0x49,0x02,0x81,0x09,0x00,0x00,0x00,0xFF};
    uintptr_t base = (uintptr_t)GetModuleHandleA("umvc3.exe");
    if (!base) base = (uintptr_t)GetModuleHandleA(NULL);
    if (!base) { rblog::write("DECRYPT-WAIT: no module base; fallback Sleep(5000)"); Sleep(5000); return false; }
    const unsigned char* text = (const unsigned char*)(base + 0x1000);
    // The two deepest, load-bearing hook targets (rebased ASLR-safe). They live ~2.5MB into .text, so they are
    // the last bytes SteamStub decrypts and re-protects — when both are executable the whole section is ready and
    // MinHook will accept every hook. Gating on the actual targets handles both whole-section and page-by-page
    // decrypt granularity; base+0x1000's signature stays as a binary-identity / decrypt-ran sanity check.
    const uintptr_t MAIN_PROC     = base + (0x1402594A0ull - 0x140000000ull);   // resim.cpp MAIN_PROC_IDA
    const uintptr_t INPUT_DISPATCH = base + (0x1402B41B0ull - 0x140000000ull);  // input.cpp INPUT_DISPATCH_IDA
    int waited = 0;
    bool sig_ok = false, main_ok = false, in_ok = false;
    while (waited < timeout_ms) {
        MEMORY_BASIC_INFORMATION mbi;
        sig_ok = VirtualQuery(text, &mbi, sizeof(mbi)) && mbi.State == MEM_COMMIT &&
                 !(mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)) && memcmp(text, SIG, 16) == 0;
        main_ok = addr_is_exec(MAIN_PROC);
        in_ok   = addr_is_exec(INPUT_DISPATCH);
        if (sig_ok && main_ok && in_ok) {
            rblog::write("DECRYPT-WAIT: .text decrypted+executable after %d ms (base=0x%llX) — Steamless=instant / packed=precise",
                         waited, (unsigned long long)base);
            return true;
        }
        Sleep(20); waited += 20;
    }
    rblog::write("DECRYPT-WAIT: TIMEOUT %d ms — sig=%d main-exec=%d input-exec=%d; proceeding best-effort (check exe build/sig)",
                 timeout_ms, (int)sig_ok, (int)main_ok, (int)in_ok);
    return false;
}

static DWORD WINAPI init_thread(LPVOID) {
    // Wait for SteamStub's .bind stub to decrypt .text (precise poll, not a fixed 5s). The HEAP REDIRECT is already
    // armed in arena::early_init (before this thread) so the engine's allocator controls land in-arena regardless.
    wait_for_text_decrypt(12000);

    addr::init();
    rblog::write("Module base: 0x%llX", (unsigned long long)addr::g_base);

    // Find the .data section, scan ConcRT refs, allocate ring buffers
    resim::early_init();

    // The HeapAlloc redirect is armed in arena::early_init (end of DLL_PROCESS_ATTACH, before this thread):
    // the engine batch-builds its allocator controls (malloc→HeapAlloc→GetProcessHeap) during the
    // decrypt window; arming the redirect inside this init_thread (post-decrypt) was too LATE — controls landed on the
    // real low-address OS heap (out-of-arena), which is the root of the free-list coherent-full coverage gap. Arming in
    // early_init makes those controls land IN-ARENA so they revert with everything else. (A/B 'noheapredirect' gate is
    // honored there too.) Nothing to do here anymore — just report the resolved state.
    if (arena::no_heapredirect())
        rblog::write("NO-HEAP-REDIRECT A/B ACTIVE — HeapAlloc stays on the native OS heap (recycling); arena heap zone unused");
    else
        rblog::write("HEAP-REDIRECT armed in early_init — engine allocator controls land in-arena");

    // Initialize MinHook before any hook creation
    MH_STATUS mh = MH_Initialize();
    if (mh != MH_OK) {
        rblog::write("MH_Initialize failed (%d)", mh);
        return 1;
    }
    rblog::write("MinHook initialized");

    suspend::init();
    handle_preserve::init();
    dead_vtable_unlink::init();
    input::init();    // Creates INPUT_DISPATCH hook
    resim::init();    // Creates MAIN_PROC hook + MH_EnableHook(all)

    rblog::write("Init complete. F5=arm rollback engine, F6=manual rollback.");
    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);

        // Init logging first
        char path[MAX_PATH];
        GetModuleFileNameA(NULL, path, MAX_PATH);
        char* slash = strrchr(path, '\\');
        if (slash) strcpy(slash + 1, "umvc3_rollback.log");
        rblog::init(path);
        rblog::write("DLL loaded (beta) — instance role=%s (env UMVC3_ROLLBACK_ROLE > netplay.cfg role= > path-heuristic > P1)", role::name());

        // OPT OUT OF EcoQoS POWER THROTTLING — the thing that made same-PC two-instance testing
        // useless. Windows 10+ throttles the EXECUTION SPEED of processes it considers background (unfocused), and a
        // second game instance would drop to roughly 6fps the moment it lost focus. That is not the game backing off
        // and no in-game setting affects it; it is the OS scheduler, so it silently wrecked every local netplay test
        // and sent us chasing "one side runs slower" bugs that were never ours.
        // Opting out costs nothing (we are a foreground-class game either way) and makes a local P1-vs-P2 test on one
        // machine behave like two machines. Guarded so it is a no-op on Windows versions without the API.
        // Resolved dynamically: MinGW's headers don't declare SetProcessInformation, and the API is Win10+ only, so a
        // static import would also break the load on anything older. Struct laid out per the Win32 ABI.
        {
            struct PPT_STATE { ULONG Version; ULONG ControlMask; ULONG StateMask; };
            constexpr ULONG PPT_CURRENT_VERSION   = 1;
            constexpr ULONG PPT_EXECUTION_SPEED   = 0x1;
            constexpr int   ProcessPowerThrottling_ = 4;   // PROCESS_INFORMATION_CLASS
            typedef BOOL (WINAPI *SetProcInfo_t)(HANDLE, int, PVOID, DWORD);

            HMODULE k32 = GetModuleHandleA("kernel32.dll");
            SetProcInfo_t spi = k32 ? (SetProcInfo_t)GetProcAddress(k32, "SetProcessInformation") : nullptr;
            if (spi) {
                PPT_STATE pt{ PPT_CURRENT_VERSION, PPT_EXECUTION_SPEED, 0 };   // StateMask 0 = DISABLE throttling
                BOOL ok = spi(GetCurrentProcess(), ProcessPowerThrottling_, &pt, sizeof(pt));
                rblog::write("POWER: EcoQoS execution-speed throttling opt-out %s — an unfocused instance now runs at "
                             "full speed (this is what capped the second local instance at ~6fps).",
                             ok ? "APPLIED" : "REJECTED by the OS");
            } else {
                rblog::write("POWER: SetProcessInformation unavailable (pre-Win10) — no EcoQoS opt-out needed.");
            }
        }

        // VEH: read-only crash logger. Logs address and dies. No skips.
        AddVectoredExceptionHandler(1, crash_logger);
        // BACKSTOP: top-of-chain unhandled filter — catches a fail-fast/heap-corruption death that reaches the top
        // unhandled (the silent case: log ended mid-healthy voice-pool with NO CRASH line => VEH never fired).
        // Reuses crash_logger (same EXCEPTION_POINTERS shape); logs the rip/code so the silent crash is named.
        SetUnhandledExceptionFilter((LPTOP_LEVEL_EXCEPTION_FILTER)crash_logger);

        // Shared memory for monitor.exe — create early so monitor can connect anytime
        role::init();
        single_instance::install();   // neuter the game single-instance guard for P2 (before WinMain runs it)
        monitor_shm::init();

        // Load real dinput8.dll (proxy)
        char sys[MAX_PATH];
        GetSystemDirectoryA(sys, MAX_PATH);
        strcat(sys, "\\dinput8.dll");
        g_real_dinput8 = LoadLibraryA(sys);
        if (g_real_dinput8) {
            g_real_DirectInput8Create = (DirectInput8Create_t)GetProcAddress(g_real_dinput8, "DirectInput8Create");
            rblog::write("Proxy: loaded real dinput8.dll from %s", sys);
        }

        // PERF A/B switches — read before early_init so the arena reservation can honor them.
        // Toggle by creating "nowritewatch.flag" / "nohooks.flag" beside the .exe (or env UMVC3_NOWRITEWATCH / UMVC3_NOHOOKS).
        {
            bool nww = arena::startup_flag("UMVC3_NOWRITEWATCH", "nowritewatch.flag");
            bool nh  = arena::startup_flag("UMVC3_NOHOOKS", "nohooks.flag");
            bool nhr = arena::startup_flag("UMVC3_NOHEAPREDIRECT", "noheapredirect.flag");
            arena::set_startup_flags(nww, nh, nhr);
            // (alloc_rethread DELETED — double-refuted foot-gun: walked the drained reserve pool, wiped 64 mgrs,
            // caused the all-parked hang on an earlier run. The flag could only reproduce a hang.)
            // QUARANTINE FAIL-CLOSED A/B: ON by default (defer every freed slot — the engine-wide slab-reuse prevention).
            // Drop quar_typed_only.flag to revert to the legacy fail-open (defer only positively-typed objects).
            bool typed_only = arena::startup_flag("UMVC3_QUAR_TYPED_ONLY", "quar_typed_only.flag");
            quarantine::set_defer_all(!typed_only);
            rblog::write("QUARANTINE: defer-all %s (%s) — drop quar_typed_only.flag to revert to legacy fail-open",
                         typed_only ? "OFF" : "ON", typed_only ? "legacy: defer typed-only" : "FAIL-CLOSED: defer every slot");
            // SENTINEL FIX A/B: ON by default (no audio carve-out => destructed MtObjects deferred, closing the 40k-frame run
            // 0x140A6A510-as-audio hole). Drop quar_audio_carveout.flag to RESTORE the legacy (buggy) carve-out.
            bool audio_co = arena::startup_flag("UMVC3_QUAR_AUDIO_CARVEOUT", "quar_audio_carveout.flag");
            quarantine::set_audio_carveout(audio_co);
            rblog::write("QUARANTINE: audio-carveout %s — sentinel fix %s (drop quar_audio_carveout.flag to restore legacy skip)",
                         audio_co ? "ON (legacy)" : "OFF", audio_co ? "DISABLED" : "ACTIVE (defer destructed objects)");
            // RTV FRESH-FRAME FIX A/B: ON by default (null reverted-alive dead wrappers' stale +0x20 => the 0x140781D15 fix).
            bool rtv_off = arena::startup_flag("UMVC3_RTV_NO_DESTROYED_FIX", "rtv_no_destroyed_fix.flag");
            rtv_probe::set_destroyed_fix(!rtv_off);
            rblog::write("RTV: destroyed-wrapper fix %s (drop rtv_no_destroyed_fix.flag to disable)", rtv_off ? "OFF" : "ON");
            // STAGE B A/B: ON by default (route Default malloc into the in-arena zone => alive-at-N Default fix, byte-reverted).
            bool stage_b_off = arena::startup_flag("UMVC3_NO_STAGE_B", "stage_b.flag");
            rdspine::set_stage_b(!stage_b_off);
            rblog::write("STAGE B: Default->heap-zone %s (drop stage_b.flag to keep Default on the CRT heap)", stage_b_off ? "OFF" : "ON");
            // (the FLIP flag was deleted — drive_page no longer writes; a dead toggle is a foot-gun.)
            // OWNED-HEAP MASTER (default ON: all four properties live in one composition). This is the
            // master switch — not a per-property scaffold. It OVERRIDES the individual A/B positions
            // above so no property can be half-on. OFF (drop owned_heap_off.flag beside the .exe / UMVC3_OWNED_HEAP_OFF=1)
            // = the legacy workaround baseline, kept for bisecting.
            bool oh_off = arena::startup_flag("UMVC3_OWNED_HEAP_OFF", "owned_heap_off.flag");
            bool owned_heap = !oh_off;
            arena::set_owned_heap_active(owned_heap);
            if (owned_heap) {
                // P1 own the backing: Stage B (Default->zone) + heap redirect stay — they are P1 for Default ("own
                // all backing uniformly"); capacity alarms (arena.cpp arena-full / heap-zone-full) armed by the master flag. P2 the map: the
                // reader oracle stays armed (arena default). P3 own the reuse, complete: uniform defer, NO carve-outs
                // (audio deferred like anything — the sentinel hole stays shut), overflow holds not frees, monotonic
                // horizon (quarantine.cpp). P4 object-granular revert: page-blind is the byte-source (rollback ≡
                // page-blind), the object walk drives zero bytes, and the 10-slot alloc-ring is DELETED so the
                // in-arena control reverts coherently via page-blind (eliminates the cross-ring skew). Workaround set OFF.
                rdspine::set_stage_b(true);
                arena::set_heap_redirect(true);
                quarantine::set_defer_all(true);
                quarantine::set_audio_carveout(false);
                // P4 — principle: save AUTHORITATIVE + REBUILD DERIVED.
                // An earlier run refuted "page-blind reverts the control coherently": the free-list is captured TORN by MT
                // splices (INVARIANT-CHECK POSTLOAD broken=31 => FUN_1404ca650 death). So split the control: the AUTHORITATIVE
                // descriptor geometry (pool bounds, region list @ctrl+0xc0) is RESTORED coherently by
                // restore_allocators (atomic 0x660 ring capture) — control_revert OFF; and the DERIVED free-list links
                // (+0x18/+0x20, head/tail/count) are REBUILT from the authoritative per-block bit0 (page-blind-
                // reverted) by alloc_rethread. The descriptor-vs-nodes skew dissolves: a rebuilt head can only
                // point at a bit0=0 block, by construction. (The first all-on build's error: it deleted the authoritative
                // restore instead of just the derived-link restore.)
                resim::set_owned_heap_control_revert(false);  // Keep restore_allocators — authoritative descriptor geometry is must-restore
                // REBUILD refuted (an earlier run + binary RE): alloc_rethread walks ctrl+0xc0 = the DRAINED reserve
                // pool (not a region index) => deterministically collects 0 => wiped all 64 managers => count<=0
                // no-op unlinks => orphaned links => the FUN_1404ca650 first-fit spin (all-parked hang). The atomic save +
                // exact restore_allocators (delta=0/skew=0/torn=0 measured) restores {descriptor+nodes} as one
                // coherent captured set — NO rebuild layer on top (the rule: don't repair what restores
                // coherently). rethread stays a manual rethread.flag diagnostic only (now wipe-guarded).
                resim::set_patch_pile_enabled(false);         // detect-and-repair workarounds OFF (coherent_set_repair/coherence_audit/alloc_invariants::repair); alloc_invariants::check kept as the ALWAYS-LOGGING oracle
                // RTV fix RE-CLASSIFIED (an earlier run: 0x140781D15 recurred at 27k frames with the fix off):
                // D3D-surface wrappers hold EXTERNAL handles — the irreducible residual where null-on-revert
                // IS the approved external-handle discipline (the voice_pool pattern), not the retired repair pile.
                // The wrappers' D3D edge is the one irreducible external residual.
                rtv_probe::set_destroyed_fix(true);
                rblog::write("OWNED-HEAP: MASTER ON — P1 backing (+capacity alarms) + P2 map + P3 reuse (complete) + P4 = atomic save + exact descriptor restore + windowed page revert (one coherent captured set; no rebuild); workarounds OFF. Oracles: invariant-check summary every rollback, arm gp_crc via F4 for long runs. owned_heap_off.flag/F1 = legacy A/B.");
            } else {
                resim::set_owned_heap_control_revert(false);   // restore_allocators stays (authoritative descriptor) in both modes
                resim::set_patch_pile_enabled(true);
                rblog::write("OWNED-HEAP: OFF — legacy patch-pile A/B baseline (restore_allocators + full pile, no rethread rebuild).");
            }
            if (nww) rblog::write("A/B SWITCH: NO-WRITE-WATCH — arena without MEM_WRITE_WATCH; rollback ENGINE DISABLED (perf isolation)");
            if (nh)  rblog::write("A/B SWITCH: NO-HOOKS — non-essential module hooks NOT installed; rollback ENGINE DISABLED (perf isolation)");
            if (nhr) rblog::write("A/B SWITCH: NO-HEAP-REDIRECT — HeapAlloc stays on the native OS heap (no arena zone redirect); rollback ENGINE DISABLED (perf isolation)");
            if (!nww && !nh && !nhr) rblog::write("A/B SWITCH: none (normal build). Drop nowritewatch.flag/nohooks.flag/noheapredirect.flag beside the .exe to isolate the perf tax.");
        }

        // CRITICAL: Reserve arena + install IAT hooks before game allocator runs.
        // This ensures all game VirtualAlloc/VirtualFree calls land in our arena.
        // The HeapAlloc redirect is armed at the end of early_init (see there).
        if (!arena::early_init()) {
            rblog::write("WARNING: Arena init failed — rollback will not work");
        }

        // Deferred init on background thread (hooks need game to finish unpacking)
        CreateThread(NULL, 0, init_thread, NULL, 0, NULL);
    }
    return TRUE;
}
