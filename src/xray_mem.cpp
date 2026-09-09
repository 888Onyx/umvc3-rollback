#include "xray_mem.h"
#include "arena.h"
#include "addr.h"
#include "resim.h"
#include "log.h"
#include <windows.h>
#include <cstdint>
#include <cstdio>
#include <cstring>

// See xray_mem.h. Max-scope capture:
// one bounded, max-scope capture per mode covering everything a drawn frame reads IN-ARENA, in 1-2 runs.
// MODE_CORE — every sUnit entity (all 128 lines, per-entity size) + fighter anim sub-objects + gameplay
// singletons + the render-input hop. The .data sim scalars are captured by VALUE-SNAPSHOT per
// frame (not page-guarded — their pages co-host the hot sUnit head; guarding them stalls).
// MODE_EFFECTS — the effect/anim OFF-BODY graph (+0x218 children, +0x220 slots, slot+0x58 binding[+0x198],
// +0xe0 channels) + the standalone sEffect-manager spine (best-effort).
// Hardening: (1) freeze() drains this tracer's IO lock like the log lock — no VEH
// deadlock during resim. (2) disarm un-guards before clearing g_armed; an in-arena fault while disarming is
// CLEAR-AND-CONTINUE (the OS already cleared the guard bit), never CONTINUE_SEARCH (which would crash on the
// unowned guard fault); non-arena faults (stack guard pages!) are left to their real handler. (3) the
// single-step branch runs first and is ungated, so an in-flight step always self-terminates. (4) every
// multi-byte read is span-checked so it can't straddle into an uncommitted page and wild-AV. Guards as much as
// fits a hard MAX_PAGES budget, then skips+tallies; out-of-arena objects a walk reaches are TALLIED (a
// page-guard tracer structurally cannot see them), never guarded. Runs at a crawl; 1-2 runs, then offline.

namespace xray_mem {
namespace {

constexpr uintptr_t PAGE     = 0x1000;
constexpr uintptr_t IDA_BASE = 0x140000000ULL;
constexpr uintptr_t IDA_END  = 0x141000000ULL;
constexpr uintptr_t MOD_SPAN = IDA_END - IDA_BASE;

constexpr int    MAX_RANGES = 1024;
// Conservative budget: 512 pages. Confirm frames complete + DISARMED fires before raising it. A heavy frame
// can't stall: this caps guarded pages and a fault-rate breaker (below) auto-disarms a degrading frame.
constexpr SIZE_T MAX_PAGES  = 512;
constexpr LONG64 FAULT_BREAKER = 8000000;   // >this many faults in one frame => pathological => auto-disarm early

enum CaptureMode { MODE_CORE = 1, MODE_EFFECTS = 2, MODE_COUNT = 2 };

static DWORD            g_tls = TLS_OUT_OF_INDEXES;
static volatile LONG    g_armed = 0;
static PVOID            g_veh = nullptr;
static HANDLE           g_file = INVALID_HANDLE_VALUE;
static CRITICAL_SECTION g_cs;
static uintptr_t        g_base = 0, g_end = 0;
static volatile LONG    g_frame = 0;
static volatile LONG    g_frames_left = 0;
static volatile LONG64  g_logged = 0;
static volatile LONG64  g_breaker_prev = 0;   // g_logged at the last frame boundary (per-frame fault-rate breaker)
static int              g_active_mode = MODE_CORE;

static char  g_buf[1 << 16];
static int   g_buf_len = 0;

static void flush_locked() {
    if (g_buf_len > 0 && g_file != INVALID_HANDLE_VALUE) {
        DWORD wrote = 0; WriteFile(g_file, g_buf, (DWORD)g_buf_len, &wrote, nullptr); g_buf_len = 0;
    }
}
static void emit(const char* line, int len) {
    EnterCriticalSection(&g_cs);
    if (g_buf_len + len > (int)sizeof(g_buf)) flush_locked();
    if (len <= (int)sizeof(g_buf)) { memcpy(g_buf + g_buf_len, line, len); g_buf_len += len; }
    LeaveCriticalSection(&g_cs);
}

// ---- guarded-range bookkeeping (touched only by the main thread in arm/disarm; the VEH admits by [g_base,g_end)) ----
static struct { uintptr_t base; SIZE_T size; } g_ranges[MAX_RANGES];
static int    g_range_count = 0;
static SIZE_T g_pages_guarded = 0;
static int    g_skipped_obj = 0;
static SIZE_T g_skipped_pages = 0;
static int    g_oob_obj = 0;     // objects a walk reached that were not in-arena (invisible to a page-guard tracer)

// arena-relative offset for the log (in-arena coords are always < arena size)
static inline uint64_t log_off(uintptr_t addr) { return (uint64_t)(addr - g_base); }
static inline char classify_val(uintptr_t v) {
    if (v >= g_base && v < g_end) return 'a';
    if (v >= addr::g_base && v < addr::g_base + MOD_SPAN) return 'm';
    return 's';
}

static void guard_one(uintptr_t b, SIZE_T sz, bool add) {
    uintptr_t p = b & ~(PAGE - 1), e = b + sz;
    while (p < e) {
        MEMORY_BASIC_INFORMATION mbi;
        if (VirtualQuery((void*)p, &mbi, sizeof(mbi)) && mbi.State == MEM_COMMIT && !(mbi.Protect & PAGE_NOACCESS)) {
            DWORD np = add ? (mbi.Protect | PAGE_GUARD) : (mbi.Protect & ~PAGE_GUARD);
            if (np != mbi.Protect) { DWORD old = 0; VirtualProtect((void*)p, PAGE, np, &old); }
        }
        p += PAGE;
    }
}

// ---- safe reads (never fault during arm — the VEH only handles GUARD faults, not wild AVs) ----
static inline bool committed(uintptr_t p) { return p > 0x10000 && arena::is_committed_addr(p); }
// span-checked: a multi-byte read must not straddle from a committed page into an uncommitted next page.
static inline bool committed_span(uintptr_t p, SIZE_T len) {
    if (!committed(p)) return false;
    if (((p & 0xFFF) + len) <= PAGE) return true;       // wholly within the start page
    return committed(p + len - 1);                       // else the last byte's page must be committed too
}
static inline uintptr_t rd_arena(uintptr_t p) { return committed_span(p, 8) ? *(uintptr_t*)p : 0; }  // in-arena 8-byte field
static inline uint32_t  rd_u32(uintptr_t p)   { return committed_span(p, 4) ? *(uint32_t*)p : 0; }
static inline uint16_t  rd_u16(uintptr_t p)   { return committed_span(p, 2) ? *(uint16_t*)p : 0; }
static inline uintptr_t rd_mod(uintptr_t ida) { return *(uintptr_t*)addr::resolve(ida); }            // .data ptr (module always committed)

static uintptr_t type_of(uintptr_t obj) {
    if (!committed_span(obj, 8)) return 0;
    uintptr_t vt = *(uintptr_t*)obj;
    return (vt >= addr::g_base && vt < addr::g_base + MOD_SPAN) ? (vt - addr::g_base + IDA_BASE) : 0;
}

// guard [base, base+size): IN-ARENA only. Module/heap objects are tallied (g_oob_obj) — a page-guard tracer
// cannot safely guard module pages (they co-host hot globals => stall) nor see external heap.
static bool guard_region(uintptr_t base, SIZE_T size, int tag, uintptr_t vt_ida) {
    if (!base || size == 0) return true;
    if (!(base >= g_base && base < g_end)) { g_oob_obj++; return false; }
    SIZE_T pages = (size + PAGE - 1) / PAGE;
    if (g_range_count >= MAX_RANGES || g_pages_guarded + pages > MAX_PAGES) { g_skipped_obj++; g_skipped_pages += pages; return false; }
    char ol[160];
    int on = snprintf(ol, sizeof(ol), "XM-OBJ %llX %llX %llX %d\n",
                      (unsigned long long)log_off(base), (unsigned long long)size, (unsigned long long)vt_ida, tag);
    if (on > 0) emit(ol, on);
    guard_one(base, size, true);
    g_ranges[g_range_count].base = base; g_ranges[g_range_count].size = size; g_range_count++;
    g_pages_guarded += pages;
    return true;
}

// ============================ MODE_CORE walks ============================

static void walk_sunit_bodies() {
    uintptr_t sunit = rd_mod(0x140E17698);
    if (!sunit) return;
    for (int line = 0; line < 128; line++) {
        uintptr_t ent = rd_arena(sunit + 0x58 + (uintptr_t)line * 0x30);
        for (int w = 0; ent && w < 256; w++) {
            if (!committed(ent)) break;
            SIZE_T span = 0x9000;
            uintptr_t hdr = ent - 0x50;                          // allocator block base (user-ptr = block+0x50)
            uint32_t s = rd_u32(hdr + 0x38) >> 1;
            if (s >= 0x100 && s <= 0x10000) span = (s + 0xFFF) & ~0xFFF;
            guard_region(ent, span, 1000 + line, type_of(ent));
            ent = rd_arena(ent + 0x20);
        }
    }
}

static void walk_fighter_subobjs() {
    uintptr_t sunit = rd_mod(0x140E17698);
    if (!sunit) return;
    for (int line = 7; line <= 8; line++) {
        uintptr_t ent = rd_arena(sunit + 0x58 + (uintptr_t)line * 0x30);
        for (int w = 0; ent && w < 64; w++) {
            if (!committed(ent)) break;
            uint32_t bc = rd_u32(ent + 0x530);                                   // bone count
            if (bc >= 1 && bc <= 300) guard_region(rd_arena(ent + 0x538), (SIZE_T)bc * 0xC0 + 0x10, 7538, 0);
            uintptr_t ov = rd_arena(ent + 0x11B0);                               // override block
            if (ov) { uint32_t oc = rd_u32(ent + 0x11A8) & 0xff; if (!oc) oc = 0x40; guard_region(ov, (SIZE_T)oc * 0x40 + 0x40, 7110, 0); }
            guard_region(rd_arena(ent + 0x548), 0x1000, 7548, 0);                 // scratch
            uintptr_t cm = rd_arena(ent + 0x100);                                 // cModel
            guard_region(cm, 0x300, 7100, type_of(cm));
            ent = rd_arena(ent + 0x20);
        }
    }
}

static void walk_singletons_core() {
    struct { uintptr_t ida; uintptr_t off; SIZE_T span; int tag; } S[] = {
        { 0x140D44A70, 0,       0x2600, 44100 },   // sCharacter (state half)
        { 0x140D47E68, 0,       0x8E0,  47800 },   // sAction
        { 0x140D46470, 0,       0x1D50, 46400 },   // sGameEffect (gameplay singleton)
        { 0x140D44060, 0,       0x400,  44000 },   // cHitSolver HEAD only
        { 0x140E177E8, 0x40000, 0x60,   17700 },   // sMain QPC band
    };
    for (auto& s : S) { uintptr_t b = rd_mod(s.ida); if (b) guard_region(b + s.off, s.span, s.tag, type_of(b)); }
    uintptr_t smain = rd_mod(0x140E177E8);
    if (smain) { uintptr_t cam = rd_arena(smain + 0x401b0); if (cam) guard_region(cam, 0x800, 17401, type_of(cam)); }
}

static void walk_render_ctx() {
    uintptr_t sr = rd_mod(0x140E179A8);
    if (!sr) return;
    uintptr_t ctx = rd_arena(sr + 0x8676e8);
    if (ctx) {
        guard_region(ctx, 0x1000, 53000, type_of(ctx));
        guard_region(rd_arena(ctx + 0x400), 0x1000, 0x53400, 0);
        guard_region(rd_arena(ctx + 0x4c8), 0x1000, 0x534c8, 0);
        guard_region(rd_arena(ctx + 0x320), 0x1000, 0x53320, 0);
    }
    uintptr_t sv = rd_mod(0x140E17930);
    if (sv) guard_region(sv, 0x800, 17930, type_of(sv));
}

// .data SIM SCALARS — not page-guarded (their pages co-host the hot sUnit head => stall). Captured by a cheap
// per-frame VALUE snapshot instead: the value sequence reveals the temporal kind (changing every frame =>
// counter/accumulator; static => seed). Module .data is always committed, so the reads are safe.
static void snapshot_data_scalars() {
    struct { uintptr_t ida; const char* nm; } D[] = {
        { 0x140D765D8, "rng" }, { 0x140E1B708, "fc1" }, { 0x140E1C008, "fc2" }, { 0x140E178F0, "tog" },
    };
    int ph = resim::resim_active() ? PH_RESIM : PH_LIVE;
    for (auto& d : D) {
        uint64_t v = *(uint64_t*)addr::resolve(d.ida);
        char line[96];
        int n = snprintf(line, sizeof(line), "XM-DATA %s %llX %ld %d\n", d.nm, (unsigned long long)v, (long)g_frame, ph);
        if (n > 0) emit(line, n);
    }
}

// ============================ MODE_EFFECTS walks ============================

static void walk_effect_edges() {
    uintptr_t sunit = rd_mod(0x140E17698);
    if (!sunit) return;
    for (int line = 0; line < 128; line++) {
        uintptr_t ent = rd_arena(sunit + 0x58 + (uintptr_t)line * 0x30);
        for (int w = 0; ent && w < 256; w++) {
            if (!committed(ent)) break;
            uintptr_t c = rd_arena(ent + 0x218);                          // +0x218 child list (owner-reciprocity gated)
            for (int k = 0; c && k < 128; k++) {
                if (!committed(c)) break;
                if (rd_arena(c + 0x10) != ent) break;                     // reciprocity broke => stop (garbage/freed)
                guard_region(c, 0x240, 8218, type_of(c));
                c = rd_arena(c + 0x18);
            }
            uint16_t cnt = rd_u16(ent + 0x208);                           // +0x220 slot pool (stride 0x150)
            uintptr_t arr = rd_arena(ent + 0x220);
            if (arr && cnt && cnt <= 256) {
                guard_region(arr, (SIZE_T)cnt * 0x150, 8220, 0);
                for (uint16_t i = 0; i < cnt; i++) {
                    uintptr_t slot = arr + (uintptr_t)i * 0x150;
                    if (!committed(slot)) break;
                    uintptr_t bind = rd_arena(slot + 0x58);
                    guard_region(bind, 0x1000, 8058, type_of(bind));      // binding subobj (+0x198 lives here)
                    uintptr_t ch = rd_arena(slot + 0xe0);
                    for (int j = 0; ch && j < 64; j++) { if (!committed(ch)) break; guard_region(ch, 0x100, 0x80E0, 0); ch = rd_arena(ch + 0x08); }
                }
            }
            ent = rd_arena(ent + 0x20);
        }
    }
}

// standalone sEffect-manager spine (0x140E17A38) — list link-offset UNCONFIRMED; best-effort; never crashes
// (every deref committed-gated). The capture's XM-OBJ map reveals whether the walk reached anything.
static void walk_seffect_spine() {
    uintptr_t mgr = rd_mod(0x140E17A38);
    if (!mgr || !committed(mgr)) return;
    guard_region(mgr, 0x400, 0x17A38, type_of(mgr));
    uintptr_t e = rd_arena(mgr + 0x58);
    for (int w = 0; e && w < 256; w++) {
        if (!committed(e)) break;
        uintptr_t vt = type_of(e);
        SIZE_T span = (vt == 0x140BAE1D0) ? 0x250 : 0x420;
        guard_region(e, span, 0x17A38 + w, vt);
        uint16_t cnt = rd_u16(e + 0x208);
        uintptr_t arr = rd_arena(e + 0x220);
        if (arr && cnt && cnt <= 256) for (uint16_t i = 0; i < cnt && i < 64; i++) { uintptr_t slot = arr + (uintptr_t)i * 0x150; if (committed(slot)) guard_region(rd_arena(slot + 0x58), 0x1000, 0x90058, 0); }
        e = rd_arena(e + 0x20);
    }
}

// ---- dispatch ----
static void guard_scoped_arm() {
    g_range_count = 0; g_pages_guarded = 0; g_skipped_obj = 0; g_skipped_pages = 0; g_oob_obj = 0;
    if (g_active_mode == MODE_CORE) {
        walk_sunit_bodies();
        walk_fighter_subobjs();
        walk_singletons_core();
        walk_render_ctx();
    } else {
        walk_effect_edges();
        walk_seffect_spine();
    }
}
static void guard_scoped_disarm() {
    for (int i = 0; i < g_range_count; i++) guard_one(g_ranges[i].base, g_ranges[i].size, false);
    g_range_count = 0;
}

static LONG CALLBACK veh(EXCEPTION_POINTERS* ep) {
    DWORD code = ep->ExceptionRecord->ExceptionCode;

    // SINGLE_STEP first, UNGATED — an in-flight step must always self-terminate (even mid-disarm), else the
    // thread storms TF or leaves a page guarded forever.
    if (code == (DWORD)EXCEPTION_SINGLE_STEP) {
        void* pend = TlsGetValue(g_tls);
        if (!pend) return EXCEPTION_CONTINUE_SEARCH;            // not our step (e.g. a watchpoint DR)
        if (InterlockedCompareExchange(&g_armed, 0, 0)) {       // re-guard the page only if still capturing
            MEMORY_BASIC_INFORMATION mbi;
            if (VirtualQuery(pend, &mbi, sizeof(mbi)) && mbi.State == MEM_COMMIT) { DWORD old = 0; VirtualProtect(pend, PAGE, mbi.Protect | PAGE_GUARD, &old); }
        }
        TlsSetValue(g_tls, nullptr);
        ep->ContextRecord->EFlags &= ~0x100;                    // clear TF
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    if (code == (DWORD)STATUS_GUARD_PAGE_VIOLATION) {
        uintptr_t addr = (uintptr_t)ep->ExceptionRecord->ExceptionInformation[1];
        if (!(addr >= g_base && addr < g_end)) return EXCEPTION_CONTINUE_SEARCH;   // Not ours (e.g. a stack guard page) — let the owner handle
        // It IS an arena page we guarded; the OS already cleared its guard bit on this fault.
        if (!InterlockedCompareExchange(&g_armed, 0, 0)) return EXCEPTION_CONTINUE_EXECUTION;   // disarm window: clear-and-continue, no re-arm
        ULONG_PTR rw = ep->ExceptionRecord->ExceptionInformation[0];   // 0 read, 1 write, 8 exec
        if (rw != 8) {
            uintptr_t rip = ep->ContextRecord->Rip;
            uintptr_t ida = rip - addr::g_base + IDA_BASE;
            if (ida >= IDA_BASE && ida < IDA_END) {                    // GAME code only
                char vclass = 's';
                if ((addr & 0xFFF) <= 0xFF8) vclass = classify_val(*(uintptr_t*)(addr & ~(uintptr_t)7));
                char line[176];
                int n = snprintf(line, sizeof(line), "XM %llX %c %ld %d %llX %lu %c\n",
                                 (unsigned long long)log_off(addr), rw == 1 ? 'w' : 'r',
                                 (long)g_frame, resim::resim_active() ? PH_RESIM : PH_LIVE,
                                 (unsigned long long)ida, GetCurrentThreadId(), vclass);
                if (n > 0) { emit(line, n); InterlockedIncrement64(&g_logged); }
            }
        }
        TlsSetValue(g_tls, (void*)(addr & ~(PAGE - 1)));
        ep->ContextRecord->EFlags |= 0x100;   // TF — re-guard this page in the #DB after the access completes
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

} // namespace

// IO-lock accessors (suspend.cpp drains these across freeze, exactly like the log lock)
bool try_lock_io() { return TryEnterCriticalSection(&g_cs) != 0; }
void lock_io()     { EnterCriticalSection(&g_cs); }
void unlock_io()   { LeaveCriticalSection(&g_cs); }

void init() {
    g_tls = TlsAlloc();
    InitializeCriticalSection(&g_cs);
    g_veh = AddVectoredExceptionHandler(1, veh);   // front-of-chain
    rblog::write("XRAY-MEM: tracer ready (dormant; F3 cycles MODE_CORE/MODE_EFFECTS, 12-frame capture) veh=%p", g_veh);
}

void arm(int frame_window) {
    if (InterlockedCompareExchange(&g_armed, 0, 0)) return;
    if (g_tls == TLS_OUT_OF_INDEXES) return;
    g_base = arena::base(); g_end = arena::end();
    if (!g_base || g_end <= g_base) { rblog::write("XRAY-MEM: arm failed — arena not ready"); return; }

    SYSTEMTIME st; GetLocalTime(&st);
    const char* mname = (g_active_mode == MODE_CORE) ? "CORE" : "EFFECTS";
    char path[256];
    snprintf(path, sizeof(path), "C:\\Users\\OnyxM\\Downloads\\UMvC3-Monitor\\logs\\xray_mem_%s_%04d%02d%02d_%02d%02d%02d.log",
             mname, st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    g_file = CreateFileA(path, GENERIC_WRITE, FILE_SHARE_READ, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (g_file == INVALID_HANDLE_VALUE) { rblog::write("XRAY-MEM: arm failed — CreateFile err=%lu", GetLastError()); return; }

    char hdr[256];
    int n = snprintf(hdr, sizeof(hdr), "XRAY-MEM-STREAM mode=%s base=0x%llX size=0x%llX window=%d cols=[off rw frame phase rip_ida tid vclass]\n",
                     mname, (unsigned long long)g_base, (unsigned long long)(g_end - g_base), frame_window);
    g_buf_len = 0; emit(hdr, n);

    g_frame = 0; g_frames_left = frame_window; g_logged = 0; g_breaker_prev = 0;
    InterlockedExchange(&g_armed, 1);     // publish before guarding so walk-time faults are logged + re-armed
    guard_scoped_arm();
    rblog::write("XRAY-MEM: ARMED mode=%s for %d frames — %d ranges, %llu/%llu pages; skipped %d obj/%llu pg; out-of-arena(invisible)=%d -> %s",
                 mname, frame_window, g_range_count, (unsigned long long)g_pages_guarded, (unsigned long long)MAX_PAGES,
                 g_skipped_obj, (unsigned long long)g_skipped_pages, g_oob_obj, path);
    g_active_mode = (g_active_mode % MODE_COUNT) + 1;   // next F3 press arms the next mode
}

void disarm() {
    if (!InterlockedCompareExchange(&g_armed, 0, 0)) return;
    guard_scoped_disarm();                 // un-guard first, while g_armed is still 1 so in-window faults are handled
    InterlockedExchange(&g_armed, 0);      // Then stop (any straggler fault now hits the clear-and-continue path)
    EnterCriticalSection(&g_cs);
    flush_locked();
    if (g_file != INVALID_HANDLE_VALUE) { CloseHandle(g_file); g_file = INVALID_HANDLE_VALUE; }
    LeaveCriticalSection(&g_cs);
    rblog::write("XRAY-MEM: DISARMED (logged %lld accesses; out-of-arena objects this run: %d)", (long long)g_logged, g_oob_obj);
}

bool armed() { return InterlockedCompareExchange(&g_armed, 0, 0) != 0; }

void on_frame() {
    if (!InterlockedCompareExchange(&g_armed, 0, 0)) return;
    // fault-rate circuit-breaker: if one frame logged a pathological number of faults (degrading toward the 2s
    // watchdog), auto-disarm early. (A frame that never completes is the hang_detector's job — on_frame can't
    // fire then; this catches the degrading case before it gets there.)
    LONG64 cur = g_logged, delta = cur - g_breaker_prev; g_breaker_prev = cur;
    if (delta > FAULT_BREAKER) { rblog::write("XRAY-MEM: circuit-breaker — %lld faults in one frame, disarming early", (long long)delta); disarm(); return; }
    snapshot_data_scalars();               // value-snapshot the .data sim scalars (cheap; not page-guarded)
    InterlockedIncrement(&g_frame);
    if (InterlockedDecrement(&g_frames_left) <= 0) disarm();
}

} // namespace xray_mem
