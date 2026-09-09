// sound_edge_reconcile.cpp — null-on-restore for STALE sound-channel voice edges.
//
// The bug: the sound UpdateThread (MtThread worker)
// crashes at rip=0x1405BEFE5 = `call *0x80(*(node+0x18))` inside FUN_1405bee80 (channel-node process virtual,
// vtable 0x140bad4b0 slot +0x88). node = an in-arena per-voice sound channel node (size 0x358, game-heap,
// 32 of them held at sChannelManager(*(sSound+0x38))+0x08). node+0x18 is a NON-OWNING ALIAS to the active
// IXAudio2SourceVoice (an OUT-OF-ARENA XAudio2 COM object); +0x20/+0x28/+0x30 are the OWNED voices the node's
// dtor (FUN_1405c7040) releases via vtable+0x90.
//
// Why (revert-split external edge — not torn-save, not object-corruption): arena::load restores node+0x18..+0x30
// byte-faithfully to the save frame (snap==live). But during the post-rollback window (the crash was 180 frames
// out) the engine legitimately DestroyVoice'd + recreated those voices, so XAudio2 freed/reused the out-of-arena
// COM block. The restored pointer now aliases a freed-and-reused block: still committed, but its vtable qword is
// garbage => `*(*(node+0x18)+0x80)` derefs a wild target => AV => the worker dies inside the sound CS
// [sSound+0x40]+0x49d0 => main later blocks Entering that CS => the deadlock. Object-preserve cannot help (the
// in-arena bytes are already correct); the OUT-OF-ARENA pointee is the stale half.
//
// The FIX (principle: external edge => null + re-acquire-by-identity; sound = pure output leaf, re-derived): at
// PH_POST_LOAD, for each channel node, validate each voice pointer (committed + readable vtable + readable call
// target); NULL the stale ones. FUN_1405bee80's entry guard `if (*(node+0x18)!=0 && *(sSound+0x40)!=0)` then
// short-circuits the whole faulting body, and the engine's own recreate path rebuilds the voice on the next
// sound tick. Nulling the owners +0x20/+0x28/
// +0x30 also stops the node dtor from DestroyVoice'ing a dead handle (double-free). VALIDATED so we never null a
// genuinely-live voice (no audio churn for the common case). Bounded: <=32 nodes x 4 fields VirtualQuery/rollback.
#include "sound_edge_reconcile.h"
#include "addr.h"
#include "log.h"
#include "resim.h"
#include <windows.h>
#include <cstdint>

namespace sound_edge_reconcile {

static volatile long g_enabled = 1;
static int64_t c_runs = 0, c_nulled = 0, c_nodes = 0;

static inline bool canon(uintptr_t p) { return p >= 0x10000 && p < 0x7FFFFFFFFFFFULL; }

// PERF: per-pass VirtualQuery memoization. reconcile() runs INSIDE the freeze() window (freeze suspended every
// thread before the restore steps), so no thread can VirtualAlloc/Free/Protect — the process memory map is STABLE
// for the entire pass ⇒ VirtualQuery on the same region always returns the same result. The 32 nodes × 4 voice
// edges × up to 3 checks each collapse onto a handful of distinct regions (all voices of a class share one vtable
// region, etc.), so caching {base,end,ok} turns the ~hundreds of NtQueryVirtualMemory syscalls (the measured
// ~50-93ms — the arena's page-granular write-watch + heap-zone fragment the VAD tree, making each VirtualQuery
// abnormally slow) into a few. Pure memoization: identical validity, far fewer syscalls. Reset at reconcile() entry.
struct QRegion { uintptr_t base, end; bool ok; };
static QRegion g_qr[64];
static int     g_qr_n = 0;
static int64_t c_vq = 0, c_vq_hit = 0;   // syscalls issued vs cache hits (proves the collapse)
static inline void qcache_reset() { g_qr_n = 0; }

// committed + readable for `len` bytes (out-of-arena COM objects => VirtualQuery, memoized per frozen pass).
static bool committed_readable(uintptr_t p, size_t len) {
    if (!canon(p)) return false;
    for (int i = 0; i < g_qr_n; i++)                                  // memoized: stable within the frozen pass
        if (p >= g_qr[i].base && p < g_qr[i].end) { c_vq_hit++; return g_qr[i].ok && (p + len) <= g_qr[i].end; }
    MEMORY_BASIC_INFORMATION mbi;
    c_vq++;
    if (!VirtualQuery((void*)p, &mbi, sizeof(mbi))) return false;     // unmapped — rare; don't cache (no region)
    uintptr_t rbase = (uintptr_t)mbi.BaseAddress, rend = rbase + mbi.RegionSize;
    DWORD rw = PAGE_READONLY|PAGE_READWRITE|PAGE_EXECUTE_READ|PAGE_EXECUTE_READWRITE|PAGE_WRITECOPY|PAGE_EXECUTE_WRITECOPY;
    bool ok = ((mbi.State & MEM_COMMIT) != 0) && ((mbi.Protect & rw) != 0) && !(mbi.Protect & (PAGE_GUARD|PAGE_NOACCESS));
    if (g_qr_n < 64) g_qr[g_qr_n++] = { rbase, rend, ok };            // cache the whole region (pos + neg)
    // ensure [p, p+len) stays within this committed region (don't straddle into an unmapped neighbor)
    return ok && (p + len) <= rend;
}

// a voice pointer is LIVE iff the exact deref chain the crash performs is safe: voice readable, its vtable
// readable through slot +0x90 (the dtor/process slots), and the +0x80 call target is itself mapped.
static bool voice_live(uintptr_t voice) {
    if (!committed_readable(voice, 8)) return false;
    uintptr_t vtbl = *(uintptr_t*)voice;
    if (!committed_readable(vtbl, 0x98)) return false;            // need slots up to +0x90
    uintptr_t target80 = *(uintptr_t*)(vtbl + 0x80);              // the exact slot 0x1405BEFE5 calls
    if (!committed_readable(target80, 16)) return false;
    return true;
}

// reconcile one channel node's 4 voice edges; returns count nulled.
static int reconcile_node(uintptr_t node) {
    int nulled = 0;
    const uintptr_t offs[4] = { 0x18, 0x20, 0x28, 0x30 };
    for (int i = 0; i < 4; i++) {
        uintptr_t* slot = (uintptr_t*)(node + offs[i]);
        uintptr_t voice = *slot;
        if (voice && !voice_live(voice)) { *slot = 0; nulled++; }
    }
    return nulled;
}

void reconcile() {
    if (!g_enabled || !resim::engine_enabled()) return;
    c_runs++;
    qcache_reset();   // PERF: fresh VirtualQuery memo per pass (map is stable for the frozen window)
    uintptr_t sSound = *(uintptr_t*)addr::resolve(0x140E18520);
    if (!canon(sSound)) return;
    uintptr_t chanmgr = *(uintptr_t*)(sSound + 0x38);
    if (!canon(chanmgr)) return;
    uintptr_t want_vt = addr::resolve(0x140BAD4B0);   // the 0x358 channel-node vtable (the proven crash class)
    int nodes = 0, nulled = 0, garbage = 0;
    // 32 pointers at chanmgr+0x08 -> 0x358 channel nodes (ctor FUN_1405bc450 loop < 0x20)
    for (int i = 0; i < 32; i++) {
        uintptr_t node = *(uintptr_t*)(chanmgr + 0x08 + (uintptr_t)i * 8);
        if (!canon(node)) continue;
        if (*(uintptr_t*)node != want_vt) {
            // LANDMINE DETECTOR: a non-null channel slot whose object's vtable is not the sound vtable = the node
            // was reverted to pre-birth/garbage (born-after-target) — reconcile skips it but the sound WORKER still
            // processes it via vtable+0x88 => garbage vtable => CFG __fastfail (the silent crash). Name it here.
            if (committed_readable(node, 8)) {
                uintptr_t gv = *(uintptr_t*)node;
                bool was = rblog::is_suppressed(); rblog::suppress(false);
                rblog::write("SND-VALID: channel slot %d node=0x%llX has NON-SOUND vtable 0x%llX (want 0x%llX) — born-after-target/garbage; sound worker will fault on it",
                             i, (unsigned long long)node, (unsigned long long)gv, (unsigned long long)want_vt);
                rblog::suppress(was); garbage++;
            }
            continue;
        }
        nodes++; nulled += reconcile_node(node);
    }
    // also sweep the 8 streaming voices (vt 0x140bad660 at sSound+0x1756c, stride 0xB30, P=*(slot-0x5C))
    {
        uintptr_t vbase = sSound + 0x1756c, pvt = addr::resolve(0x140BAD660);
        for (int i = 0; i < 8; i++) {
            uintptr_t pslot = vbase + (uintptr_t)i * 0xB30 - 0x5C;
            if (!committed_readable(pslot, 8)) continue;
            uintptr_t P = *(uintptr_t*)pslot;
            if (!canon(P) || !committed_readable(P, 8)) continue;
            uintptr_t v = *(uintptr_t*)P;
            if (v != pvt) {
                bool was = rblog::is_suppressed(); rblog::suppress(false);
                rblog::write("SND-VALID: streaming voice %d P=0x%llX has NON-SOUND vtable 0x%llX (want 0x%llX) — born-after-target/garbage",
                             i, (unsigned long long)P, (unsigned long long)v, (unsigned long long)pvt);
                rblog::suppress(was); garbage++;
            }
        }
    }
    if (garbage) { bool was = rblog::is_suppressed(); rblog::suppress(false);
        rblog::write("SND-VALID: %d garbage sound object(s) post-rollback — the silent-__fastfail landmine", garbage);
        rblog::suppress(was); }
    c_nodes += nodes; c_nulled += nulled;
    if (c_runs <= 5 || (c_runs & 63) == 0) {   // throttled: prove the VirtualQuery collapse live (survives a hard close)
        bool was = rblog::is_suppressed(); rblog::suppress(false);
        rblog::write("SND-EDGE-RECONCILE[run %lld]: %d nodes, %d distinct regions = %d VirtualQuery syscalls this pass",
                     (long long)c_runs, nodes, g_qr_n, g_qr_n);
        rblog::suppress(was);
    }
    if (nulled) {
        bool was = rblog::is_suppressed(); rblog::suppress(false);
        rblog::write("SND-EDGE-RECONCILE: nulled %d stale voice edge(s) across %d channel nodes (prevents 0x1405BEFE5)",
                     nulled, nodes);
        rblog::suppress(was);
    }
}

void report() {
    rblog::write("SND-EDGE-RECONCILE: runs=%lld nodes-scanned=%lld stale-edges-nulled=%lld | VirtualQuery syscalls=%lld cache-hits=%lld (%.0f%% collapsed)",
                 (long long)c_runs, (long long)c_nodes, (long long)c_nulled,
                 (long long)c_vq, (long long)c_vq_hit,
                 (c_vq + c_vq_hit) ? 100.0 * (double)c_vq_hit / (double)(c_vq + c_vq_hit) : 0.0);
}

} // namespace sound_edge_reconcile
