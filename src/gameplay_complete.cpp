// gameplay_complete.cpp — see gameplay_complete.h. READ-ONLY POSTLOAD measurement of gameplay completeness.
// Walks the exact gp_crc fighter enumeration (compute_fighter_segs) so it measures precisely the hashed set.
#include "gameplay_complete.h"
#include "id_oracle.h"
#include "addr.h"
#include "arena.h"
#include "log.h"
#include <windows.h>
#include <cstdint>

namespace gameplay_complete {

static volatile LONG64 c_runs = 0, c_ptrs_checked = 0, c_gaps = 0;
static volatile LONG64 c_gap_strip1 = 0, c_gap_strip2 = 0;      // which strip
static volatile LONG64 c_dead = 0, c_born = 0, c_aba = 0, c_ext = 0;   // gap verdict histogram (ext = unexpected)

static inline bool rd(uintptr_t a) { return a > 0x10000ULL && arena::is_committed_addr(a); }

// Classify one gameplay pointer's verdict; log + count if it's a completeness gap. READ-ONLY.
static void probe_field(uintptr_t holder, uintptr_t ptr, int N, const char* strip, volatile LONG64* strip_ctr) {
    if (!ptr) return;                                            // an empty gameplay slot is not a gap
    _InterlockedIncrement64(&c_ptrs_checked);
    // check_data, not check: these referents are DATA (bone/matrix arrays have no vtable; Material array elems are
    // covered via liveness, not the vtable-garbage heuristic which false-flagged float data as garbage 375 times in one run). And
    // a held-husk (quarantine-deferred) referent is kept ALIVE for this gameplay edge ⇒ safe, not a gap. Real gaps only:
    // uncommitted / born>N / died<=N-and-not-held.
    id_oracle::Verdict v = id_oracle::check_data(ptr, N);
    // ALIVE_SAME = coherent. UNKNOWN = liveness-unproven-but-not-dead (fail-open, not a gap). EXTERNAL on an in-arena
    // gameplay field is UNEXPECTED (log it, but it's not a dangling-deref gap). The real gaps are the proven-bad three.
    bool gap = (v == id_oracle::DEAD || v == id_oracle::BORN_AFTER_N || v == id_oracle::ABA_RECYCLED);
    if (v == id_oracle::EXTERNAL) _InterlockedIncrement64(&c_ext);
    if (!gap) return;
    switch (v) {
        case id_oracle::DEAD:         _InterlockedIncrement64(&c_dead); break;
        case id_oracle::BORN_AFTER_N: _InterlockedIncrement64(&c_born); break;
        case id_oracle::ABA_RECYCLED: _InterlockedIncrement64(&c_aba);  break;
        default: break;
    }
    _InterlockedIncrement64(strip_ctr);
    LONG64 n = _InterlockedIncrement64(&c_gaps);
    if (n <= 32 || (n % 128) == 0) {
        bool w = rblog::is_suppressed(); rblog::suppress(false);
        rblog::write("GAMEPLAY-COMPLETENESS-GAP #%lld [%s]: holder=0x%llX ptr=0x%llX verdict=%s at N=%d "
                     "(a gameplay edge to a non-restored referent — the fix is to COMPLETE THE CAPTURE/keep-alive, NEVER null)",
                     (long long)n, strip, (unsigned long long)holder, (unsigned long long)ptr,
                     id_oracle::verdict_name(v), N);
        rblog::suppress(w);
    }
}

void run(int target_frame) {
    uintptr_t sunit_p = addr::resolve(0x140E17698ULL);
    if (!sunit_p) return;
    uintptr_t sunit = *(uintptr_t*)sunit_p;
    if (!sunit || !arena::is_committed_addr(sunit)) return;
    _InterlockedIncrement64(&c_runs);
    // Exact gp_crc fighter walk (compute_fighter_segs in gp_crc.cpp) — same head (+0x58+line*0x30), same
    // next (+0x20), same walk cap (16), same fighter filter (bc in [1,300] + full-span committed). Measures precisely
    // the hashed gameplay set, so a gap is unambiguously a GAMEPLAY-domain completeness failure.
    for (int line = 7; line <= 8; line++) {
        uintptr_t ent = *(uintptr_t*)(sunit + 0x58 + (uintptr_t)line * 0x30);
        int walk = 0;
        while (ent && walk < 16 && arena::is_committed_addr(ent)) {
            uint32_t bc = *(uint32_t*)(ent + 0x530);
            bool span_ok = arena::is_committed_addr(ent + 0x2000) && arena::is_committed_addr(ent + 0x4000) &&
                           arena::is_committed_addr(ent + 0x6000) && arena::is_committed_addr(ent + 0x63FF);
            if (bc != 0 && bc <= 300 && span_ok) {
                // ── STRIP 1: the fighter +0x110/+0x118 dynamic Material/child array (the gameplay crash's array;
                // hashed pointer+count, elements are the gameplay referents that were freed-in-window) ──
                if (rd(ent + 0x110) && rd(ent + 0x118)) {
                    uintptr_t base = *(uintptr_t*)(ent + 0x110);
                    uint32_t   cnt  = *(uint32_t*)(ent + 0x118); if (cnt > 4096) cnt = 0;
                    if (base && rd(base) && cnt && rd(base + (uintptr_t)(cnt - 1) * 8)) {
                        for (uint32_t k = 0; k < cnt; k++)
                            probe_field(ent, *(uintptr_t*)(base + (uintptr_t)k * 8), target_frame, "strip1-array", &c_gap_strip1);
                    }
                }
                // ── STRIP 2: the bone arrays — +0x538 (bone array, count +0x530) and +0x11B0 (bone output) ──
                if (rd(ent + 0x538)) probe_field(ent, *(uintptr_t*)(ent + 0x538), target_frame, "strip2-bones",  &c_gap_strip2);
                if (rd(ent + 0x11B0)) probe_field(ent, *(uintptr_t*)(ent + 0x11B0), target_frame, "strip2-output", &c_gap_strip2);
            }
            ent = *(uintptr_t*)(ent + 0x20);
            walk++;
        }
    }
}

void report() {
    if (!c_runs) return;
    bool w = rblog::is_suppressed(); rblog::suppress(false);
    rblog::write("GAMEPLAY-COMPLETENESS: rollbacks=%lld ptrs_checked=%lld GAP=%lld {strip1=%lld strip2=%lld} "
                 "verdicts{dead=%lld born_after_N=%lld aba=%lld external(unexpected)=%lld} — GAP=0 => gameplay snapshot is a complete coherent cut (restore-faithful holds; no fix needed)",
                 (long long)c_runs, (long long)c_ptrs_checked, (long long)c_gaps, (long long)c_gap_strip1, (long long)c_gap_strip2,
                 (long long)c_dead, (long long)c_born, (long long)c_aba, (long long)c_ext);
    rblog::suppress(w);
}

long gap_count() { return (long)c_gaps; }

} // namespace gameplay_complete
