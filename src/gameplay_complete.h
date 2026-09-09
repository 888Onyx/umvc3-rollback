#pragma once
// gameplay_complete — the GAMEPLAY completeness ORACLE (measure before fixing).
//
// The taxonomy: gameplay (gp_crc-hashed) state can never be domain-valid-or-null'd (a null = a divergence the other
// peer doesn't compute = DESYNC); it must be restore-faithful (complete coherent snapshot + stable identity). The
// prediction: pure-gameplay dangling crashes are RARE, because the authoritative hashed set is restored to a coherent
// frame-N cut — so a gameplay dangling pointer is a SNAPSHOT-COMPLETENESS bug (a gameplay edge to something the capture
// didn't fully own), fixed by completing the capture (keep-alive/extend the coherent set), never by nulling. The
// corpus bears this out: across ~19 named crashes exactly one is gameplay-domain (fighter +0x110 array -> freed assist
// child), and it was fixed by KEEP-ALIVE, not a null.
//
// So before building any gameplay fix we MEASURE (oracle before fix). This is a READ-ONLY
// POSTLOAD pass: walk the exact gp_crc gameplay roots (sUnit lines 7-8 fighters, the two hashed strips — the +0x110
// Material/child array and the +0x538/+0x11B0 bone arrays) and ask id_oracle::check(ptr, N) whether each gameplay
// pointer field points at a live same-identity object at the restore frame N. Any DEAD / BORN_AFTER_N / ABA_RECYCLED
// verdict = a GAMEPLAY-COMPLETENESS-GAP: logged (counter + rate-limited detail), never written, never nulled, never
// severed. If a gap is ever observed the correct response is to complete the capture; until one is, "we believe
// gameplay is coherent" becomes a measured GAP=0. Cheap (<=9 fighters x ~16 slots + 2 ptrs), safe to run every rollback.
namespace gameplay_complete {
    void run(int target_frame);   // POSTLOAD, read-only: check the two hashed gameplay strips against id_oracle
    void report();                // GAMEPLAY-COMPLETENESS heartbeat line (throttled; never per-frame)
    long gap_count();             // total gaps observed this session (long-run gate: want 0)
}
