#pragma once
#include <cstdint>
// page_free — content-aware page correction. Not a replacement for arena::load (an earlier version tried a partial
// structural restore in its place and crashed). Instead: keep whole-page revert as the complete + coherent substrate
// (it gets RESTORE, the allocator, and the object lifecycle right for free), and make it AWARE of its contents —
// correct only the two field classes the blind revert gets wrong, using the manifest:
//
// EDGE (first half) — page-revert reinstates a stale pointer to a freed/reused object => the stale-reference crash
// (0x14080D44D). FIX: after the revert, for each manifest EDGE field, if its pointer is
// PROVABLY STALE (target not a live vtable'd object — idspine + vtable check), SEVER it
// (null). Safe by construction: we only touch edges already pointing at garbage, which
// would crash if dereferenced; nulling lets the engine's null-guards skip them.
// REBUILD (second half)— page-revert reverts a derived binding to its PRE-INIT 0 (set after the save snapshot)
// => the consumer reads NULL and dies (+0x50/+0x198). FIX: LEAVE-LIVE — capture the
// REBUILD fields' live (post-init) values before the revert, write them back after. The
// consumer reads a valid pointer; orig() re-derives them during resim anyway.
//
// FLAG-GATED (F11). ON = corrections applied after arena::load. OFF = plain page-revert.
// Pages are not deleted — they are corrected per the manifest. (Not yet validated; A/B via the gp_crc oracle +
// crash behavior.)
namespace page_free {
void init();
bool enabled();
void toggle();                      // F11
void pre_load(int frame);           // Before arena::load: capture live REBUILD-field values (leave-live half)
void post_load(int frame);          // After arena::load: write back REBUILD (leave-live) + SEVER stale EDGE pointers
void report();
}
