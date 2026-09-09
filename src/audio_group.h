#pragma once
#include <cstdint>
#include <cstddef>

// audio_group — SUBSTRATE COHERENCE for the SE-curve tables (crash A).
//
// The SE-curve tables (vtable 0x140BB4690) hold DERIVED interior pointers into a streamed blob body
// (table+0x70 -> blob; table+0x80 = blob+0x48 = the row base crash-A dereferences). Plain page-revert
// is object-unaware: it can revert the table header to frame-N while the blob body is a different frame
// (or vice-versa) => +0x80 reads a torn/zero base. The fix is to force-dirty the whole coherence group
// {table header, blob body, sparse index map} in one save frame so the group reverts atomically to N.
//
// There is no global array of live SE-tables, so we accrete a lock-free birth registry: every table that
// passes through the (already-installed, read-only) SE resolver hook registers itself here. force_dirty_all
// is called at SAVE time (gated by g_substrate_coherence) to dirty every live table's group.
namespace audio_group {

void     init();                                       // arm the registry (T0 + T1)
void     register_table(uintptr_t table);              // T0 (FUN_140688a50 / vtable 0x140BB4690) lock-free publish
void     register_table_t1(uintptr_t table);           // T1 (FUN_1406898e0 / vtable 0x140BB4760) lock-free publish
uint32_t force_dirty_all();                            // SAVE-time: dirty every live T0+T1 table's group; returns # touched
uint32_t live_count();                                 // registry occupancy (diagnostics; T0 + T1)

} // namespace audio_group
