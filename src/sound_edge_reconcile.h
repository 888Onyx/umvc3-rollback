#pragma once
// sound_edge_reconcile — null-on-restore for STALE sound-channel voice EDGES (the sound-container hang fix).
// At PH_POST_LOAD, after arena::load restores the in-arena channel nodes, their +0x18/+0x20/+0x28/+0x30
// voice pointers may alias OUT-OF-ARENA IXAudio2SourceVoice COM objects that were destroyed/reused since the
// save frame (revert-split external edge). We validate each and NULL the stale ones so the engine re-derives.
namespace sound_edge_reconcile {
    void reconcile();   // call once per rollback at PH_POST_LOAD (after arena::load, before workers resume)
    void report();
}
