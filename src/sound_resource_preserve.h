#pragma once
// sound_resource_preserve — object-granular PRESERVE for slab-packed in-arena sound RESOURCE objects.
// Closes the sound-container crash (live sSound container -> reverted rSoundSource -> garbage vtable). See the .cpp header.
#include <cstdint>
namespace sound_resource_preserve {
    void init();      // resolve the sound-resource vtable set + MH_CreateHook the resource refcount-inc (caller enables)
    void save();      // PH_SAVE (before arena::load): snapshot every live sound-resource object's bytes
    void restore();   // PH_POST_LOAD (after arena::load): write the live bytes back over the reverted pages
    void report();    // counters
    bool is_sound_vtable(uintptr_t vt);   // true if vt is a resolved sound-resource vtable (for the quarantine audio-exclude)
}
