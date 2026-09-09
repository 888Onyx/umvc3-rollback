#pragma once
#include <cstdint>
// provenance — the sub-page object index for typed-object rollback. Builds a spatial index
// of every LIVE allocator block ({base,size,serial} from idspine) so any arena address resolves to its OWNING object
// + type + generation. This demotes the 4KB page to dumb backing store: restore/preserve operates per OBJECT.
// resolve_user finds the real user/object pointer via the allocator's back-offset invariant (*(user-8)==user_off,
// from block = user - *(user-8)) instead of a hardcoded +0x50, and classifies each block TYPED/DATA/UNRESOLVED.
namespace provenance {

enum { K_TYPED = 0, K_DATA = 1, K_UNRESOLVED = 2 };

struct Owner {
    uintptr_t base;     // allocator block base (idspine key)
    uint32_t  size;     // block extent in bytes (incl header)
    int64_t   serial;   // idspine birth generation (identity coordinate for the quarantine)
    uintptr_t user;     // resolved user/object pointer (vtable@+0); 0 if unresolved
    uint16_t  user_off; // user - base (the back-offset; 0 if unresolved)
    uint8_t   kind;     // K_TYPED (module vtable) / K_DATA (self-consistent, no vtable) / K_UNRESOLVED
    uintptr_t vtable;   // *(user), 0 if none
    uint64_t  ida_vt;   // vtable in IDA space, 0 if not a umvc3 module vtable
    const char* type;   // typegraph name, "(non-reflected)" / "(data)" / "(unresolved)"
};

void build();                                                 // snapshot idspine live blocks -> sorted index
bool owner_of(uintptr_t addr, Owner* out);                    // any in-arena addr -> owning object (false if none)
bool object_at(int i, Owner* out);                            // iterate the index [0,count): i-th object (false if oob)
int  in_range(uintptr_t lo, uintptr_t hi, Owner* out, int max); // objects overlapping [lo,hi) (e.g. one page)
int  count();                                                 // live objects in the current index
void coverage();                                              // build + the coverage ledger (typed/data/UNRESOLVED + off histogram)

} // namespace provenance
