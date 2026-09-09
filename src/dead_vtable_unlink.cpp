// dead_vtable_unlink.cpp — dead-vtable entity unlink
// One job: find entities with invalid vtables, remove from all dispatch lists.
// No NULL-SAFE. No gates. No animation rules. The engine handles its own fields.
//
// History: this module started with 2031 type entries, NULL-SAFE/NULL+GATE offset arrays,
// and animation Rules 1-5. Every subsystem beyond unlink caused corruption:
// - gate_render_base destroyed morph data + bone output on 30+ scene entities
// - off_render_base read past end of small entities into pool padding
// - Rules 1-5 fired on non-model entities, zeroed float data at +0x530
// - NULL-SAFE treated floats as stale pointers, zeroed render parameters
//
// The engine null-checks every field before dereferencing (confirmed in the binary).
// The 60-slot ring provides correct page data. The scene tree hook protects
// render dispatch. Its one remaining job: remove bad-vtable entities from
// all dispatch lists.

#include "dead_vtable_unlink.h"
#include "addr.h"
#include "arena.h"
#include "log.h"
#include "monitor_shm.h"
#include <windows.h>
#include <cstdint>

namespace dead_vtable_unlink {

static bool is_valid_vtable(uintptr_t vt) {
    uintptr_t vt_off = vt - addr::g_base;
    return vt_off < 0xE00000;  // within game module
}

static void unlink_from_scheduler(uintptr_t ent, int line, uintptr_t sunit) {
    // Exact logic from the working unlink code — doubly-linked list removal
    uintptr_t prev = *(uintptr_t*)(ent + 0x18);
    uintptr_t next = *(uintptr_t*)(ent + 0x20);

    // Fix prev's next pointer
    if (prev && arena::is_committed_addr(prev)) {
        *(uintptr_t*)(prev + 0x20) = next;
    } else {
        // Entity is the HEAD — update sUnit line head
        *(uintptr_t*)(sunit + 0x58 + (uintptr_t)line * 0x30) = next;
    }

    // Fix next's prev pointer
    if (next && arena::is_committed_addr(next)) {
        *(uintptr_t*)(next + 0x18) = prev;
    } else {
        // Entity is the TAIL — update sUnit line tail
        *(uintptr_t*)(sunit + 0x50 + (uintptr_t)line * 0x30) = prev;
    }

    // Mark entity as fully dead: state=0, dispatch bits clear, line_id=sentinel
    *(uint32_t*)(ent + 0x10) = (*(uint32_t*)(ent + 0x10) & 0xFFFFF800) | 0x3F8;
    *(uintptr_t*)(ent + 0x18) = 0;
    *(uintptr_t*)(ent + 0x20) = 0;
}

void init() {
    rblog::write("DEAD-VT-UNLINK: initialized (unlink-only mode)");
}

void validate(int phase) {
    uintptr_t sunit = *(uintptr_t*)addr::resolve(0x140E17698);
    if (!sunit) {
        rblog::write("DEAD-VT-UNLINK %s: sUnit is NULL", phase == POST_LOAD ? "POST-LOAD" : "POST-RESIM");
        return;
    }

    int scanned = 0, unlinked = 0;

    for (int line = 0; line < 128; line++) {
        uintptr_t ent = *(uintptr_t*)(sunit + 0x58 + (uintptr_t)line * 0x30);
        int walk = 0;

        while (ent && walk < 512) {
            if (!arena::is_committed_addr(ent)) break;

            uintptr_t next = *(uintptr_t*)(ent + 0x20);  // save before potential unlink
            uintptr_t vt = *(volatile uintptr_t*)ent;
            scanned++;

            if (vt == 0 || !is_valid_vtable(vt)) {
                uintptr_t vt_ida = vt ? (vt - addr::g_base + 0x140000000ULL) : 0;

                rblog::write("DEAD-VT-UNLINK: line %d ent 0x%llX vt=0x%llX",
                    line, (unsigned long long)ent, (unsigned long long)vt_ida);

                monitor_shm::log_write(
                    monitor_shm::g_mon ? monitor_shm::g_mon->current_frame : 0,
                    (PhaseID)(monitor_shm::g_mon ? monitor_shm::g_mon->current_phase : 0),
                    UR_UNLINK, ent, 0x10, vt, 0);

                unlink_from_scheduler(ent, line, sunit);
                unlinked++;
            }

            ent = next;
            walk++;
        }
    }

    rblog::write("DEAD-VT-UNLINK %s: scanned %d entities, unlinked %d",
        phase == POST_LOAD ? "POST-LOAD" : "POST-RESIM", scanned, unlinked);

    if (monitor_shm::g_mon) {
        monitor_shm::g_mon->entities_scanned = (uint32_t)scanned;
        monitor_shm::g_mon->entities_nulled  = (uint32_t)unlinked;
        monitor_shm::g_mon->entities_unknown = 0;
        monitor_shm::g_mon->anim_fixed       = 0;
    }
}

} // namespace dead_vtable_unlink
