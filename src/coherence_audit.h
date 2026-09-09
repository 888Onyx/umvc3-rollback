#pragma once
// coherence_audit — the POSTLOAD invariant-violation map. Domain-agnostic. Enumerates every live heap object (via all 64
// allocators' alloc-lists), and for every ClassRef pointer field checks the referent against the coherence invariants:
// L_REFERENT_DEAD — target not canonical / unreadable (freed-and-unmapped dangling edge)
// L_REFERENT_ZEROED — target readable but its vtable slot is 0 (object freed-in-place / zeroed)
// L_REFERENT_BADVT — target readable, vtable non-zero but not a umvc3 module vtable and not another module
// (MEM_IMAGE) => garbage/type-confusion (a slab reused as non-object data)
// Every violation is aggregated by (holder_vtable, field_offset, invariant) so the output is a WORKLIST of coherence
// GAPS (a type's field that the restore leaves incoherent), not a pile of crash instances. EXTERNAL edges (target
// vtable in another loaded module, e.g. XAudio2/D3D COM) are counted separately, not flagged. Read-only.
namespace coherence_audit {
    void run(const char* tag);   // call at POSTLOAD (after all restores). Logs the worklist.
    void set_off(bool v);
    bool is_off();

    // ── EDGE REPAIRER (parent->freed-child; checker -> repairer, the move that closed the free-list root cause) ─────────────
    // A surviving holder pointing to an invalid referent (dead/zeroed/badvt) crashes when it derefs/ticks it. The
    // repair makes the restored graph satisfy "every referent is a valid object, or null" — desync-free because
    // every referent pointer is an arena address (gp_crc skips arena ptrs). Two passes at POSTLOAD (frozen):
    // CONTAINER pass (default ON): for dynamic child-arrays (e.g. vt 0x140a7b2e0 +0x110 array / +0x118 count),
    // walk the elements and NULL any child whose vtable is invalid. The iterators guard null (if(child!=0)),
    // so this is the proven, safe fix for the parent->freed-child crash family.
    // FIELD pass (default OFF; gp_crc-watched A/B): NULL fixed typegraph pointer slots whose referent is invalid.
    // Off by default because a typegraph mis-marked scalar could be nulled => drift; arm only with the F4 oracle.
    // Always reports the COH-GAP family (read-only discovery) so the whole worklist is visible in one run.
    void init();                         // MH_CreateHook the container ctors (register-by-construction enumeration)
    void repair(int frame);
    void set_container_repair(bool v);   // ON by default (verified, desync-free)
    void set_field_repair(bool v);       // OFF by default (drift risk; expand per-edge after gp_crc verification)
    bool container_repair_on();
    bool field_repair_on();
}
