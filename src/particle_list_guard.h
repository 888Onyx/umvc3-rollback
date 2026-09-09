#pragma once
// particle_list_guard — domain-valid-or-null on a leaf particle/effect list STRUCTURE.
//
// The CRASH (0x140836876, a WRITE — why "leaves self-heal" didn't save it): FUN_1408366a0 (and its 3 byte-identical
// siblings 0x140836aa0 / 0x1408368a0 / 0x1408364a0, one per particle "kind", all dispatched from 0x140839820) is a
// per-render-node particle lifetime tick: it walks a source list (head mgr+0xe0 / tail mgr+0xe8), decrements each
// node's countdown, and moves EXPIRED nodes onto a "retired" dest list (head mgr+0xf0 / tail mgr+0xf8). The append is
// `new->next=tail; *(tail+8)=new; tail=new`. After a rollback the dest tail *(mgr+0xf8) can point at a FREED node, so
// `mov %rbx,0x8(%rax)` (0x140836876) WRITES through a dangling pointer and faults. A read of a dead leaf self-heals
// (garbage VALUE, re-derived); a WRITE cannot (it faults, or silently corrupts). So the leaf philosophy still applies —
// just before the write, on the list STRUCTURE: if the tail is a dead node, reset the (already-broken) leaf list to
// empty so the append takes the engine's own empty-list branch (0x14083677e) and the list re-derives.
//
// LEAF (RE-verified, high confidence): mgr is reached via *(renderNode+0x10) in the Material/mesh update path; it is
// in none of gp_crc's hashed ranges (no fighter seg, no named singleton). So resetting it is desync-safe. The node has
// no vtable (offsets 0/8 are the intrusive links) ⇒ the husk test is the address-keyed quarantine set (via id_oracle),
// not a vtable check. Guard fires only engine-on + only on a proven husk pointer ⇒ pure no-op in clean play, and it
// only ever resets a list that is already corrupt (its tail is freed). Blast radius: the 4 tick fns have one caller
// each (the shared dispatcher, 26 owners) and the guard only touches mgr's own list invariant ⇒ safe for all owners.
namespace particle_list_guard {
    void init();            // MH_CreateHook the 4 sibling tick fns (resim.cpp enables MH_ALL_HOOKS once, after all inits)
    long guarded_count();   // times a husk list pointer routed the tick to the empty-list path (diagnostic counter)
}
