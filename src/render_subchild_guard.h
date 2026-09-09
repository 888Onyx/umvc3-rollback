// render_subchild_guard.h
// Single entry-hook on FUN_140615de0 (render-material draw-submit walk).
//
// The crash (confirmed from a crash dump): FUN_140615de0 @0x14061617E, READ 0x0,
// holder vt 0x140BB0F30 (render material) intact, walking to a null. Six sites in this one
// function do the idiom:
// mov M, [param_1 + slot]; M = render material (slots 0x150/0x158/0x160/0x168)
// mov P, [M + 0x60]; P = render sub-child ptr (first deref OK)
// mov rdx,[P]; rdx = *P = arg2 to FUN_14063e9c0 <- CRASH when P==0
// call FUN_14063e9c0
// After a rollback the material M is reverted to its frame-N state where the render sub-child
// (+0x60) was NULL (not yet built). The walk double-derefs **(M+0x60) without a null guard.
//
// Why this is a principled fix, not a workaround: the CALLEE FUN_14063e9c0 already handles
// param_2==0 ("no draw object" -> default 0xd) at every deref. The
// engine's OWN intended behavior for an absent sub-child is to pass 0; the call-site's argument
// computation just fails to reach it (it double-derefs instead of guarding). We feed the engine
// the exact value its own code is designed to handle. Matches the render-is-an-output-leaf /
// re-derived principle: render "nothing" for the absent sub-child until the engine rebuilds it.
//
// MECHANISM: at entry, for each of the 4 material slots whose +0x60 is NULL, point +0x60 at a
// static zero-qword so **(M+0x60) == 0 (callee's handled path); restore the NULL after orig.
// Read-before-write. Desync-safe: M is a render material (vt 0x140BB0F30, not in gp_crc), +0x60
// is never written inside this function, and we restore to the exact reverted value.
#pragma once
namespace render_subchild_guard {
void init();
long guarded_count();   // how many null sub-children were routed to the callee's handled path
}
