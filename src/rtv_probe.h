#pragma once
// rtv_probe — RTV/DSV surface refcount-neutral resim fix (per-resim ctor-set gate) + assertions.
namespace rtv_probe {
void init();            // create the hooks (call inside resim::init before MH_EnableHook(MH_ALL_HOOKS))
void on_resim_start();  // clear the per-resim ctor set S (call when g_resim_active is set true)
void preserve_save();   // RENDER-DOMAIN PRESERVE: snapshot live RTV/DSV +0x20 handles before arena::load
void preserve_restore();// restore the live +0x20 over the reverted-frame-N word after arena::load + null destroyed-wrapper stale surfs
void set_destroyed_fix(bool on);  // FRESH-FRAME GAP A/B: on (default) = null reverted-alive dead wrappers' stale +0x20
void report();          // FIX #2: RTV-EPOCH-SET stats (marked/consumed/fresh-frame-gap-closed) — throttled heartbeat
}
