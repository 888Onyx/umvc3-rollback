#pragma once
// draw_probe — read-only probe for the cDraw-manager child-collection stale-restore UAF (FUN_140200f50).
namespace draw_probe { void init(); void init_dlclean(); long reconfig_count(); long torn_repaired(); }
