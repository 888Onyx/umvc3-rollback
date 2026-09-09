#pragma once
#include <cstdint>

// rdspine — render/Default-allocator identity SHADOW (idspine's twin for the NON-MtScalable allocator).
//
// The GAP IT MEASURES: idspine hooks only the MtScalable allocator (FUN_1404ca650/FUN_1404cb350).
// A whole-game lifecycle sweep found the entire remaining crash family routes through one uncovered chokepoint:
// the "Default" allocator singleton DAT_140d76540 (vtable 0x140b819c0), alloc=FUN_1404C9460 / free=FUN_1404C9A00.
// Every param_7=0 DTI type lands there: nDraw::Material* (the team-hyper crash), model children, sRender present/
// retirement entries, uShot* projectiles, sCollision::Collider, uStgObj* stage objects. idspine is blind to it
// (it gates on is_arena_addr at the carve hook), so these objects get NO identity stamp => recent_free=0, id_miss=390.
//
// This module is SHADOW only: it hooks the two Default chokepoints and stamps {user,serial,birth,death,in_arena}.
// Zero behavior change (no defer, no game writes). It answers the open questions before any Default-allocator
// keep-alive ships:
// (1) IN-ARENA vs CRT — the crash forensic shows the material in-arena (reverted) but the map calls Default "CRT".
// Resolve empirically: is each Default block is_arena_addr? This DECIDES desync-safety — a CRT (non-arena)
// pointer sitting in a gp_crc-hashed singleton range is hashed BY VALUE (crc_range_ptr_aware) and keep-alive
// cannot fix that; an in-arena pointer is skipped (safe).
// (2) BIRTHS == DEATHS+LIVE — if any Default-backed pool frees in BULK (reset) instead of per-call FUN_1404C9A00,
// keep-alive never engages (birth with no death). Gate any keep-alive on births~=deaths+live.
// (3) COVERAGE — does the crashing block now HAVE an rdspine record (closes recent_free=0 / id_miss=390)?
namespace rdspine {
    void init();      // MH_CreateHook the Default alloc/free chokepoints (SHADOW); caller enables hooks
    // identity lookup for the crash forensic (read-only). fills birth/death/serial + in_arena(0/1); false if unknown.
    // size (optional, Property-4 extent) defaulted so existing callers are unaffected.
    bool lookup(uintptr_t user, int* birth_frame, int* death_frame, int64_t* serial, int* in_arena, int* size = nullptr);
    void report();    // RDSPINE stats line (births/reuses/deaths/live/full + in_arena vs crt split)
    // STAGE B A/B: on (default) = route Default malloc into the in-arena heap zone (byte-reverted => alive-at-N fix).
    // off (stage_b.flag) = legacy CRT malloc (Default blocks out-of-arena, alive-at-N unprotected).
    void set_stage_b(bool on);
}
