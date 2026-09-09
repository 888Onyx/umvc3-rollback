#pragma once
// role.h — netplay instance identity (netplay infrastructure). Which instance am I: P1 or P2?
// Resolution order: (1) UMVC3_ROLLBACK_ROLE env var ("P1"/"P2" — the launch script sets it);
// (2) role=P1|P2 in netplay.cfg next to the exe (survives a Steam relaunch, which drops the env);
// (3) exe-path heuristic (a path containing "umvc3-p2" => P2); (4) default P1. Feeds: monitor_shm per-instance name (the collision fix),
// the net session (who binds 7100 vs 7101), and any future role-based branching.
namespace role {
void init();              // resolve once at DllMain; safe to call before anything else
const char* name();       // "P1" or "P2"
bool is_p2();
}
