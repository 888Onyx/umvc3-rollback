// role.cpp — see role.h.
#include "role.h"
#include <windows.h>
#include <cstring>
#include <cstdio>
#include <cctype>

namespace role {

static char g_name[4] = "P1";
static bool g_p2 = false;
static bool g_init = false;

// role=P1|P2 straight out of netplay.cfg. Deliberately a standalone parse rather than net_config::get(): role is
// consulted by the very first log line, long before net_config is initialised, so taking that dependency would be an
// init-order trap. A dozen lines of duplication buys immunity from it.
//
// Why this exists: role used to come only from the UMVC3_ROLLBACK_ROLE env var, which assumes the launcher's
// environment reaches the game process. On a Steam-DRM title that assumption breaks the moment the launch bounces
// through Steam — Steam re-spawns the exe with its OWN environment and our variable is gone, so the game silently
// defaults to P1. Both peers then come up as P1 and the session can never pair. netplay.cfg travels with the match
// rather than with the process environment, so it survives any relaunch path.
static int role_from_cfg() {          // 1 = P2, 0 = P1, -1 = not specified
    char path[MAX_PATH];
    if (!GetModuleFileNameA(NULL, path, MAX_PATH)) return -1;
    char* slash = strrchr(path, '\\');
    if (!slash) return -1;
    slash[1] = 0;
    strncat(path, "netplay.cfg", MAX_PATH - strlen(path) - 1);

    FILE* f = fopen(path, "r");
    if (!f) return -1;
    int found = -1;
    char line[256];
    while (fgets(line, sizeof(line), f)) {
        char* p = line;
        while (*p == ' ' || *p == '\t') p++;
        if (*p == '#' || *p == ';') continue;
        if (_strnicmp(p, "role", 4) != 0) continue;
        char* eq = strchr(p, '=');
        if (!eq) continue;
        char* v = eq + 1;
        while (*v == ' ' || *v == '\t') v++;
        found = (_strnicmp(v, "P2", 2) == 0) ? 1 : 0;
        break;
    }
    fclose(f);
    return found;
}

void init() {
    if (g_init) return;
    g_init = true;
    char env[16] = {0};
    if (GetEnvironmentVariableA("UMVC3_ROLLBACK_ROLE", env, sizeof(env)) > 0) {
        if (_stricmp(env, "P2") == 0) { g_p2 = true; }          // 1. explicit env — manual testing still wins
    } else {
        int cfg = role_from_cfg();
        if (cfg >= 0) {
            g_p2 = (cfg == 1);                                   // 2. netplay.cfg — survives a Steam relaunch
        } else {
            char path[MAX_PATH] = {0};                           // 3. path heuristic (the /umvc3-p2 twin)
            GetModuleFileNameA(NULL, path, MAX_PATH);
            for (char* c = path; *c; ++c) *c = (char)tolower((unsigned char)*c);
            if (strstr(path, "umvc3-p2")) g_p2 = true;
        }
    }
    g_name[0] = 'P'; g_name[1] = g_p2 ? '2' : '1'; g_name[2] = 0;
}

const char* name() { if (!g_init) init(); return g_name; }
bool is_p2()       { if (!g_init) init(); return g_p2; }

} // namespace role
