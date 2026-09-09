// net_config.cpp — see net_config.h.
#include "net_config.h"
#include "log.h"
#include <windows.h>
#include <cstdio>
#include <cstring>
#include <cstdlib>

namespace net_config {

static char* trim(char* s) {
    while (*s == ' ' || *s == '\t') s++;
    char* e = s + strlen(s);
    while (e > s && (e[-1] == ' ' || e[-1] == '\t' || e[-1] == '\r' || e[-1] == '\n')) *--e = 0;
    return s;
}

static void set_str(char* dst, size_t cap, const char* src) {
    strncpy(dst, src, cap - 1); dst[cap - 1] = 0;
}

const Config& get() {
    static Config c;
    static bool loaded = false;
    if (loaded) return c;
    loaded = true;

    char path[MAX_PATH];
    GetModuleFileNameA(NULL, path, MAX_PATH);
    char* slash = strrchr(path, '\\');
    if (slash) slash[1] = 0; else path[0] = 0;
    strncat(path, "netplay.cfg", MAX_PATH - strlen(path) - 1);

    FILE* f = fopen(path, "r");
    if (!f) { rblog::write("NET-CFG: no netplay.cfg beside exe — legacy loopback defaults."); return c; }
    c.present = true;

    char line[256];
    while (fgets(line, sizeof(line), f)) {
        char* p = trim(line);
        if (!*p || *p == '#' || *p == ';') continue;
        char* eq = strchr(p, '=');
        if (!eq) continue;
        *eq = 0;
        char* key = trim(p);
        char* val = trim(eq + 1);
        if      (!strcmp(key, "mode"))       set_str(c.mode, sizeof(c.mode), val);
        else if (!strcmp(key, "local_port")) c.local_port = (uint16_t)atoi(val);
        else if (!strcmp(key, "peer_ip"))    set_str(c.peer_ip, sizeof(c.peer_ip), val);
        else if (!strcmp(key, "peer_port"))  c.peer_port  = (uint16_t)atoi(val);
        else if (!strcmp(key, "relay_ip"))   set_str(c.relay_ip, sizeof(c.relay_ip), val);
        else if (!strcmp(key, "relay_port")) c.relay_port = (uint16_t)atoi(val);
        else if (!strcmp(key, "code"))       set_str(c.code, sizeof(c.code), val);
    }
    fclose(f);
    rblog::write("NET-CFG: netplay.cfg loaded — mode=%s local=%u peer=%s:%u relay=%s:%u code=%s",
                 c.mode, c.local_port, c.peer_ip, c.peer_port, c.relay_ip, c.relay_port, c.code[0] ? c.code : "-");
    return c;
}

} // namespace net_config
