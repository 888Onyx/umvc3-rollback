#pragma once
#include <cstdint>
// net_config.h — reads netplay.cfg (key=value, next to the game exe) that the launcher writes. Replaces the hardcoded
// 127.0.0.1 loopback so two real machines (direct-IP now, matchmaker/code later) can find each other. Absent cfg =
// legacy loopback defaults (role-driven ports 7100/7101), so solo/two-instance-on-one-PC still works unchanged.
//
// netplay.cfg example (direct): netplay.cfg example (matchmaker, later):
// mode=direct mode=matchmaker
// local_port=7000 relay_ip=203.0.113.9
// peer_ip=192.168.1.50 relay_port=7000
// peer_port=7000 code=ABCD-1234
// (role is set by the launcher via the UMVC3_ROLLBACK_ROLE env var — see role.h — not here.)
namespace net_config {
struct Config {
    bool     present    = false;
    char     mode[16]   = "direct";         // "direct" | "matchmaker"
    uint16_t local_port = 0;                 // 0 => role-default (7100/7101)
    char     peer_ip[64]= "";                // direct target
    uint16_t peer_port  = 0;                 // 0 => role-default
    char     relay_ip[64]= "";               // matchmaker box
    uint16_t relay_port = 0;
    char     code[32]   = "";                // room code
};
const Config& get();   // parsed once from netplay.cfg beside the exe, cached
}
