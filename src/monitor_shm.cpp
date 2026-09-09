// monitor_shm.cpp — Named shared memory for monitor.exe integration.
// Creates "UMvC3RollbackMonitor" mapping on DLL load; monitor.exe reads it.
// Write-log ring buffer for per-write attribution.

#include "monitor_shm.h"
#include "role.h"
#include "log.h"
#include <windows.h>
#include <cstring>
#include <cstdio>

namespace monitor_shm {

MonitorData* g_mon = nullptr;

static HANDLE g_shm_handle = NULL;

void init() {
    // PER-INSTANCE NAME: two instances on one unqualified name silently mapped the same region and stomped each
    // other's telemetry. Name is now
    // "UMvC3RollbackMonitor.P1"/".P2" via role::name(); monitor.exe takes the role as argv[1].
    static char shm_name[64];
    snprintf(shm_name, sizeof(shm_name), "%s.%s", MONITOR_SHM_NAME, role::name());
    g_shm_handle = CreateFileMappingA(
        INVALID_HANDLE_VALUE,
        NULL,
        PAGE_READWRITE,
        0,
        sizeof(MonitorData),
        shm_name);

    if (!g_shm_handle) {
        rblog::write("MONITOR_SHM: CreateFileMapping failed (err=%lu)", GetLastError());
        return;
    }

    bool already_existed = (GetLastError() == ERROR_ALREADY_EXISTS);

    g_mon = (MonitorData*)MapViewOfFile(
        g_shm_handle,
        FILE_MAP_ALL_ACCESS,
        0, 0,
        sizeof(MonitorData));

    if (!g_mon) {
        rblog::write("MONITOR_SHM: MapViewOfFile failed (err=%lu)", GetLastError());
        CloseHandle(g_shm_handle);
        g_shm_handle = NULL;
        return;
    }

    if (!already_existed) {
        memset(g_mon, 0, sizeof(MonitorData));
    }

    rblog::write("MONITOR_SHM: ready (\"%s\", %s, %zu bytes)",
                 shm_name,
                 already_existed ? "re-opened" : "created",
                 sizeof(MonitorData));
}

void set_phase(PhaseID phase, uint32_t frame) {
    if (!g_mon) return;
    g_mon->current_phase = (uint8_t)phase;
    g_mon->current_frame = frame;
    InterlockedIncrement(&g_mon->phase_sequence);
}

void log_write(uint32_t frame, PhaseID phase, uint8_t rule_id,
               uint64_t entity, uint16_t offset,
               uint64_t old_val, uint64_t new_val) {
    if (!g_mon) return;

    uint32_t idx = InterlockedIncrement(&g_mon->writelog_head) - 1;
    idx = idx % WRITELOG_SIZE;

    WriteLogEntry& e = g_mon->writelog[idx];
    e.sequence = g_mon->phase_sequence;
    e.frame = frame;
    e.phase_id = (uint8_t)phase;
    e.rule_id = rule_id;
    e.offset = offset;
    e.entity = entity;
    e.old_val = old_val;
    e.new_val = new_val;
}

} // namespace monitor_shm
