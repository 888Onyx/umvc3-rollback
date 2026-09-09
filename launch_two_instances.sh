#!/bin/bash
# launch_two_instances.sh — two-instance netplay-test launcher.
# Starts the P2 (Steamless/Goldberg) instance with its role env set; P1 is launched via Steam as usual
# (no env needed — role.cpp's path heuristic assigns P1 to the Steam-directory copy automatically).
# Each instance gets its own log (exe-dir umvc3_rollback.log) and its own monitor shm
# ("UMvC3RollbackMonitor.P1"/".P2"; monitor.exe P2 to watch the second instance).
set -e

P2_DIR_WIN='C:\umvc3-p2'

echo "=== UMvC3 two-instance netplay test launcher ==="
echo "[1/2] Starting P2 (Steamless) with UMVC3_ROLLBACK_ROLE=P2 ..."
cmd.exe /c "set UMVC3_ROLLBACK_ROLE=P2&& cd /d ${P2_DIR_WIN}&& start \"\" umvc3.exe" 2>/dev/null || true
echo "      P2 launched from ${P2_DIR_WIN} (log: C:\\umvc3-p2\\umvc3_rollback.log)"
echo
echo "[2/2] Launch P1 through Steam as usual (packed exe; role auto-resolves to P1 by path)."
echo
echo "Verify in each log's first lines: 'instance role=P1'/'=P2' and 'MONITOR_SHM: ready (\"UMvC3RollbackMonitor.Px\")'."
echo "Both windows up + both logs healthy for 60+s = the two-instance gate."
