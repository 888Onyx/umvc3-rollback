#!/bin/bash
# Build UMvC3 Rollback Beta DLL from WSL using Windows MinGW-w64
set -e

MINGW_DIR="C:\\Users\\OnyxM\\mingw64\\bin"
PROJECT_WSL="/home/onyx/umvc3-rollback-beta-132"
WIN_BUILD="C:\\Users\\OnyxM\\umvc3-rollback-beta-132-build"
WSL_BUILD="/mnt/c/Users/OnyxM/umvc3-rollback-beta-132-build"
GAME_DIR="/mnt/c/Program Files (x86)/Steam/steamapps/common/ULTIMATE MARVEL VS. CAPCOM 3"
P2_DIR="/mnt/c/umvc3-p2"
P3_DIR="/mnt/c/umvc3-p3"   # second Steamless twin (identical build to P2) for the determinism/lockstep test. P1 (Steam copy) runs the DLL fine; P1+P2 are the two netplay-test instances.

echo "=== UMvC3 Rollback Beta DLL Builder ==="

# Create build directory on Windows filesystem
mkdir -p "$WSL_BUILD"

# Sync source files to Windows filesystem
echo "Syncing source to Windows filesystem..."
rsync -a --delete \
    --exclude 'build/' \
    --exclude 'bin/' \
    --exclude '*.dll' \
    --exclude '*.a' \
    --exclude '*.o' \
    --exclude '.git/' \
    --exclude 'docs/' \
    --exclude 'tools/' \
    "$PROJECT_WSL/" "$WSL_BUILD/src/"

echo "Building MinHook..."

# Build MinHook (C files, 64-bit)
pushd /mnt/c/Users/OnyxM > /dev/null

cmd.exe /c "set PATH=${MINGW_DIR};%PATH% && cd /d ${WIN_BUILD} && gcc.exe -c -O2 -DWIN32_LEAN_AND_MEAN -I src/lib/minhook/include src/lib/minhook/src/buffer.c -o buffer.o && gcc.exe -c -O2 -DWIN32_LEAN_AND_MEAN -I src/lib/minhook/include src/lib/minhook/src/hook.c -o hook.o && gcc.exe -c -O2 -DWIN32_LEAN_AND_MEAN -I src/lib/minhook/include src/lib/minhook/src/trampoline.c -o trampoline.o && gcc.exe -c -O2 -DWIN32_LEAN_AND_MEAN -I src/lib/minhook/include src/lib/minhook/src/hde/hde64.c -o hde64.o && ar.exe rcs libminhook.a buffer.o hook.o trampoline.o hde64.o && echo MINHOOK_OK" 2>&1

echo "Building DLL..."

# Build dinput8.dll (C++ files, 64-bit)
cmd.exe /c "set PATH=${MINGW_DIR};%PATH% && cd /d ${WIN_BUILD} && g++.exe -shared -O2 -std=c++17 -DWIN32_LEAN_AND_MEAN -I src/src -I src/lib/minhook/include src/src/log.cpp src/src/role.cpp src/src/single_instance.cpp src/src/net_transport.cpp src/src/net_session.cpp src/src/net_input.cpp src/src/net_sync.cpp src/src/net_charsel.cpp src/src/net_engine_arm.cpp src/src/net_config.cpp src/src/arena.cpp src/src/input.cpp src/src/suspend.cpp src/src/handle_preserve.cpp src/src/dead_vtable_unlink.cpp src/src/resim.cpp src/src/monitor_shm.cpp src/src/gp_crc.cpp src/src/voice_pool.cpp src/src/hang_detector.cpp src/src/rtv_probe.cpp src/src/effect_probe.cpp src/src/freelist_diag.cpp src/src/alloc_consistency.cpp src/src/draw_probe.cpp src/src/dynamic_restore.cpp src/src/effect_splice.cpp src/src/byid.cpp src/src/idspine.cpp src/src/dyndelete.cpp src/src/page_free.cpp src/src/sound_preserve.cpp src/src/sound_resource_preserve.cpp src/src/sound_edge_reconcile.cpp src/src/edge_census.cpp src/src/edge_break.cpp src/src/alloc_invariants.cpp src/src/flist_rebuild.cpp src/src/field_target_recorder.cpp src/src/xray_mem.cpp src/src/audio_group.cpp src/src/audio_probe.cpp src/src/audio_preserve.cpp src/src/coherence_audit.cpp src/src/coherent_set_repair.cpp src/src/rdspine.cpp src/src/provenance.cpp src/src/p4_shadow.cpp src/src/quarantine.cpp src/src/render_edge_probe.cpp src/src/render_subchild_guard.cpp src/src/reader.cpp src/src/material_guard.cpp src/src/id_oracle.cpp src/src/anim_curve_guard.cpp src/src/particle_list_guard.cpp src/src/count_drift_census.cpp src/src/carve_orphan_probe.cpp src/src/gameplay_complete.cpp src/src/life_floor.cpp src/src/audio_leaf.cpp src/src/dinput_probe.cpp src/src/dllmain.cpp -o dinput8.dll -L. -lminhook -static -static-libgcc -static-libstdc++ -lkernel32 -luser32 -lgdi32 -lwinmm -lpsapi -lws2_32 && echo DLL_OK" 2>&1

popd > /dev/null

# Check results
echo ""
echo "=== Build Results ==="
if [ -f "$WSL_BUILD/dinput8.dll" ]; then
    ls -la "$WSL_BUILD/dinput8.dll"
    file "$WSL_BUILD/dinput8.dll"
    echo ""
    echo "Copying to game directory..."
    cp "$WSL_BUILD/dinput8.dll" "$GAME_DIR/"
    echo "Done. DLL installed to P1 (Steam) game directory."
    # Also install to the Steamless P2 instance (netplay instance B; P1 = instance A).
    if [ -d "$P2_DIR" ]; then
        cp "$WSL_BUILD/dinput8.dll" "$P2_DIR/"
        echo "Done. DLL installed to P2 (Steamless) — $P2_DIR"
    else
        echo "NOTE: P2 dir $P2_DIR not found — skipped P2 install."
    fi
    if [ -d "$P3_DIR" ]; then
        cp "$WSL_BUILD/dinput8.dll" "$P3_DIR/"
        echo "Done. DLL installed to P3 (Steamless twin) — $P3_DIR"
    fi
else
    echo "ERROR: dinput8.dll was not produced!"
    exit 1
fi
