#!/bin/bash
# Build UMvC3 Rollback Monitor from WSL using Windows MinGW-w64
set -e

MINGW_DIR="C:\\Users\\OnyxM\\mingw64\\bin"
PROJECT_WSL="$(cd "$(dirname "$0")" && pwd)"   # this directory (monitor/)
WIN_BUILD="C:\\Users\\OnyxM\\umvc3-monitor-build"
WSL_BUILD="/mnt/c/Users/OnyxM/umvc3-monitor-build"

echo "=== UMvC3 Rollback Monitor Builder ==="

# Create build directory on Windows filesystem
mkdir -p "$WSL_BUILD"

# Sync source to Windows filesystem
echo "Syncing source to Windows filesystem..."
rsync -a --delete \
    --exclude '*.exe' \
    --exclude '.git/' \
    "$PROJECT_WSL/" "$WSL_BUILD/src/"

echo "Building monitor.exe..."

pushd /mnt/c/Users/OnyxM > /dev/null

cmd.exe /c "set PATH=${MINGW_DIR};%PATH% && cd /d ${WIN_BUILD} && g++.exe -O2 -std=c++17 -DWIN32_LEAN_AND_MEAN -DNOMINMAX -o monitor.exe src/monitor.cpp -lpsapi -lkernel32 -luser32 -static-libgcc -static-libstdc++ && echo BUILD_OK" 2>&1

popd > /dev/null

echo ""
echo "=== Build Results ==="
if [ -f "$WSL_BUILD/monitor.exe" ]; then
    ls -la "$WSL_BUILD/monitor.exe"
    echo ""
    echo "Copying to project directory..."
    cp "$WSL_BUILD/monitor.exe" "$PROJECT_WSL/"
    echo "Done: $PROJECT_WSL/monitor.exe"
else
    echo "ERROR: monitor.exe was not produced!"
    exit 1
fi
