#!/usr/bin/env bash
# test-adversary/cleanup.sh — Standalone cleanup for --load / --guided mode
# Usage: ./cleanup.sh <emulator-serial>
set -euo pipefail

SERIAL="${1:?Usage: $0 <emulator-serial>}"
STATE_FILE="/tmp/androdr-loaded-packages.txt"

# Resolve adb
if command -v adb &>/dev/null; then
    ADB="adb -s $SERIAL"
elif [ -n "${ANDROID_HOME:-}" ] && [ -x "$ANDROID_HOME/platform-tools/adb" ]; then
    ADB="$ANDROID_HOME/platform-tools/adb -s $SERIAL"
else
    echo "ERROR: adb not found." >&2
    exit 1
fi

if [ ! -f "$STATE_FILE" ]; then
    echo "No state file found at $STATE_FILE. Nothing to clean up."
    exit 0
fi

echo "=== AndroDR Adversary Cleanup ==="
echo ""

count=0
while IFS= read -r pkg || [ -n "$pkg" ]; do
    [ -z "$pkg" ] && continue
    if $ADB uninstall "$pkg" 2>/dev/null | grep -q "Success"; then
        echo "  Uninstalled: $pkg"
        ((count++)) || true
    else
        echo "  Skip (not installed): $pkg"
    fi
done < "$STATE_FILE"

# Remove injected artifacts
$ADB shell rm -f /data/local/tmp/.raptor /data/local/tmp/.stat 2>/dev/null || true

rm -f "$STATE_FILE"
echo ""
echo "Cleanup complete. Removed $count packages."
