#!/usr/bin/env bash
# test-adversary/cleanup.sh — Standalone cleanup for --load / --guided mode
# Usage: ./cleanup.sh <emulator-serial>
set -euo pipefail

SERIAL="${1:?Usage: $0 <emulator-serial>}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
MANIFEST="$SCRIPT_DIR/manifest.yml"
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

echo "=== AndroDR Adversary Cleanup ==="
echo ""

# ── Uninstall packages tracked in state file ──────────────────────────────────
count=0
if [ -f "$STATE_FILE" ]; then
    while IFS= read -r pkg || [ -n "$pkg" ]; do
        [ -z "$pkg" ] && continue
        if $ADB uninstall "$pkg" 2>/dev/null | grep -q "Success"; then
            echo "  Uninstalled: $pkg"
            ((count++)) || true
        else
            echo "  Skip (not installed): $pkg"
        fi
    done < "$STATE_FILE"
    rm -f "$STATE_FILE"
else
    echo "  No state file — skipping package uninstall step."
fi

# ── Remove every adb_inject artifact defined in the manifest ──────────────────
# Previously this was hardcoded to /data/local/tmp/.raptor and .stat, which
# silently broke whenever a new inject scenario was added. Instead, read the
# manifest and reverse every inject scenario's cleanup commands. Commands are
# idempotent (rm -f), so running them on a device that never had the artifact
# installed is harmless.
if [ ! -f "$MANIFEST" ]; then
    echo "  WARNING: manifest not found at $MANIFEST — cannot reverse inject scenarios."
else
    # Collect every cleanup: command from every adb_inject scenario
    cleanup_cmds=$(python3 - "$MANIFEST" <<'PY'
import sys, yaml
with open(sys.argv[1]) as f:
    m = yaml.safe_load(f)
for s in m.get('scenarios', []):
    if s.get('source') == 'adb_inject':
        for inj in s.get('inject', []):
            c = inj.get('cleanup', '')
            if c:
                print(c)
PY
)
    artifact_count=0
    while IFS= read -r cmd; do
        [ -z "$cmd" ] && continue
        $ADB $cmd 2>/dev/null || true
        ((artifact_count++)) || true
    done <<< "$cleanup_cmds"
    if [ "$artifact_count" -gt 0 ]; then
        echo "  Reversed $artifact_count inject-scenario artifacts from manifest."
    fi
fi

echo ""
echo "Cleanup complete. Removed $count packages."
