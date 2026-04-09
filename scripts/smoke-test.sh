#!/usr/bin/env bash
set -euo pipefail

ANDROID_HOME="${ANDROID_HOME:-$HOME/Android/Sdk}"
ADB="$ANDROID_HOME/platform-tools/adb"
EMULATOR="$ANDROID_HOME/emulator/emulator"
AVD_NAME="Medium_Phone_API_36.1"
APP_PACKAGE="com.androdr.debug"
MAIN_ACTIVITY="com.androdr.debug/com.androdr.MainActivity"
LOGCAT_OUT="build/smoke-logcat.txt"
LOGCAT_DURATION=15

# ── Preflight checks ──────────────────────────────────────────────────────────
if [[ ! -x "$ADB" ]]; then
  echo "ERROR: adb not found at $ADB. Set ANDROID_HOME correctly." >&2
  exit 1
fi
if [[ ! -x "$EMULATOR" ]]; then
  echo "ERROR: emulator not found at $EMULATOR." >&2
  exit 1
fi

# ── Emulator: reuse existing or start fresh ──────────────────────────────────
# Check whether an emulator is already booted. If so, reuse it and leave it
# running on exit. If not, boot a fresh one and kill it on exit.
#
# Reusing avoids the "Running multiple emulators with the same AVD is an
# experimental feature" failure when a developer already has the target AVD
# open during interactive work.
REUSED_EMULATOR=false
EMULATOR_PID=""
if "$ADB" devices 2>/dev/null | awk 'NR>1 && /emulator-[0-9]+\tdevice/' | grep -q .; then
  echo "Reusing running emulator."
  REUSED_EMULATOR=true
else
  echo "Starting AVD: $AVD_NAME"
  "$EMULATOR" -avd "$AVD_NAME" -no-window -no-audio -no-snapshot &
  EMULATOR_PID=$!
fi

cleanup() {
  if ! $REUSED_EMULATOR && [[ -n "$EMULATOR_PID" ]]; then
    "$ADB" -e emu kill 2>/dev/null || true
    wait "$EMULATOR_PID" 2>/dev/null || true
  fi
}
trap cleanup EXIT

# ── Wait for boot ─────────────────────────────────────────────────────────────
echo "Waiting for device..."
"$ADB" wait-for-device
echo "Waiting for boot to complete..."
until [[ "$("$ADB" shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')" == "1" ]]; do
  sleep 2
done
echo "Device ready."

# ── Build ─────────────────────────────────────────────────────────────────────
echo "Building debug APK..."
./gradlew assembleDebug --quiet

# ── Install ───────────────────────────────────────────────────────────────────
echo "Installing APK..."
"$ADB" install -r app/build/outputs/apk/debug/app-debug.apk

# ── Launch ────────────────────────────────────────────────────────────────────
echo "Launching $MAIN_ACTIVITY..."
"$ADB" logcat -c                           # clear buffer before launch
"$ADB" shell am start -n "$MAIN_ACTIVITY"

# ── Logcat check ─────────────────────────────────────────────────────────────
echo "Collecting logcat for ${LOGCAT_DURATION}s..."
mkdir -p build
sleep "$LOGCAT_DURATION"
"$ADB" logcat -d -v brief "$APP_PACKAGE:D" "*:S" > "$LOGCAT_OUT"

echo "Logcat saved to $LOGCAT_OUT"

if grep -qE "FATAL|AndroidRuntime|EXCEPTION|ANR" "$LOGCAT_OUT"; then
  echo "SMOKE TEST FAILED — fatal errors detected in logcat:" >&2
  grep -E "FATAL|AndroidRuntime|EXCEPTION|ANR" "$LOGCAT_OUT" >&2
  exit 1
fi

echo "SMOKE TEST PASSED"
