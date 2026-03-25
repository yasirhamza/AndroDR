#!/usr/bin/env bash
set -euo pipefail

ANDROID_HOME="${ANDROID_HOME:-$HOME/Android/Sdk}"
ADB="$ANDROID_HOME/platform-tools/adb"
EMULATOR="$ANDROID_HOME/emulator/emulator"
AVD_NAME="Medium_Phone_API_36.1"
APP_PACKAGE="com.androdr.debug"
MAIN_ACTIVITY="com.androdr.debug/.MainActivity"
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

# ── Start AVD headlessly ──────────────────────────────────────────────────────
echo "Starting AVD: $AVD_NAME"
"$EMULATOR" -avd "$AVD_NAME" -no-window -no-audio -no-snapshot &
EMULATOR_PID=$!
trap '"$ADB" -e emu kill 2>/dev/null; wait $EMULATOR_PID 2>/dev/null' EXIT

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
