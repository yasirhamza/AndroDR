# CI/CD Pipeline Design

**Date:** 2026-03-25
**Branch:** claude/android-edr-setup-rl68Y
**Status:** Approved

## Goal

A seamless local + remote CI/CD pipeline where:
- Claude Code owns the terminal layer (Gradle, ADB, logcat)
- GitHub Actions handles remote build, test, and artifact delivery
- The local and remote pipelines share the same Gradle commands where possible
- A clear evolution roadmap exists from the current MVP to Play Store delivery

---

## Local environment

| Resource | Path |
|---|---|
| Android SDK | `~/Android/Sdk` (`ANDROID_HOME`) |
| ADB | `~/Android/Sdk/platform-tools/adb` |
| Emulator | `~/Android/Sdk/emulator/emulator` |
| AVD | `Medium_Phone_API_36.1` |

---

## Section 1 — Remote CI (GitHub Actions)

### Existing workflow (`android-build.yml`)

Already covers:
- Build + unit tests on every push and PR to `main`
- Debug APK uploaded as artifact (14-day retention)

### Extension: instrumented test job

Add a second job `instrumented-test` to `android-build.yml` that runs **on PRs to `main` only** (not every push, to keep CI fast).

```yaml
instrumented-test:
  runs-on: ubuntu-latest
  needs: build

  steps:
    - uses: actions/checkout@v4

    - name: Set up JDK 17
      uses: actions/setup-java@v4
      with:
        java-version: '17'
        distribution: 'temurin'

    - name: Set up Gradle
      uses: gradle/actions/setup-gradle@v4

    - name: Enable KVM for hardware acceleration
      run: |
        echo 'KERNEL=="kvm", GROUP="kvm", MODE="0666", OPTIONS+="static_node=kvm"' \
          | sudo tee /etc/udev/rules.d/99-kvm4all.rules
        sudo udevadm control --reload-rules
        sudo udevadm trigger --name-match=kvm

    - name: Run instrumented tests on emulator
      uses: reactivecircus/android-emulator-runner@v2
      with:
        api-level: 34
        arch: x86_64
        profile: pixel_6
        script: ./gradlew connectedDebugAndroidTest --stacktrace

    - name: Upload instrumented test report
      uses: actions/upload-artifact@v4
      if: always()
      with:
        name: instrumented-test-report
        path: app/build/reports/androidTests/connected/
        retention-days: 14
```

**Notes:**
- `needs: build` ensures the instrumented job only runs if the build job passes
- `if: always()` on the report upload ensures test results are available even on failure
- The `api-level: 34` matches the project's `compileSdk`
- KVM enablement is required for hardware-accelerated emulation on GitHub's Ubuntu runners

---

## Section 2 — Local CI (smoke-test script)

### `scripts/smoke-test.sh`

Claude runs this **on demand** when a smoke test on the local emulator is needed. It handles the full cycle: start AVD → build → install → launch → logcat check → kill AVD.

```bash
#!/usr/bin/env bash
set -euo pipefail

ANDROID_HOME="${ANDROID_HOME:-$HOME/Android/Sdk}"
ADB="$ANDROID_HOME/platform-tools/adb"
EMULATOR="$ANDROID_HOME/emulator/emulator"
AVD_NAME="Medium_Phone_API_36.1"
APP_PACKAGE="com.androdr"
MAIN_ACTIVITY="com.androdr/.MainActivity"
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
"$ADB" shell am start -n "$MAIN_ACTIVITY"

# ── Logcat check ─────────────────────────────────────────────────────────────
echo "Collecting logcat for ${LOGCAT_DURATION}s..."
mkdir -p build
"$ADB" logcat -v brief "$APP_PACKAGE:D" "*:S" &
LOGCAT_PID=$!
sleep "$LOGCAT_DURATION"
kill $LOGCAT_PID 2>/dev/null
wait $LOGCAT_PID 2>/dev/null || true
"$ADB" logcat -d -v brief "$APP_PACKAGE:D" "*:S" > "$LOGCAT_OUT"

echo "Logcat saved to $LOGCAT_OUT"

if grep -qE "FATAL|AndroidRuntime|EXCEPTION|ANR" "$LOGCAT_OUT"; then
  echo "SMOKE TEST FAILED — fatal errors detected in logcat:" >&2
  grep -E "FATAL|AndroidRuntime|EXCEPTION|ANR" "$LOGCAT_OUT" >&2
  exit 1
fi

echo "SMOKE TEST PASSED"
```

### Usage

```bash
chmod +x scripts/smoke-test.sh
./scripts/smoke-test.sh
```

Or invoked by Claude during an explicit "test on device" step.

---

## Section 3 — CLAUDE.md additions

Add a **Local development** section to `CLAUDE.md`:

```markdown
## Local development

### Android SDK
Set `ANDROID_HOME` before running any ADB or emulator commands:
export ANDROID_HOME=~/Android/Sdk
export PATH=$PATH:$ANDROID_HOME/platform-tools:$ANDROID_HOME/emulator

Or add the above to `~/.bashrc` / `~/.zshrc`.

### Smoke test (local emulator)
Runs a headless AVD, installs the debug APK, launches the app, and checks logcat
for crashes:
./scripts/smoke-test.sh

AVD used: `Medium_Phone_API_36.1`
Requires: ANDROID_HOME set, AVD created in Android Studio.
```

---

## Section 4 — Evolution roadmap

| Phase | When | What it adds |
|---|---|---|
| **Phase 1 — MVP (this spec)** | Now | Remote: `instrumented-test` job on PRs via `android-emulator-runner`. Local: `smoke-test.sh` on demand |
| **Phase 2 — Gradle Managed Devices** | When first instrumented tests (`androidTest/`) exist | Define a Gradle Managed Device in `build.gradle.kts`; replace `smoke-test.sh` with `./gradlew managedDeviceDebugAndroidTest`; CI uses same task. One command locally and remotely |
| **Phase 3 — Release signing** | Approaching first release | Tag-triggered workflow: signs APK with keystore in GitHub Secrets, uploads to GitHub Releases. `CLAUDE.md` documents keystore setup |
| **Phase 4 — Play Store delivery** | Targeting Play Store | Add `gradle-play-publisher` to Phase 3 workflow; tag push auto-deploys to Play Store internal track |

Each phase is additive — Phase 1 requires no rework to move forward.

---

## Files changed

| File | Change |
|---|---|
| `.github/workflows/android-build.yml` | **Edit** — add `instrumented-test` job |
| `scripts/smoke-test.sh` | **Create** — local smoke test script |
| `CLAUDE.md` | **Edit** — add Local development section |

---

## Success criteria

- `instrumented-test` CI job appears in GitHub Actions on PRs to `main`
- `smoke-test.sh` runs end-to-end on `Medium_Phone_API_36.1` without manual steps
- Logcat check catches crashes and exits non-zero
- `CLAUDE.md` documents `ANDROID_HOME` and AVD name
- Existing `build` CI job is unaffected
