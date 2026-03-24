# CI/CD Pipeline Design

**Date:** 2026-03-25
**Branch:** claude/android-edr-setup-rl68Y
**Status:** Approved

## Goal

A seamless local + remote CI/CD pipeline where:
- Claude Code owns the terminal layer (Gradle, ADB, logcat)
- GitHub Actions handles remote build, test, artifact delivery, and security gates
- The local and remote pipelines share the same Gradle commands where possible
- Secure SDLC is enforced from day one — this is a security product
- A clear evolution roadmap exists from the current MVP to Play Store delivery

---

## Local environment

| Resource | Path |
|---|---|
| Android SDK | `~/Android/Sdk` (`ANDROID_HOME`) |
| ADB | `~/Android/Sdk/platform-tools/adb` |
| Emulator | `~/Android/Sdk/emulator/emulator` |
| AVD | `Medium_Phone_API_36.1` (API 36) |

---

## Section 1 — Remote CI (GitHub Actions)

### Existing workflow (`android-build.yml`)

Already covers:
- Build + unit tests on every push and PR to `main`
- Debug APK uploaded as artifact with `if: success()` — **change to `if: always()`** so the APK is available even when lint/detekt steps fail

### Extension: instrumented test job

Add `instrumented-test` job to `android-build.yml`. Add a job-level `if: github.event_name == 'pull_request'` guard so it runs **only on PRs to `main`**, not on every push.

Note: no `androidTest/` source set exists yet — this job is infrastructure-only until Phase 2. The upload step uses `if-no-files-found: warn`.

```yaml
instrumented-test:
  runs-on: ubuntu-latest
  needs: build
  if: github.event_name == 'pull_request'

  steps:
    - uses: actions/checkout@v4

    - name: Set up JDK 21
      uses: actions/setup-java@v4
      with:
        java-version: '21'
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
        if-no-files-found: warn
```

**Notes:**
- `api-level: 34` matches `compileSdk`; align with local AVD API level when writing instrumented tests (Phase 2)
- KVM enablement is required for hardware-accelerated emulation on GitHub's Ubuntu runners

---

## Section 2 — Local CI (smoke-test script)

### `scripts/smoke-test.sh`

Claude runs this **on demand** when a smoke test on the local emulator is needed. Full cycle: start AVD → build → install → launch → logcat check → kill AVD.

The debug build uses `applicationIdSuffix = ".debug"`, so the installed package is `com.androdr.debug`.

```bash
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
```

### Usage

```bash
chmod +x scripts/smoke-test.sh
./scripts/smoke-test.sh
```

---

## Section 3 — CLAUDE.md additions

Update the existing `CLAUDE.md` **Build requirements** line from `JDK 17` to `JDK 21` (CI uses JDK 21). Add a **Local development** section:

```markdown
## Local development

### Android SDK
Set `ANDROID_HOME` before running any ADB or emulator commands:

    export ANDROID_HOME=~/Android/Sdk
    export PATH=$PATH:$ANDROID_HOME/platform-tools:$ANDROID_HOME/emulator

Add the above to `~/.bashrc` / `~/.zshrc` to persist across sessions.

### Smoke test (local emulator)
Runs a headless AVD, installs the debug APK, launches the app, and checks logcat
for crashes:

    ./scripts/smoke-test.sh

AVD: `Medium_Phone_API_36.1` (API 36). Requires `ANDROID_HOME` set.
Debug package ID: `com.androdr.debug` (applicationIdSuffix = ".debug").
```

---

## Section 4 — Secure SDLC gates

All gates run on every PR to `main`. No emulator needed.

### 4a. Lint gate

Add to `android-build.yml` `build` job (after unit tests):

```yaml
- name: Run lint
  run: ./gradlew lintDebug --stacktrace

- name: Upload lint report
  uses: actions/upload-artifact@v4
  if: always()
  with:
    name: lint-report
    path: app/build/reports/lint-results-debug.html
    retention-days: 14
    if-no-files-found: warn
```

Add to `app/build.gradle.kts` inside the `android {}` block:

```kotlin
lint {
    warningsAsErrors = true
    abortOnError = true
}
```

### 4b. SAST — detekt

Add to `gradle/libs.versions.toml`:

```toml
[versions]
detekt = "1.23.7"   # Kotlin 2.0 compatible; re-evaluate when upgrading Kotlin past 2.0

[plugins]
detekt = { id = "io.gitlab.arturbosch.detekt", version.ref = "detekt" }
```

Apply in `build.gradle.kts` (root) using the version catalog pattern:

```kotlin
plugins {
    alias(libs.plugins.detekt) apply false
}
```

Apply in `app/build.gradle.kts`:

```kotlin
plugins {
    alias(libs.plugins.detekt)
}

detekt {
    config.setFrom("$rootDir/config/detekt.yml")
    buildUponDefaultConfig = true
}
```

Create `config/detekt.yml` enabling rules covering:
- Hardcoded credentials / secrets
- `java.util.Random` instead of `SecureRandom`
- Unsafe reflection
- Overly broad exception catches that may swallow security errors

CI step in `build` job:

```yaml
- name: Run detekt SAST
  run: ./gradlew detekt --stacktrace

- name: Upload detekt report
  uses: actions/upload-artifact@v4
  if: always()
  with:
    name: detekt-report
    path: build/reports/detekt/
    retention-days: 14
    if-no-files-found: warn
```

### 4c. Dependency vulnerability scanning

Add to `gradle/libs.versions.toml`:

```toml
[versions]
owaspDepCheck = "9.2.0"

[plugins]
owasp-dependency-check = { id = "org.owasp.dependencycheck", version.ref = "owaspDepCheck" }
```

Apply in root `build.gradle.kts`:

```kotlin
plugins {
    alias(libs.plugins.owasp-dependency-check)
}

dependencyCheck {
    failBuildOnCVSS = 7.0f
    formats = listOf("HTML", "JSON")
}
```

Add a separate `dependency-scan` job with `if: github.event_name == 'pull_request'` guard:

```yaml
dependency-scan:
  runs-on: ubuntu-latest
  if: github.event_name == 'pull_request'

  steps:
    - uses: actions/checkout@v4
    - uses: actions/setup-java@v4
      with:
        java-version: '21'
        distribution: 'temurin'
    - uses: gradle/actions/setup-gradle@v4

    - name: OWASP dependency check
      run: ./gradlew dependencyCheckAnalyze --stacktrace

    - name: Upload dependency check report
      uses: actions/upload-artifact@v4
      if: always()
      with:
        name: dependency-check-report
        path: build/reports/dependency-check-report.*
        retention-days: 14
        if-no-files-found: warn
```

Also add `.github/dependabot.yml` for passive background monitoring:

```yaml
version: 2
updates:
  - package-ecosystem: "gradle"
    directory: "/"
    schedule:
      interval: "weekly"
```

### 4d. Secret scanning — gitleaks

Runs on every **push** (not just PRs). Uses direct CLI invocation to avoid the `GITLEAKS_LICENSE` requirement of the managed action:

```yaml
secret-scan:
  runs-on: ubuntu-latest

  steps:
    - uses: actions/checkout@v4
      with:
        fetch-depth: 0   # full history required for gitleaks

    - name: Install gitleaks
      run: |
        curl -sSL https://github.com/gitleaks/gitleaks/releases/latest/download/gitleaks_linux_x64.tar.gz \
          | tar -xz gitleaks
        sudo mv gitleaks /usr/local/bin/

    - name: Scan for secrets
      run: gitleaks detect --source . --verbose
```

No secrets or licences required. Uses gitleaks' built-in ruleset.

### 4e. APK security check

Runs in the `build` job after `assembleDebug`. Uses `apkanalyzer` from the Android build-tools. The binary path is resolved explicitly to avoid glob expansion issues:

```yaml
- name: APK security check
  run: |
    BUILD_TOOLS=$(ls -d $ANDROID_HOME/build-tools/*/ | tail -1)
    APK=app/build/outputs/apk/debug/app-debug.apk
    MANIFEST=$("${BUILD_TOOLS}apkanalyzer" manifest print "$APK")
    # Warn on exported components without explicit permission
    if echo "$MANIFEST" | grep -qE 'exported="true"' && \
       ! echo "$MANIFEST" | grep -qE 'permission='; then
      echo "WARNING: exported component(s) without permission found"
    fi
    echo "APK advisory check complete (advisory only in Phase 1)"
```

Advisory-only in Phase 1 (does not fail the build). Becomes a hard gate in Phase 3.

---

## Section 5 — Evolution roadmap

| Phase | When | What it adds |
|---|---|---|
| **Phase 1 — MVP (this spec)** | Now | Remote: `instrumented-test` (infra-only), lint gate, detekt SAST, OWASP dep-check, gitleaks, APK advisory check. Local: `smoke-test.sh` on demand |
| **Phase 2 — Gradle Managed Devices** | When first `androidTest/` tests exist | Replace `smoke-test.sh` with `./gradlew managedDeviceDebugAndroidTest`; CI uses same task; align CI emulator API level with local AVD |
| **Phase 3 — Release signing + hard security gates** | Approaching first release | Tag-triggered signing workflow; APK security check becomes hard gate; MobSF deep scan added |
| **Phase 4 — Play Store delivery** | Targeting Play Store | `gradle-play-publisher` auto-deploys to internal track on tags |

Each phase is additive — Phase 1 requires no rework to move forward.

---

## Files changed

| File | Change |
|---|---|
| `.github/workflows/android-build.yml` | **Edit** — change APK upload to `if: always()`; add lint, detekt, APK check steps to `build` job; add `instrumented-test`, `dependency-scan`, `secret-scan` jobs with correct `if:` guards |
| `gradle/libs.versions.toml` | **Edit** — add `detekt = "1.23.7"`, `owaspDepCheck = "9.2.0"` to `[versions]`; add plugin entries to `[plugins]` |
| `build.gradle.kts` | **Edit** — add `alias(libs.plugins.detekt) apply false` and `alias(libs.plugins.owasp-dependency-check)` + `dependencyCheck {}` config |
| `app/build.gradle.kts` | **Edit** — add `alias(libs.plugins.detekt)` + `detekt {}` config; add `lint { warningsAsErrors abortOnError }` |
| `config/detekt.yml` | **Create** (new `config/` directory + file) |
| `scripts/smoke-test.sh` | **Create** (new `scripts/` directory + file) |
| `.github/dependabot.yml` | **Create** |
| `CLAUDE.md` | **Edit** — update JDK 17 → 21; add Local development section |

---

## Success criteria

- All four security gates (lint, detekt, OWASP, gitleaks) run and pass on a clean PR
- Lint errors and detekt violations fail the PR
- Dependency with CVSS ≥ 7.0 fails the `dependency-scan` job
- Secret committed to any branch is caught by gitleaks on push
- `instrumented-test` and `dependency-scan` jobs only run on PRs, not on every push
- APK upload artifact available even when lint/detekt fail (`if: always()`)
- `smoke-test.sh` runs end-to-end on `Medium_Phone_API_36.1` without manual steps
- Logcat crash check exits non-zero on fatal errors
- `CLAUDE.md` documents JDK 21, `ANDROID_HOME`, AVD name, and debug package ID
- Existing `build` CI job behaviour is unaffected for passing code
