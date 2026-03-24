# CI/CD Pipeline Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement a local + remote CI/CD pipeline with secure SDLC gates for the AndroDR Android security app.

**Architecture:** Extend the existing GitHub Actions workflow with lint, detekt SAST, OWASP dependency scanning, gitleaks secret scanning, APK advisory check, and an instrumented test job. Add a local smoke-test script that Claude runs on demand via ADB against the `Medium_Phone_API_36.1` AVD.

**Tech Stack:** GitHub Actions, Gradle (Kotlin DSL), detekt 1.23.7, OWASP Dependency-Check 9.2.0, gitleaks CLI, ADB, Android emulator, Bash

**Note on JVM versions:** CI and local toolchain use JDK 21. The `app/build.gradle.kts` compile target stays at `JavaVersion.VERSION_17` / `jvmTarget = "17"` — this is intentional (JDK 21 toolchain compiling to JDK 17 bytecode is valid and required for Android minSdk 26 compatibility).

---

## File Map

| File | Action | Responsibility |
|---|---|---|
| `.github/workflows/android-build.yml` | Modify | All CI jobs: build, security gates, instrumented test |
| `.github/dependabot.yml` | Create | Weekly Gradle dependency update PRs |
| `gradle/libs.versions.toml` | Modify | Add detekt + OWASP plugin version entries |
| `build.gradle.kts` | Modify | Declare detekt (apply false) + apply OWASP plugin + config at root level |
| `app/build.gradle.kts` | Modify | Apply detekt plugin + config; add lint block inside `android {}` |
| `config/detekt.yml` | Create | detekt security ruleset config |
| `scripts/smoke-test.sh` | Create | Local headless AVD smoke test |
| `CLAUDE.md` | Modify | Update JDK 17→21 in build requirements; add Local development section |

---

## Task 1: Update version catalog with new plugin versions

**Files:**
- Modify: `gradle/libs.versions.toml`

- [ ] Add to the `[versions]` section (after existing entries):
```toml
detekt = "1.23.7"
owaspDepCheck = "9.2.0"
```

- [ ] Add to the `[plugins]` section (after existing entries):
```toml
detekt = { id = "io.gitlab.arturbosch.detekt", version.ref = "detekt" }
owasp-dependency-check = { id = "org.owasp.dependencycheck", version.ref = "owaspDepCheck" }
```

- [ ] Verify Gradle sync succeeds locally:
```bash
cd /home/yasir/AndroDR && ./gradlew help --quiet
```
Expected: exits 0 with no version catalog errors.

- [ ] Commit:
```bash
git add gradle/libs.versions.toml
git commit -m "build: add detekt and OWASP dependency-check to version catalog"
```

---

## Task 2: Apply detekt plugin and config

**Files:**
- Modify: `build.gradle.kts` (root)
- Modify: `app/build.gradle.kts`
- Create: `config/detekt.yml`

- [ ] In `build.gradle.kts` (root), add inside the `plugins {}` block after the last existing `alias(...)` line:
```kotlin
alias(libs.plugins.detekt) apply false
```

- [ ] In `app/build.gradle.kts`, add inside the `plugins {}` block after the last existing `alias(...)` line:
```kotlin
alias(libs.plugins.detekt)
```

- [ ] In `app/build.gradle.kts`, add a `detekt {}` config block between the `ksp {}` block and the `dependencies {}` block:
```kotlin
detekt {
    config.setFrom("$rootDir/config/detekt.yml")
    buildUponDefaultConfig = true
}
```

- [ ] Create `config/detekt.yml`:
```yaml
# detekt configuration — security-focused ruleset for AndroDR
# buildUponDefaultConfig = true means all default rules apply unless overridden here

complexity:
  active: true

potential-bugs:
  active: true
  CastToNullableType:
    active: true
  LateinitUsage:
    active: true

style:
  active: true
  MagicNumber:
    active: false   # too noisy for Android UI code

exceptions:
  active: true
  TooGenericExceptionCaught:
    active: true
    exceptionNames:
      - 'Exception'
      - 'Throwable'
    allowedExceptionNameRegex: '_|(ignore|expected).*'
  TooGenericExceptionThrown:
    active: true

naming:
  active: true
```

- [ ] Verify detekt runs cleanly:
```bash
cd /home/yasir/AndroDR && ./gradlew detekt --stacktrace 2>&1 | tail -20
```
Expected: `BUILD SUCCESSFUL`. If violations found, either fix them or add `@Suppress("RuleName")` with a comment justifying the suppression.

- [ ] Commit:
```bash
git add build.gradle.kts app/build.gradle.kts config/detekt.yml
git commit -m "build: add detekt SAST with security ruleset"
```

---

## Task 3: Add lint gate to build config

**Files:**
- Modify: `app/build.gradle.kts`

- [ ] In `app/build.gradle.kts`, add a `lint {}` block **inside the `android {}` block**, after the `packaging {}` block and before the closing `}` of `android {}`:
```kotlin
    lint {
        warningsAsErrors = true
        abortOnError = true
    }
```

- [ ] Verify lint passes:
```bash
cd /home/yasir/AndroDR && ./gradlew lintDebug --stacktrace 2>&1 | tail -30
```
Expected: `BUILD SUCCESSFUL`. If errors found, fix them or suppress with `tools:ignore` in the relevant XML/code with justification comment.

- [ ] Commit:
```bash
git add app/build.gradle.kts
git commit -m "build: enforce lint as build gate (warningsAsErrors)"
```

---

## Task 4: Apply OWASP Dependency-Check plugin

**Files:**
- Modify: `build.gradle.kts` (root)

- [ ] In `build.gradle.kts` (root), add inside the `plugins {}` block after `alias(libs.plugins.detekt) apply false`:
```kotlin
alias(libs.plugins.owasp-dependency-check)
```
Note: no `apply false` here — the OWASP plugin must be applied at root level to scan all configurations.

- [ ] Add at the bottom of `build.gradle.kts` (root), after the closing `}` of the `plugins {}` block:
```kotlin
dependencyCheck {
    failBuildOnCVSS = 7.0f
    formats = listOf("HTML", "JSON")
}
```

- [ ] Verify the task exists:
```bash
cd /home/yasir/AndroDR && ./gradlew tasks --group="OWASP dependency-check" --quiet 2>&1 | head -10
```
Expected: `dependencyCheckAnalyze` appears in the task list.

- [ ] Commit:
```bash
git add build.gradle.kts
git commit -m "build: add OWASP dependency-check plugin (CVSS >= 7.0 gate)"
```

---

## Task 5: Create smoke-test script

**Files:**
- Create: `scripts/smoke-test.sh`

- [ ] Create `scripts/smoke-test.sh` with the following content (copy exactly — debug package is `com.androdr.debug` due to `applicationIdSuffix = ".debug"`):

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

- [ ] Make executable and verify syntax:
```bash
chmod +x /home/yasir/AndroDR/scripts/smoke-test.sh
bash -n /home/yasir/AndroDR/scripts/smoke-test.sh && echo "Syntax OK"
```
Expected: `Syntax OK`

- [ ] Commit:
```bash
git add scripts/smoke-test.sh
git commit -m "ci: add local smoke-test script for headless AVD testing"
```

---

## Task 6: Update CLAUDE.md

**Files:**
- Modify: `CLAUDE.md`

- [ ] In `CLAUDE.md` line 10, change `**JDK 17**` to `**JDK 21**` (the build requirement line under "Build requirements").

- [ ] Append the following section at the end of `CLAUDE.md`:
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

- [ ] Commit:
```bash
git add CLAUDE.md
git commit -m "docs: update JDK 17 to 21, add local dev / smoke test guide"
```

---

## Task 7: Create dependabot config

**Files:**
- Create: `.github/dependabot.yml`

- [ ] Create `.github/dependabot.yml`:
```yaml
version: 2
updates:
  - package-ecosystem: "gradle"
    directory: "/"
    schedule:
      interval: "weekly"
```

- [ ] Commit:
```bash
git add .github/dependabot.yml
git commit -m "ci: add Dependabot for weekly Gradle dependency updates"
```

---

## Task 8: Rewrite GitHub Actions workflow

**Files:**
- Modify: `.github/workflows/android-build.yml`

- [ ] Replace the entire content of `.github/workflows/android-build.yml` with:

```yaml
name: Android Build

on:
  push:
    branches: [ "**" ]
  pull_request:
    branches: [ main ]

jobs:
  build:
    runs-on: ubuntu-latest

    steps:
      - uses: actions/checkout@v4

      - name: Set up JDK 21
        uses: actions/setup-java@v4
        with:
          java-version: '21'
          distribution: 'temurin'

      - name: Set up Android SDK
        uses: android-actions/setup-android@v3

      - name: Set up Gradle
        uses: gradle/actions/setup-gradle@v4

      - name: Build debug APK
        run: ./gradlew assembleDebug --stacktrace

      - name: Run unit tests
        run: ./gradlew test --stacktrace

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

      - name: APK security check
        run: |
          BUILD_TOOLS=$(ls -d $ANDROID_HOME/build-tools/*/ | tail -1)
          APK=app/build/outputs/apk/debug/app-debug.apk
          MANIFEST=$("${BUILD_TOOLS}apkanalyzer" manifest print "$APK")
          if echo "$MANIFEST" | grep -qE 'exported="true"' && \
             ! echo "$MANIFEST" | grep -qE 'permission='; then
            echo "WARNING: exported component(s) without permission found"
          fi
          echo "APK advisory check complete (advisory only in Phase 1)"

      - name: Upload debug APK
        uses: actions/upload-artifact@v4
        if: always()
        with:
          name: app-debug
          path: app/build/outputs/apk/debug/app-debug.apk
          retention-days: 14

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

  dependency-scan:
    runs-on: ubuntu-latest
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

  secret-scan:
    runs-on: ubuntu-latest

    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Install gitleaks
        run: |
          curl -sSL https://github.com/gitleaks/gitleaks/releases/latest/download/gitleaks_linux_x64.tar.gz \
            | tar -xz gitleaks
          sudo mv gitleaks /usr/local/bin/

      - name: Scan for secrets
        run: gitleaks detect --source . --verbose
```

- [ ] Verify YAML is valid:
```bash
python3 -c "import yaml; yaml.safe_load(open('/home/yasir/AndroDR/.github/workflows/android-build.yml'))" && echo "YAML valid"
```
Expected: `YAML valid`

- [ ] Commit:
```bash
git add .github/workflows/android-build.yml
git commit -m "ci: add lint gate, detekt SAST, OWASP dep-check, gitleaks, instrumented test job"
```

---

## Task 9: Push and verify

- [ ] Push the branch:
```bash
git push origin claude/android-edr-setup-rl68Y
```

- [ ] Verify recent runs appear (secret-scan triggers on push):
```bash
gh run list --branch claude/android-edr-setup-rl68Y --limit 3
```
Expected: a new run entry appears. The `secret-scan` job runs on push; `instrumented-test` and `dependency-scan` only run on PRs.
