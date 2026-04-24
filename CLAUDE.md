# AndroDR — Claude Code Guide

## What this project is
AndroDR is an Android security / EDR (Endpoint Detection & Response) app built
with Kotlin, Jetpack Compose, Hilt, Room, and WorkManager.  It scans installed
apps for risk signals, audits device security flags, monitors DNS traffic via a
local VPN service, and generates structured security reports.

## Build requirements
- **JDK 21** (`java -version` must report 21.x)
- **Android SDK** with compile SDK 34 and build-tools (set `ANDROID_HOME` or
  let `local.properties` point to your SDK)
- **No API keys or secrets** required; the project compiles and runs fully
  offline

## Common commands

```bash
# Assemble a debug APK
./gradlew assembleDebug

# Run unit tests
./gradlew testDebugUnitTest

# Run lint
./gradlew lintDebug

# Install on a connected device / emulator
./gradlew installDebug

# Build a release APK (minified + shrunk)
./gradlew assembleRelease

# Refresh bundled known-good apps snapshot (requires network)
python3 scripts/generate_known_good_apps.py
```

## Architecture reference

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the architecture, module map, and design principles. Keep that document as the single source of truth — do not duplicate its content here.

## Development workflow
All pull requests target **`main`**. Feature work lives on topic branches
(e.g. `feat/<issue-number>-<short-name>`, `fix/<topic>`, `docs/<topic>`)
branched from `main`, then merged back via PR.

## Lint / code style
The project uses the default Android Lint configuration.  Run
`./gradlew lintDebug` before submitting changes; treat warnings as errors
in release builds.

## Running on a physical device
1. Enable **Developer Options** and **USB Debugging** on the device.
2. `adb devices` — confirm the device is listed.
3. `./gradlew installDebug` — builds and installs.
4. The VPN feature requires the user to accept the VPN permission prompt on
   first launch; it cannot be pre-granted.

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

### Submodule: android-sigma-rules

The sigma-rules repo is the authoritative source for the rule schema
(`rule-schema.json`). It lives at `third-party/android-sigma-rules/` as a
git submodule.

    # After cloning AndroDR (one-time setup):
    git submodule update --init

    # When you need to update the submodule to pick up upstream changes:
    cd third-party/android-sigma-rules && git pull origin main && cd ../..
    git add third-party/android-sigma-rules
    git commit -m "build: bump android-sigma-rules submodule"

**Adding a new field or logsource service to `SigmaRuleParser.kt`:**

1. Open a PR in `android-sigma-rules` updating `validation/rule-schema.json`
2. Merge that PR
3. In your AndroDR PR: bump the submodule pointer AND make the Kotlin change
4. `BundledRulesSchemaCrossCheckTest` will fail if the schema and parser disagree

**Submodule update direction (AI pipeline → AndroDR):** The submodule
pointer stays pinned until explicitly bumped. New rules added upstream by
`/update-rules` don't affect the build until they're bundled into
`app/src/main/res/raw/`. Bump the submodule when you need upstream schema
changes (e.g., after the AI pipeline reveals a schema gap).
