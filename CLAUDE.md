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
```

## Project layout

```
app/src/main/java/com/androdr/
├── data/
│   ├── db/          Room DAOs + AppDatabase
│   └── model/       Domain models (AppRisk, DeviceFlag, DnsEvent, ScanResult)
│   └── repo/        ScanRepository, DnsEventRepository
├── reporting/       ReportFormatter, ReportExporter (export + share flow)
├── scanner/         ScanOrchestrator, AppScanner, DeviceAuditor
├── ui/
│   ├── apps/        Apps screen + ViewModel
│   ├── dashboard/   Dashboard screen + ViewModel
│   ├── device/      Device audit screen + ViewModel
│   ├── history/     History screen + ViewModel (includes export)
│   └── network/     DNS monitor screen + ViewModel
├── vpn/             LocalVpnService (DNS interception)
├── worker/          PeriodicScanWorker (WorkManager)
└── MainActivity.kt
```

## Key architectural decisions
- **Hilt** for DI throughout — every ViewModel, Repository, and service is
  injected
- **Room** stores `ScanResult` (serialized via `kotlinx.serialization`) and
  `DnsEvent` rows
- **FileProvider** (`${applicationId}.fileprovider`) serves exported report
  files from `cacheDir/reports/`; paths config is at
  `res/xml/file_paths.xml`
- **ReportExporter** is a `@Singleton`; it fetches DNS events and captures
  the app's own logcat (`logcat --pid`) before writing a plaintext report

## Development branch
Active feature work lives on **`claude/android-edr-setup-rl68Y`**.

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
