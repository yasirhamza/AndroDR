# AndroDR

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Android](https://img.shields.io/badge/Android-8.0%2B-green.svg)](https://developer.android.com)

Open-source Android security scanner and endpoint detection (EDR). Detects spyware, stalkerware, and malware entirely on-device — no cloud, no accounts, no tracking.

## Who It's For

- **DV survivors** — check if a partner installed monitoring software
- **Journalists & activists** — detect state-sponsored spyware (Pegasus, Predator, Graphite)
- **IT security teams** — lightweight device health checks without commercial MDM
- **Privacy-conscious users** — verify your phone hasn't been compromised

## What It Detects

- **Known malware** — package names, signing certificates, and APK file hashes matched against threat intelligence databases
- **Stalkerware** — commercial surveillance apps (TheTruthSpy, mSpy, FlexiSPY, etc.)
- **Mercenary spyware** — Pegasus (NSO), Predator (Intellexa), Graphite (Paragon), NoviSpy, ResidentBat
- **Sideloaded apps** — apps not installed from trusted app stores
- **Surveillance permissions** — apps with camera + microphone + location + contacts access
- **Accessibility abuse** — apps misusing accessibility services for monitoring
- **Device posture** — screen lock, USB debugging, bootloader, security patch level
- **Unpatched CVEs** — checks against CISA Known Exploited Vulnerabilities catalog
- **DNS threats** — connections to known command-and-control servers (optional VPN monitor)
- **Spyware file artifacts** — filesystem checks for known spyware remnants
- **Bugreport analysis** — deep forensic analysis of Android system diagnostics

## How It Works

AndroDR uses [SIGMA](https://github.com/SigmaHQ/sigma)-compatible detection rules evaluated against device telemetry. Detection logic lives in YAML rules — transparent, auditable, community-updatable — not hardcoded in the app.

Threat intelligence feeds refresh every 12 hours from public sources (MalwareBazaar, MVT indicators, ThreatFox, CISA KEV, OSV). IOC updates deploy to all users without an app update.

## Architecture

```
app/src/main/java/com/androdr/
├── scanner/        AppScanner, DeviceAuditor, bugreport modules
├── sigma/          SIGMA rule engine, parser, evaluator
├── ioc/            Unified IOC resolver, feeds, STIX2 import/export
├── data/           Room database, models, repositories
├── reporting/      Report formatter, timeline exporter, STIX2 export
├── network/        DNS VPN service
├── ui/             Jetpack Compose screens (dashboard, apps, device, network, timeline)
└── worker/         WorkManager periodic IOC updates
```

**Key design principles:**
- Detection logic in YAML rules, not Kotlin code
- IOC data in the [rules repo](https://github.com/android-sigma-rules/rules), not bundled in the app
- All processing on-device — no cloud backend
- Privacy by design — auto-prune after 30 days, no telemetry

## Building

```bash
# Prerequisites: JDK 21, Android SDK (compile SDK 34)
# No API keys required

./gradlew assembleDebug        # Build debug APK
./gradlew testDebugUnitTest    # Run unit tests
./gradlew lintDebug detekt     # Lint + SAST
./gradlew installDebug         # Install on device/emulator
./gradlew bundleRelease        # Build release AAB for Play Store
```

## Download

[Latest release](https://github.com/yasirhamza/AndroDR/releases/latest)

## Privacy

All scanning and analysis happens entirely on your device. No data is transmitted to any server. See the [privacy policy](https://yasirhamza.github.io/androdr-site/#privacy).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for how to add detection rules, report false positives, and set up the development environment.

## License

Apache License 2.0 — see [LICENSE](LICENSE).
