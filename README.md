# AndroDR

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Android](https://img.shields.io/badge/Android-8.0%2B-green.svg)](https://developer.android.com)

Open-source Android security scanner and endpoint detection (EDR). Detects spyware, stalkerware, and malware entirely on-device — no cloud, no accounts, no tracking.

## Who it's for

- **DV survivors** — check if a partner installed monitoring software
- **Journalists and activists** — detect state-sponsored spyware (Pegasus, Predator, Graphite)
- **IT security teams** — lightweight device health checks without commercial MDM
- **Privacy-conscious users** — verify your phone hasn't been compromised

## What it detects

- **Known malware** — package names, signing certificates, and APK file hashes matched against threat intelligence databases
- **Stalkerware** — commercial surveillance apps (TheTruthSpy, mSpy, FlexiSPY, and similar)
- **Mercenary spyware** — Pegasus (NSO), Predator (Intellexa), Graphite (Paragon), NoviSpy, ResidentBat
- **Sideloaded apps** — apps installed from untrusted sources
- **Surveillance permission combinations** — apps holding camera + microphone + location + contacts access
- **Accessibility / Device Admin abuse** — apps misusing privileged services for monitoring
- **Device posture** — screen lock, USB debugging, bootloader state, security patch level
- **Unpatched CVEs** — checks against the CISA Known Exploited Vulnerabilities catalog
- **DNS command-and-control** — connections to known malicious domains (optional local VPN monitor)
- **Spyware file artifacts** — filesystem checks for known spyware remnants
- **Bug report analysis** — forensic analysis of user-provided Android bug reports (`.zip`)
- **Forensic timeline** — notable security events over time (e.g., device admin grants)

## How it works

Detection logic is expressed as [SIGMA](https://github.com/SigmaHQ/sigma)-compatible YAML rules evaluated against telemetry emitted by the scanner. Rules are reviewable as data — not hidden in compiled code.

Indicator data (malicious package names, certificate hashes, C2 domains, APK hashes) lives in the external [`android-sigma-rules`](https://github.com/yasirhamza/android-sigma-rules) repository and refreshes at runtime. New indicators reach users within hours, not release cycles.

## Architecture

```
app/src/main/java/com/androdr/
├── scanner/   Telemetry emitters (apps, device, bugreport)
├── sigma/     SIGMA rule engine
├── ioc/       IOC resolver + feed ingesters
├── data/      Room database + models
├── reporting/ Reports + STIX2 export + timeline
├── network/   Local DNS VPN monitor
└── ui/        Jetpack Compose screens
```

**Key design principles:**
- Detection logic in YAML rules, not Kotlin code
- IOC data in the external rules repo, not bundled in the APK
- All processing on-device — no backend, no accounts, no telemetry
- Privacy by design — auto-prune, no cloud backup, user-initiated sharing only

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the full architecture reference.

## Building

```bash
# Prerequisites: JDK 21, Android SDK (compile SDK 34)
# No API keys required.

./gradlew assembleDebug        # Build debug APK
./gradlew testDebugUnitTest    # Run unit tests
./gradlew lintDebug detekt     # Lint + SAST
./gradlew installDebug         # Install on device/emulator
./gradlew bundleRelease        # Build release AAB
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for the full development workflow (submodules, smoke test, PR process).

## Download

Latest release: https://github.com/yasirhamza/AndroDR/releases/latest

Mirror (for regions where GitHub downloads are throttled): https://androdr.yasirhamza.workers.dev

## Privacy

All scanning and analysis happens entirely on your device. No data is transmitted to any server. See the [privacy policy](https://androdr.yasirhamza.workers.dev/#privacy).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for how to add detection rules (manual or AI-assisted), contribute IOC data, report false positives, and set up the development environment.

## License

Apache License 2.0 — see [LICENSE](LICENSE).
