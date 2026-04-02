# Contributing to AndroDR

Thank you for your interest in contributing to AndroDR. This project helps protect people from spyware, stalkerware, and mobile threats.

## Ways to Contribute

### Detection Rules (SIGMA)
The most impactful contribution is new detection rules. Rules live in the [android-sigma-rules](https://github.com/android-sigma-rules/rules) repo, separate from the app code.

**To add a new rule:**
1. Fork the `android-sigma-rules/rules` repo
2. Create a YAML rule file in the appropriate directory (`app_scanner/`, `device_auditor/`, `dns_monitor/`, etc.)
3. Follow the format of existing rules (see `app_scanner/androdr_001_package_ioc.yml` as a template)
4. Add the rule to `rules.txt`
5. Submit a PR with a description of what the rule detects and why

**Rule format:**
```yaml
title: Short description
id: androdr-NNN
status: experimental
description: What this detects and why it matters
author: Your Name
date: YYYY/MM/DD
tags:
    - attack.tNNNN
logsource:
    product: androdr
    service: app_scanner  # or device_auditor, dns_monitor, etc.
detection:
    selection:
        field_name: value
    condition: selection
level: critical  # or high, medium, low, informational
display:
    category: app_risk  # or device_posture
    triggered_title: "What the user sees"
remediation:
    - "What the user should do, with specific Settings paths"
```

### IOC Data
Add threat indicators to `ioc-data/` files in the rules repo:
- `package-names.yml` — known malicious package names
- `cert-hashes.yml` — known malicious signing certificates
- `c2-domains.yml` — known command-and-control domains
- `popular-apps.yml` — well-known legitimate apps (reduces false positives)

### Bug Reports
Open an issue on the [AndroDR repo](https://github.com/yasirhamza/AndroDR/issues) with:
- Device model and Android version
- Steps to reproduce
- Expected vs actual behavior
- Exported scan report (if relevant)

### False Positive Reports
If AndroDR flags a legitimate app, please report it so we can add it to the known-good database. Include the package name and why it's legitimate.

## Development Setup

```bash
# Prerequisites
# - JDK 21
# - Android SDK with compile SDK 34
# - No API keys required

# Build
./gradlew assembleDebug

# Run tests
./gradlew testDebugUnitTest

# Run lint + detekt
./gradlew lintDebug detekt

# Install on device/emulator
./gradlew installDebug
```

## Architecture Principles

1. **Detection logic in YAML rules, not Kotlin code** — the SIGMA rule engine evaluates rules independently from the app code
2. **IOC data in the rules repo, not bundled in the app** — indicators auto-update without app updates
3. **All processing on-device** — no cloud backend, no telemetry, no user data transmitted
4. **Privacy by design** — collect only what's needed, auto-prune after 30 days

## Code of Conduct

This project serves people in vulnerable situations — domestic violence survivors, journalists under surveillance, activists at risk. All contributions should prioritize user safety and privacy. We do not accept contributions that compromise user privacy or introduce tracking.
