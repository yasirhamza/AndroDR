# Contributing to AndroDR

Thank you for your interest in contributing. AndroDR protects people in vulnerable situations — domestic violence survivors, journalists under surveillance, activists at risk — from spyware and stalkerware. Every contribution should advance that mission.

## Ways to contribute

- **Detection rules** (SIGMA YAML) — the most impactful contribution, see below
- **IOC data** — malicious package names, cert hashes, C2 domains, APK hashes
- **False-positive reports** — rules flagging legitimate apps
- **Bug reports** — with device details and reproduction steps
- **Feature ideas** — open a GitHub issue to discuss
- **Code** — Kotlin app code, or AI-pipeline skill improvements

## Writing detection rules — manual path

Rules live in the companion repository: [yasirhamza/android-sigma-rules](https://github.com/yasirhamza/android-sigma-rules). They are bundled into AndroDR via a git submodule and evaluated on-device.

### Add a new rule

1. Fork and clone `android-sigma-rules`.
2. Create a YAML file under the appropriate service directory (`app_scanner/`, `device_auditor/`, `dns_monitor/`, `bugreport/`, etc.).
3. Follow the format below. The authoritative schema is `validation/rule-schema.json` in the same repo.
4. Add your rule filename to `rules.txt`.
5. Open a PR with a description of what the rule detects and why it matters.

### Minimal rule example

```yaml
title: Sample stalkerware package detection
id: androdr-NNN-sample
status: experimental
description: |
  Detects the presence of <specific stalkerware product> by package name.
  Documented by <source link>.
author: Your Name
date: 2026-04-25
tags:
  - attack.t1437  # MITRE ATT&CK technique ID
logsource:
  product: androdr
  service: app_scanner
detection:
  selection:
    package_name|ioc_lookup: package_ioc_db
  condition: selection
level: critical
display:
  category: app_risk
  triggered_title: "<Product> detected"
  severity_description: "Commercial stalkerware that enables remote monitoring."
remediation:
  - "Uninstall the app: Settings → Apps → <Product> → Uninstall."
  - "If uninstall is blocked by device admin, first revoke admin: Settings → Security → Device admin apps → <Product> → Deactivate, then uninstall."
  - "If you are at risk, contact a domestic-violence resource before uninstalling — the installer may be notified."
```

### Field modifiers

The SIGMA rule engine supports these modifiers on `detection:` selections: `contains`, `startswith`, `endswith`, `re` (regex), `gte`, `lte`, `gt`, `lt`, `ioc_lookup`, and the `all` combiner. See `SigmaRuleParser.kt` for the authoritative list.

### Logsource services

The `service:` value must match a supported service. Current services include `app_scanner`, `device_auditor`, `dns_monitor`, and `bugreport`. Adding a new service requires a coordinated change in both repos — see `CLAUDE.md` → "Adding a new field or logsource service."

### Local validation

Run the validation gates locally before opening the PR. From a clone of `android-sigma-rules`:

```bash
./validation/validate.sh your_new_rule.yml
```

All gates (schema, field alignment, modifier compliance, IOC existence, no known-good false positives) must pass.

## Writing detection rules — AI-assisted path

Project maintainers use an AI pipeline (Claude Code skills and slash-commands under `.claude/`) to draft and validate rules from threat-intelligence feeds. You are welcome to use AI in your own rule-authoring workflow. The validation gates are the same whether a rule was hand-written or AI-authored — AI does not skip review.

### Suggested approach for external contributors

1. Provide the AI with this context:
   - The rule schema at `android-sigma-rules/validation/rule-schema.json`
   - Two or three existing rules in the same service directory as examples
   - The threat description or threat-intelligence source you are working from
2. Prompt the AI to produce a candidate rule in the same YAML format, setting `status: experimental` and filling in display and remediation blocks.
3. Review the output critically. AI drafts often:
   - Hallucinate field names — compare against the schema
   - Over-broaden selections — make sure the rule fires only on the intended behavior
   - Reuse remediation text from examples even when it doesn't fit — rewrite to match the actual threat
4. Run local validation gates.
5. Open the PR and mention AI assistance in the description.

For the project's internal pipeline details (agents, dispatch, multi-gate validation), see [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) §9. External contributors do not need that pipeline to contribute.

## IOC data contributions

Indicator data lives in `ioc-data/*.yml` in the rules repo:

- `package-names.yml` — known malicious package names
- `cert-hashes.yml` — malicious signing certificate hashes
- `c2-domains.yml` — command-and-control domains
- `malware-hashes.yml` — APK file hashes (SHA-256)
- `popular-apps.yml` — well-known legitimate apps (reduces false positives)

The AI pipeline's ingester dispatcher writes to these files with cross-feed deduplication. Manual edits are welcome for high-quality, well-sourced additions that the feeds haven't picked up. Include an attribution comment with each entry.

## False-positive reports

If AndroDR flags a legitimate app:

1. Open an issue titled "False positive: <app name>".
2. Include the package name, the rule id (visible in the app's finding detail), your device model and Android version, and why the app is legitimate (link to the official source, enterprise context, etc.).
3. If appropriate, open a PR against `ioc-data/popular-apps.yml` adding the app.

## Bug reports

Open an issue with:

- Device model and Android version
- Steps to reproduce
- Expected vs. actual behavior
- Exported scan report if relevant (review it first for anything you do not want to share publicly)

## Development setup

### Prerequisites

- **JDK 21** (`java -version` must report 21.x)
- **Android SDK** with compile SDK 34 and build-tools. Set `ANDROID_HOME` or point `local.properties` at your SDK.
- **No API keys or secrets required** — AndroDR compiles and runs fully offline.

### Clone and initialize

```bash
git clone https://github.com/yasirhamza/AndroDR.git
cd AndroDR
git submodule update --init
```

The submodule at `third-party/android-sigma-rules/` is authoritative for the rule schema. `BundledRulesSchemaCrossCheckTest` fails the build if the Kotlin parser and the schema disagree.

### Build and test

```bash
./gradlew assembleDebug        # Build debug APK
./gradlew testDebugUnitTest    # Unit tests
./gradlew lintDebug detekt     # Lint + SAST
./gradlew installDebug         # Install on device or emulator
./gradlew bundleRelease        # Release AAB
```

### Smoke test (local emulator)

```bash
./scripts/smoke-test.sh
```

Boots a headless `Medium_Phone_API_36.1` AVD, installs the debug APK, launches the app, and scans logcat for crashes. Requires `ANDROID_HOME` set.

### On-device testing

1. Enable **Developer Options** and **USB Debugging** on the device.
2. `adb devices` — confirm the device is listed.
3. `./gradlew installDebug`.
4. The DNS VPN feature requires the user to accept the Android VPN permission dialog on first launch — it cannot be pre-granted.

### Submodule update direction

The submodule pointer is pinned. Rules added upstream to `android-sigma-rules` do not affect the built APK until the submodule is explicitly bumped:

```bash
cd third-party/android-sigma-rules && git pull origin main && cd ../..
git add third-party/android-sigma-rules
git commit -m "build: bump android-sigma-rules submodule"
```

Bump when you need upstream schema changes (a new modifier or logsource service) or when staging rules should be promoted into the built APK.

## PR workflow

- Branch from `main`. Name branches `feat/<issue>-<short-name>`, `fix/<topic>`, `docs/<topic>`, `ci/<topic>`, `test/<topic>`.
- Target `main` in your PR. Do NOT target `claude/*` branches — those are obsolete mirrors being deleted.
- Include `Closes #N` in the PR body so merging auto-closes the linked issue.
- CI must pass — specifically the `build` check.
- Prefer small, focused PRs over sweeping changes. A PR reviewer should be able to hold the whole diff in their head.

## Architecture principles

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) §2 for the non-negotiables and the reasoning behind them.

## Code of conduct

This project serves people in vulnerable situations — domestic violence survivors, journalists under surveillance, activists at risk. All contributions must prioritize user safety and privacy. Contributions that add tracking, analytics, remote telemetry, or other mechanisms that could compromise user privacy will not be accepted regardless of technical merit.
