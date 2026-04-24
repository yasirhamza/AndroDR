# AndroDR Architecture

> This is the canonical architecture reference for AndroDR. For how to contribute, see [CONTRIBUTING.md](../CONTRIBUTING.md). For user-facing guarantees, see [PRIVACY_POLICY.md](PRIVACY_POLICY.md). The README carries only a short sketch that links here.

## 1. Overview

AndroDR is an on-device Android security scanner and endpoint detection and response (EDR) app. It detects stalkerware, malware, mercenary spyware, sideloaded app risk, accessibility-service and device-admin abuse, DNS command-and-control traffic, and unpatched CVEs — entirely on the device, with no backend and no cloud dependency. Detection logic is expressed as SIGMA-style YAML rules that are evaluated against structured telemetry events emitted by scanner modules; the Kotlin rule engine is the evaluator, and the YAML files are the behavior. IOC (indicator of compromise) data lives in an external `android-sigma-rules` repository rather than being bundled in the APK, which means new indicators reach users within hours via a background refresh rather than weeks via an app-store release.

```
┌────────────────────────┐
│  Device                │
└─────────┬──────────────┘
          │ (packages, flags, DNS, bug reports)
          ▼
┌────────────────────────┐      ┌───────────────────────┐
│  Telemetry emitters    │      │  IOC resolver         │
│  scanner/, network/    │◄────▶│  ioc/ + ioc/feeds/    │
└─────────┬──────────────┘      └───────────────────────┘
          │ structured events
          ▼
┌────────────────────────┐
│  SIGMA rule engine     │
│  sigma/                │
└─────────┬──────────────┘
          │ findings
          ▼
┌────────────────────────┐      ┌───────────────────────┐
│  Data layer  (Room)    │─────▶│  UI  (Compose)        │
│  data/                 │      │  ui/                  │
└─────────┬──────────────┘      └───────────────────────┘
          │
          ▼
┌────────────────────────┐
│  Reports (+STIX2)      │
│  reporting/            │
└────────────────────────┘
```

### Reader's map

- **Chapter 2** — Design principles: non-negotiables that constrain every module.
- **Chapter 3** — Module map: the actual package tree.
- **Chapter 4** — Detection pipeline: end-to-end data flow from device state to a user-visible finding. **Read first if you want to understand how it all fits.**
- **Chapters 5–8** — Subsystem deep-dives (data, reporting, DNS VPN, bug-report analysis).
- **Chapter 9** — External AI rule-authoring pipeline (Claude Code skills under `.claude/`).
- **Chapter 10** — Test strategy.
- **Chapter 11** — Architecture decisions with the reasoning behind each one.

---

## 2. Design Principles

The following six principles are non-negotiables that constrain every module. A change that violates any one of them requires an explicit architecture decision (see Chapter 11) before it can be merged.

1. **Detection logic lives in YAML SIGMA rules, not in Kotlin code.** The Kotlin engine is the evaluator; rules are the behavior. Adding a new detection means adding a rule file. Consequence: rules are reviewable as data, portable, and updatable without an app release.

2. **IOC data lives in the external `android-sigma-rules` repository, not bundled in the APK.** Indicator lists refresh at runtime so new indicators reach users within hours, not weeks.

3. **Telemetry emitters are pure and stateless.** `scanner/` and `network/` modules produce structured events; they do NOT decide what counts as a finding — the rule engine does. Static enforcement of this contract is tracked in [#136] and the machine-readable schema in [#137].

4. **All processing happens on the device.** No backend, no cloud, no accounts, no analytics SDK. Report sharing is user-initiated only, via the Android share sheet.

5. **Privacy by design.** Collect only what's needed; persist only what's needed; never transmit user data automatically; disable cloud backup (`android:allowBackup="false"`).

6. **SIGMA compatibility where practical.** The rule schema deliberately tracks SIGMA semantics so rules are readable by SIGMA-familiar reviewers and long-run portability stays feasible.

[#136]: https://github.com/yasirhamza/AndroDR/issues/136
[#137]: https://github.com/yasirhamza/AndroDR/issues/137

---

## 3. Module Map

Current package tree under `app/src/main/java/com/androdr/`:

```
.
├── AndroDRApplication.kt
├── MainActivity.kt
├── data/
│   ├── db/          Room DAOs + AppDatabase
│   ├── model/       Domain models (AppRisk, DeviceFlag, DnsEvent, ScanResult, timeline events, bug-report findings)
│   └── repo/        Repositories (ScanRepository, DnsEventRepository, etc.)
├── di/              Hilt modules
├── ioc/             IOC resolver, dispatcher, feeds, STIX2 serialization, periodic update worker
│   └── feeds/       Feed-specific ingesters (stalkerware, MVT, MalwareBazaar, ThreatFox, UAD, Plexus, cert-hash)
├── network/         LocalVpnService (local DNS interception) + DNS event capture
├── reporting/       ReportFormatter, ReportExporter, timeline formatter/exporter, guidance text helpers
├── scanner/         Pure telemetry emitters (app, device, accessibility, app-ops, file artifacts, process, usage stats, receivers, device-admin-grant, install event)
│   └── bugreport/   Bug-report ZIP parser and per-section modules
├── sigma/           SIGMA rule engine: parser, evaluator, engine, correlation, rule feeds, telemetry field maps
└── ui/              Jetpack Compose screens
    ├── apps/          Apps screen + ViewModel
    ├── bugreport/     Bug-report analysis screen + ViewModel
    ├── common/        Shared composables
    ├── dashboard/     Dashboard screen + ViewModel
    ├── device/        Device audit screen + ViewModel
    ├── history/       Scan history + export
    ├── network/       DNS monitor screen + ViewModel
    ├── permissions/   Permission prompts + rationales
    ├── settings/      Settings + About
    ├── theme/         Material theme tokens
    └── timeline/      Forensic timeline screen + ViewModel
```

### Notes

The sole WorkManager worker (`IocUpdateWorker`) lives inside `ioc/`, not in a separate `worker/` package. It is responsible for periodic IOC feed refreshes and is wired up via a Hilt module in `di/`.

STIX2 serialization (`StixBundle.kt`) lives directly in `ioc/`, not in a subdirectory. It is used by the reporting layer to produce machine-readable threat-intelligence exports alongside the human-readable plaintext report.

Scanner modules under `scanner/` are pure: each emitter observes one aspect of device state (installed packages, accessibility services, app-ops grants, running processes, etc.) and produces structured telemetry events. No scanner module evaluates rules or makes pass/fail judgments. The rule engine in `sigma/` is the single place detection logic runs.

UI is strictly a consumer. ViewModels observe repositories via `StateFlow`; no scanning or rule evaluation happens on the UI dispatcher. The UI layer has no direct dependency on `scanner/`, `sigma/`, or `ioc/`.
