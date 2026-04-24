# Docs Refresh PR B — Documentation Sweep Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the drift-prone mixed architecture content across README / CONTRIBUTING / CLAUDE.md with a single canonical `docs/ARCHITECTURE.md` reference, rewrite README and CONTRIBUTING to reflect current code (including an AI-assisted rule-authoring path for external contributors), trim CLAUDE.md, delete the stale ROADMAP, and deduplicate the play-store directory.

**Architecture:** Every architecture fact lives in exactly one place. README gives a short, user-first sketch with a pointer out. CONTRIBUTING focuses on how-to-contribute with a pointer out. CLAUDE.md is reduced to AI-agent-only content with a pointer out. `docs/ARCHITECTURE.md` is the one authoritative reference.

**Tech Stack:** Markdown (no code changes). `gh` CLI for issue filing.

**Spec:** `docs/superpowers/specs/2026-04-24-docs-refresh-design.md` §6.

**Prereq:** PR A plan (`2026-04-24-docs-refresh-pr-a-privacy-pipeline.md`) completed and verified end-to-end.

---

## File structure

**Repo: `yasirhamza/AndroDR`**
- Create: `docs/ARCHITECTURE.md` — canonical architecture reference (~600 lines)
- Modify: `README.md` — rewrite (~150 lines)
- Modify: `CONTRIBUTING.md` — rewrite (~300–400 lines)
- Modify: `CLAUDE.md` — trim project-layout and key-decisions sections to a pointer
- Delete: `docs/ROADMAP.md` — after extracting its "Architecture Notes" paragraph
- Delete: `docs/play-store/query-all-packages-declaration.md` (keep `16-…`)
- Delete: `docs/play-store/vpn-service-declaration.md` (keep `17-…`)
- Delete: `docs/play-store/data-safety-form.md` (keep `18-…`)
- Delete: `docs/play-store/content-rating-iarc.md` (keep `19-…`)
- Delete: `docs/play-store/store-listing.md` (keep `20-…`)

Commit order inside the PR branch is intentional — ARCHITECTURE.md lands first so later commits can reference it.

---

## Task 1: Create branch and capture baseline

**Repo:** `yasirhamza/AndroDR`

- [ ] **Step 1: Ensure PR A has merged and verified**

Check: the PR A plan's end-to-end verification is complete. The AndroDR PR from PR A is merged. If it hasn't, stop and finish PR A first.

Run: `git log --oneline -5 origin/main` — confirm the PR A content commits are in.

- [ ] **Step 2: Create branch**

```bash
cd /home/yasir/AndroDR
git checkout main
git pull --ff-only
git checkout -b docs/sweep
```

- [ ] **Step 3: Capture the current package tree to reference while drafting**

Run:
```bash
find app/src/main/java/com/androdr -maxdepth 2 -type d | sort > /tmp/androdr-package-tree.txt
cat /tmp/androdr-package-tree.txt
```
Keep this open; Tasks 2–5 and 7 cite it to stay accurate.

---

## Task 2: Draft `docs/ARCHITECTURE.md` chapters 1–3 (overview, principles, module map)

**Repo:** `yasirhamza/AndroDR`
**Files:**
- Create: `docs/ARCHITECTURE.md`

- [ ] **Step 1: Write the file header and chapter 1 (Overview)**

Create `docs/ARCHITECTURE.md` starting with:
```markdown
# AndroDR Architecture

> This is the canonical architecture reference for AndroDR. For how to contribute, see [CONTRIBUTING.md](../CONTRIBUTING.md). For user-facing guarantees, see [PRIVACY_POLICY.md](PRIVACY_POLICY.md). The README holds only a short sketch that links here.

## 1. Overview

AndroDR is an open-source Android security scanner and endpoint detection tool. It runs entirely on-device — no backend, no accounts, no telemetry — and detects stalkerware, malware, mercenary spyware, sideloaded risk, accessibility/device-admin abuse, DNS command-and-control, and unpatched CVEs. Detection logic is expressed as SIGMA-style YAML rules that are evaluated against telemetry emitted by scanner modules; indicator-of-compromise (IOC) data lives in an external rules repository so updates ship without an app release.

```
┌────────────────────────┐
│  Device                │
└─────────┬──────────────┘
          │ (packages, flags, DNS, bugreports)
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

- Chapter 2 — the non-negotiables that constrain every module.
- Chapter 3 — the actual package tree in the app as of the most recent build.
- Chapter 4 — the end-to-end detection pipeline. **Read this first if you want to understand how everything fits together.**
- Chapters 5–8 — subsystem deep-dives (data, reporting, DNS VPN, bugreport analysis).
- Chapter 9 — the external AI rule-authoring pipeline (Claude Code skills in `.claude/`).
- Chapter 10 — test strategy.
- Chapter 11 — architecture decisions with the reasoning behind each one.
```

- [ ] **Step 2: Write chapter 2 (Design principles)**

Append:
```markdown
## 2. Design principles

These are non-negotiable. Contributions that contradict them should be rejected or re-scoped.

1. **Detection logic lives in YAML SIGMA rules, not in Kotlin code.** The Kotlin rule engine is the evaluator; rules are the behavior. Adding a new detection is adding a rule file. Consequences: rules are reviewable as data, portable, and updatable without an app release.
2. **IOC data lives in the external `android-sigma-rules` repository, not bundled in the APK.** Indicator lists (malicious package names, cert hashes, C2 domains, APK hashes) refresh at runtime, so new indicators reach users within hours, not weeks.
3. **Telemetry emitters are pure and stateless.** Modules in `scanner/` and `network/` produce structured events from device state. They do not decide whether something is a finding — that's the rule engine's job. See issues [#136] (static enforcement) and [#137] (schema-as-contract).
4. **All processing happens on the device.** No backend, no cloud, no accounts, no analytics SDK. Report sharing is always user-initiated, via the Android share sheet.
5. **Privacy by design.** Collect only what's needed; persist only what's needed; never transmit user data automatically; disable cloud backup (`android:allowBackup="false"`).
6. **SIGMA compatibility where practical.** The rule schema deliberately tracks SIGMA semantics so rules can be understood by readers familiar with SIGMA, and so long-run portability to other SIGMA engines stays feasible.

[#136]: https://github.com/yasirhamza/AndroDR/issues/136
[#137]: https://github.com/yasirhamza/AndroDR/issues/137
```

- [ ] **Step 3: Write chapter 3 (Module map) against the captured tree**

Reference `/tmp/androdr-package-tree.txt` from Task 1 Step 3. Append:
```markdown
## 3. Module map

Current package tree under `app/src/main/java/com/androdr/`:

\`\`\`
├── data/
│   ├── db/          Room DAOs + AppDatabase
│   ├── model/       Domain models (AppRisk, DeviceFlag, DnsEvent, ScanResult, TimelineEvent, BugreportFinding)
│   └── repo/        ScanRepository, DnsEventRepository, TimelineRepository
├── di/              Hilt modules
├── ioc/             Unified IOC resolver, dispatcher, cross-dedup, STIX2 import/export
│   └── feeds/       Ingesters: stalkerware, MVT, MalwareBazaar, ThreatFox, UAD, Plexus, cert-hash
├── network/         LocalVpnService (local DNS interception), DNS event capture
├── reporting/       ReportFormatter, ReportExporter, STIX2 exporter, timeline serializer
├── scanner/         ScanOrchestrator, AppScanner, DeviceAuditor
│   └── bugreport/   Bugreport ZIP parser and finding emitter
├── sigma/           SIGMA rule parser, evaluator, modifier support, schema loader
├── ui/              Jetpack Compose screens
│   ├── apps/        Apps screen + ViewModel
│   ├── bugreport/   Bugreport analysis screen + ViewModel
│   ├── common/      Shared composables
│   ├── dashboard/   Dashboard screen + ViewModel
│   ├── device/      Device audit screen + ViewModel
│   ├── history/     Scan history + export
│   ├── network/     DNS monitor screen + ViewModel
│   ├── permissions/ Permission prompts + rationales
│   ├── settings/    Settings + About
│   ├── theme/       Material theme tokens
│   └── timeline/    Forensic timeline screen + ViewModel
├── worker/          WorkManager periodic IOC refresh + scan
├── AndroDRApplication.kt
└── MainActivity.kt
\`\`\`
```

- [ ] **Step 4: Verify the module tree matches reality**

Run:
```bash
for dir in data/db data/model data/repo di ioc ioc/feeds network reporting scanner scanner/bugreport sigma \
           ui/apps ui/bugreport ui/common ui/dashboard ui/device ui/history ui/network ui/permissions ui/settings ui/theme ui/timeline; do
  test -d "app/src/main/java/com/androdr/$dir" || echo "MISSING: $dir"
done
```
Expected: no output (all directories exist). Any MISSING line is a plan bug — fix the doc before continuing.

- [ ] **Step 5: Commit**

```bash
git add docs/ARCHITECTURE.md
git commit -m "docs(architecture): ch 1-3 overview, principles, module map"
```

---

## Task 3: Draft `docs/ARCHITECTURE.md` chapter 4 (Detection pipeline)

**Repo:** `yasirhamza/AndroDR`
**Files:**
- Modify: `docs/ARCHITECTURE.md`

- [ ] **Step 1: Append chapter 4**

Append:
```markdown
## 4. Detection pipeline

This is the end-to-end flow from raw device state to a user-visible finding. Four stages, four clear responsibilities.

### 4.1 Telemetry emitters (`scanner/`, `network/`, `scanner/bugreport/`)

Emitters are pure functions from device state to structured telemetry events. They do **not** know anything about detection rules, severity, or remediation. Their only job is "what is true about the device right now, expressed as typed records."

Current emitters:

- `AppScanner` → produces `AppTelemetry` records for each installed package (package name, signing cert hash, requested permissions, installer source, first-install/last-update time).
- `DeviceAuditor` → produces `DeviceFlag` records (screen lock presence, USB debugging, bootloader verifiedboot state, security patch level, dev-settings, install-from-unknown sources).
- `LocalVpnService` → produces `DnsEvent` records (domain, timestamp, querying app UID when attributable).
- `scanner/bugreport/` → produces `BugreportTelemetry` (parsed dumpsys sections, process names, abnormal wakelocks, base64 blob counts, crash patterns) from a user-provided bug report ZIP.

The purity contract is enforced by convention today and targeted for static-analysis enforcement in [#136].

### 4.2 SIGMA rule engine (`sigma/`)

The rule engine parses YAML rule files from `app/src/main/res/raw/` (bundled rules) and any remote rule feeds configured at runtime. A rule is a declaration of (a) which telemetry type it applies to, (b) field matches with modifiers (`contains`, `startswith`, `endswith`, `regex`, numeric comparisons), (c) a condition combining selections, (d) display metadata (title, severity, category), and (e) remediation guidance shown to the user.

Key files:
- `SigmaRuleParser.kt` — parses rule YAML against the schema in `third-party/android-sigma-rules/validation/rule-schema.json` (submodule; see `CLAUDE.md` for update flow).
- `SigmaEvaluator.kt` — evaluates parsed rules against a stream of telemetry events.
- `SigmaModifier.kt` — implements the modifier algebra (`|contains`, `|startswith`, etc.).

`BundledRulesSchemaCrossCheckTest` in the test suite fails the build if the parser and the schema disagree on which fields or modifiers are valid — the submodule is the authoritative contract.

### 4.3 IOC resolver (`ioc/`, `ioc/feeds/`)

Detection rules reference IOC lists by name (e.g., `ioc:packages:stalkerware`). The IOC resolver answers those lookups. Indicator types currently supported:

| Indicator type | Source examples | Dispatcher owner |
|---|---|---|
| Package name | stalkerware-indicators, MVT | PublicRepoIocFeed |
| Cert hash (signing certificate SHA-256) | stalkerware-indicators, MalwareBazaar | PublicRepoIocFeed + MalwareBazaarFeed |
| C2 domain | MVT, ThreatFox | PublicRepoIocFeed + ThreatFoxFeed |
| APK file hash (SHA-256 of APK) | MalwareBazaar | MalwareBazaarApkHashFeed |

The dispatcher (`ioc/IocDispatcher.kt`) performs cross-feed deduplication before writing the indicator to the on-device Room store. This is how the same indicator (e.g., a cert hash appearing in both the stalkerware feed and MalwareBazaar) gets merged into a single resolver entry with attribution preserved. See issue [#143] for the open edge-case around dual-writer collisions.

Cursor state (feed-last-fetched timestamps) and decisions (which indicators were accepted / rejected / deduplicated) are persisted with explicit schemas in the rules repo so the pipeline is debuggable post-hoc.

### 4.4 Findings

When the evaluator finds a match, it produces a `Finding` record carrying:
- rule id + title (from rule `display:` block)
- severity + category
- matched telemetry reference
- remediation text

Findings are persisted in Room, displayed in the dashboard / apps / device / timeline screens, and included in exported reports. Display metadata lives in the rule, not in Kotlin — adding a new detection doesn't touch UI code.

### 4.5 Example end-to-end walkthrough

1. `AppScanner` enumerates installed packages and emits `AppTelemetry(packageName="com.example.stalker", certHash="abc...", ...)`.
2. Evaluator loads rule `androdr-001-package-ioc.yml` which has selection `packageName|in:ioc:packages:stalkerware`.
3. `IocDispatcher` resolves `ioc:packages:stalkerware` → returns a set that includes `com.example.stalker` (ingested from stalkerware-indicators feed on last refresh).
4. Condition matches. Evaluator produces `Finding(ruleId="androdr-001", severity="critical", ...)`.
5. Finding is written to `ScanRepository`.
6. Apps screen observes the repository and displays the finding with remediation.
7. User exports a report; `ReportExporter` includes the finding with full context.
```

- [ ] **Step 2: Commit**

```bash
git add docs/ARCHITECTURE.md
git commit -m "docs(architecture): ch 4 detection pipeline"
```

---

## Task 4: Draft `docs/ARCHITECTURE.md` chapters 5–8 (subsystems)

**Repo:** `yasirhamza/AndroDR`
**Files:**
- Modify: `docs/ARCHITECTURE.md`

- [ ] **Step 1: Append chapter 5 (Data layer)**

Append:
```markdown
## 5. Data layer (`data/`)

- **Room database** (`AppDatabase`) stores scan results, DNS events, timeline events, bugreport findings, and IOC cache state. `ScanResult` is serialized via `kotlinx.serialization` so the schema can evolve without DB migrations for every rule change.
- **Auto-prune** policy keeps scan history retention bounded (configurable; current default: 30 days for DNS events and timeline events).
- **Cloud backup is disabled** (`android:allowBackup="false"` in manifest) — scan data never reaches Google's backup servers.
- **STIX2 indicator model** lives in `ioc/stix2/` and is used for both ingesting STIX2 bundles and exporting findings to STIX2-consuming tools.
```

- [ ] **Step 2: Append chapter 6 (Reporting & export)**

Append:
```markdown
## 6. Reporting & export (`reporting/`)

- **`ReportFormatter`** builds a plaintext report from current scan results, DNS events, timeline, and device flags.
- **`ReportExporter`** is a `@Singleton` that writes the formatted report to `cacheDir/reports/` and captures up to 300 lines of AndroDR's own process log (`logcat --pid` — not system-wide logs). A `FileProvider` configured at `${applicationId}.fileprovider` (paths: `res/xml/file_paths.xml`) serves the file to the Android share sheet.
- **STIX2 export** writes a STIX2 bundle of findings + observed indicators for forensic tool interop.
- **Timeline export** serializes the forensic timeline (e.g., device admin grants per #79) into the report.
- Every export is **user-initiated only** — there is no automatic upload path, by construction.
```

- [ ] **Step 3: Append chapter 7 (DNS monitor)**

Append:
```markdown
## 7. DNS monitor (`network/`)

`LocalVpnService` implements a local VPN that intercepts only DNS queries on-device. It:

- Never routes traffic off-device. The service acts as a local DNS resolver and forwards DNS responses back to the app that issued the query; non-DNS traffic is untouched.
- Emits `DnsEvent` records into the same evaluator pipeline as other telemetry. A rule that matches domains in the C2 domain IOC list will fire whether the domain came from a scan or from a real-time DNS event.
- Is strictly optional. The user must accept the Android VPN permission dialog to enable it; there is no way to pre-grant.

### Why DNS-only and not full traffic

Full IP-level filtering / inspection was evaluated and parked. Reasons: (a) TLS SNI inspection introduces trust issues that conflict with the privacy-by-design principle, (b) DNS-level indicator matching covers the overwhelming majority of mobile C2 use cases identified in threat-intel feeds, (c) full filtering materially expands the app's surface area and review burden. The decision is recorded in §11.
```

- [ ] **Step 4: Append chapter 8 (Bugreport analysis)**

Append:
```markdown
## 8. Bugreport analysis (`scanner/bugreport/`)

Android bug reports (`.zip`) contain dumpsys output, process lists, battery stats, and a wealth of forensic signal that doesn't surface through normal runtime APIs. AndroDR accepts a user-provided bugreport and emits findings.

Pipeline stages:

1. **Accept** — user picks a bugreport ZIP via the Android file picker. No auto-capture.
2. **Parse** — extract relevant dumpsys sections (package, accessibility, device-admin, batterystats wakelocks, process names).
3. **Emit telemetry** — produce `BugreportTelemetry` records that flow into the same rule evaluator as `AppTelemetry` and `DeviceFlag`. There is no bugreport-specific detection logic in the evaluator.
4. **Match** — rules with `logsource.service: bugreport` fire on matching telemetry.
5. **Display findings** — bugreport screen shows what was detected, with pointers into the raw dumpsys for investigation.
6. **Discard raw** — the original ZIP is not persisted after analysis. Only the structured findings are kept.

Bug reports are among the most sensitive files on an Android device. AndroDR handles them with a strict "your device, your choice" model.
```

- [ ] **Step 5: Verify Kotlin files referenced in chapters 5–8 still exist**

Run:
```bash
find app/src/main/java/com/androdr/reporting -name 'ReportFormatter.kt' -o -name 'ReportExporter.kt'
find app/src/main/java/com/androdr/network -name 'LocalVpnService.kt'
find app/src/main/java/com/androdr/scanner/bugreport -type f -name '*.kt' | head -3
```
Expected: all the named files exist. If any is missing or renamed, update the doc before committing.

- [ ] **Step 6: Commit**

```bash
git add docs/ARCHITECTURE.md
git commit -m "docs(architecture): ch 5-8 data, reporting, DNS, bugreport"
```

---

## Task 5: Draft `docs/ARCHITECTURE.md` chapters 9–11 (AI pipeline, testing, decisions) + fold ROADMAP notes

**Repo:** `yasirhamza/AndroDR`
**Files:**
- Modify: `docs/ARCHITECTURE.md`
- Read (to extract): `docs/ROADMAP.md` (not yet deleted)

- [ ] **Step 1: Append chapter 9 (AI rule-authoring pipeline)**

Append:
```markdown
## 9. AI rule-authoring pipeline

AndroDR uses an AI-assisted pipeline to generate and validate new SIGMA detection rules from threat intelligence sources. The pipeline lives in `.claude/` (Claude Code skills and slash commands) and operates on the external rules repository, not on the app. External contributors do **not** need access to this pipeline to contribute rules — see `CONTRIBUTING.md` for both manual and AI-assisted contribution paths.

### Pipeline stages

1. **Ingest** — feed-specific skills parse upstream threat-intel sources into a normalized `SIR` (Structured Indicator Record) format:
   - `/update-rules-ingest-abusech` (MalwareBazaar + ThreatFox)
   - `/update-rules-ingest-stalkerware` (AssoEchap/stalkerware-indicators)
   - `/update-rules-ingest-mvt` (mvt-project indicators)
   - `/update-rules-ingest-asb` (Android Security Bulletins)
   - `/update-rules-ingest-nvd` (NVD/NIST CVE database, Android-filtered)
   - `/update-rules-ingest-amnesty` (AmnestyTech/investigations)
   - `/update-rules-ingest-attack` (MITRE ATT&CK Mobile)
2. **Discover** — `/update-rules-discover` autonomously surfaces threat names from vendor-blog RSS/HTML indices, feeding new SIRs back into ingest.
3. **Research** — `/update-rules-research-threat` does targeted web research on a named threat to complete its SIR.
4. **Author** — `/update-rules-author` turns SIRs into candidate SIGMA YAML rules, applying the bundled rule schema and current logsource taxonomy.
5. **Validate** — `/update-rules-validate` runs a 5-gate validation pipeline (schema, field alignment, modifier compliance, IOC existence, no false-positive on known-good apps).
6. **Review** — `/update-rules-review` performs an independent LLM review of the AI-authored rules, catching issues like overfitting or missing remediation text.
7. **Stage and promote** — rules land first in `staging/`, go through Gate-4 harness testing on real telemetry, and get promoted to production when the harness confirms expected behavior.

The orchestrator `/update-rules` runs the full cycle end-to-end.

### Rules repository

All rules and IOC data live in `https://github.com/yasirhamza/android-sigma-rules`, which is vendored into AndroDR as a git submodule at `third-party/android-sigma-rules/`. The submodule pointer is only bumped when the app needs upstream schema changes — adding a rule upstream does not automatically affect the built APK.
```

- [ ] **Step 2: Append chapter 10 (Test strategy)**

Append:
```markdown
## 10. Test strategy

- **Unit tests** (`app/src/test/`) cover parsers, emitters, the rule evaluator, the IOC resolver, report formatting, and serialization. All run via `./gradlew testDebugUnitTest`.
- **Instrumentation tests** (`app/src/androidTest/`) cover Room DAOs, the DNS VPN service, and file-provider-backed export flows. Run on a connected device or emulator.
- **`BundledRulesSchemaCrossCheckTest`** asserts the Kotlin `SigmaRuleParser` and the JSON schema in the submodule agree on allowed fields and modifiers. This is the tripwire for schema drift.
- **Validation gates on rules** (see §9) run on every proposed rule change — AI-generated or hand-authored.
- **UAT persona testing** via `/uat-test` evaluates AndroDR output from real user perspectives (DV survivor, investigative journalist, IT admin) before material UX changes land.
- **On-device smoke test** (`scripts/smoke-test.sh`) boots a headless `Medium_Phone_API_36.1` AVD, installs the debug APK, launches the app, and scans logcat for crashes. Required before releasing.
- **Lint + detekt** (`./gradlew lintDebug detekt`) run on every CI build; warnings are errors in release builds.
```

- [ ] **Step 3: Read the old ROADMAP "Architecture Notes" paragraph**

Run:
```bash
sed -n '/^## Architecture Notes/,$p' docs/ROADMAP.md
```
Keep this text open for Step 4.

- [ ] **Step 4: Append chapter 11 (Decisions), absorbing the ROADMAP notes**

Append:
```markdown
## 11. Decisions

Short ADR-style entries for load-bearing choices. Each has a one-line claim followed by the reasoning.

### D1. Detection logic in YAML SIGMA rules, not Kotlin code

Rules are reviewable as data, portable, and updatable without app releases. Adding a detection is adding a rule file and an IOC entry, not a code change.

### D2. IOC data lives in an external rules repository, not bundled in the APK

Indicators update faster than app release cadence; DV survivors and journalists benefit from hours-not-weeks indicator turnaround.

### D3. DNS-only VPN scope (full IP filtering parked)

Full IP-level inspection was evaluated and rejected. DNS-level indicator matching covers the majority of observed mobile C2 patterns, and full inspection would require TLS SNI handling that conflicts with privacy-by-design.

### D4. Pure-emitter telemetry/findings contract

Emitters produce typed records; the rule engine is the only decision-maker. This keeps emitters testable, the engine deterministic, and rules the single place detection behavior lives. Static enforcement is open work: [#136]. Machine-readable schema contract: [#137].

### D5. SIGMA compatibility where practical

The rule schema deliberately tracks SIGMA semantics. Some divergences are unavoidable (Android-specific logsource services, display metadata for UI), but modifier semantics, field matching, and condition composition mirror SIGMA.

### D6. No cloud backend

No AndroDR-operated server exists. All processing is on-device. Updates to indicators happen via direct fetches from upstream threat-intel sources, unauthenticated, without transmitting user data. This choice is load-bearing for GDPR/CCPA posture.

### D7. Rule engine capabilities

The rule engine supports field matching with modifiers (`contains`, `startswith`, `endswith`, `regex`, numeric comparisons), IOC lookups (package / cert hash / domain / APK hash), evidence providers (CVE lists with campaign attribution), display metadata (titles, icons, severity, evidence type) embedded in rules, and remote rule feeds from configurable URLs.

### Open architecture work

- Persist all telemetry types to Room for complete forensic export: [#96]
- Static enforcement of the pure-emitter contract: [#136]
- Machine-readable telemetry schema contract: [#137]
- Rule-lineage tooling for the rule author agent: [#139]

[#96]: https://github.com/yasirhamza/AndroDR/issues/96
[#136]: https://github.com/yasirhamza/AndroDR/issues/136
[#137]: https://github.com/yasirhamza/AndroDR/issues/137
[#139]: https://github.com/yasirhamza/AndroDR/issues/139
[#143]: https://github.com/yasirhamza/AndroDR/issues/143
```

- [ ] **Step 5: Verify ARCHITECTURE.md has the expected structure**

Run:
```bash
grep -c '^## ' docs/ARCHITECTURE.md
grep -c '^### ' docs/ARCHITECTURE.md
wc -l docs/ARCHITECTURE.md
```
Expected: 11 top-level sections (matching the 11 chapters), ≥20 subsections, ≥500 lines.

- [ ] **Step 6: Commit**

```bash
git add docs/ARCHITECTURE.md
git commit -m "docs(architecture): ch 9-11 AI pipeline, tests, decisions (fold ROADMAP notes)"
```

---

## Task 6: Rewrite `README.md`

**Repo:** `yasirhamza/AndroDR`
**Files:**
- Modify: `README.md`

- [ ] **Step 1: Read the current README so the Write tool has a prior Read on this file, then replace**

Run: `cat README.md | head -1` (or use the Read tool).

Then use Write to replace the file with:
```markdown
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
- **Stalkerware** — commercial surveillance apps (TheTruthSpy, mSpy, FlexiSPY, etc.)
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

\`\`\`
app/src/main/java/com/androdr/
├── scanner/   Telemetry emitters (apps, device, bugreport)
├── sigma/     SIGMA rule engine
├── ioc/       IOC resolver + feed ingesters
├── data/      Room database + models
├── reporting/ Reports + STIX2 export + timeline
├── network/   Local DNS VPN monitor
└── ui/        Jetpack Compose screens
\`\`\`

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
```

- [ ] **Step 2: Verify the README tree matches reality**

Run:
```bash
for dir in scanner sigma ioc data reporting network ui; do
  test -d "app/src/main/java/com/androdr/$dir" || echo "MISSING: $dir"
done
```
Expected: no output. If anything is missing, the README tree is wrong — fix before committing.

- [ ] **Step 3: Commit**

```bash
git add README.md
git commit -m "docs(readme): rewrite to reflect current code + link to ARCHITECTURE.md"
```

---

## Task 7: Rewrite `CONTRIBUTING.md`

**Repo:** `yasirhamza/AndroDR`
**Files:**
- Modify: `CONTRIBUTING.md`

- [ ] **Step 1: Read the current CONTRIBUTING to preserve anything unique**

Read `CONTRIBUTING.md` end-to-end. Extract:
- The code-of-conduct wording (preserve verbatim — it's strong and correct).
- The rule file example structure.

- [ ] **Step 2: Replace `CONTRIBUTING.md` with fresh content**

Use Write to replace the file with:
```markdown
# Contributing to AndroDR

Thank you for your interest in contributing. AndroDR protects people in vulnerable situations — domestic violence survivors, journalists under surveillance, activists at risk — from spyware and stalkerware. Every contribution should advance that mission.

## Ways to contribute

- **Detection rules** (SIGMA YAML) — the most impactful contribution, see below
- **IOC data** — malicious package names, cert hashes, C2 domains
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
  This product is documented by <source link>.
author: Your Name
date: 2026-04-24
tags:
  - attack.t1437  # MITRE ATT&CK technique ID
logsource:
  product: androdr
  service: app_scanner
detection:
  selection:
    packageName|in: ioc:packages:stalkerware
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

### Logsource services

The `service:` value must match a supported service in `SigmaRuleParser.kt`. Current services include `app_scanner`, `device_auditor`, `dns_monitor`, and `bugreport`. Adding a new service requires a coordinated change in both repos (see `CLAUDE.md` → "Adding a new field or logsource service").

### Local validation

Before opening the PR, run the validation gates locally:

```bash
cd android-sigma-rules
./validation/validate.sh your_new_rule.yml
```

All five gates (schema, field alignment, modifier compliance, IOC existence, no known-good false positives) must pass.

## Writing detection rules — AI-assisted path

Project maintainers use an AI pipeline (Claude Code skills in `.claude/`) to draft and validate rules from threat-intelligence feeds. You are welcome to use AI in your own rule-authoring workflow — the validation gates are the same whether a rule was hand-written or AI-authored, so AI does not skip review.

### Suggested approach

1. Provide the AI with the following context:
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

For the project's internal pipeline details, see [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) §9. External contributors do not need that pipeline to contribute.

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
- Exported scan report if relevant (review it first for anything you don't want to share publicly)

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

The submodule at `third-party/android-sigma-rules/` is authoritative for the rule schema; `BundledRulesSchemaCrossCheckTest` fails the build if the parser and schema disagree.

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

The submodule pointer is pinned. The AI pipeline and upstream contributors can add rules to `android-sigma-rules` without affecting the built APK until the submodule is explicitly bumped:

```bash
cd third-party/android-sigma-rules && git pull origin main && cd ../..
git add third-party/android-sigma-rules
git commit -m "build: bump android-sigma-rules submodule"
```

Bump when you need upstream schema changes (e.g., a new modifier or logsource service) or when staging rules should be promoted into the built APK.

## PR workflow

- Branch from `main`; name branches `feat/<issue>-<short-name>`, `fix/<topic>`, `docs/<topic>`, `ci/<topic>`, `test/<topic>`.
- Target `main` in your PR. Do not target `claude/*` branches — those are obsolete mirrors being deleted.
- Include `Closes #N` in the PR body so merging auto-closes the linked issue.
- CI must pass — specifically the `build` check.
- Prefer small, focused PRs over sweeping changes. A PR reviewer should be able to hold the whole diff in their head.

## Architecture principles

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) §2 for the non-negotiables and the reasoning behind them.

## Code of conduct

This project serves people in vulnerable situations — domestic violence survivors, journalists under surveillance, activists at risk. All contributions must prioritize user safety and privacy. Contributions that add tracking, analytics, remote telemetry, or other mechanisms that could compromise user privacy will not be accepted regardless of technical merit.
```

- [ ] **Step 3: Commit**

```bash
git add CONTRIBUTING.md
git commit -m "docs(contributing): rewrite with manual + AI-assisted rule paths, PR workflow, dev setup"
```

---

## Task 8: Trim `CLAUDE.md`

**Repo:** `yasirhamza/AndroDR`
**Files:**
- Modify: `CLAUDE.md`

- [ ] **Step 1: Replace the "Project layout" and "Key architectural decisions" sections with a pointer**

Use Edit to remove the current "## Project layout" section (the stale tree) and the "## Key architectural decisions" section. Replace both with a single block:

```markdown
## Architecture reference

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the architecture, module map, and design principles. Keep that document as the single source of truth — do not duplicate its content here.
```

Everything else in `CLAUDE.md` (build requirements, common commands, development workflow, lint / style, running on physical device, local development, smoke test, submodule guide) stays as-is.

- [ ] **Step 2: Verify no stale tree remains**

Run: `grep -n 'vpn/' CLAUDE.md`
Expected: zero matches (the old tree referenced `vpn/` which has since been renamed `network/`).

Run: `grep -c '^## ' CLAUDE.md`
Expected: the total number of sections decreased by 1 from before (two sections merged into one pointer).

- [ ] **Step 3: Commit**

```bash
git add CLAUDE.md
git commit -m "docs(claude): trim architecture content to pointer at ARCHITECTURE.md"
```

---

## Task 9: Delete `docs/ROADMAP.md`

**Repo:** `yasirhamza/AndroDR`
**Files:**
- Delete: `docs/ROADMAP.md`

- [ ] **Step 1: Confirm ROADMAP "Architecture Notes" content is already in `ARCHITECTURE.md`**

Run:
```bash
grep -c 'rule engine supports' docs/ARCHITECTURE.md
```
Expected: ≥1 match — the "The rule engine supports ..." paragraph should be folded into §11 D7 per Task 5. If zero, stop and fix Task 5 before deleting.

- [ ] **Step 2: Find inbound links to ROADMAP**

Run:
```bash
grep -rn 'docs/ROADMAP\|ROADMAP\.md\b' --include='*.md' --include='*.kt' --include='*.xml' --include='*.yml' --exclude-dir=.git --exclude-dir=.claude .
```

Expected matches (known, harmless):
- `docs/detection-rules-catalog.md` — `[ROADMAP #N]` text markers (these are labels, not file links; leave alone per spec §6.5)
- `notes/apprehend-rename-plan.md` — ignore (user notes, uncommitted)
- `docs/superpowers/specs/2026-04-24-docs-refresh-design.md` and this plan file — meta-references, leave alone

If there are inbound **link** references (like `[Roadmap](docs/ROADMAP.md)`), fix them to point at the Issues page before deleting.

- [ ] **Step 3: Delete the file**

```bash
git rm docs/ROADMAP.md
git commit -m "docs: remove stale ROADMAP.md (GitHub Issues is canonical)"
```

---

## Task 10: Deduplicate `docs/play-store/`

**Repo:** `yasirhamza/AndroDR`

- [ ] **Step 1: Pairwise compare each numbered vs unnumbered file**

Run each of the following and capture the output:

```bash
diff -u docs/play-store/query-all-packages-declaration.md  docs/play-store/16-query-all-packages-declaration.md
diff -u docs/play-store/vpn-service-declaration.md         docs/play-store/17-vpn-permission-declaration.md
diff -u docs/play-store/data-safety-form.md                docs/play-store/18-data-safety-form.md
diff -u docs/play-store/content-rating-iarc.md             docs/play-store/19-content-rating-iarc.md
diff -u docs/play-store/store-listing.md                   docs/play-store/20-store-listing.md
```

For each pair:
- If the numbered version is a superset or strictly newer: delete the unnumbered version.
- If the unnumbered version has unique content: **merge forward** into the numbered version first, then delete the unnumbered one.

- [ ] **Step 2: Perform deletions (only after Step 1 confirms no content loss)**

```bash
git rm docs/play-store/query-all-packages-declaration.md
git rm docs/play-store/vpn-service-declaration.md
git rm docs/play-store/data-safety-form.md
git rm docs/play-store/content-rating-iarc.md
git rm docs/play-store/store-listing.md
```

- [ ] **Step 3: Verify no inbound links to deleted files**

Run:
```bash
for f in query-all-packages-declaration vpn-service-declaration data-safety-form content-rating-iarc store-listing; do
  echo "=== $f ==="
  grep -rn "play-store/$f" --include='*.md' --exclude-dir=.git . || true
done
```
Expected: zero matches across all five. If any inbound link still points at a deleted file, update it to point at the numbered version.

- [ ] **Step 4: Commit**

```bash
git commit -m "docs(play-store): remove duplicate unnumbered versions (superseded by 16–20)"
```

---

## Task 11: File follow-up issue for `detection-rules-catalog.md`

- [ ] **Step 1: Open the issue**

Run:
```bash
gh issue create \
  --title "docs: audit detection-rules-catalog.md against current rule catalog" \
  --label "documentation,tech-debt" \
  --body "The file \`docs/detection-rules-catalog.md\` predates the AI rule-authoring pipeline and the post-March 2026 bundled rule additions. It likely describes rules that have since been renamed, split, or superseded.

Scope of this follow-up:
- Walk \`app/src/main/res/raw/*.yml\` and cross-reference against every section in \`docs/detection-rules-catalog.md\`.
- For each entry in the catalog: confirm the rule id still exists; confirm description still matches; flag stale entries.
- Either (a) update the catalog to reflect current rules, or (b) replace it with a generator that builds the catalog from the bundled rule files so drift cannot happen again.

Out of scope for the 2026-04-24 docs refresh (see spec §3 non-goals)."
```

Expected: output includes the new issue URL; paste it into the PR B description when opening the PR.

---

## Task 12: End-to-end verification before opening PR

- [ ] **Step 1: Link check — no broken internal links**

Run:
```bash
python3 - <<'PY'
import pathlib, re
root = pathlib.Path('.')
bad = []
for md in root.rglob('*.md'):
    if any(part in md.parts for part in ('.git', '.claude', 'third-party', 'node_modules')):
        continue
    text = md.read_text(encoding='utf-8', errors='ignore')
    for m in re.finditer(r'\]\(([^)]+)\)', text):
        tgt = m.group(1).split('#', 1)[0]
        if not tgt or tgt.startswith(('http://', 'https://', 'mailto:')):
            continue
        resolved = (md.parent / tgt).resolve()
        if not resolved.exists():
            bad.append((str(md), tgt))
for path, tgt in bad:
    print(f"BROKEN {path} -> {tgt}")
print(f"total broken: {len(bad)}")
PY
```
Expected: `total broken: 0`. If any appear, fix them before opening the PR.

- [ ] **Step 2: Grep for stale references**

```bash
grep -rn 'vpn/' README.md CONTRIBUTING.md CLAUDE.md docs/ARCHITECTURE.md 2>/dev/null || echo "clean"
grep -rn 'privacy@androdr\.dev' . --exclude-dir=.git --exclude-dir=.claude 2>/dev/null || echo "clean"
grep -rn 'docs/ROADMAP' --include='*.md' . 2>/dev/null | grep -v 'docs/superpowers/' | grep -v '^Binary' || echo "clean"
```
Expected: all three print `clean` (or only meta-references inside `docs/superpowers/specs/`/`plans/`, which are allowed).

- [ ] **Step 3: Local build still passes**

```bash
./gradlew lintDebug --no-daemon
```
Expected: BUILD SUCCESSFUL. Docs changes should not affect lint, but this is the release-gate check so run it.

- [ ] **Step 4: CLAUDE.md is still parseable**

Open a new `claude` session quickly (or `cat CLAUDE.md | head -40`) to make sure the edit didn't leave a broken markdown structure.

Run: `python3 -c "import re, pathlib; t=pathlib.Path('CLAUDE.md').read_text(); hs=re.findall(r'^(#+)\s+', t, flags=re.MULTILINE); print('headings:', len(hs))"`
Expected: nonzero heading count and no syntax error.

---

## Task 13: Open PR B

- [ ] **Step 1: Push branch**

```bash
git push -u origin docs/sweep
```

- [ ] **Step 2: Open PR**

```bash
gh pr create \
  --title "docs: documentation sweep (ARCHITECTURE + README + CONTRIBUTING + CLAUDE + cleanups)" \
  --body "$(cat <<'EOF'
## Summary
- Adds canonical \`docs/ARCHITECTURE.md\` (~600 lines, 11 chapters): overview, design principles, accurate module map, detection pipeline, data layer, reporting, DNS monitor, bugreport analysis, AI rule-authoring pipeline, test strategy, decisions.
- Rewrites \`README.md\` — fresh module tree, new capabilities (bugreport analysis, forensic timeline), short architecture sketch with pointer to ARCHITECTURE.md, Cloudflare mirror note.
- Rewrites \`CONTRIBUTING.md\` — full dev setup, manual and AI-assisted rule-authoring paths, PR workflow, submodule handling.
- Trims \`CLAUDE.md\` — removes duplicated architecture content; single pointer to ARCHITECTURE.md.
- Deletes \`docs/ROADMAP.md\` — GitHub Issues is canonical; useful "Architecture Notes" paragraph folded into ARCHITECTURE.md §11.
- Deduplicates \`docs/play-store/\` — removes unnumbered duplicates superseded by 16–20 numbered versions.

## Why
Three drivers: Play Store prep, external audience refresh, internal drift cleanup. Code had moved ahead of docs since March (SIGMA engine, IOC pipeline, bugreport analysis, forensic timeline, AI pipeline).

Spec: \`docs/superpowers/specs/2026-04-24-docs-refresh-design.md\` §6.
Depends on PR A (privacy pipeline): must merge after PR A is verified end-to-end.

Follow-up issue: <paste URL from Task 11>

## Test plan
- [ ] CI \`build\` check passes
- [ ] \`./gradlew lintDebug\` passes locally
- [ ] No broken internal Markdown links (verified by link-check script)
- [ ] No stale \`privacy@androdr.dev\`, \`vpn/\` (as package path), or file-link \`docs/ROADMAP.md\` references remain
- [ ] Fresh Claude Code session loads trimmed CLAUDE.md without parse issues
- [ ] New \`docs/ARCHITECTURE.md\` module tree matches the actual \`app/src/main/java/com/androdr/\` layout

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
)"
```

- [ ] **Step 3: Report PR URL to user**

Print the PR URL so the user can review.

---

## Post-merge

After PR B merges:

- [ ] Verify the rendered README on https://github.com/yasirhamza/AndroDR looks right.
- [ ] Verify the rendered CONTRIBUTING on https://github.com/yasirhamza/AndroDR/blob/main/CONTRIBUTING.md looks right.
- [ ] Verify `docs/ARCHITECTURE.md` is discoverable via the repo's file tree.
- [ ] Close any GitHub issues superseded by the new docs (none expected — this was all drift, not feature work).
