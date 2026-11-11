# Privacy Scan in the Timeline (Part B) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A completed privacy scan appears in the Timeline as its own kind of scan: one scan entry and one entry per user-installed app with trackers found in code. These entries never count as findings, never leave the device, and live exactly as long as the privacy results.

**Architecture:** The entries are ordinary `forensic_timeline` rows marked with a new `TelemetrySource.PRIVACY_SCAN`, scan reference `-1`, no level and no rule. They are written by `PrivacyScanRunner` in the same Room transaction that completes the scan and removes the previous results, and removed through `TimelineRowDeleter`. Every Timeline reader that must not see them (exports, STIX, Clear all, linked evidence) excludes them by source, at the query or in the view model, so reporting code never learns about the privacy scan. No schema change (`telemetrySource` is TEXT).

**Tech Stack:** Kotlin, Room (`withTransaction`), Compose + Navigation, Paging 3, Robolectric, MockK, pytest (policy check).

**Spec:** `docs/superpowers/specs/2026-11-10-privacy-details-timeline-pipeline-design.md` sections 5, 7, 8, 9, 11, 12.

## Global Constraints

- Privacy entries: `telemetrySource = PRIVACY_SCAN`, `scanResultId = -1`, `level = null`, `ruleId = ""`, `kind = "event"`, `persistent = false`, `recordId = null`, categories `privacy_scan` (scan entry) and `privacy_app` (app entry) used by nothing else.
- `PRIVACY_SCAN` is never stored on a `ScanResult`, `ScanFinding`, `ScanObservation` or `TelemetryFact` (spec 5.5); the five exhaustive `when`s over the source get explicit branches, and in reporting, History and the deletion audit that branch fails loudly (`error(...)`) because it cannot be reached.
- Lifetime (5.4): replaced atomically by the next completed scan; removed by "Delete privacy results"; never by the 30-day prune, History's "Clear all" (including the start-up resume of a pending Clear all) or deleting a security scan.
- Never (5.3): in "Findings only" or the severity filters, in the CSV, plain-text or STIX exports, in SIGMA/correlation inputs, in alerts, the verdict or finding counts. Found by search (app name, package, text) and by the package filter.
- Entries state facts that stay true: no threshold, no network-only apps, no system apps; text sanitised as on the privacy screen.
- No security lock: the privacy scan still never takes `ScanLock`.
- `PrivacyBoundaryTest` unchanged and green; `reporting`, `sigma`, `ui/history`, `ScanWriteRepository`, `data/store` never mention `privacy_` or `com.androdr.privacy` (exclusions use `TelemetrySource.PRIVACY_SCAN` / the SQL literal `'PRIVACY_SCAN'`).
- Every Timeline delete goes through `TimelineRowDeleter`; every new `forensic_timeline` read passes `CompleteVisibilityGateTest`.
- Policy extended (spec 8): the privacy scan's Timeline entries are kept like the results and are never in a Timeline export; the `"| Forensic timeline events"` exemption in `scripts/test_privacy_policy_text.py` is removed so that row falls under the rule.
- Commands and commit attribution as in the Part A plan.

## Review Focus

1. History "Clear all" (and its start-up resume) must leave privacy entries: today `DELETE_SCAN_LESS_THROUGH` deletes them (Task 2, `Clear all leaves privacy entries` + `a pending Clear all resumed at start-up leaves privacy entries`).
2. An unfiltered Timeline that holds only privacy entries: export says there is nothing to export instead of writing an empty file (Task 5, `export with only privacy entries says there is nothing to export`).
3. The completion transaction failing half-way: the previous scan's results and entries stay, the new scan is not completed (Task 4, `a failure while writing entries leaves the previous scan and its entries`).
4. Opening "Open in privacy results" for an app before the privacy screen has loaded: the sheet must open once loaded, not close itself (Task 6, `the app sheet opens once the results load`).
5. An app's privacy entry and a finding for the same app: neither lists the other as linked evidence (Task 5, `privacy entries are never linked evidence`).

---

### Task 1: The `PRIVACY_SCAN` source

**Files:** `data/model/TelemetrySource.kt`; the five exhaustive `when`s (`ui/timeline/TimelineFilterSheet.kt` `telemetrySourceLabel`, `data/repo/DeletionAudit.kt`, `reporting/AlertReportSource.kt`, `reporting/ReportSummary.kt`, `ui/history/HistoryScreen.kt` `importSourceLabel`); `res/values/strings.xml`; test `app/src/test/java/com/androdr/data/model/PrivacyScanSourceTest.kt` (create).

**Interfaces:** Produces `TelemetrySource.PRIVACY_SCAN`; string `timeline_source_privacy_scan` = "Privacy scan".

- [ ] Step 1 (failing tests): `PrivacyScanSourceTest`
  - `the Source filter labels the privacy scan` — `telemetrySourceLabel(PRIVACY_SCAN)` resolves to "Privacy scan" (Robolectric resources).
  - `PRIVACY_SCAN appears only where privacy Timeline entries are written, filtered or labelled` — source scan of `app/src/main/java`: files mentioning `PRIVACY_SCAN` ⊆ a pinned allow-list (the enum, the five branches, the privacy Timeline writer, the row deleter, the Timeline DAO/queries exclusions, the Timeline UI, STIX export); any other file fails.
  - `reporting, History and the deletion audit refuse a privacy-scan source` — each of their branches throws for `PRIVACY_SCAN` (call the functions, `assertThrows`).
- [ ] Step 2: run; Expected: compile failure (`PRIVACY_SCAN` unresolved).
- [ ] Step 3: add the value and the branches.
- [ ] Step 4: run the class plus `TimelineViewModelTest`, `HistoryViewModelTest`-family tests touching labels, `PrivacyBoundaryTest`; Expected: pass.
- [ ] Step 5: commit `feat(timeline): a privacy-scan source`.

### Task 2: Removal paths and readers that must skip privacy entries

**Files:** `data/repo/TimelineRowDeleter.kt` (`privacyRows()`), `data/db/ForensicTimelineEventDao.kt` (Clear-all trio gains `AND telemetrySource != 'PRIVACY_SCAN'`; `visibleAfter` / STIX read excludes it; new `deletePrivacyRows()`), `ui/settings/SettingsViewModel.kt` if STIX reads elsewhere; tests in `data/repo/TimelineRowDeleterTest.kt`, `data/db/PruneExemptionsTest.kt`, `ui/settings/StixExportMappingTest.kt`, `data/db/CompleteVisibilityGateTest.kt` (allow-list if needed).

**Interfaces:** Produces `suspend fun TimelineRowDeleter.privacyRows()` (must run inside the caller's transaction, like its siblings).

- [ ] Step 1 (failing tests), each seeding a privacy row (`telemetrySource = PRIVACY_SCAN`, `scanResultId = -1`, `packageName` set) beside ordinary rows:
  - `the 30-day prune leaves privacy entries`
  - `deleting a security scan leaves privacy entries`
  - `Clear all leaves privacy entries`
  - `a pending Clear all resumed at start-up leaves privacy entries`
  - `privacyRows deletes privacy entries and nothing else`
  - `STIX export never includes a privacy entry`
  - `a privacy entry is never a correlation input` (a privacy row whose category equals an atom category; `AtomDao.rowsForScan`/`liveRowsBetween` do not return it)
  - The deleter gate regex learns `deletePrivacyRows`.
- [ ] Step 2: run; Expected: Clear-all, privacyRows and STIX tests fail; prune/scan-delete/correlation pass (pinning existing behaviour).
- [ ] Step 3: implement.
- [ ] Step 4: run the touched classes; Expected: pass.
- [ ] Step 5: commit `fix(timeline): privacy entries survive Clear all and stay out of STIX`.

### Task 3: The entries a privacy scan writes

**Files:** `privacy/PrivacyTimelineRows.kt` (create, pure), test `privacy/PrivacyTimelineRowsTest.kt`.

**Interfaces:** `internal object PrivacyTimelineRows { const val CATEGORY_SCAN = "privacy_scan"; const val CATEGORY_APP = "privacy_app"; const val MODULE = "privacy_scan"; const val MAX_NAMED_TRACKERS = 10; fun build(at: Long, scan: ScanCounts, results: List<PrivacyAppResult>, evidence: List<PrivacyTrackerEvidence>, networkStatus: NetworkStatus): List<ForensicTimelineEvent> }` with `data class ScanCounts(inspected, partial, failed)`.

Text (English, like other Timeline rows):
- Scan entry description: `Privacy scan: N apps inspected · trackers found in the code of M` + ` · K could not be inspected` + ` · P partly inspected` (when > 0); details: the network sentence ("Network evidence complete." / "…was incomplete." / "…could not be read." / "No network monitor data.").
- App entry description: `<label>: N tracker(s) found in code`; details: tracker names (first ten, then `and N more`), `M new since the previous privacy scan` when M > 0, `Partly inspected.` when PARTIAL.
- Labels through `displaySafe` (fallback `reportSafe(packageName)`), tracker names through `PrivacyEvidenceText`-equivalent sanitising (`displaySafe`).

- [ ] Step 1 (failing tests): one scan entry plus one per user app with ≥1 in-code tracker; `no entry for a system app`; `no entry for an app with only network evidence`; `the first ten trackers are named, then and N more`; `new since the previous scan is counted`; `partly inspected is said`; `a hostile label is sanitised and still found by its name` (description contains the cleaned label); `every entry is marked as a privacy entry and tied to no security scan` (source, `scanResultId == -1`, `level == null`, `ruleId == ""`, `persistent == false`, timestamp = `at`).
- [ ] Step 2: run; Expected: compile failure. Step 3: implement. Step 4: run; Expected: pass.
- [ ] Step 5: commit `feat(privacy): the Timeline entries of a privacy scan`.

### Task 4: Written and replaced in one transaction

**Files:** `privacy/PrivacyScanRunner.kt` (inject `AppDatabase`, `ForensicTimelineEventDao`, `TimelineRowDeleter`; completion and `deleteAll` in `db.withTransaction`), both runner test fixtures, test `privacy/PrivacyScanTimelineTest.kt` (create).

- [ ] Step 1 (failing tests, real in-memory Room):
  - `a completed scan writes its Timeline entries`
  - `a newer scan replaces the previous scan's entries`
  - `Delete privacy results removes the entries`
  - `a failure while writing entries leaves the previous scan and its entries` (Timeline DAO wrapper whose `insertAll` throws: the new scan has no `finishedAt`, the previous scan stays latest, its entries remain)
  - `entries never carry a security scan id`
  - `a privacy scan changes no alert, finding count or verdict` (`FindingsRepository.currentOnce()` equal before/after)
  - existing `the scan never touches ScanLock` stays green.
- [ ] Step 2: run; Expected: compile failure on the new constructor. Step 3: implement. Step 4: run both runner classes + new class; Expected: pass.
- [ ] Step 5: commit `feat(privacy): the scan writes its Timeline entries atomically`.

### Task 5: The Timeline screen

**Files:** `ui/timeline/TimelineViewModel.kt` (privacy header merged into By-scan by time; exports skip privacy rows; nothing-to-export when none left; linked evidence skips privacy rows), `TimelineScreen.kt`, `TimelineEventCard.kt` (privacy header variant, no severity chip or telemetry link; sheet action `Open in privacy results`), `data/db/TimelineQueries.kt` (skip the facts half for a privacy-only source filter; export exclusion flag), strings; tests in `ui/timeline/TimelineExportStreamTest.kt` (count rule becomes "count minus privacy entries"), `TimelineSearchTest.kt`, `TimelineViewModelTest.kt`, new `ui/timeline/TimelinePrivacyTest.kt`.

**Interfaces:** `TimelineScreen` gains `onOpenPrivacy: (packageName: String?) -> Unit`.

- [ ] Step 1 (failing tests): `the Source filter shows only privacy entries`; `Findings only and severity filters never show a privacy entry`; `search finds a privacy entry by app name and by package`; `one app's timeline shows its privacy entry`; `By scan lists the privacy scan by its date with its entry count`; `tapping the privacy header narrows to the privacy scan`; `CSV and plain-text exports leave privacy entries out`; `export with only privacy entries says there is nothing to export`; `privacy entries are never linked evidence`; `the details sheet offers Open in privacy results for a privacy entry only` (Compose).
- [ ] Step 2: run; Expected: failures/compile errors. Step 3: implement. Step 4: run the timeline test classes; Expected: pass.
- [ ] Step 5: commit `feat(timeline): the privacy scan as a scan of its own`.

### Task 6: Open in privacy results

**Files:** `MainActivity.kt` (`privacy?pkg={pkg}` route, Timeline callback), `ui/privacy/PrivacyScreen.kt` / `PrivacyViewModel.kt` (initial package opens its sheet once results have loaded; a missing app no longer dismisses while loading), tests `ui/privacy/PrivacyViewModelTest.kt`, `PrivacyCopyTest.kt`.

- [ ] Step 1 (failing tests): `the app sheet opens once the results load`; `an app no longer in the results opens no sheet`; route test in `PrivacyCopyTest` (`privacy?pkg=`).
- [ ] Step 2–4: run red, implement, run green.
- [ ] Step 5: commit `feat(privacy): open an app's privacy results from the Timeline`.

### Task 7: Policy, render, architecture

**Files:** `docs/PRIVACY_POLICY.md` (Forensic timeline row and the Privacy Scan section name the Timeline entries; never in a Timeline export), `scripts/test_privacy_policy_text.py` (drop the timeline exemption; require "Timeline" in the Privacy Scan section), `cloudflare-worker.js` (render), `docs/ARCHITECTURE.md` (what the Timeline table holds; 12.3 separation reworded; 12.9 Timeline entries); androdr-site PR #3 re-rendered.

- [ ] Step 1: tighten the policy test; run; Expected: fail. Step 2: edit policy, render, run; Expected: pass. Step 3: commit `docs(privacy): the policy covers the privacy scan's Timeline entries`.

### Task 8: Gates and device check

- [ ] Full `testDebugUnitTest`, `detekt`, `lintDebug`, `pytest scripts/ test-adversary/`; emulator: run a privacy scan, see the header and entries in the Timeline, filter by Privacy scan, open an entry, Open in privacy results, Clear all in History leaves the entries, Delete privacy results removes them.
