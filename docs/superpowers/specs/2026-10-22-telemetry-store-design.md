# Telemetry Store, Uncapped Timeline, Finding Lifecycle, and the Telemetry Vocabulary — Design

**Date:** 2026-10-22
**Status:** Design approved in-session (all decisions closed 2026-10-22);
revised after plan-gate rounds 1–2 (2026-10-22). Plan gate and implementation are coordinated by a
separate session (Opus), not the session that wrote this document.
**Depends on:** `docs/superpowers/specs/2026-04-09-unified-telemetry-findings-refactor-design.md`
(§4 facts-first naming, provenance as a field); the rule-repo
`validation/logsource-taxonomy.yml` (field-map shape, `raw_fact`/`judgment` grading).
**Related:** #353 (export window vs. persisted-row budget), #137 (machine-readable
telemetry schema), #342 (intrusion-log import; introduced the persistence caps).

## 1. Background and motivation

AndroDR collects a great deal and keeps very little. On the maintainer's test
device (SM-F916B, 438 packages, 11 user apps, no SIM) the on-device database
is 86 MB; 81 MB of that is the IOC indicator table (697,313 rows). The entire
forensic timeline is 92 KB — 466 rows across four scans, 414 of which are the
one-time `package_install` backfill from the first scan. The three later scans
contributed 6, 6 and 31 rows.

Tracing every writer and reader (session of 2026-10-22) found the reasons:

1. **Only a thin slice of a scan is ever persisted.** `ScanOrchestrator.runFullScan`
   writes triggered findings, once-ever install and device-admin rows, 24 h of
   usage transitions (user apps only, *replaced* on every scan), and DNS IOC
   hits. The complete record sets the scanners produce — app inventory, app-ops,
   receivers, processes, accessibility services, file-artifact checks, device
   posture — go to the rule engine and are then discarded, except for a
   process-lifetime cache (`ScanOrchestrator.last*Telemetry`).
2. **The report reads that cache.** `ReportExporter` fills the TELEMETRY
   sections from `last*Telemetry`. A report for any scan but the most recent,
   or after the process restarted, has silently empty telemetry sections. A
   report for a bug-report or intrusion-log import shows the *live device's*
   cached telemetry under the import's heading — wrong provenance. There is a
   **second report path**: `HistoryViewModel` (line ~90) calls
   `ReportFormatter.formatScanReport` directly with `lastAppTelemetry`,
   `dnsEventDao.getRecentSnapshot()` and its own `INTRUSION_ROW_LIMIT = 500`.
   `BugReportViewModel` (line ~167) and `ScanOrchestrator.analyzeBugReport`
   (lines ~544–575) also read `lastAppTelemetry`, for APK-hash and
   display-name enrichment of import rows.
3. **Bug-report imports throw away ten modules' telemetry.** Only four of
   fourteen modules emit timeline rows; the typed records of the other ten
   (tombstones, wakelocks, platform-compat, db-info, accessibility, activity,
   receivers, …) exist only as `List<Map<String, Any?>>` on the way into the
   rule engine (`BugreportModule.kt:16`).
4. **Persistence caps bound what an import keeps**: 1,000 findings, 10,000 DNS,
   5,000 connect, 5,000 security rows (`ScanOrchestrator.kt:1024–1048`). They
   were added in #342 because `ScanResult.findings` is one JSON TEXT column
   read in full for every history row, and Room's `CursorWindow` fails on a
   row over ~2 MB. The maintainer did not intend any cap: *"That seriously
   reduces the fidelity of a scanning and telemetry tool."*
5. **The readers cap again.** The Timeline tab reads `getRecentEvents(limit = 500)`
   over the whole table with no "showing N of M" indicator; the report embeds
   ≤ 500 intrusion-log rows; the timeline export is `LIMIT 10000` oldest-first
   while one import may legitimately write 21,000 rows (#353). The History
   list is `LIMIT 50`. A live scan evaluates DNS against
   `DnsEventDao.getRecentSnapshot()` = the newest 500 DNS events with no scan
   boundary — a cap on what the rules *see*, not only on what is kept.
6. **Events are re-collected and re-stored.** Nothing remembers where the
   previous scan stopped: usage stats re-pull 24 h every scan (and the save
   deletes the previous window), DNS re-evaluates the same newest 500. A
   finding on a DNS event therefore re-fires on every scan while the event
   stays in the window, and never fires if the event has already scrolled out.
7. **"Telemetry" means three things.** In the scanner layer it is a typed
   record; `TelemetrySource` is actually provenance; in the Timeline UI the
   "Hide informational telemetry" switch governs *timeline rows not derived
   from a finding* — which, given (1), is almost nothing.

### 1.1 What keeping everything costs — on a real phone

The test device understates volume badly (no SIM, 11 user apps, zero usage
events in 24 h). The estimate below is for a heavy daily-use phone: ~650
packages (200+ user apps), 2–4k foreground/background transitions a day,
5–20k DNS resolutions a day, Android 16 intrusion logging switched on.
Compression ratio anchor: `dumpsys package` from the test device (6.6 MB)
gzips 7.2×; permission-string-heavy JSON does the same or better.

| Unit | Records | Raw |
|---|---|---|
| Daily live scan — snapshots (apps 650 × ~3.5 KB, app-ops ~1.5k, receivers ~1k, rest) | ~3k | ~2.7 MB |
| Daily live scan — usage events, 24 h | 2–4k | 0.4–0.8 MB |
| Daily live scan — DNS events since previous scan | 5–20k | 0.75–3 MB |
| Weekly intrusion-log import (DNS 50–150k, connect 100–300k, security few k) | 200–450k | 50–110 MB |

Twenty daily scans plus four weekly imports, by storage layout:

| Layout | Snapshots | Live events | Imports | Total |
|---|---|---|---|---|
| SQLite rows, plain JSON | 54 MB | 25–75 MB | 200–440 MB | 280–570 MB |
| + content-hash dedup of snapshot bodies (daily churn ≈ 10 %) | ~8 MB | 25–75 MB | 200–440 MB | 230–520 MB |
| + Deflate-with-dictionary on event bodies (~5×) | ~8 MB | 5–15 MB | 40–90 MB | **55–115 MB** |
| (reference) gzip JSONL files, ~7× | — | — | — | ~45–90 MB |

These figures are bodies only. Per-event row and index overhead (fact row,
observation row, three indexed 16-byte keys) adds roughly 120–150 B per
event — about 30–65 MB per weekly import at the volumes above — so the
realistic total for the compressed layout is **~150–380 MB**, still bounded
by the user's retention and import choices and shown in Settings. The
release battery measures the real factor (§5.2).

Two conclusions drove the design: **event volume, not snapshot volume,
dominates on a real phone**, and the parser's 200,000-records-per-type bound
is one week of a real intrusion log, not a theoretical ceiling. Serialize +
compress of a few MB on a phone is well under a second; disk at the chosen
layout is comparable to the IOC table the app already carries. The
constraints are the 2 MB cursor row limit, the 500-row reads, duplicate
storage of events, and the vocabulary.

## 2. Goals, non-goals, anti-goals

**Goals**

- G1. Every telemetry record a scan or import produces is persisted, complete
  and unmodified, and can be read back for that scan — by the report, by the
  UI, by export, and by queries across scans.
- G2. No persistence cap anywhere in the scan → store → timeline path. Bounds
  are retention policies the user can see, never silent truncation.
- G3. The report for scan *X* describes scan *X* and nothing else.
- G4. The Timeline shows every timeline event, paged; it never hides rows
  without saying so.
- G5. One precise vocabulary — *telemetry record* (snapshot or event),
  *timeline event*, *finding* — used identically in code, UI text, docs, and
  the rule taxonomy; enforced by a gate.
- G6. A finding can be walked back to the exact record it matched.
- G7. **A fact is stored once.** A live event is collected by exactly one
  scan; an unchanged snapshot is one fact however many scans observe it; an
  imported event two exports both contain is one fact, observed by both.
- G8. Findings follow an alert lifecycle: a finding on state clears when the
  state clears; a finding on an event stays open until a person closes it.

**Non-goals**

- No new live emitters; no new *detection*. (The taxonomy does gain entries
  for emitters that already exist, §4.2.)
- No differential rules (snapshot-vs-snapshot detection) in this design; the
  store makes them a pure query later.
- No cloud or off-device storage; no change to the 12 h IOC/rule fetch.
- No new native library, no new SQLite build. Compression and dedup use what
  the platform ships (`java.util.zip`, SQLite JSON1).
- IP filtering remains parked (ARCHITECTURE §11 D3).

**Anti-goals** (would make this a failure even if it technically works)

- Reintroducing a cap "for safety" anywhere in the path.
- Putting large blobs back into `ScanResult` or any row a list query reads.
- A stored record that differs from what the rule engine evaluated.
- Storing the same event twice (once as a record, once as a timeline row).
- A bound that silently drops evidence; storage protection refuses visibly
  instead (§5.2).
- Source-named types or fields (`BugReportX`, `ImportedY`) — spec 2026-04-09 §4.

## 3. Vocabulary (normative)

These definitions are the contract. ARCHITECTURE.md gains a glossary section
containing them verbatim; a build gate (§9, V1) enforces the retired phrases.

| Term | Definition |
|---|---|
| **Telemetry record** | A typed fact an emitter produced, exactly as produced, before any rule saw it. Source-agnostic; provenance belongs to the observation. Every record is one of two time-shapes, decided per record (§4.3). |
| **Snapshot record** | State observed *at scan time*: app inventory, live app-ops grants, receivers, processes, accessibility services, file-artifact checks, device posture, system properties, database-path observations, platform-compat changes, ADB trusted keys, and any record whose service declares no event-time field or whose value for it is absent. |
| **Event record** | Something that happened at a time *T* the record carries: usage transitions, DNS queries, connections, security-log events, tombstones, wakelock acquisitions, package install history, bug-report app-ops accesses, battery-daily package events. An event's time has a precision (`exact` or `day`). |
| **Fact** | One distinct telemetry record, stored once however many scans or imports observed it (§5.1). |
| **Observation** | One scan's or import's sighting of a fact, at a position in that scan's emitted list. Provenance and capture time belong to the observation. |
| **Timeline event** | A timestamped row on the forensic timeline. Comes from (a) every event fact, read in place — never copied; (b) every triggered finding; (c) correlation signals; (d) detected changes (first-seen install, first-seen device-admin grant, live DNS IOC match, alert closure). **Snapshot records never become timeline events.** |
| **Finding** | Rule output in one scan (`Finding`), referencing the observation it matched. A finding on a snapshot record is a **state finding**; a finding on an event record, or a correlation finding, belongs to an **alert**. |
| **Alert** | The lasting record of an incident: opened by the first finding with its identity, kept across scans, closed only by a person (§5.4). |
| **Provenance** | Where an observation came from: `TelemetrySource` (`LIVE_SCAN`, `BUGREPORT_IMPORT`, `INTRUSION_LOG_IMPORT`). It is not a kind of telemetry. |
| **Watermark** | Per live event service, the position up to which live events have been collected. The next scan collects from it. |

**Retired phrases.** "Raw telemetry" — every telemetry record is raw by
definition; the `raw_fact`/`judgment` grading lives at the field level in the
taxonomy. "Informational telemetry" — the UI switch meant "timeline events not
referenced by a finding" and will say so. The bug-report `TimelineEvent`
class — a source-shaped, untyped row — is retired (§5.3).

Field-level naming keeps the taxonomy's `snake_case`.

## 4. Architecture

```
emitter ─▶ ServiceRecords (field maps, built once, one-shot Sequence)
              │  per 5,000-record chunk, one transaction each:
              ├─▶ store: record_body ◀ telemetry_record (fact) ◀ scan_record (observation)
              ├─▶ SigmaRuleEngine.evaluateRecords(chunk)  (same maps, same ordinals)
              └─▶ scan_finding rows ──▶ alert (one per alertKey, outlives scans)
final transaction: correlation over atom-bound categories → signals → scan row COMPLETE → watermarks

Timeline = keyset-paged UNION(event facts, forensic_timeline rows)
Report (streamed) · Telemetry browser · JSONL export · cross-scan history / diff
```

Persistence surfaces:

- **`record_body`, `telemetry_record`, `scan_record`** (new; schema 19): content,
  facts, observations. §5.1.
- **`event_watermark`** (new; schema 19). §5.2.
- **`scan_finding`, `alert`, `alert_member`** (new; schema 20): findings per
  scan, alerts across scans. §5.4.
- **`forensic_timeline`** (changed): only finding rows, correlation signals and
  detected changes; gains `recordId`, `sourceEventKey` (schema 19, indexed with
  `scanResultId`) and `level` (schema 20).
- **`ScanResult`** (changed): gains `state` (`IN_PROGRESS` | `COMPLETE`) and
  `telemetryState` (`NONE` | `STORED` | `PARTIAL_RETENTION` | `FAILED`) in
  schema 19; loses `findings` in schema 20.

### 4.1 One list, evaluated and stored

Each emitter's output is projected to field maps **once**, as
`ServiceRecords(service, source, capturedAt, records: Sequence<StoreRecord>)`
— a one-shot sequence (`constrainOnce()`), consumed exactly once by the
chunked writer (§5.2). Within each chunk the same maps are persisted and
then evaluated (`SigmaRuleEngine.evaluateRecords(service, chunk,
firstOrdinal)`; the typed `evaluate*` methods delegate to it and are kept for
live callers). A finding carries the ordinal of its record in the emitted
list; engine-side pre-filters (today: `file_scanner` skips inaccessible
paths) keep the original index. Stored equals evaluated by construction. A
gate requires every writer to evaluate through `evaluateRecords` on the
batch it persists.

Records are stored as their `toFieldMap()` projection, the map in taxonomy
`snake_case` that `SigmaRuleEvaluator` evaluates.

**Field-map completeness.** A field map carries every fact its data class
holds. Two gaps are closed as positive-only fields:
`FileArtifactTelemetry.accessible` → `accessible`;
`ImportedDnsEvent.resolvedIps` → `dns_monitor.resolved_ips`. A gate compares
each telemetry class's constructor properties with its field-map keys
(commented allow-list for intentional omissions).

**Envelope keys.** `source` and `captured_at` are observation properties
when — and only when — the map's value equals the observation's
(`source == TelemetrySource.name`, `captured_at == capturedAt`). Such keys
are removed before hashing, the observation records which it removed
(`strippedKeys` bitmask), and decode restores exactly those. Keys holding
content (eight bug-report modules emit `"source" to "bugreport_import"` or
`"adb_trusted_key"`; rules 071–076 match on it) are left in the body. The
decoded map equals the evaluated map, keys included.

Services covered: every emitter output — each typed `evaluate*`, the generic
bug-report path, `usage_stats`, `system_property`. The taxonomy's `timeline`
service (atom binding) is not a record stream.

### 4.2 Taxonomy (Phase 0, before anything is stored)

Decided (maintainer, 2026-10-22): `dbinfo_audit` / `platform_compat_audit`
collapse into `db_info` / `platform_compat`; `adb_audit`, `activity_audit`,
`usage_stats`, `system_property` are documented emitter services with no
rules.

The rules-repo change adds, per service:

- `status: emitter_only` for services with no evaluate path (`usage_stats`,
  `system_property`); `validate-rule.py` already rejects rules on non-active
  services outside `staging/` and keeps doing so; `ServiceActivationCrossCheckTest`
  accepts the status.
- `event_time_field` on `usage_stats`, `dns_monitor`, `network_monitor`,
  `security_log`, `appops_audit` (`event_time_ms`), `tombstone_parser`
  (`crash_timestamp`), `wakelock_parser` (`acquired_at`), `battery_daily`
  (`timestamp`), `package_install_history` (`timestamp`). **Not** on
  `db_info`: the dbinfo section has no per-reference time.
- `time_precision_field` where precision varies (`battery_daily:
  timestamp_precision`).
- `key_fields` on every snapshot-capable service (`app_scanner:
  [package_name]`, `receiver_audit: [package_name, intent_action]`,
  `appops_audit: [package_name, operation]`, `device_auditor: [check_id]`,
  `file_scanner: [file_path]`, …).
- `package_field` naming the field that identifies the app
  (`package_name`, `source_package` for `dns_monitor`, `app_name` for
  `network_monitor`, …).
- `optional: true` on fields only some producers set
  (`appops_audit.event_time_ms`). An optional field is also treated as
  positive-only.
- `positive_only: true` on every field old fleet binaries do not emit:
  `dns_monitor.timestamp`, `dns_monitor.resolved_ips`,
  `file_scanner.accessible`, `appops_audit.event_time_ms`,
  `battery_daily.timestamp`, `battery_daily.timestamp_precision`,
  `db_info.db_path`, `db_info.recent_query_count`, and the existing
  `requested_permissions`, `has_boot_receiver`. `validate-rule.py`'s
  negation guard is generalised from the hard-coded `requested_permissions`
  to every `positive_only` (or `optional`) field.
- Field entries for the facts the typed bug-report records gain (§5.3).

This change follows CLAUDE.md safe ordering and lands before the store.

### 4.3 One contract object; categories are a detection contract

`TaxonomyContract` (Kotlin, `sigma/`) is the **single** Kotlin mirror of the
taxonomy facts the store needs: event-time field, precision field, key
fields, package field, field order and descriptions. One cross-check test
compares it with the taxonomy in both directions. No other list of
event-capable services exists anywhere.

A record is an **event record iff its service declares an `event_time_field`
and the record's value is present and > 0**.

**Timeline categories** (`TimelineCategories`, `sigma/`) are a detection
contract, because atom rules bind on them; today's values are preserved
exactly: `usage_stats` → the record's `event_type`; `appops_audit` →
`permission_use`; `package_install_history` → `package_install`;
`battery_daily` → the record's `event_type`; `network_monitor` →
`network_connect`; `security_log` → `security_event`; `dns_monitor` →
`ioc_match` when `reason` is set, else `dns_query` (`TimelineAdapter.kt:33`);
`tombstone_parser`, `wakelock_parser` → the service name. Gate K1: every
category a bundled atom rule binds has a producer. **Only facts with
`exact` time precision become correlation atoms**; day-precision events are
timeline events but never bind 1-hour windows. Summary text lives in
`event_display.yml`, without semantics.

**Computed columns.** `subjectKey`, `category`, `packageName`,
`timePrecision` and `eventTime` are computed at write time from
`TaxonomyContract` and `TimelineCategories`. A test pins a hash of those
inputs; changing them fails with a message requiring a recompute migration.

## 5. Persistence

### 5.1 Content, facts, observations

Hashes are stored as 16-byte BLOBs (SHA-256 truncated to 128 bits).

**`record_body`**: `hash` BLOB PK; `encoding` (0 plain JSON, 1 Deflate with
preset dictionary); `dictVersion`; `body` BLOB; `rawBytes` (bounds inflation).

**`telemetry_record`** (fact): `id` PK AUTOINCREMENT; `service`; `factKey`
BLOB (unique with `service`); `subjectKey`; `eventTime`; `timePrecision`;
`category`; `packageName`; `bodyHash` BLOB. Indices: unique `(service,
factKey)`, `(service, subjectKey)`, `eventTime`, `packageName`, `bodyHash`.

**`scan_record`** (observation): `scanId`, `service`, `ordinal` (PK);
`recordId` (indexed; unique with `scanId`); `source`; `capturedAt`;
`strippedKeys`.

**Fact identity (`factKey`).**
- Event with a source-supplied identity (intrusion-log `(type, event_id,
  event_time)`; live DNS `dns:<DnsEvent.id>`): `H("src:" + key + "#" +
  bodyHash)` — identity *and* content. Same key with different content is a
  different fact.
- Every other record: `H(bodyHash + "#" + n)`, `n` = occurrence index of that
  content within the service's emitted list (counted in a primitive
  long → int map on a 64-bit hash prefix; a prefix collision only bumps a
  counter, never merges content).

**Observations.** Unique `(scanId, recordId)`: an exact duplicate record
within one scan or import (repeated export lines) is dropped and counted —
this replaces the parser's in-memory duplicate set. A **live** event fact
already observed by an earlier live scan gets no new observation (the
usage re-read overlap and any re-collection are absorbed). Imports always
observe the facts they contain.

**Write order** per chunk: bodies (`INSERT OR IGNORE`) → facts (`INSERT OR
IGNORE`; ids of existing facts looked up by `(service, factKey)`) →
observations. Every list-parameter query goes through `chunkedIn(≤ 900)`
(API 26–29 SQLite allows 999 variables).

**Reads** go through `scan_record`, so a scan's report, browser, export and
timeline filter see every record that scan observed, including facts first
stored by another scan (G1, G3). All paging is keyset (no OFFSET, no
`COUNT(*)` per page).

**Delete.** Candidates are collected from the scan's own observations in
keyset chunks; observations are deleted; candidate facts with no remaining
observation and no pin are deleted; then their bodies if unreferenced.

**Pins.** A fact referenced by any triggered finding, any alert, or any
`forensic_timeline` row is never deleted by retention or scan deletion
(references are plain columns, no FK). Evidence behind a finding outlives
the observations that produced it.

**Compression.** Event bodies: Deflate with a per-service-family preset
dictionary ≤ 4 KiB; snapshot bodies plain JSON. Dictionaries are shipped in
`res/raw/`, **immutable**, pinned by SHA-256 in a test; a changed builder
output requires a new `dictVersion`; decode selects by `dictVersion`. The
writer owns one `Deflater` per chunk (`setDictionary` after every `reset()`,
`end()` after); `decode` allocates its own `Inflater` (thread-safe) and
returns an unreadable placeholder on any failure or on inflation past
`rawBytes`. A test checks every event body's zlib header carries the
dictionary flag and the dictionary's Adler-32.

**Cross-scan reads.** `history(service, subjectKey)` and
`changedBetween(scanA, scanB, service)` keyed on `subjectKey`.

**Retention** (my call):
- Snapshot observations: kept for the newest N live scans (default 20).
  Older live scans become `PARTIAL_RETENTION`.
- Live event observations: 30 days.
- Import observations: until the user deletes the import.
- Pinned facts: always (above).
- Runs in `IocUpdateWorker`, serialised with scans by `scanMutex`, in its
  own transactions.

### 5.2 Writers, watermarks, failure handling

**Chunked single pass.** Every writer (live scan, bug-report import,
intrusion-log import) runs: insert the `ScanResult` with `state =
IN_PROGRESS` → for each 5,000-record chunk of each `ServiceRecords`, one
transaction: persist, evaluate, write `scan_finding` rows (and alert
upserts, §5.4) → final transaction: correlation, signals, summary columns,
`state = COMPLETE`, `telemetryState`, watermarks. `IN_PROGRESS` scans are
invisible to every list, report and current-findings query; a failed writer
deletes its scan (§5.1 delete), and startup sweeps any leftover
`IN_PROGRESS` scan. The VPN's DNS writes interleave between chunks; the WAL
truncates between chunks (`journal_size_limit`). Nothing of a failed import
is ever visible (the #342 B1 guarantee, kept).

**Correlation memory.** The correlator receives atoms only for the
categories atom rules bind (`SigmaRuleEngine.atomCategories()`), streamed
from the database; this is the memory bound for correlation and is gated
(T1 runs a 100,000-event import whose events include a bound category).

**Live enrichment.** `last*Telemetry` deleted; bug-report enrichment reads
the latest live scan's `app_scanner` observations within
`TelemetryReader.APP_ENRICHMENT_MAX_AGE_MS` (5 min, moved from the
orchestrator) or collects fresh and discards; never stored under an import.

**Replace-on-reimport is removed.** A re-imported or overlapping export
observes the facts it shares; the import card reports new facts,
already-stored facts and dropped duplicates.

**Watermarks** (`event_watermark(service, position, scanId)`):
- Live DNS: position = `DnsEvent.id` (monotonic; immune to late flushes and
  clock changes). First scan: ids from the last 24 h.
- Usage stats: position = event time; each scan re-reads from `position −
  5 min` (absorbed by the live-observation rule). Usage access is checked
  explicitly; no access = collection failed.
- Advance on every committed scan whose collection did not fail, **including
  when rules on that service were capability-skipped** — the skip is
  recorded (`NotEvaluatedReason`) and the stored facts remain replayable.
  Never past the scan's start; reset if ahead of `now`. The disk-full
  fallback (below) does not advance.
- Scans serialised by `scanMutex`.

**Storage protection (nothing is truncated silently).**
- Every import (bug report and intrusion log) is preflighted from the
  archive's decompressed entry sizes × a stored-size factor measured in the
  release battery (initial value 0.6, a named constant). If free space after
  the estimate would be below `2 × estimate + 200 MB`, the user sees the
  estimate and free space and may cancel or **import anyway**; a disk that
  fills mid-import rolls back the current chunk and the writer deletes the
  `IN_PROGRESS` scan.
- Parser input bounds stay as input validation (2,000,000 per type for
  intrusion logs; per-type bounds of the same order added to bug-report
  modules), each named on the import card when tripped.
- Writers catch `Throwable`; imports surface it as a persist failure.
- A live scan whose telemetry write fails (`SQLiteFullException`) is saved
  without telemetry: findings kept, `telemetryState = FAILED`, watermarks
  unchanged.
- `DnsLogBuffer` keeps a batch whose write failed and retries it on the next
  flush (within its existing buffer bound), recording a health warning.

### 5.3 Typed bug-report records; `TimelineEvent` retired

Before any module's timeline rows are removed (Phase C), four modules emit
typed records that fill the `TelemetryBundle`, each emitting **every fact it
parses** (emitter-emits-all-facts):

- `InstallTimeModule` → `PackageInstallHistoryEntry` (event, `package_install`).
- `DbInfoModule` → `DatabasePathObservation` with `db_path`,
  `recent_query_count` (snapshot).
- `PlatformCompatModule` → `PlatformCompatChange` (snapshot).
- `BatteryDailyModule` → `BatteryDailyEvent` for every entry it parses today
  (install, update, uninstall, downgrade) with today's `event_type`, plus
  `timestamp` at day precision and `timestamp_precision = "day"` when the
  section yields the date. A parity test compares the old rows with the new
  records before the rows are removed.

`WakelockParser`'s time base becomes the bug report's own capture time
(from its header), not the analysis time, so wakelock facts are correct and
dedup across re-imports. `AdbKeysModule` records are snapshots. The
hand-built `TimelineEvent` rows, `ModuleResult.timeline`,
`BugReportAnalysisResult.timeline`, `TimelineFormatter` and `TimelineEvent.kt`
are then removed.

### 5.4 Findings, alerts, lifecycle

Schema 20 (Phase D).

**`scan_finding`** — one row per finding per scan, always inserted (per-scan
views stay complete): `id`, `scanId`, `ruleId`, `triggered`, `level`,
`category`, `kind` (`STATE` | `ALERT`), `recordId` (fact), `service`,
`ordinal`, `alertId` (nullable), `findingJson` (without `matchContext`,
which is rebuilt from the pinned fact).

**`alert`** — one row per incident: `id` PK AUTOINCREMENT, `alertKey` BLOB
unique, `ruleId`, `status` (`OPEN` | `CLOSED`), `openedAt`, `openedScanId`,
`closedAt`, `closedReason`, `closedWithCredential`, `level`, `recordId`.
**`alert_member`** (`alertId`, `atomRef`) for correlation alerts, at most
1,000 refs stored plus a count.

**Kind** = `ALERT` iff the matched record is an event fact or the finding is
a correlation finding; otherwise `STATE`.

**Alert identity.**
- Record finding: `alertKey = H(ruleId, factId, evidenceDiscriminator)` —
  triggered findings only; the discriminator separates multiple evidence
  results for one record.
- Correlation finding: a new chain joins an existing alert of the same rule
  and group key when their member sets overlap (`alert_member`); otherwise a
  new alert. A growing lookback window therefore never mints a duplicate.
- Atoms: a fact referenced by a `forensic_timeline` row (`recordId`, or the
  shared `sourceEventKey` — live DNS `ioc_match` rows) is excluded from the
  correlator by the same rule `TimelineDao` uses to nest it.

**Lifecycle (maintainer decision, SOC pattern).**
- State findings are current while the **latest live scan** triggers them;
  imports never displace live state (today's `preferRuntimeScan`).
- Alerts are current from opening until a person closes them; re-fires
  attach new findings to the existing alert; a closed alert stays closed; a
  new fact opens a new alert.
- Current findings = latest live scan's triggered state findings ∪ OPEN
  alerts. The dashboard reads open alerts as a count plus a paged list.
- **Protected actions**: closing an alert, deleting a scan that has findings
  on OPEN alerts, and "Clear all" require device-credential confirmation —
  platform `BiometricPrompt` with `DEVICE_CREDENTIAL` only on API 30+,
  `KeyguardManager.createConfirmDeviceCredentialIntent` on API 26–29 (no
  weak biometrics, no new dependency). Without a secure lock screen the
  action proceeds and is recorded `closedWithCredential = false`, shown as
  such in the report. Controls reject touches flagged
  `FLAG_WINDOW_IS_OBSCURED` / `FLAG_WINDOW_IS_PARTIALLY_OBSCURED`.
- Deleting a scan deletes its `scan_finding` rows, never an `alert`. Each
  closure writes a scan-independent timeline row (`scanResultId = -1`).
- The report lists state findings, open alerts (with the scan that opened
  them) and closed alerts (time, note, credential flag).

**Migration 19 → 20.** For each `ScanResult` row, `findings` is read by
`length` and 256 KB `substr` chunks (no row may abort the migration);
corrupt JSON keeps the scan with zero findings. Kind: findings written at
schema 19 carry `service`/`ordinal` → resolve the fact through `scan_record`
and decide per record; older findings → `ALERT` iff `matchContext` holds the
service's event-time field > 0 or the service is always-event
(`dns_monitor`, `network_monitor`, `security_log`); unknown rule ids →
`STATE`. Rule id → service comes from a frozen table generated at schema 20.
Alerts: keyed from the fact when resolvable, else from `ruleId` + a hash of
`matchContext`; OPEN if their scan is within the last 30 days, else CLOSED
"migrated (older than 30 days)". `forensic_timeline.level` is backfilled.

`Finding` gains `service` and `ordinal` at evaluation; `recordId` is
resolved per chunk at save.

### 5.5 Caps removed

Deleted: `FINDINGS_PERSIST_CAP`, `DNS_PERSIST_CAP`, `CONNECT_PERSIST_CAP`,
`SECURITY_PERSIST_CAP`, `capTriggeredFindings`, the caps log,
`getAllForExport`'s `LIMIT 10000`, the report's `take(500)`,
`HistoryViewModel.INTRUSION_ROW_LIMIT`, `getAllScans`'s `LIMIT 50`, the
timeline DAO's `limit = 500` defaults, and `getRecentSnapshot()` as the scan
DNS window. Allow-listed with a comment naming the gate:
`ScanResultDao.getLatestTwo` (semantic two), `IndicatorDao.lookup`
(`LIMIT 1`), `DnsEventDao.getRecentEvents` / `getRecentSnapshot` (the live
DNS monitor screen's display window).

### 5.6 Timeline rows

`forensic_timeline` keeps finding rows, correlation signals and detected
changes. The 30-day prune applies to `LIVE_SCAN` rows only, never to pinned
references' targets or to closure rows.

## 6. Timeline

- **One keyset-paged query** in a dedicated `TimelineDao`: `UNION ALL` of
  event facts (scan filter through `scan_record`) and `forensic_timeline`
  rows, ordered `(time DESC, rowKind, id DESC)`, keyed on that tuple, via a
  custom `PagingSource` that registers an `InvalidationTracker.Observer`. One
  SQL builder per filter shape; `COALESCE` for non-null columns in the fact
  branch. A fact referenced by a `forensic_timeline` row is nested under it.
- **Counts** on every group header and the filter bar from aggregate
  queries; date groups use the device's zone (`ZoneId`, DST-correct).
- **Presentation (my calls):** severity filter in SQL on `level`; no
  cross-page roll-up; finding rows for every scan; pinned section shows
  current findings.
- **Switch renamed** "Show findings and their evidence only";
  `TimelineRow.TelemetryRow` → `TimelineRow.EventRow`.
- **Correlation** keys atoms by `AtomRef` (`Row(id)` | `Fact(id)`); signal
  details carry `member_fact_ids` beside `member_event_ids` and every
  consumer reads both (gate).
- **View telemetry** from History, scan headers, finding detail.

## 7. Report and export

- One path: `ReportExporter`, streaming to a file `Writer`. The History
  sheet shows a summary (findings, per-service counts, telemetry state) and
  opens the full report as a file.
- TELEMETRY sections read only the scan's observations; missing telemetry
  says why (`NONE` pre-feature, `PARTIAL_RETENTION`, `FAILED`).
- Device-controlled strings and field keys are escaped: every character in
  Unicode categories Cc, Cf, Zl, Zp, Co, Cn (covers `\r`, `\n`, U+0085,
  U+2028/9, bidi overrides) is rendered as `\uXXXX`.
- Full telemetry stays in `BOTH` and `TELEMETRY_ONLY` (owner intent); the
  export dialog states record count, size, and the sensitive categories
  included (DNS history, connections, app usage, installed apps).
- FINDINGS: state findings, open alerts, closed alerts.
- JSONL export streams through `GZIPOutputStream`. Every report or export
  deletes other files in `cache/reports/` older than one hour first.
  `TimelineExporter` streams and keeps its CSV formula guard.

## 8. UI

### 8.1 Telemetry browser

From History, scan headers and finding detail: services with counts →
one service's records (keyset paged; search over indexed columns, debounced)
→ a record's fields in taxonomy order with descriptions; snapshot records
show their subject's history across scans with changed fields highlighted.
Unreadable bodies show as such.

### 8.2 Settings

Storage size (distinct bodies; snapshots / live events / imports), "Keep
snapshot telemetry for the last N scans" (default 20), "Delete old snapshot
telemetry now".

## 9. Testing and gates (regression policy)

All gates are JVM unit tests (Robolectric 4.14.1, SDK 35).

- **S1** full decoded map equals evaluated map per service (envelope keys
  restored only where stripped; content `source` values preserved).
- **S2** facts stored once: real records across two imports with different
  `capturedAt` share facts; identical-content events in one batch stay
  distinct; same source key with different content → two facts; unchanged
  snapshots share facts across scans; exact duplicate lines in one import →
  one observation, counted.
- **S3** a failed writer leaves no visible scan and no store rows; startup
  sweeps `IN_PROGRESS`.
- **S4** deleting import A keeps facts import B observed and facts pinned
  by findings.
- **S5** shipped dictionaries match pinned hashes; v1 fixture decodes; event
  bodies carry the dictionary flag and id.
- **S6** a corrupt body decodes to an unreadable placeholder.
- **S7** one-shot sequence: a writer consuming a `ServiceRecords` twice fails.
- **E1** every writer evaluates exactly the chunk it persists; `file_scanner`
  ordinal with an inaccessible record first.
- **E2** field-map completeness.
- **W1** watermarks: consecutive scans observe each live event once; no
  advance on failed collection, missing usage access, or disk-full fallback;
  advance despite a capability-skipped rule, observation count linear over N
  such scans; late-flushed DNS collected; clock-ahead reset.
- **R1** report provenance per scan, import, retention-trimmed, pre-feature,
  failed-telemetry.
- **R2** single report path; no `last*Telemetry`.
- **R3** escaping: `\n`, `\r`, U+2028, U+202E in values and keys.
- **B1** real `BugReportAnalyzer` on a fixture: every module with telemetry
  observed; the four converted modules emit typed records; battery parity
  with the old rows; wakelock time from the report header.
- **C1** no persistence caps (incl. `limit: Int = n` defaults; allow-list §5.5).
- **T1** 100,000-event import: all rows page; counts match; no duplicated
  event rows; no `TEMP B-TREE`; captured SQL has no `OFFSET`; correlation
  over a bound category completes.
- **K1** every atom-bound category has a producer; day-precision facts never
  become atoms.
- **F1** migration 19→20: 1,200 findings; corrupt row; 3 MB row; schema-19
  findings resolved per record; live app-ops finding stays STATE; DNS finding
  ALERT; 30-day OPEN/CLOSED split; `level` backfilled.
- **F2** a finding's `recordId` resolves to its matched record, every service.
- **L1** lifecycle: state follows latest live scan, not imports; alert
  persists until closed; overlapping import attaches its finding to the same
  alert and keeps its own `scan_finding` row; growing correlation window
  joins the existing alert; closed stays closed; new fact → new alert.
- **L2** close, delete-scan-with-open-alerts and clear-all require the
  confirmation; obscured touches rejected; closure rows survive scan
  deletion.
- **M1** preflight from decompressed sizes, margin `2 × estimate + 200 MB`,
  "import anyway"; telemetry write failure keeps live findings; DNS flush
  retry.
- **Q1** no post-API-26 SQLite syntax in DAO, migration or timeline SQL;
  every list-parameter DAO call goes through `chunkedIn`.
- **X1** computed-column contract hash pinned.
- **V1** vocabulary gate. **P1** import timeline rows survive the prune.
  **D1** imported DNS finding carries its record time (lands with Phase 0).
- Taxonomy cross-checks and `ServiceActivationCrossCheckTest` (re-derived
  from `evaluateRecords` call sites, vacuity guard kept).

Release battery (standing policy): clean installs on the F916B and
emulators including API 26 and a low-RAM image; scan twice; bug-report
import; intrusion-log import twice; maximal fixture on the low-RAM image;
measure the stored-size factor; browse; close an alert and delete a scan
through the credential prompt; compare report telemetry to the browser;
note that a Play-track downgrade across schemas 19/20 wipes data.

## 10. Decisions

**Decided by the maintainer (2026-10-22):**

- Store everything; no caps. Disk cost is acceptable (§1.1).
- Snapshot records stay out of the timeline.
- Terminology must be consistent and precise across code, UI, docs, taxonomy.
- The bug-report telemetry loss is a defect.
- SQLite (queryable across scans), not files; a fact is stored once.
- Alerts stay open until a person closes them; state findings clear
  themselves.
- Taxonomy: collapse `dbinfo_audit` / `platform_compat_audit`; document the
  four emitter services with no rules.

**Plan-gate resolutions (my calls; findings files
`docs/superpowers/plans/2026-10-22-telemetry-store-plan-gate-round{1,2}-findings.md`):**

- Fact / observation / content split; content-checked source identity;
  conditional envelope stripping (§4.1, §5.1).
- Chunked single-pass writers with `IN_PROGRESS` scans (§5.2).
- Watermarks always advance; live facts observed once (§5.2).
- Findings per scan, alerts across scans; overlap-joined correlation alerts;
  credential-protected close/delete/clear (§5.4).
- Typed bug-report records emitting every fact; day-precision events never
  atoms; wakelock time base fixed (§5.3).
- Immutable versioned dictionaries; 128-bit BLOB keys (§5.1).
- Preflight with "import anyway" (§5.2).
- One `TaxonomyContract`; computed-column contract hash (§4.3).
- Keyset paging everywhere; pins for findings, alerts, timeline refs (§5.1, §6).
- Report streaming, escaping, sensitive-category notice; full telemetry kept
  per owner intent (§7).
- Replace-on-reimport removed; retention snapshots-by-count, events-by-age.

**Left to the builder:** browser Compose structure; dictionary-build script
wiring; import-card wording.

## 11. Follow-ups recorded, not scoped

- Differential timeline events from `changedBetween` and rules over them.
- Retroactive matching of stored `dns_monitor` facts when IOCs change (needs
  an indexed lookup column; cheap to add later).
- Replay of stored facts through a newer ruleset (`evaluateRecords`), which
  also recovers capability-skipped evaluation.
- Full-body search; JSON1 queries over snapshot bodies.
- #137 machine-readable schema from the taxonomy.
- The live `DnsEvent` table becoming `dns_monitor` facts (needs facts
  observed by the VPN, not only scans).
- `BatteryDailyModule`'s `package_downgrade` is a judgment computed in the
  emitter; move it to a rule.
- Usage-stats all apps, user-selectable. A richer alert case model.

## 12. References

- osquery: snapshot vs. differential (event) query semantics.
- MVT: per-module results, `timeline.csv`, `*_detected.json`.
- Elastic Security alerts: ancestor event IDs; open/closed workflow status.
- SQLite JSON1; content-addressed storage; Deflate preset dictionaries
  (zlib checks the dictionary's Adler-32 — hence immutability); SQLite's
  999-variable limit before 3.32.
- Room `CursorWindow` 2 MB row limit (the origin of the #342 caps).
