# Telemetry Store, Uncapped Timeline, Finding Lifecycle, and the Telemetry Vocabulary — Design

**Date:** 2026-10-22
**Status:** Design approved in-session (all decisions closed 2026-10-22);
ready for the plan gate. Plan gate and implementation are coordinated by a
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
- G7. **A fact is stored once.** An event is observed by exactly one scan;
  an unchanged snapshot body is kept once however many scans see it; an
  imported event that two exports both contain is kept once.
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
- Source-named types or fields (`BugReportX`, `ImportedY`) — spec 2026-04-09 §4.

## 3. Vocabulary (normative)

These definitions are the contract. ARCHITECTURE.md gains a glossary section
containing them verbatim; a build gate (§9, V1) enforces the retired phrases.

| Term | Definition |
|---|---|
| **Telemetry record** | A typed fact an emitter produced, exactly as produced, before any rule saw it. Source-agnostic; provenance is the `TelemetrySource` field. Every record is one of two time-shapes. |
| **Snapshot record** | State observed *at scan time*: `AppTelemetry`, `AppOpsTelemetry` (live), `ReceiverTelemetry`, `ProcessTelemetry`, `AccessibilityTelemetry`, `FileArtifactTelemetry`, `DeviceTelemetry`, `SystemPropertySnapshot`, `DatabasePathObservation`, `PlatformCompatChange`. A snapshot record has a `captured_at` but is not *about* a moment. |
| **Event record** | Something that happened at a time *T* the record carries: usage transitions, `DnsEvent`, `NetworkTelemetry` (connect), `SecurityLogEvent`, `TombstoneEvent`, `WakelockAcquisition`, `BatteryDailyEvent`, `PackageInstallHistoryEntry`, app-ops access records parsed from a bug report. Decided per record, §4.3. |
| **Timeline event** | A timestamped row on the forensic timeline. Comes from (a) every event record, read in place — never copied; (b) every triggered finding; (c) correlation signals; (d) **detected changes** between consecutive snapshots (today: first-seen install, first-seen device-admin grant). **Snapshot records never become timeline events.** |
| **Finding** | Rule output (`Finding`). References the record it matched by `recordId`. A finding on a snapshot record is a **state finding**; a finding on an event record is an **alert**. |
| **Provenance** | Where a record came from: `TelemetrySource` (`LIVE_SCAN`, `BUGREPORT_IMPORT`, `INTRUSION_LOG_IMPORT`). It is not a kind of telemetry. |
| **Watermark** | Per event service, the `eventTime` up to which live events have been collected. The next scan collects from it. |

**Retired phrases.** "Raw telemetry" — every telemetry record is raw by
definition; the `raw_fact`/`judgment` grading lives at the field level in the
taxonomy, where it belongs. "Informational telemetry" — the UI switch meant
"timeline events not referenced by a finding" and will say so. The bug-report
`TimelineEvent` class — a source-shaped, untyped row — is retired (§5.3).

Field-level naming keeps the taxonomy's `snake_case`.

## 4. Architecture

```
emitters ──typed records──▶ SigmaRuleEngine ──▶ findings ──▶ scan_finding (rows, lifecycle)
     │   (events: since watermark)                                │ recordId
     │  toFieldMap()                                              ▼
     ▼                                                    telemetry_record ◀─┐
telemetry_record  (one row per record; body deduped / compressed)           │
     │                                                                       │
     ├── event rows ─────────────────┐                                       │
     │                               ▼                                       │
     │                     Timeline = UNION( event records,                  │
     │                                       forensic_timeline:              │
     │                                         finding rows, signals, changes)
     ▼
Report · Telemetry browser · JSONL export · cross-scan queries
```

Persistence surfaces:

- **`telemetry_record` + `record_body`** (new): every record of every scan or
  import, stored once. §5.1.
- **`scan_finding`** (new): one row per finding with lifecycle columns,
  replacing the `ScanResult.findings` JSON column. §5.4.
- **`event_watermark`** (new): per-service collection watermark. §5.2.
- **`forensic_timeline`** (changed): holds only what has no record behind it
  — finding rows, correlation signals, detected changes. Event rows are no
  longer copied into it. §6.

### 4.1 Why the stored shape is the field map

Records are stored as their `toFieldMap()` projection — the `Map<String, Any?>`
in taxonomy `snake_case` that `SigmaRuleEvaluator` actually evaluates — not as
the Kotlin data classes. Reasons:

- It is, by construction, *exactly what the rules saw* (anti-goal 3).
- The taxonomy documents every field, type, nullability and grading for
  every service *it knows*; the store inherits that schema and advances #137.
  Six emitter services are not in the taxonomy today — §4.2.
- Apart from `DnsEvent`, none of the telemetry data classes is
  `@Serializable`; the field map is already the serialization boundary the
  2026-04-09 spec calls "the compatibility boundary".
- SQLite JSON1 (`json_extract`, present in Android's SQLite at every API level
  the app supports) can query it in place, so cross-scan questions —
  "every snapshot of this package", "when did this permission first appear" —
  are ordinary indexed queries.

Services covered: every emitter output, whether or not the engine evaluates
it — each `SigmaRuleEngine.evaluate*` entry point, the generic
`evaluateGeneric(records, service)` path used by bug-report modules,
`usage_stats`, and `SystemPropertySnapshot`. Live `DnsEvent` rows keep their
existing `DnsEvent` table (the VPN drain path is unchanged); the events a
scan evaluates are also written to the store as that scan's `dns_monitor`
records. The taxonomy's `timeline` service (`field_map: none`, atom binding)
is not a record stream and has no rows.

### 4.2 Services the taxonomy does not know (open — §10, Q1)

The following emit records today with no taxonomy entry, so the store would
have no schema for them: the generic bug-report services `adb_audit`
(`AdbKeysModule`), `activity_audit` (`ActivityModule`), `dbinfo_audit`
(`DbInfoModule`), `platform_compat_audit` (`PlatformCompatModule`);
`usage_stats` (no `toFieldMap` — `UsageStatsScanner` builds timeline rows
directly); and `SystemPropertySnapshot` (in `TelemetryBundle`, no
`evaluate*`, no `toFieldMap`, no service name). Two of the generic names
duplicate typed services for the same facts (`dbinfo_audit` ≈ `db_info`,
`platform_compat_audit` ≈ `platform_compat`).

**Decided (maintainer, 2026-10-22):** the two duplicates collapse into the
typed services — `DbInfoModule` and `PlatformCompatModule` emit `db_info` and
`platform_compat` records with the typed field maps, and the `_audit` names
are deleted. `adb_audit`, `activity_audit`, `usage_stats` and
`system_property` are added to the taxonomy as emitter entries with their
fields documented and **no rules**; `usage_stats` and `SystemPropertySnapshot`
get `toFieldMap()` projections. The taxonomy PR goes through the safe-ordering
procedure in CLAUDE.md (branch in `android-sigma-rules`, bump the AndroDR
submodule to that commit, green `LogsourceTaxonomyCrossCheckTest` +
`DetectionFieldCrossCheckTest`, then merge the rules branch, then re-point).
Every stored service therefore has a taxonomy entry before S1/V1 are written.

### 4.3 Snapshot or event: decided per record, by a declared time field

Some services carry both shapes under one name: live `AppOpsTelemetry` is a
snapshot (`last_access_time` is `0L` — "not available via public API"),
while bug-report app-ops records carry a real `event_time_ms`. The rule:
**a record is an event record iff its service declares an event-time field
and the record's value for it is present and > 0; otherwise it is a snapshot
record.** The declaration is a Kotlin registry `EventTimeFields: Map<service,
fieldName>` in `sigma/` next to `TelemetryFieldMaps`, cross-checked against
the taxonomy by the existing `LogsourceTaxonomyCrossCheckTest` pattern (the
taxonomy gains an optional `event_time_field:` key per service so the two
cannot drift). The same registry decides the storage treatment (§5.1), the
timeline membership (§6), and the finding lifecycle (§5.4). (My call.)

## 5. Persistence

### 5.1 `telemetry_record` and `record_body`

Room entities, DB version 18 → 19 (one migration step shared with §5.4).

**`record_body`** — one row per distinct record content:

| column | type | meaning |
|---|---|---|
| `hash` | String PK | SHA-256 of the canonical JSON of `fields` |
| `encoding` | Int | 0 = plain JSON (snapshot bodies); 1 = Deflate with preset dictionary (event bodies) |
| `body` | BLOB | the field map |
| `rawBytes` | Int | uncompressed size |

**`telemetry_record`** — one row per record observed:

| column | type | meaning |
|---|---|---|
| `id` | Long PK auto | the `recordId` findings reference |
| `scanId` | Long, indexed | `ScanResult.id` of the scan or import that stored it |
| `service` | String, indexed with `scanId` | taxonomy service |
| `ordinal` | Int | position in the emitter's output |
| `source` | `TelemetrySource` | provenance |
| `capturedAt` | Long | |
| `packageName` | String?, indexed | copied from `fields` when present |
| `eventTime` | Long?, indexed | copied from the service's event-time field; null for snapshots |
| `eventKey` | String?, unique with `service` | event records only — the source's own id (`event_id`) when it has one, else `hash` |
| `bodyHash` | String → `record_body.hash` | |

**Dedup rules (G7).**
- Snapshot bodies: `INSERT OR IGNORE` into `record_body` by hash; a second
  scan of an unchanged app adds a 60-byte reference row, not a 3.5 KB body.
  Across 20 daily scans, snapshot storage is ≈ 1 + 19 × churn.
- Event records: `INSERT OR IGNORE` on `(service, eventKey)`. A re-import or
  an overlapping export stores nothing new for events already present; the
  import summary reports "N new events, M already stored". Live events are
  deduped upstream by watermark (§5.2) and the unique key is the safety net.
- Deleting a scan deletes its `telemetry_record` rows; bodies no longer
  referenced are dropped in the same transaction
  (`DELETE FROM record_body WHERE hash NOT IN (SELECT bodyHash …)`, batched).

**Compression (my call).** Event bodies are Deflate-compressed with a preset
dictionary (`java.util.zip.Deflater.setDictionary`) built at build time from
the taxonomy's field names and the fixed vocabularies they take (permission
names, security-log tags, common TLDs), checked into `res/raw/` and versioned
by `encoding`. Snapshot bodies stay plain JSON so cross-scan `json_extract`
queries work on them; event records are browsed by the indexed columns
(`eventTime`, `packageName`, `service`) and by per-service denormalized keys
added where the browse needs them (`domain` for `dns_monitor`,
`destination_ip`/`port` for `network_monitor`), and the body is opened only
on expand or export. Storing bodies compressed inside SQLite rather than as
files keeps the whole save in one Room transaction, with no file/DB split,
no orphan sweep, and no integrity hash to verify on read.

**Read API** (`TelemetryStore`, suspend, `Dispatchers.IO`):

- `services(scanId): List<ServiceSummary>` (count, bytes per service)
- `records(scanId, service): PagingSource<Int, TelemetryRecord>`
- `record(recordId): TelemetryRecord?`
- `history(packageName, service): Flow<List<TelemetryRecord>>` — every scan's
  record of one package, newest first (the cross-scan query)
- `changedBetween(scanA, scanB, service): List<Pair<TelemetryRecord?, TelemetryRecord?>>`
  — records whose body hash differs, appeared, or disappeared (the
  foundation for §11 differential events; implemented here because it is one
  query and it is what "detected change" means)
- `exportJsonl(scanId, out: OutputStream)` — MVT-style results dump

**Retention** (my call, see §10): full records kept for the most recent
**20 live scans**; older live scans keep their `ScanResult`, `scan_finding`
rows and `forensic_timeline` rows and lose their `telemetry_record` rows
(dedup means unchanged bodies survive while any kept scan references them).
Imports are kept until the user deletes them. The count is a Settings value
with that default; Settings shows the store's size by category (snapshots,
live events, imports) so the user sees what a long-kept import costs.

### 5.2 Writers and watermarks

**`event_watermark(service PK, eventTime, scanId)`.** For each event service
collected live (`usage_stats`, `dns_monitor`), `runFullScan` collects events
with `eventTime > watermark` up to scan start, stores them, and advances the
watermark to the newest stored `eventTime` inside the save transaction. First
scan (no watermark): 24 h floor, the current behaviour. Consequences:

- `UsageStatsScanner.collectTimelineEvents(hoursBack)` becomes
  `collectEvents(sinceMs, untilMs)`; `deleteBySource("usage_stats")` in
  `ScanRepository` is deleted — each scan keeps its own events.
- The post-hoc DNS evaluation uses `dnsEventDao.eventsBetween(since, until)`
  instead of `getRecentSnapshot()` (newest 500). `getRecentSnapshot` keeps
  its one remaining caller, the DNS monitor screen, and is allow-listed in C1
  with a comment.
- A live event is evaluated by exactly one scan, so an alert fires once; its
  lifecycle is then §5.4's, not re-firing's.

**`runFullScan`**: after the telemetry phase, every awaited list — app,
device, process, file, accessibility, receiver, app-ops, usage events, DNS
events since watermark — is handed to the store inside the save transaction.
The `last*Telemetry` fields are deleted. Their four readers are rerouted:
`ReportExporter` and `HistoryViewModel`'s direct `formatScanReport` call
(collapsed into the single `ReportExporter` path, §7) read the store;
`BugReportViewModel` and `analyzeBugReport`'s APK-hash/display-name
enrichment read the **most recent live scan's `app_scanner` records** (within
the existing freshness window) or collect fresh and discard. Live inventory
used only for enrichment is **not** stored under the import's scanId — an
import's store holds only the import's records, so R1 holds. (My call.)

**`analyzeBugReport`**: every `TelemetryBundle` list and every
`ModuleResult.telemetry` list (keyed by `telemetryService`) is handed to the
store. This is the fix for motivation (3).

**`analyzeIntrusionLog`**: `dnsEvents`, `networkEvents`, `securityEvents` —
the *complete* parsed lists, not the capped ones — written in batches of
5,000 rows inside the one transaction. The correlator (§5.3 of #342) receives
event rows by category through a query over `telemetry_record`, not one
in-memory list. (Resolves builder-check Q2.)

### 5.3 Event records and the retirement of `TimelineEvent`

Bug-report modules that today build `TimelineEvent(timestamp, source,
category, description, severity, packageName)` instead emit typed event
records into `ModuleResult.telemetry` (they already do for rule evaluation;
the duplicate hand-built row goes away). Event display text — the one line
the Timeline shows for a record — comes from a per-service template in a
small `event-display.yml` resource (rule YAML owns finding text; this owns
event text — my call). The `(packageName, timestamp)` dedup against finding
rows (`ScanOrchestrator.kt:617`) is replaced by the `recordId` link: a
finding row *points at* its event record; the UI nests them instead of
hiding one.

`TimelineEvent.kt`, `TimelineFormatter`'s dependence on it, and
`BugReportAnalysisResult.timeline` are removed.

### 5.4 `scan_finding` — findings become rows with a lifecycle

Room entity `ScanFinding` (table `scan_finding`): `id` (auto), `scanId`
(indexed), `ruleId` (indexed), `triggered` (indexed), `level`, `category`,
`recordId` (nullable → `telemetry_record.id`), `kind` (`STATE` | `ALERT`,
derived from the matched record's shape per §4.3), `status`
(`OPEN` | `CLOSED`), `closedAt`, `closedReason` (free text, nullable), and
the remaining `Finding` fields as columns or small JSON (`tags`, `evidence`,
`matchContext`, `impliesFlags`).

**Lifecycle (maintainer decision, SOC pattern).**
- A **state finding** (`kind = STATE`) is true of a scan. It appears in
  "current findings" while the latest scan triggers it and leaves when a
  later scan does not. No user action; `status` is unused for it.
- An **alert** (`kind = ALERT`) is opened by the scan whose event triggered
  it and **stays in "current findings" until a person closes it**, however
  many scans follow. Closing records `closedAt` and an optional reason; the
  finding row and its timeline row are never deleted. A closed alert on an
  event is not re-opened by a later scan (the event is stored once and
  evaluated once); a *new* event matching the same rule opens a new alert.
- "Current findings" (dashboard, apps/device screens, the report's
  FINDINGS section) = latest scan's state findings ∪ all `OPEN` alerts from
  any kept scan. Alerts whose scan is retention-expired keep their
  `scan_finding` row (retention removes records, not findings).
- UI: an alert row gets "Close" with an optional note; the dashboard shows
  open-alert count separately from state findings; the report lists open
  alerts with the scan that opened them.

Migration 18 → 19 explodes every existing `ScanResult.findings` array into
rows (`kind` from the rule's service via the §4.3 registry; existing alerts
start `OPEN`) and drops the column. `ScanResult` keeps its scalar summary
columns; `findings` becomes repository-loaded (`ScanRepository.findings(scanId)`
and `currentFindings()`), and the history list query reads `ScanResult`
alone — the 2 MB window is no longer in play, so `FINDINGS_PERSIST_CAP`,
`capTriggeredFindings`, and the `truncated`-driven "kept N of M" copy are
deleted. `computeDiff`, dashboard, device audit, apps screen and report move
to the repository methods; `Flow<List<ScanResult>>` consumers that need
findings get a `Flow<ScanWithFindings>` relation.

`Finding` gains `recordId: Long? = null` (G6). `matchContext` stays as the
display copy (fleet compatibility; old rows have no ref).

### 5.5 Caps removed

Deleted: `FINDINGS_PERSIST_CAP`, `DNS_PERSIST_CAP`, `CONNECT_PERSIST_CAP`,
`SECURITY_PERSIST_CAP`, `capTriggeredFindings`, the "Intrusion-log
persistence caps dropped rows" log, `ForensicTimelineEventDao.getAllForExport`'s
`LIMIT 10000`, the report's `intrusionEvents.take(500)` and the DAO's `500`
argument behind it, `HistoryViewModel.INTRUSION_ROW_LIMIT`,
`ScanResultDao.getAllScans`'s `LIMIT 50` (History becomes a paged list like
the Timeline), and `getRecentSnapshot()` as the live scan's DNS evaluation
window (§5.2). `getLatestTwo` is a semantic "two", not a cap, and is
allow-listed. Parser-level bounds that defend against malformed input
(`MAX_LINE_LENGTH`, `MAX_*_RECORDS = 200_000` per type, clock-skew window)
stay: they are input validation with a `truncated` flag the user sees, not
persistence caps — but since §1.1 shows 200k per type is one real week, the
builder raises them to a value that is defensive rather than binding (my
call: 2,000,000) and the import card states the bound when it trips. A gate
(§9, C1) fails the build if a `_PERSIST_CAP`, `_ROW_LIMIT`, or
unparameterized `LIMIT` reappears outside the allow-list.

### 5.6 Retention of timeline rows

The 30-day `forensic_timeline` prune stays for `LIVE_SCAN` rows. Import rows
are exempt (`deleteOlderThan` gains a `telemetrySource = LIVE_SCAN` guard);
today it silently removes an import's evidence after 30 days, which
contradicts "kept until the user deletes it". The 24 h usage window and the
OEM filter in `UsageStatsScanner` are replaced by the watermark (§5.2); the
OEM filter is unchanged in this design — see §10.

## 6. Timeline

- **One query, two sources.** The Timeline is a paged `UNION ALL` of (a)
  `telemetry_record` rows with `eventTime IS NOT NULL`, projected through
  `event-display.yml`, and (b) `forensic_timeline` rows (finding rows,
  correlation signals, detected changes). Event rows are read in place —
  anti-goal 4. Room `room-paging` 2.6.1 (same pinned Room version; adds
  `androidx.paging` 3.x, pinned); the ViewModel exposes
  `Flow<PagingData<TimelineRow>>`. Scan-group and date-group headers come
  from SQL aggregates (`count`, `min`, `max` per `scanId` / per day).
- **Counts are shown.** Every group header and the filter bar show the total
  for the current filter; nothing is hidden without a number.
- **What paging changes in presentation (my calls).** Today
  `mergeTimelineRows` + `rollUpFindings` work in memory over the full list:
  only the latest scan's findings are matched to rows by `ruleId`, duplicate
  findings are rolled up with a `duplicateCount`, and the severity filter runs
  in memory because `forensic_timeline` has no level column. With paging:
  (a) finding rows get a denormalized `level` column on `forensic_timeline`
  so the severity filter is SQL; (b) cross-page roll-up goes — rows are flat,
  and a finding row nests its evidence via `recordId` instead; (c) finding
  rows appear for every scan, while the pinned section above the list shows
  **current findings** per §5.4 (latest state findings + open alerts).
- **Switch renamed.** "Hide informational telemetry" → "Show findings and
  their evidence only". `TimelineRow.TelemetryRow` → `TimelineRow.EventRow`.
- **View telemetry.** A scan group header and a History row gain
  "View telemetry", opening the telemetry browser (§8.1) for that scan. A
  finding row's detail gains "Matched record", opening `recordId`.
- **Intrusion-log DNS findings at time 0.** `DnsEvent.toFieldMap()` has no
  `timestamp`, so DNS-rule findings from imports land at "Unknown". Adding
  `timestamp` to the `dns_monitor` taxonomy service and field map fixes this;
  it is a taxonomy edit and follows the safe-ordering procedure in CLAUDE.md.
  Positive-reference-only rule for the fleet applies.

## 7. Report and export

- `ReportExporter.export(scan)` reads **only** `TelemetryStore` records for
  `scan.id` for every TELEMETRY section, and `ScanRepository.currentFindings()`
  / `findings(scan.id)` for the FINDINGS section. `ScanOrchestrator.last*Telemetry`
  and the `appScanner.collectTelemetry()` fallback are deleted.
  `HistoryViewModel`'s direct `ReportFormatter.formatScanReport` call is
  removed; all report generation goes through `ReportExporter` — one path,
  one provenance rule.
- A scan whose records are retention-expired prints "Telemetry for this scan
  is no longer stored (retention: last N scans)" in each section — never an
  empty section, never another scan's data.
- The DEVICE CHECKS "requires a live scan" line stays; the TELEMETRY sections
  for an import now describe the import. The report's FINDINGS section
  distinguishes state findings from open alerts, and names the scan that
  opened each alert.
- `ExportMode.TELEMETRY_ONLY` renders every stored service in full.
- New share action on a scan: **"Export telemetry (JSONL)"** — the scan's
  records as JSON Lines, gzip-compressed on the way out, via the existing
  `FileProvider` cache path.
- `TimelineExporter` (txt/csv) streams all rows for the current filter.

## 8. UI

### 8.1 Telemetry browser

Reached from History, Timeline scan headers, and finding detail. Screen 1:
the scan's services with record counts and sizes. Screen 2: one service's
records as a paged, searchable list (search over the indexed columns; full
body search is a follow-up); each record expands to its `fields` as
key/value rows in taxonomy order, with the taxonomy `description` as helper
text, and — for snapshot records — a "History" action showing that
package's record across scans with changed fields highlighted
(`TelemetryStore.history`). No editing.

### 8.2 Settings

"Telemetry storage": current size split into snapshots / live events /
imports; "Keep full telemetry for the last N scans" (default 20); "Delete
stored telemetry for old scans now"; per-import delete lives on the History
row as today.

## 9. Testing and gates (regression policy)

Every defect named in §1 ships with a deterministic gate:

- **S1 `TelemetryStoreRoundTripTest`** — for every active service, write
  records, read back, field maps equal; `record(id)` resolves; event bodies
  round-trip through Deflate with the shipped dictionary.
- **S2 `TelemetryStoreDedupTest`** — two scans of the same 400 snapshot
  records add 400 bodies once and 800 reference rows; one changed record adds
  one body. Two imports with 1,000 overlapping events store each event once
  and report "N new, M already stored".
- **S3 `TelemetryStoreFailedSaveTest`** — transaction throws → no records,
  no bodies, watermark unchanged.
- **S4 `TelemetryStoreDeleteTest`** — `deleteScan` removes rows and
  unreferenced bodies, keeps bodies another scan references.
- **W1 `EventWatermarkTest`** — two consecutive scans over a fixture event
  stream: no event stored twice, none missed, watermark advances only on
  successful save.
- **R1 `ReportProvenanceTest`** — two scans with distinct inventories; report
  for scan A contains only A's packages; report for an import contains none of
  the live device's; report for a retention-expired scan prints the retention
  line in every telemetry section. Gate for motivation (2).
- **R2 `SingleReportPathTest`** — source scan: `ReportFormatter.formatScanReport`
  is called from `ReportExporter` only.
- **B1 `BugReportTelemetryPersistedTest`** — every module in the Hilt set
  that returns `telemetry` has store rows with the same record count after
  `analyzeBugReport`. Gate for motivation (3).
- **C1 `NoPersistenceCapsGateTest`** — source scan over `scanner/`, `data/`,
  `reporting/`, `ui/`: no `_PERSIST_CAP`, no `_ROW_LIMIT`, no `take(` on a
  persisted list in the save path, no literal `LIMIT <n>` in any DAO except
  an explicit allow-list (`getLatestTwo`, `getRecentSnapshot` for the DNS
  screen), each with a comment naming this gate. Gate for motivations (4)(5).
- **T1 `TimelineUncappedTest`** — 100,000-event import; the paged union
  yields all rows; headers report 100,000; no `forensic_timeline` row exists
  for an event record (anti-goal 4); import wall-clock asserted under a
  budget on the emulator in the instrumented suite.
- **F1 `ScanFindingMigrationTest`** — Room migration 18→19 on a fixture DB
  with 1,200 findings in one scan (over the old cap) yields 1,200 rows and a
  readable history list; alerts migrate as `OPEN`.
- **F2 `FindingRecordRefTest`** — a finding's `recordId` resolves to the
  record whose fields equal its `matchContext` scalars.
- **L1 `FindingLifecycleTest`** — a state finding leaves current findings
  when the next scan does not trigger it; an alert stays until closed; a
  closed alert is not re-opened by a re-scan; a new matching event opens a
  new alert. Gate for motivation (6).
- **V1 `VocabularyGateTest`** — `main` source, `res/values`, `docs/*.md`
  (excluding `docs/superpowers/specs/` history): no "raw telemetry", no
  "informational telemetry", no class named `TimelineEvent`; every term in §3
  appears in ARCHITECTURE's glossary.
- **P1 `ImportRowsExemptFromPruneTest`** — 31-day-old import rows survive
  `deleteOlderThan`; live rows do not.
- **D1 `DnsFindingTimestampTest`** (with the taxonomy change) — an imported
  DNS finding's timeline row carries the record's time.
- `LogsourceTaxonomyCrossCheckTest` / `DetectionFieldCrossCheckTest` gate the
  taxonomy edits (`dns_monitor.timestamp`, `event_time_field`, Q1 services).

Release battery (standing policy): clean install on F916B + emulators, full
scan twice (watermark), bug-report import, intrusion-log import twice
(overlap dedup), open each in the telemetry browser, close an alert, export
each report and compare telemetry sections to the browser.

## 10. Decisions

**Decided by the maintainer (2026-10-22):**

- Store everything; no caps. Disk cost is acceptable (§1.1).
- Snapshot records stay out of the timeline; the timeline carries event
  records, findings, signals, and detected changes.
- Terminology must be consistent and precise across code, UI, docs, taxonomy.
- The bug-report telemetry loss is a defect, not a design choice.
- Store in SQLite (queryable across scans), not files; dedup telemetry so a
  fact is stored once.
- Alerts (findings on events) stay open until a person closes them — SOC
  pattern. State findings clear by themselves.

- Taxonomy coverage (Q1): collapse `dbinfo_audit`/`platform_compat_audit`
  into the typed services; add the four remaining emitter services to the
  taxonomy with no rules (§4.2).

**Builder-check questions, all resolved:** Q1 (taxonomy, §4.2); Q2
(materialization — events are read in place, §6; imports batch-insert, §5.2);
Q3 (DNS window — watermarks, §5.2); Q4–Q7 folded into §5.2, §6 and §5.5.

**My calls (change freely; marked so you can see them):**

- Stored shape = `toFieldMap()` field map; snapshot bodies plain JSON,
  deduped by content hash; event bodies Deflate with a build-time preset
  dictionary (§5.1).
- Retention default: last 20 live scans in full; imports until deleted (§5.1).
- Findings move to `scan_finding` rows in this design rather than a follow-up,
  because it is the only honest way to delete `FINDINGS_PERSIST_CAP` (§5.4).
- Alert closing is a status + optional note, not a full case model (§5.4).
- Event display text lives in a small `event-display.yml` resource (§5.3).
- Paging via Room `room-paging` + `androidx.paging` (new pinned dependency) (§6).
- Switch label: "Show findings and their evidence only" (§6).
- Snapshot/event decided per record by a declared event-time field (§4.3).
- Import enrichment reads the latest live scan's records, never stores live
  inventory under an import (§5.2).
- Paging drops cross-page roll-up; `level` denormalized onto finding rows;
  finding rows for all scans, pinned section = current findings (§6).
- History list paged, not `LIMIT 50` (§5.5).
- Parser input bounds raised to 2,000,000 per type; the import card names the
  bound when it trips (§5.5).
- Usage-stats OEM filter left as it is; the store makes a later "all apps"
  change a one-line decision.

**Left to the builder:** table/column names beyond those given; the exact
Compose structure of the browser; whether `TelemetryRecord` is a data class
over `JsonObject` or a typed envelope; migration batch sizes; dictionary
construction script and its CI check; how the import card words "N new, M
already stored".

## 11. Follow-ups recorded, not scoped

- Differential **timeline events** from `changedBetween` (uninstall, permission
  added, new accessibility service, cert change) — the query exists in §5.1;
  turning its output into `forensic_timeline` change rows and rules over them
  is the next design.
- Usage-stats all apps (drop the OEM filter), user-selectable.
- Full-body search in the telemetry browser.
- `TelemetryRecord` as the single evaluator input type (today each
  `evaluate*` takes its own list) — would let stored records be *replayed*
  through a newer ruleset, MVT-style re-analysis.
- #137: generate the machine-readable schema from the taxonomy and validate
  store rows against it in CI.
- The live `DnsEvent` table: ~15k rows/day on a heavy phone under a 30-day
  prune is ~450k rows / ~70 MB on its own today. Out of scope here; it needs
  the same once-stored discipline (or to become `dns_monitor` event records
  outright).
- A richer alert case model (assignee, disposition enum, bulk close) if the
  simple status proves insufficient.

## 12. References

- osquery: snapshot vs. differential (event) query semantics.
- MVT (Mobile Verification Toolkit): per-module `*.json` results,
  `timeline.csv` from the timestamped subset, `*_detected.json` for matches.
- Elastic Security detection alerts carry ancestor event IDs
  (`kibana.alert.ancestors`) and an open/acknowledged/closed workflow status.
- SQLite JSON1 (`json_extract`), content-addressed storage, Deflate preset
  dictionaries (`java.util.zip.Deflater.setDictionary`).
- Room `CursorWindow` 2 MB row limit (the origin of the #342 caps).
