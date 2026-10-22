# Telemetry Store, Uncapped Timeline, Finding Lifecycle, and the Telemetry Vocabulary — Design

**Date:** 2026-10-22
**Status:** Design approved in-session (all decisions closed 2026-10-22);
revised after plan-gate round 1 (2026-10-22). Plan gate and implementation are coordinated by a
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
| **Telemetry record** | A typed fact an emitter produced, exactly as produced, before any rule saw it. Source-agnostic; provenance is the `TelemetrySource` of the observation. Every record is one of two time-shapes, decided per record (§4.3). |
| **Snapshot record** | State observed *at scan time*: app inventory, live app-ops grants, receivers, processes, accessibility services, file-artifact checks, device posture, system properties, database-path observations, platform-compat changes, ADB trusted keys, and any record whose service declares no event-time field or whose value for it is absent. |
| **Event record** | Something that happened at a time *T* the record carries: usage transitions, DNS queries, connections, security-log events, tombstones, wakelock acquisitions, package install history, bug-report app-ops accesses, battery-daily package events whose day is known. |
| **Fact** | One distinct telemetry record, stored once however many scans or imports observed it (§5.1). |
| **Observation** | One scan's or import's sighting of a fact, at a position in that scan's emitted list. Provenance and capture time belong to the observation. |
| **Timeline event** | A timestamped row on the forensic timeline. Comes from (a) every event fact, read in place — never copied; (b) every triggered finding; (c) correlation signals; (d) detected changes (first-seen install, first-seen device-admin grant, live DNS IOC match, alert closure). **Snapshot records never become timeline events.** |
| **Finding** | Rule output (`Finding`). References the observation it matched. A finding on a snapshot record is a **state finding**; a finding on an event record, or a correlation finding, is an **alert**. |
| **Provenance** | Where an observation came from: `TelemetrySource` (`LIVE_SCAN`, `BUGREPORT_IMPORT`, `INTRUSION_LOG_IMPORT`). It is not a kind of telemetry. |
| **Watermark** | Per live event service, the position up to which live events have been collected. The next scan collects from it. |

**Retired phrases.** "Raw telemetry" — every telemetry record is raw by
definition; the `raw_fact`/`judgment` grading lives at the field level in the
taxonomy, where it belongs. "Informational telemetry" — the UI switch meant
"timeline events not referenced by a finding" and will say so. The bug-report
`TimelineEvent` class — a source-shaped, untyped row — is retired (§5.3).

Field-level naming keeps the taxonomy's `snake_case`.

## 4. Architecture

```
emitters ─▶ ServiceRecords (field maps, built once) ─┬─▶ SigmaRuleEngine.evaluateRecords ─▶ findings
                                                     │        (same list, same ordinals)        │
                                                     ▼                                          ▼
                     record_body ◀── telemetry_record (fact) ◀── scan_record (observation) ◀── scan_finding
                                            │                                              (STATE | ALERT, alertKey)
                                            ├── event facts ──┐
                                            │                 ▼
                                            │      Timeline = UNION(event facts, forensic_timeline)
                                            ▼
                       Report (streamed) · Telemetry browser · JSONL export · cross-scan history / diff
```

Persistence surfaces:

- **`record_body`, `telemetry_record`, `scan_record`** (new): content, facts,
  observations. §5.1.
- **`scan_finding`** (new): findings as rows with lifecycle, replacing the
  `ScanResult.findings` JSON column. §5.4.
- **`event_watermark`** (new): per live event service. §5.2.
- **`forensic_timeline`** (changed): holds only finding rows, correlation
  signals and detected changes; gains `recordId` (nullable) and `level`. §6.
- **`ScanResult`** (changed): loses `findings`; gains `telemetryState`
  (`NONE` for scans before this feature, `STORED`, `PARTIAL_RETENTION`,
  `FAILED`) so a report can say *why* telemetry is missing.

### 4.1 One list, evaluated and stored

Each emitter's output is projected to field maps **once**, into
`ServiceRecords(service, records)`. The rule engine evaluates exactly that
list (`SigmaRuleEngine.evaluateRecords(service, records)`; the typed
`evaluate*` methods delegate to it), and the store persists exactly that
list. A finding carries the ordinal of its record in that list; any
engine-side pre-filter (today: `file_scanner` skips inaccessible paths)
iterates with the original index, so ordinals always address the stored
list. This makes anti-goal 3 true by construction and is the input shape a
later "replay stored records through a newer ruleset" needs.

Records are stored as their `toFieldMap()` projection — the map in taxonomy
`snake_case` that `SigmaRuleEvaluator` actually evaluates:

- It is exactly what the rules saw.
- The taxonomy documents every field; the store inherits that schema and
  advances #137.
- Apart from `DnsEvent`, the telemetry data classes are not `@Serializable`;
  the field map is already the compatibility boundary.

**Field-map completeness.** A field map must carry every fact its data class
holds, or the stored record is lossy. Two gaps exist today and are closed as
positive-only fields: `FileArtifactTelemetry.accessible` → `accessible`;
`ImportedDnsEvent.resolvedIps` → `resolved_ips` on `dns_monitor`. A gate
compares each telemetry class's constructor properties with its field-map
keys, with an explicit, commented allow-list for intentional omissions.

**Envelope keys.** `captured_at` and `source` are observation properties,
not content. They are removed from the map before hashing and stored on the
observation; decode restores them. Content hashing therefore identifies the
same fact across imports.

Services covered: every emitter output — each typed `evaluate*`, the generic
`evaluateGeneric` bug-report path, `usage_stats`, `system_property`. The
taxonomy's `timeline` service (atom binding) is not a record stream.

### 4.2 Taxonomy (Phase 0, before anything is stored)

Decided (maintainer, 2026-10-22): the two duplicates collapse into the typed
services; `adb_audit`, `activity_audit`, `usage_stats`, `system_property`
are documented as emitter services with no rules.

The rules-repo change adds, per service:

- `status: emitter_only` for services with no evaluate path (`usage_stats`,
  `system_property`). `validate-rule.py` rejects a rule on an `emitter_only`
  service outside `staging/`; `ServiceActivationCrossCheckTest` accepts the
  status. A rule that could never fire on the fleet cannot validate.
- `event_time_field: <field>` for every service whose records can be events.
- `key_fields: [..]` — the fields that identify a snapshot's subject
  (`app_scanner: [package_name]`, `receiver_audit: [package_name,
  intent_action]`, `appops_audit: [package_name, operation]`,
  `device_auditor: [check_id]`, `file_scanner: [file_path]`, …) — used for
  per-subject history and scan-to-scan comparison.
- `optional: true` on fields only some producers set (`appops_audit.event_time_ms`,
  set by bug-report records only). The cross-check allows a member field map
  to omit optional fields.
- `positive_only: true` on fields old fleet binaries do not emit
  (`dns_monitor.timestamp`, `dns_monitor.resolved_ips`,
  `file_scanner.accessible`, `appops_audit.event_time_ms`, and the existing
  `requested_permissions` / `has_boot_receiver`). `validate-rule.py`'s
  negation guard is generalised from the hard-coded `requested_permissions`
  to every `positive_only` field.
- Field entries for the facts the typed bug-report records gain (§5.3).

This change follows CLAUDE.md safe ordering and lands before the store, so
every stored service has a schema from the first record written.

### 4.3 Snapshot or event, per record; categories as a contract

A record is an **event record iff its service declares an
`event_time_field` and the record's value for it is present and > 0**.
`EventTimeFields` (Kotlin, `sigma/`) is generated from that declaration and
cross-checked against the taxonomy; it is the single source for storage
treatment (§5.1), timeline membership (§6) and finding kind (§5.4). There is
no second list anywhere.

**Timeline categories are a detection contract**, because atom rules bind on
them. `TimelineCategories` (Kotlin, `sigma/`) maps each event service to the
category its timeline events carry, preserving today's values exactly:
`usage_stats` → the record's `event_type` (`app_foreground` /
`app_background`); `appops_audit` → `permission_use`;
`package_install_history` → `package_install`; `battery_daily` → the
record's `event_type` (`package_uninstall` / `package_update` /
`package_downgrade`); `network_monitor` → `network_connect`; `security_log`
→ `security_event`; `dns_monitor` → today's imported-DNS category
(`TimelineAdapter`). A gate fails if any category a bundled atom rule binds
has no producer. Display text (one summary line per event) lives in
`event_display.yml` and carries no semantics.

## 5. Persistence

### 5.1 Content, facts, observations

Room entities (schema 19, Phase A).

**`record_body`** — distinct content:

| column | type | meaning |
|---|---|---|
| `hash` | String PK | SHA-256 of the canonical JSON of the field map minus envelope keys |
| `encoding` | Int | 0 plain JSON; 1 Deflate with preset dictionary |
| `dictVersion` | Int | which shipped dictionary (0 for plain) |
| `body` | BLOB | |
| `rawBytes` | Int | uncompressed size; bounds inflation on decode |

**`telemetry_record`** — one row per fact:

| column | type | meaning |
|---|---|---|
| `id` | Long PK auto | the fact id findings and timeline rows reference |
| `service` | String | |
| `factKey` | String | unique with `service` (below) |
| `subjectKey` | String? | from the service's `key_fields`; indexed with `service` |
| `eventTime` | Long? | indexed; null for snapshots |
| `category` | String? | event facts only, from `TimelineCategories` |
| `packageName` | String? | indexed |
| `bodyHash` | String → `record_body` | indexed |

**`scan_record`** — one row per observation:

| column | type | meaning |
|---|---|---|
| `scanId` | Long | `ScanResult.id` |
| `service` | String | |
| `ordinal` | Int | position in the emitted list; PK (`scanId`, `service`, `ordinal`) |
| `recordId` | Long → `telemetry_record` | indexed |
| `source` | `TelemetrySource` | provenance of this observation |
| `capturedAt` | Long | |

**Fact identity (`factKey`).**
- An event whose source supplies an identity carries it in the envelope, not
  the field map: intrusion-log records carry the parser's existing key
  `(type, event_id, event_time)`. Never bare `event_id` — the parser
  documents it can restart daily.
- Every other record: `bodyHash#n`, where `n` is the occurrence index of
  that content within the emitted list. Identical-content events in one
  batch (A and AAAA lookups in the same millisecond) are distinct facts;
  the same content observed again later (an overlapping export, an
  unchanged app on the next scan) is the same fact.

**Write.** Bodies first (`INSERT OR IGNORE`), then facts (`INSERT OR
IGNORE`; on `-1`, look the id up by `(service, factKey)`), then observations.
`persist` returns the ordinal → fact-id map for the batch. Records are
written in chunks of 5,000 from a `Sequence`; no full list of field maps is
ever built.

**Reads** are per scan through `scan_record`, so a scan's report, browser,
export and timeline filter see every record that scan observed, including
facts first stored by another scan (G1, G3). Keyset paging on
`(scanId, service, ordinal)` or fact id; no OFFSET.

**Delete.** A scan's observations are deleted; then facts with no remaining
observation; then bodies with no remaining fact — batched, all indexed.
Deleting import A never removes a fact import B also observed.

**Compression.** Event bodies are Deflate-compressed with a preset
dictionary; snapshot bodies stay plain JSON, so later features can query
them with SQLite JSON1. Dictionaries are per service family, ≤ 4 KiB each
(a 32 KiB dictionary costs 32 KiB of hashing per record), built from the
taxonomy's field names and fixed vocabularies, shipped in `res/raw/`, and
**immutable once shipped**: each is pinned by SHA-256 in a test, a changed
builder output requires a new `dictVersion`, and decoding selects the
dictionary by `dictVersion`. One `Deflater`/`Inflater` per batch, `reset()`
between records, `end()` after. A body that fails to inflate, or would
inflate past `rawBytes`, decodes to a placeholder record marked unreadable —
never an exception out of paging or the report.

**Cross-scan reads.** `history(service, subjectKey)` — every observation of
one subject, newest first. `changedBetween(scanA, scanB, service)` — subjects
whose fact changed, appeared or disappeared, keyed on `subjectKey`.

**Retention** (my call):
- Snapshot observations: kept for the most recent N live scans (default 20,
  Settings). Older live scans' snapshot observations are deleted; their
  `ScanResult.telemetryState` becomes `PARTIAL_RETENTION`.
- Event observations from live scans: kept 30 days, the same as the
  timeline today.
- Import observations: kept until the user deletes the import.
- Any fact referenced by an OPEN alert is kept regardless.
- Retention runs from Phase A (logic) in `IocUpdateWorker`; Settings UI in
  Phase E.

### 5.2 Writers, watermarks, failure handling

**Writers.** `runFullScan`, `analyzeBugReport` and `analyzeIntrusionLog`
build `ServiceRecords` once, evaluate, and hand the same records to the
store in the save transaction. Order inside the transaction: observations
and facts → correlation atoms queried → correlator → scan row →
`scan_finding` rows → watermarks.

**Live enrichment.** The `last*Telemetry` fields are deleted. Bug-report
APK-hash and display-name enrichment reads the latest live scan's
`app_scanner` observations (within `APP_TELEMETRY_CACHE_MAX_AGE_MS`) or
collects fresh and discards. Live inventory used for enrichment is never
stored under an import.

**Replace-on-reimport is removed.** `deletePriorIntrusionLogRows` contradicts
"imports kept until the user deletes them" and would delete other imports'
evidence. A re-imported or overlapping export creates its own observations
of the facts it shares; the import card reports "N new facts, M already
stored".

**Watermarks** (`event_watermark(service, position, scanId)`):
- `dns_monitor` (live): position = the monotonic `DnsEvent.id`. Late-flushed
  rows and clock jumps cannot skip events.
- `usage_stats`: position = event time. Each scan re-reads from
  `position − 5 min`; the overlap is absorbed by fact identity. Usage access
  is checked explicitly (`queryEvents` returns empty, not an exception,
  without it); no access = collection failed.
- First scan: 24 h floor.
- The watermark advances only when the save commits, the collection did not
  fail, and no rule on that service was capability-skipped this scan (a
  skipped rule would otherwise consume events it never evaluated). It never
  moves past the scan's start time and resets if it is ahead of `now`.
- Scans are serialised by a `scanMutex`.

**Storage protection (replaces the caps; nothing is truncated silently).**
- Before an import, a free-space preflight (`StatFs`) against an estimate of
  its stored size; if it would leave less than a safety margin
  (500 MB or 10 % of the volume, whichever is larger), the import is refused
  with a message naming the estimate and the free space.
- Parser input bounds stay as input validation, raised to 2,000,000 records
  per type, with the import card naming the bound when it trips. Peak memory
  is bounded by the 5,000-record chunk, not by the import.
- `PRAGMA journal_size_limit` set so the WAL is truncated after a large
  import.
- Persistence catches `Throwable` (including `OutOfMemoryError`) and
  surfaces `IntrusionLogPersistException`.
- If a live scan's telemetry write fails (e.g. `SQLITE_FULL`), the save is
  retried without telemetry: findings are kept, `telemetryState = FAILED`,
  and the report says so.

### 5.3 Typed bug-report records; `TimelineEvent` retired

Four modules build untyped rows today and must emit typed records that fill
the `TelemetryBundle` before anything that depended on their rows is
removed:

- `InstallTimeModule` → `PackageInstallHistoryEntry` (event; category
  `package_install`).
- `DbInfoModule` → `DatabasePathObservation`, extended with `db_path` and
  `recent_query_count` (taxonomy fields added).
- `PlatformCompatModule` → `PlatformCompatChange`.
- `BatteryDailyModule` → `BatteryDailyEvent` with `timestamp` at day
  precision when the section yields the day's date; otherwise the record is
  a snapshot.

`AdbKeysModule` records are snapshots (a trusted key has no time) and leave
the timeline; they appear in the browser and report. `AppOpsModule` records
already carry `event_time_ms`. The hand-built `TimelineEvent` rows,
`ModuleResult.timeline`, `BugReportAnalysisResult.timeline`,
`TimelineFormatter` and `TimelineEvent.kt` are then removed. A finding row
points at its observation; the UI nests evidence under the finding instead
of the `(packageName, timestamp)` dedup that hid one of them.

### 5.4 `scan_finding` — findings as rows with a lifecycle

Schema 20 (Phase C). Columns: `id`, `scanId`, `ruleId`, `triggered`,
`level`, `category`, `kind` (`STATE` | `ALERT`), `status` (`OPEN` |
`CLOSED`), `closedAt`, `closedReason`, `recordId` (fact), `service`,
`ordinal`, `alertKey` (ALERT only, unique), `findingJson`.

**Kind** = `ALERT` iff the matched record is an event record (§4.3) or the
finding is a correlation finding; otherwise `STATE`.

**Alert identity.** `alertKey` = `ruleId:factId` for record findings;
`ruleId:` + sorted member refs for correlation findings. Unique: a re-fire —
overlapping import, correlation lookback, re-read overlap — inserts nothing,
and a closed alert stays closed. A *new* event matching the same rule is a
new fact and opens a new alert.

**Lifecycle (maintainer decision, SOC pattern).**
- State findings are current while the **latest live scan** triggers them
  (imports never displace live state — the dashboard keeps today's
  `preferRuntimeScan` semantics).
- Alerts are current from the scan that opened them until a person closes
  them.
- "Current findings" (dashboard, apps/device screens, report) = latest live
  scan's triggered state findings ∪ every OPEN alert.
- **Closing is protected.** Close requires device-credential confirmation
  (`androidx.biometric`, `DEVICE_CREDENTIAL` allowed), the control sets
  `filterTouchesWhenObscured`, each closure is written as a timeline row,
  and the report lists closed alerts with time and note. Malware driving the
  UI through Accessibility cannot silently dismiss evidence.

**Migration 19 → 20.** Each `ScanResult.findings` value is read by length
and `substr` chunks (a row over the 2 MB cursor window must not abort the
migration); corrupt JSON yields zero findings with the scan row kept. Kind
comes from a frozen `ruleId → service` table generated from the bundled
rules at schema 20. Migrated alerts are OPEN only for the latest live scan;
older ones migrate CLOSED with reason "migrated". `forensic_timeline.level`
is backfilled from the migrated findings.

`Finding` gains `service` and `ordinal` at evaluation; `recordId` is
resolved from the ordinal map at save. `matchContext` stays as the display
copy.

### 5.5 Caps removed

Deleted: `FINDINGS_PERSIST_CAP`, `DNS_PERSIST_CAP`, `CONNECT_PERSIST_CAP`,
`SECURITY_PERSIST_CAP`, `capTriggeredFindings`, the caps log,
`getAllForExport`'s `LIMIT 10000`, the report's `take(500)`,
`HistoryViewModel.INTRUSION_ROW_LIMIT`, `getAllScans`'s `LIMIT 50` (History
pages), the timeline DAO's `limit = 500` defaults, and `getRecentSnapshot()`
as the scan's DNS window. Allow-listed with a comment naming the gate:
`ScanResultDao.getLatestTwo` (semantic two), `IndicatorDao.lookup`
(`LIMIT 1`, existence), `DnsEventDao.getRecentEvents` /
`getRecentSnapshot` (the live DNS monitor screen's display window).

### 5.6 Timeline rows

`forensic_timeline` keeps finding rows, correlation signals and detected
changes. The 30-day prune applies to `LIVE_SCAN` rows only; import rows are
kept with their import.

## 6. Timeline

- **One paged query.** `UNION ALL` of event facts (with the scan filter
  applied through `scan_record`) and `forensic_timeline` rows, ordered
  `(time DESC, rowKind, id DESC)`. One `@RawQuery` per filter shape so each
  branch uses its index; no "`:x IS NULL OR`" predicates. A fact referenced
  by a `forensic_timeline` row (`recordId`) is rendered nested under that
  row — finding evidence, live DNS IOC matches — not as a second row.
- Lives in a dedicated `TimelineDao`; `ForensicTimelineEventDao` keeps
  writes.
- **Counts are shown** on every group header and the filter bar. Date groups
  use the device's local day.
- **Presentation (my calls):** severity filter is SQL over `level`;
  cross-page roll-up goes, a finding nests its evidence; finding rows for
  every scan; the pinned section shows current findings (§5.4).
- **Switch renamed** to "Show findings and their evidence only";
  `TimelineRow.TelemetryRow` → `TimelineRow.EventRow`.
- **Correlation** binds atoms from both tables. `computeAtomBindings` and the
  correlator key atoms by `AtomRef` (`Row(id)` | `Fact(id)`); signal details
  carry `member_fact_ids` beside `member_event_ids`, and every consumer of
  the latter reads both (gate).
- **View telemetry** from History, scan headers, and finding detail.
- **Imported DNS findings at time 0** fixed by `dns_monitor.timestamp`
  (Phase 0).

## 7. Report and export

- One path: `ReportExporter`, streaming to a file `Writer`. The History
  sheet shows a summary (findings, per-service record counts, telemetry
  state) and opens the full report as a file. No report is held as one
  `String`.
- TELEMETRY sections read only the scan's observations. Missing telemetry
  says why: `NONE` → "Telemetry was not stored for scans before version X";
  `PARTIAL_RETENTION` → "Snapshot telemetry for this scan is no longer
  stored (retention: last N scans)"; `FAILED` → "Telemetry could not be
  stored for this scan".
- Device-controlled strings are escaped by the generic renderer (control and
  non-printable characters rendered visibly, line breaks never emitted from
  a value).
- Full telemetry stays in `BOTH` and `TELEMETRY_ONLY` (owner intent); the
  export dialog states the record count and size before sharing.
- FINDINGS section: state findings, open alerts (with the scan that opened
  them), closed alerts (time and note).
- "Export telemetry (JSONL)" streams through `GZIPOutputStream`; stale files
  in `cache/reports/` are removed on each export. `TimelineExporter` streams
  and keeps its CSV formula guard.

## 8. UI

### 8.1 Telemetry browser

From History, timeline scan headers and finding detail: services with
counts and sizes → one service's records (paged, debounced search over
indexed columns) → a record's fields in taxonomy order with descriptions,
and for snapshot records a History view of the subject across scans with
changed fields highlighted. Unreadable bodies show as such.

### 8.2 Settings

Telemetry storage size (distinct bodies, split snapshots / live events /
imports), "Keep snapshot telemetry for the last N scans" (default 20),
"Delete old snapshot telemetry now".

## 9. Testing and gates (regression policy)

All gates are JVM unit tests (Robolectric 4.14.1 pinned to SDK 35 for Room).

- **S1** round-trip per service (compare canonical forms; Int/Long and
  tagged encodings preserved).
- **S2** facts stored once: real typed records with different `capturedAt`
  across two imports share facts; identical-content events in one batch stay
  distinct; unchanged snapshots share facts across scans.
- **S3** failed save writes nothing (bodies, facts, observations, watermark).
- **S4** deleting import A keeps facts import B observed.
- **S5** dictionary immutability: shipped dictionaries match pinned hashes;
  a v1 fixture body decodes.
- **S6** a corrupt body decodes to an unreadable placeholder.
- **E1** stored list equals evaluated list for every evaluate entry point;
  `file_scanner` ordinal with an inaccessible record ahead.
- **E2** field-map completeness against constructor properties.
- **W1** watermarks: no event twice or missed across consecutive scans;
  no advance on failed collection, missing usage access, or capability-skipped
  rule; late-flushed DNS row collected; clock-ahead reset.
- **R1** report provenance per scan, import, retention-trimmed, pre-feature
  and failed-telemetry scans.
- **R2** single report path; no `last*Telemetry`.
- **R3** a wakelock tag containing `\n== FINDINGS ==` renders escaped.
- **B1** real `BugReportAnalyzer` on a fixture bug report: every module with
  telemetry produces store observations, the four converted modules produce
  typed records.
- **C1** no persistence caps (regex includes `limit: Int = <n>` defaults;
  allow-list per §5.5).
- **T1** 100,000-event import: all rows page; counts match; no
  `forensic_timeline` row duplicates an event fact; no `TEMP B-TREE` in any
  filter shape's query plan.
- **K1** every category a bundled atom binds has a producer.
- **F1** migration 19→20: 1,200 findings, a corrupt row, a 3 MB row; kinds
  from the frozen table; only latest live alerts OPEN; `level` backfilled.
- **F2** a finding's `recordId` resolves to the record it matched, for every
  service.
- **L1** lifecycle: state findings follow the latest live scan, not imports;
  alerts persist until closed; re-fire and overlapping import create no
  duplicate; closed stays closed; a new event opens a new alert.
- **L2** closing requires the credential confirmation and writes a timeline
  row.
- **V1** vocabulary gate.
- **P1** import timeline rows survive the 30-day prune.
- **D1** imported DNS finding carries the record's time.
- **Q1** DAO SQL uses no feature newer than API 26's SQLite (UPSERT,
  `RETURNING`, window functions, `NULLS LAST`).
- **M1** storage preflight refuses an import that would breach the margin;
  telemetry write failure keeps the live scan's findings.
- `LogsourceTaxonomyCrossCheckTest`, `DetectionFieldCrossCheckTest`,
  `ServiceActivationCrossCheckTest` gate Phase 0.

Release battery (standing policy): clean installs on the F916B and
emulators including API 26 and a low-RAM image; scan twice; bug-report
import; intrusion-log import twice (overlap); maximal intrusion-log fixture
on the low-RAM image; browse; close an alert (credential prompt); export
and compare report telemetry to the browser; note that a Play-track
downgrade across schemas 19/20 wipes data.

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

**Plan-gate round 1 resolutions (my calls; see
`docs/superpowers/plans/2026-10-22-telemetry-store-plan-gate-round1-findings.md`):**

- Fact / observation split with envelope identity (§5.1).
- Immutable versioned per-service dictionaries (§5.1).
- One evaluated-and-stored list (§4.1); field-map completeness (§4.1).
- Kind per record; alert identity; watermarks before the lifecycle (§5.2, §5.4).
- Typed records for four bug-report modules before their rows go (§5.3).
- Categories as a Kotlin contract (§4.3).
- Storage protection: preflight, chunking, `journal_size_limit`,
  failed-telemetry fallback (§5.2).
- Closing alerts requires device credential (§5.4).
- Report streaming, escaping, telemetry-state messages; full telemetry kept
  in the report per owner intent, with size shown before sharing (§7).
- Taxonomy `emitter_only`, `key_fields`, `optional`, `positive_only` (§4.2).
- Replace-on-reimport removed (§5.2).
- Retention: snapshots by scan count, live events by age, imports kept, open
  alerts pinned (§5.1).

**Earlier calls kept:** stored shape = field map; findings move to rows;
summary text in `event_display.yml`; paging via `room-paging` +
`androidx.paging`; switch label; history paged.

**Left to the builder:** Compose structure of the browser; migration batch
sizes; dictionary-build script and its CI wiring; import-card wording.

## 11. Follow-ups recorded, not scoped

- Differential timeline events from `changedBetween` (uninstall, permission
  added, cert change) and rules over them.
- Retroactive matching of stored `dns_monitor` facts when the IOC set
  changes.
- Replay of stored records through a newer ruleset (`evaluateRecords` is the
  entry point).
- Full-body search; JSON1 queries over snapshot bodies.
- #137 machine-readable schema generated from the taxonomy.
- The live `DnsEvent` table (~70 MB at 30 days on a heavy phone) becoming
  `dns_monitor` facts outright.
- Usage-stats all apps, user-selectable.
- A richer alert case model.

## 12. References

- osquery: snapshot vs. differential (event) query semantics.
- MVT: per-module results, `timeline.csv`, `*_detected.json`.
- Elastic Security alerts: ancestor event IDs and open/closed workflow status.
- SQLite JSON1; content-addressed storage; Deflate preset dictionaries
  (zlib checks the dictionary's Adler-32 — hence immutability).
- Room `CursorWindow` 2 MB row limit (the origin of the #342 caps).
