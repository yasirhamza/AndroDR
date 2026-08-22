# Intrusion Log Import — Design

**Date:** 2026-08-22
**Status:** Design approved in-session; spec pending maintainer review
**Depends on:** nothing shipped; touches `network_monitor` taxonomy status and adds a `security_log` service
**Related:** `docs/plans/2026-08-22-cellular-telemetry-tier1-spec.md` §11 (where this
feature was first recorded as a finding and explicitly not scoped)

## 1. Background and motivation

Android 16's **Advanced Protection → Intrusion Logging** (user-enabled in
Settings) records three streams of device activity: DNS resolutions, outbound
connections, and security events (unlocks, ADB shell activity, file transfers,
app installs, process launches). The logs are end-to-end encrypted and
cloud-backed; **there is no public API for an app to read them**. They are
reachable only via a user-initiated Settings download ("Access logs") or
AndroidQF, and are parsed offline by MVT's `check-intrusion-logs` module.
Amnesty International's Security Lab documented the format
(<https://docs.mvt.re/en/latest/android/intrusion_logs/>).

Consequences that shape this design:

- **Import, not monitor.** AndroDR cannot subscribe to this stream. The feature
  is an offline analysis path for a user-provided export, structurally parallel
  to the existing bug-report import.
- **It closes a real visibility gap.** The maintainer's device performs
  DNS-over-TLS (port 853), which AndroDR's VPN-based DNS monitor cannot
  observe — yet `dns_event` records the resolved hostname regardless. Imported
  logs give the existing `dns_monitor` rules hostnames the live path can never
  see.
- **It rescues a stranded taxonomy slot.** `connect_event` maps almost
  field-for-field onto `NetworkTelemetry` (`data/model/NetworkTelemetry.kt`),
  whose `network_monitor` logsource service has been `status: unwired` since
  its introduction: `toFieldMap()` exists but `SigmaRuleEngine` has no
  evaluate method, so `network_monitor` rules cannot fire.

### This is not the parked IP-filtering decision (D3)

`docs/ARCHITECTURE.md` §11 D3 parked *live VPN-based IP inspection* on battery
cost, privacy (TLS SNI would require local MITM), and false-positive-breakage
grounds. This feature is *offline import of logs the platform has already
written*: zero battery cost, no packet interception, no allow/deny decisions.
It is a different proposal that happens to touch the same data plane, approved
on its own merits (this document). The same distinction is recorded in the
cellular Tier 1 spec §11.

## 2. Goals and non-goals

**Goals**

1. Parse a user-provided Intrusion Logging export (all three event types) into
   typed telemetry, evaluated by YAML rules with no hardcoded detection logic.
2. Wire the `network_monitor` logsource end-to-end (evaluator + live caller +
   taxonomy + tests) as one indivisible change.
3. Introduce a `security_log` logsource service for security events.
4. Persist events into the forensic timeline with honest provenance and
   bounded volume; surface them in the timeline UI and the text report.

**Non-goals**

- Live capture of intrusion logs (no API exists).
- Any change to the VPN/DNS monitor's capture scope (D3 stands).
- An IP-based IOC feed. Current IOC feeds are domain/package/hash; adding IP
  indicators is a separate proposal.
- Porting MVT code. MVT (Python, MPL-2.0) is the *schema and tag-registry
  reference*; all parsing is re-expressed in Kotlin. (The standing MVT
  mirror-feed dedup concern applies to IOC feeds, which this parser does not
  touch.)
- Cellular telemetry of any kind (owned by the cellular Tier 1 work).
- An `AdvancedProtectionManager` posture check (deferred to its own issue by
  maintainer decision; see cellular spec §11).

## 3. Artifact and record format

**Artifact:** a ZIP containing one file per day named `YYYY-MM-DD.txt`
(observed: `2026-08-22.txt` from a Samsung device on Android 17; multi-day
exports are expected to contain more files). AndroidQF places the same files
under an `intrusion-logs/` directory. The sniffer therefore accepts per-day
`.txt` entries at the top level or one directory deep.

**Records:** newline-delimited JSON, one event per line, each wrapped in a
top-level type key:

```json
{"dns_event":{"event_id":0,"event_time":1787400345334,"package_name":"…","hostname":"…","ip_addresses":["/34.160.125.113"],"ip_addresses_count":1}}
{"connect_event":{"event_id":1,"event_time":1787400345540,"package_name":"…","port":443,"ip_address":"/34.160.125.113"}}
{"security_event":{"event_id":…,"event_time":…,"tag":210002,"data":[…]}}
```

Format facts (verified against a real 21-event sample and the MVT docs):

- `event_id` is a monotonic counter **shared across all event types**
  (interleaved). Byte-identical duplicate records occur (observed: two
  identical `connect_event`s with the same timestamp). **Dedup on `event_id`,
  first-seen across files** — deduping on field tuples would collapse
  legitimate repeat connects.
- `event_time` is epoch milliseconds (UTC).
- IP literals carry a leading `/` (Java `InetAddress.toString()` with an empty
  hostname). Strip on parse.
- `connect_event` has **no protocol field** — genuinely absent from the
  source, not merely unmapped. The design does not invent one.
- `dns_event` carries `ip_addresses` (array) + `ip_addresses_count`;
  `connect_event` carries a single `ip_address` + `port`.
- `security_event` is `{event_time, tag, data[]}` where `tag` is a numeric
  `android.app.admin.SecurityLog` tag and `data` is a tag-specific value
  array. MVT's SecurityEvent module is the parsing reference.
- Connects with no preceding `dns_event` are normal (cached resolutions,
  hardcoded IPs, DNS predating the capture window). **The dns→connect join is
  not reliable** and no component may depend on it.
- The Android 16+ requirement binds the **source** device only. Analyzing an
  imported file has no minSdk implication for AndroDR.

## 4. Architecture

### 4.1 Routing (artifact sniffer)

The existing bug-report import screen and file picker are the single entry
point. On accepting a ZIP, a sniffer inspects entry names:

- an entry whose name starts with `dumpstate` → existing `BugReportAnalyzer`,
  unchanged;
- entries matching `YYYY-MM-DD.txt` (top level or one directory deep,
  including `intrusion-logs/`) → new `IntrusionLogAnalyzer`;
- neither → a clear "not a recognized artifact" error.

This is one `when` in one place — deliberately not an artifact-registry
framework. If a third artifact type ever arrives, this routing point is the
registry seed.

### 4.2 `IntrusionLogAnalyzer` (`scanner/intrusionlog/`)

Mirrors `BugReportAnalyzer`'s coordinator shape:

1. Streams each matching entry **line by line** (a 12-month export can be
   large; whole-file loads are forbidden).
2. Routes each line by wrapper key to one of three per-type parsers.
3. Dedups on `event_id`, first-seen across files.
4. Counts malformed lines and skips them (fail-soft per line); the count is
   surfaced in results, never swallowed.
5. Evaluates rules over the **complete parsed stream** (§6), then persists
   (§7).

Parsers are **pure emitters**: no `Finding` construction, no severity-shaped
fields — `PureEmitterContractTest` gates them like every other emitter. All
facts are emitted verbatim (unknown security-event tags included); curation
belongs in rules.

**Re-import semantics:** each import first calls
`ForensicTimelineEventDao.deleteBySource("intrusion_log")` — an import
represents the latest export; replace, never accumulate. The raw ZIP is never
retained (same privacy model as bug reports).

## 5. Event model

### 5.1 `connect_event` → `NetworkTelemetry` (existing model, first live use)

| Export field   | `NetworkTelemetry` field | Note                                   |
|----------------|--------------------------|----------------------------------------|
| `ip_address`   | `destinationIp`          | leading `/` stripped                   |
| `port`         | `destinationPort`        |                                        |
| `package_name` | `appName`                | hint, not identity (shared-UID smear)  |
| `event_time`   | `timestamp`              | epoch ms                               |
| —              | `appUid`                 | resolved via PackageManager at import time if the package is still installed; `-1` otherwise |
| —              | `protocol`               | absent in source; stays null           |

### 5.2 `dns_event` → transient `DnsEvent` value objects

Imported DNS events are shaped as `DnsEvent` value objects — `domain` =
hostname, `appName` = `package_name` (surfacing as `source_package` in the
rule field map), `appUid` resolved as in §5.1, `isBlocked = false`,
`reason = null` — and fed to the existing `evaluateDns()` path. They are **not** inserted into the live
`DnsEvent` Room table — the live table remains the VPN monitor's alone.

Payoff: every existing `dns_monitor` rule (domain-IOC, DDNS-C2, Graphite)
fires on imported events — including DoT-resolved hostnames the VPN cannot
see — with **zero rule changes**.

The `ip_addresses` array is carried into timeline detail but **not** added to
the `dns_monitor` rule field map: a field addition triggers the schema/taxonomy
cross-check ceremony and is deferred until a rule actually needs it (§11).

### 5.3 `security_event` → `SecurityLogEvent` (new model) + tag registry

`SecurityLogEvent(timestamp, tag, data: List<String>)` plus a
`SecurityLogTagRegistry` that maps numeric `SecurityLog` tags to names and
extracts per-tag fields for a curated high-value subset (ADB shell
interactive/command, app process start, package install/uninstall/update,
keyguard events, certificate-authority install — exact list built from
Android's `SecurityLog` constants, cross-checked against MVT's parser).
Unknown tags are emitted verbatim as `tag` + `raw_data`; the registry never
drops an event.

## 6. Rule engine and taxonomy

### 6.1 `network_monitor`: unwired → active, as one indivisible change

One PR pair (a rules-repo PR for the taxonomy edit, one AndroDR PR for
everything else plus the submodule bump) delivers, together:

- `SigmaRuleEngine.evaluateNetwork()` (mirroring `evaluateDns`),
- its **live caller** in the import flow,
- the taxonomy flip `network_monitor: status: unwired → active` in
  `validation/logsource-taxonomy.yml`,
- the `LogsourceTaxonomyCrossCheckTest` / `DetectionFieldCrossCheckTest`
  updates.

The taxonomy cross-check asserts bidirectionally with an exact service count,
so any partial landing fails the build — that is the point. An evaluator
without a caller would recreate exactly the dead-rule failure the `unwired`
status warns about.

### 6.2 `security_log`: new taxonomy service

New service `security_log` (model `SecurityLogEvent`, `status: active` from
birth — it ships with its caller). Requires the standard two-repo ceremony:
rules-repo schema PR first (`rule-schema.json` logsource enum +
`logsource-taxonomy.yml` entry), then one AndroDR PR bumping the submodule and
landing the Kotlin change, per CLAUDE.md. Both taxonomy edits follow the safe
ordering (rules-repo branch → AndroDR submodule-bump PR → CI green → merge
rules main → re-point submodule), because the taxonomy is the trust root of
`validate-rule.py`'s field lint.

### 6.3 Evaluation and starter rules

Evaluation runs at import time, exactly like bug-report analysis: any bundled
or remote rule whose `logsource.service` matches fires with no special-casing.

- `dns_monitor`: **zero new rules** — existing rules fire (§5.2).
- `network_monitor` and `security_log`: this spec fixes only *candidate*
  starter rules — conservative, high-signal (e.g. `security_log`: ADB shell
  command observed, non-market package install; `network_monitor`: connect to
  ADB-over-TCP port 5555). Final YAML goes through the normal update-rules
  pipeline with per-candidate human review, then bundled + byte-equal mirrored
  + `rules.txt` + `rules.sha256` regenerated, per the mirror-parity and
  manifest-integrity gates. These services are not `device_posture`, so its
  severity cap does not apply; severities stay conservative regardless.

## 7. Persistence, retention, volume

Events persist as `ForensicTimelineEvent` rows:

- `telemetrySource = TelemetrySource.INTRUSION_LOG_IMPORT` (new enum value;
  stored as a name string — no schema migration),
- `source = "intrusion_log"`, `category` per type,
- `startTimestamp` = the event's own time (timeline orders by when things
  happened),
- correlation IDs joining across sources: `dns:$domain` — deliberately
  identical to the live VPN convention, so an imported DoT resolution and a
  live plaintext query for the same domain correlate — plus `net:$ip:$port`
  and `sec:$tag`.

**Retention:** the existing 30-day prune keys on `createdAt`
(`ForensicTimelineEventDao.deleteOlderThan`), i.e. insertion time — imported
historical events live 30 days from *import*, not from event time. No change
needed. Combined with `deleteBySource` on re-import, imports never accumulate.

**Volume:** connect events dominate. Rules always evaluate the **complete
parsed stream** — detection never sees a truncated picture. Timeline
persistence applies generous per-type caps, newest-first: security events
uncapped, DNS capped at 10,000, connects at 5,000 (constants, tuneable). When
a cap bites, the results screen states "persisted N of M" — no silent
truncation. Inserts go through the existing `insertAll` batching; the table's
`startTimestamp`/`packageName`/`telemetrySource` indices cover the queries.

## 8. UI and report surfaces

- **Import:** existing bug-report import screen and picker; the sniffer
  routes. No second import button.
- **Results:** per-artifact-type body — for intrusion logs: date range
  covered, per-type event counts, duplicates collapsed, malformed lines
  skipped, cap notices, top talkers by package; findings via the standard
  finding UI.
- **Timeline:** `INTRUSION_LOG_IMPORT` becomes one more `telemetrySource`
  filter chip; `TimelineExporter` and the STIX2 path pick the rows up from
  `forensic_timeline` with no changes.
- **Text report:** new `INTRUSION LOG` block in the TELEMETRY SECTION
  (reusing the DNS block's `<- app` attribution row format), gated by
  `ExportMode` like every other telemetry block. Findings fold into the
  FINDINGS SECTION automatically.

## 9. Privacy and compliance

- `PRIVACY_POLICY.md` gains a disclosure mirroring the bug-report one:
  user-initiated import, analyzed entirely locally, raw ZIP never retained,
  parsed events kept on-device at most 30 days from import and replaced on
  re-import, nothing transmitted.
- **No new permissions; no Data Safety change.** Nothing new is collected off
  the device and nothing is transmitted.
- `docs/ARCHITECTURE.md` gains a subsection beside the bug-report analyzer
  documenting the sniffer routing, per-type parsers, and tag registry — and
  the explicit D3-distinction paragraph (§1 above).

## 10. Testing

- **Parser unit tests:** wrapper-key routing; `/`-strip; `event_id` dedup
  across overlapping files; malformed-line fail-soft counting; tag-registry
  known/unknown paths; ZIP layout variants (top-level `YYYY-MM-DD.txt`, one
  directory deep, `intrusion-logs/`).
- **Fixtures:** a sanitized slice of the maintainer's real export, including
  real `security_event` lines once extracted from it; synthetic
  `security_event` lines from the `SecurityLog` constants until then.
- **Structural gates (existing):** `PureEmitterContractTest` on the new
  emitters; `LogsourceTaxonomyCrossCheckTest` + `DetectionFieldCrossCheckTest`
  on the `network_monitor` flip and the new `security_log` service;
  `BundledRulesSchemaCrossCheckTest`, `BundledMirrorParityTest`,
  `RuleManifestIntegrityTest` on any starter rules.
- **End-to-end:** fixture ZIP → sniffer → analyzer → rule evaluation →
  findings + timeline rows (asserting `telemetrySource` and correlation IDs);
  replace-on-reimport; cap surfacing.
- UI stays unit-first, matching existing practice.

## 11. Open questions and follow-ups (recorded, not scoped)

1. **`security_event` fixtures:** extract real lines from the maintainer's
   full export to validate the tag registry before its rules land.
2. **`ip_addresses` as a `dns_monitor` rule field:** deferred until a rule
   needs it (schema/taxonomy ceremony required).
3. **IP-based IOC feed:** separate proposal; would give `network_monitor`
   rules an `ioc_lookup` target.
4. **`AdvancedProtectionManager` posture check:** its own issue (maintainer
   decision, cellular spec §11).

## 12. References

- MVT intrusion-logs documentation: <https://docs.mvt.re/en/latest/android/intrusion_logs/>
- `docs/plans/2026-08-22-cellular-telemetry-tier1-spec.md` §11 — field
  mapping, DoT gap, D3 distinction, no-app-read-API evidence
- `docs/ARCHITECTURE.md` §7 (DNS monitor), §8 (bug-report analysis),
  §11 D3 (parked IP filtering)
- `third-party/android-sigma-rules/validation/logsource-taxonomy.yml`
  (`network_monitor: status: unwired`)
