# Issue #119 — Autonomous Threat Discovery Design

- **Issue:** #119 (`feat: autonomous threat discovery from unstructured sources (blog/news)`)
- **Date:** 2026-04-17
- **Status:** Design approved; ready for implementation plan
- **Target branch:** `main` (per CLAUDE.md)
- **Scope estimate:** ~1 week, 1 PR against AndroDR + minor schema update PR against submodule

## Background

Today the AI rule update pipeline auto-discovers threats from 7 structured feeds
(ThreatFox, MalwareBazaar, ASB, NVD, stalkerware-indicators, ATT&CK,
AmnestyTech) but has no auto-discovery from unstructured sources (vendor blogs,
news sites). Threats that appear in Kaspersky/Lookout/Zimperium blogs 1–4 weeks
before they reach structured feeds — the window where threat-intel value is
highest — go undetected until a human names them manually.

Concrete example: the SparkKitty Android/iOS spyware was disclosed by
Kaspersky Securelist in early 2024 and never picked up by any structured
feed AndroDR ingests. Only surfaced during manual validation of the #117
Phase 5 dogfood.

Prerequisites for this work (both merged 2026-04-16):
- **#126** — `threat_research` added to `allowed-sources.json` (submodule rules#7).
  Unblocks threat-research-sourced IOCs from reaching `ioc-data/*.yml`.
- **#128** — structural rejection of MD5/SHA-1/TLSH/SHA-512/ssdeep in
  APK-hash files; named-format errors with recovery hints (submodule rules#8).
  Prevents Kaspersky MD5-style IOCs from polluting ioc-data as dead weight.

## Decision summary

Add a new `/update-rules discover` invocation that produces a work list of
threat names by scraping 5 vendor RSS feeds; dispatches the existing
`update-rules-research-threat` skill in parallel for up to `--top N`
discovered threats (N default 5); SIRs flow through the existing pipeline
unchanged from Step 3 onwards.

Key design choices (each selected from 2–3 considered alternatives during
brainstorming):

- **Cursor granularity:** per-source (each source advances independently;
  robust to partial failures)
- **Source list:** 5 vendor-original RSS sources only (securelist,
  welivesecurity, blog.zimperium, lookout threat-intel, blog.google/TAG).
  Aggregators (BleepingComputer, HackerNews) and HTML-only sources (Dr.Web)
  deferred
- **Extraction:** balanced regex (CVE + category-suffix + camelcase) +
  static denylist + rule-index cross-reference
- **Research fan-out:** parallel (up to N=5 concurrent subagents)
- **Dropped from v1:** `full-with-discover` composite mode (YAGNI; users
  can run `full` then `discover` back-to-back)

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│ /update-rules discover [--top N]  (N default 5)         │
└────────────────────┬────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────┐
│ update-rules-discover skill (NEW)                       │
│ • Reads feed-state.json's per-source discover cursors   │
│ • Fetches RSS for 5 vendor blogs in parallel            │
│ • Filters each RSS to posts newer than per-source cursor│
│ • Extracts threat names from titles+intros              │
│ • Returns {threat_names[up to top-N], updated_cursors}  │
└────────────────────┬────────────────────────────────────┘
                     │ threat_names: e.g., ["SparkKitty", "CVE-2026-0049"]
                     ▼
┌─────────────────────────────────────────────────────────┐
│ Dispatcher fan-out (N parallel Agent subagents):        │
│   update-rules-research-threat "SparkKitty"             │
│   update-rules-research-threat "CVE-2026-0049"          │
│   ...                                                   │
│ Each returns SIRs + candidate_ioc_entries in Phase 4    │
│ output contract (from #117).                            │
└────────────────────┬────────────────────────────────────┘
                     │ SIRs[] (flat union across successful subagents)
                     ▼
     [existing pipeline from Step 4 onwards:
      Rule Author → Validator → Step 6.5 cross-dedup →
      Step 7 approval → Step 8.1 write to ioc-data]
```

**Critical boundary:** the `update-rules-discover` skill does NOT research
threats. It only emits a work list. Heavy lifting (web research, IOC
extraction, ATT&CK mapping) stays in the existing `update-rules-research-threat`
skill (exercised + confirmed working in the #117 Phase 5 dogfood).

## Cursor model

Per-source cursors in `feed-state.json`:

```json
{
  "feeds": { "...": "..." },
  "discover": {
    "sources": {
      "securelist": {
        "last_seen_timestamp": "2026-04-17T00:00:00Z",
        "last_post_url": "https://securelist.com/some-article/12345/"
      },
      "welivesecurity":  { "last_seen_timestamp": "...", "last_post_url": "..." },
      "zimperium":       { "last_seen_timestamp": "...", "last_post_url": "..." },
      "lookout":         { "last_seen_timestamp": "...", "last_post_url": "..." },
      "google-tag":      { "last_seen_timestamp": "...", "last_post_url": "..." }
    }
  }
}
```

### Design notes

- **`discover` at top level, sibling of `feeds`.** Cleaner than smuggling it
  into `feeds` (which holds per-structured-ingester cursors).
- **`last_post_url` as a belt-and-suspenders check.** Edge case: a blog
  republishes an older post with a backdated timestamp (editorial
  corrections). If the newest URL doesn't match the cursor, re-scrape
  regardless of timestamp.
- **Bootstrap:** missing source cursor → scrape last 30 days of RSS, take
  top-N via normal extraction path. Only time a run might produce many
  candidates; steady state is 0–2 per source per week.
- **Partial-failure semantics:** sources that succeed this run advance their
  cursor; sources that failed (fetch error, robots.txt block, parse error)
  don't. Next run picks them up.

### Schema update

New top-level `discover` block in `validation/feed-state-schema.json`:

```json
"discover": {
  "type": "object",
  "additionalProperties": false,
  "required": ["sources"],
  "properties": {
    "sources": {
      "type": "object",
      "additionalProperties": false,
      "properties": {
        "securelist":     { "$ref": "#/$defs/DiscoverSourceCursor" },
        "welivesecurity": { "$ref": "#/$defs/DiscoverSourceCursor" },
        "zimperium":      { "$ref": "#/$defs/DiscoverSourceCursor" },
        "lookout":        { "$ref": "#/$defs/DiscoverSourceCursor" },
        "google-tag":     { "$ref": "#/$defs/DiscoverSourceCursor" }
      }
    }
  }
}
```

`DiscoverSourceCursor` def:
```json
"DiscoverSourceCursor": {
  "type": "object",
  "required": ["last_seen_timestamp", "last_post_url"],
  "additionalProperties": false,
  "properties": {
    "last_seen_timestamp": { "type": "string", "format": "date-time" },
    "last_post_url": { "type": "string", "format": "uri" }
  }
}
```

Adding a new source in v2 requires a schema PR. Intentional friction —
matches project convention of explicit allow-lists at trust boundaries.

## Source list (v1)

5 vendor-original RSS sources:

| Source ID | RSS URL | Notes |
|---|---|---|
| `securelist` | `https://securelist.com/feed/` | Kaspersky; high-signal Android research |
| `welivesecurity` | `https://www.welivesecurity.com/en/feed/` | ESET; frequent Android analyses |
| `zimperium` | `https://blog.zimperium.com/feed/` | Mobile-focused; MalwareBazaar data partner |
| `lookout` | `https://www.lookout.com/threat-intelligence/feed` | Mobile-focused; nation-state coverage |
| `google-tag` | `https://blog.google/threat-analysis-group/rss/` | Google TAG; Android-relevant campaigns |

**Excluded from v1** (listed in issue body):
- `bleepingcomputer.com/tag/android`, `thehackernews.com/search/label/Android` — aggregators; derived from vendor posts. If we scrape vendors directly, we capture ~every story the aggregators cite, earlier.
- `news.drweb.com/list` — lower volume; format unclear (likely HTML-only). Defer until proven needed.

Exact RSS URLs may need fixup during implementation; the skill should handle
minor URL adjustments without schema changes (URLs live in the skill markdown,
only the source IDs are in the schema).

## Extraction pipeline

### Input

Per post: title + first 200 characters of body (intro paragraph).

### Regex patterns (applied in order, most precise first)

1. **CVE IDs:** `\bCVE-\d{4}-\d{4,7}\b` — trivial, high precision, always a real
   candidate worth researching.
2. **Category-suffix matches:** `\b[A-Z][a-zA-Z0-9]{2,}(?:Kit|RAT|Stealer|Trojan|Spy|Bot|Banker|Loader|Dropper|Miner|Ransomware|Worm)\b`
   — catches `MalwareKit`, `XLoader`, etc. Low false-positive rate.
3. **CamelCase-novel-tokens:** `\b(?:[A-Z][a-z]+){2,}\b` — catches `SparkKitty`,
   `GriftHorse`, `RatsnakeRAT`. False-positive prone without filters.

### Post-filters (applied in order)

1. **Category-context boost.** CamelCase tokens appearing within 5 words of a
   malware keyword (`trojan`, `spyware`, `malware`, `banker`, `stealer`,
   `campaign`, `spy`, `backdoor`, `surveillance`, `APT`, `botnet`) are promoted
   to high-confidence. Isolated camelcase → low-confidence, deprioritized for
   top-N selection.
2. **Static denylist** (~50 tokens) shipped with the skill. Includes:
   - Platform/brand: `AppStore`, `GooglePlay`, `PlayStore`, `PlayProtect`,
     `AndroidAuto`, `iCloud`, `FaceTime`, `BlueTooth`, `WiFi`
   - Vendor names: `Google`, `Apple`, `Amazon`, `Samsung`, `Huawei`, `Xiaomi`,
     `OnePlus`, `Motorola`, `Nokia`
   - Generic security: `AndroidSecurity`, `CyberSecurity`, `ThreatIntel`,
     `MachineLearning`, `DeepLearning`
   - Common compounds: `JavaScript`, `TypeScript`, `PowerShell`, `OpenSource`,
     `FullStack`
3. **Rule-index cross-reference.** For each surviving candidate, check against
   existing rule titles + family metadata. Already-tracked candidates skipped
   with log note `already covered by androdr-NNN` (saves research subagent
   budget).
4. **Cursor filter.** Candidate survives only if the source post's `pub_date`
   is newer than the per-source cursor's `last_seen_timestamp`.

### Top-N ranking

1. High-confidence candidates (CVE / category-suffix / boosted camelcase) first
2. Within tier, most-recent post first
3. Across sources, no single source gets more than `ceil(N*0.4)` slots (source
   diversity — prevents one chatty blog from drowning others)

### Logging (stderr)

Every run writes a per-source log block. Example:

```
[discover] securelist: 12 posts since cursor, 4 candidates extracted, 1 kept after filter
[discover]   kept: SparkKitty (2026-04-14, https://securelist.com/sparkkitty-ios-android-malware/...)
[discover]   dropped (denylist): "AppStore" (title: "...spyware found in the App Store...")
[discover]   dropped (already-tracked): "Anatsa" (androdr-078)
[discover]   dropped (cursor): "OlderCampaign" (pub_date 2026-03-15 < cursor 2026-04-10)
[discover] welivesecurity: 8 posts, 2 candidates, 2 kept
...
```

Log is the tuning surface: denylist edits + extraction pattern adjustments
are analyst-driven from this output.

## Dispatcher wiring (`update-rules.md`)

### Step 1 (Read State) extension

When `mode == discover`, also read `discover.sources.*` cursor block.

### Step 2 (Dispatch Ingesters) — new branch

```
if mode == discover:
  1. Spawn ONE subagent: update-rules-discover
     → returns {threat_names[], source_urls[], pub_dates[], updated_cursors}
  2. If threat_names empty:
     report "no new threats discovered; N posts scanned; per-source log attached"
     STOP
  3. Fan out: for each threat_name (up to --top N), spawn a parallel
     update-rules-research-threat subagent via the Agent tool
  4. Collect SIRs from successful subagents; log failures; never abort
     the whole run for a single subagent failure
  5. Proceed to Step 3 (Triage SIRs) with the collected union
```

### Steps 3–8 unchanged

SIRs from discover flow through existing Rule Author → Validator → Step 6.5
cross-dedup → Step 7 approval → Step 8.1 write path. The
`source: threat_research` label (unblocked in #126) and
`requires_verification: true` (per Bundle 2 single-unstructured rule) are
both set by the research-threat skill automatically.

### Dispatcher-level logging

```
[dispatcher] discover produced 5 threat names: [SparkKitty, CVE-2026-0049, ...]
[dispatcher] fan-out: 5 parallel update-rules-research-threat subagents
[dispatcher]   ✓ SparkKitty: 1 SIR (requires_verification=true, 11 domains, 0 hashes after #128 filter)
[dispatcher]   ✓ CVE-2026-0049: 1 SIR (requires_verification=false, 2 references)
[dispatcher]   ✗ Anatsa: subagent failed (Cloudflare 429 on lookout.com); retry in next run
[dispatcher] fan-out complete: 4/5 successful, 5 SIRs total
[dispatcher] proceeding to Step 3 with union of successful subagents
```

### Safety-rule additions to `update-rules.md`'s final section

- NEVER dispatch discover without a top-N bound (default 5 is the cap; no
  `--top 9999`)
- NEVER retry a failed discover subagent inside the same run (fail fast, try
  again next run)
- NEVER advance a per-source cursor if that source's fetch failed
- NEVER include full-with-discover as a composite mode (explicitly dropped;
  users run `full` then `discover` back-to-back if they want both)

## Guardrails

### Rate limiting

- 1 RSS fetch per source per discover invocation (RSS returns 20–50 posts;
  no pagination needed)
- 5 RSS fetches run in parallel (different hosts; no cross-site entanglement)
- Research-threat fan-out: up to N=5 parallel subagents; each subagent's own
  politeness governs its web fetches
- No retry loops on failure

### robots.txt compliance

- Fetch `<origin>/robots.txt` once per source per run; cache in-memory for run
- If RSS path disallowed → skip source, log
- If robots.txt fetch itself fails → allow the RSS fetch; document explicitly
  ("we tried")

### Polite User-Agent

All HTTP from discover + downstream research-threat include:
```
User-Agent: AndroDR-AI-Rule-Pipeline/1.0 (+https://github.com/yasirhamza/AndroDR)
```

## Testing

### Unit-testable pieces

The skill markdown itself is LLM-executed, not Python. Three testable components:

1. **Denylist lint test.** Python+pytest. Loads denylist YAML; asserts:
   - No duplicates
   - All entries match `^[A-Z][a-zA-Z0-9]{2,}$`
   - Does NOT include known real malware family names (SparkKitty, Anatsa,
     TrickMo, Pegasus, Predator, Graphite, ClayRat) — guards against future
     edit accidentally muting a real threat
2. **Cross-check test (Kotlin, mirrors `BundledRulesSchemaCrossCheckTest`
   pattern).** Asserts the 5 source IDs in the skill match the 5 source IDs
   in `feed-state-schema.json`'s `discover.sources.properties`. Locks the
   drift loop.
3. **RSS-snapshot fixtures** under `.claude/commands/fixtures/discover/`.
   5 representative RSS feed XML files (one per source) with known-expected
   extraction output. Not automated CI (skill markdown isn't Python);
   reproducible via manual dogfood replay.

### End-to-end smoke (post-merge)

Run `/update-rules discover --top 3` in a fresh session against live vendor
RSS. Expected:
- Each of 5 sources emits a posts-scanned count
- 0–3 candidates survive to research-threat dispatch
- Each research-threat returns a SIR (often `requires_verification: true`)
- SIRs flow through Rule Author + Validator
- Step 6.5 cross-dedup correctly filters any Kotlin-mirror overlaps
- Step 7 presents for approve/modify/reject

Same dogfood pattern as #117 Phase 5.

## Explicit scope boundaries

### Out of scope

- **LLM-based extraction.** Regex + denylist only per issue body. Revisit if
  accuracy proves insufficient.
- **Social-media monitoring.** Twitter/X, Mastodon; different rate-limit
  + legal context.
- **Non-English sources.** Chinese/Russian blogs; needs language detection
  + translation.
- **Scheduled automation.** Discover remains human-triggered.
- **`full-with-discover` composite mode.** YAGNI for v1.
- **Subagent retry-in-run.** Fail fast; retry next invocation.
- **Automatic denylist tuning.** Denylist stays manually edited.
- **HTML-only or aggregator sources.** BleepingComputer, HackerNews, Dr.Web
  deferred.

## Implementation phases (hint for writing-plans)

Likely phase breakdown:

1. **Submodule schema PR** — add `discover` block to `feed-state-schema.json`
2. **AndroDR PR** — the main work:
   - New `.claude/commands/update-rules-discover.md` skill
   - Denylist YAML (shipped alongside skill)
   - Extraction regex documentation
   - Cross-check Kotlin test for source-ID drift
   - Dispatcher changes to `.claude/commands/update-rules.md`
     (new Step 2 discover branch + safety rules)
   - Unit test for denylist lint
   - RSS fixture files + dogfood replay documentation

## Related

- **Prerequisite (merged):** #126 (AndroDR) / rules#7 (submodule) —
  threat_research source allowlist
- **Prerequisite (merged):** #128 (AndroDR) / rules#8 (submodule) —
  hash-format rejection
- **Upstream:** #117 (closed 2026-04-16) — complementary IOC pipeline;
  #119 is the explicitly-named follow-up in #117's spec
- **Epic:** #104 (AI rule framework audit) — closed 2026-04-15
