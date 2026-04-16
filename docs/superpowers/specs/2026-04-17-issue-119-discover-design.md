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
threat names via **hybrid RSS-Python + Web-LLM extraction** across 5 vendor
sources; dispatches the existing `update-rules-research-threat` skill in
parallel for up to `--top N` discovered threats (N default 5); SIRs flow
through the existing pipeline unchanged from Step 3 onwards.

Key design choices (each selected from 2–3 considered alternatives during
brainstorming):

- **Cursor granularity:** per-source (each source advances independently;
  robust to partial failures)
- **Source list:** 5 vendor sources via hybrid paths:
  - **3 RSS sources** (deterministic Python extraction): securelist,
    welivesecurity, blog.google/TAG
  - **2 Web sources** (LLM extraction via WebFetch): zimperium (RSS feed
    no longer exists), lookout (Cloudflare-fronted; WebFetch's browser
    path handles it where direct HTTP 403s)
  - Aggregators (BleepingComputer, HackerNews) and low-volume Russian-
    language sources (Dr.Web) deferred
- **Extraction:** hybrid approach with common rule set:
  - **RSS path:** `scripts/discover_extract.py` (deterministic, unit-tested)
    — regex (CVE + category-suffix + camelcase + two-word-with-context) +
    static denylist + rule-index cross-reference
  - **Web path:** LLM via WebFetch, instructed to apply the same rule set
    when parsing HTML blog indices
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
│ • Dispatches hybrid extraction across 5 sources:        │
│                                                         │
│   RSS path (Python, deterministic):                     │
│   ┌─────────────────────────────────────────────────┐   │
│   │ scripts/discover_extract.py <source.xml>        │   │
│   │   • RSS/Atom parser (feedparser or stdlib)      │   │
│   │   • Apply patterns (CVE, suffix, camelcase,     │   │
│   │     two-word-with-context)                      │   │
│   │   • Apply denylist                              │   │
│   │   • Cross-ref against existing rule index       │   │
│   │   • Return JSON candidate list                  │   │
│   │ Sources: securelist, welivesecurity, google-tag │   │
│   └─────────────────────────────────────────────────┘   │
│                                                         │
│   Web path (LLM via WebFetch):                          │
│   ┌─────────────────────────────────────────────────┐   │
│   │ WebFetch <blog-index-url>                       │   │
│   │   • LLM parses HTML, extracts recent posts      │   │
│   │   • Applies SAME regex rules as documented in   │   │
│   │     the skill markdown                          │   │
│   │   • Returns same JSON candidate list shape      │   │
│   │ Sources: zimperium, lookout                     │   │
│   └─────────────────────────────────────────────────┘   │
│                                                         │
│ • Merges candidates from both paths                     │
│ • Ranks, picks top-N                                    │
│ • Returns {threat_names[], updated_cursors, log[]}      │
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
- **Bootstrap:** missing source cursor → scrape whatever the current RSS
  feed holds (typically 10–100 most recent posts depending on source; not a
  fixed 30-day window since feeds may roll off faster or slower). Only time
  a run might produce many candidates; steady state is 0–2 per source per
  week.
- **Partial-failure semantics (precise):**
  - **fetch succeeded + parse succeeded + ≥1 item returned** → advance
    cursor to newest-item timestamp + URL
  - **fetch failed** (network error, DNS fail, 4xx/5xx) → skip, do NOT
    advance cursor, log as `fetch_error`
  - **fetch succeeded but parse failed** (malformed RSS, HTML-error-page
    disguised as XML, Cloudflare interstitial HTML) → skip, do NOT advance
    cursor, log as `parse_error` for operator diagnosis
  - **robots.txt disallows path** → skip, do NOT advance, log once per run
- **`last_post_url` CMS-migration recovery:** if `last_post_url` is not
  found in the current feed AND `last_seen_timestamp` is more than 90 days
  old, assume the source's URL scheme changed, fall back to
  timestamp-only comparison for cursor advancement. Log as
  `cms_migration_detected` so an operator can update the source config if
  needed.

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

5 sources via hybrid paths. URLs verified by live probe 2026-04-17:

| Source ID | Type | URL | Notes |
|---|---|---|---|
| `securelist` | rss | `https://securelist.com/feed/` | Kaspersky; 200 OK, full bodies via `content:encoded`. ~10 items/month |
| `welivesecurity` | rss | `https://www.welivesecurity.com/en/feed/` | ESET; 200 OK, **description-only** (no full body). ~100 items (high volume) |
| `google-tag` | rss | `https://blog.google/threat-analysis-group/rss/` | Google TAG; 200 OK, description-only |
| `zimperium` | web | `https://www.zimperium.com/blog/` | Mobile-focused; no working RSS (blog.zimperium.com moved); WebFetch'd HTML index |
| `lookout` | web | `https://www.lookout.com/threat-intelligence/blog` | Mobile-focused; Cloudflare-fronted (403 on direct fetch); WebFetch'd HTML index |

**Note on description-only RSS:** welivesecurity and google-tag expose only
a ~50–200 char summary per post, not the full body. Extraction operates on
title + summary. This is enough for category-suffix / camelcase / two-word
pattern hits that appear in titles (most threat-name disclosures do lead
with the name), but weaker for titles that bury the name in the body.
Acceptable; the manual `/update-rules threat "<name>"` path remains as
fallback for threats not surfaced via title/summary.

**Note on web-path sources:** when RSS doesn't exist or is blocked, WebFetch
the HTML blog index page. LLM parses the rendered page, extracts post
titles + meta descriptions or excerpt snippets, and returns the same
candidate shape as the Python RSS path. Browser-UA path in WebFetch
typically bypasses Cloudflare challenges where our User-Agent header does
not.

**Excluded from v1** (listed in issue body):
- `bleepingcomputer.com/tag/android`, `thehackernews.com/search/label/Android` — aggregators; derived from vendor posts. If we scrape vendors directly, we capture ~every story the aggregators cite, earlier.
- `news.drweb.com/list` — lower volume; Russian-language content majority; format unclear. Defer until proven needed.

URLs live in the skill markdown + the Python helper's source-config table.
Only source IDs are encoded in the schema. Adding a new source ID to the
schema requires a submodule PR (intentional friction at the allow-list).

## Extraction pipeline

### Input

Per post: title + available summary/description + body-when-available.
Varies by source (see Source list table).

### Regex patterns (applied in order, most precise first)

1. **CVE IDs:** `\bCVE-\d{4}-\d{4,7}\b` — trivial, high precision, always a
   real candidate worth researching.
2. **Category-suffix matches:**
   `\b[A-Z][a-zA-Z0-9]{2,}(?:Kit|RAT|Stealer|Trojan|Spy|Bot|Banker|Loader|Dropper|Miner|Ransomware|Worm)\b`
   — catches `MalwareKit`, `XLoader`, `ClayRat`, etc. Low false-positive rate.
3. **CamelCase-novel-tokens:** `\b(?:[A-Z][a-z]+){2,}\b` — catches
   `SparkKitty`, `GriftHorse`, `RatsnakeRAT`. False-positive prone without
   filters.
4. **Two-word threat names with strict context:**
   `\b([A-Z][a-z]+) ([A-Z][a-z]+)\b` — catches `Silver Fox`, `Lazarus Group`,
   `Cozy Bear`, `Sandworm Team`. High false-positive rate WITHOUT context
   (matches `Good Morning`, `Happy Birthday`, `United States`); therefore
   **match is only accepted when within 5 words of a malware context
   keyword** (see post-filter 1 below). This asymmetric strict-context
   requirement is specific to pattern 4.

### Post-filters (applied in order)

1. **Category-context gate + boost.** Malware keyword set:
   `trojan, spyware, malware, banker, stealer, campaign, spy, backdoor,
   surveillance, APT, botnet, ransomware, loader, dropper, rootkit, rat,
   cryptojacker, infostealer`.
   - Pattern 1 (CVE) + Pattern 2 (suffix): context-independent, high-conf
   - Pattern 3 (camelcase): context → high-conf; no context → low-conf
     (still kept, but ranked behind high-conf for top-N selection)
   - **Pattern 4 (two-word): context is REQUIRED. No context → dropped.**
2. **Static denylist** (~50 tokens) shipped alongside the skill. Includes:
   - Platform/brand: `AppStore`, `GooglePlay`, `PlayStore`, `PlayProtect`,
     `AndroidAuto`, `iCloud`, `FaceTime`, `BlueTooth`, `WiFi`
   - Vendor names: `Google`, `Apple`, `Amazon`, `Samsung`, `Huawei`, `Xiaomi`,
     `OnePlus`, `Motorola`, `Nokia`
   - Generic security: `AndroidSecurity`, `CyberSecurity`, `ThreatIntel`,
     `MachineLearning`, `DeepLearning`
   - Common compounds: `JavaScript`, `TypeScript`, `PowerShell`, `OpenSource`,
     `FullStack`
3. **Rule-index cross-reference.** For each surviving candidate, check
   against existing rule titles + family metadata. Already-tracked
   candidates skipped with log note `already covered by androdr-NNN`
   (saves research subagent budget).
4. **Cursor filter.** Candidate survives only if the source post's
   `pub_date` is newer than the per-source cursor's `last_seen_timestamp`
   (or, under CMS-migration fallback, just the timestamp check).

### Top-N ranking

1. High-confidence candidates (CVE / suffix / context-boosted camelcase /
   context-required two-word) first
2. Within tier, most-recent post first
3. Simple first-N slice — no source-diversity distribution math for v1
   (reviewer flagged `ceil(N*0.4)` as over-engineered for N=5; can add if
   analysts report one source drowning others)

### Logging (stderr)

Every run writes a per-source log block. Example:

```
[discover] securelist (rss): 12 posts since cursor, 4 candidates extracted, 1 kept after filter
[discover]   kept: SparkKitty (2026-04-14, https://securelist.com/sparkkitty-ios-android-malware/...)
[discover]   dropped (denylist): "AppStore" (title: "...spyware found in the App Store...")
[discover]   dropped (already-tracked): "Anatsa" (androdr-078)
[discover]   dropped (cursor): "OlderCampaign" (pub_date 2026-03-15 < cursor 2026-04-10)
[discover]   dropped (pattern-4 no-context): "Good Morning" (title: "Good Morning Vietnam: A retrospective")
[discover] welivesecurity (rss): 8 posts, 2 candidates, 2 kept
[discover] zimperium (web): HTML parsed via WebFetch, 15 posts extracted, 1 candidate kept
[discover] lookout (web): HTML parsed via WebFetch, 12 posts extracted, 0 candidates
[discover] google-tag (rss): 20 posts since cursor, 3 candidates, 2 kept
```

Log is the tuning surface: denylist edits + extraction pattern adjustments
are analyst-driven from this output.

### Python helper (`scripts/discover_extract.py`)

Lives under `.claude/commands/scripts/discover_extract.py` (same repo as
the skill that invokes it).

**Responsibilities (RSS path only):**
- Parse RSS/Atom XML (use stdlib `xml.etree.ElementTree` or the existing
  project's YAML/JSON patterns for consistency — no new deps if avoidable)
- Apply patterns 1–4 + post-filters 1–4 deterministically
- Return JSON to stdout: `{candidates: [...], log: [...],
  cursor_update: {last_seen_timestamp, last_post_url}}` or
  `{error: "...", log: [...]}` on fetch/parse failure

**Web path does NOT use this helper.** The discover skill invokes WebFetch
directly for zimperium / lookout, and the skill's markdown instructs the
LLM to apply the same rule set (patterns + denylist + rule-index check)
when extracting from HTML. Rule-set documentation in the skill markdown
MUST match the Python helper's behavior — drift between the two is caught
by eyeballing the log output during dogfood runs and by the extraction
fixture tests (see Testing section).

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

### Unit tests (Python path)

Because the RSS path lives in deterministic Python, extraction quality IS
unit-testable via golden fixtures. This is the main drift-detection gain
over LLM-only extraction.

1. **Denylist lint test** (`test_discover_denylist.py`). Loads denylist
   YAML; asserts:
   - No duplicates
   - All entries match `^[A-Z][a-zA-Z0-9]{2,}$`
   - Does NOT contain any entry from an explicit **known-malware-name guard
     list**: `SparkKitty, SparkCat, Anatsa, TrickMo, Pegasus, Predator,
     Graphite, ClayRat, BlackRock, Joker, FluBot, Brata, Hook, Anubis,
     Silver, Fox, Cozy, Lazarus, Sandworm` — guards against a future edit
     accidentally muting a real threat family or APT name. Tokens that
     ARE valid English words when standalone (`Silver`, `Fox`, `Cozy`,
     `Predator`) carry extra risk of well-meaning denylist additions.
2. **Extraction golden-fixture tests** (`test_discover_extract.py`).
   Committed fixture inputs under
   `.claude/commands/fixtures/discover/*.xml` (3 RSS feeds frozen in time,
   one per RSS source: securelist, welivesecurity, google-tag). Paired
   with expected-output JSON files. Test harness invokes
   `discover_extract.py` on each fixture and asserts byte-identical output.
   - Catches regex drift (someone edits pattern 3's regex → fixture output
     changes → test fails)
   - Catches denylist accidental additions (Silver Fox survives → test
     fails because expected-output didn't include it)
   - Catches rule-index logic drift
3. **Source-ID cross-check test** (Kotlin, mirrors
   `BundledRulesSchemaCrossCheckTest`). Asserts the 5 source IDs
   referenced by the skill match the 5 source IDs in
   `feed-state-schema.json`'s `discover.sources.properties`. Locks
   schema↔skill drift.
4. **Source-URL binding lint** (Python, in
   `test_discover_source_urls.py`). Asserts each source ID's configured
   URL has a hostname containing the source ID stem (e.g., `lookout` →
   must be on `*.lookout.com`). Guards against a skill-markdown edit
   silently re-pointing a source at `attacker.com`.

### Dogfood replay (Web path + end-to-end)

Web path (zimperium, lookout) extraction is LLM-interpreted and varies
session-to-session; not meaningfully unit-testable. Covered by:

- **Committed HTML fixtures** under
  `.claude/commands/fixtures/discover/*.html` (blog-index snapshots). These
  are NOT used by automated tests — only by manual dogfood replays.
  Reproducible: "extract candidates from this fixture" produces comparable
  output across runs even if not byte-identical.
- **End-to-end smoke (post-merge):** run `/update-rules discover --top 3`
  against live sources. Expected:
  - Each of 5 sources emits a posts-scanned count + path indicator (rss/web)
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

1. **Submodule schema PR** — add `discover` top-level block + 5 source-ID
   properties to `feed-state-schema.json`; matching `DiscoverSourceCursor`
   $def. Small PR, same pattern as #117 Phase 1's schema changes.
2. **AndroDR PR** — the main work:
   - New `.claude/commands/update-rules-discover.md` skill (dispatches
     Python helper for RSS sources, WebFetch for web sources, merges
     candidates)
   - New `.claude/commands/scripts/discover_extract.py` (deterministic
     RSS-path extraction)
   - Denylist YAML (shipped alongside the skill and helper)
   - Fixture XML + expected-JSON pairs under
     `.claude/commands/fixtures/discover/` (3 RSS + 2 HTML)
   - Python unit tests: denylist lint, extraction goldens, source-URL
     binding
   - Kotlin cross-check test for source-ID drift (mirrors
     `BundledRulesSchemaCrossCheckTest`)
   - Dispatcher changes to `.claude/commands/update-rules.md` (new Step 2
     discover branch + safety rules)
   - Submodule bump to pick up Phase 1

## Related

- **Prerequisite (merged):** #126 (AndroDR) / rules#7 (submodule) —
  threat_research source allowlist
- **Prerequisite (merged):** #128 (AndroDR) / rules#8 (submodule) —
  hash-format rejection
- **Upstream:** #117 (closed 2026-04-16) — complementary IOC pipeline;
  #119 is the explicitly-named follow-up in #117's spec
- **Epic:** #104 (AI rule framework audit) — closed 2026-04-15
