# Rule-Update Pipeline Rework Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Restructure `/update-rules` into a research-led combined sweep (default mode), shard the author stage and bypass it for IOC-only SIRs, refresh moved/blocked discover source URLs with a cursor-reset-once rule, fix the abuse.ch/ASB ingester doc rot, and wire the adopted Jev ATT&CK tag suggester as an advisory, fail-open step.

**Architecture:** All behavioral change lives in pipeline skill markdown (`.claude/commands/*.md`) plus two new Python scripts in `.claude/commands/scripts/`. The rules repo (`third-party/android-sigma-rules`) receives exactly two files: a one-time discover cursor reset and a ledger-mode list update — no rule YAML, no taxonomy, no manifest changes. No AndroDR Kotlin is touched.

**Tech Stack:** Markdown skill files; Python 3 (stdlib only for the Jev script's testable core; the live Jev call reuses the frozen trial's vendored `typesafe_sdk`/`httpx2` from the eval repo's `.venv`); `pytest` for the URL-lock and Jev tests; `validate-feed-state.py` as the rules-repo gate.

**Spec:** `docs/superpowers/specs/2026-10-14-pipeline-rework-design.md` — the plan argues from the spec; executors read both.

## Global Constraints

- NEVER write rules to production service directories — `staging/<service>/` only (spec §3.6).
- NEVER set `status` to anything other than `experimental` for AI-generated rules (spec §3.6).
- NEVER modify AndroDR application code (Kotlin sources) — this rework edits skills only (spec §3.6).
- NEVER commit API keys or credentials to any file. The Jev API key stays in the GNOME keyring and is piped on stdin at call time (`secret-tool lookup service jev-androdr account typesafe`) — never argv, env, or files (trial rule).
- Six validation gates; validators parallel per candidate; retry-once policy (spec §3.6).
- Cross-dedup safety: `U_authoritative` empty → abort; mirror-feed survivors → WARN (spec §3.6).
- NEVER advance a per-source cursor when that source's fetch or parse failed (spec §3.5/§3.6).
- ioc-data writes: both validators must pass; no `kotlin-mirror-feeds.yml` change in the same commit as an ioc-data write (spec §3.6).
- HitL gate before any write; one ledger per run; lessons cap 20; approval-trend print (spec §3.6).
- NEVER pass `--allow-upstream-unreachable` in automated runs (spec §3.6).
- All changes via PRs to `main`, never direct push; wait for `ci-success` (AndroDR) / `validate` (rules repo) before merge.
- Rules-repo edits in this plan touch only `feed-state.json` and `pipeline-runs/README.md` — neither is listed in `rules.txt`, so `rules.sha256` does NOT need regeneration.
- Jev suggestions are ADVISORY and NEVER auto-applied; scores are non-gating (trial verdict: Recall@3 0.971, but miscalibration persists, ECE ≈ 0.2).
- End every commit message with `Co-Authored-By: Claude Code <noreply@anthropic.com>`; end PR descriptions with `🤖 Generated with [Claude Code](https://claude.com/claude-code)`.
- Skill markdown is not hot-reloaded: dogfooding happens in a fresh session after merge (spec §4).

## Review Focus

1. **Same-host URL moves** (Cleafy `cleafy.com/cleafy-labs` → `cleafy.com/labs`, Zimperium `www.` drop, WLS feed path) — the hostname-substring lock test passes unchanged through a same-host move, so URL rot recurs silently. Pinned by upgrading `test_discover_source_urls.py` to assert EXACT URLs (Task 2).
2. **Jev called with no keyring key** — a sweep must not stall or crash on a missing key; it must warn and keep the author's tags. Pinned by `test_no_key_exits_3` → exit code 3 (Task 5).
3. **Equal Jev scores across techniques** — unordered ranking would make two runs on the same candidates disagree. Pinned to the registered semantics (descending score, tie-break by technique ID, `score.jev_b1_ranking`) by `test_rank_top3_descending_then_id_tiebreak` (Task 5).
4. **Every Jev call erroring (API down)** — must not look like "model returned no suggestions". Pinned by `test_exit_code_all_errors_is_4`: all-errored is exit 4, distinct from 0 (Task 5 script contract; dispatcher treats 3/4 identically: WARN + author tags stand).
5. **Cursor reset that leaves `feed-state.json` schema-invalid** — `DiscoverSourceCursor` REQUIRES `last_seen_timestamp` + `last_post_url`, so a "reset" must delete the whole source object, not blank fields. Pinned by running `validate-feed-state.py` as the rules-repo commit's gate (Task 6).

---

### Task 1: Ingest-skill doc rot (abuse.ch + ASB)

**Files:**
- Modify: `.claude/commands/update-rules-ingest-abusech.md:29-35,90-115`
- Modify: `.claude/commands/update-rules-ingest-asb.md:21`

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces: ThreatFox instructions that match the live API (`first_seen` field, `limit=1000`, HIGH severity example); ASB skill with the dead `androidvulnerabilities.org` step removed. No downstream task depends on these texts programmatically.

- [ ] **Step 1: Create the implementation branch**

```bash
cd /home/yasir/AndroDR
git fetch origin
git checkout -b feat/pipeline-rework origin/main
```

- [ ] **Step 2: Fix the ThreatFox query limit** (`.claude/commands/update-rules-ingest-abusech.md`, line 32 — inside the curl block)

Replace:
```bash
     -d '{"query": "taginfo", "tag": "Android", "limit": 100}'
```
with:
```bash
     -d '{"query": "taginfo", "tag": "Android", "limit": 1000}'
```

The API's documented maximum is 1000; the 100-record window silently orphans catch-up gaps (2026-10-14 run: reached only to 2026-09-09 against a 2026-08-02 cursor).

- [ ] **Step 3: Fix the ThreatFox field name** (same file, lines 34-35)

Replace:
```
2. Parse the JSON response. Each IOC has: `id`, `ioc`, `ioc_type`, `threat_type`, `malware`, `tags`, `first_seen_utc`, `reference`
3. Filter to IOCs with `first_seen_utc` after `last_seen_timestamp` (or take all if null)
```
with:
```
2. Parse the JSON response. Each IOC has: `id`, `ioc`, `ioc_type`, `threat_type`, `malware`, `tags`, `first_seen`, `reference`
3. Filter to IOCs with `first_seen` after `last_seen_timestamp` (or take all if null)
```

- [ ] **Step 4: Align the C2-domain severity example to the existing file** (same file, line 104 — the threatfox `c2-domains.yml` example entry)

Replace:
```json
        "severity": "CRITICAL",
```
with:
```json
        "severity": "HIGH",
```

Every existing threatfox row in `ioc-data/c2-domains.yml` is HIGH; the CRITICAL example produced a severity conflict at the 2026-10-14 gate. (The MalwareBazaar example on line 115 already says HIGH — leave it.)

- [ ] **Step 5: Remove the dead ASB source** (`.claude/commands/update-rules-ingest-asb.md`, line 21)

Delete the line:
```
   c. Also check `https://androidvulnerabilities.org/` for structured JSON data on the same CVEs
```

The site is frozen at 2015-era data and confirmed unusable (verified again by the 2026-10-14 ASB ingester). The `b.` step above it extracts CVEs from the bulletin HTML tables, which is the real source.

- [ ] **Step 6: Verify**

```bash
cd /home/yasir/AndroDR
grep -n "first_seen_utc" .claude/commands/update-rules-ingest-abusech.md   # expect: no output
grep -n '"limit": 100}' .claude/commands/update-rules-ingest-abusech.md   # expect: no output (brace-anchored so 1000 doesn't match)
grep -n "CRITICAL" .claude/commands/update-rules-ingest-abusech.md         # expect: no output
grep -n "androidvulnerabilities" .claude/commands/update-rules-ingest-asb.md # expect: no output
```

- [ ] **Step 7: Commit**

```bash
git add .claude/commands/update-rules-ingest-abusech.md .claude/commands/update-rules-ingest-asb.md
git commit -m "fix(skills): abuse.ch first_seen/limit/severity + ASB dead-source doc rot

2026-10-14 sweep findings: ThreatFox returns first_seen (not first_seen_utc);
limit=100 silently orphaned the 2026-08-02→2026-09-09 catch-up gap (API max
is 1000); the CRITICAL severity example conflicted with every existing
threatfox row in c2-domains.yml (all HIGH); androidvulnerabilities.org is
frozen 2015-era data.

Co-Authored-By: Claude Code <noreply@anthropic.com>"
```

### Task 2: Discover URLs, Lookout removal, liveness + cursor-reset rules

**Files:**
- Modify: `.claude/commands/update-rules-discover.md:25,32,40-46,61,91,125,128,144,154`
- Modify: `.claude/commands/scripts/test_discover_source_urls.py:11-41`
- Test: `.claude/commands/scripts/test_discover_source_urls.py` (upgraded in this task)

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces: canonical source URLs (WLS `https://www.welivesecurity.com/en/rss/feed/`, Cleafy `https://www.cleafy.com/labs`, Zimperium `https://zimperium.com/blog`); a 7-source active list (no Lookout); a liveness log line per source; the cursor-reset-once rule that Task 6's feed-state edit applies at merge time. The exact-URL test lock protects all future URL edits.

- [ ] **Step 1: Update the RSS-path table row** (line 32)

Replace:
```
| `welivesecurity` | `https://www.welivesecurity.com/en/feed/` |
```
with:
```
| `welivesecurity` | `https://www.welivesecurity.com/en/rss/feed/` |
```

- [ ] **Step 2: Update the web-path table rows and drop Lookout** (lines 40-46)

Replace:
```
| Source ID | Index URL |
|---|---|
| `zimperium` | `https://www.zimperium.com/blog/` |
| `lookout` | `https://www.lookout.com/threat-intelligence` |
| `threatfabric` | `https://www.threatfabric.com/blogs` |
| `cleafy` | `https://www.cleafy.com/cleafy-labs` |
| `group-ib` | `https://www.group-ib.com/blog/` |
```
with:
```
| Source ID | Index URL |
|---|---|
| `zimperium` | `https://zimperium.com/blog` |
| `threatfabric` | `https://www.threatfabric.com/blogs` |
| `cleafy` | `https://www.cleafy.com/labs` |
| `group-ib` | `https://www.group-ib.com/blog/` |

> `lookout` (`https://www.lookout.com/threat-intelligence`) is retained here
> as a **reference-only mention**: it 403 bot-blocks every fetch, so it is
> NOT an active source and gets no cursor. If Lookout ever unblocks, it can
> be re-added as an active row with a fresh cursor (a URL change resets the
> cursor once — see Rules).
```

- [ ] **Step 2b: Update the two test-name references in the skill** — Step 8 renames the test's dict, so the skill's references to it must follow.

Line 25, replace:
```
URL hostname bindings are locked by `test_discover_source_urls.py`. DO NOT edit URLs without updating the test's EXPECTED_HOSTNAME_SUBSTRING.
```
with:
```
URL bindings are locked by `test_discover_source_urls.py`. DO NOT edit URLs without updating the test's EXPECTED_SOURCE_URLS — the test asserts exact URLs, so even a same-host path change fails it.
```

Line 154 (Rules section), replace:
```
- NEVER edit a source URL without updating `test_discover_source_urls.py`'s EXPECTED_HOSTNAME_SUBSTRING
```
with:
```
- NEVER edit a source URL without updating `test_discover_source_urls.py`'s EXPECTED_SOURCE_URLS
```

- [ ] **Step 3: Add the liveness + cursor-reset rules to the skill** (insert between the robustness-caveat blockquote — line 61 — and `## Process` — line 63)

```markdown

## Liveness logging

Every discovery pass records a per-source liveness status in the output
`log`, one line per source:

```
[discover] <source_id> (<rss|web>): live — N posts, M raw names, K kept after structural filter
[discover] <source_id> (<rss|web>): moved — fetched via redirect from the configured URL (log the final URL)
[discover] <source_id> (<rss|web>): blocked — Cloudflare 403 / bot-check (cursor not advanced)
[discover] <source_id> (<rss|web>): dead — 404/5xx/DNS failure (cursor not advanced)
```

`live` and `moved` are fetch successes (cursor may advance if parse
succeeded). `blocked` and `dead` are fetch failures: skip the source, log
it, and do NOT advance its cursor — the threat names still reach a human
via the report, and a name known by any other route can always be
researched with `/update-rules threat`. These statuses supersede the old
generic `fetch_error` log label; a source that fetched but failed to
parse keeps its existing `parse_error` label.
```

- [ ] **Step 4: Drop Lookout from the web-path process list** (line 91)

Replace:
```
For zimperium / lookout / threatfabric / cleafy / group-ib:
```
with:
```
For zimperium / threatfabric / cleafy / group-ib:
```

- [ ] **Step 5: Fix the source count** (line 125)

Replace:
```
Collect candidates from all 8 sources. Dedup by threat_name (keep the earliest-surfaced source URL per name). Rank:
```
with:
```
Collect candidates from all 7 active sources. Dedup by threat_name (keep the earliest-surfaced source URL per name). Rank:
```

- [ ] **Step 6: Drop Lookout from the tie-break order** (line 128)

Replace:
```
2. Break pub_date ties by source-order preference (securelist → welivesecurity → google-tag → zimperium → lookout → threatfabric → cleafy → group-ib) for determinism
```
with:
```
2. Break pub_date ties by source-order preference (securelist → welivesecurity → google-tag → zimperium → threatfabric → cleafy → group-ib) for determinism
```

- [ ] **Step 6b: Update the Output example log to the new liveness vocabulary** (line 144)

Replace:
```
    "[discover] lookout (web): fetch_error: Cloudflare 403 (cursor not advanced)"
```
with:
```
    "[discover] group-ib (web): blocked — Cloudflare 403 (cursor not advanced)"
```

(The `lookout` example is stale twice over: lookout is no longer an active source, and `fetch_error` is superseded by the liveness statuses from Step 3.)

- [ ] **Step 7: Add the cursor-reset rule to the skill's Rules section** (insert after the existing "NEVER advance a source cursor when that source's fetch or parse failed" rule, around line 156)

```markdown
- A source whose URL CHANGES gets its discover cursor reset ONCE, at the
  time the URL change lands: delete that source's whole object from
  `discover.sources` in `feed-state.json` (the schema requires both cursor
  fields, so a reset is a deletion, not a blanking). The next pass re-scans
  the source from scratch and writes a fresh cursor. This is what recovers
  a source that moved and went silently unfetched — Cleafy's URL moved in
  ~May 2026 and its cursor sat stale for five months while the old URL
  redirected.
```

- [ ] **Step 8: Upgrade the URL-lock test to exact URLs** (`.claude/commands/scripts/test_discover_source_urls.py`) — the hostname-substring lock cannot see same-host path changes (this is Review Focus item 1).

Replace the `EXPECTED_HOSTNAME_SUBSTRING` dict (lines 11-20) with an exact-URL dict:
```python
EXPECTED_SOURCE_URLS = {
    "securelist":     "https://securelist.com/feed/",
    "welivesecurity": "https://www.welivesecurity.com/en/rss/feed/",
    "zimperium":      "https://zimperium.com/blog",
    "google-tag":     "https://blog.google/security/rss/",
    "threatfabric":   "https://www.threatfabric.com/blogs",
    "cleafy":         "https://www.cleafy.com/labs",
    "group-ib":       "https://www.group-ib.com/blog/",
}
```
and replace `test_each_source_url_matches_hostname` (lines 27-41) with the exact-URL variant:
```python
def test_each_source_url_has_exact_expected_url():
    content = SKILL_PATH.read_text()
    failures = []
    for source_id, expected_url in EXPECTED_SOURCE_URLS.items():
        m = re.search(rf"\b{re.escape(source_id)}\b", content)
        if m is None:
            failures.append(f"source_id {source_id!r} not mentioned in skill")
            continue
        window = content[m.start(): m.start() + 400]
        if expected_url not in window:
            failures.append(
                f"source_id {source_id!r} mentioned but exact URL "
                f"{expected_url!r} not found within 400 chars — same-host "
                f"URL moves are the silent-rot class this lock exists for"
            )
    assert not failures, "\n".join(failures)
```

(Lookout is deliberately absent from `EXPECTED_SOURCE_URLS`: it is
reference-only now, and the skill text carries its URL in a blockquote
note, not an active table row. `test_skill_file_exists` is unchanged —
the file ends up with 2 tests, both passing.)

- [ ] **Step 9: Verify**

```bash
cd /home/yasir/AndroDR
python3 -m pytest .claude/commands/scripts/test_discover_source_urls.py -v
```
Expected: 2 passed (`test_skill_file_exists`, `test_each_source_url_has_exact_expected_url`). Also:
```bash
grep -c '^| `' .claude/commands/update-rules-discover.md  # expect: 7 (3 RSS + 4 web data rows — the lookout row is gone)
grep -n "EXPECTED_HOSTNAME_SUBSTRING" .claude/commands/update-rules-discover.md  # expect: no output
grep -n "8 sources\|/en/feed/\|cleafy-labs\|www.zimperium\|fetch_error: Cloudflare" .claude/commands/update-rules-discover.md  # expect: no output
grep -c "lookout" .claude/commands/update-rules-discover.md  # expect >= 2 (reference-only mentions retained: the table note + the Why-these-three blockquote)
```

- [ ] **Step 10: Commit**

```bash
git add .claude/commands/update-rules-discover.md .claude/commands/scripts/test_discover_source_urls.py
git commit -m "feat(discover): refresh moved URLs, drop Lookout, add liveness + cursor-reset rules

WLS feed moved to /en/rss/feed/, Cleafy Labs to cleafy.com/labs (source
silent since ~May when the URL moved), Zimperium dropped www. Lookout is
403-blocked on every fetch and becomes reference-only. New per-source
liveness log (live/moved/blocked/dead). URL change now resets the source's
discover cursor once (deletion of the whole source object — the schema
requires both cursor fields). URL-lock test upgraded from hostname
substring to exact URLs so same-host moves can't pass silently.

Co-Authored-By: Claude Code <noreply@anthropic.com>"
```

### Task 3: Dispatcher — combined sweep as the default mode

**Files:**
- Modify: `.claude/commands/update-rules.md:9-17,36-42,44-79,276-280,317-327`

**Interfaces:**
- Consumes: nothing from earlier tasks (independent of Tasks 1-2).
- Produces: the combined-sweep mode contract that Task 4's author split and Task 5's Jev step slot into; ledger mode `sweep` (list value added to `pipeline-runs/README.md` in Task 6); the covered-families list format consumed by the landscape-researcher brief.

- [ ] **Step 1: Make the combined sweep the no-arg default** (lines 9-17)

Replace:
```
## Parse Invocation

The user invokes one of four modes:
- `/update-rules full` — check all feeds for new threat intel
- `/update-rules source <id>` — check one feed (valid IDs: `abusech`, `asb`, `nvd`, `amnesty`, `stalkerware`, `attack`, `prodaft`)
- `/update-rules threat "<name>"` — research a specific threat by name
- `/update-rules discover [--top N]` — autonomously discover up to N (default 5) emerging threats from configured discovery sources and fan out to research subagents

If no argument is given, ask which mode to use.
```
with:
```
## Parse Invocation

The user invokes one of five modes:
- `/update-rules` (no args) — **combined sweep** (the default): one run with a discovery pass, one landscape researcher, and all seven feed ingesters
- `/update-rules full` — feeds-only sweep (kept for quick cursor advances; no discovery, no landscape researcher)
- `/update-rules source <id>` — check one feed (valid IDs: `abusech`, `asb`, `nvd`, `amnesty`, `stalkerware`, `attack`, `prodaft`)
- `/update-rules threat "<name>"` — research a specific threat by name
- `/update-rules discover [--top N]` — autonomously discover up to N (default 5) emerging threats from configured discovery sources and fan out to research subagents

If no argument is given, run the combined sweep — never ask.
```

- [ ] **Step 2: Add the covered-families derivation to Step 1** (append to Step 1's numbered list, after item 3)

```
4. Build the **covered-families list** for the landscape researcher brief:
   the union of family names appearing in the rule index (rule titles and
   descriptions) and in `ioc-data/*.yml` (`family:` values), deduplicated,
   comma-separated. Derived from the repo at run time — never persisted.
```

- [ ] **Step 3: Add the combined-sweep dispatch block to Step 2** (insert immediately after the "Based on the invocation mode:" line, before "**Full sweep:**")

```
**Combined sweep (no-arg default):** ONE parallel dispatch, in a single
message via the Agent tool, of:

- The discovery pass: `update-rules-discover` with `top_n=5` (the cap),
  `rule_index` from the existing rule glob, and `cursor_per_source` from
  `feed-state.json`'s `discover.sources` block — then one
  `update-rules-research-threat` subagent per discovered threat name, as
  the discover mode fans out today.
- **One landscape researcher** (`claude` subagent, NOT a feed ingester) with
  the standing brief below — the only new standing member of the sweep.
- All seven feed ingesters (`update-rules-ingest-abusech`, `-asb`, `-nvd`,
  `-amnesty`, `-stalkerware`, `-attack`, `-prodaft`) with their cursors,
  exactly as the full sweep dispatches them.

A single member's failure (feed failure, research subagent 429/timeout)
never aborts the sweep — log it and continue. The run's ledger mode is
`sweep`. Proceed to Step 3 with the union of all SIRs.

### Landscape researcher standing brief (combined sweep only)

> You are a threat-landscape researcher for a consumer Android EDR. Your
> job is to find the most important Android threats published in the
> window — not the ones any single feed surfaces. Survey these four areas,
> in this order:
>
> 1. Commercial stalkerware vendors and their apps (new products,
>    rebrands, capability updates to known vendors)
> 2. RAT builder kits and source-code leaks (Android spyware/RAT source
>    on GitHub, forums, Telegram channels)
> 3. Mercenary / commercial surveillance vendors (NSO-class and smaller;
>    new campaigns, forensic reports from Amnesty / Citizen Lab / Google TAG)
> 4. Surveillance SDKs embedded in otherwise-benign apps (analytics/ad
>    SDK scandals, data-broker SDKs)
>
> Rules:
> - Window: since **<the dispatcher fills in: the run date of the most
>   recent ledger in `pipeline-runs/` with mode `full`, `sweep`, or
>   `discover`; if none exists, the last 8 weeks>**.
> - Dedup-aware: you are given a covered-families list (families already
>   tracked by the rule index and `ioc-data/*.yml`). Skip a threat whose
>   family is on the list UNLESS the new reporting adds indicators or
>   behavior beyond what is already tracked.
> - Return AT MOST 8 SIRs, ranked by consumer-EDR detection value.
> - NEVER invent IOCs. Every indicator must come from a cited public
>   source, source-tagged `threat_research`. A SIR resting on a single
>   unstructured source sets `requires_verification: true`.
> - Consumer lens: prioritize what an EDR on the victim's device can
>   actually detect (installed apps, permissions, files, DNS, processes)
>   over network-infrastructure or purely victim-side intel.
> - Emit SIRs in the same shape as `update-rules-research-threat`
>   (`source`, `threat`, `indicators`, `behavioral_signals`,
>   `attack_techniques`, `confidence`, `rule_hint`,
>   `requires_verification`).
```

- [ ] **Step 4: Note the combined flow at Step 3** (append to Step 3, after the two existing bullets)

```
- In a combined sweep, the pool mixes feed SIRs, discovered-threat SIRs,
  and landscape-researcher SIRs — one pool, one triage, same rules. The
  per-source liveness statuses from the discovery pass are reported in the
  run summary alongside per-feed statuses.
```

- [ ] **Step 5: Record the ledger mode** (in Step 8.3 of the dispatcher, insert after the first sentence — after `(schema in \`pipeline-runs/README.md\`).` — and before `Record per candidate:`)

```
Combined-sweep runs use mode `sweep` in both the file name
(`YYYY-MM-DD-sweep.yml`) and the ledger's `mode:` field.
```

- [ ] **Step 6: Replace the composite-mode safety rule** (Safety Rules section)

Replace:
```
- NEVER include `full-with-discover` as a composite mode. Users wanting
  both should run `/update-rules full` then `/update-rules discover`
  back-to-back.
```
with:
```
- NEVER dispatch the combined sweep's discovery pass without a top-N
  bound. The default (5) IS the cap — the combined sweep inherits it. A
  pathologically noisy extraction run must not spawn dozens of research
  subagents inside a sweep that already carries a landscape researcher
  and seven feed ingesters.
```

- [ ] **Step 7: Verify**

```bash
cd /home/yasir/AndroDR
grep -c "combined sweep" .claude/commands/update-rules.md   # expect >= 3 (invocation, Step 2, Step 3 note)
grep -n "ask which mode" .claude/commands/update-rules.md    # expect: no output
grep -n "full-with-discover" .claude/commands/update-rules.md # expect: no output
```

- [ ] **Step 8: Commit**

```bash
git add .claude/commands/update-rules.md
git commit -m "feat(dispatcher): research-led combined sweep as the default mode

No-arg /update-rules now runs one parallel dispatch: discovery pass (top-5
capped) + per-threat researchers + one landscape researcher (standing brief
over 4 areas, dedup-aware, <=8 SIRs, consumer lens, no invented IOCs) + all
7 feed ingesters. The old 'never merge full-with-discover' rule is replaced
by the bounded combined mode. Ledger mode: sweep.

Co-Authored-By: Claude Code <noreply@anthropic.com>"
```

### Task 4: Dispatcher — author-stage split (IOC-only bypass, shards, intrusion-log surfaces)

**Files:**
- Modify: `.claude/commands/update-rules.md:89-109` (Step 4, full replacement)
- Modify: `.claude/commands/update-rules.md:169-189` (Step 7, one added line)

**Interfaces:**
- Consumes: Task 3's combined-sweep flow (the SIR pool reaches Step 4 unchanged).
- Produces: the shard input contract (batch of 3-5 SIRs + assigned provisional ID range; the author's existing "Rule IDs are provisional" paragraph in `update-rules-author.md:131-134` already documents the renumber — no author-skill edit needed); the `ATT&CK (Jev):` gate line that Task 5 fills.

- [ ] **Step 1: Replace Step 4 wholesale** (lines 89-109)

Replace the entire current "## Step 4: Generate Rules" section with:

```
## Step 4: Generate Rules

Split the SIR pool by shape BEFORE dispatching any author.

### 4.1 IOC-only SIRs bypass the author

A SIR is **IOC-only** when its actionable content is purely indicators —
package names, domains, hashes, cert hashes — with NO behavioral signal
(`rule_hint: ioc_lookup` and no `behavioral_signals`). The author's own
Decision Gate would emit IOC data for it and no rule; dispatching an
author is pure cost. Route an IOC-only SIR's `candidate_ioc_entries`
straight to Step 6.5 and the HitL gate — NO author agent. Log the bypass
in the run summary (count + SIR ids).

A SIR with ANY behavioral signal — even one that also carries indicators
(`rule_hint: hybrid`) — goes to the author. When in doubt, author it.

### 4.2 Author shards for rule-shaped SIRs

1. Read the logsource field taxonomy first:
   1. Read `third-party/android-sigma-rules/validation/logsource-taxonomy.yml`
   2. Map the SIRs' `rule_hint` values to services:
      - `ioc_lookup` → `app_scanner` (package names), `dns_monitor` (domains)
      - `behavioral` → `app_scanner`, `accessibility_audit`, `appops_audit`, `receiver_audit`
      - `device_posture` → `device_auditor`
      - `network` → `dns_monitor`, `network_monitor`
      - `hybrid` → all of the above
   3. **Filter out services with `status: unwired`** before extracting fields — rules targeting them cannot fire. The Rule Author will record a `telemetry_gap` decision if the SIR requires such a service. (As of 2026-10-14 every service in the taxonomy is `active`; the filter stays as the guard for future unwired services.)
   4. Extract the `fields:` blocks for the remaining services.

2. **Intrusion-log surfaces — give the author this context verbatim:**

   > `dns_monitor`, `network_monitor`, and `security_log` all evaluate
   > imported Android Advanced Protection logs on-device:
   > `IntrusionLogAnalyzer.kt` runs `evaluateDns` + `evaluateNetwork` +
   > `evaluateSecurityLog` over the COMPLETE parsed stream. `security_log`
   > currently has ZERO rules — it is an open surface. Available fields:
   > dns_monitor: `domain`, `app_uid`, `source_package`, `is_blocked`,
   > `reason`. network_monitor: `destination_ip`, `destination_port`,
   > `protocol`, `app_uid`, `app_name`, `timestamp`, `source`,
   > `captured_at`. security_log: `timestamp`, `tag`, `tag_name`,
   > `security_data`, `source`, `captured_at`. Domain IOCs match
   > retroactively against up to 12 months of imported history. A SIR
   > that fits these surfaces may target them (e.g. a mercenary-spyware
   > install chain leaving `adb_shell_cmd` / `app_process_start` security
   > events).

3. Shard the rule-shaped SIRs into batches of ~3-5 and dispatch ONE
   author agent (`update-rules-author`) per shard in a single message
   (multiple Agent tool uses for true parallelism). The dispatcher
   pre-assigns each shard a provisional rule-ID range from the next
   available ID (e.g. shard 1: 096-100, shard 2: 101-105) so shards
   cannot collide. Each shard receives:
   - Its batch of SIRs
   - Its assigned ID range (provisional — the dispatcher renumbers after)
   - The next available rule ID context, 5 existing production rules as
     style examples (pick diverse services/types), the existing rule
     index (semantic dedup against PRODUCTION rules stays — that is
     judgment, not bookkeeping), the extracted taxonomy field blocks,
     and `validation/authoring-lessons.yml` (missing/unparseable →
     dispatch without it and log a warning — never fail the run over
     lessons)

   Cross-shard dedup is NOT the author's job — Step 6.5 is the only
   dedup gate for IOC data, and cross-shard semantic duplicates surface
   at Step 7 (below).

4. After all shards return: **renumber** all CandidateRules into one
   sequential block starting at the next available ID (the author skill's
   "Rule IDs are provisional" paragraph documents this contract). While
   renumbering, flag any two candidates with the same service whose
   selection blocks overlap substantially — present the overlap as a
   REVIEW NOTE at Step 7 and let the human decide. NEVER silently drop
   either.

Each author shard returns a list of CandidateRule objects (YAML + decision
manifest); the dispatcher merges the shard outputs before Step 5.
```

- [ ] **Step 2: Add the Jev gate line to Step 7's passing-candidate block** (after the existing `ATT&CK:      [technique IDs]` line)

```
ATT&CK (Jev): [top-3 suggested techniques with the author's tags marked; or "(unavailable — logged)"]
```

(This line is presented only when Task 5's suggester ran; the suggester is advisory — its suggestions are never auto-applied.)

- [ ] **Step 3: Verify**

```bash
cd /home/yasir/AndroDR
grep -n "status: unwired.*network_monitor\|skip \`network_monitor\`" .claude/commands/update-rules.md  # expect: no output
grep -c "4.1 IOC-only SIRs bypass\|4.2 Author shards\|Intrusion-log surfaces" .claude/commands/update-rules.md  # expect: 3
grep -n "ATT&CK (Jev)" .claude/commands/update-rules.md  # expect: 1 hit (Step 7 block)
```

- [ ] **Step 4: Commit**

```bash
git add .claude/commands/update-rules.md
git commit -m "feat(dispatcher): shard the author, bypass IOC-only SIRs, open intrusion-log surfaces

IOC-only SIRs (ioc_lookup, no behavioral signals) route straight to
cross-dedup + gate — no author agent (July run's cost center). Rule-shaped
SIRs go to parallel author shards of 3-5 with pre-assigned provisional ID
ranges; the dispatcher renumbers into one sequential block. The stale
'network_monitor is unwired' note is removed (all taxonomy services are
active; IntrusionLogAnalyzer evaluates dns/network/security rules over
imported Advanced Protection logs — security_log has zero rules and is an
open surface). Step 7 gains the advisory 'ATT&CK (Jev):' line.

Co-Authored-By: Claude Code <noreply@anthropic.com>"
```

### Task 5: Jev ATT&CK tag suggester (script + tests + dispatcher wiring)

**Files:**
- Create: `.claude/commands/scripts/jev_suggest.py`
- Create: `.claude/commands/scripts/test_jev_suggest.py`
- Modify: `.claude/commands/update-rules.md` (new "Step 4.5" section between Step 4 and Step 5)

**Interfaces:**
- Consumes: the renumbered CandidateRule list from Task 4's Step 4.4; the frozen trial's registered materials — battery `criteria/B1_nouls.json`, model `jev-1.13.0`, endpoint `https://api.typesafe.ai`, SDK + HTTP client vendored in `/home/yasir/projects/jev-androdr-eval` (commit `d89e1b3`; trial preregistration frozen at `339e907`); the API key from the GNOME keyring (`secret-tool lookup service jev-androdr account typesafe`) piped on stdin.
- Produces: stdout JSONL, one record per candidate: `{"id": <rule id>, "model": "jev-1.13.0", "top3": [{"technique": "T1430", "p": 0.9}, ...]}` (or `"error": {type, status, request_id}`). Exit codes: 0 = emitted (per-candidate errors recorded inline); 3 = no key or missing battery; 4 = every candidate errored. The dispatcher treats 3/4 exactly the same: WARN + author tags stand.

**Provenance note (spec §3.4 divergence, resolved):** spec §3.4's parenthetical says "local scorer through the user's Ollama Cloud server", but §3.4 also says "The implementation plan pins the exact call, model tag, and prompt battery from the Jev trial's **registered materials**" — and those materials pin model `jev-1.13.0` via `https://api.typesafe.ai` (`typesafe_sdk` + `httpx2`, key from the GNOME keyring). This plan follows the registered materials; the Ollama-Cloud route in project memory applies to other heavy inference, not the Jev battery.

- [ ] **Step 1: Write the failing tests** (`.claude/commands/scripts/test_jev_suggest.py`)

```python
"""Unit tests for jev_suggest.py — pure functions + fail-open paths.

The live API path mirrors the frozen trial harness (jev-androdr-eval @
d89e1b3) and is exercised only in a real sweep; these tests pin what can
silently break between runs: the registered B-item state shape, the
registered ranking semantics (score.jev_b1_ranking: descending score,
tie-break by technique ID), and the fail-open exit codes the dispatcher
depends on (3 = no key/battery, 4 = all candidates errored).
"""
import importlib.util
import json
import pathlib
import subprocess
import sys
import tempfile

SCRIPT = pathlib.Path(__file__).resolve().parent / "jev_suggest.py"


def load_module():
    spec = importlib.util.spec_from_file_location("jev_suggest", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_build_state_matches_registered_b_item_shape():
    mod = load_module()
    state = mod.build_state({
        "id": "x", "title": "T", "description": "D",
        "detection": "condition: selection", "service": "app_scanner",
    })
    assert state == {
        "title": "T", "description": "D",
        "detection": "condition: selection", "service": "app_scanner",
    }


def test_rank_top3_descending_then_id_tiebreak():
    mod = load_module()
    nouls = {"T1429": 0.9, "T1430": 0.9, "T1404": 0.8, "T1417": 0.7}
    top3 = mod.rank_top3(nouls)
    assert [t["technique"] for t in top3] == ["T1429", "T1430", "T1404"]
    assert top3[0]["p"] == 0.9


def test_rank_top3_fewer_than_three():
    mod = load_module()
    assert [t["technique"] for t in mod.rank_top3({"T1404": 0.5})] == ["T1404"]


def test_no_key_exits_3():
    with tempfile.NamedTemporaryFile("w", suffix=".jsonl", delete=False) as c, \
         tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as b:
        c.write(json.dumps({"id": "x", "title": "t", "description": "d",
                            "detection": "c", "service": "s"}) + "\n")
        b.write("{}")
        cpath, bpath = c.name, b.name
    r = subprocess.run(
        [sys.executable, str(SCRIPT), "--candidates", cpath, "--battery", bpath],
        input="\n", capture_output=True, text=True)
    assert r.returncode == 3
    assert "no key" in r.stderr


def test_missing_battery_exits_3_even_with_key():
    with tempfile.NamedTemporaryFile("w", suffix=".jsonl", delete=False) as c:
        c.write("{}\n")
        cpath = c.name
    r = subprocess.run(
        [sys.executable, str(SCRIPT), "--candidates", cpath,
         "--battery", "/nonexistent/B1_nouls.json"],
        input="fake-key\n", capture_output=True, text=True)
    assert r.returncode == 3
    assert "battery" in r.stderr


def test_exit_code_all_errors_is_4():
    mod = load_module()
    assert mod.exit_code(3, 0) == 4   # every candidate errored
    assert mod.exit_code(3, 1) == 0   # partial success still emits + exit 0
    assert mod.exit_code(0, 0) == 0   # empty input is vacuous success
```

- [ ] **Step 2: Run the tests to verify they fail**

```bash
cd /home/yasir/AndroDR
python3 -m pytest .claude/commands/scripts/test_jev_suggest.py -v
```
Expected: all 6 FAIL — `jev_suggest.py` does not exist (file-not-found errors).

- [ ] **Step 3: Write the script** (`.claude/commands/scripts/jev_suggest.py`)

```python
#!/usr/bin/env python3
"""Jev ATT&CK Mobile tag suggester — pipeline Step 4.5 (advisory, fail-open).

Registered materials (Jev trial, Study B ADOPT): battery
criteria/B1_nouls.json and ranking semantics from jev-androdr-eval @
d89e1b3 (trial preregistration frozen at 339e907); model jev-1.13.0 via
https://api.typesafe.ai.

The API key arrives on stdin (piped from:
    secret-tool lookup service jev-androdr account typesafe
) — never argv, env, or files.

Input:  --candidates FILE — JSONL of {id, title, description, detection, service}
        --battery PATH   — default $JEV_EVAL_REPO/criteria/B1_nouls.json
Output: stdout JSONL {id, model, top3: [{technique, p}...]} in input order;
        a candidate that errors emits {id, model, error: {type, status,
        request_id}} instead — type/status/request_id only, never the
        server text (trial rule).
Exit:   0 = emitted (possibly with per-candidate errors);
        3 = no key or missing battery; 4 = every candidate errored.
The dispatcher treats 3/4/all-errors identically: WARN, author tags stand.
"""
import argparse
import json
import os
import sys

MODEL = "jev-1.13.0"
BASE_URL = "https://api.typesafe.ai"
DEFAULT_EVAL_REPO = "/home/yasir/projects/jev-androdr-eval"
TOP_N = 3


def build_state(candidate):
    """The B-item state shape the battery was registered against
    (jev-androdr-eval src/items.py b_state: title/description/detection/service)."""
    return {
        "title": candidate["title"],
        "description": candidate["description"],
        "detection": candidate["detection"],
        "service": candidate["service"],
    }


def rank_top3(nouls):
    """Registered ranking (jev-androdr-eval src/score.py jev_b1_ranking):
    descending yes-score, ties broken by technique ID."""
    ranked = sorted(nouls.items(), key=lambda kv: (-kv[1], kv[0]))
    return [{"technique": t, "p": p} for t, p in ranked[:TOP_N]]


def exit_code(n_candidates, n_ok):
    """Fail-open contract: all-errored is 4 (loud), everything else is 0.
    Pinned by test so an API outage can never masquerade as 'the model
    returned no suggestions'."""
    return 4 if n_candidates and n_ok == 0 else 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--candidates", required=True)
    ap.add_argument("--battery", default=None)
    args = ap.parse_args()

    eval_repo = os.environ.get("JEV_EVAL_REPO", DEFAULT_EVAL_REPO)
    battery_path = args.battery or os.path.join(eval_repo, "criteria", "B1_nouls.json")
    try:
        with open(battery_path) as f:
            battery = json.load(f)
    except OSError as e:
        print(f"jev: battery missing/unreadable: {battery_path}: {e}", file=sys.stderr)
        return 3

    key = sys.stdin.readline().strip()
    if not key:
        print("jev: no key on stdin", file=sys.stderr)
        return 3

    # The trial's SDK + HTTP client are installed in the eval repo's venv —
    # the same interpreter scripts/jev pins. This script must be run with
    # that venv's python (the dispatcher command does); no sys.path games.
    import httpx2  # noqa: E402
    import typesafe_sdk as ts  # noqa: E402

    with open(args.candidates) as f:
        candidates = [json.loads(line) for line in f if line.strip()]

    client = ts.TypeSafeClient(
        api_key=key, model=MODEL, base_url=BASE_URL,
        http_client=httpx2.Client(trust_env=False, timeout=60))
    del key

    n_ok = n_err = 0
    for cand in candidates:
        rec = {"id": cand["id"], "model": MODEL}
        try:
            resp = client.system_one(build_state(cand), battery)
            rec["top3"] = rank_top3({qid: a.noul for qid, a in resp.nouls.items()})
            n_ok += 1
        except ts.TypeSafeError as e:
            rec["error"] = {"type": type(e).__name__,
                            "status": getattr(e, "status", None),
                            "request_id": getattr(e, "request_id", None)}
            n_err += 1
        print(json.dumps(rec, sort_keys=True))
        sys.stdout.flush()

    if candidates and n_ok == 0:
        print(f"jev: every candidate errored ({n_err})", file=sys.stderr)
    return exit_code(len(candidates), n_ok)


if __name__ == "__main__":
    sys.exit(main())
```

- [ ] **Step 4: Run the tests to verify they pass**

```bash
cd /home/yasir/AndroDR
python3 -m pytest .claude/commands/scripts/test_jev_suggest.py -v
```
Expected: 6 passed. (None of the tests touch the network or the keyring; the no-key/no-battery paths exit before the SDK import.)

- [ ] **Step 5: Wire Step 4.5 into the dispatcher** (`.claude/commands/update-rules.md`, insert between Step 4 and Step 5)

```
## Step 4.5: Jev ATT&CK tag suggester (advisory, fail-open)

After the author shards return and candidates are renumbered, write every
passing CandidateRule to `/tmp/jev-candidates-<runid>.jsonl` (one JSON
object per line: `id`, `title`, `description`, `detection` — the rule's
detection block as text — `service`), then run:

```bash
secret-tool lookup service jev-androdr account typesafe \
  | /home/yasir/projects/jev-androdr-eval/.venv/bin/python -I \
      .claude/commands/scripts/jev_suggest.py \
      --candidates /tmp/jev-candidates-<runid>.jsonl
```

The eval repo is the frozen trial harness (`jev-androdr-eval` @ `d89e1b3`);
its `.venv` python provides the `typesafe_sdk` + `httpx2` the script
imports (the same interpreter `scripts/jev` pins). The script loads the
registered B1 battery (`criteria/B1_nouls.json`) from that repo; the
`JEV_EVAL_REPO` env var can override the repo path (default
`/home/yasir/projects/jev-androdr-eval`). The script calls model
`jev-1.13.0` via `https://api.typesafe.ai` and emits each candidate's
top-3 ATT&CK Mobile techniques with scores.

**Fail-open is mandatory.** Exit 3 (no key / missing battery), exit 4
(all candidates errored), or a script crash → log a WARN ("Jev unavailable —
author tags stand") and continue to Step 5. NEVER block the pipeline on
Jev, NEVER retry it inside the run, NEVER auto-apply a suggestion — the
trial verdict adopted it as an advisory suggester only (Recall@3 0.971;
scores stay non-gating — miscalibration persists, ECE ≈ 0.2). Delete the
/tmp candidates file after the gate. At Step 7, each candidate's block
gains the `ATT&CK (Jev):` line showing the top-3 suggestions with the
author's own tags marked.
```

- [ ] **Step 6: Verify**

```bash
cd /home/yasir/AndroDR
python3 -m pytest .claude/commands/scripts/test_jev_suggest.py .claude/commands/scripts/test_discover_source_urls.py -v
grep -c "Step 4.5: Jev" .claude/commands/update-rules.md          # expect: 1
grep -n "jev-1.13.0\|api.typesafe.ai" .claude/commands/update-rules.md  # expect: hits only in Step 4.5
grep -rn "secret-tool" .claude/ --include="*.md" | grep -v "stdin\|lookup"  # expect: no output (key never lands in argv/env/files)
```

- [ ] **Step 7: Commit**

```bash
git add .claude/commands/scripts/jev_suggest.py .claude/commands/scripts/test_jev_suggest.py .claude/commands/update-rules.md
git commit -m "feat(jev): advisory ATT&CK tag suggester wired as fail-open Step 4.5

Jev trial Study B ADOPT (Recall@3 0.971 vs 0.229 baseline): the B1 battery
(criteria/B1_nouls.json, eval repo @ d89e1b3), model jev-1.13.0 via
api.typesafe.ai, key from the GNOME keyring on stdin. Advisory + fail-open:
exit 3/4 or crash -> WARN, author tags stand, never retried in-run, never
auto-applied (scores stay non-gating). Unit tests pin the registered state
shape, ranking semantics, and fail-open exit codes.

Co-Authored-By: Claude Code <noreply@anthropic.com>"
```

### Task 6: Rules-repo PR — discover cursor reset + ledger `sweep` mode

**Files (sigma repo, inside the submodule):**
- Modify: `third-party/android-sigma-rules/feed-state.json` (delete 3 source objects under `discover.sources`)
- Modify: `third-party/android-sigma-rules/pipeline-runs/README.md:7-8` (mode list)

**Interfaces:**
- Consumes: Task 2's cursor-reset rule (this task APPLIES it at merge time, as the spec directs: "Apply at merge time for the three moved sources").
- Produces: a merged rules-repo commit that Task 7's AndroDR PR points the submodule at. The deleted cursors cause the next discovery pass to re-scan WLS/Cleafy/Zimperium from scratch and write fresh cursors.

- [ ] **Step 1: Branch in the submodule**

```bash
cd /home/yasir/AndroDR/third-party/android-sigma-rules
git fetch origin
git checkout -b pipeline/discover-cursor-reset-and-sweep-mode origin/main
```

- [ ] **Step 2: Delete the three cursor objects** from `discover.sources` in `feed-state.json` (a reset is a whole-object deletion — `DiscoverSourceCursor` REQUIRES both `last_seen_timestamp` and `last_post_url`, so a "reset" cannot blank fields):

Delete exactly these three objects (WeLiveSecurity, Zimperium, Cleafy — the moved URLs; their cursors reset once so the next pass re-scans from scratch):

```
"welivesecurity": {
    "last_seen_timestamp": "2026-08-17T09:00:00Z",
    "last_post_url": "https://www.welivesecurity.com/en/business-security/qr-code-phishing-slip-past-corporate-security-measures/"
},
"zimperium": {
    "last_seen_timestamp": "2026-08-20T00:00:00Z",
    "last_post_url": "https://zimperium.com/blog/mobile-threat-watch/device-code-phishing-up-1500"
},
"cleafy": {
    "last_seen_timestamp": "2026-05-18T00:00:00Z",
    "last_post_url": "https://cleafy.com/cleafy-labs/nfc-relay-goes-local-how-ai-is-accelerating-a-new-wave-of-independent-malware-developers"
},
```

Keep `securelist`, `google-tag`, `threatfabric`, `group-ib` untouched.
`lookout` needs NO deletion — it never earned a cursor (a source that
always 403s never appears in `updated_cursors`, and the current file has
no `lookout` entry; its removal is handled skill-side in Task 2). Mind
the trailing commas when deleting objects out of the middle so the JSON
stays well-formed. (If the JSON on the branch differs from the values
above, delete the objects by source-id name, not by value.)

- [ ] **Step 3: Add `sweep` to the ledger mode list** (`pipeline-runs/README.md`, lines 7-8)

Replace:
```
File name: `YYYY-MM-DD-<mode>.yml` (mode: `full`, `source-<id>`, `threat`,
`discover`, or `e2e`; append `-2`, `-3`… for multiple same-day runs).
```
with:
```
File name: `YYYY-MM-DD-<mode>.yml` (mode: `full`, `source-<id>`, `threat`,
`discover`, `sweep`, or `e2e`; append `-2`, `-3`… for multiple same-day
runs). `sweep` = the combined research-led run (discovery pass + landscape
researcher + all feeds), the pipeline's no-arg default since 2026-10.
```

- [ ] **Step 4: Validate the state before committing**

```bash
cd /home/yasir/AndroDR/third-party/android-sigma-rules
python3 validation/validate-feed-state.py
```
Expected: exit 0 (the three deletions are schema-legal — `discover.sources` has no required source keys). If it exits non-zero, fix the JSON; do NOT commit a state that fails validation.

- [ ] **Step 5: Commit + push + PR (rules repo)**

```bash
git add feed-state.json pipeline-runs/README.md
git commit -m "pipeline: reset discover cursors for moved URLs, add sweep ledger mode

WeLiveSecurity/Cleafy/Zimperium URLs moved (old URLs redirect); per the
cursor-reset-once rule their discover cursors are deleted so the next pass
re-scans from scratch (Cleafy was silent ~5 months through its URL move).
Lookout has no cursor to reset — it never advanced past its 403s and its
removal is handled skill-side. Ledger mode list gains 'sweep' — the
combined research-led run shape.

Co-Authored-By: Claude Code <noreply@anthropic.com>"
git push -u origin pipeline/discover-cursor-reset-and-sweep-mode
gh pr create --repo yasirhamza/android-sigma-rules \
  --base main --head pipeline/discover-cursor-reset-and-sweep-mode \
  --title "pipeline: discover cursor reset for moved URLs + sweep ledger mode" \
  --body "..."
```
PR body: same rationale as the commit message, note that neither file is listed in `rules.txt` so no `rules.sha256` regeneration applies, end with `🤖 Generated with [Claude Code](https://claude.com/claude-code)`.

- [ ] **Step 6: Wait for green `validate`, then merge** (never merge on red; never direct-push). Record the merged commit SHA for Task 7.

### Task 7: PRs, submodule bump, rollout + dogfood

**Files:**
- Modify: `docs/superpowers/specs/2026-10-14-pipeline-rework-design.md` + this plan (already committed on `docs/pipeline-rework-design` — merge via their own docs PR first)
- Modify: `third-party/android-sigma-rules` (gitlink bump on `feat/pipeline-rework`)

**Interfaces:**
- Consumes: Tasks 1-5 commits on `feat/pipeline-rework`; Task 6's merged rules-repo SHA.
- Produces: merged PRs; a fresh-session dogfood run whose ledger is the acceptance evidence.

- [ ] **Step 1: Merge the docs PR** — `docs/pipeline-rework-design` (spec commit `4f77fde` + this plan) → PR to `main`, wait for `ci-success`, merge.

- [ ] **Step 2: Bump the submodule on `feat/pipeline-rework`** (only after Task 6's rules PR is merged)

```bash
cd /home/yasir/AndroDR
git -C third-party/android-sigma-rules fetch origin
git -C third-party/android-sigma-rules checkout origin/main
git add third-party/android-sigma-rules
git commit -m "build: bump android-sigma-rules submodule (discover cursor reset + sweep ledger mode)

Co-Authored-By: Claude Code <noreply@anthropic.com>"
```
(Do NOT stage anything else with the gitlink bump; the AndroDR-side change is only the submodule pointer.)

- [ ] **Step 3: Open the implementation PR**

```bash
git push -u origin feat/pipeline-rework
gh pr create --base main --head feat/pipeline-rework \
  --title "feat(pipeline): research-led combined sweep rework" \
  --body "..."
```
PR body: summary of Tasks 1-5 (one line each), links to the spec and plan, the Review Focus list, the Jev provenance line (eval repo @ `d89e1b3`, model `jev-1.13.0`, Study B ADOPT), the dogfood note (markdown is not hot-reloaded — first exercised by the next no-arg sweep in a fresh session), and `🤖 Generated with [Claude Code](https://claude.com/claude-code)`.

- [ ] **Step 4: Wait for `ci-success`, then merge.**

- [ ] **Step 5: Dogfood + acceptance evidence.** In a FRESH session (skill markdown is not hot-reloaded), run `/update-rules` with no arguments. The first combined sweep is the rework's acceptance test (spec §4); compare its ledger (`pipeline-runs/YYYY-MM-DD-sweep.yml`) against historical runs on: SIRs reaching the author stage (should drop sharply), author-stage wall-time, rules generated per sweep, `approval_without_modification_rate` (must not regress), and every discover source reporting a liveness status. Prose-only skill edits have no unit-test surface — the ledger is their deterministic record.