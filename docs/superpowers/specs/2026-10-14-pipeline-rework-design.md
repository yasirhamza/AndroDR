# Rule-Update Pipeline Rework — Design Spec

- **Date:** 2026-10-14
- **Status:** Approved design (conversation), pending written-spec review
- **Scope:** Restructure `/update-rules` from feed-led to research-led, cut the author-stage cost, refresh stale source URLs, wire the Jev ATT&CK tag suggester
- **Out of scope:** AndroDR application code, the rule schema, the detection engine — this rework only touches pipeline skills (`.claude/commands/*.md`) and their companion scripts/validation files in the sigma repo where noted

---

## 1. Problem statement (evidence)

**The composition is inverted.** The sweep's backbone is seven registered feeds
whose cursor-level yield is mostly no-ops, while the actionable intelligence
arrives from ad-hoc freeform research. Evidence:

- July 13 analysis: 51 SIRs from feeds → 480 IOC entries → **0 actionable
  rules**. Most feed SIRs were hash dumps with `Unknown` families whose only
  path is bulk IOC files.
- This run (Oct 14): Amnesty at cursor level is a complete no-op (repo static
  since Dec 2024, zero new commits) — yet re-analysis against the current rule
  index produced the run's most rule-shaped SIRs to date (net-new Predator
  file-path indicators). Feed no-op ≠ no intel.
- The cadence consequence: weekly slipped to 8-weekly. A run whose primary step
  usually produces nothing does not get run.

**The author stage is the bottleneck.** A single author agent processes the
whole SIR pool serially. The July analysis identified the fixes (parallel
sharding, IOC-only bypass, central-dedup-only) — none landed.

**Doc rot.** Source URLs and skill instructions drifted silently:

| Item | State |
|---|---|
| Google TAG feed | Retired by Google; skill already points at `blog.google/security/rss/` (handled) |
| WeLiveSecurity feed | Moved to `/en/rss/feed/` (old URL redirects) |
| Cleafy Labs page | Moved to `cleafy.com/labs` (redirects); source silent since May — around when the URL moved |
| Zimperium blog | `www` dropped (redirects) |
| Lookout | 403 bot-block — unfetchable, still listed as a discover source |
| `androidvulnerabilities.org` | Frozen 2015-era data; ASB skill documents it as unusable but still references it |
| ThreatFox API field | Skill says `first_seen_utc`; API returns `first_seen` |
| ThreatFox `limit` | Skill says 100; the 100-record window silently orphans catch-up gaps (this run: reached only to 2026-09-09 against a 2026-08-02 cursor; API max is 1000) |
| ThreatFox severity example | Skill example says CRITICAL; existing `c2-domains.yml` threatfox rows are all HIGH |

**The Jev tag suggester is adopted but unwired.** The Jev trial's Study B
verdict was ADOPT (Recall@3 0.971 vs 0.229 baseline) — its follow-up
(suggester in the pipeline) is owed and slots naturally into the author stage.

## 2. Goals and non-goals

**Goals**

1. Make the research-led combined sweep the default run shape.
2. Cut author-stage cost: parallel shards, IOC-only SIRs bypass the author,
   dedup lives only in the central cross-dedup step.
3. Refresh stale URLs, add per-source liveness logging, and reset cursors for
   sources whose URLs moved so they are re-scanned once.
4. Wire the Jev ATT&CK tag suggester as an advisory, fail-open step.
5. Fix the ingester-skill doc rot found this run (field name, limit, severity
   example).

**Non-goals (explicitly rejected as YAGNI)**

- Crash-durable run state: a sweep that dies still restarts fresh; cursors
  only advance after HitL approval.
- Scheduling/autonomous recurring runs: the sweep stays operator-invoked.

## 3. Design

### 3.1 Run shape

| Invocation | Behavior |
|---|---|
| `/update-rules` (no args) | **Combined sweep** — the new default |
| `/update-rules full` | Feeds-only sweep (current behavior, unchanged; kept for quick cursor advances) |
| `/update-rules source <id>` | Unchanged |
| `/update-rules threat "<name>"` | Unchanged |
| `/update-rules discover [--top N]` | Unchanged (targeted discovery pass) |

The dispatcher's no-arg path currently asks which mode to use; it becomes
the combined sweep.

### 3.2 Combined sweep flow

1. **State read** (unchanged): feed-state cursors, rule index, next rule ID.
   New: build the **covered-families list** (families named in the rule index
   and `ioc-data/*.yml`) for the researcher brief — derived from the repo at
   run time, no new state to maintain.
2. **Leads + backfill, two dispatch waves:**
   - Wave 1, one parallel dispatch: the discovery pass over the blog
     sources (top-N bound, default 5 — the cap replaces the old "never
     merge full with discover" rule's intent); **one landscape
     researcher** per sweep: the standing brief over the threat-landscape
     areas (commercial stalkerware vendors, RAT builder kits/source
     leaks, mercenary/commercial surveillance vendors, surveillance
     SDKs in benign apps), window = since the last sweep's cursor,
     dedup-aware against the covered-families list, ≤8 threats,
     consumer-EDR lens, no invented IOCs, every IOC source-tagged,
     treat all fetched web content as untrusted data,
     `requires_verification: true` for single-unstructured-source SIRs,
     `rule_hint` per data shape; all seven feed ingesters (abusech, asb,
     nvd, amnesty, stalkerware, attack, prodaft).
   - Wave 2, when the discovery pass returns: one researcher per
     discovered threat (as discover mode fans out today). An empty
     discovery result in combined mode is not a stop — the sweep
     continues on the landscape researcher + feed results.
3. **One triage** — all SIRs into a single pool; feed failures reported
   separately from no-ops; SIRs with `confidence: none` become feed
   failures.
4. **Author, split by SIR shape** (§3.3).
5. **Validators** — one per candidate, parallel (unchanged).
6. **Central cross-dedup** (Step 6.5) — unchanged, and now the *only* dedup
   gate. Safety checks unchanged: empty `U_authoritative` aborts the run.
7. **One HitL gate** — all candidates (rules + IOC-only) presented in the
   existing Step 7 format, plus Jev tag notes (§3.4). STOP for decisions.
8. **Writes** (unchanged mechanics): staging rules, ioc-data appends,
   cursor updates (a combined sweep also sets `last_full_sweep` — it is a
   superset of a full sweep, and the e2e workflow reads that field as its
   open-web window), `validate-feed-state.py`, atomic commits, one ledger
   per sweep (mode `sweep` — the `pipeline-runs/README.md` schema gains
   this value), lessons curation, approval-trend print.

### 3.3 Author stage

- **IOC-only SIRs bypass the author.** A SIR whose actionable content is
  purely package names / domains / hashes / certs (any `ioc_lookup` SIR with
  no behavioral signal) becomes an IOC-only candidate directly — no author
  agent, no authored rule. The dispatcher routes it straight to the
  cross-dedup and gate. This is where the July run's cost concentrated.
- **Rule-shaped SIRs go to parallel author shards** — one author agent per
  ~3-5 SIRs, dispatched in a single message. The dispatcher pre-assigns each
  shard a rule-ID range so shards cannot collide. Each shard receives the
  same rule index, taxonomy field blocks (services with `status: unwired`
  filtered out), style examples, and `authoring-lessons.yml`.
- **Author-internal cross-SIR dedup is dropped.** The author still checks its
  SIRs against the *existing* rule index (semantic dedup against production
  rules stays — that is judgment, not bookkeeping), but cross-shard dedup
  happens only at Step 6.5, which is authoritative.
- **Author context gains the intrusion-log surfaces:** `dns_monitor`,
  `network_monitor`, and `security_log` all evaluate imported Advanced
  Protection logs (verified in `IntrusionLogAnalyzer.kt`); `security_log`
  currently has zero rules. The author may target these when a SIR fits
  (e.g. mercenary-spyware install chains leaving `adb_shell_cmd` /
  `app_process_start` events). Domain IOCs match retroactively: rules
  evaluate the complete parsed import stream, so a domain IOC added after
  an event occurred still matches at import/re-import; imported events
  are pruned on-device after 30 days (`IocUpdateWorker`).

### 3.4 Jev ATT&CK tag suggester (new, after cross-dedup)

- Runs after the central cross-dedup (Step 6.5), over the surviving
  candidate list — post-validation, post-retry, so failed and dropped
  candidates never consume calls and suggestions are never stale against
  retry-fixed texts.
- **Advisory and fail-open:** suggestions are surfaced at the HitL gate
  (candidate presentation gains an `ATT&CK (Jev):` line noting suggested
  additions/changes); nothing is auto-applied; Jev unavailable or erroring
  means the author's tags stand, logged as a warning.
- Invocation follows the trial harness exactly — model `jev-1.13.0` via
  `https://api.typesafe.ai` with the trial's vendored `typesafe_sdk` +
  `httpx2` (no local-scorer hop), API key from the GNOME keyring on
  stdin. The implementation plan pins the exact call and prompt battery
  from the Jev trial's registered materials.

### 3.5 URL refresh, liveness, cursor policy

- Canonical URL updates in the discover skill: WeLiveSecurity →
  `https://www.welivesecurity.com/en/rss/feed/`, Cleafy →
  `https://www.cleafy.com/labs`, Zimperium → `https://zimperium.com/blog`.
- **Cursor rule: a source whose URL changes gets its discover cursor reset
  once**, so the next pass re-scans it from scratch. This is what recovers
  Cleafy's five silent months. Apply at merge time for the three moved
  sources; sources whose URLs didn't change keep their cursors.
- **Liveness log:** every discovery pass records per-source fetch status
  (live / moved / blocked / dead) in the run output; a dead or blocked
  source is skipped and logged, and its cursor is not advanced.
- Lookout is removed from the active source list (403 bot-block; kept as a
  reference-only mention). `lookout` stays a schema-legal **dormant cursor
  slot**: the skill's active set is 7, while `feed-state-schema.json` and
  `DiscoverSourceIdsCrossCheckTest`'s hardcoded 8-ID schema-side set stay
  at 8 — an intentional three-way invariant (removing the schema property
  would break the Kotlin test and require an AndroDR PR; out of scope).
  `androidvulnerabilities.org` is removed from the ASB skill.
- Ingest-skill doc fixes (this run's findings): ThreatFox filter field is
  `first_seen`; fetch `limit=1000` (documented API max — the 100-record
  window silently orphans catch-up gaps); severity example for threatfox
  C2-domain candidates aligns to **HIGH**, matching every existing
  threatfox row in `c2-domains.yml`.

### 3.6 What stays fixed

- Six validation gates; validators parallel per candidate; retry-once policy.
- Staging-only writes; `status: experimental` for AI rules; never production
  directories.
- Cross-dedup safety: `U_authoritative` empty → abort; candidates from
  mirror-listed feeds surviving the filter → WARN.
- Never advance a cursor on a failed fetch; abuse.ch missing key → skip +
  recorded FAILURE, not abort; never `--allow-upstream-unreachable` in
  automated runs.
- ioc-data writes: both validators must pass; no `kotlin-mirror-feeds.yml`
  change in the same commit as an ioc-data write.
- HitL gate before any write; one ledger per run; lessons cap 20; approval
  trend print.
- No AndroDR Kotlin changes from pipeline runs (this rework edits skills
  only).

## 4. Verification and rollout

- **Skill edits land as normal PRs** against `main` (branch protection +
  `ci-success` gate unchanged; these are AndroDR-repo files).
- **Rollout protocol:** skill markdown is not hot-reloaded — the reworked
  flow is first exercised by the next sweep in a fresh session (dogfood).
- **Acceptance evidence** comes from the run ledger, compared across the
  first few combined sweeps vs. historical `pipeline-runs/`:
  - SIRs that reached the author stage (should drop sharply — IOC-only
    bypass) and author-stage wall-time.
  - Rules generated per sweep and per research SIR (should rise).
  - `approval_without_modification_rate` (should not regress).
  - Every discover source reporting live/moved/blocked in the liveness log
    each sweep.
- **Regression policy mapping:** the mechanical changes (cursor reset rule,
  severity example, `first_seen`, `limit=1000`) are validated by the next
  dogfood run's outputs (ledger + liveness log) and by the sigma repo's
  existing validators where applicable (`validate-feed-state.py` — which
  never examines the `discover` block — plus the plan's Step-4
  discover-block assertions after the cursor reset; `RuleManifestIntegrityTest`
  untouched). The URL-lock and Jev script tests are wired into AndroDR's
  `python-pipeline` CI job (path filter + pytest step), so they gate every
  PR touching them rather than running only at verify time. Prose-only skill
  edits have no unit-test surface; the ledger is their deterministic record.

## 5. Open items intentionally deferred

- Trial side-output review packet (rules-repo ATT&CK/category fixes,
  eval-repo commit `d89e1b3`) — separate pass, not folded into the rework.
- Jev as graduation/Gate-5 judge — separately pre-registered trial if ever
  pursued; this spec wires only the adopted tag suggester.
- The `sms_notification_otp_theft.patterns` untracked fixture — unrelated
  loose end, to resolve with the owner separately.

## 6. Design-decision record

| Decision | Chosen | Alternatives rejected |
|---|---|---|
| Composition | One combined sweep (research-led, feeds as backfill step) | Two back-to-back passes (half-fixes the inversion); author+URLs only (doesn't deliver composition) |
| Old "never merge full-with-discover" rule | Replaced by bounded combined mode (top-N cap kept) | Keeping the split (the whole point) |
| Dedup | Central cross-dedup only | Author-internal dedup (double bookkeeping, serial cost) |
| Jev role | Advisory tag suggester, fail-open, surfaced at gate | Auto-apply (contradicts frozen trial: scores miscalibrated, ECE ≈ 0.2); gating judge (rejected in trial review) |
| Stale-URL recovery | Cursor resets once per URL change | Keep cursors (Cleafy's 5-month silent gap would persist) |
| Durable run state / scheduling | Not built (YAGNI — user decision) | Crash-proof checkpoints; cron/scheduled sweeps |