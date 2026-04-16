# Issue #117 — Complementary IOC Pipeline (Option F)

- **Issue:** #117 (`bug: runtime IOC/CVE feeds bypass the rule repo; pipeline validation gates don't protect users`)
- **Date:** 2026-04-16
- **Status:** Design approved; ready for implementation plan
- **Target branch:** `main` (per CLAUDE.md)
- **Scope estimate:** ~3 weeks, 4 PRs across 2 repos
- **PR:** #123 (this spec)

## Background

The AndroDR app already fetches IOCs from the curated `android-sigma-rules`
repo at runtime (`IocUpdateWorker.doWork()` calls `PublicRepoIocFeed.update()`
every periodic cycle; this fetches `ioc-data/package-names.yml`,
`c2-domains.yml`, `cert-hashes.yml`, and `popular-apps.yml` and upserts into
the unified `indicators` Room table).

The eight "bypass" Kotlin feed clients enumerated in issue #117 run
**alongside** that rule-repo reader, not instead of it. Both paths write to
the same `indicators` table via the same DAO (idempotent `upsertAll` on
`(type, value)` primary key); both are consumed by the same
`IndicatorResolver` on the SIGMA `ioc_lookup` hot path.

The actual bug is **upstream**: the AI rule-update pipeline's ingesters
(`update-rules-ingest-*` skills) emit SIRs for rule authoring but don't
populate `ioc-data/*.yml` systematically. That's why files like
`malware-hashes.yml` were empty until issue #118's HitL run added 30
ClayRat hashes — the pipeline has no write path to those files for indicator
deltas. Hence the rule-repo hop is wired up on every device but starved of
content.

Verification also showed that the existing validators (`validate-ioc-data.py`,
Gate 1–5 pipeline) do **not** detect indicator-level poison from a hijacked
upstream. The meaningful trust boundary at the rule-repo hop is the
human-in-the-loop Step 8 approval in `update-rules.md`, not the validators —
weak for bulk indicator writes, non-zero for rule-carried IOCs.

## Decision: Option F (complementary, additive)

**The rule repo's `ioc-data/*.yml` becomes the pipeline-discovered delta
*over* what the Kotlin bypass feeds already cover upstream, not a replacement
mirror.**

- **Track A** — eight Kotlin bypass feeds: permanent bulk pass-through of
  their respective upstreams. No changes.
- **Track B** — `ioc-data/*.yml` in rule repo: curated net-new entries from
  `/update-rules` research and pipeline ingesters covering upstreams no
  Kotlin feed mirrors (AmnestyTech, CitizenLab, ASB, NVD, ATT&CK).
- Both tracks write to the same `indicators` Room table; idempotent upsert
  handles the edge where the same `(type, value)` arrives from both sides.
- A rule-repo validator enforces the complementarity invariant:
  no entry in any `ioc-data/*.yml` may appear in any feed declared in
  `validation/kotlin-mirror-feeds.yml`.

**Trust-model framing:** the rule-repo hop is defense-in-depth
(delay + human review on Step 8 rule approval + commit-pinned forensic
replay via git history), not a single trust boundary. The supply-chain
threat model framing in the original #117 body overstated what the
validators catch.

Forensic replay specifically benefits **investigators with repo access**
(e.g., "at commit SHA X on date Y, what domains were in the rule repo's
c2-domains.yml?"). Exposing this to end users in the app (e.g., "this
indicator came from rule-repo commit SHA X") is a separate UX ask and
not part of this work.

**Rejected alternatives:**

- **Original #117 (data-transport routing of all 8 feeds).** Introduces a
  staleness failure mode the architecture change itself creates, requiring
  the mandatory Phase 2.5 freshness gate and the client-side staleness
  surface to mitigate. ~6–8 weeks for a single-trust-boundary claim the
  validators don't actually enforce.
- **Counter-proposal (schema only, data transport unchanged).** Misses that
  the existing `IndicatorResolver` + unified `indicators` table is already
  the "IocRegistry" it proposed building, and misses that the AI pipeline's
  Step 8 human review is a real (if imperfect) trust layer.
- **Option E (fix pipeline write path; retire Kotlin feeds opportunistically).**
  Close to Option F but implicitly allows the rule repo to accumulate
  redundant mirrors of upstream data. Option F's complementarity invariant
  prevents that drift by construction.

## Architecture

```
                ┌─────────────────────────────────────────┐
                │         Upstream IOC feeds              │
                │ (stalkerware, MVT, ThreatFox, MBazaar,  │
                │  Amnesty, ASB, NVD, ATT&CK, Citizen Lab)│
                └───────┬──────────────────────┬──────────┘
                        │                      │
          ┌─────────────┘                      └──────────────┐
          ▼                                                   ▼
┌───────────────────────┐                      ┌─────────────────────────┐
│  Track A: Kotlin      │                      │  Track B: AI Pipeline   │
│  bypass feeds (8)     │                      │  (/update-rules …)      │
│  = bulk pass-through  │                      │  = curated additive     │
│                       │                      │    delta                │
│  Runs periodically    │                      │  Runs on human trigger  │
│  on every device      │                      │  or schedule            │
└──────────┬────────────┘                      └────────────┬────────────┘
           │                                                │
           │                                                ▼
           │                              ┌─────────────────────────────┐
           │                              │  rule-repo: ioc-data/*.yml  │
           │                              │  (net-new entries only;     │
           │                              │   validator enforces        │
           │                              │   complementary-to rule)    │
           │                              └────────────┬────────────────┘
           │                                           │
           │                                           ▼
           │                              ┌─────────────────────────────┐
           │                              │  PublicRepoIocFeed (Kotlin) │
           │                              │  = existing rule-repo reader│
           │                              └────────────┬────────────────┘
           │                                           │
           └────────────────────────┬──────────────────┘
                                    ▼
                        ┌────────────────────────┐
                        │  indicators Room table │
                        │  (idempotent upsert)   │
                        └────────────┬───────────┘
                                     ▼
                        ┌────────────────────────┐
                        │  IndicatorResolver     │
                        │  → SIGMA ioc_lookup    │
                        └────────────────────────┘
```

### Key invariant

Any entry in any `ioc-data/*.yml` must **not** appear in any feed listed in
`validation/kotlin-mirror-feeds.yml`. Enforced by
`validation/validate-ioc-complementarity.py` both at pipeline-commit time
and in rule-repo CI.

**Drift handling (upstream mutation):** upstreams mutate — an entry
legitimately sourced from AmnestyTech today may appear in ThreatFox next
month when it gets absorbed. Under a naive fail-closed CI, this would
break unrelated PRs as third-party feeds drift. The complementarity
validator therefore runs in two modes:

- **Strict mode** — applied to entries added or modified in the current
  change (i.e., files touched by the PR or the pipeline commit). Any
  new-or-changed entry must pass complementarity at commit time.
- **Advisory mode** — applied to pre-existing entries in files the change
  didn't touch. Drift violations are reported as warnings (visible in CI
  logs, surfaced by the periodic-pruner follow-up issue), not failures.

Pipeline-local use always operates in strict mode, because the pipeline is
always touching the files it writes. Rule-repo CI determines strict vs.
advisory per file based on the PR diff (`git diff --name-only`).

## Rule repo deliverables

All under `third-party/android-sigma-rules/`.

### 1. `validation/ioc-entry-schema.json`

JSON Schema for a single IOC entry. Formalizes the shape already used across
existing `ioc-data/*.yml` files; no new fields introduced.

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "required": ["indicator", "category", "severity", "source"],
  "properties": {
    "indicator":   { "type": "string", "minLength": 1 },
    "family":      { "type": "string" },
    "category":    {
      "enum": ["STALKERWARE", "SPYWARE", "MALWARE",
               "NATION_STATE_SPYWARE", "FORENSIC_TOOL",
               "MONITORING", "POPULAR", "KNOWN_GOOD_OEM"]
    },
    "severity":    { "enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW"] },
    "source":      { "type": "string" },
    "description": { "type": "string" },
    "first_seen":  { "type": "string", "format": "date" }
  },
  "additionalProperties": false
}
```

### 2. `validation/ioc-lookup-definitions.yml`

Declarative map of SIGMA `ioc_lookup: <name>` identifiers to their
corresponding IOC types and source files. Lifts the currently-hardcoded map
from `ScanOrchestrator.initRuleEngine()` into data.

```yaml
lookups:
  package_ioc_db:
    type: PACKAGE_NAME
    files: [ioc-data/package-names.yml]
    description: "Known-malicious Android package names"
  cert_hash_ioc_db:
    type: CERT_HASH
    files: [ioc-data/cert-hashes.yml]
  domain_ioc_db:
    type: C2_DOMAIN
    files: [ioc-data/c2-domains.yml]
  apk_hash_ioc_db:
    type: APK_HASH
    files: [ioc-data/apk-hashes.yml]
  known_good_app_db:
    type: PACKAGE_NAME
    files: [ioc-data/popular-apps.yml, ioc-data/known-oem-prefixes.yml]
```

Third-party consumers implementing the SIGMA dialect resolve
`field|ioc_lookup: <db_name>` by reading this file + the referenced
`ioc-data/*.yml` files. Rule-author surface is unchanged.

### 3. `validation/kotlin-mirror-feeds.yml`

Single global declaration of which upstream feeds the AndroDR Kotlin clients
fetch directly. Drives the complementarity validator.

```yaml
# Feeds AndroDR's Kotlin bypass clients fetch directly.
# Entries in ioc-data/*.yml must NOT duplicate anything in these feeds.
feeds:
  - id: stalkerware-indicators
    url: https://raw.githubusercontent.com/AssoEchap/stalkerware-indicators/master/ioc.yaml
    parser: stalkerware-yaml
  - id: mvt-indicators
    url: https://raw.githubusercontent.com/mvt-project/mvt-indicators/main/indicators.yaml
    parser: mvt-stix
  - id: threatfox
    url: https://threatfox.abuse.ch/export/json/recent/
    parser: threatfox-json
  - id: malwarebazaar
    url: https://bazaar.abuse.ch/export/csv/recent/
    parser: malwarebazaar-csv
```

The pipeline's `amnesty`, `citizenlab`, `asb`, `nvd`, `attack` ingesters are
intentionally **not** in this list — no Kotlin client mirrors them, so IOCs
sourced from those upstreams legitimately flow into `ioc-data/*.yml`.
HaGeZi, UAD, Plexus, and Zimperium are intentionally omitted for reasons
given in the out-of-scope section.

Note on MalwareBazaar: the Kotlin codebase has both `MalwareBazaarApkHashFeed`
(wired, CSV export) and `MalwareBazaarCertFeed` (stub — `fetch()` currently
returns `emptyList()` with a "API integration pending" log). Only the APK
endpoint is declared above. Cert-hash entries from MalwareBazaar flowing
into `ioc-data/cert-hashes.yml` are legitimate additive contribution under
Option F until the cert feed is wired to a real upstream. When that
happens, `kotlin-mirror-feeds.yml` and its cross-check must be updated in
the same PR that wires the Kotlin feed.

### 4. `validation/validate-ioc-data.py` (extended)

Existing script; gains JSON-Schema validation against `ioc-entry-schema.json`
as the first check. Keeps the existing category / family-pattern / cert-hash
format / duplicate-indicator checks for backward compatibility and
defense-in-depth.

### 5. `validation/validate-ioc-complementarity.py` (new)

For each `ioc-data/*.yml` file:

1. Read `kotlin-mirror-feeds.yml`.
2. For each feed, fetch the upstream into an ephemeral
   `{(type, normalized_value)}` set. Working set size estimate:
   stalkerware-indicators ioc.yaml ~100 KB; MVT indicators.yaml a few MB;
   ThreatFox recent JSON ~5–10 MB; MalwareBazaar recent CSV a few MB.
   Total in-scope working set <20 MB; fits comfortably in memory, and is
   ephemeral per pipeline run (discarded after commit).
3. For every entry in every `ioc-data/*.yml`, assert
   `(type, normalized_value)` does not appear in any ephemeral set.
4. Exit non-zero with offending entries listed.

**Failure modes:**

- **PR merge gate (rule-repo CI):** fail-closed. An auto-merged PR cannot
  self-heal if an upstream is briefly unreachable, so strictness is correct.
- **Pipeline local use (`/update-rules`):** defer-with-warning flag
  available (`--allow-upstream-unreachable`), so a pipeline operator with
  an intermittent upstream can retry. Not a default.

## Pipeline changes

Seven ingester skills (`update-rules-ingest-*.md`) and the dispatcher
(`update-rules.md`) change. Rule Author, Validator (5-gate), and Review
skills are untouched.

### Per-ingester change

Each ingester today:

1. Fetches upstream
2. Filters to Android-relevant entries
3. Emits SIRs
4. Returns SIR array

After this work, each ingester also:

5. Holds fetched entries in scope as ephemeral snapshot `S`
6. Extracts normalized IOCs from SIRs / threat context
7. Performs **self-dedup only** — filters out any candidate also present
   in its own `S` (i.e., the entry was already in its upstream, so it's
   not net-new for this ingester)
8. Returns `(SIRs, candidate_ioc_entries, S_hash_set)` to the dispatcher,
   where `S_hash_set` is the `{(type, normalized_value)}` projection of
   the snapshot

Cross-dedup is NOT done in-ingester. Ingesters run as parallel subagent
processes that don't share memory, so any cross-dedup logic colocated with
ingesters would be incorrect.

### Dispatcher cross-dedup (new step 6.5)

Between Step 6 (triage SIRs) and Step 7 (approval UX), the dispatcher:

1. Collects `S_hash_set` from every completed ingester
2. Also fetches each feed in `kotlin-mirror-feeds.yml` into its own
   `S_hash_set` (even when the corresponding ingester didn't run — covers
   the case where e.g. only the stalkerware ingester ran, but candidates
   still must be checked against ThreatFox's upstream)
3. Takes the union of all `S_hash_set`s — the **authoritative upstream
   coverage set** for this run
4. For each ingester's `candidate_ioc_entries`, filters out anything in
   the union — these were in *some* upstream, just not the ingester's own
5. Passes the filtered candidates to Step 7

This guarantees cross-dedup correctness regardless of which ingesters ran
and how they were parallelized.

### Dispatcher change (`update-rules.md`)

Steps 1–6 unchanged. Steps 7–8 extend:

- **Step 7 — approval UX:** user approves a threat → approves both its
  rules (existing) AND its candidate IOC entries as one unit. IOC-only
  candidates (no accompanying rule) are first-class: the generic
  `sigma_androdr_001_package_ioc`, `_002_cert_hash_ioc`,
  `_003_domain_ioc`, `_004_apk_hash_ioc` rules already match anything in
  their respective lookup DBs, so new IOCs automatically gain detection
  without per-threat rule authoring.

- **Step 8 — commit:**
  - Append approved IOC entries to the appropriate `ioc-data/<file>.yml`
  - Run `validate-ioc-data.py` (schema + legacy checks) on every touched
    file; abort on failure
  - Run `validate-ioc-complementarity.py` on every touched file; abort on
    failure
  - Write rules (existing behavior)
  - Update `feed-state.json` with new cursors (existing) plus new
    `ioc_data_last_write` timestamp per ingester
  - Commit

### `feed-state.json` schema

Additive field per ingester: `ioc_data_last_write: <ISO 8601 timestamp>`.
`feed-state-schema.json` updated to declare the new field (optional; since
`additionalProperties: false` is in force per the dispatcher's Step 8 note).

### Safety rule additions in `update-rules.md`

- NEVER commit an `ioc-data/*.yml` write that
  `validate-ioc-complementarity.py` rejects.
- NEVER pass `--allow-upstream-unreachable` or equivalent bypass flags in
  automated (non-interactive) pipeline runs.

## Testing & guardrails

### Kotlin tests (JVM unit tests)

1. **`IocLookupDefinitionsCrossCheckTest`** — mirrors
   `BundledRulesSchemaCrossCheckTest`. Asserts every lookup name in
   `validation/ioc-lookup-definitions.yml` is present in
   `ScanOrchestrator.initRuleEngine()`'s hardcoded map, and vice versa.
   Build fails on drift.

2. **`IocDataSchemaCrossCheckTest`** — walks every `ioc-data/*.yml` in the
   submodule, validates each entry against `ioc-entry-schema.json` using
   the `networknt` JSON Schema library (same library used by the existing
   rule-schema cross-check test). Build fails on any schema violation.

3. **`KotlinMirrorFeedsCrossCheckTest`** — asserts correspondence between
   the set of Kotlin bypass feed classes in `com/androdr/ioc/feeds/` and
   entries in `validation/kotlin-mirror-feeds.yml`. Uses a declarative
   `KOTLIN_BYPASS_FEED_IDS` constant in the test (mapping the 4 in-scope
   feeds to their `kotlin-mirror-feeds.yml` IDs: `stalkerware-indicators`,
   `mvt-indicators`, `threatfox`, `malwarebazaar`). Test fails if (i) any
   in-scope bypass feed class is added without a new YAML entry, or (ii)
   an entry in the YAML has no corresponding Kotlin feed class. URL
   constants remain `private const val` in the feed classes — URLs are
   authoritative only in the YAML; Kotlin just references them through
   `SafeHttpFetch`. No reflection required.

### Python validators (rule-repo CI)

3. **`validate-ioc-data.py` (extended)** — schema-first validation, then
   existing legacy checks. Runs per-file in rule-repo CI on every PR
   touching `ioc-data/`.

4. **`validate-ioc-complementarity.py` (new)** — the dedup gate.
   Runs locally during `/update-rules` (before commit) and in rule-repo
   CI on every PR touching `ioc-data/` or `kotlin-mirror-feeds.yml`.

### CI workflow update

The submodule's existing GitHub Actions workflow under `.github/workflows/`
gains invocations of the new validators.

### Explicitly dropped guardrails (from original #117)

- Phase 4 unit test banning non-rule-repo URLs in `com/androdr/ioc/` — would
  forbid the architecture itself under Option F.
- Phase 2.5 server-side freshness gate (non-empty / recency / source-diversity).
  Under complementary model, rule-repo file staleness degrades from critical
  to just a missed research delta; Track A still fires. A lightweight
  non-empty check on files intended to have content is optional follow-up,
  not blocking.

## Phase breakdown

Four PRs across two repos. Critical path: Phase 1 → Phase 3 → Phase 2 →
Phase 4 → Phase 5. Phase 3 precedes Phase 2 so that `IocDataSchemaCrossCheckTest`
runs against already-pruned (and thus schema-conformant) content; otherwise
the cross-check test could fail on entries Phase 3 would have removed
anyway.

### Phase 1 — rule-repo foundations (android-sigma-rules PR) — ~3 days

- `validation/ioc-entry-schema.json`
- `validation/ioc-lookup-definitions.yml`
- `validation/kotlin-mirror-feeds.yml`
- `validation/validate-ioc-data.py` extended with schema-first validation
- CI workflow picks up the extended validator
- No changes to existing `ioc-data/*.yml` content yet

### Phase 3 — complementarity gate + prune (android-sigma-rules PR) — ~2–3 days

Runs before Phase 2 (reorder vs. earlier draft).

- `validation/validate-ioc-complementarity.py` with strict/advisory mode
  logic as specified under "Drift handling"
- CI wires it in: strict on changed files, advisory on untouched files;
  `--allow-upstream-unreachable` flag available for pipeline-local use
- **Run once against current `ioc-data/*.yml`:** prune every entry already
  present in any `kotlin-mirror-feeds.yml` upstream
- PR description lists pruned entries (count + source breakdown) so
  reviewers can spot-check; the pruned-set diff IS the assertion that
  prune executed correctly
- Commit pruned files in the same PR so rule-repo HEAD is self-consistent
  after merge

**Migration safety — the one non-obvious regression to prevent.**
`PublicRepoIocFeed.fetchAndUpsertPackages()` calls
`deleteStaleEntries(SOURCE_ID, ...)` scoped to `source_id =
"androdr_public_repo"` — so any row on-device whose `source` column is
still `androdr_public_repo` (because no Kotlin Track A feed has written
over it with its own source) will be deleted on the next `IocUpdateWorker`
run once the entry disappears from the rule-repo file.

For entries pruned BECAUSE they're in a Kotlin-mirrored upstream, the
same `(type, value)` will be re-upserted by the corresponding Kotlin
Track A feed in the same worker cycle (Kotlin track runs first in
`IocUpdateWorker.doWork()`, at line 38), with its own source ID — so the
net effect is "row stays, source switches from `androdr_public_repo` to
e.g. `stalkerware_indicators`." No detection regression.

For entries sourced from AmnestyTech / CitizenLab / ASB / NVD / ATT&CK
that happen to get pruned (shouldn't, but defensively): no Kotlin Track A
covers them, so the row would actually get deleted. The complementarity
validator must not prune such entries by construction — only entries
confirmed present in a `kotlin-mirror-feeds.yml` upstream are pruned.
Validator invariant: `source` of a pruned entry must correspond to a
`kotlin-mirror-feeds.yml` feed id.

**Pre-merge verification of Phase 3:** on a test device, snapshot the
`indicators` row count and the `(type, value, source)` tuples; apply the
pruned `ioc-data/*.yml` via a simulated `PublicRepoIocFeed.update()`;
run `IndicatorUpdater` (Kotlin Track A); confirm that (i) total row count
does not drop net, and (ii) every pruned `(type, value)` is still present
in the indicators table after the cycle (with a Track A source ID).

### Phase 2 — Kotlin cross-check tests (AndroDR PR) — ~1 day

Runs after Phase 3. Submodule bump picks up both Phase 1 and Phase 3.

- `IocLookupDefinitionsCrossCheckTest`
- `IocDataSchemaCrossCheckTest`
- `KotlinMirrorFeedsCrossCheckTest` — simplified: asserts class-name-based
  correspondence between the eight Kotlin bypass feed classes in
  `com/androdr/ioc/feeds/` and entries in `kotlin-mirror-feeds.yml` (no
  URL-reflection; URLs remain `private const val` in Kotlin, authoritative
  in YAML). Test uses a declarative `KOTLIN_BYPASS_FEED_IDS: Set<String>`
  constant maintained by hand alongside the feed-class list — drift is
  detected when a new feed class is added without updating either.
- Submodule bump to Phase 1+3 tip

### Phase 4 — pipeline ingester extensions (AndroDR PR) — ~8–11 days

`.claude/commands/*.md` changes only.

- Each of the 7 ingester skills: hold ephemeral upstream snapshot in
  scope; emit candidate IOC entries + snapshot hash set alongside SIRs;
  self-dedup only
- `update-rules.md` dispatcher: new Step 6.5 centralized cross-dedup
  against the union of ingester snapshots + freshly-fetched
  `kotlin-mirror-feeds.yml` feeds; Step 7 IOC-only approval path; Step 8
  writes to `ioc-data/*.yml`, runs both validators, aborts on failure
- `feed-state.json` additive field `ioc_data_last_write`; schema updated

Realistic estimate reflects: 7 × ~0.5d skill rewrites + ~1d dispatcher
surgery + ~2d normalizer tuning against real upstream shapes (ThreatFox
JSON quirks, MalwareBazaar CSV edge cases, MVT STIX parsing) +
~1–2d integration testing + buffer.

### Phase 5 — end-to-end smoke — ~1 day

- Run `/update-rules full` against a test fixture upstream
- Verify IOCs land in `ioc-data/`, pass all validators, get committed
- Verify the app's next `IocUpdateWorker` run loads them (observable as
  `indicators` table row-count delta)

## Out of scope

### From original #117

- Phase 4 guardrail banning non-rule-repo URLs in `com/androdr/ioc/`
- Phase 2.5 server-side freshness gate
- Client-side staleness banner, degraded-confidence labels, forced-refresh
  UX, stale-scan telemetry
- Rewriting any of the 8 Kotlin bypass feed clients
- Deleting any of the 8 Kotlin bypass feed clients

### Explicit feed carve-outs

- **`HaGeZiTifFeed`** — ~1M-entry DNS blocklist; wrong shape for YAML.
  Distinct engineering track (compiled Bloom filter, release artifact)
  if ever pursued.
- **`UadKnownAppFeed`, `PlexusKnownAppFeed`** — known-good datasets;
  different trust model ("this is benign" vs. "this is malicious");
  complementarity logic as designed doesn't naturally apply.
- **`ZimperiumIocFeed`** — third-party mirror-of-a-mirror; re-evaluating
  whether we need it at all is a separate conversation.
- **`CveRepository.kt` (CISA KEV + Google OSV)** — CVE entities have
  `fixedInPatchLevel`, `cisaDateAdded`, `isActivelyExploited`,
  `vendorProject`, `product`, plus ETag/304 caching. Schema doesn't fit
  generic IOC shape. The deeper reason: CVE matching is
  *patch-level-relative range query* (`cveDao.getUnpatchedCves(devicePatchLevel)`
  at `CveRepository.kt:73`), not an equality-lookup `ioc_lookup` — the
  complementarity invariant as designed doesn't apply. CISA/Google are
  themselves authoritative; supply-chain argument is weakest here.
  Separate track if ever pursued.

### From counter-proposal

- Building a new `IocRegistry` Kotlin class — the existing
  `IndicatorResolver` + unified `indicators` Room table already is this.
- Generating Kotlin data classes from the JSON schema — cross-check tests
  are cheaper and already the established pattern.

### Punted to follow-up

- Periodic pruner that cleans `ioc-data/*.yml` entries once upstream later
  covers them (drift prevention as maintenance, not as a gate).
- Issue #119 (autonomous threat discovery) — gets a working output channel
  for free once Phase 4 lands, but no work on #119 itself is in this scope.
- Migration of CVE / HaGeZi / known-good feeds to the rule repo.
- User-visible provenance surface ("this indicator came from rule-repo
  commit SHA X") — forensic replay becomes *possible* via git history;
  exposing it in-app is a separate UX ask.

## Related work

- **Epic:** #104 (AI rule framework audit) — closed 2026-04-15
- **Meta-plan:** `docs/superpowers/plans/2026-04-11-ai-rule-framework-audit-meta-plan.md`
- **Related follow-up:** #119 (autonomous threat discovery from unstructured
  sources) — depends on this work for its output to reach users
- **Supersedes:** the original #117 issue body (Phases 1–4) and the
  2026-04-16 counter-proposal comment
