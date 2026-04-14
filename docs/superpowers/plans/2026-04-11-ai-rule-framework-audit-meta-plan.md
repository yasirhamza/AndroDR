# AI-Powered Rule Update Framework — Audit Remediation Meta Plan

**Tracking issue (epic):** #104
**Source audit:** in-session audit 2026-04-11
**Branch:** TBD (new branch off `claude/android-edr-setup-rl68Y`)
**Merge model:** Per-sub-plan PR, not atomic. Bundle 1's three sub-plans form a dependency chain but each merges independently so the build-time gate lands early and starts catching drift immediately. Every PR references its sub-plan issue via `Closes #N`; the epic (#104) is closed manually once all five sub-plan issues resolve.

---

## Purpose of this document

An audit of the AI-powered SIGMA rule update framework on 2026-04-11 surfaced 11 concrete findings. The root cause of most of them is a structural gap: **two independent write paths modify rules** — the dev pipeline (human PRs) and the AI pipeline (`/update-rules`) — and only the AI pipeline enforces schema discipline. The dev pipeline has already drifted the validator out of sync with runtime requirements (missing `category` field, stale logsource whitelist, no correlation rule support, staging ID collision).

This meta-plan organizes remediation into **three bundles comprising five sub-plans**, ordered so:
1. The drift loop closes first (structural fix, not procedural)
2. The pipeline is proven to work end-to-end with at least one real AI-generated rule promoted
3. Author quality improves on top of a now-trustworthy pipeline
4. Operational hardening automates the whole thing

**Execution model:** For each sub-plan — brainstorm (if flagged) → write spec → user approves → write plan → execute via `subagent-driven-development` → two-reviewer cycle → merge. Each sub-plan's plan is written against the actual codebase state after the previous sub-plan merges, not against assumptions.

---

## Context — findings from the audit

Numbered per the original audit report (reproduced here for self-containment):

1. **F1** — Gate 4 (Dry-Run Evaluation) has no programmatic test harness
2. **F2** — Pipeline has never successfully promoted an AI-generated rule end-to-end; 5 staging rules sit untouched
3. **F3** — IOC data `source` field is mandatory per spec but unenforced
4. **F4** — `feed-state.json` cursor schema inconsistent across ingesters; NVD cursor is `null`
5. **F5** — No scheduled automation; feed state 9 days stale
6. **F6** — Decision manifest from Rule Author has no JSON schema
7. **F7** — Threat researcher could hallucinate IOCs with no cross-source verification
8. **F8** — Bundled correlation rules have no integration tests
9. **F9** — Rule Author has no logsource field taxonomy reference
10. **F10** — No build-time check that bundled rules parse and conform to schema
11. **F11** — IOC source enum not validated in `merge-ioc-data.py`

**Discovered during scoping (not in original audit):**
- **Validator is stale** — `rule-schema.json` missing required top-level `category`; `valid_services` whitelist missing `receiver_audit`, `tombstone_parser`, `accessibility`, `appops`, `network_monitor`; no support for correlation rule type
- **Staging rule ID collision** — `androdr-071` is taken in production (`crash_loop_anti_forensics`) but also claimed by staging rule `popular_app_impersonation`
- **Root cause (per user on 2026-04-11):** dev pipeline has no build-time enforcement that rule changes keep schema + validator in sync, so drift is structural not procedural

---

## Bundle inventory

| Bundle | Sub-plans | Approach | Why |
|---|---|---|---|
| 1. Close drift loop + prove pipeline works | 1a, 1b, 1c | **Brainstorm first** for 1a and 1b; 1c direct to plan | Multiple design decisions; highest leverage |
| 2. Author quality | 2 | **Brainstorm first** | Judgment calls on confidence thresholds and taxonomy shape |
| 3. Framework hardening | 3 | **Partial brainstorm** (F5 only) | F4/F6/F8 mechanical; F5 needs automation cadence decisions |

## Sub-plan inventory

| # | Issue | Sub-plan file | Status | Approach | Goal |
|---|---|---|---|---|---|
| 1a | #105 | `2026-04-11-ai-rule-framework-01a-validator-sync.md` | Pending | Brainstorm → spec → plan | Sync `rule-schema.json` + `validate-rule.py` with runtime; add build-time Gradle gate parsing every bundled rule + validating against schema. **Closes the drift loop permanently.** |
| 1b | #106 | `2026-04-11-ai-rule-framework-01b-gate4-ioc-source.md` | Pending | Brainstorm → spec → plan | Build programmatic Gate 4 test harness callable by validator skill; enforce IOC `source` field validation in `merge-ioc-data.py` |
| 1c | #107 | `2026-04-11-ai-rule-framework-01c-staging-rerun-and-proof.md` | Pending | Direct to plan | Re-run 5 staging rules through updated validator; decide promote/renumber/reject per rule; run `/update-rules source stalkerware` end-to-end; promote at least one AI-generated rule to production |
| 2 | #108 | `2026-04-11-ai-rule-framework-02-author-quality.md` | Pending | Brainstorm → spec → plan | Threat researcher IOC confidence filtering (F7); logsource field taxonomy as Rule Author input (F9) |
| 3 | #109 | `2026-04-11-ai-rule-framework-03-hardening.md` | Pending | F5 brainstorm → partial spec → plan; F4/F6/F8 direct | Cursor schema standardization (F4); scheduled GitHub Actions automation (F5); decision manifest JSON schema (F6); correlation rule integration tests (F8) |

**Total estimated work:** 5 sub-plans; mix of mechanical and design-heavy work.

---

## Per-sub-plan entry/exit contracts

### Sub-plan 1a — Validator Sync and Build-time Gate

**Entry state:** main branch current. `android-sigma-rules/validation/rule-schema.json` missing `category` in required fields. `validate-rule.py:63` whitelist is `{app_scanner, device_auditor, dns_monitor, process_monitor, file_scanner}` (stale). No build-time rule validation in Gradle. Staging rules untouched.

**Exit state:**
- `android-sigma-rules` added to AndroDR as a git submodule at `third-party/android-sigma-rules/`
- `rule-schema.json` updated: top-level `category` added to required fields with enum matching `RuleCategory` values; `additionalProperties` left permissive (true)
- `valid_services` whitelist in `validate-rule.py` synced with actual telemetry model classes — add `receiver_audit`, `tombstone_parser`, `accessibility`, `appops`, `network_monitor`
- Correlation rule schema support deferred to Bundle 3 (#109) — only detection/atom rules are cross-checked
- New `BundledRulesSchemaCrossCheckTest.kt` unit test validates all 44 detection/atom rules against both `SigmaRuleParser.parse()` (Kotlin runtime) AND the JSON schema from the submodule (via `com.networknt:json-schema-validator:2.0.1`); fails build on any disagreement
- CI workflow updated with `git submodule update --init`
- All 44 current detection/atom bundled rules pass the new gate
- Developer workflow documented in CLAUDE.md (submodule init, two-PR dance for schema changes)

**What 1b can assume:** Validator is trustworthy; schema matches runtime; build fails on drift; both write paths are structurally synced via the submodule.

---

### Sub-plan 1b — Gate 4 Harness and IOC Source Validation

**Entry state:** end of 1a. Gate 4 is documented but has no programmatic harness; `update-rules-validate` skill instructs reviewers to hand-trace or write throwaway tests. `merge-ioc-data.py` does not validate `source` field against allowed enum.

**Exit state:**
- New `GateFourTestHarness.kt` in `app/src/test/` with a simple API: `runGate4(rule: SigmaRule, truePositives: List<TelemetrySample>, trueNegatives: List<TelemetrySample>): Gate4Result`
- `update-rules-validate` skill updated to describe inputs to the harness instead of hand-tracing
- At least 3 representative synthetic fixtures checked in: simple selection, `ioc_lookup`, correlation atom
- `merge-ioc-data.py` validates `source` field against enum (`stalkerware-indicators`, `malwarebazaar`, `threatfox`, `amnesty-investigations`, `citizenlab-indicators`, `mvt-indicators`, `virustotal`, `android-security-bulletin`); rejects entries with missing or unknown source; exits non-zero with a clear error
- `validate-rule.py` gains a companion function for IOC data files so the skill can invoke validation either on a rule or an IOC file

**What 1c can assume:** Gate 4 can be run programmatically; IOC merges can't accept polluted data; validator gives trustworthy answers across all 5 gates.

---

### Sub-plan 1c — Staging Rerun and End-to-End Proof

**Entry state:** end of 1b. Validator and gates are trustworthy. 5 staging rules still sit in `android-sigma-rules/staging/`. No AI-generated rule has ever been promoted through the full pipeline.

**Exit state:**
- All 5 staging rules re-validated against updated framework; per-rule decision recorded in a decision log committed to the repo:
  - **androdr-069** (overlay permission) — decision TBD (likely reject as single-permission-too-broad, preserve intel as correlation atom)
  - **androdr-070** (DDNS C2) — decision TBD (likely migrate domain list to `ioc-data/domains.yml`, promote rule as `domain|ioc_lookup` form consistent with rule 005)
  - **androdr-051** (Cellebrite CVEs) — decision TBD (likely promote as-is after adding top-level `category`)
  - **androdr-066** (boot persistence) — decision TBD (likely reject or demote to low + strengthen with correlation)
  - **androdr-071** (fake popular app) — MUST renumber (ID collision with production); decision TBD (likely migrate prefix list to IOC data)
- Any rules promoted get top-level `category` added and pass the new Gradle gate
- `/update-rules source stalkerware` run end-to-end with real feed state; produces at least one new candidate rule that passes all 5 gates including the new Gate 4 harness
- At least one candidate promoted to `app/src/main/res/raw/`, committed via the pipeline's decision output
- `feed-state.json` updated with correct cursor from the run
- Release notes entry: "First AI-generated SIGMA rule promoted via end-to-end pipeline"

**What Bundle 2 can assume:** Pipeline actually works; drift is closed; at least one AI-generated rule is in production; we have empirical signal on what the Rule Author currently produces.

---

### Sub-plan 2 — Author Quality

**Entry state:** end of 1c. Pipeline works but empirical output from 1c may reveal weak rules — thin evidence, missing telemetry fields, hallucinated IOCs.

**Exit state:**
- `update-rules-research-threat` skill enforces "2 sources or 1 structured source" rule; single-source IOCs marked `requires_verification` and routed to manual review
- Logsource field taxonomy documented (shape decided during brainstorming — markdown reference, embedded in skill, or auto-generated from `toFieldMap()` implementations)
- Rule Author skill consumes taxonomy; decision manifest includes `telemetry_gap` decision type for out-of-taxonomy fields
- Re-run from 1c repeated against the same threat; output measurably improved (more specific field matchers, fewer weak single-source rules, fewer ambiguous decisions)

**What Bundle 3 can assume:** Rule Author and researcher produce release-quality output; automation can run unsupervised with reasonable confidence.

---

### Sub-plan 3 — Framework Hardening

**Entry state:** end of 2. Pipeline works, produces good rules, but runs only on manual trigger. Feed state drifts between runs. Correlation rules untested.

**Exit state:**
- `feed-state.json` migrated to unified cursor schema; each feed has `last_seen_timestamp` + feed-specific secondary keys; NVD cursor initialized
- New GitHub Actions workflow `.github/workflows/update-rules-scheduled.yml` runs `/update-rules full` weekly; commits output to `android-sigma-rules` repo; opens PR against main for human review; does **not** auto-merge
- `decisions-schema.json` added to `android-sigma-rules/validation/`; Gate 1 validates decision manifest structure against it
- `SigmaCorrelationRuleIntegrationTest.kt` added to `app/src/test/`; exercises each bundled correlation rule against synthetic timeline events; verifies expected signals fire; fails build on regression
- All new hardening work passes the build-time gate from sub-plan 1a

**Scope changes during execution (recorded 2026-04-14):**
- **F5 (scheduled automation) — DEFERRED.** Automating a WIP pipeline without a
  production track record bakes in risk. Revisit in a later sprint once the
  authoring pipeline has run unsupervised for several cycles without hallucination
  or drift. The "feed state drifts between runs" concern is mitigated by the
  unified cursor schema from F4 (at least the staleness is auditable now).
- **F8 (correlation integration tests) — ALREADY SATISFIED.** Pre-existing
  tests cover the stated requirement: `AllCorrelationRulesFireTest.kt` runs all
  4 correlation rules end-to-end on a single synthetic timeline, and
  `CorrelationMigrationFixturesTest.kt` has 6 per-rule tests including 2 negative
  cases (outside-window, insufficient-count). A new
  `SigmaCorrelationRuleIntegrationTest.kt` would duplicate these.

**What's next (out of this meta-plan):** Public rules repo release (Tier 1 project per `project_rule_engine_priority`), coverage metrics, SIGMA-HQ upstream contribution. Separately, #117 tracks routing all runtime IOC/CVE fetches through the rule repo (client bypass artifact from early prototyping).

---

## Ordering and rationale

**Bundle 1 must be done first and in order.** Without 1a (validator sync + build gate), everything else builds on sand: you can't trust validation results, can't prove the pipeline works, and drift will recur on the next sprint. 1b depends on 1a (you need a trustworthy validator before adding Gate 4 programmatic support). 1c depends on both (you need the full validation stack working before claiming end-to-end proof).

**Bundle 2 must wait for Bundle 1.** Improving author quality is speculation until the pipeline actually works and produces empirical output you can measure. Doing it earlier risks optimizing the wrong things.

**Bundle 3 must wait for Bundle 2.** Automating a pipeline that produces mediocre rules just automates mediocrity. Schedule automation only once rules are release-quality.

**Parallelization:** Inside Bundle 1, 1a → 1b → 1c is a strict chain. Inside Bundle 3, F4 (cursor schema) must precede F5 (automation) because the scheduler reads cursors; F6 (manifest schema) and F8 (correlation tests) are independent and can run in parallel subagent streams.

---

## Open decisions (resolve during Bundle 1 brainstorming)

These affect sub-plan 1a's scope and must be settled before 1a's spec is written:

1. **Build-time gate mechanism.** Kotlin parser, Python validator, or both?
   *Recommendation:* Kotlin parser is mandatory (lives in main repo build, no extra dependency). Python validator is optional (runs only if Python is on PATH, prints a warning otherwise). This catches the 95% case in Gradle and the remaining 5% in CI where Python is guaranteed.

2. **Where does IOC source validation live?**
   *Recommendation:* Both — `validate-rule.py` (via a new `validate-ioc-data.py` sibling) for the pipeline's validator skill, and `merge-ioc-data.py` as the last line of defense before disk write.

3. **Gate 4 test harness shape.**
   *Recommendation:* Standalone Kotlin class in `app/src/test/` with a simple runnable API. No code generation, no YAML fixtures, no separate test-rule DSL. The validator skill describes inputs to the harness and reads structured output.

Decisions deferred to sub-plan 1c spec writing (don't affect 1a):

4. **androdr-071 ID collision** — renumber staging or production?
   *Recommendation:* Renumber the staging rule (production already shipped).

5. **Low-value staging rules (069, 066).** Promote, strengthen, or reject?
   *Recommendation:* Reject both; preserve intel as correlation atoms or IOC data.

6. **Bundle 1 "done" definition** — one rule promoted or all 5 resolved?
   *Recommendation:* The narrower one — one promoted end-to-end. The 5 staging rules are evaluated as a side effect but not blockers.

---

## Out of scope

Explicitly **not** in this meta-plan:
- Removing remaining hardcoded patterns from detection code (already done in PR #81)
- Wiring `evaluateDns()` into VPN/scan pipeline (separate project per `project_dns_eval_wiring` memory)
- Authoring new detection rules beyond what the 1c end-to-end run produces
- Publishing the rules repo as a standalone public project (separate Tier 1 project per `project_rule_engine_priority` memory)
- Migrating the AI pipeline skills to a shared plugin repo
- UAT on any of the above (existing UAT framework can be invoked separately via `uat-test` skill)

---

## Next step

**Start Bundle 1 with brainstorming for sub-plan 1a.** Invoke `superpowers:brainstorming` with the goal: *"Design sub-plan 1a: sync the validator with runtime schema and add a build-time gate that prevents future drift between the dev pipeline and the AI-powered rule updater."*

The brainstorm should:
1. Resolve open decisions 1, 2, 3 above
2. Produce a spec at `docs/superpowers/specs/2026-04-11-validator-sync-and-build-time-gate.md`

Then `superpowers:writing-plans` produces `docs/superpowers/plans/2026-04-11-ai-rule-framework-01a-validator-sync.md`. Then `superpowers:subagent-driven-development` executes. Then two-reviewer cycle. Then merge.

Sub-plans 1b, 1c, 2, 3 follow the same loop. Sub-plan 3 skips brainstorming for F4/F6/F8 and goes direct to plan writing, then brainstorms only F5.
