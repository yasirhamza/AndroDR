# Pipeline Candidate Accuracy — Design

**Date:** 2026-06-10
**Status:** Approved (brainstorm 2026-06-10)
**Goal metric:** % of pipeline candidates approved by the human reviewer *without modification*, tracked per run.

## Problem

The AI rule-update pipeline produces candidates (SIGMA rules + IOC-data entries)
that reach human-in-the-loop review carrying errors that should never have
gotten that far. Every class below has cost real review time:

| Failure | Class | Example |
|---|---|---|
| Invalid IOC category | machine-checkable | 49 entries authored with `category: TROJAN` (not in the schema enum); all failed `validate-ioc-data.py`, human relabeled to `MALWARE` |
| Over-severity posture rule | machine-checkable | androdr-084 proposed at `high`; `SeverityCapPolicy` clamps `device_posture` findings to `medium`, but no validation script checks declared levels |
| Duplicate rule semantics | partially checkable | androdr-084 duplicated androdr-047 (CISA-KEV-sourced) once capped to medium; shipped then reverted (#212/#213) |
| Retired-ID reuse risk | machine-checkable | e2e workflow hardcoded `next_id: androdr-084` after 084 was retired (fixed in #214, but nothing *enforces* non-reuse) |
| Judgment errors | not checkable | FP-risk misses, borderline severity, weak single-source IOCs |

A structural weakness compounds this: in the `update-rules-e2e` workflow,
Gate 5 ("LLM self-review with fresh eyes") runs **inside the same agent**
that ran Gates 1–3, so the independence the review skill was designed for
does not actually exist in the workflow path.

## Approach (chosen: C — both, phased)

Phase 1 makes every machine-checkable failure class mechanically unreachable
via deterministic scripts in the **public** `android-sigma-rules` repo.
Phase 2 adds a feedback loop so the remaining judgment-class errors shrink
over time and quality becomes a tracked number.

**Scope:** `.claude/` skills + e2e workflow in AndroDR, and validation
scripts/files in `third-party/android-sigma-rules`. **No Android app code.**

---

## Phase 1 — Deterministic gates

### 1a. Severity-cap lint (`validation/validate-rule.py`, sigma repo)

New check: if the top-level `category` field is `"device_posture"` and
`level` is `high` or `critical` → **error**:

> **Implementation correction (2026-06-11):** the cap is applied at runtime
> via `SeverityCapPolicy.applyCap(rule.category, rule.level)` — the
> **top-level `category`** field. `display.category` only selects the UI
> grouping bucket (androdr-020/030 are `category: incident`, displayed
> under device_posture, and legitimately fire at `critical`). The lint
> therefore keys on top-level `category` only.

> `device_posture rules are clamped to medium at runtime by SeverityCapPolicy; declare level: medium or below (or reclassify as category incident if a genuine HIGH/CRITICAL signal is intended)`

`medium`, `low`, `informational` pass unchanged. `app_risk`/`network`
categories are unaffected.

### 1b. Lone-exploited-CVE lint (`validation/validate-rule.py`, sigma repo)

New check: a rule with top-level `category == "device_posture"` (same
keying as 1a, per the 2026-06-11 correction) whose detection references
the `unpatched_cve_id` field with **exactly one** CVE value (string
equality or single-element list, any modifier) → **error**. An **empty**
value list is also rejected as a vacuous selection (reviewer finding,
2026-06-11):

> `single actively-exploited-CVE rules duplicate androdr-047 (CISA KEV catalog); only named-campaign CVE sets (cf. androdr-048..052) justify a dedicated rule`

Rules keying on two or more CVE values pass (campaign-set pattern).
Rules not using `unpatched_cve_id` are unaffected.

### 1c. Retired-ID registry (sigma repo)

New file `validation/retired-rule-ids.txt` — one `androdr-NNN` per line,
`#` comments allowed; seeded with `androdr-084` (retired 2026-06-08,
duplicate of androdr-047). `validate-rule.py` errors if the candidate's
`id` appears in the registry:

> `rule ID androdr-NNN was retired and must not be reused; allocate the next free ID`

Removal workflow note in the file header: IDs are never removed from the
registry once added.

### 1d. Author auto-retry on deterministic failures (AndroDR side)

The e2e workflow currently runs validators once; failed candidates go
straight to the report. Change: failed candidates are sent back —
validator stderr verbatim — to a **fresh author agent** for one repair
attempt, then re-validated AND re-reviewed. A second failure marks the
candidate failed for the report. One retry round only (matches the
dispatcher skill's existing Step 6 contract; prevents loops).

> **Implementation note (2026-06-11):** the repair round triggers on ANY
> failure, including independent-review (judgment) failures, not only
> deterministic-gate failures as originally drafted — review verdicts come
> with concrete `issues` that are just as repairable, and the
> one-round + `skip_note` escape hatch bounds the cost either way.

### 1e. Independent Gate 5 reviewer (AndroDR side, e2e workflow)

The workflow spawns a **separate reviewer agent per candidate**, prompted
from `update-rules-review.md` with ONLY: candidate YAML, a brief SIR
summary, and 2–3 similar existing rules. It does NOT see the validator's
gate results or the author's reasoning. The workflow merges its structured
review into `gates.self_review` in JS. The validator agent's own Gate 5
instruction is dropped from the workflow prompt (the validate *skill* keeps
its inline-review text for the dispatcher path, where a validator subagent
cannot spawn agents).

### Phase 1 tests (sigma repo, pytest)

- posture rule at `medium` → pass; at `high` / `critical` → fail (1a)
- posture rule keying one CVE → fail; CVE-set campaign rule → pass;
  non-CVE posture rule → pass (1b)
- candidate with retired ID → fail; fresh ID → pass (1c)
- registry file parse: comments/blank lines tolerated (1c)

Existing production + staging rules must all still pass `validate-rule.py`
(regression sweep in the test).

---

## Phase 2 — Feedback loop

### 2a. Run ledger (`pipeline-runs/` in the sigma repo, public)

One YAML per run, written by the dispatcher at the end of Step 8 (after
all HitL decisions), through the normal HitL gate before commit:

```yaml
run: 2026-06-10
mode: full          # full | source:<id> | threat | discover | e2e
candidates:
  - id: androdr-085            # or indicator for IOC-only candidates
    verdict: approved          # approved | approved_with_modification | rejected
    reason: ""                 # reviewer's stated reason (required for non-approved)
    failure_class: null        # severity_judgment | fp_risk | duplicate_semantics |
                               # weak_sourcing | category_choice | other | null
totals:
  candidates: 7
  approved: 5
  approved_with_modification: 1
  rejected: 1
  approval_without_modification_rate: 0.71
```

Ledger write failures never block rule commits — rules are the product,
the ledger is telemetry. Failure is reported in the run summary.

### 2b. Authoring lessons (`validation/authoring-lessons.yml`, sigma repo)

A curated, capped (≤ 20 entries) list of judgment guidance, NOT a raw log:

```yaml
lessons:
  - class: duplicate_semantics
    guidance: >
      Posture rules keying on a single actively-exploited CVE duplicate
      androdr-047; propose named-campaign CVE-set rules only.
```

Flow: after each run, if rejection reasons suggest a new lesson, the
dispatcher proposes the addition as a candidate (HitL approve/reject).
The dispatcher and e2e workflow inject the file's contents into every
author AND validator prompt. A missing or unparseable lessons file
degrades to "no lessons injected" + a logged warning — never a run
failure. When the cap is hit, the dispatcher proposes which stale lesson
to drop (HitL).

### 2c. Metric surfacing

The dispatcher's run summary prints `approval_without_modification_rate`
for the current run and the previous four (read from `pipeline-runs/`),
so the trend is visible at the end of every run.

---

## Delivery

1. **PR 1 (sigma repo):** lints 1a/1b, registry 1c, pytest suite,
   `authoring-lessons.yml` (seeded with 2–3 lessons from the memories:
   posture cap, no-TROJAN, lone-CVE), `pipeline-runs/` README + schema
   comment. All rules in production/staging must pass.
2. **PR 2 (AndroDR):** submodule bump; e2e workflow changes (1d retry,
   1e independent reviewer, lessons injection); dispatcher + author +
   validator skill updates (ledger Step 8 instructions, lessons injection,
   metric summary). Two-reviewer cycle per project policy.

Order matters: PR 1 merges first so PR 2's submodule bump picks it up.

## Out of scope

- Android app code (incl. `GateFourFixtureTest` extensions, FP-corpus runs)
- Feed reliability work (#127 ThreatFox parsers, #138 smoke tests)
- Detection coverage (#180 taxonomy, #209 implies_flags, #139 lineage)
- Gate 4 un-deferral in the e2e workflow

These remain candidates for later phases under the same goal.
