# Pipeline Candidate Accuracy Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make every machine-checkable pipeline failure class (over-severity posture rules, lone-exploited-CVE duplicates, retired-ID reuse) mechanically un-reachable via deterministic lints in the public sigma repo, restore Gate-5 independence + add one author-repair round in the e2e workflow, and add a run ledger + curated lessons feedback loop.

**Architecture:** Part A extends `validate-rule.py` in the `third-party/android-sigma-rules` submodule (its own public repo, own PR) with three lints + a pytest suite, and seeds the Phase-2 files. Part B bumps the submodule in AndroDR and rewires the e2e workflow's Validate phase (independent reviewer agent per candidate, one repair round) plus dispatcher/author skill updates for the ledger and lessons.

**Tech Stack:** Python 3 (stdlib + pyyaml + pytest, subprocess-based tests matching `test_validate_ioc_data.py` conventions), Claude Code workflow JS, markdown skills.

**Spec:** `docs/superpowers/specs/2026-06-10-pipeline-candidate-accuracy-design.md`

**Conventions for all tasks:**
- Sigma-repo work happens inside `/home/yasir/AndroDR/third-party/android-sigma-rules` on branch `feat/candidate-accuracy-gates` (create in Task 1). AndroDR work happens in `/home/yasir/AndroDR` on branch `feat/pipeline-candidate-accuracy` (create in Task 7).
- Run sigma-repo tests with: `python3 -m pytest validation/ -q` (from the submodule root).
- The workflow JS cannot be `node --check`ed directly (top-level `return` is valid only in the harness's async wrapper). Syntax-check it with the wrapper snippet given in Task 10 Step 4.
- Ground-truth facts already verified: `SigmaRuleEvaluator.kt:108` derives the severity-cap category from `display.category`; campaign rules 048–052 use `unpatched_cve_id|contains` with ≥3 values; androdr-047 uses `unpatched_cve_count|gte: 1` (the lone-CVE lint must NOT fire on it); all existing posture rules declare `level: medium` or lower.

---

## Part A — sigma repo (public): deterministic gates

### Task 1: Retired-ID registry

**Files:**
- Create: `validation/retired-rule-ids.txt` (in the submodule)
- Create: `validation/test_validate_rule_lints.py`
- Modify: `validation/validate-rule.py`

- [ ] **Step 1: Create branch in the submodule**

```bash
cd /home/yasir/AndroDR/third-party/android-sigma-rules
git checkout main && git pull --ff-only
git checkout -b feat/candidate-accuracy-gates
```

- [ ] **Step 2: Write the failing tests**

Create `validation/test_validate_rule_lints.py`:

```python
"""Tests for the candidate-accuracy lints in validate-rule.py (AndroDR pipeline
candidate-accuracy spec, 2026-06-10): retired-ID registry, device-posture
severity cap, lone-exploited-CVE rejection, plus a regression sweep over all
existing rules.

Run:
    python3 -m pytest validation/test_validate_rule_lints.py -v
"""
import copy
import pathlib
import subprocess
import sys

import yaml

THIS_DIR = pathlib.Path(__file__).parent
REPO = THIS_DIR.parent
SCRIPT = THIS_DIR / "validate-rule.py"

# A known-good production posture rule is the mutation baseline — guarantees
# the unmodified parts always satisfy the schema.
BASE = yaml.safe_load(
    (REPO / "device_auditor" / "androdr_044_stale_patch.yml").read_text()
)


def run_validator_on(tmp_path, rule: dict):
    p = tmp_path / "rule.yml"
    p.write_text(yaml.safe_dump(rule, sort_keys=False))
    return subprocess.run(
        [sys.executable, str(SCRIPT), str(p)],
        capture_output=True, text=True,
    )


def make_rule(**overrides) -> dict:
    rule = copy.deepcopy(BASE)
    rule.update(overrides)
    return rule


# ---------- retired-ID registry ----------

def test_retired_id_rejected(tmp_path):
    result = run_validator_on(tmp_path, make_rule(id="androdr-084"))
    assert result.returncode == 1
    assert "retired" in result.stderr


def test_fresh_id_accepted(tmp_path):
    result = run_validator_on(tmp_path, make_rule(id="androdr-200"))
    assert result.returncode == 0, result.stderr


def test_registry_file_exists_and_seeded():
    registry = THIS_DIR / "retired-rule-ids.txt"
    assert registry.exists()
    ids = {
        line.strip()
        for line in registry.read_text().splitlines()
        if line.strip() and not line.startswith("#")
    }
    assert "androdr-084" in ids
```

- [ ] **Step 3: Run tests to verify they fail**

```bash
cd /home/yasir/AndroDR/third-party/android-sigma-rules
python3 -m pytest validation/test_validate_rule_lints.py -v
```
Expected: `test_retired_id_rejected` FAILS (validator passes the rule, returncode 0); `test_registry_file_exists_and_seeded` FAILS (file missing). `test_fresh_id_accepted` may already pass.

- [ ] **Step 4: Create the registry file**

Create `validation/retired-rule-ids.txt`:

```
# Retired AndroDR rule IDs — NEVER reuse these.
# An ID lands here when its rule is removed from production/staging for any
# reason (duplicate, superseded, bad design). IDs are append-only: once
# listed, an ID stays here forever, even if the original removal is later
# regretted — allocate a new ID instead.
# Checked by validate-rule.py; a candidate using a retired ID fails Gate 1.

androdr-084   # retired 2026-06-08: duplicate of androdr-047 once severity-capped (PRs rules#30/#31, AndroDR#212/#213)
```

- [ ] **Step 5: Implement the registry check in `validate-rule.py`**

Add a loader next to `load_permissions` (after line 38):

```python
def load_retired_ids(path: Path) -> set[str]:
    """IDs listed in retired-rule-ids.txt may never be reused."""
    if not path.exists():
        return set()
    with open(path) as f:
        return {
            line.split("#")[0].strip()
            for line in f
            if line.split("#")[0].strip()
        }
```

Change the `validate_rule` signature (line 41) to accept the set with a safe default:

```python
def validate_rule(rule: dict, schema: dict, permissions: set[str],
                  retired_ids: frozenset[str] | set[str] = frozenset()) -> list[str]:
```

Extend the existing `if "id" in rule:` block (lines 50–53) to:

```python
    if "id" in rule:
        rule_id = rule["id"]
        if not isinstance(rule_id, str) or not rule_id.startswith("androdr-"):
            errors.append(f"Rule ID must match 'androdr-NNN', got: {rule_id}")
        elif rule_id in retired_ids:
            errors.append(
                f"Rule ID {rule_id} was retired and must not be reused "
                f"(see validation/retired-rule-ids.txt); allocate the next free ID"
            )
```

In `main()`, load and pass the registry — after the `permissions = ...` line:

```python
    retired_path = SCRIPT_DIR / "retired-rule-ids.txt"
    retired_ids = load_retired_ids(retired_path)
```

and change the call:

```python
    errors = validate_rule(rule, schema, permissions, retired_ids)
```

- [ ] **Step 6: Run tests to verify they pass**

```bash
python3 -m pytest validation/test_validate_rule_lints.py -v
```
Expected: 3 passed.

- [ ] **Step 7: Commit**

```bash
git add validation/retired-rule-ids.txt validation/validate-rule.py validation/test_validate_rule_lints.py
git commit -m "feat(validation): retired-rule-ID registry, checked by validate-rule.py"
```

### Task 2: Device-posture severity-cap lint

**Files:**
- Modify: `validation/validate-rule.py`
- Modify: `validation/test_validate_rule_lints.py`

- [ ] **Step 1: Write the failing tests** (append to `validation/test_validate_rule_lints.py`)

```python
# ---------- device-posture severity cap ----------

def test_posture_rule_at_high_rejected(tmp_path):
    result = run_validator_on(tmp_path, make_rule(level="high"))
    assert result.returncode == 1
    assert "SeverityCapPolicy" in result.stderr


def test_posture_rule_at_critical_rejected(tmp_path):
    result = run_validator_on(tmp_path, make_rule(level="critical"))
    assert result.returncode == 1


def test_posture_rule_at_medium_accepted(tmp_path):
    result = run_validator_on(tmp_path, make_rule(level="medium"))
    assert result.returncode == 0, result.stderr


def test_posture_cap_keys_on_top_level_category_too(tmp_path):
    # display.category app_risk but top-level category device_posture → capped
    rule = make_rule(level="high")
    rule["display"] = copy.deepcopy(rule["display"])
    rule["display"]["category"] = "app_risk"
    rule["category"] = "device_posture"
    result = run_validator_on(tmp_path, rule)
    assert result.returncode == 1


def test_non_posture_rule_at_high_accepted(tmp_path):
    rule = make_rule(level="high")
    rule.pop("category", None)
    rule.pop("report_safe_state", None)
    rule["display"] = copy.deepcopy(rule["display"])
    rule["display"]["category"] = "app_risk"
    rule["display"].pop("safe_title", None)
    result = run_validator_on(tmp_path, rule)
    assert result.returncode == 0, result.stderr
```

Note: `BASE` (androdr_044) has `display.category: device_posture`, so `make_rule(level="high")` is a capped-category rule by default.

- [ ] **Step 2: Run tests to verify the new ones fail**

```bash
python3 -m pytest validation/test_validate_rule_lints.py -v
```
Expected: the two `rejected` tests and `keys_on_top_level` FAIL; the `accepted` tests pass.

- [ ] **Step 3: Implement the lint**

In `validate_rule()`, immediately after the existing `level` check (line 58–59 block), add:

```python
    # Severity-cap policy: device_posture findings are clamped to 'medium' at
    # runtime (AndroDR SeverityCapPolicy; evaluator derives the cap category
    # from display.category, see SigmaRuleEvaluator). Declaring above medium
    # is dead text — reject so the pipeline never proposes it.
    effective_category = (
        rule.get("category")
        or rule.get("display", {}).get("category")
        if isinstance(rule.get("display", {}), dict) else rule.get("category")
    )
    posture = (
        rule.get("category") == "device_posture"
        or (isinstance(rule.get("display"), dict)
            and rule["display"].get("category") == "device_posture")
    )
    if posture and rule.get("level") in ("high", "critical"):
        errors.append(
            "device_posture rules are clamped to 'medium' at runtime by "
            "SeverityCapPolicy; declare level: medium or below (or reclassify "
            "as category: incident if a genuine HIGH/CRITICAL signal is intended)"
        )
```

(The `effective_category` variable is reused by Task 3 — keep it even though
the `posture` flag is what this lint reads.)

- [ ] **Step 4: Run tests to verify they pass**

```bash
python3 -m pytest validation/test_validate_rule_lints.py -v
```
Expected: all pass.

- [ ] **Step 5: Commit**

```bash
git add validation/validate-rule.py validation/test_validate_rule_lints.py
git commit -m "feat(validation): reject device_posture rules declared above the medium severity cap"
```

### Task 3: Lone-exploited-CVE lint

**Files:**
- Modify: `validation/validate-rule.py`
- Modify: `validation/test_validate_rule_lints.py`

- [ ] **Step 1: Write the failing tests** (append to `validation/test_validate_rule_lints.py`)

```python
# ---------- lone-exploited-CVE rejection ----------

def _cve_rule(cves):
    rule = make_rule()
    rule["detection"] = {
        "selection": {"unpatched_cve_id|contains": cves},
        "condition": "selection",
    }
    return rule


def test_single_cve_list_rejected(tmp_path):
    result = run_validator_on(tmp_path, _cve_rule(["CVE-2026-12345"]))
    assert result.returncode == 1
    assert "androdr-047" in result.stderr


def test_single_cve_string_rejected(tmp_path):
    result = run_validator_on(tmp_path, _cve_rule("CVE-2026-12345"))
    assert result.returncode == 1


def test_cve_set_accepted(tmp_path):
    result = run_validator_on(
        tmp_path, _cve_rule(["CVE-2026-1", "CVE-2026-2", "CVE-2026-3"])
    )
    assert result.returncode == 0, result.stderr


def test_non_cve_posture_rule_unaffected(tmp_path):
    result = run_validator_on(tmp_path, make_rule())
    assert result.returncode == 0, result.stderr
```

- [ ] **Step 2: Run tests to verify the new ones fail**

```bash
python3 -m pytest validation/test_validate_rule_lints.py -v
```
Expected: the two `rejected` tests FAIL; the `accepted`/`unaffected` tests pass.

- [ ] **Step 3: Implement the lint**

In `validate_rule()`, inside the existing detection loop (`for sel_name, sel_value in detection.items():`, line 85), after the modifier checks, add:

```python
            # Lone actively-exploited-CVE rule = duplicate of androdr-047
            # (CISA KEV catalog) once the severity cap lands. Only
            # named-campaign CVE *sets* (cf. androdr-048..052) justify a
            # dedicated rule.
            base_field = field_key.split("|")[0]
            if base_field == "unpatched_cve_id" and posture:
                cve_values = sel_value[field_key]
                count = len(cve_values) if isinstance(cve_values, list) else 1
                if count == 1:
                    errors.append(
                        "single actively-exploited-CVE rules duplicate "
                        "androdr-047 (CISA KEV catalog); only named-campaign "
                        "CVE sets (cf. androdr-048..052) justify a dedicated rule"
                    )
```

Note: this sits inside the `for field_key in sel_value:` loop where `field_key`
is in scope; the `posture` flag comes from Task 2's code, which runs earlier
in the function. Move the Task 2 block ABOVE the detection loop if it isn't
already (it is, if inserted after the `level` check as instructed).

- [ ] **Step 4: Run tests to verify they pass**

```bash
python3 -m pytest validation/test_validate_rule_lints.py -v
```
Expected: all pass.

- [ ] **Step 5: Commit**

```bash
git add validation/validate-rule.py validation/test_validate_rule_lints.py
git commit -m "feat(validation): reject lone actively-exploited-CVE posture rules (androdr-047 duplicates)"
```

### Task 4: Regression sweep — every existing rule still passes

**Files:**
- Modify: `validation/test_validate_rule_lints.py`

- [ ] **Step 1: Write the sweep test** (append)

```python
# ---------- regression: all shipped rules still pass ----------

def test_all_existing_rules_pass_validator():
    rule_files = sorted(REPO.glob("*/androdr_*.yml")) + sorted(
        REPO.glob("staging/*/androdr_*.yml")
    )
    assert len(rule_files) > 30, "rule discovery glob looks broken"
    failures = []
    for p in rule_files:
        result = subprocess.run(
            [sys.executable, str(SCRIPT), str(p)],
            capture_output=True, text=True,
        )
        if result.returncode != 0:
            failures.append(f"{p.relative_to(REPO)}:\n{result.stderr}")
    assert not failures, "\n".join(failures)
```

- [ ] **Step 2: Run the full suite**

```bash
python3 -m pytest validation/ -q
```
Expected: all pass (including pre-existing `test_validate_ioc_*` suites). If any shipped rule fails a new lint, STOP — that is a design-level conflict to surface to the human, not something to "fix" by weakening the lint.

- [ ] **Step 3: Commit**

```bash
git add validation/test_validate_rule_lints.py
git commit -m "test(validation): regression sweep — all shipped rules pass the new lints"
```

### Task 5: Seed Phase-2 files (lessons + ledger home)

**Files:**
- Create: `validation/authoring-lessons.yml`
- Create: `pipeline-runs/README.md`

- [ ] **Step 1: Create `validation/authoring-lessons.yml`**

```yaml
# Curated judgment guidance for the AndroDR AI rule pipeline.
# Injected verbatim into Rule Author AND Validator/Reviewer prompts.
# HARD CAP: 20 lessons. Additions/removals go through the pipeline's
# human-in-the-loop gate (proposed by the dispatcher from run-ledger
# rejection reasons, approved by the human).
# Each lesson: class (failure_class taxonomy from pipeline-runs/README.md)
# + guidance (one short paragraph, imperative voice).

lessons:
  - class: severity_judgment
    guidance: >
      device_posture rules are clamped to medium at runtime by
      SeverityCapPolicy. Never declare high/critical on a posture rule;
      convey urgency through the title and remediation text instead
      (cf. androdr-048..052).
  - class: category_choice
    guidance: >
      The IOC category enum has no TROJAN. Label banking trojans and RATs
      as MALWARE; surveillance-ware as SPYWARE or NATION_STATE_SPYWARE.
      Never invent enum values — validate-ioc-data.py rejects them.
  - class: duplicate_semantics
    guidance: >
      A posture rule keying on a single actively-exploited CVE duplicates
      androdr-047 (CISA KEV-sourced). Only named-campaign CVE sets with a
      threat-specific title justify a dedicated rule.
```

- [ ] **Step 2: Create `pipeline-runs/README.md`**

```markdown
# Pipeline run ledger

One YAML file per AI rule-update pipeline run, written at the end of the
human-in-the-loop review (Step 8 of the dispatcher). Rules are the product;
this ledger is telemetry — a ledger write failure never blocks a rule commit.

File name: `YYYY-MM-DD-<mode>.yml` (mode: `full`, `source-<id>`, `threat`,
`discover`, or `e2e`; append `-2`, `-3`… for multiple same-day runs).

## Schema

```yaml
run: 2026-06-10
mode: full
candidates:
  - id: androdr-085          # rule ID, or the indicator for IOC-only candidates
    verdict: approved        # approved | approved_with_modification | rejected
    reason: ""               # reviewer's words; REQUIRED unless verdict=approved
    failure_class: null      # severity_judgment | fp_risk | duplicate_semantics |
                             # weak_sourcing | category_choice | other | null
totals:
  candidates: 7
  approved: 5
  approved_with_modification: 1
  rejected: 1
  approval_without_modification_rate: 0.71   # approved / candidates, 2 dp
```

`failure_class` feeds `validation/authoring-lessons.yml` curation: recurring
classes become candidate lessons, proposed by the dispatcher and approved by
the human like any other candidate.
```

- [ ] **Step 3: Sanity-check the lessons file parses**

```bash
python3 -c "import yaml; d=yaml.safe_load(open('validation/authoring-lessons.yml')); assert isinstance(d['lessons'], list) and len(d['lessons'])==3; print('lessons OK')"
```
Expected: `lessons OK`

- [ ] **Step 4: Commit**

```bash
git add validation/authoring-lessons.yml pipeline-runs/README.md
git commit -m "feat(pipeline): seed authoring-lessons.yml and pipeline-runs ledger home"
```

### Task 6: Sigma-repo PR

- [ ] **Step 1: Full local verification**

```bash
cd /home/yasir/AndroDR/third-party/android-sigma-rules
python3 -m pytest validation/ -q
```
Expected: all pass, 0 failures.

- [ ] **Step 2: Push and open PR**

```bash
git push -u origin feat/candidate-accuracy-gates
gh pr create --base main --title "feat(validation): candidate-accuracy gates (severity cap, lone-CVE, retired IDs) + lessons/ledger seeds" --body "Deterministic lints so the AndroDR AI pipeline can never re-propose its past failure classes: device_posture severity cap (SeverityCapPolicy mirror), lone actively-exploited-CVE rejection (androdr-047 duplicates), retired-rule-ID registry. Plus seeded validation/authoring-lessons.yml and pipeline-runs/ ledger home. Spec: AndroDR docs/superpowers/specs/2026-06-10-pipeline-candidate-accuracy-design.md.

🤖 Generated with [Claude Code](https://claude.com/claude-code)"
```

- [ ] **Step 3: Merge (project policy: local verification suffices; cancel any in-flight CI first)**

```bash
gh run list --branch feat/candidate-accuracy-gates --json databaseId,status -q '.[] | select(.status != "completed") | .databaseId' | xargs -r -n1 gh run cancel
gh pr merge --admin --squash --delete-branch
git checkout main && git pull --ff-only
```

---

## Part B — AndroDR: workflow + skills

### Task 7: Submodule bump

**Files:**
- Modify: submodule pointer `third-party/android-sigma-rules`

- [ ] **Step 1: Branch + bump**

```bash
cd /home/yasir/AndroDR
git checkout main && git pull --ff-only
git checkout -b feat/pipeline-candidate-accuracy
cd third-party/android-sigma-rules && git checkout main && git pull --ff-only && cd ../..
git add third-party/android-sigma-rules
git commit -m "build: bump android-sigma-rules submodule (candidate-accuracy gates)"
```

- [ ] **Step 2: Verify the bump picked up the new files**

```bash
ls third-party/android-sigma-rules/validation/retired-rule-ids.txt third-party/android-sigma-rules/validation/authoring-lessons.yml third-party/android-sigma-rules/pipeline-runs/README.md
```
Expected: all three paths print (no "No such file").

### Task 8: Workflow — schemas + new prompts (independent reviewer, repair)

**Files:**
- Modify: `.claude/workflows/update-rules-e2e.workflow.js`

- [ ] **Step 1: Add the two new output schemas**

After the `VALIDATE_OUT` schema definition, add:

```js
const REVIEW_OUT = {
  type: 'object',
  required: ['verdict'],
  additionalProperties: true,
  properties: {
    verdict: { type: 'string' },              // pass | pass_with_notes | fail
    false_positive_risk: { type: 'string' },  // low | medium | high
    issues: { type: 'array', items: { type: 'string' } },
    suggestions: { type: 'array', items: { type: 'string' } },
    notes: { type: 'array', items: { type: 'string' } },
  },
}
const REPAIR_OUT = {
  type: 'object',
  required: ['rule_id', 'yaml'],
  additionalProperties: true,
  properties: {
    rule_id: { type: 'string' },
    yaml: { type: 'string' },
    decisions: { type: 'array', items: { type: 'object', additionalProperties: true } },
    skip_note: { type: 'string' },
  },
}
```

- [ ] **Step 2: Strip Gate 5 from `validatePrompt` and renumber its gate set**

In `validatePrompt`, replace:

```js
Read ${REPO}/.claude/commands/update-rules-validate.md. Run Gates 1, 1.2, 2, 3, and 5.
```

with:

```js
Read ${REPO}/.claude/commands/update-rules-validate.md. Run Gates 1, 1.2, 2, and 3 ONLY.
DO NOT run Gate 5 (self-review): an INDEPENDENT reviewer agent runs it separately in this workflow so it has genuinely fresh eyes. Record gates.self_review = {"pass": null, "skipped": true, "reason": "run independently by the workflow"}.
```

and DELETE the line beginning `Gate 5: perform the self-review yourself…` from the same prompt. Also append to the prompt body (before the `sigma_repo_path:` line):

```js
Authoring lessons: READ ${SIGMA}/validation/authoring-lessons.yml if it exists and apply its guidance when judging the rule. If missing or unparseable, proceed without it and note that in your output.
```

- [ ] **Step 3: Add `reviewPrompt` and `repairPrompt` functions**

After the `validatePrompt` function, add:

```js
function reviewPrompt(c, sirs) {
  const related = sirs
    .filter(s => s && s.threat && s.threat.name)
    .map(s => `- ${s.threat.name}: ${(s.threat.description || '').slice(0, 200)}`)
    .slice(0, 10)
    .join('\n')
  return `You are an INDEPENDENT reviewer for the AndroDR SIGMA pipeline (Gate 5), running inside ${REPO} (rules submodule at ${SIGMA}). You have NOT seen the Rule Author's reasoning or any validator gate results — review with completely fresh eyes.

Read ${REPO}/.claude/commands/update-rules-review.md and apply its five criteria exactly.
Also READ ${SIGMA}/validation/authoring-lessons.yml if it exists and apply its guidance; if missing, proceed without it.

For "similar_rules" context, pick 2-3 same-category entries from this index and read their YAML files in the submodule:
${RULE_INDEX}

SIR summaries (source threat intel context):
${related || '(none provided)'}

Candidate YAML:
---
${c.yaml || ''}
---

Return ONLY {verdict, false_positive_risk, issues, suggestions, notes} JSON per the review command's output section. Entire final message = that JSON.`
}

function repairPrompt(candidate, validation, sirs) {
  return `You are the Rule Author for the AndroDR SIGMA pipeline, running inside ${REPO} (rules submodule at ${SIGMA}).

Read ${REPO}/.claude/commands/update-rules-author.md and follow it EXACTLY.
Also READ ${SIGMA}/validation/authoring-lessons.yml if it exists and apply its guidance.

Your earlier candidate FAILED validation. Fix ONLY the reported failures — do not redesign the rule, change its ID, or touch passing aspects. If a failure cannot be fixed without inventing data (e.g. an IOC the SIRs never contained), return the original yaml unchanged plus a skip_note explaining why.

today's date: ${TODAY}

FAILED candidate (rule_id ${candidate.rule_id || 'unknown'}):
---
${candidate.yaml || ''}
---

ValidationResult (fix every gate with pass=false; validator stderr is included verbatim):
${JSON.stringify(validation)}

Source SIRs (the ONLY permitted data source for indicators):
${JSON.stringify(sirs)}

Return ONLY {rule_id, yaml, decisions, skip_note?} JSON. Entire final message = that JSON.`
}
```

- [ ] **Step 4: Add lessons injection to `authorPrompt`**

In `authorPrompt`, after the `Logsource taxonomy: …` paragraph, add this line:

```js
Authoring lessons: READ ${SIGMA}/validation/authoring-lessons.yml if it exists — it is curated guidance distilled from past human rejections. Apply every lesson. If the file is missing or unparseable, proceed without it and say so in a log field.
```

- [ ] **Step 5: Commit**

```bash
cd /home/yasir/AndroDR
git add .claude/workflows/update-rules-e2e.workflow.js
git commit -m "feat(workflow): independent Gate-5 reviewer + repair prompts + lessons injection (prompts/schemas)"
```

### Task 9: Workflow — rewire the Validate phase (assess, merge, one repair round)

**Files:**
- Modify: `.claude/workflows/update-rules-e2e.workflow.js`

- [ ] **Step 1: Replace the Validate orchestration block**

Replace everything from `phase('Validate')` down to (and including) the
`const passed = …` / `const failed = …` lines with:

```js
phase('Validate')

function mergeAssessment(c, v, r, retryCount) {
  const validation = v || { rule_id: c.rule_id || 'unknown', overall: 'error', gates: {}, retry_count: 0 }
  validation.gates = validation.gates || {}
  validation.gates.self_review = r
    ? { pass: r.verdict !== 'fail', verdict: r.verdict, fp_risk: r.false_positive_risk || 'unknown', suggestions: r.suggestions || [], issues: r.issues || [] }
    : { pass: false, verdict: 'error', fp_risk: 'unknown', suggestions: [], issues: ['review agent failed or was skipped'] }
  const gatesPass = !!v && validation.overall === 'pass'
  const reviewPass = !!r && r.verdict !== 'fail'
  validation.overall = (gatesPass && reviewPass) ? 'pass' : 'fail'
  validation.retry_count = retryCount
  return { candidate: c, validation }
}

// Validator and independent reviewer run concurrently per candidate:
// slots [2i] = validation, [2i+1] = review. IOC validation rides last.
const assessThunks = candidates.flatMap(c => [
  () => agent(validatePrompt(c, allSirs), { label: `validate:${c.rule_id || 'rule'}`, phase: 'Validate', schema: VALIDATE_OUT }),
  () => agent(reviewPrompt(c, allSirs), { label: `review:${c.rule_id || 'rule'}`, phase: 'Validate', schema: REVIEW_OUT }),
])
const iocValidationThunk = iocData.length
  ? [() => agent(iocValidatePrompt(iocData), { label: 'validate:ioc-data', phase: 'Validate', schema: IOC_VALIDATE_OUT })]
  : []

const assessRaw = await parallel([...assessThunks, ...iocValidationThunk])
const iocValidation = iocData.length
  ? (assessRaw[assessRaw.length - 1] || { valid_entries: [], rejected: [], log: ['ioc validation agent failed or was skipped'] })
  : { valid_entries: [], rejected: [], log: [] }

const firstRound = candidates.map((c, i) => mergeAssessment(c, assessRaw[2 * i], assessRaw[2 * i + 1], 0))
const passed = firstRound.filter(rv => rv.validation.overall === 'pass')
let failed = firstRound.filter(rv => rv.validation.overall !== 'pass')

// One author-repair round for failures (dispatcher Step 6 contract: a second
// failure is final). Repaired candidates are re-validated AND re-reviewed.
if (failed.length) {
  log(`${failed.length} candidate(s) failed first assessment — one repair round`)
  const repairs = await parallel(failed.map(rv => () =>
    agent(repairPrompt(rv.candidate, rv.validation, allSirs),
      { label: `repair:${rv.candidate.rule_id || 'rule'}`, phase: 'Validate', schema: REPAIR_OUT })))
  const retryPairs = []
  const unrepairable = []
  repairs.forEach((rep, i) => {
    if (rep && rep.yaml && !rep.skip_note) {
      retryPairs.push({ candidate: { ...failed[i].candidate, yaml: rep.yaml, decisions: rep.decisions || failed[i].candidate.decisions } })
    } else {
      if (rep && rep.skip_note) failed[i].validation.repair_skip_note = rep.skip_note
      unrepairable.push(failed[i])
    }
  })
  const reRaw = retryPairs.length ? await parallel(retryPairs.flatMap(p => [
    () => agent(validatePrompt(p.candidate, allSirs), { label: `revalidate:${p.candidate.rule_id || 'rule'}`, phase: 'Validate', schema: VALIDATE_OUT }),
    () => agent(reviewPrompt(p.candidate, allSirs), { label: `rereview:${p.candidate.rule_id || 'rule'}`, phase: 'Validate', schema: REVIEW_OUT }),
  ])) : []
  const secondRound = retryPairs.map((p, i) => mergeAssessment(p.candidate, reRaw[2 * i], reRaw[2 * i + 1], 1))
  passed.push(...secondRound.filter(rv => rv.validation.overall === 'pass'))
  failed = [...unrepairable, ...secondRound.filter(rv => rv.validation.overall !== 'pass')]
  log(`After repair round: ${passed.length} passed, ${failed.length} failed`)
}
```

(The old `validationThunks` / `validatedAll` / `ruleValidations` block is fully
superseded — make sure no stray references to those names remain.)

- [ ] **Step 2: Update `meta.phases` Validate detail**

Replace the Validate entry in `meta.phases` with:

```js
    { title: 'Validate', detail: 'gates 1/1.2/2/3 + independent Gate-5 reviewer per candidate + one author-repair round; IOC structural validation (gate 4 + strict complementarity deferred)' },
```

- [ ] **Step 3: Syntax-check the workflow the way the harness wraps it**

```bash
cd /home/yasir/AndroDR
python3 - <<'EOF'
src = open('.claude/workflows/update-rules-e2e.workflow.js').read()
idx = src.index('\n}\n', src.index('export const meta'))
open('/tmp/wf-body.mjs','w').write('async function main(args, agent, parallel, pipeline, phase, log, budget, workflow) {\n' + src[idx+3:] + '\n}\n')
EOF
node --check /tmp/wf-body.mjs && echo "BODY SYNTAX OK"
grep -n "validatedAll\|ruleValidations\|validationThunks" .claude/workflows/update-rules-e2e.workflow.js || echo "NO STALE REFERENCES"
```
Expected: `BODY SYNTAX OK` and `NO STALE REFERENCES` (the grep must find nothing).

- [ ] **Step 4: Commit**

```bash
git add .claude/workflows/update-rules-e2e.workflow.js
git commit -m "feat(workflow): rewire Validate phase — independent review merge + one repair round"
```

### Task 10: Dispatcher skill — run ledger, metric, lessons curation

**Files:**
- Modify: `.claude/commands/update-rules.md`

- [ ] **Step 1: Add Step 8.3 (ledger) and Step 8.4 (lessons + metric)**

In `.claude/commands/update-rules.md`, after the `### 8.2 Safety rules` section, insert:

```markdown
### 8.3 Run ledger (Phase 2, candidate-accuracy spec)

After all HitL decisions, write one ledger file to `pipeline-runs/` in the
sigma repo: `YYYY-MM-DD-<mode>.yml` (schema in `pipeline-runs/README.md`).
Record per candidate: `id` (rule ID or indicator), `verdict`
(`approved` / `approved_with_modification` / `rejected`), the reviewer's
`reason` (required unless approved), and a `failure_class`
(`severity_judgment`, `fp_risk`, `duplicate_semantics`, `weak_sourcing`,
`category_choice`, `other`, or `null`). Compute `totals` including
`approval_without_modification_rate` (approved ÷ candidates, 2 decimal
places). Show the ledger to the user before committing (normal HitL gate).

**A ledger write failure never blocks rule commits** — rules are the
product, the ledger is telemetry. Report the failure in the run summary
and move on.

### 8.4 Lessons curation + metric trend

1. If any rejection `reason` this run describes a *judgment* error not yet
   covered by `validation/authoring-lessons.yml`, draft a one-paragraph
   lesson (`class` + `guidance`) and present it as a candidate for the user
   to approve, modify, or reject. Hard cap: 20 lessons — at the cap,
   propose which stale lesson to drop.
2. In the final run summary, print `approval_without_modification_rate`
   for this run and the previous four (read from `pipeline-runs/`), oldest
   first, so the trend is visible:

   ```
   Approval-without-modification trend: 0.57 → 0.63 → 0.71 (this run)
   ```
```

- [ ] **Step 2: Add lessons injection to Step 4 (Rule Author dispatch)**

In Step 4, the list of things passed to the Rule Author currently ends with
the extracted taxonomy field lists. Add one more bullet:

```markdown
- **The contents of `third-party/android-sigma-rules/validation/authoring-lessons.yml`** (curated guidance from past human rejections). If the file is missing or unparseable, dispatch without it and log a warning — never fail the run over lessons.
```

- [ ] **Step 3: Commit**

```bash
git add .claude/commands/update-rules.md
git commit -m "feat(skills): dispatcher run ledger, approval-rate trend, lessons curation"
```

### Task 11: Author + validator skill touch-ups

**Files:**
- Modify: `.claude/commands/update-rules-author.md`
- Modify: `.claude/commands/update-rules-validate.md`

- [ ] **Step 1: Author skill — declare the lessons input**

In `update-rules-author.md`, in the `## Input` list, add after the
`taxonomy_fields` bullet:

```markdown
- `authoring_lessons`: (optional) curated guidance distilled from past human rejections (`validation/authoring-lessons.yml`). Treat every lesson as a hard constraint on your output. When absent, proceed normally.
```

- [ ] **Step 2: Validator skill — registry + new lints note**

In `update-rules-validate.md`, in the Gate 1 manual-check list, add after the
`id` format bullet (`- \`id\` follows \`androdr-NNN\` pattern`):

```markdown
- `id` is NOT listed in `{sigma_repo_path}/validation/retired-rule-ids.txt` (retired IDs are never reused — `validate-rule.py` also enforces this)
```

And at the end of the Gate 1 section (after the `Record:` line), add:

```markdown
Note: `validate-rule.py` also enforces the device-posture severity cap
(`device_posture` rules above `medium` fail) and rejects lone
actively-exploited-CVE posture rules (androdr-047 duplicates). Surface the
script's stderr verbatim — the Rule Author needs it for repair.
```

- [ ] **Step 3: Commit**

```bash
git add .claude/commands/update-rules-author.md .claude/commands/update-rules-validate.md
git commit -m "feat(skills): lessons input for author; registry + new-lint notes for validator"
```

### Task 12: Verify, review, PR

- [ ] **Step 1: Full local verification**

```bash
cd /home/yasir/AndroDR
# workflow syntax (harness wrapper)
python3 - <<'EOF'
src = open('.claude/workflows/update-rules-e2e.workflow.js').read()
idx = src.index('\n}\n', src.index('export const meta'))
open('/tmp/wf-body.mjs','w').write('async function main(args, agent, parallel, pipeline, phase, log, budget, workflow) {\n' + src[idx+3:] + '\n}\n')
EOF
node --check /tmp/wf-body.mjs && echo "BODY SYNTAX OK"
# discover helper suite (unchanged, but cheap insurance)
python3 -m pytest .claude/commands/scripts/ -q
# submodule suite (new lints)
cd third-party/android-sigma-rules && python3 -m pytest validation/ -q && cd ../..
```
Expected: `BODY SYNTAX OK`, both pytest runs fully green.

- [ ] **Step 2: Two-reviewer cycle (project policy — mandatory)**

Dispatch two parallel review subagents with different personalities against
`git diff main...HEAD`:
1. *Spec-compliance checker*: verify every spec section (Phase 1: 1a–1e,
   Phase 2: 2a–2c) maps to a commit in this branch + the sigma-repo PR;
   flag gaps and regressions.
2. *Adversarial fact-checker*: verify the workflow JS logic end-to-end
   (slot indexing `2i`/`2i+1` in both rounds, repair/skip routing, no stale
   references), and every factual claim in the skill edits against the
   submodule files.

Fix everything they find; re-run Step 1 after fixes.

- [ ] **Step 3: PR + merge**

```bash
git push -u origin feat/pipeline-candidate-accuracy
gh pr create --base main --title "feat(pipeline): candidate-accuracy gates wiring + feedback loop (skills/workflow)" --body "AndroDR half of the candidate-accuracy spec (docs/superpowers/specs/2026-06-10-pipeline-candidate-accuracy-design.md): submodule bump for the new validate-rule.py lints; e2e workflow gains an INDEPENDENT Gate-5 reviewer per candidate and a one-round author repair loop; dispatcher gains the pipeline-runs ledger, approval-rate trend, and lessons curation; author/validator skills updated accordingly.

🤖 Generated with [Claude Code](https://claude.com/claude-code)"
gh run list --branch feat/pipeline-candidate-accuracy --json databaseId,status -q '.[] | select(.status != "completed") | .databaseId' | xargs -r -n1 gh run cancel
gh pr merge --admin --squash --delete-branch
git checkout main && git pull --ff-only
```

---

## Self-review notes (plan author)

- **Spec coverage:** 1a→Task 2, 1b→Task 3, 1c→Task 1, 1d→Task 9 (repair
  round), 1e→Tasks 8+9 (reviewPrompt + merge), tests→Tasks 1–4,
  2a→Task 10 (8.3), 2b→Tasks 5+8+10 (file, injection, curation),
  2c→Task 10 (8.4), delivery order→Task 6 before Task 7. No gaps.
- **Known sequencing constraint:** Task 6 (sigma PR merge) MUST complete
  before Task 7 (submodule bump), or the bump won't contain the lints.
- **Skill-reload caveat:** the skill/workflow edits in Part B are not
  hot-reloaded; dogfooding the updated pipeline requires a fresh session
  after merge.
