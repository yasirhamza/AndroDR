# AI Rule Framework Bundle 3 — Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Unify feed cursor schema (F4) and formalize decision manifest structure (F6). F5 (scheduled automation) deferred; F8 (correlation integration tests) already satisfied by existing `AllCorrelationRulesFireTest` and `CorrelationMigrationFixturesTest`.

**Architecture:** Mechanical refactor + schema authoring. Touch `feed-state.json` and each ingester skill for F4; add `decisions-schema.json` and wire Gate 1 validation for F6. All work lives in the `android-sigma-rules` submodule except the skill prompt edits which live in `.claude/commands/`.

**Tech Stack:** JSON Schema Draft 2020-12, Python (validator scripts), Markdown (skill prompts)

**Issue:** #109 | **Epic:** #104 | **Depends on:** #108 (sub-plan 2 — PR #114, for the `ioc_confidence` / `telemetry_gap` decision types that #109 formalizes)

---

## Scope Decisions (carried from meta-plan + this session's brainstorm)

| Finding | Status | Rationale |
|---|---|---|
| F4 (cursor schema) | **In scope** | Each feed uses a different cursor shape; NVD cursor is `null` (never initialized) |
| F5 (scheduled automation) | **Deferred** | Pipeline still WIP; automating it before a production track record just automates instability. Revisit in a later sprint. |
| F6 (decisions schema) | **In scope** | #108 extended the decision manifest with `type: ioc_confidence \| telemetry_gap`. Formalize before this becomes de-facto stable. |
| F8 (correlation tests) | **Already satisfied** | `AllCorrelationRulesFireTest.kt` (end-to-end, 4 rules on 1 timeline) + `CorrelationMigrationFixturesTest.kt` (6 per-rule tests including 2 negative) cover the meta-plan's stated requirement. |

Also: update the meta-plan document to record these scope changes so future sessions don't re-plan F5/F8.

---

## File Structure

| File | Purpose |
|---|---|
| `third-party/android-sigma-rules/feed-state.json` | Migrated to unified cursor schema; NVD cursor initialized |
| `third-party/android-sigma-rules/validation/feed-state-schema.json` | **New** — JSON Schema for feed-state.json |
| `third-party/android-sigma-rules/validation/validate-feed-state.py` | **New** — validator script, exits non-zero on schema violations |
| `third-party/android-sigma-rules/validation/decisions-schema.json` | **New** — JSON Schema for Rule Author decision manifest |
| `third-party/android-sigma-rules/validation/validate-decisions.py` | **New** — validator script for decision manifests |
| `.claude/commands/update-rules-ingest-*.md` (7 files) | Skill prompts read/write the unified cursor fields; NVD reads/writes `last_seen_timestamp` + `last_modified` |
| `.claude/commands/update-rules-author.md` | Point to `decisions-schema.json` as the authoritative format |
| `.claude/commands/update-rules-validate.md` | Gate 1 calls `validate-decisions.py` on the Rule Author's decision manifest |
| `docs/superpowers/plans/2026-04-11-ai-rule-framework-audit-meta-plan.md` | Note F5 deferred, F8 already satisfied |

---

### Task 1: Define the unified cursor schema

**Files:**
- Create: `third-party/android-sigma-rules/validation/feed-state-schema.json`

This task just defines the schema. Migration of the existing `feed-state.json`
happens in Task 2 so any schema mistakes can be caught before touching real cursor data.

Unified model: every feed has `last_seen_timestamp` as the primary cursor (ISO 8601
UTC) plus optional feed-specific secondary keys. The secondary keys are kept because
they remain useful for feed-specific APIs (e.g., ThreatFox's `query_time` parameter,
MalwareBazaar's `query_time`, stalkerware-indicators' commit SHA for diffing).

- [ ] **Step 1: Write the schema**

Create `third-party/android-sigma-rules/validation/feed-state-schema.json`:

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "AndroDR Feed State",
  "description": "Cursor state for all AI rule pipeline feed ingesters.",
  "type": "object",
  "required": ["version", "last_full_sweep", "feeds"],
  "additionalProperties": false,
  "properties": {
    "version": {
      "type": "integer",
      "const": 2,
      "description": "Schema version. Bumped from 1 to 2 in sub-plan 3."
    },
    "last_full_sweep": {
      "type": "string",
      "format": "date",
      "description": "YYYY-MM-DD of the last /update-rules full invocation."
    },
    "feeds": {
      "type": "object",
      "additionalProperties": false,
      "required": [
        "threatfox",
        "malwarebazaar",
        "asb",
        "nvd",
        "stalkerware_indicators",
        "attack_mobile",
        "amnesty"
      ],
      "properties": {
        "threatfox":              { "$ref": "#/$defs/FeedCursor" },
        "malwarebazaar":          { "$ref": "#/$defs/FeedCursor" },
        "asb":                    { "$ref": "#/$defs/FeedCursorWithBulletin" },
        "nvd":                    { "$ref": "#/$defs/FeedCursorWithModified" },
        "stalkerware_indicators": { "$ref": "#/$defs/FeedCursorWithCommit" },
        "attack_mobile":          { "$ref": "#/$defs/FeedCursorWithVersion" },
        "amnesty":                { "$ref": "#/$defs/FeedCursor" }
      }
    }
  },
  "$defs": {
    "FeedCursor": {
      "type": "object",
      "required": ["last_seen_timestamp"],
      "additionalProperties": false,
      "properties": {
        "last_seen_timestamp": {
          "type": "string",
          "format": "date-time",
          "description": "ISO 8601 UTC timestamp of the most recent successful ingest."
        }
      }
    },
    "FeedCursorWithBulletin": {
      "type": "object",
      "required": ["last_seen_timestamp", "last_bulletin"],
      "additionalProperties": false,
      "properties": {
        "last_seen_timestamp": { "type": "string", "format": "date-time" },
        "last_bulletin": {
          "type": "string",
          "pattern": "^\\d{4}-\\d{2}-\\d{2}$",
          "description": "YYYY-MM-DD of the most recent Android Security Bulletin ingested."
        }
      }
    },
    "FeedCursorWithModified": {
      "type": "object",
      "required": ["last_seen_timestamp", "last_modified"],
      "additionalProperties": false,
      "properties": {
        "last_seen_timestamp": { "type": "string", "format": "date-time" },
        "last_modified": {
          "type": "string",
          "format": "date-time",
          "description": "NVD API lastModStartDate cursor (ISO 8601)."
        }
      }
    },
    "FeedCursorWithCommit": {
      "type": "object",
      "required": ["last_seen_timestamp", "last_commit_sha"],
      "additionalProperties": false,
      "properties": {
        "last_seen_timestamp": { "type": "string", "format": "date-time" },
        "last_commit_sha": {
          "type": "string",
          "pattern": "^[0-9a-f]{7,40}$",
          "description": "GitHub commit SHA (short or full) from the last successful ingest."
        }
      }
    },
    "FeedCursorWithVersion": {
      "type": "object",
      "required": ["last_seen_timestamp", "last_version"],
      "additionalProperties": false,
      "properties": {
        "last_seen_timestamp": { "type": "string", "format": "date-time" },
        "last_version": {
          "type": "string",
          "pattern": "^\\d+\\.\\d+$",
          "description": "MITRE ATT&CK Mobile version string (e.g. '15.1')."
        }
      }
    }
  }
}
```

- [ ] **Step 2: Verify the schema is valid JSON Schema Draft 2020-12**

```bash
cd third-party/android-sigma-rules
python3 -c "import json; json.load(open('validation/feed-state-schema.json'))"
```

Expected: no output (valid JSON).

- [ ] **Step 3: Commit in submodule**

```bash
cd third-party/android-sigma-rules
git add validation/feed-state-schema.json
git commit -m "feat: add feed-state JSON schema (#109 F4)

Unifies cursor shape across all 7 ingesters: every feed has
last_seen_timestamp plus feed-specific secondary keys preserved
for API-specific needs (bulletin date, NVD lastModified, commit
SHA, ATT&CK version)."
```

---

### Task 2: Migrate `feed-state.json` to v2 schema

**Files:**
- Modify: `third-party/android-sigma-rules/feed-state.json`

The existing `feed-state.json` has inconsistent cursor shapes. Rewrite it using
the schema from Task 1. All feeds gain `last_seen_timestamp`. NVD, previously
`null`, is initialized to the same timestamp as `last_full_sweep`.

- [ ] **Step 1: Rewrite feed-state.json**

Replace the contents of `third-party/android-sigma-rules/feed-state.json` with:

```json
{
  "version": 2,
  "last_full_sweep": "2026-04-02",
  "feeds": {
    "threatfox": {
      "last_seen_timestamp": "2026-04-01T18:36:30Z"
    },
    "malwarebazaar": {
      "last_seen_timestamp": "2026-04-01T16:43:59Z"
    },
    "asb": {
      "last_seen_timestamp": "2025-05-01T00:00:00Z",
      "last_bulletin": "2025-05-01"
    },
    "nvd": {
      "last_seen_timestamp": "2026-04-02T00:00:00Z",
      "last_modified": "2026-04-02T00:00:00Z"
    },
    "stalkerware_indicators": {
      "last_seen_timestamp": "2026-04-10T00:00:00Z",
      "last_commit_sha": "b8635c5"
    },
    "attack_mobile": {
      "last_seen_timestamp": "2026-04-02T00:00:00Z",
      "last_version": "15.1"
    },
    "amnesty": {
      "last_seen_timestamp": "2026-04-01T00:00:00Z"
    }
  }
}
```

Cursor values were derived as follows:
- threatfox, malwarebazaar: copy from the old `last_query_time` (already ISO 8601)
- asb: promote `last_bulletin` to a full timestamp (midnight UTC of that date) and keep the bulletin date as a secondary key
- nvd: initialize to `last_full_sweep` date (`2026-04-02`) with `last_modified` equal, per the meta-plan's "NVD cursor initialized" requirement
- stalkerware_indicators: use 2026-04-10 (when commit `b8635c5` was ingested per #108's re-run A output) and preserve the commit SHA
- attack_mobile: initialize to `last_full_sweep`, preserve version
- amnesty: promote the old `last_checked` date to midnight UTC timestamp

- [ ] **Step 2: Validate the new file against the schema**

```bash
cd third-party/android-sigma-rules
python3 -c "
import json
import jsonschema
schema = json.load(open('validation/feed-state-schema.json'))
data = json.load(open('feed-state.json'))
jsonschema.validate(data, schema)
print('VALID')
"
```

Expected: `VALID`

If `jsonschema` isn't installed: `pip install jsonschema` (or use Task 3's validator script).

- [ ] **Step 3: Commit in submodule**

```bash
git add feed-state.json
git commit -m "feat: migrate feed-state.json to unified v2 schema (#109 F4)

- Every feed now has last_seen_timestamp as primary cursor
- NVD cursor initialized (was null)
- Feed-specific secondary keys preserved (bulletin, commit SHA, etc.)
- Validated against feed-state-schema.json"
```

---

### Task 3: Write `validate-feed-state.py` validator

**Files:**
- Create: `third-party/android-sigma-rules/validation/validate-feed-state.py`

Mirrors the pattern of `validate-rule.py` and `validate-ioc-data.py` so CI and
the pipeline skills can run schema checks without depending on a pip-installed
`jsonschema` package (we use a small in-repo validator like the existing scripts).

- [ ] **Step 1: Write the validator**

Create `third-party/android-sigma-rules/validation/validate-feed-state.py`:

```python
#!/usr/bin/env python3
"""Validate feed-state.json against feed-state-schema.json.

Usage: python validate-feed-state.py [path/to/feed-state.json]
       Defaults to ../feed-state.json (repo root).

Exit codes:
  0 = valid
  1 = validation errors (printed to stderr)
  2 = file not found / parse error
"""

import json
import re
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).parent
DEFAULT_STATE_PATH = SCRIPT_DIR.parent / "feed-state.json"
SCHEMA_PATH = SCRIPT_DIR / "feed-state-schema.json"

ISO_TS_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$")
ISO_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
SHA_RE = re.compile(r"^[0-9a-f]{7,40}$")
VERSION_RE = re.compile(r"^\d+\.\d+$")


def _check_iso_timestamp(value, path, errors):
    if not isinstance(value, str) or not ISO_TS_RE.match(value):
        errors.append(f"{path}: expected ISO 8601 UTC timestamp, got {value!r}")


def _check_iso_date(value, path, errors):
    if not isinstance(value, str) or not ISO_DATE_RE.match(value):
        errors.append(f"{path}: expected YYYY-MM-DD, got {value!r}")


def _check_feed_cursor(cursor, feed_name, required_extra, extra_check, errors):
    """extra_check is a list of (key, validator_fn) pairs for feed-specific keys."""
    if not isinstance(cursor, dict):
        errors.append(f"feeds.{feed_name}: expected object, got {type(cursor).__name__}")
        return
    allowed = {"last_seen_timestamp"} | set(required_extra)
    if "last_seen_timestamp" not in cursor:
        errors.append(f"feeds.{feed_name}: missing last_seen_timestamp")
    else:
        _check_iso_timestamp(cursor["last_seen_timestamp"], f"feeds.{feed_name}.last_seen_timestamp", errors)
    for extra in required_extra:
        if extra not in cursor:
            errors.append(f"feeds.{feed_name}: missing {extra}")
    for key, check_fn in extra_check:
        if key in cursor:
            check_fn(cursor[key], f"feeds.{feed_name}.{key}", errors)
    for key in cursor:
        if key not in allowed:
            errors.append(f"feeds.{feed_name}: unexpected key {key!r}")


FEED_SPEC = {
    "threatfox":              ([], []),
    "malwarebazaar":          ([], []),
    "asb":                    (["last_bulletin"], [("last_bulletin", _check_iso_date)]),
    "nvd":                    (["last_modified"], [("last_modified", _check_iso_timestamp)]),
    "stalkerware_indicators": (
        ["last_commit_sha"],
        [("last_commit_sha",
          lambda v, p, e: e.append(f"{p}: expected git SHA, got {v!r}") if not (isinstance(v, str) and SHA_RE.match(v)) else None)]
    ),
    "attack_mobile":          (
        ["last_version"],
        [("last_version",
          lambda v, p, e: e.append(f"{p}: expected N.N version, got {v!r}") if not (isinstance(v, str) and VERSION_RE.match(v)) else None)]
    ),
    "amnesty":                ([], []),
}


def validate(state: dict) -> list[str]:
    errors: list[str] = []
    if state.get("version") != 2:
        errors.append(f"version must be 2 (got {state.get('version')!r}); run migration")
    if "last_full_sweep" not in state:
        errors.append("missing last_full_sweep")
    else:
        _check_iso_date(state["last_full_sweep"], "last_full_sweep", errors)

    feeds = state.get("feeds", {})
    if not isinstance(feeds, dict):
        errors.append("feeds: expected object")
        return errors

    for feed_name, (required_extra, extra_check) in FEED_SPEC.items():
        if feed_name not in feeds:
            errors.append(f"feeds.{feed_name}: missing")
            continue
        _check_feed_cursor(feeds[feed_name], feed_name, required_extra, extra_check, errors)

    for feed_name in feeds:
        if feed_name not in FEED_SPEC:
            errors.append(f"feeds.{feed_name}: unknown feed (allowed: {sorted(FEED_SPEC)})")

    return errors


def main():
    state_path = Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_STATE_PATH
    if not state_path.exists():
        print(f"File not found: {state_path}", file=sys.stderr)
        sys.exit(2)
    try:
        state = json.loads(state_path.read_text())
    except json.JSONDecodeError as e:
        print(f"JSON parse error: {e}", file=sys.stderr)
        sys.exit(2)

    errors = validate(state)
    if errors:
        print(f"FAIL: {state_path.name} — {len(errors)} error(s):", file=sys.stderr)
        for err in errors:
            print(f"  - {err}", file=sys.stderr)
        sys.exit(1)
    print(f"PASS: {state_path.name}")
    sys.exit(0)


if __name__ == "__main__":
    main()
```

- [ ] **Step 2: Run the validator against the migrated feed-state.json**

```bash
cd third-party/android-sigma-rules
python3 validation/validate-feed-state.py
```

Expected: `PASS: feed-state.json`

- [ ] **Step 3: Sanity-check it fails on bad input**

```bash
echo '{"version": 1}' > /tmp/bad-state.json
python3 validation/validate-feed-state.py /tmp/bad-state.json
rm /tmp/bad-state.json
```

Expected exit code 1 with errors:
```
FAIL: bad-state.json — N error(s):
  - version must be 2 (got 1); run migration
  - missing last_full_sweep
  - feeds.threatfox: missing
  ...
```

- [ ] **Step 4: Commit in submodule**

```bash
git add validation/validate-feed-state.py
chmod +x validation/validate-feed-state.py
git commit -m "feat: add validate-feed-state.py (#109 F4)

Validates feed-state.json against feed-state-schema.json without
requiring pip-installed jsonschema. Mirrors validate-rule.py and
validate-ioc-data.py patterns."
```

---

### Task 4: Update ingester skills to read/write the unified cursor fields

**Files:**
- Modify: `.claude/commands/update-rules-ingest-abusech.md`
- Modify: `.claude/commands/update-rules-ingest-asb.md`
- Modify: `.claude/commands/update-rules-ingest-nvd.md`
- Modify: `.claude/commands/update-rules-ingest-stalkerware.md`
- Modify: `.claude/commands/update-rules-ingest-attack.md`
- Modify: `.claude/commands/update-rules-ingest-amnesty.md`
- Modify: `.claude/commands/update-rules-ingest-citizenlab.md`

Each skill reads a cursor from `feed-state.json` at start and returns an updated cursor
at end. The new schema adds `last_seen_timestamp` to every cursor object. Skills must
read and write this field; they must continue to read and write their feed-specific
secondary key where one exists.

- [ ] **Step 1: Update abusech ingester**

In `.claude/commands/update-rules-ingest-abusech.md`, find the "Input" / "Cursor" section
(whatever it's called) that describes the cursor shape. Update every reference to match:

- Threatfox cursor is now: `{ "last_seen_timestamp": "<ISO-8601-UTC>" }`
- Malwarebazaar cursor is now: `{ "last_seen_timestamp": "<ISO-8601-UTC>" }`

Where the skill previously read `last_query_time`, read `last_seen_timestamp`.
Where the skill previously wrote `last_query_time`, write `last_seen_timestamp`.

The ingester should also set `last_seen_timestamp` to the current ingest time
(ISO 8601 UTC) on a successful ingest.

- [ ] **Step 2: Update asb ingester**

ASB cursor is now: `{ "last_seen_timestamp": "<ISO-8601-UTC>", "last_bulletin": "YYYY-MM-DD" }`.
`last_bulletin` keeps its existing semantics (the most recent bulletin slug). On
every successful ingest, update both `last_seen_timestamp` (to now) and `last_bulletin`
(to the newest bulletin processed).

- [ ] **Step 3: Update nvd ingester**

NVD cursor is now: `{ "last_seen_timestamp": "<ISO-8601-UTC>", "last_modified": "<ISO-8601-UTC>" }`.
`last_modified` is passed to NVD's API as `lastModStartDate`. `last_seen_timestamp`
records when the ingester ran. On success, set `last_modified` to the `lastModEndDate`
returned from NVD and `last_seen_timestamp` to now.

If the skill currently treats a `null` cursor as a special-case "initial fetch" path,
remove that branch — the cursor is now always initialized (Task 2 seeded it to
`2026-04-02T00:00:00Z`).

- [ ] **Step 4: Update stalkerware ingester**

Stalkerware cursor is now:
`{ "last_seen_timestamp": "<ISO-8601-UTC>", "last_commit_sha": "<7-40 hex>" }`.
Read/write both fields.

- [ ] **Step 5: Update attack ingester**

Attack cursor is now:
`{ "last_seen_timestamp": "<ISO-8601-UTC>", "last_version": "<N.N>" }`.
Read/write both fields.

- [ ] **Step 6: Update amnesty ingester**

Amnesty cursor is now: `{ "last_seen_timestamp": "<ISO-8601-UTC>" }`.
Drop `last_checked` — it is replaced by `last_seen_timestamp`.

- [ ] **Step 7: Update citizenlab ingester (if it has a cursor)**

Citizen Lab ingester currently receives `existing_rule_index` rather than a
cursor. If it has no cursor state in `feed-state.json`, no changes needed.
Verify by reading the skill file; if no cursor is referenced, skip this step.

- [ ] **Step 8: Commit skill edits**

```bash
git add .claude/commands/update-rules-ingest-*.md
git commit -m "feat(skills): migrate ingesters to unified cursor schema (#109 F4)

All 7 ingesters now read/write last_seen_timestamp as the primary
cursor. Feed-specific secondary keys retained where they serve an
API purpose (NVD lastModified, ASB bulletin, stalkerware commit SHA,
ATT&CK version)."
```

---

### Task 5: Bump submodule pointer in parent repo

**Files:**
- Modify: `third-party/android-sigma-rules` (submodule pointer)

- [ ] **Step 1: Commit submodule pointer bump**

```bash
cd /home/yasir/AndroDR
git add third-party/android-sigma-rules
git commit -m "build: bump android-sigma-rules submodule (#109 F4 cursor schema)"
```

- [ ] **Step 2: Run unit tests to confirm nothing regressed**

```bash
export JAVA_HOME=/home/yasir/Applications/android-studio/jbr
export PATH=$JAVA_HOME/bin:$PATH
./gradlew testDebugUnitTest
```

Expected: BUILD SUCCESSFUL.

---

### Task 6: Define `decisions-schema.json`

**Files:**
- Create: `third-party/android-sigma-rules/validation/decisions-schema.json`

This formalizes the decision manifest structure the Rule Author produces. The
schema must cover the format introduced in #108 (`type: ioc_confidence` and
`type: telemetry_gap`) while remaining backwards-compatible with untyped entries
used by existing ambiguity flags.

- [ ] **Step 1: Write the schema**

Create `third-party/android-sigma-rules/validation/decisions-schema.json`:

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "AndroDR Rule Author Decision Manifest",
  "description": "Schema for the 'decisions' array returned by update-rules-author.",
  "type": "object",
  "required": ["decisions"],
  "additionalProperties": false,
  "properties": {
    "decisions": {
      "type": "array",
      "items": { "$ref": "#/$defs/Decision" }
    }
  },
  "$defs": {
    "Decision": {
      "type": "object",
      "required": ["field", "chosen", "alternative", "reasoning"],
      "additionalProperties": false,
      "properties": {
        "rule_id": {
          "type": ["string", "null"],
          "pattern": "^androdr-(NNN|\\d{3}|corr-\\d{3}|atom-[a-z0-9-]+)$",
          "description": "Rule ID the decision applies to, or null for pre-creation decisions (skip, telemetry_gap)."
        },
        "field": {
          "type": "string",
          "description": "Field name the decision applies to, 'rule_creation' for meta-decisions, or 'ioc_data' for IOC-level decisions."
        },
        "type": {
          "type": "string",
          "enum": ["ioc_confidence", "telemetry_gap"],
          "description": "Decision type. Omitted for generic ambiguity flags (severity, IOC breadth, behavioral borderline)."
        },
        "chosen": {
          "type": "string",
          "description": "The choice the Rule Author made."
        },
        "alternative": {
          "type": "string",
          "description": "The alternative that was rejected."
        },
        "reasoning": {
          "type": "string",
          "description": "Why the chosen option was picked over the alternative."
        },
        "missing_field": {
          "type": "string",
          "description": "Only present for type=telemetry_gap. The taxonomy field that would have been needed."
        },
        "suggested_service": {
          "type": "string",
          "description": "Only present for type=telemetry_gap. The logsource service the missing field should belong to."
        }
      },
      "allOf": [
        {
          "if":   { "properties": { "type": { "const": "telemetry_gap" } }, "required": ["type"] },
          "then": { "required": ["missing_field", "suggested_service"] }
        },
        {
          "if":   { "not": { "properties": { "type": { "const": "telemetry_gap" } }, "required": ["type"] } },
          "then": {
            "properties": {
              "missing_field":     { "not": {} },
              "suggested_service": { "not": {} }
            }
          }
        }
      ]
    }
  }
}
```

The conditional rules enforce:
- `type: telemetry_gap` requires `missing_field` + `suggested_service`
- Other decision entries must NOT include `missing_field` or `suggested_service`

- [ ] **Step 2: Verify valid JSON**

```bash
cd third-party/android-sigma-rules
python3 -c "import json; json.load(open('validation/decisions-schema.json'))"
```

Expected: no output.

- [ ] **Step 3: Commit in submodule**

```bash
git add validation/decisions-schema.json
git commit -m "feat: add decisions-schema.json (#109 F6)

Formalizes the decision manifest format extended in #108:
- ioc_confidence: Rule Author's verdict on requires_verification SIRs
- telemetry_gap: missing_field + suggested_service recorded when
  the Rule Author declines to write a rule because the taxonomy
  lacks a needed field or the service is unwired
- Existing untyped decisions (severity ambiguity, IOC breadth)
  continue to validate"
```

---

### Task 7: Write `validate-decisions.py` validator

**Files:**
- Create: `third-party/android-sigma-rules/validation/validate-decisions.py`

- [ ] **Step 1: Write the validator**

Create `third-party/android-sigma-rules/validation/validate-decisions.py`:

```python
#!/usr/bin/env python3
"""Validate a Rule Author decision manifest against decisions-schema.json.

Usage: python validate-decisions.py <path/to/decisions.json-or-.yml>

Exit codes:
  0 = valid
  1 = validation errors (printed to stderr)
  2 = file not found / parse error
"""

import json
import re
import sys
from pathlib import Path

try:
    import yaml
except ImportError:
    yaml = None

ALLOWED_TYPES = {"ioc_confidence", "telemetry_gap"}
RULE_ID_RE = re.compile(r"^androdr-(NNN|\d{3}|corr-\d{3}|atom-[a-z0-9-]+)$")
GAP_ONLY_KEYS = {"missing_field", "suggested_service"}
REQUIRED_KEYS = {"field", "chosen", "alternative", "reasoning"}
OPTIONAL_KEYS = {"rule_id", "type"} | GAP_ONLY_KEYS
ALLOWED_KEYS = REQUIRED_KEYS | OPTIONAL_KEYS


def validate_decision(decision: dict, index: int) -> list[str]:
    errors: list[str] = []
    if not isinstance(decision, dict):
        return [f"decisions[{index}]: not an object"]

    for key in REQUIRED_KEYS:
        if key not in decision:
            errors.append(f"decisions[{index}]: missing required field {key!r}")

    for key in decision:
        if key not in ALLOWED_KEYS:
            errors.append(f"decisions[{index}]: unexpected key {key!r}")

    rule_id = decision.get("rule_id")
    if rule_id is not None and (not isinstance(rule_id, str) or not RULE_ID_RE.match(rule_id)):
        errors.append(f"decisions[{index}].rule_id: must match androdr-NNN or null, got {rule_id!r}")

    dtype = decision.get("type")
    if dtype is not None and dtype not in ALLOWED_TYPES:
        errors.append(f"decisions[{index}].type: must be one of {sorted(ALLOWED_TYPES)}, got {dtype!r}")

    is_gap = dtype == "telemetry_gap"
    for key in GAP_ONLY_KEYS:
        present = key in decision
        if is_gap and not present:
            errors.append(f"decisions[{index}]: telemetry_gap requires {key!r}")
        if not is_gap and present:
            errors.append(f"decisions[{index}]: {key!r} is only valid when type=telemetry_gap")

    return errors


def validate(manifest: dict) -> list[str]:
    if not isinstance(manifest, dict):
        return ["manifest: top-level must be an object"]
    if "decisions" not in manifest:
        return ["manifest: missing 'decisions' array"]
    decisions = manifest["decisions"]
    if not isinstance(decisions, list):
        return ["manifest.decisions: expected array"]

    errors: list[str] = []
    for i, d in enumerate(decisions):
        errors.extend(validate_decision(d, i))
    return errors


def load(path: Path) -> dict:
    text = path.read_text()
    if path.suffix in {".yml", ".yaml"}:
        if yaml is None:
            sys.exit("pyyaml required to validate YAML manifests: pip install pyyaml")
        return yaml.safe_load(text)
    return json.loads(text)


def main():
    if len(sys.argv) < 2:
        print("Usage: python validate-decisions.py <manifest.json|.yml>", file=sys.stderr)
        sys.exit(2)

    path = Path(sys.argv[1])
    if not path.exists():
        print(f"File not found: {path}", file=sys.stderr)
        sys.exit(2)

    try:
        manifest = load(path)
    except (json.JSONDecodeError, Exception) as e:
        print(f"Parse error: {e}", file=sys.stderr)
        sys.exit(2)

    errors = validate(manifest)
    if errors:
        print(f"FAIL: {path.name} — {len(errors)} error(s):", file=sys.stderr)
        for err in errors:
            print(f"  - {err}", file=sys.stderr)
        sys.exit(1)
    print(f"PASS: {path.name}")
    sys.exit(0)


if __name__ == "__main__":
    main()
```

- [ ] **Step 2: Sanity-check with a valid fixture**

```bash
cd third-party/android-sigma-rules
cat > /tmp/good-decisions.yml <<'EOF'
decisions:
  - rule_id: "androdr-099"
    field: "level"
    chosen: "high"
    alternative: "medium"
    reasoning: "Active exploitation reports justify high severity."
  - rule_id: null
    field: "rule_creation"
    type: "telemetry_gap"
    chosen: "skip"
    alternative: "create rule using field 'battery_drain_rate'"
    reasoning: "SIR requires telemetry not in taxonomy"
    missing_field: "battery_drain_rate"
    suggested_service: "app_scanner"
  - rule_id: null
    field: "ioc_data"
    type: "ioc_confidence"
    chosen: "skip"
    alternative: "include domain from single blog post"
    reasoning: "Only one unstructured source"
EOF
python3 validation/validate-decisions.py /tmp/good-decisions.yml
rm /tmp/good-decisions.yml
```

Expected: `PASS: good-decisions.yml`

- [ ] **Step 3: Sanity-check with an invalid fixture**

```bash
cat > /tmp/bad-decisions.yml <<'EOF'
decisions:
  - rule_id: "not-a-real-id"
    field: "level"
    chosen: "high"
    alternative: "medium"
    reasoning: "..."
  - rule_id: null
    field: "rule_creation"
    type: "telemetry_gap"
    chosen: "skip"
    alternative: "..."
    reasoning: "..."
  - rule_id: null
    field: "level"
    chosen: "medium"
    alternative: "high"
    reasoning: "..."
    missing_field: "oops"
EOF
python3 validation/validate-decisions.py /tmp/bad-decisions.yml
rm /tmp/bad-decisions.yml
```

Expected exit code 1 with errors:
- `decisions[0].rule_id: must match androdr-NNN or null, got 'not-a-real-id'`
- `decisions[1]: telemetry_gap requires 'missing_field'`
- `decisions[1]: telemetry_gap requires 'suggested_service'`
- `decisions[2]: 'missing_field' is only valid when type=telemetry_gap`

- [ ] **Step 4: Commit in submodule**

```bash
git add validation/validate-decisions.py
chmod +x validation/validate-decisions.py
git commit -m "feat: add validate-decisions.py (#109 F6)

Standalone validator for Rule Author decision manifests. Accepts
YAML or JSON. Used by update-rules-validate (Gate 1) and available
for ad-hoc checks."
```

---

### Task 8: Wire `validate-decisions.py` into Gate 1

**Files:**
- Modify: `.claude/commands/update-rules-validate.md`

Gate 1 is the static-structure gate. Today it describes rule-level checks (schema,
required fields). It gains one more check: if the Rule Author returns a non-empty
`decisions` array with the candidate, validate it against `decisions-schema.json`
via `validate-decisions.py`.

- [ ] **Step 1: Edit the Validator skill to add Gate 1 decision validation**

In `.claude/commands/update-rules-validate.md`, find the "Gate 1" section (which
covers static structural checks). Add a subsection right after the rule YAML
structural check:

```markdown
### Gate 1.2: Decision Manifest Structure

If the candidate includes a non-empty `decisions` array, validate its structure
by invoking `validate-decisions.py`:

1. Write the decisions array (plus `decisions:` wrapper) to a temporary YAML file.
2. Run: `python3 third-party/android-sigma-rules/validation/validate-decisions.py <tmp>`
3. If exit code is non-zero, the candidate FAILS Gate 1.
4. Failure message MUST include the stderr output so the Rule Author can fix it on retry.

Empty decision arrays are valid (not every rule has ambiguities).
```

- [ ] **Step 2: Commit**

```bash
git add .claude/commands/update-rules-validate.md
git commit -m "feat(skills): Gate 1 validates decision manifest structure (#109 F6)

When the Rule Author returns a non-empty decisions array, the
validator runs validate-decisions.py against it. Structural errors
(missing fields, malformed telemetry_gap, unknown type) fail Gate 1
and feed back to the Rule Author for retry."
```

---

### Task 9: Point Rule Author skill at the formal schema

**Files:**
- Modify: `.claude/commands/update-rules-author.md`

The Rule Author's "Decision Flagging" section describes the decision format in
English. Add a pointer to `decisions-schema.json` as the authoritative format so
future edits to either stay in sync.

- [ ] **Step 1: Edit the Rule Author skill**

In `.claude/commands/update-rules-author.md`, find the "Decision Flagging" section
header. Immediately under the heading, before the "Format:" subsection, add:

```markdown
> **Authoritative format:** `third-party/android-sigma-rules/validation/decisions-schema.json`.
> The validator (Gate 1) rejects candidates whose decision manifest violates this schema.
> The examples below must match the schema.
```

- [ ] **Step 2: Commit**

```bash
git add .claude/commands/update-rules-author.md
git commit -m "feat(skills): point Rule Author at decisions-schema.json (#109 F6)

Makes the JSON schema the authoritative source for the decision
manifest format. Skill examples remain for readability but defer
to the schema on conflicts."
```

---

### Task 10: Bump submodule pointer for F6 commits

**Files:**
- Modify: `third-party/android-sigma-rules` (submodule pointer)

- [ ] **Step 1: Commit submodule bump**

```bash
cd /home/yasir/AndroDR
git add third-party/android-sigma-rules
git commit -m "build: bump android-sigma-rules submodule (#109 F6 decisions schema)"
```

- [ ] **Step 2: Push the submodule to its remote first**

```bash
git -C third-party/android-sigma-rules push origin HEAD:main
```

Expected output includes the new SHA on the remote main branch.

---

### Task 11: Update meta-plan with scope changes

**Files:**
- Modify: `docs/superpowers/plans/2026-04-11-ai-rule-framework-audit-meta-plan.md`

The meta-plan currently lists F5 and F8 as Bundle 3 work. Record that F5 is
deferred and F8 was already satisfied so future sessions don't re-plan them.

- [ ] **Step 1: Edit the meta-plan's Sub-plan 3 section**

In `docs/superpowers/plans/2026-04-11-ai-rule-framework-audit-meta-plan.md`, find the
"Sub-plan 3 — Framework Hardening" section. After the existing **Exit state** bullets,
add a **Scope changes during execution** block:

```markdown
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
```

- [ ] **Step 2: Commit**

```bash
git add docs/superpowers/plans/2026-04-11-ai-rule-framework-audit-meta-plan.md
git commit -m "docs: record Bundle 3 scope changes (F5 deferred, F8 satisfied)"
```

---

### Task 12: Final verification

**Files:** none (verification only)

- [ ] **Step 1: Full test suite**

```bash
export JAVA_HOME=/home/yasir/Applications/android-studio/jbr
export PATH=$JAVA_HOME/bin:$PATH
./gradlew testDebugUnitTest detekt lintDebug
```

Expected: BUILD SUCCESSFUL.

- [ ] **Step 2: Submodule validators**

```bash
cd third-party/android-sigma-rules
python3 validation/validate-feed-state.py
python3 -c "import json; json.load(open('validation/decisions-schema.json')); print('decisions-schema.json: valid JSON')"
```

Expected:
- `PASS: feed-state.json`
- `decisions-schema.json: valid JSON`

- [ ] **Step 3: No leftover references to the old cursor shape**

```bash
cd /home/yasir/AndroDR
grep -rn "last_query_time\|last_checked" .claude/commands/update-rules-ingest-*.md
```

Expected: no output. If any matches appear, the corresponding skill in Task 4
missed a reference.
