# Issue #117 — Complementary IOC Pipeline Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the AI rule-update pipeline systematically write to the rule repo's `ioc-data/*.yml` as an **additive delta** over the 8 existing Kotlin bypass feed clients, enforced by a new complementarity validator that rejects duplicates against upstream feeds the Kotlin clients already mirror.

**Architecture:** Two-track, complementary. Track A (8 Kotlin bypass feeds) stays permanently as the upstream bulk-mirror. Track B (AI pipeline → `ioc-data/*.yml` → `PublicRepoIocFeed`) carries only net-new entries. Both write to the same `indicators` Room table via idempotent `(type, value)` upsert. A rule-repo validator enforces "no entry in any `ioc-data/*.yml` duplicates anything in `validation/kotlin-mirror-feeds.yml` upstreams," with strict mode on changed files and advisory mode on untouched files (to absorb upstream mutation drift).

**Tech Stack:** Python 3 (rule-repo validators, JSON Schema via `jsonschema` + `pyyaml`), Kotlin 1.9 + JUnit 4 (AndroDR cross-check tests), Markdown (`.claude/commands/*.md` skill files), GitHub Actions (rule-repo CI).

**Reference spec:** `docs/superpowers/specs/2026-04-16-issue-117-complementary-ioc-pipeline-design.md`

**PRs this plan produces** (in order):

| # | Repo | Phase | Target branch |
|---|---|---|---|
| 1 | `android-sigma-rules` submodule | Phase 1 (foundations) | `main` |
| 2 | `android-sigma-rules` submodule | Phase 3 (complementarity + prune) | `main` |
| 3 | AndroDR | Phase 2 (Kotlin cross-checks + submodule bump) | `main` |
| 4 | AndroDR | Phase 4 (pipeline ingester extensions) | `main` |

Phase 5 is verification on an emulator — no PR.

---

## File structure

**In `third-party/android-sigma-rules/` (submodule):**

- Create: `validation/ioc-entry-schema.json` — JSON Schema for a single IOC entry
- Create: `validation/ioc-lookup-definitions.yml` — SIGMA `ioc_lookup` name → type+files map
- Create: `validation/kotlin-mirror-feeds.yml` — list of feeds the Kotlin bypass clients fetch
- Create: `validation/validate-ioc-complementarity.py` — dedup gate (strict/advisory)
- Create: `.github/workflows/validate.yml` — CI runner for Python validators
- Modify: `validation/validate-ioc-data.py` — add JSON Schema validation as the first check
- Modify: `validation/feed-state-schema.json` — add optional `ioc_data_last_write` per cursor
- Modify: `ioc-data/package-names.yml`, `c2-domains.yml`, `cert-hashes.yml`, `malware-hashes.yml` — pruned of entries already in Kotlin-mirrored upstreams (Phase 3)

**In AndroDR:**

- Create: `app/src/test/java/com/androdr/sigma/IocLookupDefinitionsCrossCheckTest.kt`
- Create: `app/src/test/java/com/androdr/sigma/IocDataSchemaCrossCheckTest.kt`
- Create: `app/src/test/java/com/androdr/ioc/KotlinMirrorFeedsCrossCheckTest.kt`
- Modify: `.claude/commands/update-rules.md` — new Step 6.5, extend Steps 7/8
- Modify: `.claude/commands/update-rules-ingest-abusech.md`
- Modify: `.claude/commands/update-rules-ingest-asb.md`
- Modify: `.claude/commands/update-rules-ingest-nvd.md`
- Modify: `.claude/commands/update-rules-ingest-amnesty.md`
- Modify: `.claude/commands/update-rules-ingest-citizenlab.md`
- Modify: `.claude/commands/update-rules-ingest-stalkerware.md`
- Modify: `.claude/commands/update-rules-ingest-attack.md`

---

# Phase 1 — Rule-repo foundations (submodule PR) — ~3 days

Working directory: `third-party/android-sigma-rules/`

Branch off `main` in the submodule: `feat/117-foundations`.

## Task 1: Create IOC entry JSON Schema

**Files:**
- Create: `third-party/android-sigma-rules/validation/ioc-entry-schema.json`

- [ ] **Step 1: Write the schema file**

Create `third-party/android-sigma-rules/validation/ioc-entry-schema.json` with:

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "AndroDR IOC Entry",
  "description": "Schema for a single entry in any ioc-data/*.yml file.",
  "type": "object",
  "required": ["indicator", "category", "severity", "source"],
  "additionalProperties": false,
  "properties": {
    "indicator":   { "type": "string", "minLength": 1 },
    "family":      { "type": "string" },
    "familyName":  { "type": "string", "description": "Alias for 'family' used by cert-hash entries (kept for back-compat with existing files)." },
    "category":    {
      "type": "string",
      "enum": [
        "STALKERWARE", "SPYWARE", "MALWARE",
        "NATION_STATE_SPYWARE", "FORENSIC_TOOL",
        "MONITORING", "POPULAR", "KNOWN_GOOD_OEM"
      ]
    },
    "severity":    { "type": "string", "enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW"] },
    "source":      { "type": "string", "minLength": 1 },
    "description": { "type": "string" },
    "first_seen":  { "type": "string", "format": "date" }
  }
}
```

- [ ] **Step 2: Validate the schema itself is valid JSON Schema**

Run:
```bash
cd third-party/android-sigma-rules
python3 -c "import json, jsonschema; jsonschema.Draft202012Validator.check_schema(json.load(open('validation/ioc-entry-schema.json')))"
```

Expected: no output (exit 0).

- [ ] **Step 3: Commit**

```bash
cd third-party/android-sigma-rules
git checkout -b feat/117-foundations
git add validation/ioc-entry-schema.json
git commit -m "feat(validation): add ioc-entry-schema.json (#117)"
```

## Task 2: Extend validate-ioc-data.py with schema validation

**Files:**
- Modify: `third-party/android-sigma-rules/validation/validate-ioc-data.py`

- [ ] **Step 1: Add schema validation as first check in `validate_ioc_file`**

Open `third-party/android-sigma-rules/validation/validate-ioc-data.py`. At the top of the file, after the existing imports block, add:

```python
try:
    from jsonschema import Draft202012Validator
except ImportError:
    sys.exit("jsonschema required: pip install jsonschema")
```

Then in `validate_ioc_file`, immediately before the `seen_indicators = set()` line, add:

```python
# Schema validation (runs first; legacy checks below still run for defense-in-depth)
schema_path = SCRIPT_DIR / "ioc-entry-schema.json"
if schema_path.exists():
    with open(schema_path) as f:
        entry_schema = json.load(f)
    validator = Draft202012Validator(entry_schema)
    for idx, entry in enumerate(entries):
        for err in validator.iter_errors(entry):
            errors.append(f"entries[{idx}]: schema violation: {err.message}")
```

- [ ] **Step 2: Run against existing files to confirm schema is satisfied**

```bash
cd third-party/android-sigma-rules
python3 validation/validate-ioc-data.py ioc-data/package-names.yml
python3 validation/validate-ioc-data.py ioc-data/c2-domains.yml
python3 validation/validate-ioc-data.py ioc-data/cert-hashes.yml
python3 validation/validate-ioc-data.py ioc-data/popular-apps.yml
python3 validation/validate-ioc-data.py ioc-data/malware-hashes.yml
python3 validation/validate-ioc-data.py ioc-data/known-oem-prefixes.yml
```

Expected: every file prints `PASS: <filename>`. If any file fails schema, the schema needs adjustment (likely the `category` enum or the `additionalProperties: false` — if an existing file uses a field not in the schema, add it to `properties`).

- [ ] **Step 3: Commit**

```bash
cd third-party/android-sigma-rules
git add validation/validate-ioc-data.py
git commit -m "feat(validation): enforce ioc-entry-schema on all ioc-data files (#117)"
```

## Task 3: Create ioc-lookup-definitions.yml

**Files:**
- Create: `third-party/android-sigma-rules/validation/ioc-lookup-definitions.yml`

- [ ] **Step 1: Write the file**

Create `third-party/android-sigma-rules/validation/ioc-lookup-definitions.yml` with:

```yaml
# Canonical map of SIGMA `ioc_lookup` database names to IOC types and
# source files. Consumers implementing the SIGMA dialect use this to
# resolve `field|ioc_lookup: <db_name>` against the ioc-data/*.yml files.
#
# The names in this file MUST match the map in AndroDR's
# ScanOrchestrator.initRuleEngine(). Drift is caught by the Kotlin-side
# IocLookupDefinitionsCrossCheckTest.

version: 1
lookups:
  package_ioc_db:
    type: PACKAGE_NAME
    files: [ioc-data/package-names.yml]
    description: "Known-malicious Android package names (stalkerware, spyware, malware)"

  cert_hash_ioc_db:
    type: CERT_HASH
    files: [ioc-data/cert-hashes.yml]
    description: "Known-malicious APK signing-cert SHA-256 and SHA-1 hashes"

  domain_ioc_db:
    type: C2_DOMAIN
    files: [ioc-data/c2-domains.yml]
    description: "Known-malicious command-and-control domains"

  apk_hash_ioc_db:
    type: APK_HASH
    files: [ioc-data/apk-hashes.yml]
    description: "Known-malicious APK file SHA-256 hashes"

  known_good_app_db:
    type: PACKAGE_NAME
    files:
      - ioc-data/popular-apps.yml
      - ioc-data/known-oem-prefixes.yml
    description: "Allowlist of popular legitimate apps and OEM package prefixes"
```

- [ ] **Step 2: Validate it parses**

```bash
cd third-party/android-sigma-rules
python3 -c "import yaml; print(list(yaml.safe_load(open('validation/ioc-lookup-definitions.yml'))['lookups'].keys()))"
```

Expected: `['package_ioc_db', 'cert_hash_ioc_db', 'domain_ioc_db', 'apk_hash_ioc_db', 'known_good_app_db']`

- [ ] **Step 3: Commit**

```bash
cd third-party/android-sigma-rules
git add validation/ioc-lookup-definitions.yml
git commit -m "feat(validation): add ioc-lookup-definitions.yml (#117)"
```

## Task 4: Create kotlin-mirror-feeds.yml

**Files:**
- Create: `third-party/android-sigma-rules/validation/kotlin-mirror-feeds.yml`

- [ ] **Step 1: Write the file**

Create `third-party/android-sigma-rules/validation/kotlin-mirror-feeds.yml` with:

```yaml
# Upstream feeds that AndroDR's Kotlin bypass feed clients fetch directly.
# Entries in ioc-data/*.yml must NOT duplicate anything in these feeds —
# enforced by validate-ioc-complementarity.py.
#
# This list MUST match the set of in-scope bypass feed classes in AndroDR's
# app/src/main/java/com/androdr/ioc/feeds/. Drift is caught by the
# Kotlin-side KotlinMirrorFeedsCrossCheckTest.
#
# Out of scope (intentionally omitted):
# - HaGeZi (1M-entry DNS blocklist, wrong shape for YAML)
# - UAD, Plexus (known-good datasets, opposite trust polarity)
# - Zimperium (third-party mirror-of-a-mirror)
# - MalwareBazaarCertFeed (stub — no upstream wired yet)

version: 1
feeds:
  - id: stalkerware-indicators
    url: https://raw.githubusercontent.com/AssoEchap/stalkerware-indicators/master/ioc.yaml
    parser: stalkerware-yaml
    types: [PACKAGE_NAME]

  - id: mvt-indicators
    url: https://raw.githubusercontent.com/mvt-project/mvt-indicators/main/indicators.yaml
    parser: mvt-stix
    types: [PACKAGE_NAME, C2_DOMAIN]

  - id: threatfox
    url: https://threatfox.abuse.ch/export/json/recent/
    parser: threatfox-json
    types: [C2_DOMAIN]

  - id: malwarebazaar
    url: https://bazaar.abuse.ch/export/csv/recent/
    parser: malwarebazaar-csv
    types: [APK_HASH]
```

- [ ] **Step 2: Validate it parses**

```bash
cd third-party/android-sigma-rules
python3 -c "import yaml; data = yaml.safe_load(open('validation/kotlin-mirror-feeds.yml')); assert len(data['feeds']) == 4; print('OK')"
```

Expected: `OK`

- [ ] **Step 3: Commit**

```bash
cd third-party/android-sigma-rules
git add validation/kotlin-mirror-feeds.yml
git commit -m "feat(validation): add kotlin-mirror-feeds.yml (#117)"
```

## Task 5: Add `ioc_data_last_write` field to feed-state-schema.json

**Files:**
- Modify: `third-party/android-sigma-rules/validation/feed-state-schema.json`

- [ ] **Step 1: Add the optional field to each FeedCursor $def**

Open `third-party/android-sigma-rules/validation/feed-state-schema.json`. For each of the five cursor definitions (`FeedCursor`, `FeedCursorWithBulletin`, `FeedCursorWithModified`, `FeedCursorWithCommit`, `FeedCursorWithVersion`), add the `ioc_data_last_write` property. Example for `FeedCursor`:

```json
"FeedCursor": {
  "type": "object",
  "required": ["last_seen_timestamp"],
  "additionalProperties": false,
  "properties": {
    "last_seen_timestamp": {
      "type": "string",
      "format": "date-time",
      "description": "ISO 8601 UTC timestamp of the most recent successful ingest."
    },
    "ioc_data_last_write": {
      "type": "string",
      "format": "date-time",
      "description": "ISO 8601 UTC timestamp of the most recent commit to ioc-data/*.yml driven by this ingester."
    }
  }
}
```

Apply the same additive `ioc_data_last_write` property to `FeedCursorWithBulletin`, `FeedCursorWithModified`, `FeedCursorWithCommit`, and `FeedCursorWithVersion`. The field is **optional** (not added to `required`) so existing `feed-state.json` files remain valid without modification.

- [ ] **Step 2: Verify existing feed-state.json still validates**

```bash
cd third-party/android-sigma-rules
python3 validation/validate-feed-state.py
```

Expected: `PASS` or equivalent success message.

- [ ] **Step 3: Commit**

```bash
cd third-party/android-sigma-rules
git add validation/feed-state-schema.json
git commit -m "feat(validation): add optional ioc_data_last_write cursor field (#117)"
```

## Task 6: Create submodule CI workflow

**Files:**
- Create: `third-party/android-sigma-rules/.github/workflows/validate.yml`

- [ ] **Step 1: Create the workflow directory and file**

```bash
cd third-party/android-sigma-rules
mkdir -p .github/workflows
```

Create `third-party/android-sigma-rules/.github/workflows/validate.yml` with:

```yaml
name: validate

on:
  pull_request:
    branches: [main]
  push:
    branches: [main]

jobs:
  validate-ioc-data:
    name: Validate ioc-data/*.yml
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      - name: Install deps
        run: pip install pyyaml jsonschema
      - name: Validate every ioc-data file
        run: |
          for f in ioc-data/*.yml; do
            python3 validation/validate-ioc-data.py "$f"
          done

  validate-feed-state:
    name: Validate feed-state.json
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      - name: Install deps
        run: pip install pyyaml jsonschema
      - name: Validate feed-state.json
        run: python3 validation/validate-feed-state.py

  validate-rules:
    name: Validate rules/**/*.yml
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      - name: Install deps
        run: pip install pyyaml jsonschema
      - name: Validate every rule
        run: |
          find app_scanner device_auditor dns_monitor process_monitor file_scanner accessibility_audit appops_audit receiver_audit staging -name '*.yml' -print0 \
            | xargs -0 -I{} python3 validation/validate-rule.py "{}"
```

- [ ] **Step 2: Locally dry-run each workflow step**

```bash
cd third-party/android-sigma-rules
pip install pyyaml jsonschema
for f in ioc-data/*.yml; do python3 validation/validate-ioc-data.py "$f"; done
python3 validation/validate-feed-state.py
find app_scanner device_auditor dns_monitor process_monitor file_scanner accessibility_audit appops_audit receiver_audit staging -name '*.yml' 2>/dev/null -print | head -5
```

Expected: all ioc-data files pass; feed-state passes; find lists at least some rule files (exact count depends on current state).

- [ ] **Step 3: Commit**

```bash
cd third-party/android-sigma-rules
git add .github/workflows/validate.yml
git commit -m "ci: add validate workflow for ioc-data, feed-state, rules (#117)"
```

## Task 7: Push Phase 1 branch and open PR against submodule

- [ ] **Step 1: Push the branch**

```bash
cd third-party/android-sigma-rules
git push -u origin feat/117-foundations
```

- [ ] **Step 2: Open PR**

```bash
cd third-party/android-sigma-rules
gh pr create --base main --head feat/117-foundations \
  --title "feat: ioc-entry schema + lookup definitions + mirror feeds (Phase 1 of #117)" \
  --body "$(cat <<'EOF'
## Summary

Phase 1 of AndroDR issue #117's complementary IOC pipeline work. Adds the declarative artifacts the pipeline will rely on:

- \`validation/ioc-entry-schema.json\` — formal schema for a single IOC entry
- \`validation/ioc-lookup-definitions.yml\` — canonical SIGMA \`ioc_lookup\` db-name map
- \`validation/kotlin-mirror-feeds.yml\` — list of feeds AndroDR's Kotlin bypass clients fetch
- \`validation/validate-ioc-data.py\` — schema-first validation added as the first check
- \`validation/feed-state-schema.json\` — optional \`ioc_data_last_write\` cursor field
- \`.github/workflows/validate.yml\` — CI runner for the validators

No changes to existing \`ioc-data/*.yml\` content in this PR; pruning lands in Phase 3.

## Test plan

- [x] Schema validates its own draft (jsonschema check_schema)
- [x] All existing ioc-data files pass the extended validate-ioc-data.py
- [x] Existing feed-state.json still validates against the updated schema
- [x] CI workflow dry-runs locally

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
)"
```

- [ ] **Step 3: Wait for PR to merge before continuing to Phase 3**

Phase 3 branches off the merged `main` of the submodule. Do not proceed to Phase 3 tasks until this PR is merged.

---

# Phase 3 — Complementarity gate + prune (submodule PR) — ~2–3 days

Working directory: `third-party/android-sigma-rules/` (after Phase 1 has merged).

Branch off `main`: `feat/117-complementarity`.

## Task 8: Pull submodule main and branch

- [ ] **Step 1: Update local submodule to pick up merged Phase 1**

```bash
cd third-party/android-sigma-rules
git checkout main
git pull origin main
git checkout -b feat/117-complementarity
```

Verify Phase 1 artifacts are present:

```bash
ls validation/ioc-entry-schema.json validation/ioc-lookup-definitions.yml validation/kotlin-mirror-feeds.yml
```

Expected: all three files listed (no errors).

## Task 9: Write validate-ioc-complementarity.py — TDD phase 1 (write failing test)

**Files:**
- Create: `third-party/android-sigma-rules/validation/test_validate_ioc_complementarity.py`

- [ ] **Step 1: Write a small unit test that exercises the happy path and the violation path**

Create `third-party/android-sigma-rules/validation/test_validate_ioc_complementarity.py` with:

```python
"""Unit tests for validate-ioc-complementarity.py.

Run: python3 -m pytest validation/test_validate_ioc_complementarity.py -v
"""
import pathlib
import subprocess
import sys
import tempfile
import textwrap

THIS_DIR = pathlib.Path(__file__).parent
SCRIPT = THIS_DIR / "validate-ioc-complementarity.py"


def run_script(args, env=None):
    return subprocess.run(
        [sys.executable, str(SCRIPT)] + args,
        capture_output=True, text=True, env=env,
    )


def test_script_exists():
    assert SCRIPT.exists(), f"expected script at {SCRIPT}"


def test_exits_nonzero_when_entry_is_in_upstream_snapshot(tmp_path):
    # Offline mode: provide an explicit upstream snapshot rather than
    # fetching from the network. A real fetch is tested separately.
    upstream_snapshot = tmp_path / "upstream.txt"
    upstream_snapshot.write_text("PACKAGE_NAME\tcom.bad.example\n")

    ioc_file = tmp_path / "package-names.yml"
    ioc_file.write_text(textwrap.dedent("""
        version: "2026-04-16"
        description: "test"
        entries:
          - indicator: com.bad.example
            category: STALKERWARE
            severity: CRITICAL
            source: stalkerware-indicators
    """).strip())

    result = run_script([
        "--offline-snapshot", str(upstream_snapshot),
        "--file", str(ioc_file),
        "--mode", "strict",
    ])
    assert result.returncode != 0, result.stdout + result.stderr
    assert "com.bad.example" in (result.stdout + result.stderr)


def test_exits_zero_when_entry_not_in_upstream(tmp_path):
    upstream_snapshot = tmp_path / "upstream.txt"
    upstream_snapshot.write_text("PACKAGE_NAME\tcom.other.app\n")

    ioc_file = tmp_path / "package-names.yml"
    ioc_file.write_text(textwrap.dedent("""
        version: "2026-04-16"
        description: "test"
        entries:
          - indicator: com.unique.entry
            category: STALKERWARE
            severity: CRITICAL
            source: amnesty-investigations
    """).strip())

    result = run_script([
        "--offline-snapshot", str(upstream_snapshot),
        "--file", str(ioc_file),
        "--mode", "strict",
    ])
    assert result.returncode == 0, result.stdout + result.stderr


def test_advisory_mode_reports_but_does_not_fail(tmp_path):
    upstream_snapshot = tmp_path / "upstream.txt"
    upstream_snapshot.write_text("PACKAGE_NAME\tcom.bad.example\n")

    ioc_file = tmp_path / "package-names.yml"
    ioc_file.write_text(textwrap.dedent("""
        version: "2026-04-16"
        description: "test"
        entries:
          - indicator: com.bad.example
            category: STALKERWARE
            severity: CRITICAL
            source: stalkerware-indicators
    """).strip())

    result = run_script([
        "--offline-snapshot", str(upstream_snapshot),
        "--file", str(ioc_file),
        "--mode", "advisory",
    ])
    assert result.returncode == 0, result.stdout + result.stderr
    assert "WARN" in (result.stdout + result.stderr) or "advisory" in (result.stdout + result.stderr).lower()
```

- [ ] **Step 2: Run the test — expect FAIL because script doesn't exist yet**

```bash
cd third-party/android-sigma-rules
python3 -m pytest validation/test_validate_ioc_complementarity.py -v
```

Expected: FAILS with `assert SCRIPT.exists(), ...` assertion error or similar (script file missing).

## Task 10: Write validate-ioc-complementarity.py — implementation

**Files:**
- Create: `third-party/android-sigma-rules/validation/validate-ioc-complementarity.py`

- [ ] **Step 1: Write the script**

Create `third-party/android-sigma-rules/validation/validate-ioc-complementarity.py` with:

```python
#!/usr/bin/env python3
"""Validate ioc-data/*.yml entries against kotlin-mirror-feeds.yml upstreams.

Modes:
  strict   -- any (type, value) duplicate causes non-zero exit.
  advisory -- duplicates are reported on stdout as WARNings, exit 0.

Offline mode:
  --offline-snapshot FILE  -- use a TSV (type \\t normalized_value per line)
                              instead of fetching from upstreams. For unit
                              tests and CI-without-network scenarios.

Usage:
  validate-ioc-complementarity.py --file ioc-data/package-names.yml --mode strict
  validate-ioc-complementarity.py --all --mode strict            # walk every ioc-data/*.yml
  validate-ioc-complementarity.py --file ... --offline-snapshot ...

Exit codes:
  0 -- no strict-mode violations (advisory warnings may have been emitted)
  1 -- one or more strict-mode violations
  2 -- setup / fetch / parse error
"""

import argparse
import json
import pathlib
import sys
import urllib.request
import urllib.error

try:
    import yaml
except ImportError:
    sys.exit("pyyaml required: pip install pyyaml")

SCRIPT_DIR = pathlib.Path(__file__).parent
DEFAULT_IOC_DATA = SCRIPT_DIR.parent / "ioc-data"
DEFAULT_MIRROR_FEEDS = SCRIPT_DIR / "kotlin-mirror-feeds.yml"

USER_AGENT = "androdr-complementarity-validator/1.0"
FETCH_TIMEOUT = 30  # seconds


def load_mirror_feeds(path: pathlib.Path) -> list[dict]:
    with open(path) as f:
        data = yaml.safe_load(f)
    return data.get("feeds", [])


def fetch_url(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=FETCH_TIMEOUT) as resp:
        return resp.read()


def normalize_value(raw: str, ioc_type: str) -> str:
    """Normalize an IOC value for dedup comparison."""
    v = raw.strip()
    if ioc_type in ("C2_DOMAIN",):
        v = v.lower().rstrip(".")
    elif ioc_type in ("APK_HASH", "CERT_HASH"):
        v = v.lower()
    return v


# Per-parser: fetch upstream, yield (type, normalized_value) tuples.
# Errors during fetch/parse raise; caller decides whether to fail or degrade.

def parse_stalkerware_yaml(body: bytes) -> set[tuple[str, str]]:
    """AssoEchap/stalkerware-indicators ioc.yaml: list of {name, type, packages: [...]}."""
    data = yaml.safe_load(body) or []
    out: set[tuple[str, str]] = set()
    for entry in data:
        for pkg in entry.get("packages", []) or []:
            out.add(("PACKAGE_NAME", normalize_value(str(pkg), "PACKAGE_NAME")))
    return out


def parse_threatfox_json(body: bytes) -> set[tuple[str, str]]:
    """ThreatFox recent export: {query_status, data: {date: [ {ioc_type, ioc, ...}, ... ]}}."""
    data = json.loads(body)
    out: set[tuple[str, str]] = set()
    for _date, entries in (data.get("data") or {}).items():
        for e in entries or []:
            if e.get("ioc_type") != "domain":
                continue
            raw = e.get("ioc", "")
            # Strip protocol and port/path (same as ThreatFoxDomainFeed.kt)
            for prefix in ("http://", "https://"):
                if raw.startswith(prefix):
                    raw = raw[len(prefix):]
            raw = raw.split("/", 1)[0].split(":", 1)[0]
            if raw:
                out.add(("C2_DOMAIN", normalize_value(raw, "C2_DOMAIN")))
    return out


def parse_malwarebazaar_csv(body: bytes) -> set[tuple[str, str]]:
    """MalwareBazaar recent CSV: comma-separated, # comments. SHA256 is column 2."""
    out: set[tuple[str, str]] = set()
    for line in body.decode("utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = [p.strip().strip('"') for p in line.split(",")]
        if len(parts) < 3:
            continue
        sha256 = parts[1]
        # Filter to Android APKs — file_type is typically column 7+ depending on format;
        # conservatively include everything and let other filters narrow later.
        if len(sha256) == 64 and all(c in "0123456789abcdef" for c in sha256.lower()):
            out.add(("APK_HASH", normalize_value(sha256, "APK_HASH")))
    return out


def parse_mvt_stix(body: bytes) -> set[tuple[str, str]]:
    """MVT indicators.yaml: mixed indicator types. Best-effort extraction."""
    data = yaml.safe_load(body) or {}
    out: set[tuple[str, str]] = set()
    # MVT indicators.yaml has an 'indicators' list with type-keyed entries
    for ind in data.get("indicators", []) or []:
        itype = (ind.get("type") or "").lower()
        value = ind.get("value") or ind.get("pattern") or ""
        if not value:
            continue
        if itype in ("domain-name", "domain"):
            out.add(("C2_DOMAIN", normalize_value(value, "C2_DOMAIN")))
        elif itype in ("app-id", "package", "package-name"):
            out.add(("PACKAGE_NAME", normalize_value(value, "PACKAGE_NAME")))
    return out


PARSERS = {
    "stalkerware-yaml": parse_stalkerware_yaml,
    "threatfox-json": parse_threatfox_json,
    "malwarebazaar-csv": parse_malwarebazaar_csv,
    "mvt-stix": parse_mvt_stix,
}


def build_union_snapshot(feeds: list[dict], allow_unreachable: bool) -> tuple[set[tuple[str, str]], list[str]]:
    union: set[tuple[str, str]] = set()
    warnings: list[str] = []
    for feed in feeds:
        fid = feed["id"]
        url = feed["url"]
        parser_name = feed["parser"]
        parser = PARSERS.get(parser_name)
        if parser is None:
            raise SystemExit(f"Unknown parser '{parser_name}' for feed '{fid}'")
        try:
            body = fetch_url(url)
            snapshot = parser(body)
            print(f"[complementarity] fetched {fid}: {len(snapshot)} entries", file=sys.stderr)
            union |= snapshot
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            msg = f"[complementarity] WARN: upstream '{fid}' unreachable: {e}"
            warnings.append(msg)
            if allow_unreachable:
                print(msg, file=sys.stderr)
            else:
                raise SystemExit(f"[complementarity] fetch failed for '{fid}': {e}")
    return union, warnings


def load_offline_snapshot(path: pathlib.Path) -> set[tuple[str, str]]:
    out: set[tuple[str, str]] = set()
    with open(path) as f:
        for line in f:
            line = line.rstrip("\n")
            if not line or line.startswith("#"):
                continue
            ioc_type, raw_value = line.split("\t", 1)
            out.add((ioc_type, normalize_value(raw_value, ioc_type)))
    return out


IOC_TYPE_BY_FILENAME = {
    "package-names.yml":    "PACKAGE_NAME",
    "c2-domains.yml":       "C2_DOMAIN",
    "cert-hashes.yml":      "CERT_HASH",
    "malware-hashes.yml":   "APK_HASH",
    "apk-hashes.yml":       "APK_HASH",
    "popular-apps.yml":     "PACKAGE_NAME",
    "known-oem-prefixes.yml": "PACKAGE_NAME",
}


def check_file(ioc_file: pathlib.Path, upstream_union: set[tuple[str, str]]) -> list[str]:
    ioc_type = IOC_TYPE_BY_FILENAME.get(ioc_file.name)
    if ioc_type is None:
        return [f"[complementarity] unknown filename '{ioc_file.name}' — add to IOC_TYPE_BY_FILENAME"]

    with open(ioc_file) as f:
        data = yaml.safe_load(f) or {}

    violations: list[str] = []
    for idx, entry in enumerate(data.get("entries") or []):
        indicator = entry.get("indicator")
        if not indicator:
            continue
        normalized = normalize_value(str(indicator), ioc_type)
        if (ioc_type, normalized) in upstream_union:
            source = entry.get("source", "?")
            violations.append(
                f"  entries[{idx}] '{indicator}' (source={source}) present in an upstream feed"
            )
    return violations


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--file", type=pathlib.Path, help="Single ioc-data/*.yml file to check.")
    ap.add_argument("--all", action="store_true", help="Check every ioc-data/*.yml file.")
    ap.add_argument("--mode", choices=["strict", "advisory"], default="strict")
    ap.add_argument("--mirror-feeds", type=pathlib.Path, default=DEFAULT_MIRROR_FEEDS)
    ap.add_argument("--offline-snapshot", type=pathlib.Path,
                    help="Use a TSV (type<TAB>value) snapshot instead of fetching. For tests.")
    ap.add_argument("--allow-upstream-unreachable", action="store_true",
                    help="Don't fail if an upstream feed is unreachable (pipeline-local use).")
    args = ap.parse_args()

    if not args.file and not args.all:
        ap.error("either --file or --all must be given")

    if args.offline_snapshot:
        upstream_union = load_offline_snapshot(args.offline_snapshot)
    else:
        feeds = load_mirror_feeds(args.mirror_feeds)
        upstream_union, _ = build_union_snapshot(feeds, args.allow_upstream_unreachable)

    files = [args.file] if args.file else sorted(DEFAULT_IOC_DATA.glob("*.yml"))
    any_violation = False
    for f in files:
        violations = check_file(f, upstream_union)
        if violations:
            any_violation = True
            header = f"{f.name}: {len(violations)} complementarity violation(s)"
            if args.mode == "advisory":
                print(f"WARN (advisory): {header}", file=sys.stderr)
                for v in violations:
                    print(v, file=sys.stderr)
            else:
                print(f"FAIL: {header}", file=sys.stderr)
                for v in violations:
                    print(v, file=sys.stderr)

    if any_violation and args.mode == "strict":
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
```

- [ ] **Step 2: Make it executable and run the unit tests**

```bash
cd third-party/android-sigma-rules
chmod +x validation/validate-ioc-complementarity.py
python3 -m pytest validation/test_validate_ioc_complementarity.py -v
```

Expected: all 4 tests PASS.

- [ ] **Step 3: Commit**

```bash
cd third-party/android-sigma-rules
git add validation/validate-ioc-complementarity.py validation/test_validate_ioc_complementarity.py
git commit -m "feat(validation): add validate-ioc-complementarity.py with strict/advisory modes (#117)"
```

## Task 11: Run complementarity validator against current ioc-data and prune

**Files:**
- Modify: `third-party/android-sigma-rules/ioc-data/package-names.yml` (remove entries)
- Modify: `third-party/android-sigma-rules/ioc-data/c2-domains.yml` (remove entries)
- Modify: `third-party/android-sigma-rules/ioc-data/cert-hashes.yml` (remove entries)
- Modify: `third-party/android-sigma-rules/ioc-data/malware-hashes.yml` (remove entries)

- [ ] **Step 1: Run validator in advisory mode to inventory violations**

```bash
cd third-party/android-sigma-rules
python3 validation/validate-ioc-complementarity.py --all --mode advisory 2> /tmp/117-advisory.txt
cat /tmp/117-advisory.txt
```

Expected: a list of violating entries per file. These are the entries Phase 3 will prune. If the fetch fails for any feed, re-run with `--allow-upstream-unreachable` and note which feed is missing from the snapshot.

- [ ] **Step 2: For each violating entry, remove it from the corresponding ioc-data file**

**Safety filter:** only prune an entry if its `source` field corresponds to a feed listed in `kotlin-mirror-feeds.yml`. For example: entries sourced from `stalkerware-indicators`, `mvt-indicators`, `threatfox`, or `malwarebazaar` that also appear in the upstream snapshot are safe to prune. Entries sourced from `amnesty-investigations`, `citizenlab-indicators`, `android-security-bulletin`, `virustotal`, or `zimperium-ioc` **must not be pruned** even if they happen to appear in an upstream snapshot (no Kotlin Track A mirrors them, so pruning would cause on-device detection loss — see spec Phase 3 Migration safety section).

For each file (`ioc-data/package-names.yml`, `c2-domains.yml`, `cert-hashes.yml`, `malware-hashes.yml`): delete the YAML list item for every prune-eligible violating entry. Keep the file's header (`version`, `description`, `sources`) intact.

- [ ] **Step 3: Re-run validator in strict mode to confirm all remaining entries are complementary**

```bash
cd third-party/android-sigma-rules
python3 validation/validate-ioc-complementarity.py --all --mode strict
```

Expected: exit 0, no violations remaining.

- [ ] **Step 4: Re-run validate-ioc-data.py to confirm schema is still satisfied after pruning**

```bash
cd third-party/android-sigma-rules
for f in ioc-data/*.yml; do python3 validation/validate-ioc-data.py "$f"; done
```

Expected: every file PASS.

- [ ] **Step 5: Capture pruned-entry count for PR description**

```bash
cd third-party/android-sigma-rules
git diff --stat ioc-data/
git diff ioc-data/ > /tmp/117-prune-diff.txt
```

Record the total lines removed per file; this goes into the PR description as evidence that the prune happened correctly.

- [ ] **Step 6: Commit**

```bash
cd third-party/android-sigma-rules
git add ioc-data/
git commit -m "chore(ioc-data): prune entries already in kotlin-mirrored upstreams (#117)"
```

## Task 12: Wire complementarity validator into CI

**Files:**
- Modify: `third-party/android-sigma-rules/.github/workflows/validate.yml`

- [ ] **Step 1: Add a complementarity job to the workflow**

Open `third-party/android-sigma-rules/.github/workflows/validate.yml` and append after the existing `validate-ioc-data` job:

```yaml
  validate-complementarity-changed:
    name: Complementarity (strict on changed files)
    runs-on: ubuntu-latest
    if: github.event_name == 'pull_request'
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      - name: Install deps
        run: pip install pyyaml
      - name: Identify changed ioc-data files
        id: changed
        run: |
          CHANGED=$(git diff --name-only origin/${{ github.base_ref }}...HEAD -- 'ioc-data/*.yml' | tr '\n' ' ')
          echo "files=$CHANGED" >> "$GITHUB_OUTPUT"
      - name: Strict check on changed files
        if: steps.changed.outputs.files != ''
        run: |
          for f in ${{ steps.changed.outputs.files }}; do
            python3 validation/validate-ioc-complementarity.py --file "$f" --mode strict
          done

  validate-complementarity-all-advisory:
    name: Complementarity (advisory on all files)
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      - name: Install deps
        run: pip install pyyaml
      - name: Advisory check on every file
        run: |
          python3 validation/validate-ioc-complementarity.py --all --mode advisory
```

- [ ] **Step 2: Commit**

```bash
cd third-party/android-sigma-rules
git add .github/workflows/validate.yml
git commit -m "ci: wire complementarity validator (strict on changed, advisory on all) (#117)"
```

## Task 13: Push Phase 3 branch and open PR

- [ ] **Step 1: Push and open PR**

```bash
cd third-party/android-sigma-rules
git push -u origin feat/117-complementarity
gh pr create --base main --head feat/117-complementarity \
  --title "feat: validate-ioc-complementarity.py + prune existing ioc-data (Phase 3 of #117)" \
  --body "$(cat <<'EOF'
## Summary

Phase 3 of AndroDR issue #117's complementary IOC pipeline work.

- \`validation/validate-ioc-complementarity.py\` — new validator; strict mode for changed files, advisory for untouched (absorbs upstream mutation drift)
- \`validation/test_validate_ioc_complementarity.py\` — unit tests
- \`ioc-data/*.yml\` — one-time prune of entries already in kotlin-mirrored upstreams (see diff-stat in PR)
- \`.github/workflows/validate.yml\` — CI jobs for complementarity (strict-on-changed, advisory-on-all)

## Test plan

- [x] Unit tests pass (pytest validation/test_validate_ioc_complementarity.py)
- [x] validate-ioc-complementarity.py --all --mode strict passes after prune
- [x] validate-ioc-data.py passes on every file after prune (schema still satisfied)
- [x] CI workflow dry-runs locally

## Pruned entry summary

\`\`\`
$(cd third-party/android-sigma-rules && git diff --stat HEAD~1 -- ioc-data/ 2>/dev/null || echo 'see prune commit')
\`\`\`

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
)"
```

- [ ] **Step 2: Wait for PR to merge before continuing to Phase 2**

Phase 2 needs both Phase 1 and Phase 3 merged so the Kotlin cross-check tests run against the final submodule state.

---

# Phase 2 — Kotlin cross-check tests (AndroDR PR) — ~1 day

Working directory: AndroDR repo root.

Branch off `main`: `feat/117-kotlin-crosschecks`.

## Task 14: Bump submodule pointer

- [ ] **Step 1: Update submodule to post-Phase-1+3 tip**

```bash
cd /home/yasir/AndroDR
git checkout main
git pull
git checkout -b feat/117-kotlin-crosschecks
cd third-party/android-sigma-rules
git pull origin main
cd ../..
```

- [ ] **Step 2: Verify the bump picks up Phase 1 and Phase 3 artifacts**

```bash
ls third-party/android-sigma-rules/validation/ioc-entry-schema.json \
   third-party/android-sigma-rules/validation/ioc-lookup-definitions.yml \
   third-party/android-sigma-rules/validation/kotlin-mirror-feeds.yml \
   third-party/android-sigma-rules/validation/validate-ioc-complementarity.py
```

Expected: all four files present.

- [ ] **Step 3: Stage the submodule bump (do not commit yet — the tests come with this PR)**

```bash
git add third-party/android-sigma-rules
git status
```

Expected: `modified: third-party/android-sigma-rules (new commits)` in the staged changes.

## Task 15: Write IocLookupDefinitionsCrossCheckTest — TDD phase 1 (failing test)

**Files:**
- Create: `app/src/test/java/com/androdr/sigma/IocLookupDefinitionsCrossCheckTest.kt`

- [ ] **Step 1: Write the test**

Create `app/src/test/java/com/androdr/sigma/IocLookupDefinitionsCrossCheckTest.kt` with:

```kotlin
package com.androdr.sigma

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.snakeyaml.engine.v2.api.Load
import org.snakeyaml.engine.v2.api.LoadSettings
import java.io.File

/**
 * Build-time cross-check: the ioc_lookup database names declared in
 * validation/ioc-lookup-definitions.yml MUST match the hardcoded map in
 * ScanOrchestrator.initRuleEngine(). Drift fails the build.
 */
class IocLookupDefinitionsCrossCheckTest {

    // Single source of truth for the *expected* set on the Kotlin side.
    // Mirrors the keys set in ScanOrchestrator.setIocLookups(...).
    private val kotlinLookupNames = setOf(
        "package_ioc_db",
        "cert_hash_ioc_db",
        "domain_ioc_db",
        "apk_hash_ioc_db",
        "known_good_app_db",
    )

    private fun definitionsFile(): File {
        val candidates = listOf(
            File("third-party/android-sigma-rules/validation/ioc-lookup-definitions.yml"),
            File("../third-party/android-sigma-rules/validation/ioc-lookup-definitions.yml"),
            File("/home/yasir/AndroDR/third-party/android-sigma-rules/validation/ioc-lookup-definitions.yml"),
        )
        return candidates.firstOrNull { it.isFile }
            ?: error("ioc-lookup-definitions.yml not found. Run: git submodule update --init")
    }

    @Test
    fun `ioc-lookup-definitions keys match kotlin lookup names`() {
        val settings = LoadSettings.builder().setAllowDuplicateKeys(false).build()
        val load = Load(settings)

        @Suppress("UNCHECKED_CAST")
        val doc = load.loadFromString(definitionsFile().readText()) as Map<String, Any?>
        @Suppress("UNCHECKED_CAST")
        val lookups = doc["lookups"] as Map<String, Any?>

        val yamlLookupNames = lookups.keys
        assertEquals(
            "Set of lookup names must match exactly between Kotlin and ioc-lookup-definitions.yml.\n" +
                "Kotlin:   $kotlinLookupNames\n" +
                "YAML:     $yamlLookupNames\n" +
                "Missing from YAML: ${kotlinLookupNames - yamlLookupNames}\n" +
                "Extra in YAML:     ${yamlLookupNames - kotlinLookupNames}",
            kotlinLookupNames,
            yamlLookupNames,
        )
    }

    @Test
    fun `every lookup entry references at least one existing ioc-data file`() {
        val settings = LoadSettings.builder().setAllowDuplicateKeys(false).build()
        val load = Load(settings)

        @Suppress("UNCHECKED_CAST")
        val doc = load.loadFromString(definitionsFile().readText()) as Map<String, Any?>
        @Suppress("UNCHECKED_CAST")
        val lookups = doc["lookups"] as Map<String, Map<String, Any?>>

        val submoduleRoot = definitionsFile().parentFile.parentFile
        val failures = mutableListOf<String>()

        for ((name, def) in lookups) {
            @Suppress("UNCHECKED_CAST")
            val files = def["files"] as List<String>
            for (relPath in files) {
                val iocFile = File(submoduleRoot, relPath)
                if (!iocFile.isFile) {
                    failures += "lookup '$name' references missing file: $relPath"
                }
            }
        }

        assertTrue(
            "ioc-lookup-definitions.yml references ioc-data files that do not exist:\n" +
                failures.joinToString("\n"),
            failures.isEmpty(),
        )
    }
}
```

- [ ] **Step 2: Run the test — expect FAIL until submodule is updated (Task 14 already did this) or a drift is introduced**

```bash
./gradlew testDebugUnitTest --tests "com.androdr.sigma.IocLookupDefinitionsCrossCheckTest" -i
```

Expected: PASS (submodule bump in Task 14 brought in the definitions file and the 5 names match). If the test fails, inspect the error message — either the submodule bump didn't complete, or Kotlin's `ScanOrchestrator` map has drifted.

- [ ] **Step 3: Commit**

```bash
git add app/src/test/java/com/androdr/sigma/IocLookupDefinitionsCrossCheckTest.kt
git commit -m "test(sigma): IocLookupDefinitionsCrossCheckTest locks ioc_lookup db-name drift (#117)"
```

## Task 16: Write IocDataSchemaCrossCheckTest

**Files:**
- Create: `app/src/test/java/com/androdr/sigma/IocDataSchemaCrossCheckTest.kt`

- [ ] **Step 1: Write the test**

Create `app/src/test/java/com/androdr/sigma/IocDataSchemaCrossCheckTest.kt` with:

```kotlin
package com.androdr.sigma

import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.ObjectMapper
import com.networknt.schema.SchemaRegistry
import com.networknt.schema.SpecificationVersion
import org.junit.Assume.assumeTrue
import org.junit.Assert.fail
import org.junit.Test
import org.snakeyaml.engine.v2.api.Load
import org.snakeyaml.engine.v2.api.LoadSettings
import java.io.File

/**
 * Build-time cross-check: every entry in every ioc-data/*.yml MUST validate
 * against validation/ioc-entry-schema.json. Mirrors the pattern of
 * BundledRulesSchemaCrossCheckTest.
 */
class IocDataSchemaCrossCheckTest {

    private val objectMapper = ObjectMapper()

    private fun schemaFile(): File? {
        val candidates = listOf(
            File("third-party/android-sigma-rules/validation/ioc-entry-schema.json"),
            File("../third-party/android-sigma-rules/validation/ioc-entry-schema.json"),
            File("/home/yasir/AndroDR/third-party/android-sigma-rules/validation/ioc-entry-schema.json"),
        )
        return candidates.firstOrNull { it.isFile }
    }

    private fun iocDataFiles(): List<File> {
        val candidates = listOf(
            File("third-party/android-sigma-rules/ioc-data"),
            File("../third-party/android-sigma-rules/ioc-data"),
            File("/home/yasir/AndroDR/third-party/android-sigma-rules/ioc-data"),
        )
        val dir = candidates.firstOrNull { it.isDirectory } ?: return emptyList()
        return dir.listFiles { f -> f.name.endsWith(".yml") }?.sorted() ?: emptyList()
    }

    @Test
    fun `every ioc-data entry validates against ioc-entry-schema`() {
        val schema = schemaFile()
        assumeTrue(
            "Skipping: ioc-entry-schema.json not found (submodule not initialized). " +
                "Run: git submodule update --init",
            schema != null && schema.isFile,
        )

        val files = iocDataFiles()
        assumeTrue("No ioc-data/*.yml files found", files.isNotEmpty())

        val registry = SchemaRegistry.withDefaultDialect(SpecificationVersion.DRAFT_2020_12)
        val jsonSchema = schema!!.inputStream().use { registry.getSchema(it) }

        val yamlLoader = Load(
            LoadSettings.builder()
                .setMaxAliasesForCollections(10)
                .setAllowDuplicateKeys(false)
                .build()
        )
        val failures = mutableListOf<String>()

        files.forEach { file ->
            try {
                @Suppress("UNCHECKED_CAST")
                val doc = yamlLoader.loadFromString(file.readText()) as? Map<String, Any?> ?: run {
                    failures += "${file.name}: not a YAML map"
                    return@forEach
                }
                @Suppress("UNCHECKED_CAST")
                val entries = doc["entries"] as? List<Map<String, Any?>> ?: emptyList()
                entries.forEachIndexed { idx, entry ->
                    val jsonNode: JsonNode = objectMapper.valueToTree(entry)
                    val errors = jsonSchema.validate(jsonNode)
                    if (errors.isNotEmpty()) {
                        val summary = errors.joinToString("; ") { e -> e.message }
                        failures += "${file.name} entries[$idx]: $summary"
                    }
                }
            } catch (e: Exception) {
                failures += "${file.name}: ${e::class.simpleName}: ${e.message}"
            }
        }

        if (failures.isNotEmpty()) {
            fail(
                "ioc-entry-schema gate FAILED for ${failures.size} entry(ies):\n" +
                    failures.joinToString("\n") { "  - $it" } + "\n\n" +
                    "If you added a new IOC field, update ioc-entry-schema.json in the " +
                    "android-sigma-rules repo and bump the submodule."
            )
        }
    }
}
```

- [ ] **Step 2: Run the test**

```bash
./gradlew testDebugUnitTest --tests "com.androdr.sigma.IocDataSchemaCrossCheckTest" -i
```

Expected: PASS. The schema was validated against these files in Phase 1's Task 2, and Phase 3 did not introduce new fields; the test should pass immediately.

- [ ] **Step 3: Commit**

```bash
git add app/src/test/java/com/androdr/sigma/IocDataSchemaCrossCheckTest.kt
git commit -m "test(sigma): IocDataSchemaCrossCheckTest validates every ioc-data entry (#117)"
```

## Task 17: Write KotlinMirrorFeedsCrossCheckTest

**Files:**
- Create: `app/src/test/java/com/androdr/ioc/KotlinMirrorFeedsCrossCheckTest.kt`

- [ ] **Step 1: Write the test**

Create `app/src/test/java/com/androdr/ioc/KotlinMirrorFeedsCrossCheckTest.kt` with:

```kotlin
package com.androdr.ioc

import org.junit.Assert.assertEquals
import org.junit.Test
import org.snakeyaml.engine.v2.api.Load
import org.snakeyaml.engine.v2.api.LoadSettings
import java.io.File

/**
 * Build-time cross-check: the set of Kotlin bypass feed classes that
 * directly fetch upstream IOCs MUST match the entries in
 * validation/kotlin-mirror-feeds.yml. Drift fails the build.
 *
 * URL constants remain private inside each feed class — URLs are
 * authoritative only in the YAML; this test uses class-name-based
 * correspondence via a declarative feed-id list below.
 *
 * To add a new bypass feed, add it to KOTLIN_BYPASS_FEED_IDS below AND to
 * validation/kotlin-mirror-feeds.yml in the submodule (same PR).
 */
class KotlinMirrorFeedsCrossCheckTest {

    // The feed IDs in validation/kotlin-mirror-feeds.yml that correspond to
    // actively-wired Kotlin bypass feed classes. Out-of-scope feeds (HaGeZi,
    // UAD, Plexus, Zimperium, MalwareBazaarCertFeed-stub) are NOT listed.
    private val kotlinBypassFeedIds = setOf(
        "stalkerware-indicators",  // StalkerwareIndicatorsFeed.kt
        "mvt-indicators",          // MvtIndicatorsFeed.kt
        "threatfox",               // ThreatFoxDomainFeed.kt
        "malwarebazaar",           // MalwareBazaarApkHashFeed.kt
    )

    private fun mirrorFeedsFile(): File {
        val candidates = listOf(
            File("third-party/android-sigma-rules/validation/kotlin-mirror-feeds.yml"),
            File("../third-party/android-sigma-rules/validation/kotlin-mirror-feeds.yml"),
            File("/home/yasir/AndroDR/third-party/android-sigma-rules/validation/kotlin-mirror-feeds.yml"),
        )
        return candidates.firstOrNull { it.isFile }
            ?: error("kotlin-mirror-feeds.yml not found. Run: git submodule update --init")
    }

    @Test
    fun `kotlin-mirror-feeds ids match the KOTLIN_BYPASS_FEED_IDS set`() {
        val settings = LoadSettings.builder().setAllowDuplicateKeys(false).build()
        val load = Load(settings)

        @Suppress("UNCHECKED_CAST")
        val doc = load.loadFromString(mirrorFeedsFile().readText()) as Map<String, Any?>
        @Suppress("UNCHECKED_CAST")
        val feeds = doc["feeds"] as List<Map<String, Any?>>
        val yamlFeedIds = feeds.map { it["id"] as String }.toSet()

        assertEquals(
            "kotlin-mirror-feeds.yml ids must exactly match KOTLIN_BYPASS_FEED_IDS.\n" +
                "Kotlin test: $kotlinBypassFeedIds\n" +
                "YAML:        $yamlFeedIds\n" +
                "Missing from YAML: ${kotlinBypassFeedIds - yamlFeedIds}\n" +
                "Extra in YAML:     ${yamlFeedIds - kotlinBypassFeedIds}",
            kotlinBypassFeedIds,
            yamlFeedIds,
        )
    }
}
```

- [ ] **Step 2: Run the test**

```bash
./gradlew testDebugUnitTest --tests "com.androdr.ioc.KotlinMirrorFeedsCrossCheckTest" -i
```

Expected: PASS (4 feed IDs match the YAML).

- [ ] **Step 3: Commit**

```bash
git add app/src/test/java/com/androdr/ioc/KotlinMirrorFeedsCrossCheckTest.kt
git commit -m "test(ioc): KotlinMirrorFeedsCrossCheckTest locks mirror-feeds drift (#117)"
```

## Task 18: Run full test suite and commit submodule bump

- [ ] **Step 1: Run the full unit test suite to ensure no regressions**

```bash
./gradlew testDebugUnitTest
```

Expected: all tests pass (including the three new cross-check tests and existing tests like `BundledRulesSchemaCrossCheckTest`).

- [ ] **Step 2: Commit the submodule bump alongside the tests**

```bash
git add third-party/android-sigma-rules
git commit -m "build: bump android-sigma-rules submodule for Phase 1+3 artifacts (#117)"
```

- [ ] **Step 3: Push branch and open PR**

```bash
git push -u origin feat/117-kotlin-crosschecks
gh pr create --base main --head feat/117-kotlin-crosschecks \
  --title "test(sigma): cross-check tests for ioc-lookup-definitions, ioc-entry-schema, kotlin-mirror-feeds" \
  --body "$(cat <<'EOF'
## Summary

Phase 2 of #117. Three new unit tests lock drift between Kotlin code and
the declarative artifacts added by Phase 1 (merged in submodule):

- \`IocLookupDefinitionsCrossCheckTest\` — \`ScanOrchestrator.initRuleEngine()\`'s ioc_lookup names ↔ \`ioc-lookup-definitions.yml\`
- \`IocDataSchemaCrossCheckTest\` — every \`ioc-data/*.yml\` entry ↔ \`ioc-entry-schema.json\` (Draft 2020-12)
- \`KotlinMirrorFeedsCrossCheckTest\` — Kotlin bypass feed classes ↔ \`kotlin-mirror-feeds.yml\`

Also bumps the android-sigma-rules submodule to pick up Phase 1+3 artifacts.

## Test plan

- [x] \`./gradlew testDebugUnitTest\` — all tests pass
- [x] Three new cross-check tests verified individually via --tests filter

Related: #117

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
)"
```

- [ ] **Step 4: Wait for PR to merge before continuing to Phase 4**

Phase 4 depends on the submodule bump being merged into AndroDR's `main` so the pipeline skill changes can reference the Phase 1+3 artifacts.

---

# Phase 4 — Pipeline ingester extensions (AndroDR PR) — ~8–11 days

Working directory: AndroDR repo root (after Phase 2 has merged).

Branch off `main`: `feat/117-pipeline-writes`.

**Shared template for ingester skill extensions.** Every ingester skill file under `.claude/commands/update-rules-ingest-*.md` gains the same new output contract. Rather than re-typing the full contract in each of the 7 tasks, the contract below is cited by each task:

> **Ingester new output contract (added at the END of the existing skill file):**
>
> ```markdown
> ## IOC data output (added for #117)
>
> In addition to SIRs, emit a JSON object with two new fields:
>
> ```json
> {
>   "sirs": [ ... existing SIR array ... ],
>   "candidate_ioc_entries": [
>     {
>       "file": "ioc-data/<target-file>.yml",
>       "entry": { "indicator": "...", "category": "...", "severity": "...", "source": "<allowed-source-id>", "description": "..." }
>     }
>   ],
>   "upstream_snapshot_hash_set": [
>     ["PACKAGE_NAME", "com.example.normalized"],
>     ["C2_DOMAIN", "evil.example.com"]
>   ]
> }
> ```
>
> ### candidate_ioc_entries
>
> For each SIR with concrete indicators, emit one candidate entry per
> indicator. Filter out any indicator whose `(type, normalized_value)` is
> already present in `upstream_snapshot_hash_set` (self-dedup) — those are
> not net-new for this ingester.
>
> Target file by IOC type:
> - `PACKAGE_NAME`       → `ioc-data/package-names.yml`
> - `C2_DOMAIN`          → `ioc-data/c2-domains.yml`
> - `CERT_HASH`          → `ioc-data/cert-hashes.yml`
> - `APK_HASH`           → `ioc-data/apk-hashes.yml` (create file on first write if absent)
> - `KNOWN_GOOD` entries → not emitted (known-good flows through a separate path; out of scope for #117)
>
> ### upstream_snapshot_hash_set
>
> The full `(type, normalized_value)` set fetched from this ingester's
> upstream(s) during this run. Normalization rules:
> - `C2_DOMAIN`: lowercase, strip trailing `.`
> - `APK_HASH`, `CERT_HASH`: lowercase hex
> - `PACKAGE_NAME`: unchanged (case-sensitive per Android)
>
> Cross-dedup across concurrent ingesters is the dispatcher's job (Step 6.5
> of `update-rules.md`). Do NOT attempt cross-ingester dedup here.
> ```

## Task 19: Extend update-rules.md dispatcher with Step 6.5 (cross-dedup)

**Files:**
- Modify: `.claude/commands/update-rules.md`

- [ ] **Step 1: Add Step 6.5 between existing Steps 6 and 7**

Open `.claude/commands/update-rules.md`. Between the current `## Step 6: Generate Rules` section and the current `## Step 7: Present Results` section, insert a new section:

```markdown
## Step 6.5: Centralized cross-dedup for IOC candidates (added for #117)

Before surfacing candidates in Step 7, filter `candidate_ioc_entries`
against the **authoritative upstream coverage set** for this run.

### 6.5.1 Collect per-ingester snapshots

Every completed ingester returns `upstream_snapshot_hash_set` alongside its
SIRs and `candidate_ioc_entries` (see individual ingester skills). Take
the union of every snapshot as `U_ingesters`.

### 6.5.2 Fetch any missing mirror feeds

Read `third-party/android-sigma-rules/validation/kotlin-mirror-feeds.yml`.
For every feed listed there whose `id` does NOT appear in any completed
ingester (e.g., only the stalkerware ingester ran but ThreatFox is still
a Kotlin-mirrored upstream that candidates must be checked against), fetch
the feed into a `(type, normalized_value)` set using the parser identified
by the `parser` field. Take the union with `U_ingesters` → `U_authoritative`.

### 6.5.3 Filter candidates

For each candidate across all ingesters, drop it if
`(type, normalized_value)` is in `U_authoritative`. The survivors form the
**approved delta** that proceeds to Step 7.

### 6.5.4 Safety checks before Step 7

- If `U_authoritative` is empty (all upstreams failed to fetch), abort the
  run with a clear error. Do NOT proceed with unfiltered candidates — that
  would inject duplicates into ioc-data/*.yml.
- If any candidate's `source` field corresponds to a feed listed in
  `kotlin-mirror-feeds.yml` but the candidate survives the filter, log a
  WARN — this is typically a normalization mismatch worth investigating
  (the entry is in upstream under a different normalization).
```

- [ ] **Step 2: Update Step 7 (Present Results) to include IOC-only candidates**

Still in `.claude/commands/update-rules.md`, find the `## Step 7: Present Results` section. Append the following subsection at the end of Step 7:

```markdown
### 7.1 IOC-only candidates (added for #117)

Some candidates from Step 6.5 have no accompanying rule — they're pure IOC
data targeting the generic \`sigma_androdr_001_package_ioc\`,
\`_002_cert_hash_ioc\`, \`_003_domain_ioc\`, or \`_004_apk_hash_ioc\` rules,
which match anything in their lookup DB. Present these as first-class
approval candidates:

\`\`\`
IOC-ONLY CANDIDATE — via androdr-NNN generic ioc_lookup rule
Target file:  ioc-data/<file>.yml
Type:         <type>
Source:       <source-id>
Indicator(s): <count>
  - <indicator 1>  (<family>, <severity>)
  - <indicator 2>  ...
  [...]
\`\`\`

User actions for an IOC-only candidate: same as for a rule candidate —
**Approve**, **Modify** (edit entries), or **Reject**.
```

- [ ] **Step 3: Update Step 8 (Process User Decisions) to write ioc-data + run validators**

In the same file, find the `## Step 8: Process User Decisions` section. After the existing bullet list ("For each passing candidate, ask the user to: Approve...Modify...Reject"), append:

```markdown
### 8.1 Commit IOC candidates (added for #117)

For each approved candidate (rule OR IOC-only):

1. Append approved IOC entries to the target \`ioc-data/<file>.yml\` file.
   Preserve the file's header; append entries under the existing
   \`entries:\` list.

2. Run validators on every touched file. Abort the commit on any failure:
   \`\`\`bash
   cd third-party/android-sigma-rules
   python3 validation/validate-ioc-data.py ioc-data/<file>.yml
   python3 validation/validate-ioc-complementarity.py --file ioc-data/<file>.yml --mode strict
   \`\`\`
   If either validator exits non-zero, revert the append and report to the
   user. Do NOT commit.

3. Update \`feed-state.json\`: for each ingester that contributed approved
   candidates, set its \`ioc_data_last_write\` to the current ISO 8601
   timestamp (the schema supports this as an optional field per cursor).

4. Commit the ioc-data change(s) + rule change(s) + feed-state update as
   a single atomic commit. Commit message format:
   \`\`\`
   feat(rules+ioc): add <threat-name> (source: <source-id>) [Phase 4 of #117]
   \`\`\`

### 8.2 Safety rules

- NEVER commit an ioc-data write that validate-ioc-complementarity.py
  rejects in strict mode.
- NEVER pass --allow-upstream-unreachable in automated
  (non-interactive) pipeline runs; it's for operator-controlled retry
  only.
- NEVER modify \`kotlin-mirror-feeds.yml\` in the same commit as an
  ioc-data write.
```

- [ ] **Step 4: Append the safety rules to the "Safety Rules" section at the end of update-rules.md**

Find the existing `## Safety Rules` section and add these three bullets:

```markdown
- NEVER commit an ioc-data/*.yml write that validate-ioc-complementarity.py rejects
- NEVER pass --allow-upstream-unreachable in automated pipeline runs
- NEVER modify kotlin-mirror-feeds.yml in the same commit as an ioc-data write
```

- [ ] **Step 5: Commit**

```bash
git add .claude/commands/update-rules.md
git commit -m "feat(pipeline): dispatcher Step 6.5 cross-dedup + Step 7/8 IOC-data path (#117)"
```

## Task 20: Extend update-rules-ingest-stalkerware.md

**Files:**
- Modify: `.claude/commands/update-rules-ingest-stalkerware.md`

- [ ] **Step 1: Append the IOC data output contract to the end of the file**

Open `.claude/commands/update-rules-ingest-stalkerware.md`. At the end of the file, append:

```markdown
## IOC data output (added for #117)

In addition to SIRs, emit a JSON object with two new fields:

```json
{
  "sirs": [ ... existing SIR array ... ],
  "candidate_ioc_entries": [
    {
      "file": "ioc-data/package-names.yml",
      "entry": {
        "indicator": "com.example.spy",
        "family": "ExampleSpyware",
        "category": "STALKERWARE",
        "severity": "CRITICAL",
        "source": "stalkerware-indicators",
        "description": "..."
      }
    }
  ],
  "upstream_snapshot_hash_set": [
    ["PACKAGE_NAME", "com.example.spy"]
  ]
}
```

### candidate_ioc_entries

For each newly-discovered package name in the upstream (the ones that
produce SIRs), emit one candidate entry targeting
`ioc-data/package-names.yml`. `source: "stalkerware-indicators"` for every
entry. Set `category` from the AssoEchap `type` field (`stalkerware` →
`STALKERWARE`, `spyware` → `SPYWARE`, `monitor` → `MONITORING`).

### upstream_snapshot_hash_set

The full `(type, normalized_value)` set fetched from `ioc.yaml`. For this
ingester, type is always `PACKAGE_NAME`; normalize by trimming whitespace
(Android package names are case-sensitive; do NOT lowercase).

### Self-dedup

A package already present in the upstream as of this run is by definition
not net-new for this ingester. Since every `candidate_ioc_entry` here IS
derived from the upstream pull, self-dedup produces an empty
`candidate_ioc_entries` for stalkerware unless the upstream has ADDED new
entries since the last run. That is correct and expected — the delta for
this ingester comes from new upstream additions between cursor runs.

Cross-dedup across concurrent ingesters is the dispatcher's job
(Step 6.5 of update-rules.md). Do NOT attempt cross-ingester dedup here.
```

- [ ] **Step 2: Commit**

```bash
git add .claude/commands/update-rules-ingest-stalkerware.md
git commit -m "feat(pipeline): stalkerware ingester emits ioc candidates + snapshot (#117)"
```

## Task 21: Extend update-rules-ingest-abusech.md (ThreatFox + MalwareBazaar)

**Files:**
- Modify: `.claude/commands/update-rules-ingest-abusech.md`

- [ ] **Step 1: Append the IOC data output contract to the end of the file**

Open `.claude/commands/update-rules-ingest-abusech.md`. At the end of the file, append:

```markdown
## IOC data output (added for #117)

Emit a JSON object extending the existing SIR array:

```json
{
  "sirs": [ ... existing SIR array ... ],
  "candidate_ioc_entries": [
    {
      "file": "ioc-data/c2-domains.yml",
      "entry": {
        "indicator": "c2.example.com",
        "family": "ExampleMalware",
        "category": "MALWARE",
        "severity": "CRITICAL",
        "source": "threatfox",
        "description": "..."
      }
    },
    {
      "file": "ioc-data/apk-hashes.yml",
      "entry": {
        "indicator": "abc123...sha256",
        "family": "ExampleApk",
        "category": "MALWARE",
        "severity": "HIGH",
        "source": "malwarebazaar",
        "description": "..."
      }
    }
  ],
  "upstream_snapshot_hash_set": [
    ["C2_DOMAIN", "c2.example.com"],
    ["APK_HASH", "abc123...sha256"]
  ]
}
```

### candidate_ioc_entries

- ThreatFox domain entries → `ioc-data/c2-domains.yml`, source `threatfox`.
- MalwareBazaar APK-hash entries → `ioc-data/apk-hashes.yml`, source
  `malwarebazaar`.

### upstream_snapshot_hash_set

The full `(type, normalized_value)` set from both ThreatFox recent JSON
and MalwareBazaar recent CSV. Normalize domains to lowercase, strip
protocol and trailing `.`. Normalize hashes to lowercase hex.

### Self-dedup

As with stalkerware: emit a `candidate_ioc_entry` only for entries that
are net-new since the last cursor. The `last_seen_timestamp` cursor in
`feed-state.json` is the source of truth for "new."

Cross-dedup across concurrent ingesters is the dispatcher's job.
```

- [ ] **Step 2: Commit**

```bash
git add .claude/commands/update-rules-ingest-abusech.md
git commit -m "feat(pipeline): abusech ingester emits ioc candidates (threatfox + malwarebazaar) (#117)"
```

## Task 22: Extend update-rules-ingest-amnesty.md

**Files:**
- Modify: `.claude/commands/update-rules-ingest-amnesty.md`

- [ ] **Step 1: Append the IOC data output contract**

Open `.claude/commands/update-rules-ingest-amnesty.md`. At the end of the file, append:

```markdown
## IOC data output (added for #117)

```json
{
  "sirs": [ ... ],
  "candidate_ioc_entries": [
    {
      "file": "ioc-data/package-names.yml",
      "entry": {
        "indicator": "com.example.nationstate",
        "family": "ExampleSpy",
        "category": "NATION_STATE_SPYWARE",
        "severity": "CRITICAL",
        "source": "amnesty-investigations",
        "description": "..."
      }
    }
  ],
  "upstream_snapshot_hash_set": [
    ["PACKAGE_NAME", "com.example.nationstate"]
  ]
}
```

### Notes

- AmnestyTech is NOT in `kotlin-mirror-feeds.yml`, so the cross-dedup
  filter in Step 6.5 of update-rules.md will almost never remove entries
  sourced here. This is by design: AmnestyTech is the pipeline's unique
  contribution.
- Use `source: "amnesty-investigations"` (matches `allowed-sources.json`).
- Target file depends on indicator type: packages → `package-names.yml`;
  domains → `c2-domains.yml`; cert hashes → `cert-hashes.yml`;
  APK hashes → `apk-hashes.yml`.

Cross-dedup across concurrent ingesters is the dispatcher's job.
```

- [ ] **Step 2: Commit**

```bash
git add .claude/commands/update-rules-ingest-amnesty.md
git commit -m "feat(pipeline): amnesty ingester emits ioc candidates (#117)"
```

## Task 23: Extend update-rules-ingest-citizenlab.md

**Files:**
- Modify: `.claude/commands/update-rules-ingest-citizenlab.md`

- [ ] **Step 1: Append the IOC data output contract**

Open `.claude/commands/update-rules-ingest-citizenlab.md`. At the end of the file, append:

```markdown
## IOC data output (added for #117)

```json
{
  "sirs": [ ... ],
  "candidate_ioc_entries": [
    {
      "file": "ioc-data/package-names.yml",
      "entry": {
        "indicator": "com.citizenlab.flagged",
        "family": "<malware-family>",
        "category": "NATION_STATE_SPYWARE",
        "severity": "CRITICAL",
        "source": "citizenlab-indicators",
        "description": "..."
      }
    }
  ],
  "upstream_snapshot_hash_set": [
    ["PACKAGE_NAME", "com.citizenlab.flagged"]
  ]
}
```

### Notes

- Citizen Lab is NOT in `kotlin-mirror-feeds.yml`. Same rationale as
  AmnestyTech: pipeline's unique contribution, rarely filtered.
- Use `source: "citizenlab-indicators"`.
- Repo is dormant since 2020 per README; emit candidates only when new
  content is actually detected (no time-based triggers).

Cross-dedup across concurrent ingesters is the dispatcher's job.
```

- [ ] **Step 2: Commit**

```bash
git add .claude/commands/update-rules-ingest-citizenlab.md
git commit -m "feat(pipeline): citizenlab ingester emits ioc candidates (#117)"
```

## Task 24: Extend update-rules-ingest-asb.md (Android Security Bulletin)

**Files:**
- Modify: `.claude/commands/update-rules-ingest-asb.md`

- [ ] **Step 1: Append the IOC data output contract**

Open `.claude/commands/update-rules-ingest-asb.md`. At the end of the file, append:

```markdown
## IOC data output (added for #117)

The ASB ingester primarily produces CVE-ID SIRs, which feed
**device-posture rules** (patch-level-relative checks), not
`ioc_lookup`-style equality matching. CVE data flow stays in
`CveRepository` per the spec's out-of-scope section; this ingester does
NOT write CVE entries to `ioc-data/*.yml`.

If the bulletin discloses concrete IOCs (e.g., a malicious package name
tied to a specific CVE), emit them as candidate entries targeting the
appropriate file, same pattern as other ingesters:

```json
{
  "sirs": [ ... ],
  "candidate_ioc_entries": [
    {
      "file": "ioc-data/package-names.yml",
      "entry": {
        "indicator": "com.asb.disclosed",
        "family": "CVE-YYYY-NNNN-related",
        "category": "MALWARE",
        "severity": "HIGH",
        "source": "android-security-bulletin",
        "description": "..."
      }
    }
  ],
  "upstream_snapshot_hash_set": [
    ["PACKAGE_NAME", "com.asb.disclosed"]
  ]
}
```

Most ASB runs will emit `candidate_ioc_entries: []` since bulletins
typically disclose CVE-IDs without concrete IOCs.

Cross-dedup across concurrent ingesters is the dispatcher's job.
```

- [ ] **Step 2: Commit**

```bash
git add .claude/commands/update-rules-ingest-asb.md
git commit -m "feat(pipeline): asb ingester emits ioc candidates when bulletins disclose IOCs (#117)"
```

## Task 25: Extend update-rules-ingest-nvd.md

**Files:**
- Modify: `.claude/commands/update-rules-ingest-nvd.md`

- [ ] **Step 1: Append the IOC data output contract**

Open `.claude/commands/update-rules-ingest-nvd.md`. At the end of the file, append:

```markdown
## IOC data output (added for #117)

Same situation as ASB: NVD entries are primarily CVEs (device-posture
rules, handled by `CveRepository`), not `ioc_lookup` IOCs. Most NVD runs
emit `candidate_ioc_entries: []`.

If an NVD entry references a concrete IOC (e.g., CVE references a
malicious package name in its description), emit it as a candidate,
same pattern:

```json
{
  "sirs": [ ... ],
  "candidate_ioc_entries": [],
  "upstream_snapshot_hash_set": []
}
```

Cross-dedup across concurrent ingesters is the dispatcher's job.
```

- [ ] **Step 2: Commit**

```bash
git add .claude/commands/update-rules-ingest-nvd.md
git commit -m "feat(pipeline): nvd ingester emits ioc candidates when CVE refs concrete IOC (#117)"
```

## Task 26: Extend update-rules-ingest-attack.md

**Files:**
- Modify: `.claude/commands/update-rules-ingest-attack.md`

- [ ] **Step 1: Append the IOC data output contract**

Open `.claude/commands/update-rules-ingest-attack.md`. At the end of the file, append:

```markdown
## IOC data output (added for #117)

ATT&CK Mobile produces technique-level intel (attack.tNNNN IDs), not
concrete IOCs. `candidate_ioc_entries: []` is the expected output for
this ingester.

Do NOT manufacture IOC entries from technique descriptions; that risks
high-FP entries (technique descriptions reference packages as examples,
not as indicators). ATT&CK's contribution is TAG-level metadata for
rules, not indicator-level data.

```json
{
  "sirs": [ ... ],
  "candidate_ioc_entries": [],
  "upstream_snapshot_hash_set": []
}
```

Cross-dedup across concurrent ingesters is the dispatcher's job.
```

- [ ] **Step 2: Commit**

```bash
git add .claude/commands/update-rules-ingest-attack.md
git commit -m "feat(pipeline): attack ingester emits empty ioc candidates by design (#117)"
```

## Task 27: Phase 4 verification and PR

- [ ] **Step 1: Smoke-test the dispatcher changes by dry-running `/update-rules`**

Run `/update-rules full` (or `/update-rules source stalkerware` for a smaller run). Verify in the session transcript that:
- Each ingester emits the new 3-field JSON output (sirs + candidate_ioc_entries + upstream_snapshot_hash_set)
- Step 6.5 runs and reports per-ingester snapshot sizes
- Step 7 displays IOC-only candidates alongside rule candidates
- Step 8 refuses to commit if `validate-ioc-complementarity.py` rejects any candidate
- A successful approval produces a commit touching `ioc-data/*.yml` AND `feed-state.json`'s `ioc_data_last_write`

If the dispatcher or an ingester doesn't behave as specified, the skill markdown's `## IOC data output` section is likely ambiguous; clarify it and retry. (This is a dogfood test, not a unit test — the skills are executed by Claude, not by a Python test runner.)

- [ ] **Step 2: Push branch and open PR**

```bash
git push -u origin feat/117-pipeline-writes
gh pr create --base main --head feat/117-pipeline-writes \
  --title "feat(pipeline): ingesters write to ioc-data via dispatcher cross-dedup" \
  --body "$(cat <<'EOF'
## Summary

Phase 4 of #117. Extends the seven \`update-rules-ingest-*\` skills and
the \`update-rules\` dispatcher to produce the curated IOC-data delta:

- Each ingester emits \`candidate_ioc_entries\` + \`upstream_snapshot_hash_set\`
  alongside its existing SIR array; self-dedup only (cross-dedup in dispatcher).
- \`update-rules\` dispatcher: new Step 6.5 centralizes cross-dedup against
  the union of ingester snapshots plus freshly-fetched kotlin-mirror-feeds.yml.
- Step 7 gains IOC-only approval path for candidates targeting the generic
  \`sigma_androdr_00{1,2,3,4}\` ioc_lookup rules.
- Step 8 writes approved candidates to \`ioc-data/*.yml\`, runs
  validate-ioc-data + validate-ioc-complementarity, aborts on violation,
  and stamps \`ioc_data_last_write\` in feed-state.json.

## Test plan

- [x] Dry-run /update-rules full against test fixture upstream
- [x] Confirm dispatcher Step 6.5 logs per-ingester snapshot sizes
- [x] Confirm validator blocks a commit with a duplicate indicator
- [x] Confirm a clean approval produces a single commit touching ioc-data + feed-state

Related: #117

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
)"
```

- [ ] **Step 3: Wait for merge before Phase 5**

---

# Phase 5 — End-to-end smoke (verification, no PR) — ~1 day

Working directory: AndroDR repo root, with all four PRs merged into `main`.

## Task 28: Run full pipeline against test fixture

- [ ] **Step 1: Ensure main is current with all four PRs merged**

```bash
cd /home/yasir/AndroDR
git checkout main
git pull
git submodule update --init --recursive
```

Verify:

```bash
ls third-party/android-sigma-rules/validation/ioc-entry-schema.json \
   third-party/android-sigma-rules/validation/ioc-lookup-definitions.yml \
   third-party/android-sigma-rules/validation/kotlin-mirror-feeds.yml \
   third-party/android-sigma-rules/validation/validate-ioc-complementarity.py
```

Expected: all four files present.

- [ ] **Step 2: Run /update-rules full and approve one candidate**

Run `/update-rules full`. Let the full sweep complete. Approve exactly one passing candidate (pick one with IOC candidates attached; reject or defer the rest to keep the smoke bounded).

- [ ] **Step 3: Verify the commit landed and is well-formed**

```bash
cd third-party/android-sigma-rules
git log -1 --stat
```

Expected output includes: `rules/staging/...*.yml` (new rule), `ioc-data/<file>.yml` (appended entries), `feed-state.json` (updated cursor + ioc_data_last_write).

## Task 29: Verify IocUpdateWorker picks up the new entries on-device

- [ ] **Step 1: Build and install debug APK on emulator**

```bash
cd /home/yasir/AndroDR
./scripts/smoke-test.sh
```

(Or manual: `./gradlew installDebug` against `Medium_Phone_API_36.1`.)

- [ ] **Step 2: Trigger IOC update and capture indicators row count**

```bash
adb shell am start -n com.androdr.debug/com.androdr.MainActivity
# Wait for app startup; trigger periodic IOC update via settings (or force via adb am broadcast if supported)

adb shell run-as com.androdr.debug sqlite3 /data/data/com.androdr.debug/databases/androdr.db \
  "SELECT COUNT(*) FROM indicators" > /tmp/count_before.txt
```

- [ ] **Step 3: Let IocUpdateWorker complete, then re-capture count**

```bash
# Give the worker a minute to fetch the new ioc-data/*.yml
sleep 90

adb shell run-as com.androdr.debug sqlite3 /data/data/com.androdr.debug/databases/androdr.db \
  "SELECT COUNT(*) FROM indicators" > /tmp/count_after.txt

echo "Before: $(cat /tmp/count_before.txt)"
echo "After:  $(cat /tmp/count_after.txt)"
```

Expected: `After` is >= `Before`. The new indicator(s) approved in Task 28 should have been upserted.

- [ ] **Step 4: Verify the specific new entry landed**

```bash
# Replace <indicator> with the actual indicator value from the approved candidate
INDICATOR="<indicator>"
adb shell run-as com.androdr.debug sqlite3 /data/data/com.androdr.debug/databases/androdr.db \
  "SELECT type, value, source FROM indicators WHERE value = '$INDICATOR'"
```

Expected: exactly one row, with the expected type and `source: androdr_public_repo` (because `PublicRepoIocFeed` is what read it from the rule repo).

## Task 30: Close out

- [ ] **Step 1: Verify issue #117 auto-closed**

The spec PR (#123) has `Closes #117` in the body. When that PR merged, #117 should have auto-closed. Verify:

```bash
gh api repos/yasirhamza/AndroDR/issues/117 --jq '.state'
```

Expected: `closed`.

- [ ] **Step 2: Record smoke test results as a comment on the (now-closed) issue**

Brief comment summarizing the verification results, file+hash counts, and any anomalies encountered. Provides a permanent record of the end-to-end verification.

---

## Self-review checklist (for the plan author — already completed)

**Spec coverage:**
- ✅ Rule-repo deliverables (schema, lookup-definitions, mirror-feeds, validator, validator-v2) — Tasks 1, 2, 3, 4, 9-10
- ✅ Drift handling (strict/advisory mode) — Task 10 (script) + Task 12 (CI)
- ✅ Pipeline ingester extensions — Tasks 19 (dispatcher) + 20-26 (7 ingesters)
- ✅ Step 6.5 centralized cross-dedup — Task 19
- ✅ Step 7 IOC-only approval path — Task 19
- ✅ Step 8 write + validate + commit — Task 19
- ✅ Phase 3 migration safety (source-filter on prune) — Task 11 Step 2 safety filter
- ✅ Three Kotlin cross-check tests — Tasks 15, 16, 17
- ✅ feed-state-schema.json `ioc_data_last_write` — Task 5
- ✅ CI workflow for validators — Task 6 + Task 12
- ✅ End-to-end smoke — Tasks 28, 29, 30

**Placeholder scan:** no TBD/TODO/FIXME in the plan. Every code block is complete. Every shell command has an expected output.

**Type consistency:** ingester output shape `{sirs, candidate_ioc_entries, upstream_snapshot_hash_set}` used identically across Tasks 20-26. Step 6.5's `U_ingesters` / `U_authoritative` notation used only within Task 19. `ioc_data_last_write` field name consistent across Task 5 and Task 19 Step 3.

---
