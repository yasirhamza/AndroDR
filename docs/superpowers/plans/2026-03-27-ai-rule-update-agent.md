# AI-Powered SIGMA Rule Update Agent Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a Claude Code agent workflow that ingests threat intel from 7+ feeds, generates validated SIGMA rules, and presents them for human review in a staging pipeline.

**Architecture:** A dispatcher skill (`/update-rules`) orchestrates specialized sub-agents: feed ingesters produce Structured Intelligence Records (SIRs), a Rule Author generates SIGMA YAML, and a Validator runs five gates (schema, IOC verification, dedup, dry-run, LLM self-review). All output lands in `rules/staging/` of the public sigma repo.

**Tech Stack:** Claude Code skills (markdown prompt files), Python validation scripts, AndroDR's existing SigmaRuleParser/Evaluator (Kotlin/JUnit) for dry-run testing, YAML/JSON for data contracts.

**Spec:** `docs/superpowers/specs/2026-03-27-ai-rule-update-agent-design.md`

---

## File Structure

### Claude Code Skills (`.claude/commands/`)

| File | Responsibility |
|------|---------------|
| `.claude/commands/update-rules.md` | Dispatcher — parses invocation mode, reads state, orchestrates sub-agents, presents results |
| `.claude/commands/update-rules-ingest-abusech.md` | Feed ingester for ThreatFox, MalwareBazaar, URLhaus |
| `.claude/commands/update-rules-ingest-asb.md` | Feed ingester for Android Security Bulletins |
| `.claude/commands/update-rules-ingest-nvd.md` | Feed ingester for NVD/NIST CVE database |
| `.claude/commands/update-rules-ingest-amnesty.md` | Feed ingester for AmnestyTech/investigations GitHub |
| `.claude/commands/update-rules-ingest-citizenlab.md` | Feed ingester for Citizen Lab malware-indicators |
| `.claude/commands/update-rules-ingest-stalkerware.md` | Feed ingester for stalkerware-indicators GitHub |
| `.claude/commands/update-rules-ingest-attack.md` | Feed ingester for MITRE ATT&CK Mobile STIX data |
| `.claude/commands/update-rules-research-threat.md` | Threat researcher — web search for named threats |
| `.claude/commands/update-rules-author.md` | Rule Author — generates SIGMA YAML from SIRs |
| `.claude/commands/update-rules-validate.md` | Validator — runs 5-gate pipeline on candidate rules |
| `.claude/commands/update-rules-review.md` | LLM Self-Review (Gate 5) — reviews rule for logic/FP/severity |

### Validation & Schema (in public sigma repo)

| File | Responsibility |
|------|---------------|
| `validation/sir-schema.json` | JSON Schema for Structured Intelligence Records |
| `validation/rule-schema.json` | JSON Schema for AndroDR SIGMA rules (Gate 1) |
| `validation/android-permissions.txt` | Valid Android permission names (Gate 2) |
| `validation/validate-rule.py` | Python script: schema validation + field name checks |
| `validation/test-fixtures/benign-app.json` | Synthetic benign app telemetry for Gate 4 |
| `validation/test-fixtures/benign-device.json` | Synthetic benign device telemetry for Gate 4 |

### Repo Scaffolding (public sigma repo)

| File | Responsibility |
|------|---------------|
| `rules/production/app_risk/.gitkeep` | Directory structure |
| `rules/production/device_posture/.gitkeep` | Directory structure |
| `rules/production/network/.gitkeep` | Directory structure |
| `rules/production/process/.gitkeep` | Directory structure |
| `rules/production/file/.gitkeep` | Directory structure |
| `rules/staging/app_risk/.gitkeep` | Directory structure |
| `rules/staging/device_posture/.gitkeep` | Directory structure |
| `rules/staging/network/.gitkeep` | Directory structure |
| `rules/staging/process/.gitkeep` | Directory structure |
| `rules/staging/file/.gitkeep` | Directory structure |
| `ioc-data/package-names.yml` | Known-bad package names |
| `ioc-data/cert-hashes.yml` | Known-bad signing certificates |
| `ioc-data/c2-domains.yml` | Known C2 domains |
| `ioc-data/malware-hashes.yml` | Known malware file hashes |
| `feed-state.json` | Feed cursor manifest |
| `rules.txt` | Updated manifest pointing to `rules/production/` paths |
| `docs/rule-format.md` | Rule authoring guide |
| `docs/logsource-taxonomy.md` | AndroDR logsource field definitions |

### AndroDR App Changes

| File | Responsibility |
|------|---------------|
| `app/src/main/java/com/androdr/sigma/SigmaRuleFeed.kt` | Minor update: support `rules/production/` prefix in manifest paths |

---

## Task Breakdown

### Task 1: Public Sigma Repo Scaffolding

**Files:**
- Create: `rules/production/{app_risk,device_posture,network,process,file}/.gitkeep`
- Create: `rules/staging/{app_risk,device_posture,network,process,file}/.gitkeep`
- Create: `ioc-data/package-names.yml`
- Create: `ioc-data/cert-hashes.yml`
- Create: `ioc-data/c2-domains.yml`
- Create: `ioc-data/malware-hashes.yml`
- Create: `feed-state.json`
- Create: `rules.txt`

**Context:** This task targets the public `android-sigma-rules` repo (not the AndroDR repo). If the repo doesn't exist yet locally, clone it or create it first. All paths in this task are relative to that repo root.

- [ ] **Step 1: Create directory structure**

```bash
mkdir -p rules/production/{app_risk,device_posture,network,process,file}
mkdir -p rules/staging/{app_risk,device_posture,network,process,file}
mkdir -p ioc-data
mkdir -p validation/test-fixtures
mkdir -p docs
touch rules/production/app_risk/.gitkeep
touch rules/production/device_posture/.gitkeep
touch rules/production/network/.gitkeep
touch rules/production/process/.gitkeep
touch rules/production/file/.gitkeep
touch rules/staging/app_risk/.gitkeep
touch rules/staging/device_posture/.gitkeep
touch rules/staging/network/.gitkeep
touch rules/staging/process/.gitkeep
touch rules/staging/file/.gitkeep
```

- [ ] **Step 2: Create IOC data files**

Create `ioc-data/package-names.yml`:
```yaml
version: "2026-03-27"
description: "Known malicious Android package names"
sources: []
entries: []
```

Create `ioc-data/cert-hashes.yml`:
```yaml
version: "2026-03-27"
description: "Known malicious APK signing certificate hashes"
sources: []
entries: []
```

Create `ioc-data/c2-domains.yml`:
```yaml
version: "2026-03-27"
description: "Known command-and-control domains for Android malware"
sources: []
entries: []
```

Create `ioc-data/malware-hashes.yml`:
```yaml
version: "2026-03-27"
description: "Known malicious APK file hashes (SHA-256)"
sources: []
entries: []
```

- [ ] **Step 3: Create feed-state.json**

Create `feed-state.json`:
```json
{
  "version": 1,
  "last_full_sweep": null,
  "feeds": {
    "threatfox": {
      "last_query_time": null,
      "last_id": null
    },
    "malwarebazaar": {
      "last_query_time": null
    },
    "urlhaus": {
      "last_query_time": null
    },
    "asb": {
      "last_bulletin": null
    },
    "nvd": {
      "last_modified": null
    },
    "stalkerware_indicators": {
      "last_commit_sha": null
    },
    "attack_mobile": {
      "last_version": null
    }
  }
}
```

- [ ] **Step 4: Create rules.txt manifest**

Create `rules.txt` (empty — will be populated as rules are promoted to production):
```
# AndroDR SIGMA Rules Manifest
# Each line is a path relative to the repo root
# SigmaRuleFeed fetches each .yml file listed here
```

- [ ] **Step 5: Commit scaffolding**

```bash
git add -A
git commit -m "chore: scaffold repo structure for AI rule update pipeline

Directories: rules/production/, rules/staging/, ioc-data/, validation/, docs/
Files: feed-state.json, rules.txt, empty IOC data files"
```

---

### Task 2: Validation Schemas & Scripts

**Files:**
- Create: `validation/sir-schema.json`
- Create: `validation/rule-schema.json`
- Create: `validation/android-permissions.txt`
- Create: `validation/validate-rule.py`
- Create: `validation/test-fixtures/benign-app.json`
- Create: `validation/test-fixtures/benign-device.json`

**Context:** Still in the public `android-sigma-rules` repo. These files support the Validator agent (Gates 1-4).

- [ ] **Step 1: Create SIR JSON Schema**

Create `validation/sir-schema.json`:
```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "Structured Intelligence Record (SIR)",
  "type": "object",
  "required": ["source", "threat", "indicators", "confidence", "rule_hint"],
  "properties": {
    "source": {
      "type": "object",
      "required": ["feed", "url", "retrieved_at"],
      "properties": {
        "feed": { "type": "string" },
        "url": { "type": "string", "format": "uri" },
        "retrieved_at": { "type": "string", "format": "date-time" }
      }
    },
    "threat": {
      "type": "object",
      "required": ["name"],
      "properties": {
        "name": { "type": "string" },
        "families": { "type": "array", "items": { "type": "string" }, "default": [] },
        "description": { "type": "string", "default": "" }
      }
    },
    "attack_techniques": {
      "type": "array",
      "items": {
        "type": "object",
        "required": ["id", "name"],
        "properties": {
          "id": { "type": "string", "pattern": "^T\\d{4}(\\.\\d{3})?$" },
          "name": { "type": "string" }
        }
      },
      "default": []
    },
    "indicators": {
      "type": "object",
      "properties": {
        "package_names": { "type": "array", "items": { "type": "string" }, "default": [] },
        "cert_hashes": { "type": "array", "items": { "type": "string" }, "default": [] },
        "domains": { "type": "array", "items": { "type": "string" }, "default": [] },
        "file_hashes": { "type": "array", "items": { "type": "string" }, "default": [] },
        "urls": { "type": "array", "items": { "type": "string" }, "default": [] },
        "ips": { "type": "array", "items": { "type": "string" }, "default": [] }
      }
    },
    "vulnerabilities": {
      "type": "array",
      "items": {
        "type": "object",
        "required": ["id"],
        "properties": {
          "id": { "type": "string", "pattern": "^CVE-\\d{4}-\\d+$" },
          "cvss": { "type": "number" },
          "affected_versions": { "type": "array", "items": { "type": "string" } }
        }
      },
      "default": []
    },
    "behavioral_signals": {
      "type": "array",
      "items": {
        "type": "object",
        "required": ["type"],
        "properties": {
          "type": { "type": "string" },
          "permissions": { "type": "array", "items": { "type": "string" } },
          "description": { "type": "string" }
        }
      },
      "default": []
    },
    "confidence": { "type": "string", "enum": ["high", "medium", "low", "none"] },
    "rule_hint": { "type": "string", "enum": ["ioc_lookup", "behavioral", "device_posture", "network", "hybrid"] }
  }
}
```

- [ ] **Step 2: Create rule JSON Schema (Gate 1)**

Create `validation/rule-schema.json`:
```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "AndroDR SIGMA Rule",
  "type": "object",
  "required": ["title", "id", "status", "description", "logsource", "detection", "level", "tags"],
  "properties": {
    "title": { "type": "string", "minLength": 1 },
    "id": { "type": "string", "pattern": "^androdr-\\d{3}$" },
    "status": { "type": "string", "enum": ["experimental", "test", "production"] },
    "description": { "type": "string" },
    "author": { "type": "string" },
    "date": { "type": "string" },
    "logsource": {
      "type": "object",
      "required": ["product", "service"],
      "properties": {
        "product": { "const": "androdr" },
        "service": {
          "type": "string",
          "enum": ["app_scanner", "device_auditor", "dns_monitor", "process_monitor", "file_scanner"]
        }
      }
    },
    "detection": {
      "type": "object",
      "required": ["condition"],
      "properties": {
        "condition": { "type": "string", "minLength": 1 }
      }
    },
    "level": { "type": "string", "enum": ["critical", "high", "medium", "low"] },
    "tags": {
      "type": "array",
      "items": { "type": "string" }
    },
    "falsepositives": { "type": "array", "items": { "type": "string" } },
    "remediation": { "type": "array", "items": { "type": "string" } },
    "display": {
      "type": "object",
      "properties": {
        "category": { "type": "string", "enum": ["app_risk", "device_posture", "network"] },
        "icon": { "type": "string" },
        "triggered_title": { "type": "string" },
        "safe_title": { "type": "string" },
        "evidence_type": { "type": "string", "enum": ["none", "cve_list", "ioc_match", "permission_cluster"] },
        "summary_template": { "type": "string" }
      }
    }
  }
}
```

- [ ] **Step 3: Create Android permissions list**

Create `validation/android-permissions.txt` with all standard Android permissions. This file is used by Gate 2 to validate permission names in behavioral rules.

```bash
# Generate from Android SDK docs — the most commonly used permissions
# This is a curated subset; add more as needed
cat > validation/android-permissions.txt << 'PERMS'
ACCESS_COARSE_LOCATION
ACCESS_FINE_LOCATION
ACCESS_BACKGROUND_LOCATION
ACCESS_NETWORK_STATE
ACCESS_WIFI_STATE
BLUETOOTH
BLUETOOTH_ADMIN
BLUETOOTH_CONNECT
BLUETOOTH_SCAN
BODY_SENSORS
CALL_PHONE
CAMERA
GET_ACCOUNTS
INSTALL_PACKAGES
INTERNET
MANAGE_EXTERNAL_STORAGE
NFC
POST_NOTIFICATIONS
PROCESS_OUTGOING_CALLS
READ_CALENDAR
READ_CALL_LOG
READ_CONTACTS
READ_EXTERNAL_STORAGE
READ_MEDIA_AUDIO
READ_MEDIA_IMAGES
READ_MEDIA_VIDEO
READ_PHONE_NUMBERS
READ_PHONE_STATE
READ_SMS
RECEIVE_MMS
RECEIVE_SMS
RECEIVE_WAP_PUSH
RECORD_AUDIO
REQUEST_INSTALL_PACKAGES
SEND_SMS
SYSTEM_ALERT_WINDOW
USE_BIOMETRIC
USE_FINGERPRINT
VIBRATE
WRITE_CALENDAR
WRITE_CALL_LOG
WRITE_CONTACTS
WRITE_EXTERNAL_STORAGE
WRITE_SETTINGS
BIND_ACCESSIBILITY_SERVICE
BIND_DEVICE_ADMIN
BIND_NOTIFICATION_LISTENER_SERVICE
BIND_VPN_SERVICE
FOREGROUND_SERVICE
QUERY_ALL_PACKAGES
REQUEST_DELETE_PACKAGES
SCHEDULE_EXACT_ALARM
USE_EXACT_ALARM
PERMS
```

- [ ] **Step 4: Create validation script (Gate 1 + field checks)**

Create `validation/validate-rule.py`:
```python
#!/usr/bin/env python3
"""Validate an AndroDR SIGMA rule YAML file against the rule schema.

Usage: python validate-rule.py <rule.yml> [--schema rule-schema.json]

Exit codes:
  0 = valid
  1 = validation errors (printed to stderr)
  2 = file not found / parse error
"""

import json
import sys
from pathlib import Path

try:
    import yaml
except ImportError:
    sys.exit("pyyaml required: pip install pyyaml")

SCRIPT_DIR = Path(__file__).parent
VALID_MODIFIERS = {
    "contains", "startswith", "endswith", "re",
    "gte", "lte", "gt", "lt", "ioc_lookup",
}
MAX_REGEX_LENGTH = 500


def load_schema(schema_path: Path) -> dict:
    with open(schema_path) as f:
        return json.load(f)


def load_permissions(perms_path: Path) -> set[str]:
    with open(perms_path) as f:
        return {line.strip() for line in f if line.strip() and not line.startswith("#")}


def validate_rule(rule: dict, schema: dict, permissions: set[str]) -> list[str]:
    """Return list of error strings. Empty list means valid."""
    errors = []

    # Required fields
    for field in schema.get("required", []):
        if field not in rule:
            errors.append(f"Missing required field: {field}")

    if "id" in rule:
        rule_id = rule["id"]
        if not isinstance(rule_id, str) or not rule_id.startswith("androdr-"):
            errors.append(f"Rule ID must match 'androdr-NNN', got: {rule_id}")

    if "status" in rule and rule["status"] not in ("experimental", "test", "production"):
        errors.append(f"Invalid status: {rule['status']}")

    if "level" in rule and rule["level"] not in ("critical", "high", "medium", "low"):
        errors.append(f"Invalid level: {rule['level']}")

    # Logsource
    logsource = rule.get("logsource", {})
    if logsource.get("product") != "androdr":
        errors.append(f"logsource.product must be 'androdr', got: {logsource.get('product')}")
    valid_services = {"app_scanner", "device_auditor", "dns_monitor", "process_monitor", "file_scanner"}
    if logsource.get("service") not in valid_services:
        errors.append(f"Invalid logsource.service: {logsource.get('service')}")

    # Detection — check condition references and modifiers
    detection = rule.get("detection", {})
    condition = detection.get("condition", "")
    selection_names = {k for k in detection if k != "condition"}

    for token in condition.replace("(", " ").replace(")", " ").split():
        if token.lower() not in ("and", "or", "not") and token not in selection_names:
            errors.append(f"Condition references undefined selection: {token}")

    for sel_name, sel_value in detection.items():
        if sel_name == "condition" or not isinstance(sel_value, dict):
            continue
        for field_key in sel_value:
            if "|" in field_key:
                _, modifier = field_key.rsplit("|", 1)
                if modifier not in VALID_MODIFIERS:
                    errors.append(f"Invalid modifier '{modifier}' in field '{field_key}'")
                if modifier == "re":
                    values = sel_value[field_key]
                    if isinstance(values, list):
                        for v in values:
                            if isinstance(v, str) and len(v) > MAX_REGEX_LENGTH:
                                errors.append(f"Regex pattern exceeds {MAX_REGEX_LENGTH} chars in '{field_key}'")
                    elif isinstance(values, str) and len(values) > MAX_REGEX_LENGTH:
                        errors.append(f"Regex pattern exceeds {MAX_REGEX_LENGTH} chars in '{field_key}'")

    # Display block
    display = rule.get("display", {})
    if display:
        valid_categories = {"app_risk", "device_posture", "network"}
        if "category" in display and display["category"] not in valid_categories:
            errors.append(f"Invalid display.category: {display['category']}")
        valid_evidence = {"none", "cve_list", "ioc_match", "permission_cluster"}
        if "evidence_type" in display and display["evidence_type"] not in valid_evidence:
            errors.append(f"Invalid display.evidence_type: {display['evidence_type']}")

    # Tags — check ATT&CK format
    for tag in rule.get("tags", []):
        if tag.startswith("attack.t") or tag.startswith("attack.T"):
            tid = tag.replace("attack.", "").upper()
            # Basic format check: TNNNN or TNNNN.NNN
            parts = tid.split(".")
            if not (len(parts) in (1, 2) and parts[0][0] == "T" and parts[0][1:].isdigit()):
                errors.append(f"Invalid ATT&CK tag format: {tag}")

    return errors


def main():
    if len(sys.argv) < 2:
        print("Usage: python validate-rule.py <rule.yml>", file=sys.stderr)
        sys.exit(2)

    rule_path = Path(sys.argv[1])
    if not rule_path.exists():
        print(f"File not found: {rule_path}", file=sys.stderr)
        sys.exit(2)

    schema_path = SCRIPT_DIR / "rule-schema.json"
    perms_path = SCRIPT_DIR / "android-permissions.txt"

    schema = load_schema(schema_path)
    permissions = load_permissions(perms_path) if perms_path.exists() else set()

    with open(rule_path) as f:
        try:
            rule = yaml.safe_load(f)
        except yaml.YAMLError as e:
            print(f"YAML parse error: {e}", file=sys.stderr)
            sys.exit(2)

    errors = validate_rule(rule, schema, permissions)

    if errors:
        print(f"FAIL: {rule_path.name} — {len(errors)} error(s):", file=sys.stderr)
        for err in errors:
            print(f"  - {err}", file=sys.stderr)
        sys.exit(1)
    else:
        print(f"PASS: {rule_path.name}")
        sys.exit(0)


if __name__ == "__main__":
    main()
```

- [ ] **Step 5: Create synthetic test fixtures for Gate 4**

Create `validation/test-fixtures/benign-app.json`:
```json
{
  "package_name": "com.google.android.gm",
  "app_name": "Gmail",
  "cert_hash": "sha256:f0fd6c5b410f25cb25c3b53346c8972fae30f8ee7411df910480ad6b2d60db83",
  "is_system_app": false,
  "from_trusted_store": true,
  "is_known_oem_app": false,
  "has_accessibility_service": false,
  "has_device_admin": false,
  "surveillance_permission_count": 0,
  "permissions": ["INTERNET", "READ_CONTACTS", "GET_ACCOUNTS"]
}
```

Create `validation/test-fixtures/benign-device.json`:
```json
{
  "adb_enabled": false,
  "dev_options_enabled": false,
  "unknown_sources_enabled": false,
  "screen_lock_enabled": true,
  "patch_level": "2026-03-01",
  "patch_age_days": 27,
  "bootloader_unlocked": false,
  "wifi_adb_enabled": false
}
```

- [ ] **Step 6: Test the validation script**

Run against an existing bundled rule (copy one into the repo temporarily):
```bash
python3 validation/validate-rule.py /path/to/test-rule.yml
```
Expected: PASS (if rule is valid) or specific error messages.

- [ ] **Step 7: Commit validation tooling**

```bash
git add validation/
git commit -m "feat: add validation schemas, scripts, and test fixtures

SIR and rule JSON schemas, Android permissions list, Python validation
script (Gate 1), and synthetic telemetry fixtures for dry-run testing (Gate 4)."
```

---

### Task 3: Documentation — Rule Format & Logsource Taxonomy

**Files:**
- Create: `docs/rule-format.md`
- Create: `docs/logsource-taxonomy.md`

**Context:** Public sigma repo. These docs are referenced by the Rule Author agent for style consistency, and by future community contributors.

- [ ] **Step 1: Write rule format guide**

Create `docs/rule-format.md`:
```markdown
# AndroDR SIGMA Rule Format

AndroDR detection rules follow the [SIGMA rule specification](https://github.com/SigmaHQ/sigma-specification)
with Android-specific logsource definitions and an extended `display` block
for mobile UI rendering.

## Required Fields

| Field | Type | Description |
|-------|------|-------------|
| `title` | string | Human-readable rule name |
| `id` | string | Unique identifier: `androdr-NNN` (zero-padded 3 digits) |
| `status` | string | `experimental`, `test`, or `production` |
| `description` | string | What the rule detects and why it matters |
| `logsource` | object | Must have `product: androdr` and a valid `service` |
| `detection` | object | Named selections + condition expression |
| `level` | string | `critical`, `high`, `medium`, or `low` |
| `tags` | list | MITRE ATT&CK Mobile technique IDs (e.g., `attack.t1417.001`) |

## Optional Fields

| Field | Type | Description |
|-------|------|-------------|
| `author` | string | Rule author name |
| `date` | string | Creation date (`YYYY/MM/DD`) |
| `falsepositives` | list | Known scenarios that trigger false matches |
| `remediation` | list | Actionable steps for the user (supports `{variable}` templates) |
| `display` | object | UI rendering hints (see below) |

## Display Block

```yaml
display:
  category: app_risk          # app_risk | device_posture | network
  icon: warning               # Material icon hint
  triggered_title: "Title"    # Shown when rule matches (supports {variables})
  safe_title: "Safe Title"    # Shown when rule does NOT match (device_posture only)
  evidence_type: ioc_match    # none | cve_list | ioc_match | permission_cluster
  summary_template: "..."     # Detail text (supports {variables})
```

## Detection Modifiers

Field names can include a pipe-separated modifier:

| Modifier | Behavior | Example |
|----------|----------|---------|
| (none) | Exact match (case-insensitive for strings) | `adb_enabled: true` |
| `contains` | Substring match (case-insensitive) | `package_name\|contains: "malware"` |
| `startswith` | Prefix match (case-insensitive) | `package_name\|startswith: "com.fake"` |
| `endswith` | Suffix match (case-insensitive) | `package_name\|endswith: ".spy"` |
| `re` | Regex match (max 500 chars, 1s timeout) | `package_name\|re: "com\\.fake\\..*"` |
| `gte` | Greater than or equal (numeric) | `patch_age_days\|gte: 90` |
| `lte` | Less than or equal (numeric) | `surveillance_permission_count\|lte: 1` |
| `gt` | Greater than (numeric) | `patch_age_days\|gt: 180` |
| `lt` | Less than (numeric) | `patch_age_days\|lt: 30` |
| `ioc_lookup` | Delegates to named IOC database | `package_name\|ioc_lookup: package_ioc_db` |

## Condition Expressions

- Single selection: `condition: selection`
- AND: `condition: sel_permissions and sel_sideloaded`
- OR: `condition: sel_package or sel_cert`
- Left-to-right precedence: `a and b or c` means `(a AND b) OR c`

## Severity Levels

| Level | Use When |
|-------|----------|
| `critical` | Active exploitation, known spyware, 0-click compromise |
| `high` | Significant risk requiring action (banking trojan, stalkerware, unpatched critical CVE) |
| `medium` | Elevated risk worth investigating (sideloaded app, outdated patch) |
| `low` | Informational or low-confidence signal |

## Example Rule

```yaml
title: App installed from untrusted source
id: androdr-010
status: production
description: Detects apps not installed from Google Play or other trusted stores
author: AndroDR
date: 2026/03/25
logsource:
    product: androdr
    service: app_scanner
detection:
    selection:
        is_system_app: false
        from_trusted_store: false
        is_known_oem_app: false
    condition: selection
level: medium
tags:
    - attack.t1474.001
display:
    category: app_risk
    icon: download
    triggered_title: "Sideloaded Application"
    evidence_type: none
falsepositives:
    - "Apps installed via ADB for development"
    - "F-Droid or other alternative stores"
remediation:
    - "Verify you intended to install this app from outside a trusted store."
```
```

- [ ] **Step 2: Write logsource taxonomy**

Create `docs/logsource-taxonomy.md`:
```markdown
# AndroDR Logsource Taxonomy

All rules use `product: androdr`. The `service` field determines which
telemetry source the rule evaluates against.

## Services

### `app_scanner`

Evaluates per-app telemetry for each installed application.

| Field | Type | Description |
|-------|------|-------------|
| `package_name` | string | Android package name (e.g., `com.example.app`) |
| `app_name` | string | User-visible app label |
| `cert_hash` | string | SHA-256 hash of APK signing certificate |
| `is_system_app` | boolean | Pre-installed system app |
| `from_trusted_store` | boolean | Installed from Google Play or other trusted store |
| `is_known_oem_app` | boolean | Recognized OEM/carrier app |
| `has_accessibility_service` | boolean | Declares an accessibility service |
| `has_device_admin` | boolean | Requests device administrator privileges |
| `surveillance_permission_count` | integer | Count of surveillance-category permissions |
| `permissions` | list | Declared Android permissions |

### `device_auditor`

Evaluates device-wide security posture. Rules emit both triggered (match)
and safe (no match) findings for binary state display.

| Field | Type | Description |
|-------|------|-------------|
| `adb_enabled` | boolean | USB debugging enabled |
| `dev_options_enabled` | boolean | Developer options enabled |
| `unknown_sources_enabled` | boolean | Install from unknown sources allowed |
| `screen_lock_enabled` | boolean | Screen lock configured |
| `patch_level` | string | Android security patch level (YYYY-MM-DD) |
| `patch_age_days` | integer | Days since last security patch |
| `bootloader_unlocked` | boolean | Bootloader is unlocked |
| `wifi_adb_enabled` | boolean | Wireless ADB debugging enabled |
| `unpatched_cve_id` | string | CVE IDs of unpatched vulnerabilities (for contains matching) |
| `unpatched_cves` | list | Structured CVE objects (for evidence providers) |

### `dns_monitor`

Evaluates DNS queries intercepted by the local VPN service.

| Field | Type | Description |
|-------|------|-------------|
| `query_domain` | string | Queried domain name |
| `source_package` | string | Package name of the app making the query |
| `query_type` | string | DNS record type (A, AAAA, CNAME, etc.) |

### `process_monitor`

Evaluates running process telemetry.

| Field | Type | Description |
|-------|------|-------------|
| `process_name` | string | Process name |
| `package_name` | string | Associated package name |
| `uid` | integer | Unix user ID |

### `file_scanner`

Evaluates file system artifact telemetry.

| Field | Type | Description |
|-------|------|-------------|
| `file_path` | string | Absolute file path |
| `file_hash` | string | SHA-256 hash of file contents |
| `file_size` | integer | File size in bytes |
```
```

- [ ] **Step 3: Commit documentation**

```bash
git add docs/
git commit -m "docs: add rule format guide and logsource taxonomy

Rule format covers all fields, modifiers, severity levels, and examples.
Logsource taxonomy defines all fields per service for rule authors."
```

---

### Task 4: Dispatcher Skill — `/update-rules`

**Files:**
- Create: `.claude/commands/update-rules.md` (in AndroDR repo)

**Context:** Back in the AndroDR repo. This is the main entry point skill that the user invokes. It parses the invocation mode, reads state, orchestrates sub-agents, and presents results.

- [ ] **Step 1: Create the dispatcher skill**

Create `.claude/commands/update-rules.md`:
```markdown
---
description: "AI-powered SIGMA rule update — ingest threat intel, generate rules, validate, and review"
---

# Update Rules Dispatcher

You are the dispatcher for the AndroDR AI-powered SIGMA rule update pipeline. You orchestrate feed ingesters, the rule author, and the validator to produce candidate detection rules for human review.

## Parse Invocation

The user invokes one of three modes:
- `/update-rules full` — check all feeds for new threat intel
- `/update-rules source <id>` — check one feed (valid IDs: `abusech`, `asb`, `nvd`, `amnesty`, `citizenlab`, `stalkerware`, `attack`)
- `/update-rules threat "<name>"` — research a specific threat by name

If no argument is given, ask which mode to use.

## Step 1: Read State

1. Read `feed-state.json` from the public sigma repo to get feed cursors
2. Glob `rules/production/**/*.yml` and `rules/staging/**/*.yml` to build an index of existing rules (IDs, titles, IOCs referenced)
3. Determine the next available rule ID by finding the highest `androdr-NNN` across all existing rules and incrementing

The public sigma repo path: check if `../android-sigma-rules/` exists relative to the AndroDR repo. If not, ask the user where it is.

## Step 2: Dispatch Ingesters

Based on the invocation mode:

**Full sweep:** Spawn all feed ingester agents in parallel using the Agent tool:
- `update-rules-ingest-abusech` with cursor from feed-state.json
- `update-rules-ingest-asb` with cursor from feed-state.json
- `update-rules-ingest-nvd` with cursor from feed-state.json
- `update-rules-ingest-amnesty` with existing rule index
- `update-rules-ingest-citizenlab` with existing rule index
- `update-rules-ingest-stalkerware` with cursor from feed-state.json
- `update-rules-ingest-attack` with cursor from feed-state.json

**Source-focused:** Spawn only the named ingester agent.

**Threat-focused:** Spawn `update-rules-research-threat` with the threat name.

Each ingester returns a JSON array of SIR objects (or an empty array if nothing new).

## Step 3: Triage SIRs

Collect all SIRs from ingesters. If none returned data, report "No new threat intelligence found" with per-feed status and stop.

For each SIR:
- Log the source, threat name, confidence, and indicator counts
- Skip SIRs with `confidence: "none"` (ingester errors) — report them as feed failures

## Step 4: Generate Rules

Pass all valid SIRs to the Rule Author agent (`update-rules-author`) along with:
- The next available rule ID
- 5 existing production rules as style examples (pick diverse services/types)
- The existing rule index (for dedup awareness)

The Rule Author returns a list of CandidateRule objects (YAML + decision manifest).

## Step 5: Validate Rules

For each CandidateRule, spawn a Validator agent (`update-rules-validate`) with:
- The candidate rule YAML
- The source SIR(s) that informed it
- The existing rule index
- Path to the validation directory in the sigma repo

Validators can run in parallel (one per candidate rule).

Each returns a ValidationResult (pass/fail per gate).

## Step 6: Handle Retries

For any rule that failed validation:
1. Send the failure details back to the Rule Author agent with the specific error
2. The Rule Author attempts a fix and returns an updated CandidateRule
3. Run the Validator again on the updated candidate
4. If it fails a second time, mark it as a failed candidate

## Step 7: Present Results

Format the output as follows:

For each **passing** candidate:
```
CANDIDATE: androdr-NNN — [title]
Source:      [feed name], retrieved [date]
Service:     [service]
Level:       [level]
ATT&CK:      [technique IDs]
IOCs:        [counts by type]
Validation:  [gate results: checkmark or X per gate]

FLAGGED DECISIONS: (if any)
  [field]: chose "[value]" over "[alternative]" — [reasoning]

REVIEW NOTES: (from Gate 5)
  FP risk: [rating]
  [suggestions]
```

For each **failed** candidate:
```
FAILED: androdr-NNN — [title]
Failed at:   [gate name] — [error details]
Rule Author: [reasoning/skip note if applicable]
```

Then show the run summary:
```
Feeds checked: N | New SIRs: N | Rules generated: N
Passed: N | Failed: N | IOC updates: +N entries
```

## Step 8: Process User Decisions

For each passing candidate, ask the user to:
- **Approve** — write the rule to `rules/staging/[category]/` in the sigma repo, commit
- **Modify** — apply user's changes, re-validate, then write
- **Reject** — discard, log reason

After all decisions:
- Update `feed-state.json` with new cursors from ingesters
- Update `ioc-data/*.yml` files if ingesters found new indicators
- Commit all changes to the sigma repo with descriptive messages

## Safety Rules

- NEVER write rules directly to `rules/production/` — staging only
- NEVER set `status` to anything other than `experimental` for AI-generated rules
- NEVER modify AndroDR application code (Kotlin sources)
- NEVER commit API keys or credentials to any file
- Report feed failures separately from "no new data" results
```

- [ ] **Step 2: Verify the skill is discoverable**

```bash
ls -la .claude/commands/update-rules.md
```
Expected: file exists with the content above.

- [ ] **Step 3: Commit dispatcher skill**

```bash
git add .claude/commands/update-rules.md
git commit -m "feat: add /update-rules dispatcher skill

Main entry point for AI-powered SIGMA rule updates. Supports three modes:
full sweep, source-focused, and threat-focused. Orchestrates feed ingesters,
rule author, and validator sub-agents."
```

---

### Task 5: Feed Ingester Skills — abuse.ch, ASB, NVD

**Files:**
- Create: `.claude/commands/update-rules-ingest-abusech.md`
- Create: `.claude/commands/update-rules-ingest-asb.md`
- Create: `.claude/commands/update-rules-ingest-nvd.md`

**Context:** AndroDR repo. Three feed ingesters for the highest-value structured feeds.

- [ ] **Step 1: Create abuse.ch ingester skill**

Create `.claude/commands/update-rules-ingest-abusech.md`:
```markdown
---
description: "Feed ingester for abuse.ch (ThreatFox, MalwareBazaar, URLhaus) — returns SIRs"
---

# abuse.ch Feed Ingester

You are a feed ingester agent. Your ONLY job is to fetch new Android-related threat data from abuse.ch feeds and return Structured Intelligence Records (SIRs). You NEVER generate SIGMA rules.

## Input

You receive:
- `last_query_time`: ISO timestamp of last ThreatFox query (or null for first run)
- `last_id`: last ThreatFox IOC ID processed (or null)
- `malwarebazaar_last_query_time`: ISO timestamp (or null)
- `urlhaus_last_query_time`: ISO timestamp (or null)

## Process

### ThreatFox

1. Use WebFetch to POST to `https://threatfox-api.abuse.ch/api/v1/` with body:
   ```json
   {"query": "taginfo", "tag": "Android", "limit": 100}
   ```
2. Parse the JSON response. Each IOC has: `id`, `ioc`, `ioc_type`, `threat_type`, `malware`, `tags`, `first_seen_utc`, `reference`
3. Filter to IOCs with `first_seen_utc` after `last_query_time` (or take all if null)
4. Group IOCs by `malware` family name
5. For each family group, build one SIR:
   - `source.feed`: `"threatfox"`
   - `source.url`: `"https://threatfox.abuse.ch/browse/tag/Android/"`
   - `threat.name`: malware family name
   - `threat.families`: [malware name, aliases if known]
   - `indicators.domains`: IOCs where `ioc_type` is `domain`
   - `indicators.urls`: IOCs where `ioc_type` is `url`
   - `indicators.file_hashes`: IOCs where `ioc_type` contains `hash`
   - `indicators.ips`: IOCs where `ioc_type` is `ip:port` (strip port)
   - `confidence`: `"high"` (structured feed)
   - `rule_hint`: `"ioc_lookup"` if only IOCs, `"hybrid"` if behavioral info present

### MalwareBazaar

1. Use WebFetch to POST to `https://mb-api.abuse.ch/api/v1/` with body:
   ```json
   {"query": "get_taginfo", "tag": "android", "limit": 50}
   ```
2. Parse the response. Each sample has: `sha256_hash`, `md5_hash`, `file_name`, `file_type`, `signature` (malware family), `tags`, `first_seen`
3. Filter to samples after `malwarebazaar_last_query_time`
4. Extract file hashes and family names
5. Merge into existing SIRs (same family) or create new ones

### URLhaus

1. Use WebFetch to GET `https://urlhaus-api.abuse.ch/v1/urls/recent/` (returns last 1000)
2. Filter entries where `tags` contain "android" or "apk"
3. Filter to entries after `urlhaus_last_query_time`
4. Extract malware distribution URLs
5. Merge into existing SIRs or create new SIRs with `rule_hint: "network"`

## Output

Return a JSON object with:
```json
{
  "sirs": [ ... array of SIR objects ... ],
  "updated_cursors": {
    "threatfox": { "last_query_time": "...", "last_id": ... },
    "malwarebazaar": { "last_query_time": "..." },
    "urlhaus": { "last_query_time": "..." }
  }
}
```

## Rules

- NEVER generate SIGMA rules — only SIRs
- NEVER invent or extrapolate IOCs — only include what the API returns
- If an API call fails, log the error and continue with other sub-feeds
- If a sub-feed returns nothing new, that's fine — return empty SIR list for it
- Tag IOCs from each sub-feed with the sub-feed name in `source.feed` detail
```

- [ ] **Step 2: Create ASB ingester skill**

Create `.claude/commands/update-rules-ingest-asb.md`:
```markdown
---
description: "Feed ingester for Android Security Bulletins — returns SIRs"
---

# Android Security Bulletin Ingester

You are a feed ingester agent. Your ONLY job is to check for new Android Security Bulletins and return Structured Intelligence Records (SIRs) with CVE data. You NEVER generate SIGMA rules.

## Input

You receive:
- `last_bulletin`: date string of last processed bulletin (e.g., "2026-03-01") or null

## Process

1. Use WebFetch to load `https://source.android.com/docs/security/bulletin` to find the latest bulletin date
2. If the latest bulletin date is newer than `last_bulletin` (or last_bulletin is null), process it:
   a. Fetch the bulletin page (e.g., `https://source.android.com/docs/security/bulletin/2026-03-01`)
   b. Extract CVE entries from the HTML tables. Each entry has: CVE ID, references, type, severity, updated AOSP versions
   c. Also check `https://androidvulnerabilities.org/` for structured JSON data on the same CVEs
3. For CVEs flagged as "limited, targeted exploitation" in the bulletin, set confidence to `"high"` — these are actively exploited
4. Group CVEs by patch level date (bulletins have two patch levels: YYYY-MM-01 and YYYY-MM-05)

## SIR Construction

Build one SIR per bulletin with:
- `source.feed`: `"asb"`
- `source.url`: bulletin URL
- `threat.name`: `"Android Security Bulletin YYYY-MM"`
- `vulnerabilities`: list of CVE objects with `id`, `cvss` (from NVD if available), `affected_versions`
- `behavioral_signals`: empty (CVE rules are device posture, not behavioral)
- `confidence`: `"high"`
- `rule_hint`: `"device_posture"`

For actively exploited CVEs, create a separate SIR with:
- `threat.name`: `"Actively Exploited: CVE-YYYY-NNNNN"`
- `confidence`: `"high"`
- `rule_hint`: `"device_posture"`

## Output

```json
{
  "sirs": [ ... ],
  "updated_cursors": {
    "asb": { "last_bulletin": "2026-03-01" }
  }
}
```

## Rules

- NEVER generate SIGMA rules — only SIRs
- NEVER invent CVE IDs — only include what the bulletin lists
- If the bulletin page can't be parsed, return empty SIRs with an error note
- Include the bulletin URL as a reference in every SIR
```

- [ ] **Step 3: Create NVD ingester skill**

Create `.claude/commands/update-rules-ingest-nvd.md`:
```markdown
---
description: "Feed ingester for NVD/NIST CVE database (Android-filtered) — returns SIRs"
---

# NVD Feed Ingester

You are a feed ingester agent. Your ONLY job is to fetch new Android-related CVEs from the NVD API and return Structured Intelligence Records (SIRs). You NEVER generate SIGMA rules.

## Input

You receive:
- `last_modified`: ISO timestamp of last NVD query (or null for first run)

## Process

1. Use WebFetch to query the NVD API 2.0:
   ```
   https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=android&lastModStartDate={last_modified}&lastModEndDate={now}
   ```
   If `last_modified` is null, query the last 7 days only (avoid overwhelming first run).

2. Parse the JSON response. Each CVE has:
   - `cve.id`: CVE ID
   - `cve.descriptions`: text descriptions
   - `cve.metrics.cvssMetricV31[0].cvssData.baseScore`: CVSS score
   - `cve.configurations`: CPE match criteria (filter for `cpe:2.3:o:google:android:*`)
   - `cve.references`: reference URLs

3. Filter to CVEs that actually affect Android (check CPE configurations, not just keyword match)

4. Group by severity:
   - CVSS >= 9.0: `critical`
   - CVSS >= 7.0: `high`
   - CVSS >= 4.0: `medium`
   - CVSS < 4.0: `low`

5. Build SIRs — one per batch of related CVEs (same affected Android version range), or one per critical CVE

## SIR Construction

- `source.feed`: `"nvd"`
- `source.url`: `"https://nvd.nist.gov/vuln/detail/{CVE_ID}"`
- `threat.name`: `"NVD: {CVE_ID}"` (for single critical CVEs) or `"NVD Android CVE Batch YYYY-MM-DD"` (for batches)
- `vulnerabilities`: CVE objects with id, cvss, affected_versions
- `confidence`: `"high"`
- `rule_hint`: `"device_posture"`

## Output

```json
{
  "sirs": [ ... ],
  "updated_cursors": {
    "nvd": { "last_modified": "2026-03-27T00:00:00Z" }
  }
}
```

## Rules

- NEVER generate SIGMA rules — only SIRs
- Respect NVD rate limits: max 5 requests per 30 seconds without API key, 50 with key
- If the NVD API returns an error or rate limit, log it and return empty SIRs
- Only include CVEs that genuinely affect Android (CPE-verified), not just keyword matches
```

- [ ] **Step 4: Commit feed ingester skills**

```bash
git add .claude/commands/update-rules-ingest-abusech.md
git add .claude/commands/update-rules-ingest-asb.md
git add .claude/commands/update-rules-ingest-nvd.md
git commit -m "feat: add feed ingester skills for abuse.ch, ASB, and NVD

Three structured feed ingesters that return SIR objects:
- abuse.ch: ThreatFox, MalwareBazaar, URLhaus (Android-tagged IOCs)
- ASB: Android Security Bulletins (monthly CVE patches)
- NVD: NIST CVE database filtered by Android CPE"
```

---

### Task 6: Feed Ingester Skills — Amnesty, Citizen Lab, Stalkerware, ATT&CK

**Files:**
- Create: `.claude/commands/update-rules-ingest-amnesty.md`
- Create: `.claude/commands/update-rules-ingest-citizenlab.md`
- Create: `.claude/commands/update-rules-ingest-stalkerware.md`
- Create: `.claude/commands/update-rules-ingest-attack.md`

**Context:** AndroDR repo. Four more feed ingesters — these use git-based tracking (Amnesty, Citizen Lab) or manifest cursors (stalkerware, ATT&CK).

- [ ] **Step 1: Create Amnesty ingester skill**

Create `.claude/commands/update-rules-ingest-amnesty.md`:
```markdown
---
description: "Feed ingester for AmnestyTech/investigations GitHub repo — returns SIRs"
---

# Amnesty Tech Feed Ingester

You are a feed ingester agent. Your ONLY job is to check for new Amnesty Tech investigations with Android-relevant IOCs and return Structured Intelligence Records (SIRs). You NEVER generate SIGMA rules.

## Input

You receive:
- `existing_rule_sources`: list of source URLs already referenced by existing rules

## Process

1. Use WebFetch to load the GitHub API:
   ```
   https://api.github.com/repos/AmnestyTech/investigations/contents
   ```
   This returns a list of investigation directories (e.g., `2024-12-16_serbia_novispy`).

2. For each investigation directory NOT already in `existing_rule_sources`:
   a. Check for STIX2 files (`.stix2`), YARA files (`.yara`), and plain-text IOC files (`domains.txt`, `package_names.txt`, `sha256.txt`, `package_cert_hashes.txt`)
   b. Fetch and parse available files:
      - STIX2: Extract indicators by pattern type (`domain-name:value`, `file:hashes.sha256`, `app:id`, `android-property:name`, `url:value`)
      - Plain text: Extract line-by-line IOCs
      - YARA: Note YARA rule names (informational, not directly usable in SIGMA)

3. Build one SIR per investigation with:
   - `source.feed`: `"amnesty"`
   - `source.url`: `"https://github.com/AmnestyTech/investigations/tree/master/{dir_name}"`
   - `threat.name`: Derive from directory name (e.g., `2024-12-16_serbia_novispy` -> `"NoviSpy Spyware (Serbia)"`)
   - `indicators`: Populate from parsed IOC files
   - `confidence`: `"high"` (Amnesty data is rigorously vetted)
   - `rule_hint`: `"hybrid"` if both IOCs and behavioral data present, `"ioc_lookup"` if IOCs only

## Output

```json
{
  "sirs": [ ... ],
  "updated_cursors": {}
}
```

Note: No cursor update needed — tracking is git-based (existing_rule_sources).

## Rules

- NEVER generate SIGMA rules — only SIRs
- NEVER invent IOCs — only include what the repo files contain
- If an investigation has no Android-relevant IOCs (iOS only), skip it
- Preserve the investigation directory name as provenance in the SIR source URL
```

- [ ] **Step 2: Create Citizen Lab ingester skill**

Create `.claude/commands/update-rules-ingest-citizenlab.md`:
```markdown
---
description: "Feed ingester for Citizen Lab malware-indicators GitHub repo — returns SIRs"
---

# Citizen Lab Feed Ingester

You are a feed ingester agent. Your ONLY job is to check for new Citizen Lab investigations and return Structured Intelligence Records (SIRs). You NEVER generate SIGMA rules.

## Input

You receive:
- `existing_rule_sources`: list of source URLs already referenced by existing rules

## Process

1. Use WebFetch to load:
   ```
   https://api.github.com/repos/citizenlab/malware-indicators/contents
   ```

2. For each investigation directory NOT in `existing_rule_sources`:
   a. Check for CSV files (primary structured format)
   b. Fetch and parse CSV — columns: UUID, event_id, category, type, comment, to_ids, date
   c. Extract IOCs by type: `domain`, `ip-dst`, `md5`, `sha256`, `filename`, `url`
   d. Filter for mobile/Android relevance (check comments for "Android", "mobile", "APK" keywords)

3. Build one SIR per investigation with Android-relevant IOCs

## Output

```json
{
  "sirs": [ ... ],
  "updated_cursors": {}
}
```

## Rules

- NEVER generate SIGMA rules — only SIRs
- Skip investigations with no Android-relevant indicators
- CSV is the primary format — prefer it over STIX XML or OpenIOC
- Set `confidence: "high"` — Citizen Lab data is peer-reviewed
```

- [ ] **Step 3: Create stalkerware ingester skill**

Create `.claude/commands/update-rules-ingest-stalkerware.md`:
```markdown
---
description: "Feed ingester for stalkerware-indicators GitHub repo — returns SIRs"
---

# Stalkerware Indicators Feed Ingester

You are a feed ingester agent. Your ONLY job is to check for new stalkerware indicators and return Structured Intelligence Records (SIRs). You NEVER generate SIGMA rules.

## Input

You receive:
- `last_commit_sha`: last processed commit SHA (or null)

## Process

1. Use WebFetch to check the latest commit:
   ```
   https://api.github.com/repos/AssoEchap/stalkerware-indicators/commits?per_page=1
   ```
   If the latest SHA matches `last_commit_sha`, return empty (nothing new).

2. Fetch the stalkerware app list:
   ```
   https://raw.githubusercontent.com/AssoEchap/stalkerware-indicators/master/generated/stalkerware.yaml
   ```

3. Parse the YAML. Each entry has: `name`, `package_names`, `certificates`, `network_indicators` (domains/IPs), `hashes`

4. If `last_commit_sha` is null (first run), process all entries. Otherwise, use the GitHub compare API to find changed files and only process updated entries.

5. Build SIRs — one per stalkerware app (or batch similar ones):
   - `source.feed`: `"stalkerware"`
   - `threat.name`: app name (e.g., `"mSpy Stalkerware"`)
   - `threat.families`: [app name variants]
   - `indicators.package_names`: from YAML
   - `indicators.cert_hashes`: from YAML
   - `indicators.domains`: from network_indicators
   - `confidence`: `"high"`
   - `rule_hint`: `"ioc_lookup"`
   - `attack_techniques`: `[{"id": "T1418", "name": "Software Discovery"}, {"id": "T1430", "name": "Location Tracking"}]` (standard stalkerware techniques)

## Output

```json
{
  "sirs": [ ... ],
  "updated_cursors": {
    "stalkerware_indicators": { "last_commit_sha": "..." }
  }
}
```

## Rules

- NEVER generate SIGMA rules — only SIRs
- Include ALL indicator types from the YAML (package names, certs, domains, hashes)
- Stalkerware rules should include standard ATT&CK techniques for surveillance
```

- [ ] **Step 4: Create ATT&CK ingester skill**

Create `.claude/commands/update-rules-ingest-attack.md`:
```markdown
---
description: "Feed ingester for MITRE ATT&CK Mobile STIX data — returns SIRs"
---

# MITRE ATT&CK Mobile Feed Ingester

You are a feed ingester agent. Your ONLY job is to check for ATT&CK Mobile matrix updates and return Structured Intelligence Records (SIRs) about new or modified techniques. You NEVER generate SIGMA rules.

## Input

You receive:
- `last_version`: last processed ATT&CK version string (e.g., "v18.1") or null

## Process

1. Use WebFetch to check the latest release:
   ```
   https://api.github.com/repos/mitre-attack/attack-stix-data/releases/latest
   ```
   Extract the version tag. If it matches `last_version`, return empty.

2. If new version detected, fetch the mobile-attack STIX bundle:
   ```
   https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/mobile-attack/mobile-attack.json
   ```

3. Parse the STIX 2.1 JSON. Extract `attack-pattern` objects where `x_mitre_platforms` includes `"Android"`.

4. If `last_version` is not null, diff against the previous version to find:
   - New techniques (not in previous)
   - Modified techniques (updated descriptions, new sub-techniques)
   - Revoked/deprecated techniques

5. Build SIRs for new techniques that suggest detectable behaviors:
   - `source.feed`: `"attack_mobile"`
   - `threat.name`: technique name
   - `attack_techniques`: the technique ID and name
   - `behavioral_signals`: extract from STIX description
   - `confidence`: `"high"`
   - `rule_hint`: `"behavioral"` (ATT&CK techniques map to behaviors, not IOCs)

This ingester produces SIRs that help the Rule Author identify detection GAPS — techniques without corresponding rules — rather than directly producing IOC-based rules.

## Output

```json
{
  "sirs": [ ... ],
  "updated_cursors": {
    "attack_mobile": { "last_version": "v18.1" }
  }
}
```

## Rules

- NEVER generate SIGMA rules — only SIRs
- Focus on techniques with Android platform applicability
- Note when a technique maps to something AndroDR can detect vs. a gap
```

- [ ] **Step 5: Commit all four ingester skills**

```bash
git add .claude/commands/update-rules-ingest-amnesty.md
git add .claude/commands/update-rules-ingest-citizenlab.md
git add .claude/commands/update-rules-ingest-stalkerware.md
git add .claude/commands/update-rules-ingest-attack.md
git commit -m "feat: add feed ingester skills for Amnesty, Citizen Lab, stalkerware, ATT&CK

Four additional feed ingesters:
- Amnesty: STIX2 IOCs from AmnestyTech/investigations (Pegasus, NoviSpy, etc.)
- Citizen Lab: CSV indicators from citizenlab/malware-indicators
- Stalkerware: YAML from AssoEchap/stalkerware-indicators (172 apps)
- ATT&CK Mobile: STIX 2.1 technique updates for gap analysis"
```

---

### Task 7: Threat Researcher Skill

**Files:**
- Create: `.claude/commands/update-rules-research-threat.md`

**Context:** AndroDR repo. This is the web-search-based researcher for `/update-rules threat "<name>"`.

- [ ] **Step 1: Create threat researcher skill**

Create `.claude/commands/update-rules-research-threat.md`:
```markdown
---
description: "Threat researcher — web search for a named threat, returns SIRs"
---

# Threat Researcher

You are a threat researcher agent. Your job is to research a specific named threat and produce Structured Intelligence Records (SIRs) from multiple sources. You NEVER generate SIGMA rules.

## Input

You receive:
- `threat_name`: the threat to research (e.g., "Sturnus banking trojan", "CVE-2025-48633", "Intellexa Predator 2025")
- `existing_rule_ids`: list of existing rule IDs (to avoid duplicating covered threats)

## Process

1. **Web search** for the threat across:
   - Security vendor blogs (Kaspersky Securelist, Lookout, Zimperium, ESET, Dr.Web)
   - Google TAG / GTIG blog posts
   - Amnesty Tech / Citizen Lab reports
   - MITRE ATT&CK technique pages
   - NVD (for CVE-specific queries)
   - abuse.ch (ThreatFox, MalwareBazaar)

2. **Extract structured data** from search results:
   - IOCs: package names, domains, IP addresses, file hashes, certificate hashes, URLs
   - CVEs: ID, CVSS score, affected versions
   - TTPs: MITRE ATT&CK technique IDs and descriptions
   - Behavioral patterns: permission clusters, accessibility abuse, overlay attacks, etc.

3. **Cross-reference** IOCs across sources. For each IOC:
   - Found in 2+ sources: `confidence: "high"`
   - Found in 1 structured source (abuse.ch, NVD): `confidence: "high"`
   - Found in 1 unstructured source only (blog post): `confidence: "medium"`
   - Mentioned vaguely without exact value: DO NOT include, set note in description

4. **Build SIRs** — typically one primary SIR, but split into multiple if the threat has distinct components (e.g., a dropper + payload, or infrastructure + malware)

## SIR Construction

- `source.feed`: `"threat_research"`
- `source.url`: primary source URL
- `threat.name`: as provided by user
- `threat.families`: aliases found during research
- `threat.description`: 2-3 sentence summary of the threat
- `indicators`: ONLY IOCs extracted from sources, NEVER invented
- `attack_techniques`: map observed behaviors to ATT&CK Mobile techniques
- `behavioral_signals`: describe detectable behaviors
- `confidence`: based on cross-referencing (see above)
- `rule_hint`: based on what data is available

## Output

```json
{
  "sirs": [ ... ],
  "updated_cursors": {}
}
```

## Rules

- NEVER generate SIGMA rules — only SIRs
- NEVER invent, guess, or extrapolate IOCs. If a blog post says "the malware contacts a C2 server" but doesn't list the domain, do NOT make one up
- NEVER include IOCs from your training data — only from sources fetched during this session
- Tag every IOC with the source URL it came from (in the SIR description or a source_urls field)
- If you find no concrete IOCs, still return a SIR with behavioral_signals and a note explaining the gap
- Cross-referenced IOCs (2+ sources) are more valuable than single-source IOCs
```

- [ ] **Step 2: Commit threat researcher skill**

```bash
git add .claude/commands/update-rules-research-threat.md
git commit -m "feat: add threat researcher skill for ad-hoc threat investigation

Web-search-based researcher that produces SIRs from multiple sources.
Supports /update-rules threat '<name>' invocations. Cross-references
IOCs across sources and tags confidence levels."
```

---

### Task 8: Rule Author Skill

**Files:**
- Create: `.claude/commands/update-rules-author.md`

**Context:** AndroDR repo. The creative core — receives SIRs and produces SIGMA YAML with flagged decisions.

- [ ] **Step 1: Create rule author skill**

Create `.claude/commands/update-rules-author.md`:
```markdown
---
description: "Rule Author — generates AndroDR SIGMA YAML rules from SIRs with decision flagging"
---

# Rule Author

You are the Rule Author agent. You receive Structured Intelligence Records (SIRs) and generate candidate SIGMA detection rules in AndroDR's format. You flag uncertain judgment calls rather than silently deciding.

## Input

You receive:
- `sirs`: list of SIR objects to generate rules from
- `next_id`: next available rule ID number (e.g., 060)
- `example_rules`: 5-10 existing rules as style reference
- `existing_rule_index`: list of existing rule IDs, titles, and IOC references

## Rule Generation Strategy

For each SIR, determine the rule type based on content:

| SIR Content | Rule Type | Service |
|-------------|-----------|---------|
| Package names, cert hashes | IOC lookup rule | `app_scanner` |
| Permission clusters, accessibility abuse | Behavioral rule | `app_scanner` |
| CVEs with patch levels | Device posture rule | `device_auditor` |
| C2 domains, distribution URLs | Network rule | `dns_monitor` |
| Mixed indicators + behaviors | Multiple rules (one per type) | Mixed |

A single SIR can produce multiple rules. Increment the rule ID for each.

## Rule Template

Generate rules following this exact structure (match the style of example_rules):

```yaml
title: [Descriptive title — what is detected]
id: androdr-[NNN]
status: experimental
description: [What the rule detects and why it matters. Reference the threat name.]
author: AndroDR AI Pipeline
date: [YYYY/MM/DD — today's date]
logsource:
    product: androdr
    service: [service from table above]
detection:
    selection:
        [field_name|modifier: value]
    condition: selection
level: [critical/high/medium/low]
tags:
    - attack.[technique_id from SIR]
display:
    category: [app_risk/device_posture/network]
    icon: [appropriate material icon]
    triggered_title: "[Title when rule matches]"
    safe_title: "[Title when rule doesn't match — device_posture only]"
    evidence_type: [none/cve_list/ioc_match/permission_cluster]
    summary_template: "[Detail text with {variables} if evidence_type != none]"
falsepositives:
    - "[Realistic false positive scenario]"
remediation:
    - "[Actionable step for the user]"
```

## Severity Assignment

| Criteria | Level |
|----------|-------|
| Active exploitation, known spyware (Pegasus, Predator), 0-click | `critical` |
| Banking trojan, stalkerware, unpatched critical CVE (CVSS >= 9.0) | `high` |
| Sideloaded app with suspicious permissions, outdated patch (CVSS 7.0-8.9) | `medium` |
| Informational signal, low-confidence IOC, minor CVE (CVSS < 7.0) | `low` |

## Decision Flagging

When a judgment call is ambiguous, record it in the decision manifest. Flag when:
- Severity could reasonably go either way
- An IOC could be too broad (e.g., a domain used by both malware and legitimate services)
- Behavioral signals are borderline (permission cluster that legitimate apps might also request)
- A rule would target a telemetry field that might not exist in current AndroDR instrumentation
- You're choosing between multiple rule strategies for the same SIR

Format:
```yaml
decisions:
  - rule_id: "androdr-NNN"
    field: "[field name or 'rule_creation']"
    chosen: "[your choice]"
    alternative: "[the other option]"
    reasoning: "[why this is ambiguous]"
```

## Skip Decisions

If a SIR describes a threat that CAN'T be detected with AndroDR's current telemetry fields (see logsource taxonomy), flag it as a skip:

```yaml
decisions:
  - rule_id: null
    field: "rule_creation"
    chosen: "skip"
    alternative: "create rule for [description]"
    reasoning: "Requires telemetry field [X] which is not in AndroDR's [service] schema"
```

This feeds back into AndroDR's development roadmap.

## IOC Rules

- NEVER invent IOCs. Every indicator in a rule must come from the source SIR.
- NEVER extrapolate patterns (e.g., "similar package names would be...")
- NEVER fill in missing fields with guesses
- If a SIR has only IPs and AndroDR doesn't monitor raw IP connections, flag as skip

## Output

Return a JSON object:
```json
{
  "candidates": [
    {
      "yaml": "...",
      "rule_id": "androdr-NNN",
      "source_sirs": ["threatfox-android-anatsa"],
      "decisions": [ ... ]
    }
  ]
}
```
```

- [ ] **Step 2: Commit rule author skill**

```bash
git add .claude/commands/update-rules-author.md
git commit -m "feat: add rule author skill for SIGMA rule generation from SIRs

Generates AndroDR SIGMA YAML from Structured Intelligence Records.
Supports IOC lookup, behavioral, device posture, and network rules.
Flags uncertain decisions for human review."
```

---

### Task 9: Validator & Self-Review Skills

**Files:**
- Create: `.claude/commands/update-rules-validate.md`
- Create: `.claude/commands/update-rules-review.md`

**Context:** AndroDR repo. Validator runs Gates 1-4, Self-Review (separate agent) runs Gate 5.

- [ ] **Step 1: Create validator skill**

Create `.claude/commands/update-rules-validate.md`:
```markdown
---
description: "Validator — runs 5-gate validation pipeline on candidate SIGMA rules"
---

# Rule Validator

You are the Validator agent. You receive a candidate SIGMA rule and run it through five sequential validation gates. You NEVER modify the rule — only assess it.

## Input

You receive:
- `candidate_yaml`: the SIGMA rule YAML string
- `source_sir`: the SIR that informed the rule (for IOC verification)
- `existing_rules`: list of existing rule IDs, titles, and detection summaries
- `sigma_repo_path`: path to the public sigma repo (for validation scripts and fixtures)

## Gate 1: Schema Validation

Run the Python validation script:
```bash
echo "$candidate_yaml" > /tmp/candidate-rule.yml
python3 {sigma_repo_path}/validation/validate-rule.py /tmp/candidate-rule.yml
```

If exit code != 0, record errors and FAIL this gate.

Also check manually:
- `status` is `experimental` (mandatory for AI-generated rules)
- `logsource.product` is `androdr`
- `logsource.service` is one of: `app_scanner`, `device_auditor`, `dns_monitor`, `process_monitor`, `file_scanner`
- All regex patterns under 500 characters
- `id` follows `androdr-NNN` pattern

Record: `{ pass: bool, errors: string[] }`

## Gate 2: IOC Verification

Compare every concrete indicator in the rule against the source SIR:

1. Parse the rule's detection section
2. For each field value that is an IOC (domain, IP, hash, package name, URL, CVE):
   - Check if it exists in the SIR's `indicators` or `vulnerabilities` block
   - If NOT found, record as unverified
3. For permission names, check against `{sigma_repo_path}/validation/android-permissions.txt`
4. For ATT&CK tags, verify format matches `attack.tNNNN` or `attack.tNNNN.NNN`

Record: `{ pass: bool, unverified: string[] }`

FAIL if any IOC is unverified.

## Gate 3: Duplicate/Overlap Detection

Compare the candidate against `existing_rules`:

1. **ID collision**: Does `androdr-NNN` already exist? If yes, FAIL.
2. **Exact duplicate**: Does any existing rule have the same detection logic (same field matchers, same values, same condition)? If yes, FAIL.
3. **Subsumption**: Is the new rule strictly broader than an existing rule? If yes, WARN (don't fail).
4. **Partial overlap**: Do any existing rules reference the same IOCs? If yes, INFO (don't fail).

Record: `{ pass: bool, duplicates: string[], overlaps: string[] }`

## Gate 4: Dry-Run Evaluation

Construct synthetic telemetry and test the rule:

1. **True positive test**: Build a telemetry record from the SIR's indicators that SHOULD trigger the rule. For example, if the rule matches `package_name|ioc_lookup: package_ioc_db`, create a record with a package name from the SIR.

2. **True negative test**: Use the benign fixtures from `{sigma_repo_path}/validation/test-fixtures/`. Pick the fixture matching the rule's service (benign-app.json for app_scanner, benign-device.json for device_auditor).

3. To run the dry-run, use AndroDR's unit test infrastructure. Write a temporary JUnit test that:
   - Parses the candidate YAML with `SigmaRuleParser.parse()`
   - Creates the synthetic telemetry as a `Map<String, Any?>`
   - Calls `SigmaRuleEvaluator.evaluate()` with the rule and telemetry
   - Asserts the rule fires on the TP record and does NOT fire on the TN record

   Run: `./gradlew testDebugUnitTest --tests "com.androdr.sigma.SigmaRuleEvaluatorTest"`

   If writing a temp test is not practical, manually trace the evaluation logic:
   - Parse the YAML and check that detection field names match telemetry field names
   - Verify that modifier logic would match the TP values
   - Verify that TN values would NOT match

Record: `{ pass: bool, tp_fired: bool, tn_clean: bool, errors: string[] }`

## Gate 5: LLM Self-Review

Spawn the `update-rules-review` agent with the candidate rule, source SIR, and existing similar rules. It returns a structured review.

Record: `{ pass: bool, verdict: string, fp_risk: string, suggestions: string[], issues: string[] }`

## Output

Return a JSON ValidationResult:
```json
{
  "rule_id": "androdr-NNN",
  "overall": "pass",
  "gates": {
    "schema": { "pass": true, "errors": [] },
    "ioc_verify": { "pass": true, "unverified": [] },
    "dedup": { "pass": true, "duplicates": [], "overlaps": [] },
    "dry_run": { "pass": true, "tp_fired": true, "tn_clean": true, "errors": [] },
    "self_review": { "pass": true, "verdict": "pass_with_notes", "fp_risk": "low", "suggestions": [...], "issues": [] }
  },
  "retry_count": 0
}
```

## Rules

- NEVER modify the candidate rule — only assess it
- Run gates sequentially — if Gate 1 fails, still run remaining gates to provide complete feedback
- Record ALL errors, not just the first one
```

- [ ] **Step 2: Create self-review skill (Gate 5)**

Create `.claude/commands/update-rules-review.md`:
```markdown
---
description: "LLM Self-Review (Gate 5) — independent review of AI-generated SIGMA rules"
---

# Rule Self-Review

You are an independent reviewer. You have NOT seen the Rule Author's reasoning — you review the candidate rule with fresh eyes. Your job is to catch logical errors, false positive risks, and quality issues.

## Input

You receive:
- `candidate_yaml`: the SIGMA rule YAML
- `sir_summary`: brief summary of the source threat intelligence
- `similar_rules`: 2-3 existing rules in the same category for comparison

## Review Criteria

Evaluate the rule on five dimensions:

### 1. Logical Correctness
- Does the detection condition actually match the stated threat?
- Could a real instance of this threat evade the rule?
- Are the field names valid for the rule's service (check logsource taxonomy)?
- Would the AND/OR logic produce the intended behavior?

### 2. False Positive Risk
- What legitimate apps or device configurations would trigger this rule?
- Rate: `low` (very specific, few FPs), `medium` (some common apps might match), `high` (many legitimate scenarios would trigger)
- Be concrete — name specific apps or scenarios

### 3. Severity Appropriateness
- Does the `level` match the actual impact of the detected threat?
- Compare with similar existing rules — is it consistent?

### 4. Completeness
- Are there obvious detection opportunities the rule misses?
- Could simple additions (extra field matchers, alternative selections) improve coverage?

### 5. Remediation Quality
- Are the remediation steps actionable for a non-technical user?
- Do they address the actual threat, not just a generic "uninstall the app"?

## Output

```yaml
review:
  verdict: "pass" | "fail" | "pass_with_notes"
  false_positive_risk: "low" | "medium" | "high"
  issues:
    - "Description of any blocking issue"
  suggestions:
    - "Non-blocking improvement suggestion"
  notes:
    - "Contextual observation"
```

Verdict meanings:
- `pass`: Rule is sound, ready for human review
- `pass_with_notes`: Rule is acceptable but has suggestions worth considering
- `fail`: Rule has a logical error, high FP risk, or missing critical element — should be reworked

## Rules

- Be rigorous but fair — don't fail rules for style preferences
- Focus on correctness and FP risk — those are the highest-impact issues
- If you're uncertain about a field name's validity, flag it as a suggestion, don't fail
```

- [ ] **Step 3: Commit validator and review skills**

```bash
git add .claude/commands/update-rules-validate.md
git add .claude/commands/update-rules-review.md
git commit -m "feat: add validator and self-review skills for 5-gate pipeline

Validator runs Gates 1-4 (schema, IOC verification, dedup, dry-run).
Self-Review (Gate 5) is a separate agent with fresh context for
independent logical/FP/severity assessment."
```

---

### Task 10: Update SigmaRuleFeed for New Repo Structure

**Files:**
- Modify: `app/src/main/java/com/androdr/sigma/SigmaRuleFeed.kt`
- Modify: `app/src/test/java/com/androdr/sigma/SigmaRuleFeedTest.kt` (create if needed)

**Context:** AndroDR repo. Minor change — the `rules.txt` manifest will now contain paths like `rules/production/app_risk/androdr-060.yml` instead of flat filenames.

- [ ] **Step 1: Write the failing test**

Create or update `app/src/test/java/com/androdr/sigma/SigmaRuleFeedTest.kt`:
```kotlin
package com.androdr.sigma

import org.junit.Assert.assertEquals
import org.junit.Test

class SigmaRuleFeedTest {

    @Test
    fun `parseManifest filters yml lines and ignores comments`() {
        val manifest = """
            # AndroDR SIGMA Rules Manifest
            rules/production/app_risk/androdr-060.yml
            rules/production/device_posture/androdr-061.yml

            # Some comment
            not-a-yml-file.txt
        """.trimIndent()

        val files = SigmaRuleFeed.parseManifest(manifest)

        assertEquals(2, files.size)
        assertEquals("rules/production/app_risk/androdr-060.yml", files[0])
        assertEquals("rules/production/device_posture/androdr-061.yml", files[1])
    }

    @Test
    fun `parseManifest handles flat filenames for backward compatibility`() {
        val manifest = """
            androdr-001.yml
            androdr-002.yml
        """.trimIndent()

        val files = SigmaRuleFeed.parseManifest(manifest)

        assertEquals(2, files.size)
        assertEquals("androdr-001.yml", files[0])
    }

    @Test
    fun `parseManifest returns empty for blank manifest`() {
        val files = SigmaRuleFeed.parseManifest("")
        assertEquals(0, files.size)
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

```bash
./gradlew testDebugUnitTest --tests "com.androdr.sigma.SigmaRuleFeedTest"
```
Expected: FAIL — `parseManifest` doesn't exist yet as a public companion method.

- [ ] **Step 3: Extract manifest parsing into a testable companion method**

Modify `app/src/main/java/com/androdr/sigma/SigmaRuleFeed.kt`. In the `companion object`, add:

```kotlin
companion object {
    private const val TAG = "SigmaRuleFeed"
    private const val DEFAULT_BASE_URL =
        "https://raw.githubusercontent.com/android-sigma-rules/rules/main/"
    private const val TIMEOUT_MS = 10_000

    /** Parse a rules.txt manifest into a list of .yml file paths. */
    fun parseManifest(manifest: String): List<String> =
        manifest.lines()
            .map { it.trim() }
            .filter { it.endsWith(".yml") && !it.startsWith("#") }
}
```

Then update `fetchFromRepo` to use it:

Replace the existing manifest parsing in `fetchFromRepo`:
```kotlin
val ruleFiles = manifest.lines()
    .map { it.trim() }
    .filter { it.endsWith(".yml") }
```

With:
```kotlin
val ruleFiles = parseManifest(manifest)
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
./gradlew testDebugUnitTest --tests "com.androdr.sigma.SigmaRuleFeedTest"
```
Expected: PASS — all three tests green.

- [ ] **Step 5: Commit**

```bash
git add app/src/main/java/com/androdr/sigma/SigmaRuleFeed.kt
git add app/src/test/java/com/androdr/sigma/SigmaRuleFeedTest.kt
git commit -m "feat: extract parseManifest in SigmaRuleFeed, support subdirectory paths

Manifest (rules.txt) can now contain paths like
rules/production/app_risk/androdr-060.yml alongside flat filenames.
Comments (lines starting with #) are filtered out."
```

---

### Task 11: End-to-End Integration Test

**Files:**
- No new files — this task tests the full skill chain

**Context:** AndroDR repo. Verify the dispatcher skill is discoverable and the sub-agent flow works.

- [ ] **Step 1: Verify all skills are discoverable**

```bash
ls -la .claude/commands/update-rules*.md
```
Expected: 12 files:
```
update-rules.md
update-rules-ingest-abusech.md
update-rules-ingest-asb.md
update-rules-ingest-nvd.md
update-rules-ingest-amnesty.md
update-rules-ingest-citizenlab.md
update-rules-ingest-stalkerware.md
update-rules-ingest-attack.md
update-rules-research-threat.md
update-rules-author.md
update-rules-validate.md
update-rules-review.md
```

- [ ] **Step 2: Verify sigma repo scaffolding**

Check that all directories and files exist in the public sigma repo:
```bash
ls rules/production/ rules/staging/ ioc-data/ validation/ docs/ feed-state.json rules.txt
```

- [ ] **Step 3: Verify validation script runs**

```bash
cd [sigma-repo-path]
python3 validation/validate-rule.py [path-to-any-existing-androdr-rule.yml]
```
Expected: `PASS: [filename]`

- [ ] **Step 4: Run a dry test invocation**

Invoke `/update-rules source stalkerware` (stalkerware-indicators is a small, public repo — good for testing). Verify:
1. Dispatcher reads feed-state.json
2. Stalkerware ingester fetches indicators
3. SIRs are produced
4. Rule Author generates candidate rules
5. Validator runs all 5 gates
6. Presenter shows formatted output
7. User can approve/reject

This is a manual smoke test. Document any issues found and fix them.

- [ ] **Step 5: Commit any fixes from integration testing**

```bash
git add -A
git commit -m "fix: address issues found during integration testing"
```
(Only if fixes were needed.)
