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

## Required environment

Runs from a terminal shell; subagents inherit the parent session's environment via WebFetch. Before dispatching any ingester, verify the required vars are present:

| Feed | Env var | Requirement |
|---|---|---|
| abusech (ThreatFox + MalwareBazaar) | `MALWAREBAZAAR_API_KEY` | **Required** — the single abuse.ch Auth-Key covers both endpoints. HTTP 401 without it. |
| asb (Android Security Bulletin) | — | None (public HTML) |
| nvd | `NVD_API_KEY` | **Optional** — raises anon rate limit from 5 req/30s to 50 req/30s. Weekly cadence works anonymously. |
| amnesty, stalkerware, citizenlab, attack (GitHub-based) | `GITHUB_TOKEN` | **Optional** — raises anon GitHub API limit from 60/hr to 5000/hr. Weekly cadence works anonymously. |

**Abort the full-sweep run** if `MALWAREBAZAAR_API_KEY` is missing when `abusech` is in the dispatch set. A single-feed invocation (`/update-rules source asb`, `/update-rules source amnesty`, etc.) that doesn't need abusech should proceed regardless.

Note: `virustotal` is listed in `allowed-sources.json` as a valid provenance label but no ingester currently calls the VT API. `VIRUSTOTAL_API_KEY` is not needed today.

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

**Before dispatching the Rule Author**, read the logsource field taxonomy:
1. Read `android-sigma-rules/validation/logsource-taxonomy.yml`
2. Identify which services are relevant based on the SIRs' `rule_hint` values:
   - `ioc_lookup` → `app_scanner` (package names), `dns_monitor` (domains)
   - `behavioral` → `app_scanner`, `accessibility_audit`, `appops_audit`, `receiver_audit`
   - `device_posture` → `device_auditor`
   - `network` → `dns_monitor` (skip `network_monitor` — `status: unwired` per taxonomy)
   - `hybrid` → include all of the above
3. **Filter out services with `status: unwired`** before extracting fields — rules targeting them cannot fire. The Rule Author will record a `telemetry_gap` decision if the SIR requires such a service.
4. Extract the `fields:` blocks for the remaining services

Pass all valid SIRs to the Rule Author agent (`update-rules-author`) along with:
- The next available rule ID
- 5 existing production rules as style examples (pick diverse services/types)
- The existing rule index (for dedup awareness)
- **The extracted taxonomy field lists for relevant services** (injected into the prompt context so the Rule Author doesn't need to read the file itself)

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

### 7.1 IOC-only candidates (added for #117)

Some candidates from Step 6.5 have no accompanying rule — they're pure IOC
data targeting the generic `sigma_androdr_001_package_ioc`,
`_002_cert_hash_ioc`, `_003_domain_ioc`, or `_004_apk_hash_ioc` rules,
which match anything in their lookup DB. Present these as first-class
approval candidates:

```
IOC-ONLY CANDIDATE — via androdr-NNN generic ioc_lookup rule
Target file:  ioc-data/<file>.yml
Type:         <type>
Source:       <source-id>
Indicator(s): <count>
  - <indicator 1>  (<family>, <severity>)
  - <indicator 2>  ...
  [...]
```

User actions for an IOC-only candidate: same as for a rule candidate —
**Approve**, **Modify** (edit entries), or **Reject**.

## Step 8: Process User Decisions

For each passing candidate, ask the user to:
- **Approve** — write the rule to `rules/staging/[category]/` in the sigma repo, commit
- **Modify** — apply user's changes, re-validate, then write
- **Reject** — discard, log reason

After all decisions:
- Update `feed-state.json` with new cursors from ingesters. Strip any extra keys that aren't declared in `third-party/android-sigma-rules/validation/feed-state-schema.json` — the schema uses `additionalProperties: false`.
- **Validate the updated feed-state.json before committing:** run `python3 third-party/android-sigma-rules/validation/validate-feed-state.py`. If it exits non-zero, abort the run and report the errors. Do not commit a state that fails validation.
- Update `ioc-data/*.yml` files if ingesters found new indicators
- Commit all changes to the sigma repo with descriptive messages

### 8.1 Commit IOC candidates (added for #117)

For each approved candidate (rule OR IOC-only):

1. Append approved IOC entries to the target `ioc-data/<file>.yml` file.
   Preserve the file's header; append entries under the existing
   `entries:` list.

2. Run validators on every touched file. Abort the commit on any failure:
   ```bash
   cd third-party/android-sigma-rules
   python3 validation/validate-ioc-data.py ioc-data/<file>.yml
   python3 validation/validate-ioc-complementarity.py --file ioc-data/<file>.yml --mode strict
   ```
   If either validator exits non-zero, revert the append and report to the
   user. Do NOT commit.

3. Update `feed-state.json`: for each ingester that contributed approved
   candidates, set its `ioc_data_last_write` to the current ISO 8601
   timestamp (the schema supports this as an optional field per cursor).

4. Commit the ioc-data change(s) + rule change(s) + feed-state update as
   a single atomic commit. Commit message format:
   ```
   feat(rules+ioc): add <threat-name> (source: <source-id>) [Phase 4 of #117]
   ```

### 8.2 Safety rules

- NEVER commit an ioc-data write that validate-ioc-complementarity.py
  rejects in strict mode.
- NEVER pass --allow-upstream-unreachable in automated
  (non-interactive) pipeline runs; it's for operator-controlled retry
  only.
- NEVER modify `kotlin-mirror-feeds.yml` in the same commit as an
  ioc-data write.

## Safety Rules

- NEVER write rules directly to `rules/production/` — staging only
- NEVER set `status` to anything other than `experimental` for AI-generated rules
- NEVER modify AndroDR application code (Kotlin sources)
- NEVER commit API keys or credentials to any file
- Report feed failures separately from "no new data" results
- NEVER commit an ioc-data/*.yml write that validate-ioc-complementarity.py rejects
- NEVER pass --allow-upstream-unreachable in automated pipeline runs
- NEVER modify kotlin-mirror-feeds.yml in the same commit as an ioc-data write
