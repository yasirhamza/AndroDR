# Broker-SDK SIR Research Pass Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Produce 8 per-SDK Structured Intelligence Records (SIRs) as JSON artifacts that the next session's `update-rules-author` invocation will consume to build the `installed_app` rule pack for data-broker SDKs.

**Architecture:** Eight parallel `Agent` dispatches invoking the `update-rules-research-threat` skill, one per SDK. Each subagent writes a single SIR JSON to a fixed path. After all eight return, two reviewer agents (spec-compliance + harsh-quality) run in parallel; failures trigger targeted re-dispatch. Final artifacts commit to the topic branch and ship via PR.

**Tech Stack:** Markdown spec + JSON SIR artifacts. No Kotlin, no YAML rules. Tooling: Agent tool (parallel subagent dispatch), WebSearch/WebFetch (inside subagents), git/gh CLI for PR.

**Spec:** [`docs/superpowers/specs/2026-05-18-broker-sdk-sir-research-design.md`](../specs/2026-05-18-broker-sdk-sir-research-design.md)

**Topic branch:** `feat/168-broker-sdk-sirs` (already created; spec already committed as `138971c`).

---

## File Structure

**To be created in this plan:**

```
docs/superpowers/research/2026-05-18-broker-sdks/
├── README.md                  # Index pointing to spec, scanner spec, SIRs, #168
├── outlogic.json              # Subagent 1 output
├── venntel.json               # Subagent 2 output
├── mobilewalla.json           # Subagent 3 output
├── adsquare.json              # Subagent 4 output
├── predicio.json              # Subagent 5 output
├── cuebiq.json                # Subagent 6 output
├── gravy-analytics.json       # Subagent 7 output (aggregator, requires_verification:true)
└── babel-street.json          # Subagent 8 output (consumer, requires_verification:true)
```

**Already in place:**

- `docs/superpowers/specs/2026-05-18-broker-sdk-sir-research-design.md` — committed
- `.claude/commands/update-rules-research-threat.md` — skill body to embed in subagent prompts

**Not in scope:**

- No Kotlin source files touched
- No YAML SIGMA rules authored
- No changes to `android-sigma-rules` submodule
- No changes to `feed-state.json` (off-pipeline pass)

---

### Task 1: Create the research directory with a placeholder README

**Why:** Subagents in Task 2 each write to a fixed path; the parent directory must exist. The placeholder README is fleshed out in Task 3 once the SIRs are known.

**Files:**
- Create: `docs/superpowers/research/2026-05-18-broker-sdks/README.md`

- [ ] **Step 1: Create the directory**

Run: `mkdir -p docs/superpowers/research/2026-05-18-broker-sdks`
Expected: directory exists; `ls` shows it empty.

- [ ] **Step 2: Write the placeholder README**

Path: `docs/superpowers/research/2026-05-18-broker-sdks/README.md`

```markdown
# Data-broker SDK SIRs — research pass 2026-05-18

Structured Intelligence Records (SIRs) for the 8 entities named in issue #168,
produced as input to the future `installed_app` rule pack (6 SDKs) and the
future `dns` rule pack (2 aggregators).

**Status:** in progress — SIR files are written by parallel research-threat
subagents per the implementation plan.

**Spec:** [../../specs/2026-05-18-broker-sdk-sir-research-design.md](../../specs/2026-05-18-broker-sdk-sir-research-design.md)
**Scanner prereq:** [../../specs/2026-05-17-data-broker-sdk-scanner-design.md](../../specs/2026-05-17-data-broker-sdk-scanner-design.md)
**Issue:** [#168](https://github.com/yasirhamza/AndroDR/issues/168)

Once all SIRs are written and reviewed, this README will be replaced with a per-file index.
```

- [ ] **Step 3: Verify**

Run: `ls -la docs/superpowers/research/2026-05-18-broker-sdks/`
Expected: only `README.md` present.

- [ ] **Step 4: Commit**

Run:
```bash
git add docs/superpowers/research/2026-05-18-broker-sdks/README.md
git commit -m "$(cat <<'EOF'
docs(#168): scaffold broker-SDK SIR research directory

Placeholder README; SIRs land in Task 2.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 2: Dispatch 8 parallel research-threat subagents

**Why:** Each SDK has independent research surface; parallel dispatch is mandatory (no shared state, no ordering dependency). This single message produces all 8 SIR JSON files.

**Files:**
- Create: `docs/superpowers/research/2026-05-18-broker-sdks/outlogic.json` (subagent writes)
- Create: `docs/superpowers/research/2026-05-18-broker-sdks/venntel.json` (subagent writes)
- Create: `docs/superpowers/research/2026-05-18-broker-sdks/mobilewalla.json` (subagent writes)
- Create: `docs/superpowers/research/2026-05-18-broker-sdks/adsquare.json` (subagent writes)
- Create: `docs/superpowers/research/2026-05-18-broker-sdks/predicio.json` (subagent writes)
- Create: `docs/superpowers/research/2026-05-18-broker-sdks/cuebiq.json` (subagent writes)
- Create: `docs/superpowers/research/2026-05-18-broker-sdks/gravy-analytics.json` (subagent writes)
- Create: `docs/superpowers/research/2026-05-18-broker-sdks/babel-street.json` (subagent writes)

- [ ] **Step 1: Read the skill body to embed**

Read the full contents of `.claude/commands/update-rules-research-threat.md`. This text is embedded verbatim into each subagent prompt.

- [ ] **Step 2: Build the per-SDK brief table**

Use exactly these brief values when constructing the 8 prompts:

| Slug | threat.name to use | Aliases to pass | Type | requires_verification baseline |
|---|---|---|---|---|
| outlogic | Outlogic | X-Mode Social, X-Mode | SDK | false (revise to true if only 1 unstructured source) |
| venntel | Venntel | Venntel Mobile, Loud Mobile | SDK | false (revise to true if only 1 unstructured source) |
| mobilewalla | Mobilewalla | — | SDK | false (revise to true if only 1 unstructured source) |
| adsquare | Adsquare | — | SDK | false (revise to true if only 1 unstructured source) |
| predicio | Predicio | — | SDK | false (revise to true if only 1 unstructured source) |
| cuebiq | Cuebiq | — | SDK | false (revise to true if only 1 unstructured source) |
| gravy-analytics | Gravy Analytics | Unacast (merged) | Aggregator | **true** (mandatory — no on-device collector of its own) |
| babel-street | Babel Street | LocateX | Consumer | **true** (mandatory — buys broker data, no on-device collector) |

- [ ] **Step 3: Dispatch all 8 subagents in a single message**

Use 8 `Agent` tool calls in one message (true parallelism). For each, use `subagent_type: "general-purpose"` and this prompt template (substituting the per-SDK row from Step 2):

```
You are a threat researcher producing one Structured Intelligence Record (SIR) for "<threat.name>" (also known as: <aliases or "no known aliases">).

This is an off-pipeline research pass for AndroDR issue #168 (data-broker SDK detection). The SIR you produce will feed the future `installed_app` rule pack (for SDKs) or `dns` rule pack (for aggregators/consumers).

# Skill instructions (follow these exactly):

<full verbatim contents of .claude/commands/update-rules-research-threat.md>

# Project-specific overrides (override the skill where they conflict):

1. Output a SINGLE SIR object, NOT the {sirs:[...], updated_cursors:{}} envelope. Write only one JSON object.
2. Include these provenance fields at the top level:
   - "provenance": {
       "vendor_page": "<URL or null>",
       "independent_sources": ["<url1>", "<url2>", ...]   // length >= 1
     }
3. For each indicator, include "source_urls": [<url1>, ...] so the rule author can cite specific provenance per indicator.
4. If <type> is "Aggregator" or "Consumer", set "requires_verification": true at the top level. Acknowledge in threat.description that no on-device collector is known; indicators should be DNS-shaped (telemetry hostnames) or behavioral_signals only. Do NOT invent embedded_component_class or embedded_native_lib indicators for these entries.
5. If the SDK type is "SDK" and you find <2 sources total, set "requires_verification": true.

# Write target:

Write the SIR JSON to: docs/superpowers/research/2026-05-18-broker-sdks/<slug>.json

Use pretty-printed JSON (2-space indent) so the file diffs cleanly.

# Hard rules (lifted from the skill body — do not violate):

- Never invent IOCs. If a source says "the SDK contacts a backend" but does not name the host, do NOT make one up.
- Only extract IOCs from sources you fetched during this dispatch.
- Never include IOCs from your training data.
- Tag every IOC with the source URL it came from.

# Return value:

Return the full JSON object you wrote, plus one line of the form:
"Confidence: <high|medium>; on-device anchors: <N component classes, M native libs>; sources: <K URLs>."
```

- [ ] **Step 4: Verify all 8 files were written**

Run: `ls -la docs/superpowers/research/2026-05-18-broker-sdks/*.json | wc -l`
Expected: `8`

Run: `ls docs/superpowers/research/2026-05-18-broker-sdks/*.json`
Expected: all 8 slugs from Step 2 are present.

- [ ] **Step 5: Verify each file is valid JSON**

Run:
```bash
for f in docs/superpowers/research/2026-05-18-broker-sdks/*.json; do
  python3 -c "import json; json.load(open('$f'))" && echo "OK: $f" || echo "INVALID: $f"
done
```
Expected: 8 lines, all `OK:`.

- [ ] **Step 6: Spot-check the aggregator SIRs have requires_verification:true**

Run:
```bash
python3 -c "import json; \
print('gravy:', json.load(open('docs/superpowers/research/2026-05-18-broker-sdks/gravy-analytics.json')).get('requires_verification')); \
print('babel:', json.load(open('docs/superpowers/research/2026-05-18-broker-sdks/babel-street.json')).get('requires_verification'))"
```
Expected: both print `True`.

If either is `False` or missing, the subagent didn't honor the mandatory override. Re-dispatch that specific subagent before proceeding.

- [ ] **Step 7: Do NOT commit yet**

The two-reviewer cycle in Task 4 may reject SIRs and trigger re-dispatch. Commit happens only after reviews pass (Task 6).

---

### Task 3: Write the final README index

**Why:** Replace the placeholder from Task 1 with a per-file index summarizing what each SIR contains. Done after Task 2 so the summary reflects the actual SIR content.

**Files:**
- Modify: `docs/superpowers/research/2026-05-18-broker-sdks/README.md`

- [ ] **Step 1: Extract a one-line summary per SIR**

For each of the 8 JSON files, read and produce a one-line summary of the form:
`<slug>.json — <threat.name>: <confidence>; <N on-device anchors / DNS-only>; verify:<true|false>`

Example: `outlogic.json — Outlogic: high confidence; 3 component-class prefixes, 1 native lib; verify:false`

- [ ] **Step 2: Overwrite the README**

Path: `docs/superpowers/research/2026-05-18-broker-sdks/README.md`

```markdown
# Data-broker SDK SIRs — research pass 2026-05-18

Structured Intelligence Records (SIRs) for the 8 entities named in issue #168,
produced as input to the future `installed_app` rule pack (6 SDKs) and the
future `dns` rule pack (2 aggregators).

## Files

### SDKs (anchor the future `installed_app` rule pack)

- [`outlogic.json`](outlogic.json) — <one-line summary from Step 1>
- [`venntel.json`](venntel.json) — <one-line summary from Step 1>
- [`mobilewalla.json`](mobilewalla.json) — <one-line summary from Step 1>
- [`adsquare.json`](adsquare.json) — <one-line summary from Step 1>
- [`predicio.json`](predicio.json) — <one-line summary from Step 1>
- [`cuebiq.json`](cuebiq.json) — <one-line summary from Step 1>

### Aggregators / consumers (anchor the future `dns` rule pack)

- [`gravy-analytics.json`](gravy-analytics.json) — <one-line summary from Step 1>
- [`babel-street.json`](babel-street.json) — <one-line summary from Step 1>

## References

- **Spec:** [../../specs/2026-05-18-broker-sdk-sir-research-design.md](../../specs/2026-05-18-broker-sdk-sir-research-design.md)
- **Scanner prereq (PR #183):** [../../specs/2026-05-17-data-broker-sdk-scanner-design.md](../../specs/2026-05-17-data-broker-sdk-scanner-design.md)
- **Issue:** [#168](https://github.com/yasirhamza/AndroDR/issues/168)

## Handoff

Next session opens `update-rules-author` against the 6 SDK SIRs to produce the
`installed_app` rule pack. The 2 aggregator SIRs sit unused until the
future `dns` rule pack session opens.
```

Replace the `<one-line summary from Step 1>` placeholders with the actual extracted summaries.

- [ ] **Step 3: Verify**

Run: `cat docs/superpowers/research/2026-05-18-broker-sdks/README.md`
Expected: no `<...>` placeholders remain; 8 file-links present.

---

### Task 4: Two-reviewer cycle (parallel)

**Why:** Project standing rule — every implementation goes through both reviewers in parallel. Reviewers gate the commit; failures trigger Task 5.

**Files:** No files modified by reviewers. They produce written reports as tool-result return values.

- [ ] **Step 1: Dispatch both reviewers in a single message**

Use 2 `Agent` tool calls in one message. Both use `subagent_type: "general-purpose"`.

**Reviewer A — Spec compliance.** Prompt:

```
You are the spec-compliance reviewer for the broker-SDK SIR research pass.

Spec: docs/superpowers/specs/2026-05-18-broker-sdk-sir-research-design.md
Artifacts: docs/superpowers/research/2026-05-18-broker-sdks/*.json (8 files)

For each of the 8 SIR JSON files, verify:

1. File exists at the expected path with the expected slug.
2. `source.feed == "threat_research"`.
3. Required keys are present (read the schema table in the spec).
4. `provenance.independent_sources` is an array of length >= 1.
5. Per-IOC `source_urls` arrays are present on every entry in `indicators[]`.
6. `confidence` is `"high"` or `"medium"` (no `"low"`, no other values).
7. `requires_verification` is `true` for `gravy-analytics.json` AND `babel-street.json` (mandatory regardless of source count).
8. No envelope wrapper (each file holds a single SIR object at the top level, NOT `{sirs:[...], updated_cursors:{}}`).
9. File is valid JSON (parses cleanly).

After the per-file pass, also check the COHORT-LEVEL acceptance criterion:

10. Of the 6 SDK SIRs (outlogic, venntel, mobilewalla, adsquare, predicio, cuebiq), at least 4 must contain >= 1 concrete on-device anchor — meaning at least one `indicators[]` entry with type `embedded_component_class` (a class-name prefix) OR `embedded_native_lib` (a `.so` filename). SDKs with 0 anchors must have `requires_verification: true` and behavioral_signals[] non-empty. If fewer than 4 of the 6 SDKs are anchored, flag the cohort FAIL.

Output a per-file PASS/FAIL plus the cohort-level result, plus a short bulleted list of any failures. Do NOT modify files.
```

**Reviewer B — Harsh quality.** Prompt:

```
You are the harsh-quality reviewer for the broker-SDK SIR research pass. Be skeptical. Your job is to catch fabrication, sloppy claims, and vague writing that the spec-compliance check would let through.

Spec: docs/superpowers/specs/2026-05-18-broker-sdk-sir-research-design.md
Artifacts: docs/superpowers/research/2026-05-18-broker-sdks/*.json (8 files)

For each SIR:

1. Spot-check 2 random indicators against their cited `source_urls`. Use WebFetch to retrieve the source. Does the source actually contain the indicator? If not, flag fabrication.
2. Look for class-name prefixes or native-lib filenames that "smell right" but don't appear in any cited source. These are the highest-risk fabrications because they look authoritative.
3. If a SIR with `type: SDK` claims `confidence: "high"` but only cites one source URL, flag it — confidence should be `medium` and `requires_verification: true`.
4. Read `threat.description` — does it actually describe broker-pipeline behavior, or is it LLM filler? Flag descriptions that could apply to any ad-tech SDK.
5. Read `behavioral_signals[]` — is each entry concrete enough to anchor a future SIGMA rule, or vague ("collects location data")?
6. For the 2 aggregator SIRs (gravy-analytics, babel-street): confirm they do NOT claim embedded_component_class or embedded_native_lib indicators (those would be invented — these entities don't ship SDKs).

Output a per-file VERDICT (PASS, ACCEPTABLE, REJECT) with reasoning. REJECT means re-dispatch is required. Do NOT modify files.
```

- [ ] **Step 2: Collect both reviewer reports**

Wait for both Agent calls to return. Read both reports.

- [ ] **Step 3: Classify outcome**

- If both reviewers return PASS/ACCEPTABLE for all 8 SIRs → proceed to Task 6.
- If either reviewer flags any SIR as FAIL/REJECT → proceed to Task 5.

---

### Task 5: Fix-and-recheck loop (conditional — only if Task 4 flagged issues)

**Why:** Reviewer-flagged SIRs need targeted re-research, not a full re-dispatch. Bounded loop prevents infinite cycles.

**Files:** Re-writes only the SIR JSONs that were flagged.

- [ ] **Step 1: Build the re-dispatch list**

For each SIR flagged by either reviewer, record:
- Slug
- Reviewer feedback (verbatim, bulleted)

- [ ] **Step 2: Re-dispatch only the flagged SDKs**

Send one message with N parallel `Agent` calls (where N = number of flagged SIRs). Each prompt uses the same template as Task 2 Step 3, with an additional section at the end:

```
# Reviewer feedback to address

The previous SIR you produced for <threat.name> was flagged by reviewers. Address each item below and re-write the file:

<verbatim reviewer feedback>

Specifically:
- If a fabricated indicator was flagged, REMOVE IT or replace it with a real one citing a real source URL fetched during this dispatch.
- If confidence was downgraded, set `confidence: "medium"` and `requires_verification: true`.
- If description was LLM-filler, rewrite anchored on the actual broker-pipeline role from the cited sources.

Overwrite docs/superpowers/research/2026-05-18-broker-sdks/<slug>.json with the corrected SIR.
```

- [ ] **Step 3: Re-run the reviewer cycle on only the changed files**

Re-dispatch both reviewers as in Task 4 Step 1, but scope their work to the slugs in Step 1's list.

- [ ] **Step 4: Loop guard**

If the same SIR fails the second review, STOP. Do not loop again. Report to the user with the reviewer feedback and ask whether to drop the SDK from this pass, manually edit, or accept the SIR with `requires_verification: true` as a mitigation. Each SDK gets at most 2 attempts (initial + one re-dispatch).

---

### Task 6: Commit the SIR artifacts

**Files:** Stages the 9 new files (8 JSON + README) on the existing `feat/168-broker-sdk-sirs` branch.

- [ ] **Step 1: Confirm we're on the right branch**

Run: `git branch --show-current`
Expected: `feat/168-broker-sdk-sirs`

If not, run: `git checkout feat/168-broker-sdk-sirs`

- [ ] **Step 2: Stage the new files**

Run:
```bash
git add docs/superpowers/research/2026-05-18-broker-sdks/
git status
```
Expected: `git status` shows 8 JSON files + README.md staged under `docs/superpowers/research/2026-05-18-broker-sdks/`. (README was staged in Task 1; this also includes the rewrite from Task 3.)

- [ ] **Step 3: Commit**

Run:
```bash
git commit -m "$(cat <<'EOF'
docs(#168): research-pass SIRs for 8 data-broker entities

Six on-device SDKs (Outlogic, Venntel, Mobilewalla, Adsquare, Predicio,
Cuebiq) and two aggregators (Gravy Analytics, Babel Street) as JSON SIRs
for the next session's installed_app rule-pack authoring.

Both reviewer cycles (spec-compliance, harsh-quality) passed.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

- [ ] **Step 4: Verify**

Run: `git log -2 --pretty=format:'%h %s'`
Expected: the latest commit is this one; the previous is the spec commit (`138971c`).

---

### Task 7: Open the PR

**Files:** No file changes. GitHub side-effect only.

- [ ] **Step 1: Push the branch**

Run: `git push -u origin feat/168-broker-sdk-sirs`
Expected: branch published; tracking set.

- [ ] **Step 2: Create the PR**

Run:
```bash
gh pr create --title "docs(#168): broker-SDK SIR research pass" --body "$(cat <<'EOF'
## Summary
- Spec + 8 per-SDK SIR JSONs for the data-broker detection arc (issue #168).
- 6 SDK SIRs (Outlogic, Venntel, Mobilewalla, Adsquare, Predicio, Cuebiq) feed the future `installed_app` rule pack.
- 2 aggregator SIRs (Gravy Analytics, Babel Street/LocateX) feed the future `dns` rule pack; both flagged `requires_verification: true` by design.
- No code or YAML rules in this PR — research artifacts only.

Part of #168 (does not close — rule-pack authoring is the next session).

## Test plan
- [x] Each SIR validates as JSON (`python3 -c "import json; json.load(...)"`).
- [x] Spec-compliance reviewer agent passed all 8 SIRs.
- [x] Harsh-quality reviewer agent passed all 8 SIRs (or accepted with documented `requires_verification: true`).
- [x] Aggregator SIRs confirm no `embedded_component_class` / `embedded_native_lib` claims.

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
)"
```

- [ ] **Step 3: Capture the PR URL**

The previous command prints the PR URL. Record it for Task 8.

---

### Task 8: Admin-merge (per project CI-wait pattern)

**Why:** Per project convention, admin-merge after local checks pass; CI wait is out of budget on this VM and adds no signal for a docs-only PR.

**Files:** No file changes. GitHub side-effect only.

- [ ] **Step 1: Confirm CI "build" check status**

For a docs-only PR (no Kotlin, no YAML), CI build is irrelevant but the user's standing rule says we still wait for "build" to pass. Check:

Run: `gh pr checks <PR-number>`
Expected: either `build` is `pass` or there are no required gradle checks for a docs-only diff. If anything is `fail`, STOP and investigate.

- [ ] **Step 2: Merge**

Run: `gh pr merge <PR-number> --squash --admin --delete-branch`
Expected: merge succeeds, branch deleted on remote and locally.

- [ ] **Step 3: Verify on main**

Run:
```bash
git checkout main
git pull
ls docs/superpowers/research/2026-05-18-broker-sdks/
```
Expected: README.md + 8 JSON files present on `main`.

---

## Definition of done

- 8 SIR JSON files committed under `docs/superpowers/research/2026-05-18-broker-sdks/`, each conforming to the spec schema.
- README.md is a real index (not the Task 1 placeholder).
- Both reviewer cycles passed (or any remaining `requires_verification: true` flags are intentional and documented).
- PR merged to `main` via admin-merge after the build check is green.
- The next session can `cat docs/superpowers/research/2026-05-18-broker-sdks/*.json | jq -s` to get a JSON array suitable for `update-rules-author`.
