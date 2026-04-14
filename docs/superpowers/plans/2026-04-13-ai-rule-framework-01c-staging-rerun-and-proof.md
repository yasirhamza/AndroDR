# Sub-plan 1c: Staging Rerun + End-to-End Proof

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Re-validate 5 staging rules, decide promote/reject for each, run `/update-rules source stalkerware` end-to-end, and promote at least one AI-generated rule to production — proving the full pipeline works.

**Architecture:** Fix staging rules to pass the updated validator (add top-level `category`, renumber ID collision), write Gate 4 fixtures for promoted rules, copy to `app/src/main/res/raw/`, run Gradle gate. Then run the `/update-rules` skill for a live stalkerware feed ingest + rule generation cycle.

**Tech Stack:** YAML rule files, Python validator (`validate-rule.py`), Kotlin Gate 4 harness + Gradle build gate (`BundledRulesSchemaCrossCheckTest`), `/update-rules` AI skill pipeline.

**Tracking:** Epic #104, issue #107. PR closes #107.

---

## File Map

| Action | Path | Responsibility |
|--------|------|----------------|
| Modify | `third-party/android-sigma-rules/staging/app_scanner/androdr_071_popular_app_impersonation.yml` | Renumber ID 071→077, add top-level `category` |
| Modify | `third-party/android-sigma-rules/staging/app_scanner/androdr_069_overlay_permission.yml` | Add top-level `category`, demote level to medium |
| Modify | `third-party/android-sigma-rules/staging/device_auditor/androdr_051_cellebrite_cves.yml` | Add top-level `category` |
| Modify | `third-party/android-sigma-rules/staging/dns_monitor/androdr_070_ddns_c2.yml` | Add top-level `category` |
| Modify | `third-party/android-sigma-rules/staging/receiver_audit/androdr_066_boot_persistence.yml` | Add top-level `category`, demote level to low |
| Copy→Create | `app/src/main/res/raw/sigma_androdr_051_cellebrite_cves.yml` | Promoted staging rule |
| Copy→Create | `app/src/main/res/raw/sigma_androdr_070_ddns_c2.yml` | Promoted staging rule |
| Copy→Create | `app/src/main/res/raw/sigma_androdr_069_overlay_permission.yml` | Promoted staging rule |
| Copy→Create | `app/src/main/res/raw/sigma_androdr_066_boot_persistence.yml` | Promoted staging rule |
| Copy→Create | `app/src/main/res/raw/sigma_androdr_077_popular_app_impersonation.yml` | Promoted staging rule (renumbered from 071) |
| Create | `app/src/test/resources/gate4-fixtures/cellebrite-cves.yml` | Gate 4 fixture for androdr-051 |
| Create | `app/src/test/resources/gate4-fixtures/ddns-c2.yml` | Gate 4 fixture for androdr-070 |
| Create | `app/src/test/resources/gate4-fixtures/overlay-permission.yml` | Gate 4 fixture for androdr-069 |
| Create | `app/src/test/resources/gate4-fixtures/boot-persistence.yml` | Gate 4 fixture for androdr-066 |
| Create | `app/src/test/resources/gate4-fixtures/popular-app-impersonation.yml` | Gate 4 fixture for androdr-077 |
| Create | `docs/decisions/2026-04-13-staging-rule-triage.md` | Decision log for all 5 staging rules |
| Create | Gate 4 fixture(s) for any rules produced by `/update-rules` run | TBD path — depends on rule output |
| Copy→Create | `app/src/main/res/raw/sigma_androdr_NNN_*.yml` | At least one rule from `/update-rules` run |
| Modify | `third-party/android-sigma-rules/feed-state.json` | Updated cursor after stalkerware feed ingest |

---

## Staging Rule Triage Decisions

Based on rule analysis against the updated validator and schema:

| Rule | ID | Decision | Rationale |
|------|-----|----------|-----------|
| Cellebrite CVEs | 051 | **Promote** | Specific CVE-based detection, strong references (Amnesty International), critical severity justified. Just needs top-level `category: device_posture`. |
| DDNS C2 | 070 | **Promote** | `domain\|endswith` is correct for DDNS suffixes (not individual IOCs — `ioc_lookup` would be wrong here). Comprehensive provider list. Needs top-level `category: incident`. |
| Overlay Permission | 069 | **Promote at medium** | Combined with sideload + known-good filter, this is a useful signal. Demote from `high` to `medium` — overlay permission alone is common. Needs `category: incident`. |
| Boot Persistence | 066 | **Promote at low** | Boot receivers are extremely common among legitimate apps, but with known-good filter it adds triage value. Demote from `medium` to `low`. Needs `category: incident`. |
| Popular App Impersonation | 071→077 | **Renumber + Promote** | ID collides with production `crash_loop_anti_forensics`. Renumber to 077 (next available). Solid detection — sideloaded + prefix match + known-good filter. Needs `category: incident`. |

**All 5 rules are missing the top-level `category` field** (required since sub-plan 1a synced the schema). This is the expected failure — staging rules predate the schema update.

---

## Task 1: Branch Setup + Initial Validation Baseline

**Files:**
- Read: all 5 staging rules, `validate-rule.py`, `rule-schema.json`

- [ ] **Step 1: Create feature branch**

```bash
git checkout claude/android-edr-setup-rl68Y
git pull origin claude/android-edr-setup-rl68Y
git checkout -b feat/107-staging-rerun-e2e-proof
```

- [ ] **Step 2: Run Python validator against all 5 staging rules to document baseline failures**

```bash
cd third-party/android-sigma-rules
python3 validation/validate-rule.py staging/device_auditor/androdr_051_cellebrite_cves.yml
python3 validation/validate-rule.py staging/dns_monitor/androdr_070_ddns_c2.yml
python3 validation/validate-rule.py staging/app_scanner/androdr_069_overlay_permission.yml
python3 validation/validate-rule.py staging/receiver_audit/androdr_066_boot_persistence.yml
python3 validation/validate-rule.py staging/app_scanner/androdr_071_popular_app_impersonation.yml
cd ../..
```

Expected: All 5 FAIL with "Missing required field: category". Rule 071 may also fail on ID collision if the validator checks uniqueness (it doesn't currently, but document the observation).

- [ ] **Step 3: Record the baseline failures** (note exact error messages for the decision log)

---

## Task 2: Fix Staging Rules — Add Top-Level `category` and Renumber 071

**Files:**
- Modify: `third-party/android-sigma-rules/staging/device_auditor/androdr_051_cellebrite_cves.yml`
- Modify: `third-party/android-sigma-rules/staging/dns_monitor/androdr_070_ddns_c2.yml`
- Modify: `third-party/android-sigma-rules/staging/app_scanner/androdr_069_overlay_permission.yml`
- Modify: `third-party/android-sigma-rules/staging/receiver_audit/androdr_066_boot_persistence.yml`
- Modify: `third-party/android-sigma-rules/staging/app_scanner/androdr_071_popular_app_impersonation.yml`

- [ ] **Step 1: Add `category: device_posture` to androdr-051 (Cellebrite CVEs)**

Insert after `status: experimental`:

```yaml
category: device_posture
```

- [ ] **Step 2: Add `category: incident` to androdr-070 (DDNS C2)**

Insert after `status: experimental`:

```yaml
category: incident
```

- [ ] **Step 3: Add `category: incident` to androdr-069 (overlay permission) and demote level**

Insert after `status: experimental`:

```yaml
category: incident
```

Change `level: high` to `level: medium`.

- [ ] **Step 4: Add `category: incident` to androdr-066 (boot persistence) and demote level**

Insert after `status: experimental`:

```yaml
category: incident
```

Change `level: medium` to `level: low`.

- [ ] **Step 5: Renumber androdr-071 → androdr-077 (popular app impersonation)**

In `third-party/android-sigma-rules/staging/app_scanner/androdr_071_popular_app_impersonation.yml`:

Change `id: androdr-071` to `id: androdr-077`.

Add after `status: experimental`:

```yaml
category: incident
```

Rename the file:

```bash
cd third-party/android-sigma-rules/staging/app_scanner
git mv androdr_071_popular_app_impersonation.yml androdr_077_popular_app_impersonation.yml
cd ../../../..
```

- [ ] **Step 6: Re-run validator on all 5 fixed rules**

```bash
cd third-party/android-sigma-rules
python3 validation/validate-rule.py staging/device_auditor/androdr_051_cellebrite_cves.yml
python3 validation/validate-rule.py staging/dns_monitor/androdr_070_ddns_c2.yml
python3 validation/validate-rule.py staging/app_scanner/androdr_069_overlay_permission.yml
python3 validation/validate-rule.py staging/receiver_audit/androdr_066_boot_persistence.yml
python3 validation/validate-rule.py staging/app_scanner/androdr_077_popular_app_impersonation.yml
cd ../..
```

Expected: All 5 PASS.

- [ ] **Step 7: Commit submodule changes**

```bash
cd third-party/android-sigma-rules
git add -A staging/
git commit -m "fix: add top-level category to staging rules, renumber 071→077"
cd ../..
git add third-party/android-sigma-rules
git commit -m "build: bump android-sigma-rules submodule (staging rule fixes)"
```

---

## Task 3: Write Gate 4 Fixtures for All 5 Staging Rules

**Files:**
- Create: `app/src/test/resources/gate4-fixtures/cellebrite-cves.yml`
- Create: `app/src/test/resources/gate4-fixtures/ddns-c2.yml`
- Create: `app/src/test/resources/gate4-fixtures/overlay-permission.yml`
- Create: `app/src/test/resources/gate4-fixtures/boot-persistence.yml`
- Create: `app/src/test/resources/gate4-fixtures/popular-app-impersonation.yml`

- [ ] **Step 1: Create fixture for androdr-051 (Cellebrite CVEs)**

File: `app/src/test/resources/gate4-fixtures/cellebrite-cves.yml`

```yaml
rule_file: sigma_androdr_051_cellebrite_cves.yml
service: device_auditor

true_positives:
  - unpatched_cve_id:
      - "CVE-2024-53104"
      - "CVE-2024-53197"

  - unpatched_cve_id:
      - "CVE-2024-50302"

true_negatives:
  - unpatched_cve_id:
      - "CVE-2023-12345"

  - unpatched_cve_id: []
```

- [ ] **Step 2: Create fixture for androdr-070 (DDNS C2)**

File: `app/src/test/resources/gate4-fixtures/ddns-c2.yml`

```yaml
rule_file: sigma_androdr_070_ddns_c2.yml
service: dns_monitor

true_positives:
  - domain: "evil.duckdns.org"

  - domain: "malware.no-ip.com"

  - domain: "c2.ddns.net"

true_negatives:
  - domain: "www.google.com"

  - domain: "duckdns.org"

  - domain: "example.com"
```

- [ ] **Step 3: Create fixture for androdr-069 (overlay permission)**

File: `app/src/test/resources/gate4-fixtures/overlay-permission.yml`

```yaml
rule_file: sigma_androdr_069_overlay_permission.yml
service: app_scanner

ioc_stubs:
  known_good_app_db:
    - "com.legitimate.overlay"

true_positives:
  - package_name: "com.shady.banker"
    is_system_app: false
    from_trusted_store: false
    permissions:
      - "android.permission.SYSTEM_ALERT_WINDOW"
      - "android.permission.INTERNET"

true_negatives:
  # Known-good app with overlay permission → filtered
  - package_name: "com.legitimate.overlay"
    is_system_app: false
    from_trusted_store: false
    permissions:
      - "android.permission.SYSTEM_ALERT_WINDOW"

  # System app → excluded
  - package_name: "com.android.systemui"
    is_system_app: true
    from_trusted_store: false
    permissions:
      - "android.permission.SYSTEM_ALERT_WINDOW"

  # From trusted store → excluded
  - package_name: "com.playstore.app"
    is_system_app: false
    from_trusted_store: true
    permissions:
      - "android.permission.SYSTEM_ALERT_WINDOW"

  # No overlay permission → excluded
  - package_name: "com.shady.nooverlay"
    is_system_app: false
    from_trusted_store: false
    permissions:
      - "android.permission.INTERNET"
```

- [ ] **Step 4: Create fixture for androdr-066 (boot persistence)**

File: `app/src/test/resources/gate4-fixtures/boot-persistence.yml`

```yaml
rule_file: sigma_androdr_066_boot_persistence.yml
service: receiver_audit

ioc_stubs:
  known_good_app_db:
    - "com.whatsapp"

true_positives:
  - package_name: "com.shady.stalker"
    intent_action: "android.intent.action.BOOT_COMPLETED"
    is_system_app: false

  - package_name: "com.shady.stalker"
    intent_action: "android.intent.action.LOCKED_BOOT_COMPLETED"
    is_system_app: false

true_negatives:
  # Known-good app → filtered
  - package_name: "com.whatsapp"
    intent_action: "android.intent.action.BOOT_COMPLETED"
    is_system_app: false

  # System app → excluded
  - package_name: "com.android.phone"
    intent_action: "android.intent.action.BOOT_COMPLETED"
    is_system_app: true

  # Different intent → excluded
  - package_name: "com.shady.stalker"
    intent_action: "android.intent.action.PACKAGE_ADDED"
    is_system_app: false
```

- [ ] **Step 5: Create fixture for androdr-077 (popular app impersonation, renumbered)**

File: `app/src/test/resources/gate4-fixtures/popular-app-impersonation.yml`

```yaml
rule_file: sigma_androdr_077_popular_app_impersonation.yml
service: app_scanner

ioc_stubs:
  known_good_app_db:
    - "com.whatsapp"

true_positives:
  - package_name: "com.whatsapp.fake"
    is_sideloaded: true

  - package_name: "com.instagram.premium"
    is_sideloaded: true

  - package_name: "org.telegram.mod"
    is_sideloaded: true

true_negatives:
  # Known-good app → filtered
  - package_name: "com.whatsapp"
    is_sideloaded: true

  # Not sideloaded → excluded
  - package_name: "com.whatsapp.fake"
    is_sideloaded: false

  # Unrelated package → excluded
  - package_name: "com.example.myapp"
    is_sideloaded: true
```

- [ ] **Step 6: Commit fixtures**

```bash
git add app/src/test/resources/gate4-fixtures/cellebrite-cves.yml
git add app/src/test/resources/gate4-fixtures/ddns-c2.yml
git add app/src/test/resources/gate4-fixtures/overlay-permission.yml
git add app/src/test/resources/gate4-fixtures/boot-persistence.yml
git add app/src/test/resources/gate4-fixtures/popular-app-impersonation.yml
git commit -m "test: add Gate 4 fixtures for 5 staging rules"
```

---

## Task 4: Promote All 5 Staging Rules to Production

**Files:**
- Create: `app/src/main/res/raw/sigma_androdr_051_cellebrite_cves.yml`
- Create: `app/src/main/res/raw/sigma_androdr_066_boot_persistence.yml`
- Create: `app/src/main/res/raw/sigma_androdr_069_overlay_permission.yml`
- Create: `app/src/main/res/raw/sigma_androdr_070_ddns_c2.yml`
- Create: `app/src/main/res/raw/sigma_androdr_077_popular_app_impersonation.yml`

- [ ] **Step 1: Copy all 5 fixed staging rules to production**

```bash
cp third-party/android-sigma-rules/staging/device_auditor/androdr_051_cellebrite_cves.yml \
   app/src/main/res/raw/sigma_androdr_051_cellebrite_cves.yml

cp third-party/android-sigma-rules/staging/receiver_audit/androdr_066_boot_persistence.yml \
   app/src/main/res/raw/sigma_androdr_066_boot_persistence.yml

cp third-party/android-sigma-rules/staging/app_scanner/androdr_069_overlay_permission.yml \
   app/src/main/res/raw/sigma_androdr_069_overlay_permission.yml

cp third-party/android-sigma-rules/staging/dns_monitor/androdr_070_ddns_c2.yml \
   app/src/main/res/raw/sigma_androdr_070_ddns_c2.yml

cp third-party/android-sigma-rules/staging/app_scanner/androdr_077_popular_app_impersonation.yml \
   app/src/main/res/raw/sigma_androdr_077_popular_app_impersonation.yml
```

- [ ] **Step 2: Run Gradle gate to verify all 53 rules pass (48 existing + 5 new)**

```bash
./gradlew testDebugUnitTest --tests "com.androdr.sigma.BundledRulesSchemaCrossCheckTest"
```

Expected: All tests PASS. If any fail, read the error output — likely a field mismatch between the YAML and what `SigmaRuleParser` expects.

- [ ] **Step 3: Run Gate 4 fixture tests to verify all new fixtures pass**

```bash
./gradlew testDebugUnitTest --tests "com.androdr.sigma.GateFourFixtureTest"
```

Expected: All parameterized tests PASS (3 existing + 5 new = 8 fixtures). If any fail, the fixture's TP/TN records don't match the rule's detection logic — adjust the fixture.

- [ ] **Step 4: Commit promoted rules**

```bash
git add app/src/main/res/raw/sigma_androdr_051_cellebrite_cves.yml
git add app/src/main/res/raw/sigma_androdr_066_boot_persistence.yml
git add app/src/main/res/raw/sigma_androdr_069_overlay_permission.yml
git add app/src/main/res/raw/sigma_androdr_070_ddns_c2.yml
git add app/src/main/res/raw/sigma_androdr_077_popular_app_impersonation.yml
git commit -m "feat: promote 5 AI-generated staging rules to production

First AI-generated SIGMA rules promoted via the end-to-end pipeline.
Rules: androdr-051 (Cellebrite CVEs), androdr-066 (boot persistence),
androdr-069 (overlay permission), androdr-070 (DDNS C2),
androdr-077 (popular app impersonation, renumbered from 071)."
```

---

## Task 5: Run `/update-rules source stalkerware` End-to-End

> **Executor note:** This task invokes the `/update-rules` AI skill, which dispatches feed ingesters and the rule author pipeline. Run this in the main session, not a subagent.

**Files:**
- Read: `third-party/android-sigma-rules/feed-state.json`
- Read: `third-party/android-sigma-rules/ioc-data/package-names.yml` (existing stalkerware IOCs)

- [ ] **Step 1: Record current feed state for stalkerware**

```bash
cat third-party/android-sigma-rules/feed-state.json
```

Note the `stalkerware_indicators.last_commit_sha` value (currently `348fd7b`).

- [ ] **Step 2: Index current production rules to determine next available ID**

```bash
grep -h "^id:" app/src/main/res/raw/sigma_androdr_0*.yml | sort -t'-' -k2 -n | tail -5
```

After promoting staging rules, the highest numbered ID should be 077. The next available ID for new rules is **078**.

- [ ] **Step 3: Invoke `/update-rules source stalkerware`**

Run the skill:

```
/update-rules source stalkerware
```

This will:
1. Run the stalkerware feed ingester against `github.com/AssoEchap/stalkerware-indicators`
2. Diff against existing IOC data in `ioc-data/package-names.yml` and `ioc-data/c2-domains.yml`
3. Produce SIRs (Signal Intelligence Records) for new findings
4. Pass SIRs to the Rule Author to generate candidate rules
5. Run each candidate through the 5-gate validator (including the new Gate 4 harness)
6. Present results for approval

- [ ] **Step 4: Review skill output**

For each candidate rule produced:
- Verify it passed all 5 gates (especially Gate 4 dry-run)
- Check the detection logic makes sense
- Confirm the rule ID starts at 078+
- Approve rules that pass; reject or request modification for rules that fail

If the feed has no new indicators since `last_commit_sha: 348fd7b`, the ingester may report "no new SIRs." In that case, the skill should still produce at least one candidate from existing un-ruled indicators. If it produces nothing:
- Check whether the ingester is reading the correct remote
- The stalkerware-indicators repo may genuinely have no new data since April 2
- This is acceptable — the end-to-end proof comes from the staging rules already promoted
- Skip to Task 7 (decision log)

---

## Task 6: Promote End-to-End Rule(s) from `/update-rules` Output

> **Conditional:** Only execute if Task 5 produced approved candidate rules. If not, skip to Task 7.

**Files:**
- Create: `app/src/main/res/raw/sigma_androdr_078_*.yml` (or whatever the skill produces)
- Create: `app/src/test/resources/gate4-fixtures/*.yml` (fixture for each promoted rule)

- [ ] **Step 1: Save approved rule(s) to staging in the submodule**

For each approved candidate, the `/update-rules` skill should have already written the rule file. If it wrote to staging, verify it's there:

```bash
ls third-party/android-sigma-rules/staging/*/androdr_078*
```

- [ ] **Step 2: Copy approved rule(s) to production**

```bash
cp third-party/android-sigma-rules/staging/<service>/androdr_078_<name>.yml \
   app/src/main/res/raw/sigma_androdr_078_<name>.yml
```

- [ ] **Step 3: Write Gate 4 fixture for each promoted rule**

Create a fixture in `app/src/test/resources/gate4-fixtures/` following the same structure as the fixtures in Task 3. The `/update-rules` validator (Gate 4) should have already generated TP/TN test cases — reuse those.

- [ ] **Step 4: Run Gradle gate + Gate 4 fixture tests**

```bash
./gradlew testDebugUnitTest --tests "com.androdr.sigma.BundledRulesSchemaCrossCheckTest"
./gradlew testDebugUnitTest --tests "com.androdr.sigma.GateFourFixtureTest"
```

Expected: All PASS.

- [ ] **Step 5: Update feed-state.json with new cursor**

The `/update-rules` skill should update `feed-state.json` automatically. Verify:

```bash
cat third-party/android-sigma-rules/feed-state.json | python3 -m json.tool
```

Check that `stalkerware_indicators.last_commit_sha` has been updated from `348fd7b` to the latest commit.

- [ ] **Step 6: Commit submodule + promoted rule(s)**

```bash
cd third-party/android-sigma-rules
git add -A
git commit -m "feat: add rule(s) from stalkerware feed ingest run"
cd ../..
git add third-party/android-sigma-rules
git add app/src/main/res/raw/sigma_androdr_078_*.yml
git add app/src/test/resources/gate4-fixtures/*.yml
git commit -m "feat: promote AI-generated rule(s) from end-to-end stalkerware ingest"
```

---

## Task 7: Decision Log + Final Verification

**Files:**
- Create: `docs/decisions/2026-04-13-staging-rule-triage.md`

- [ ] **Step 1: Write the decision log**

File: `docs/decisions/2026-04-13-staging-rule-triage.md`

```markdown
# Staging Rule Triage — 2026-04-13

**Context:** 5 AI-generated rules sat in `android-sigma-rules/staging/` since
2026-04-02. Sub-plans 1a and 1b updated the validator and added Gate 4 harness
support. This triage re-validates each rule and records promote/reject decisions.

**Tracking:** Epic #104, sub-plan 1c (#107).

## Triage Results

| Rule | ID | Validator | Gate 4 | Decision | Notes |
|------|----|-----------|--------|----------|-------|
| Cellebrite CVEs | 051 | PASS (after adding `category`) | PASS | **Promoted** | Added `category: device_posture`. Strong detection, specific CVEs, Amnesty reference. |
| DDNS C2 | 070 | PASS (after adding `category`) | PASS | **Promoted** | Added `category: incident`. `endswith` modifier correct for DDNS suffixes — not migrated to `ioc_lookup` because these are TLD-like patterns, not individual domain IOCs. |
| Overlay Permission | 069 | PASS (after adding `category`) | PASS | **Promoted at medium** | Added `category: incident`, demoted `high` → `medium`. Sideload + known-good filter limits FP, but single permission is still broad. |
| Boot Persistence | 066 | PASS (after adding `category`) | PASS | **Promoted at low** | Added `category: incident`, demoted `medium` → `low`. Boot receivers extremely common; useful as triage signal, not standalone alert. |
| Popular App Impersonation | 071→077 | PASS (after renumber + `category`) | PASS | **Renumbered + Promoted** | Renumbered from 071 (collides with production `crash_loop_anti_forensics`) to 077 (next available). Added `category: incident`. |

## Common Fix Applied

All 5 rules were missing the top-level `category` field, which became required
when sub-plan 1a synced the schema. This is the expected failure mode — staging
rules predate the schema update. The build-time gate now prevents this class of
drift.

## End-to-End Pipeline Run

[Fill in after Task 5/6 — record what `/update-rules source stalkerware` produced,
which rules were approved, and any issues encountered during the run.]
```

- [ ] **Step 2: Ensure the `docs/decisions/` directory exists**

```bash
mkdir -p docs/decisions
```

- [ ] **Step 3: Run full unit test suite**

```bash
./gradlew testDebugUnitTest
```

Expected: All tests PASS. This confirms the 5 new production rules + any end-to-end rules are compatible with the Kotlin parser and Gate 4 harness.

- [ ] **Step 4: Commit decision log**

```bash
git add docs/decisions/2026-04-13-staging-rule-triage.md
git commit -m "docs: add staging rule triage decision log (#107)"
```

- [ ] **Step 5: Update decision log with end-to-end run results**

Fill in the "End-to-End Pipeline Run" section of the decision log with actual results from Task 5/6 — what the ingester found, what rules were produced, which were approved/rejected, and any issues encountered.

- [ ] **Step 6: Final PR preparation**

```bash
git log --oneline claude/android-edr-setup-rl68Y..HEAD
```

Verify the commit history is clean, then open PR:
- Title: `feat: promote staging rules + end-to-end pipeline proof (#107)`
- Body: reference epic #104, sub-plan 1c, include `Closes #107`
- Base: `claude/android-edr-setup-rl68Y`

---

## Exit Criteria (from meta-plan)

- [ ] All 5 staging rules re-validated; per-rule decision recorded in decision log
- [ ] Rules promoted to `app/src/main/res/raw/` pass the build-time Gradle gate
- [ ] `/update-rules source stalkerware` run end-to-end (even if no new rules produced)
- [ ] At least one AI-generated rule in production (satisfied by staging promotions)
- [ ] `feed-state.json` updated with correct cursor
- [ ] Gate 4 fixtures exist for every promoted rule
