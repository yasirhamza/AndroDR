# Broker-SDK `installed_app` Rule Pack Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship the first 4 SIGMA detection rules that use the `embedded_component_class` field shipped in PR #183 — one per anchored broker SDK (Outlogic, Venntel, Predicio, Cuebiq) — plus 4 Gate-4 fixtures and 2 `telemetry_gap` decisions for the un-anchored SDKs.

**Architecture:** Two coordinated PRs. PR-1 lands the rule YAMLs and decision manifest in the `android-sigma-rules` submodule. PR-2 in AndroDR bumps the submodule pointer, copies the rule YAMLs into `app/src/main/res/raw/` for runtime bundling, and adds the Gate-4 fixtures that exercise the rules through the existing `GateFourTestHarness` Kotlin test class.

**Tech Stack:** YAML (SIGMA rules + Gate-4 fixtures + decision manifest). Python validators (Gate 1 schema, Gate 2 lint, Gate 3 provenance) inside the submodule. Kotlin unit tests (Gate 4 + cross-check tests) in AndroDR. `gh` CLI for PRs. No new code.

**Spec:** [`docs/superpowers/specs/2026-05-18-broker-sdk-installed-app-rule-pack-design.md`](../specs/2026-05-18-broker-sdk-installed-app-rule-pack-design.md)

**Branch already created:** `feat/168-installed-app-broker-sdk-pack` in AndroDR (spec already committed there as `4670324` → `a68bd24`). A sibling branch with the same name will be created in the submodule.

---

## File Structure

### To be created — submodule (`third-party/android-sigma-rules/`)

```
staging/app_scanner/
├── androdr_079_data_broker_outlogic.yml
├── androdr_080_data_broker_venntel.yml
├── androdr_081_data_broker_predicio.yml
└── androdr_082_data_broker_cuebiq.yml

decisions/
└── 2026-05-18-broker-sdk-pack.yml   # contains 2 telemetry_gap entries
```

The `decisions/` filename and exact layout follow the project's existing decision-manifest convention; the implementation reads `validation/decisions-schema.json` to confirm field names before writing the file.

### To be created — AndroDR (`/home/yasir/AndroDR/`)

```
app/src/main/res/raw/
├── sigma_androdr_079_data_broker_outlogic.yml   # copy of submodule file
├── sigma_androdr_080_data_broker_venntel.yml    # copy of submodule file
├── sigma_androdr_081_data_broker_predicio.yml   # copy of submodule file
└── sigma_androdr_082_data_broker_cuebiq.yml     # copy of submodule file

app/src/test/resources/gate4-fixtures/
├── outlogic-broker-sdk.yml
├── venntel-broker-sdk.yml
├── predicio-broker-sdk.yml
└── cuebiq-broker-sdk.yml
```

### Already in place

- `docs/superpowers/specs/2026-05-18-broker-sdk-installed-app-rule-pack-design.md` (committed)
- The 6 SDK SIRs at `docs/superpowers/research/2026-05-18-broker-sdks/` (PR #188)
- The `embedded_component_class` taxonomy entry at `third-party/android-sigma-rules/validation/logsource-taxonomy.yml` (PR #178)
- The `AppTelemetry.embeddedComponentClasses` Kotlin field (PR #183)
- `app/src/test/java/com/androdr/sigma/GateFourTestHarness.kt` + `GateFourFixtureTest.kt`

### Not in scope

- Bumping `level: experimental` → `production`. Follow-up PR.
- Moving rule files from `staging/app_scanner/` to `app_scanner/`. Follow-up PR.
- Promoting the decision manifest to anything other than informational.
- Any Kotlin source-file changes; the existing harness and parser already handle the new fields.
- DNS rule pack; combination rule. Separate specs.

---

### Task 1: Create submodule topic branch + workspace check

**Why:** The submodule is its own git repo. Branch must exist before any files land. Confirm the working tree is clean before touching anything to avoid mixing up unrelated drift.

**Files:** None modified in this task — branch creation only.

- [ ] **Step 1: Confirm AndroDR branch**

Run: `git -C /home/yasir/AndroDR branch --show-current`
Expected: `feat/168-installed-app-broker-sdk-pack`. If anything else, run `git checkout feat/168-installed-app-broker-sdk-pack`.

- [ ] **Step 2: Confirm submodule working tree state**

Run: `git -C /home/yasir/AndroDR/third-party/android-sigma-rules status --short`
Expected: empty output (clean). If there are uncommitted changes, STOP — they likely belong to another in-progress effort; ask the user before proceeding.

- [ ] **Step 3: Create submodule topic branch**

Run:
```bash
git -C /home/yasir/AndroDR/third-party/android-sigma-rules checkout -b feat/168-installed-app-broker-sdk-pack
```
Expected: `Switched to a new branch 'feat/168-installed-app-broker-sdk-pack'`.

- [ ] **Step 4: Verify branch and remote**

Run: `git -C /home/yasir/AndroDR/third-party/android-sigma-rules branch --show-current && git -C /home/yasir/AndroDR/third-party/android-sigma-rules remote -v`
Expected: branch `feat/168-installed-app-broker-sdk-pack`; remote `origin` points to the `android-sigma-rules` GitHub repo.

---

### Task 2: Write the 4 SIGMA YAML rules in the submodule

**Why:** Rule YAMLs are the substantive detection content. Follow the `androdr_078_meiya_pico_forensics.yml` style verbatim for consistency.

**Files:**
- Create: `third-party/android-sigma-rules/staging/app_scanner/androdr_079_data_broker_outlogic.yml`
- Create: `third-party/android-sigma-rules/staging/app_scanner/androdr_080_data_broker_venntel.yml`
- Create: `third-party/android-sigma-rules/staging/app_scanner/androdr_081_data_broker_predicio.yml`
- Create: `third-party/android-sigma-rules/staging/app_scanner/androdr_082_data_broker_cuebiq.yml`

- [ ] **Step 1: Write androdr_079_data_broker_outlogic.yml**

Path: `third-party/android-sigma-rules/staging/app_scanner/androdr_079_data_broker_outlogic.yml`

```yaml
title: Embedded data-broker SDK — Outlogic (X-Mode Social)
id: androdr-079
status: experimental
category: incident
description: >
    Detects the Outlogic (formerly X-Mode Social) location-data broker SDK
    embedded inside an installed app. X-Mode was banned from the Play Store
    in December 2020 after Vice/Motherboard reporting tied it to US military
    and federal LE buyers. The vendor was acquired by Digital Envoy in
    August 2021 and rebranded as Outlogic. The FTC finalized a settlement
    in April 2024 prohibiting sale of sensitive location data. The match
    set is the two unambiguous io.xmode.* class prefixes documented by
    Exodus Privacy tracker #354 and the ExpressVPN 'Xoth' investigation;
    the io.mysdk.* prefix is intentionally excluded because it is shared
    with SignalFrame/WirelessRegistry and would cause false positives.
author: AndroDR (AI-generated)
date: 2026/05/18
references:
    - https://reports.exodus-privacy.eu.org/en/trackers/354/
    - https://www.ftc.gov/news-events/news/press-releases/2024/04/ftc-finalizes-order-x-mode-successor-outlogic-prohibiting-it-sharing-or-selling-sensitive-location
tags:
    - attack.t1430
    - attack.t1437.001
logsource:
    product: androdr
    service: app_scanner
detection:
    selection:
        embedded_component_class|contains:
            - 'io.xmode.BcnConfig'
            - 'io.xmode.locationsdk'
    filter_system_app:
        is_system_app: true
    condition: selection and not filter_system_app
level: medium
display:
    category: app_risk
    icon: warning
    triggered_title: "Data-broker SDK: Outlogic"
    evidence_type: ioc_match
    summary_template: "Outlogic SDK class detected: {matched_value}"
    guidance: "This app embeds the Outlogic (X-Mode) location-broker SDK, known for reselling fine-grained location data to military and federal LE customers. Consider uninstalling or denying location permissions."
falsepositives:
    - "App that legitimately embeds the SDK with disclosed user consent; rare given the SDK's regulatory history."
    - "Pre-installed system app shipping the SDK (filtered out by filter_system_app)."
remediation:
    - "Review whether you need this app; broker SDKs run in the background."
    - "If keeping the app, deny ACCESS_BACKGROUND_LOCATION and ACCESS_FINE_LOCATION."
```

- [ ] **Step 2: Write androdr_080_data_broker_venntel.yml**

Path: `third-party/android-sigma-rules/staging/app_scanner/androdr_080_data_broker_venntel.yml`

```yaml
title: Embedded data-broker SDK — Venntel (Gravy GOLD legacy)
id: androdr-080
status: experimental
category: incident
description: >
    Detects the legacy Gravy GOLD SDK (published under TimeRAZOR Inc.,
    later branded Venntel) embedded inside an installed app. Venntel
    resold the resulting location feed to ICE, CBP, DEA, and US military
    customers per Senator Wyden's investigations and the FTC complaint
    (December 2024). Match set is the two confirmed class prefixes from
    the vendor's own Javadoc and an independent third-party mirror.
author: AndroDR (AI-generated)
date: 2026/05/18
references:
    - https://www.ftc.gov/news-events/news/press-releases/2024/12/ftc-takes-action-against-gravy-analytics-venntel-unlawfully-selling-location-data-tracking-consumers
    - https://www.eff.org/deeplinks/2022/08/fog-revealed-guided-tour-how-cops-can-browse-your-location-data
tags:
    - attack.t1430
    - attack.t1437.001
logsource:
    product: androdr
    service: app_scanner
detection:
    selection:
        embedded_component_class|contains:
            - 'com.timerazor.gravysdk'
            - 'com.gravy.gravysdk'
    filter_system_app:
        is_system_app: true
    condition: selection and not filter_system_app
level: medium
display:
    category: app_risk
    icon: warning
    triggered_title: "Data-broker SDK: Venntel"
    evidence_type: ioc_match
    summary_template: "Venntel/Gravy GOLD SDK class detected: {matched_value}"
    guidance: "This app embeds the legacy Gravy GOLD SDK, whose data flowed through Venntel to US federal law-enforcement customers. The SDK is legacy and rare in modern apps; presence is high-signal."
falsepositives:
    - "App that legitimately embeds the SDK with disclosed user consent; rare given Venntel's regulatory history."
    - "Pre-installed system app shipping the SDK (filtered out by filter_system_app)."
remediation:
    - "Review whether you need this app; the Gravy GOLD SDK transmits precise location to broker infrastructure."
    - "If keeping the app, deny ACCESS_BACKGROUND_LOCATION and ACCESS_FINE_LOCATION."
```

- [ ] **Step 3: Write androdr_081_data_broker_predicio.yml**

Path: `third-party/android-sigma-rules/staging/app_scanner/androdr_081_data_broker_predicio.yml`

```yaml
title: Embedded data-broker SDK — Predicio (Telescope)
id: androdr-081
status: experimental
category: incident
description: >
    Detects the Predicio 'Telescope' SDK embedded inside an installed app.
    Predicio was removed from Google Play and Apple's App Store in
    February 2021 after Vice/Motherboard reporting (Joseph Cox) exposed
    that the Salaat First Muslim prayer app exfiltrated user location to
    predic.io endpoints. The SDK is functionally defunct but historical
    versions may persist on devices that have not been re-published.
author: AndroDR (AI-generated)
date: 2026/05/18
references:
    - https://www.vice.com/en/article/muslim-app-location-data-salaat-first/
    - https://reports.exodus-privacy.eu.org/en/trackers/357/
tags:
    - attack.t1430
    - attack.t1437.001
logsource:
    product: androdr
    service: app_scanner
detection:
    selection:
        embedded_component_class|contains:
            - 'com.telescope.android'
            - 'io.predic.tracker'
    filter_system_app:
        is_system_app: true
    condition: selection and not filter_system_app
level: medium
display:
    category: app_risk
    icon: warning
    triggered_title: "Data-broker SDK: Predicio"
    evidence_type: ioc_match
    summary_template: "Predicio (Telescope) SDK class detected: {matched_value}"
    guidance: "This app embeds the Predicio location-broker SDK, banned from both major app stores in 2021. Historical versions may remain on un-updated apps; consider uninstalling."
falsepositives:
    - "Legacy app that has not been re-published since 2020-2021 and retained the Predicio SDK."
    - "Pre-installed system app shipping the SDK (filtered out by filter_system_app)."
remediation:
    - "Uninstall this app or check the developer's website for an updated version that removed the SDK."
    - "If keeping the app, deny ACCESS_BACKGROUND_LOCATION and ACCESS_FINE_LOCATION."
```

- [ ] **Step 4: Write androdr_082_data_broker_cuebiq.yml**

Path: `third-party/android-sigma-rules/staging/app_scanner/androdr_082_data_broker_cuebiq.yml`

```yaml
title: Embedded data-broker SDK — Cuebiq
id: androdr-082
status: experimental
category: incident
description: >
    Detects the Cuebiq location-data broker SDK embedded inside an
    installed app. Cuebiq-sourced data was used in the New York Times
    'Privacy Project' (December 2019) to re-identify named individuals,
    including a US Secret Service agent traveling with the President.
    Cuebiq announced an SDK sunset in 2021 but a permissive variant
    remained available; historical versions persist in apps that have
    not been re-published. Match set is the two canonical class anchors
    from Exodus Privacy tracker #57 and the glorifiedgrep OSS static
    analysis tool.
author: AndroDR (AI-generated)
date: 2026/05/18
references:
    - https://reports.exodus-privacy.eu.org/en/trackers/57/
    - https://www.adexchanger.com/mobile/location-intel-provider-cuebiq-is-shutting-down-its-sdk-in-the-name-of-privacy/
tags:
    - attack.t1430
    - attack.t1437.001
logsource:
    product: androdr
    service: app_scanner
detection:
    selection:
        embedded_component_class|contains:
            - 'com.cuebiq.cuebiqsdk.model.Collector'
            - 'com.cuebiq.cuebiqsdk.receiver.CoverageReceiver'
    filter_system_app:
        is_system_app: true
    condition: selection and not filter_system_app
level: medium
display:
    category: app_risk
    icon: warning
    triggered_title: "Data-broker SDK: Cuebiq"
    evidence_type: ioc_match
    summary_template: "Cuebiq SDK class detected: {matched_value}"
    guidance: "This app embeds the Cuebiq location-data broker SDK, whose data has been used to track named individuals (NYT Privacy Project, 2019). Consider uninstalling or denying location permissions."
falsepositives:
    - "Legacy app that has not been re-published since the 2021 SDK sunset."
    - "Pre-installed system app shipping the SDK (filtered out by filter_system_app)."
remediation:
    - "Review whether you need this app; the Cuebiq SDK transmits precise location to broker infrastructure."
    - "If keeping the app, deny ACCESS_BACKGROUND_LOCATION and ACCESS_FINE_LOCATION."
```

- [ ] **Step 5: Verify all 4 files exist**

Run: `ls third-party/android-sigma-rules/staging/app_scanner/androdr_07{9,80,81,82}*.yml 2>/dev/null | wc -l`
Wait — that's a bash arithmetic confusion. Use this instead:
```bash
ls third-party/android-sigma-rules/staging/app_scanner/androdr_079*.yml \
   third-party/android-sigma-rules/staging/app_scanner/androdr_080*.yml \
   third-party/android-sigma-rules/staging/app_scanner/androdr_081*.yml \
   third-party/android-sigma-rules/staging/app_scanner/androdr_082*.yml | wc -l
```
Expected: `4`.

- [ ] **Step 6: Run the schema validator on each rule**

Run from inside the submodule:
```bash
cd third-party/android-sigma-rules && \
for f in staging/app_scanner/androdr_07{9,80,81,82}*.yml; do
  python3 validation/validate-rule.py "$f"
done && cd -
```
Expected: each file reports no errors. If any fail, fix the affected YAML inline before continuing.

- [ ] **Step 7: Do NOT commit yet**

Rules + decisions + fixtures land in one cohesive submodule commit after Task 3.

---

### Task 3: Write the decision manifest for the 2 telemetry_gap entries

**Why:** Mobilewalla and Adsquare yielded no on-device anchors per their SIRs. Per the rule-author skill, missing-fingerprint cases are recorded as `telemetry_gap` decisions, not authored as thin rules.

**Files:**
- Create: `third-party/android-sigma-rules/decisions/2026-05-18-broker-sdk-pack.yml`

- [ ] **Step 1: Confirm the decision-manifest convention**

Run:
```bash
ls third-party/android-sigma-rules/decisions/ 2>/dev/null
cat third-party/android-sigma-rules/validation/decisions-schema.json | head -40
```
Expected: confirms either an existing `decisions/` directory + a JSON schema describing the entry shape, or surfaces that no such directory exists yet — in which case the implementer creates it. The schema is the authoritative source for field names; if any field in the example below disagrees with the schema, the schema wins.

- [ ] **Step 2: Write the manifest**

Path: `third-party/android-sigma-rules/decisions/2026-05-18-broker-sdk-pack.yml`

```yaml
# Decisions accompanying the broker-SDK installed_app rule pack (issue #168).
# Two telemetry_gap entries — Mobilewalla and Adsquare yielded no on-device
# anchors per their SIRs (docs/superpowers/research/2026-05-18-broker-sdks/
# in the AndroDR repo). No SIGMA rules ship for these two; this manifest
# records why and what evidence would justify revisiting.

decisions:
  - rule_id: null
    field: "rule_creation"
    type: "telemetry_gap"
    chosen: "skip"
    alternative: "create installed_app rule with embedded_component_class anchor"
    reasoning: >
        Mobilewalla SIR (sir-2026-05-18-mobilewalla) explicitly states that no
        public Android package prefix, class name, native library, or telemetry
        hostname tied to a deployed first-party Mobilewalla on-device SDK has
        been disclosed by any reviewed source (Exodus Privacy has no entry,
        AppCensus has no published profile, the Reardon/Egelman corpus does
        not name them). Per the FTC complaint, ~95% of Mobilewalla's data is
        sourced second-hand via RTB bidstream and DSP/DMP suppliers, not via
        a first-party SDK shipped at scale. The only public first-party SDK
        references are (a) a server-side Python client mw-feature-serving-sdk
        on PyPI, and (b) an optional Android add-on documented for the
        LendBetter Covariate integration with no published class names.
        Recommend revisiting if reverse-engineering of a Covariate-integrated
        APK (LendBetter is the obvious target) surfaces concrete class anchors.
    missing_field: "concrete_mobilewalla_sdk_anchor"
    source_sir: "sir-2026-05-18-mobilewalla"

  - rule_id: null
    field: "rule_creation"
    type: "telemetry_gap"
    chosen: "skip"
    alternative: "create installed_app rule with embedded_component_class anchor"
    reasoning: >
        Adsquare SIR (sir-2026-05-18-adsquare) confirms aggregator posture by
        three independent structured sources: Adsquare's own statement to
        The Markup ("Adsquare doesn't collect location data. Adsquare sources
        and aggregates location data from a variety of suppliers."), Adsquare's
        own public GitHub artifacts being 100% server-side Java/Avro ingestion
        libraries (data-delivery, data-stats-hll, NO Android client SDK), and
        the complete absence of an Adsquare tracker entry in the Exodus Privacy
        database as of 2026-05-18. No first-party Android SDK exists to
        fingerprint. Adsquare is detectable only INDIRECTLY via its confirmed
        upstream supplier SDKs (Tamoco, Predicio, etc.). Recommend revisiting
        if reverse engineering of a Databroker-Files-implicated German app
        (named in the Netzpolitik/BR/Le Monde joint investigation) surfaces
        an Adsquare-attributed package name on disk.
    missing_field: "concrete_adsquare_sdk_anchor"
    source_sir: "sir-2026-05-18-adsquare"
```

If the schema check in Step 1 revealed any field-name disagreement (`source_sir` vs `source_sirs`, `missing_field` shape, etc.), adapt the YAML to match the schema before writing.

- [ ] **Step 3: Validate the decision manifest**

Run from the submodule root:
```bash
cd third-party/android-sigma-rules && \
python3 validation/validate-decisions.py decisions/2026-05-18-broker-sdk-pack.yml && \
cd -
```
Expected: no errors.

- [ ] **Step 4: Do NOT commit yet** — commit happens after Task 4.

---

### Task 4: Commit submodule changes + push + open submodule PR

**Files:** Stages the 4 rules + 1 decision manifest in the submodule. No file content changes.

- [ ] **Step 1: Stage and commit**

Run from `/home/yasir/AndroDR/third-party/android-sigma-rules/`:
```bash
git -C third-party/android-sigma-rules add \
  staging/app_scanner/androdr_07{9,80,81,82}*.yml \
  decisions/2026-05-18-broker-sdk-pack.yml
git -C third-party/android-sigma-rules status --short
```
Expected: 5 files staged (4 `A` rules + 1 `A` decision file). If `decisions/` was newly created, the directory will show as added implicitly via the file.

- [ ] **Step 2: Commit**

```bash
git -C third-party/android-sigma-rules commit -m "$(cat <<'EOF'
feat(rules): broker-SDK installed_app pack (#168)

Four SIGMA rules consuming the embedded_component_class field shipped in
AndroDR PR #183 — one per anchored broker SDK from the SIR research pass
(AndroDR PR #188). Plus two telemetry_gap decisions for Mobilewalla and
Adsquare, which yielded no on-device anchors.

androdr-079: Outlogic / X-Mode Social
androdr-080: Venntel / Gravy GOLD legacy
androdr-081: Predicio / Telescope
androdr-082: Cuebiq

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
git -C third-party/android-sigma-rules log -1 --pretty=format:'%h %s'
```
Expected: commit succeeds; last commit message visible.

- [ ] **Step 3: Push the submodule branch**

```bash
git -C third-party/android-sigma-rules push -u origin feat/168-installed-app-broker-sdk-pack
```
Expected: branch published; tracking set.

- [ ] **Step 4: Open the submodule PR**

```bash
cd third-party/android-sigma-rules
gh pr create --title "feat(rules): broker-SDK installed_app pack (#168)" --body "$(cat <<'EOF'
## Summary
- 4 SIGMA rules under `staging/app_scanner/` (androdr-079..082) consuming the
  `embedded_component_class` field shipped in AndroDR PR #183.
- 2 `telemetry_gap` decisions in `decisions/2026-05-18-broker-sdk-pack.yml` for
  Mobilewalla and Adsquare, whose SIRs documented no on-device anchors.
- First user of the new embedded-SDK taxonomy fields anywhere in the corpus.

Related: AndroDR issue #168, AndroDR PR #183 (scanner), AndroDR PR #188 (SIRs).

## Test plan
- [x] `validate-rule.py` passes on each of the 4 rule files.
- [x] `validate-decisions.py` passes on the manifest.
- [ ] Sibling AndroDR PR runs `GateFourFixtureTest` against the bundled copies of these rules to confirm they fire on positive fixtures and stay silent on negatives.

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
)"
cd ..
```
Capture the PR URL for the AndroDR PR description in Task 9.

- [ ] **Step 5: Admin-merge the submodule PR**

Per project memory `feedback_ci_wait_pattern.md`: rule-corpus PRs admin-merge after local validators pass; CI is out of budget. Run:
```bash
SUBMODULE_PR_NUM=$(gh pr view --repo yasirhamza/android-sigma-rules feat/168-installed-app-broker-sdk-pack --json number -q .number)
gh pr merge --repo yasirhamza/android-sigma-rules "$SUBMODULE_PR_NUM" --squash --admin --delete-branch
```
Expected: merge succeeds, remote branch deleted. The local branch can remain.

- [ ] **Step 6: Update the submodule to the merged commit on main**

```bash
git -C third-party/android-sigma-rules fetch origin
git -C third-party/android-sigma-rules checkout main
git -C third-party/android-sigma-rules pull --ff-only
git -C third-party/android-sigma-rules log -1 --pretty=format:'%H %s'
```
Expected: HEAD points to the squash-merged commit. Capture the commit SHA — Task 5 reads it implicitly by `git submodule status`, but recording it now is useful for the AndroDR PR description.

---

### Task 5: Bundle the 4 rules into AndroDR's `res/raw/`

**Why:** The Gate-4 harness (`GateFourTestHarness.kt`) reads rule YAMLs from `app/src/main/res/raw/`, not directly from the submodule. The runtime bundling step copies the rule files into that resource directory with the `sigma_` filename prefix the harness expects.

**Files:**
- Create: `app/src/main/res/raw/sigma_androdr_079_data_broker_outlogic.yml`
- Create: `app/src/main/res/raw/sigma_androdr_080_data_broker_venntel.yml`
- Create: `app/src/main/res/raw/sigma_androdr_081_data_broker_predicio.yml`
- Create: `app/src/main/res/raw/sigma_androdr_082_data_broker_cuebiq.yml`

- [ ] **Step 1: Confirm AndroDR branch**

Run: `git -C /home/yasir/AndroDR branch --show-current`
Expected: `feat/168-installed-app-broker-sdk-pack`.

- [ ] **Step 2: Copy each rule with the bundled filename prefix**

Run:
```bash
for slug in outlogic venntel predicio cuebiq; do
  case $slug in
    outlogic) NNN=079;;
    venntel)  NNN=080;;
    predicio) NNN=081;;
    cuebiq)   NNN=082;;
  esac
  cp third-party/android-sigma-rules/staging/app_scanner/androdr_${NNN}_data_broker_${slug}.yml \
     app/src/main/res/raw/sigma_androdr_${NNN}_data_broker_${slug}.yml
done
```

- [ ] **Step 3: Verify all 4 bundled files exist**

Run: `ls app/src/main/res/raw/sigma_androdr_079_data_broker_*.yml app/src/main/res/raw/sigma_androdr_080_data_broker_*.yml app/src/main/res/raw/sigma_androdr_081_data_broker_*.yml app/src/main/res/raw/sigma_androdr_082_data_broker_*.yml`
Expected: 4 paths printed, no errors.

- [ ] **Step 4: Verify the bundled files match the submodule files**

Run:
```bash
for slug in outlogic venntel predicio cuebiq; do
  case $slug in outlogic) NNN=079;; venntel) NNN=080;; predicio) NNN=081;; cuebiq) NNN=082;; esac
  diff third-party/android-sigma-rules/staging/app_scanner/androdr_${NNN}_data_broker_${slug}.yml \
       app/src/main/res/raw/sigma_androdr_${NNN}_data_broker_${slug}.yml && echo "OK: $slug"
done
```
Expected: 4 lines `OK: outlogic` ... `OK: cuebiq`. If any diff is non-empty, re-copy that file.

- [ ] **Step 5: Do NOT commit yet** — fixtures land in Task 6; commit after tests pass in Task 7.

---

### Task 6: Write the 4 Gate-4 fixtures

**Why:** Gate 4 fixtures assert that each rule fires on positive telemetry and stays silent on negatives. They also encode design intent — the SignalFrame negative case is what defends the choice to drop `io.mysdk.*` from the Outlogic match set.

**Files:**
- Create: `app/src/test/resources/gate4-fixtures/outlogic-broker-sdk.yml`
- Create: `app/src/test/resources/gate4-fixtures/venntel-broker-sdk.yml`
- Create: `app/src/test/resources/gate4-fixtures/predicio-broker-sdk.yml`
- Create: `app/src/test/resources/gate4-fixtures/cuebiq-broker-sdk.yml`

- [ ] **Step 1: Write outlogic-broker-sdk.yml**

Path: `app/src/test/resources/gate4-fixtures/outlogic-broker-sdk.yml`

```yaml
# Fixture for androdr-079: Outlogic (X-Mode Social) data-broker SDK.
# The fifth true_negative (SignalFrame using io.mysdk.*) is load-bearing:
# it asserts that the rule does NOT match the io.mysdk.* prefix, which
# was intentionally dropped from the match set to avoid false positives
# on SignalFrame/WirelessRegistry-using apps.
rule_file: sigma_androdr_079_data_broker_outlogic.yml
service: app_scanner
true_positives:
  - package_name: "com.example.outlogicembedder"
    is_system_app: false
    embedded_component_class:
      - "io.xmode.BcnConfig"
      - "io.xmode.locationsdk.GeoSyncService"
true_negatives:
  # System-app masquerade — filter_system_app suppresses
  - package_name: "com.example.outlogicembedder"
    is_system_app: true
    embedded_component_class:
      - "io.xmode.BcnConfig"
  # Benign user app — no embedded class at all
  - package_name: "com.google.android.gm"
    is_system_app: false
    embedded_component_class: []
  # Cross-isolation: Cuebiq fixture's class must NOT trigger Outlogic
  - package_name: "com.example.cuebiqembedder"
    is_system_app: false
    embedded_component_class:
      - "com.cuebiq.cuebiqsdk.model.Collector"
  # SignalFrame/WirelessRegistry uses io.mysdk.* — must NOT trigger Outlogic.
  # This case defends the design choice to drop io.mysdk.* from the match set.
  - package_name: "com.example.signalframeembedder"
    is_system_app: false
    embedded_component_class:
      - "io.mysdk.networkmodule.network.networking.wirelessregistry.WrxConfig"
```

- [ ] **Step 2: Write venntel-broker-sdk.yml**

Path: `app/src/test/resources/gate4-fixtures/venntel-broker-sdk.yml`

```yaml
# Fixture for androdr-080: Venntel / Gravy GOLD legacy SDK.
rule_file: sigma_androdr_080_data_broker_venntel.yml
service: app_scanner
true_positives:
  - package_name: "com.example.venntelembedder"
    is_system_app: false
    embedded_component_class:
      - "com.timerazor.gravysdk.GravyService"
      - "com.gravy.gravysdk.ParcelableState"
true_negatives:
  # System-app masquerade — filter_system_app suppresses
  - package_name: "com.example.venntelembedder"
    is_system_app: true
    embedded_component_class:
      - "com.timerazor.gravysdk.GravyService"
  # Benign user app
  - package_name: "com.google.android.gm"
    is_system_app: false
    embedded_component_class: []
  # Cross-isolation: Outlogic fixture's class must NOT trigger Venntel
  - package_name: "com.example.outlogicembedder"
    is_system_app: false
    embedded_component_class:
      - "io.xmode.BcnConfig"
  # Similar-sounding but unrelated package — must NOT trigger
  - package_name: "com.example.gravyfood"
    is_system_app: false
    embedded_component_class:
      - "com.gravyfood.delivery.MainActivity"
```

- [ ] **Step 3: Write predicio-broker-sdk.yml**

Path: `app/src/test/resources/gate4-fixtures/predicio-broker-sdk.yml`

```yaml
# Fixture for androdr-081: Predicio / Telescope SDK.
rule_file: sigma_androdr_081_data_broker_predicio.yml
service: app_scanner
true_positives:
  - package_name: "com.example.predicioembedder"
    is_system_app: false
    embedded_component_class:
      - "com.telescope.android.LocationCollector"
      - "io.predic.tracker.Beacon"
true_negatives:
  # System-app masquerade — filter_system_app suppresses
  - package_name: "com.example.predicioembedder"
    is_system_app: true
    embedded_component_class:
      - "com.telescope.android.LocationCollector"
  # Benign user app
  - package_name: "com.google.android.gm"
    is_system_app: false
    embedded_component_class: []
  # Cross-isolation: Venntel fixture's class must NOT trigger Predicio
  - package_name: "com.example.venntelembedder"
    is_system_app: false
    embedded_component_class:
      - "com.timerazor.gravysdk.GravyService"
  # The legitimate Telescope astronomy app (telescope.* without .android suffix)
  # must NOT trigger — defends against accidental contains-style overmatch.
  - package_name: "com.celestron.telescope"
    is_system_app: false
    embedded_component_class:
      - "com.celestron.telescope.app.MainActivity"
```

- [ ] **Step 4: Write cuebiq-broker-sdk.yml**

Path: `app/src/test/resources/gate4-fixtures/cuebiq-broker-sdk.yml`

```yaml
# Fixture for androdr-082: Cuebiq data-broker SDK.
rule_file: sigma_androdr_082_data_broker_cuebiq.yml
service: app_scanner
true_positives:
  - package_name: "com.example.cuebiqembedder"
    is_system_app: false
    embedded_component_class:
      - "com.cuebiq.cuebiqsdk.model.Collector"
      - "com.cuebiq.cuebiqsdk.receiver.CoverageReceiver"
true_negatives:
  # System-app masquerade — filter_system_app suppresses
  - package_name: "com.example.cuebiqembedder"
    is_system_app: true
    embedded_component_class:
      - "com.cuebiq.cuebiqsdk.model.Collector"
  # Benign user app
  - package_name: "com.google.android.gm"
    is_system_app: false
    embedded_component_class: []
  # Cross-isolation: Predicio fixture's class must NOT trigger Cuebiq
  - package_name: "com.example.predicioembedder"
    is_system_app: false
    embedded_component_class:
      - "com.telescope.android.LocationCollector"
  # An unrelated app with a 'cuebiq' substring outside the SDK namespace —
  # must NOT trigger Cuebiq.
  - package_name: "com.example.cuebiqtravelblog"
    is_system_app: false
    embedded_component_class:
      - "com.cuebiqtravelblog.MainActivity"
```

- [ ] **Step 5: Verify all 4 fixtures exist**

Run: `ls app/src/test/resources/gate4-fixtures/outlogic-broker-sdk.yml app/src/test/resources/gate4-fixtures/venntel-broker-sdk.yml app/src/test/resources/gate4-fixtures/predicio-broker-sdk.yml app/src/test/resources/gate4-fixtures/cuebiq-broker-sdk.yml`
Expected: 4 paths printed.

---

### Task 7: Run AndroDR unit tests to verify Gate 4 + cross-checks

**Why:** The fixtures must drive `GateFourFixtureTest` to a PASS state, and `BundledRulesSchemaCrossCheckTest` + `LogsourceTaxonomyCrossCheckTest` + the parser tests must remain green. This is the local gate before pushing.

**Files:** None modified by this task.

- [ ] **Step 1: Run the focused Gate 4 test first**

Run: `./gradlew :app:testDebugUnitTest --tests 'com.androdr.sigma.GateFourFixtureTest' -i 2>&1 | tail -40`
Expected: BUILD SUCCESSFUL; the new fixtures are picked up; each rule fires on its `true_positives` and not on its `true_negatives`. If a fixture fails, the test output names the rule + fixture + which record failed.

If any fixture fails, the implementer fixes the fixture (NOT the rule, unless the rule is provably wrong) and re-runs Step 1. The fixture is the asserter; if the rule legitimately fails its own positive case, that's a rule bug to fix in Task 2's files (and update the submodule branch + bundled copy).

- [ ] **Step 2: Run the cross-check tests**

Run: `./gradlew :app:testDebugUnitTest --tests 'com.androdr.sigma.BundledRulesSchemaCrossCheckTest' --tests 'com.androdr.sigma.LogsourceTaxonomyCrossCheckTest' --tests 'com.androdr.sigma.SigmaRuleParserTest' -i 2>&1 | tail -40`
Expected: BUILD SUCCESSFUL. These tests catch schema drift between Kotlin and YAML (which should not occur — taxonomy and `AppTelemetry` are aligned) and parser regressions.

- [ ] **Step 3: Run the full unit test suite**

Run: `./gradlew testDebugUnitTest 2>&1 | tail -20`
Expected: BUILD SUCCESSFUL. Cold gradle on this VM is ~5-15 min per memory `feedback_ci_wait_pattern.md`-adjacent constraints; warm runs are much faster.

- [ ] **Step 4: Run lint**

Run: `./gradlew lintDebug 2>&1 | tail -20`
Expected: BUILD SUCCESSFUL. New resources under `res/raw/` may trigger lint informationals about unknown resource names — these are expected for SIGMA rule YAMLs and have not historically been a blocker.

---

### Task 7.5: Gate 5 — per-rule LLM self-review via `update-rules-review` skill

**Why:** Gate 5 of the spec's validation flow is a structured per-rule review against criteria from `update-rules-review.md`: logical correctness, FP risk, severity appropriateness, completeness, remediation quality. It is narrower than the two-reviewer cycle in Task 8 and complementary to it — Task 8's reviewers check spec compliance + adversarial quality across the whole pack; Gate 5 checks each individual rule against the rule-author skill's review criteria.

**Files:** None modified. Reviewers produce structured YAML output as Agent tool return values.

- [ ] **Step 1: Dispatch 4 reviewers in parallel — one per rule**

Use 4 `Agent` tool calls in one message, all with `subagent_type: "general-purpose"`. For each rule, the prompt embeds the `update-rules-review` skill body verbatim plus the candidate rule, the source SIR summary, and 2-3 similar existing rules for comparison.

Per-rule prompt template (substituting per-rule values):

```
You are the LLM self-review agent for AndroDR rule androdr-<NNN>. Review the candidate rule against the criteria below. You have NOT seen the rule author's reasoning — review with fresh eyes.

# Skill instructions (follow exactly):

<verbatim contents of .claude/commands/update-rules-review.md>

# Candidate rule YAML

<paste full YAML of third-party/android-sigma-rules/staging/app_scanner/androdr_<NNN>_data_broker_<slug>.yml>

# Source SIR summary

Threat: <SDK name from the SIR>
Description: <2-sentence summary from the SIR's threat.description>
Indicators: <list of class-name anchors and any other relevant indicators from the SIR>
Confidence: high; requires_verification: <value from SIR>.

# Similar existing rules for comparison

<paste full YAML of:
 - third-party/android-sigma-rules/app_scanner/androdr_001_package_ioc.yml
 - third-party/android-sigma-rules/staging/app_scanner/androdr_078_meiya_pico_forensics.yml>

Run the 5-criterion review and return the structured YAML output specified in the skill.
```

- [ ] **Step 2: Collect the 4 reviews**

Each review returns a YAML block with `verdict: pass / pass_with_notes / fail`, `false_positive_risk: low/medium/high`, `issues: []`, `suggestions: []`. Read all 4.

- [ ] **Step 3: Classify outcome**

- All 4 verdicts `pass` or `pass_with_notes` with `fp_risk: low` → proceed to Task 8.
- Any verdict `fail` OR any `fp_risk: high` → proceed to Task 8.5 (which handles both Gate-5 and Task-8 reviewer feedback uniformly) BEFORE running Task 8. The fix loop applies; loop guard still max 2 attempts.

- [ ] **Step 4: Record outcomes**

Capture the 4 review YAMLs in the AndroDR PR description (Task 9 Step 4) under a "Gate 5 reviews" section so the merge gate is auditable post-hoc.

---

### Task 8: Two-reviewer cycle in parallel (spec-compliance + harsh-quality)

**Why:** Project standing rule (memories `feedback_two_reviewers.md`, `feedback_mandatory_review.md`). Reviewers gate the commit.

**Files:** None modified. Reviewers produce written reports as Agent tool return values.

- [ ] **Step 1: Dispatch both reviewers in a single message**

Use 2 `Agent` tool calls in one message, both with `subagent_type: "general-purpose"`.

**Reviewer A — Spec compliance.** Prompt:

```
You are the spec-compliance reviewer for the broker-SDK installed_app rule pack.

Spec: /home/yasir/AndroDR/docs/superpowers/specs/2026-05-18-broker-sdk-installed-app-rule-pack-design.md

Artifacts:
- Rules: third-party/android-sigma-rules/staging/app_scanner/androdr_07{9,80,81,82}_data_broker_*.yml
- Decisions: third-party/android-sigma-rules/decisions/2026-05-18-broker-sdk-pack.yml
- Bundled rules: app/src/main/res/raw/sigma_androdr_07{9,80,81,82}_data_broker_*.yml
- Fixtures: app/src/test/resources/gate4-fixtures/{outlogic,venntel,predicio,cuebiq}-broker-sdk.yml

For each rule file, verify against the spec's per-rule design section:
1. id, status: experimental, level: medium, category: incident, service: app_scanner.
2. Detection selector uses `embedded_component_class|contains` with exactly the match values locked in the deltas table — and NOT `io.mysdk.*` for Outlogic.
3. filter_system_app + condition match the exemplar.
4. evidence_type is `ioc_match` (not the originally-drafted `embedded_sdk_fingerprint`).
5. references list cites the SIR provenance (≥1 vendor + ≥1 independent source).
6. tags include attack.t1430 and attack.t1437.001.

For each bundled rule in res/raw/: byte-identical to the submodule file (modulo trailing newlines).

For each fixture file: rule_file references the bundled name with sigma_ prefix; service: app_scanner; true_positives contain the SDK's class names; true_negatives include system-app variant + benign + cross-isolation. Outlogic fixture must include the io.mysdk.* SignalFrame negative case.

For the decision manifest: 2 entries (Mobilewalla, Adsquare), each type: telemetry_gap, chosen: skip, source_sir set, reasoning quotes the SIR gap analysis.

Output PASS/FAIL per artifact + a summary verdict. Read-only — do not modify files.
```

**Reviewer B — Harsh quality.** Prompt:

```
You are the harsh-quality reviewer for the broker-SDK installed_app rule pack. Be skeptical.

Same artifact list as Reviewer A. Spec: /home/yasir/AndroDR/docs/superpowers/specs/2026-05-18-broker-sdk-installed-app-rule-pack-design.md.
SIRs for cross-reference: /home/yasir/AndroDR/docs/superpowers/research/2026-05-18-broker-sdks/

Check:
1. Class-name match values appear verbatim in the cited SIR indicators[] entries. Use jq or grep to confirm; flag any value that is NOT in the SIR.
2. References URLs in each rule actually back up the SDK identification (spot-check with WebFetch on at least 1 URL per rule; flag UNREACHABLE separately from NOT VERIFIED).
3. Rule descriptions are anchored on cited evidence, not LLM filler. A description that could apply to any data-broker SDK with the name swapped is a REJECT.
4. The Outlogic rule does NOT contain `io.mysdk.` anywhere in the detection block. Failure here is a hard REJECT.
5. Fixture true_negatives are concrete and meaningful — not just copies of true_positives with a different package name. Each negative should defend a specific design choice or class of false-positive risk.
6. The decision-manifest reasoning text accurately summarizes the SIR's gap analysis; flag any fabricated claim.
7. Severity calibration: level: medium for all 4 broker-SDK rules is intentional (privacy harm, not malware). Confirm no rule slipped into critical/high without justification.

Verdict per artifact: PASS / ACCEPTABLE / REJECT. REJECT triggers re-author. Read-only.
```

- [ ] **Step 2: Collect both reports**

Wait for both Agent calls to return. Read the verdicts.

- [ ] **Step 3: Classify outcome**

- Both reviewers return PASS/ACCEPTABLE on all artifacts → proceed to Task 9.
- Either reviewer flags REJECT on any artifact → proceed to Task 8.5 (fix loop).

---

### Task 8.5: Fix-and-recheck loop (conditional)

**Why:** Targeted fix for reviewer-flagged artifacts. Bounded loop prevents infinite cycles.

**Files:** Re-writes only the flagged YAML files.

- [ ] **Step 1: Build the fix list**

For each artifact flagged REJECT, record: file path + reviewer feedback verbatim + which specific element needs change.

- [ ] **Step 2: Apply targeted edits**

Use the `Edit` tool on each flagged file. Do NOT rewrite whole files unless necessary. If a rule's match values are wrong, fix them in BOTH the submodule rule AND the bundled copy in `res/raw/`.

- [ ] **Step 3: Re-validate the affected files**

For submodule rules: `python3 third-party/android-sigma-rules/validation/validate-rule.py <file>`.
For the decision manifest: `python3 third-party/android-sigma-rules/validation/validate-decisions.py <file>`.
For fixtures: `./gradlew :app:testDebugUnitTest --tests 'com.androdr.sigma.GateFourFixtureTest' -i`.

- [ ] **Step 4: Re-run the two reviewers**

Re-dispatch only the reviewers whose verdict was REJECT (or both if either had REJECT). Loop guard: max 2 fix attempts. If a third attempt is needed, STOP and escalate to the user with the reviewer feedback.

- [ ] **Step 5: Verdict converged** → proceed to Task 9.

---

### Task 9: Commit AndroDR changes, push, open PR

**Files:** Stages bundled rules + fixtures on `feat/168-installed-app-broker-sdk-pack`.

- [ ] **Step 1: Stage the new files**

Run from `/home/yasir/AndroDR/`:
```bash
git add \
  app/src/main/res/raw/sigma_androdr_079_data_broker_outlogic.yml \
  app/src/main/res/raw/sigma_androdr_080_data_broker_venntel.yml \
  app/src/main/res/raw/sigma_androdr_081_data_broker_predicio.yml \
  app/src/main/res/raw/sigma_androdr_082_data_broker_cuebiq.yml \
  app/src/test/resources/gate4-fixtures/outlogic-broker-sdk.yml \
  app/src/test/resources/gate4-fixtures/venntel-broker-sdk.yml \
  app/src/test/resources/gate4-fixtures/predicio-broker-sdk.yml \
  app/src/test/resources/gate4-fixtures/cuebiq-broker-sdk.yml \
  third-party/android-sigma-rules
git status --short
```
Expected: 8 new files staged + the submodule entry showing the pointer bump (`M third-party/android-sigma-rules`).

- [ ] **Step 2: Commit**

```bash
git commit -m "$(cat <<'EOF'
feat(rules): broker-SDK installed_app pack — bundling + Gate 4 fixtures (#168)

Sibling to android-sigma-rules PR <SUBMODULE_PR_URL>. Bundles the 4
broker-SDK rules (androdr-079..082) into res/raw/ and adds 4 Gate-4
fixtures asserting each rule fires on positive telemetry and stays
silent on negatives — including the load-bearing SignalFrame io.mysdk.*
case that defends the design choice to drop that prefix from the
Outlogic rule.

Submodule pointer bumped to the merged PR commit.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```
Replace `<SUBMODULE_PR_URL>` with the URL captured in Task 4 Step 4.

- [ ] **Step 3: Push the branch**

```bash
git push -u origin feat/168-installed-app-broker-sdk-pack
```

- [ ] **Step 4: Open the AndroDR PR**

```bash
gh pr create --title "feat(#168): broker-SDK installed_app rule pack" --body "$(cat <<'EOF'
## Summary
- Bundles 4 SIGMA rules (androdr-079..082) into `app/src/main/res/raw/` —
  Outlogic, Venntel, Predicio, Cuebiq broker SDKs.
- 4 Gate-4 fixtures under `app/src/test/resources/gate4-fixtures/` exercise
  each rule against positive + negative telemetry, including the
  SignalFrame `io.mysdk.*` case that defends dropping that prefix from
  the Outlogic match set.
- Submodule pointer bumped to the merged `android-sigma-rules` PR
  (`feat(rules): broker-SDK installed_app pack`).

Companion of `android-sigma-rules` PR <SUBMODULE_PR_URL>. Part of #168
(does NOT close — DNS rule pack and combination rule are subsequent
sessions).

## Test plan
- [x] `./gradlew :app:testDebugUnitTest --tests 'com.androdr.sigma.GateFourFixtureTest'` green.
- [x] `./gradlew :app:testDebugUnitTest --tests 'com.androdr.sigma.BundledRulesSchemaCrossCheckTest'` green.
- [x] `./gradlew testDebugUnitTest` green.
- [x] `./gradlew lintDebug` green.
- [x] Two-reviewer cycle (spec-compliance + harsh-quality) passed.
- [ ] On-device dry-run on Samsung Z Fold 2 (R3CR300WRRH): zero findings
      for the 4 new rule IDs on the user's installed apps; `adb logcat -s AppScanner:D`
      evidence captured below.

## On-device evidence
<paste adb logcat output from Task 10 here before merging>

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
)" 2>&1 | tail -5
```
Replace `<SUBMODULE_PR_URL>` and capture the new PR number.

---

### Task 10: On-device dry-run on Z Fold 2

**Why:** Spec acceptance criterion. The Z Fold 2 has the user's real app inventory. None of those apps should ship Outlogic/Venntel/Predicio/Cuebiq SDKs; we expect zero findings for the 4 new rule IDs. Any unexpected hit is a false positive that needs investigation BEFORE merge.

**Files:** None modified.

- [ ] **Step 1: Confirm device connectivity (USB passthrough is intermittent)**

Run: `adb devices`
Expected: `R3CR300WRRH` listed with state `device`. If `unauthorized` or `offline`, ask the user to re-plug / accept the prompt on the device. If the device is not visible at all, escalate to the user — the dry-run is required per the spec.

- [ ] **Step 2: Build and install the debug APK**

Run: `./gradlew installDebug 2>&1 | tail -10`
Expected: `BUILD SUCCESSFUL`; APK installed. The `applicationIdSuffix = ".debug"` means the install does not collide with any release build of AndroDR.

- [ ] **Step 3: Launch the app and trigger a scan**

Either tap "Scan" on the Dashboard manually, or run:
```bash
adb shell am start -n com.androdr.debug/com.androdr.MainActivity
```
Wait for the scan to complete (the Dashboard surfaces a progress indicator; the 435-app Z Fold 2 takes ~30s end-to-end per the prior session's numbers).

- [ ] **Step 4: Capture relevant logcat output**

```bash
adb logcat -d -s AppScanner:D SigmaRuleEngine:D RuleMatchService:D | tee /tmp/androdr-broker-sdk-dryrun.log
```
Then filter:
```bash
grep -E 'androdr-(079|080|081|082)' /tmp/androdr-broker-sdk-dryrun.log
```
Expected: empty output (no rule firings for the 4 new IDs). If anything appears, capture the full context and investigate before merging.

- [ ] **Step 5: Paste evidence into the PR description**

Append to the PR description (use `gh pr edit <PR-NUM> --body ...`):

```
On-device dry-run on Samsung Z Fold 2 (R3CR300WRRH), 2026-05-18:

$ adb logcat -d -s AppScanner:D | head -3
<paste first 3 lines>

$ grep -E 'androdr-(079|080|081|082)' /tmp/androdr-broker-sdk-dryrun.log | wc -l
0

No findings for the 4 new rule IDs across the device's <N> installed apps.
```

---

### Task 11: Admin-merge AndroDR PR

**Why:** Per memory `feedback_ci_wait_pattern.md`, admin-merge after local checks pass; CI is out of budget. Don't admin-merge until on-device evidence is in the PR body.

**Files:** None modified.

- [ ] **Step 1: Confirm PR check status**

Run: `gh pr checks <PR-NUM>`
Expected: pending or partial-pass on CI checks. If any check is `fail`, STOP and investigate.

- [ ] **Step 2: Confirm the PR body has the on-device evidence appended (Task 10 Step 5)**

Run: `gh pr view <PR-NUM> --json body --jq .body | grep -E 'On-device dry-run|androdr-(079|080|081|082)' | head -5`
Expected: the dry-run block from Task 10 Step 5 is present.

- [ ] **Step 3: Admin-merge**

Run: `gh pr merge <PR-NUM> --squash --admin --delete-branch`
Expected: merge succeeds, branch deleted on remote and locally.

- [ ] **Step 4: Verify on main**

```bash
git checkout main
git pull --ff-only
git log -2 --pretty=format:'%h %s'
ls app/src/main/res/raw/sigma_androdr_07{9,80,81,82}_*.yml
ls app/src/test/resources/gate4-fixtures/*-broker-sdk.yml
```
Expected: latest commit is the squash-merge; 4 bundled rules + 4 fixtures present on `main`.

---

## Definition of done

- 4 SIGMA rules merged in the `android-sigma-rules` submodule under `staging/app_scanner/` (`status: experimental`, `level: medium`).
- 2 `telemetry_gap` decisions merged in `decisions/2026-05-18-broker-sdk-pack.yml`.
- Submodule pointer in AndroDR `main` is bumped to the merged submodule commit.
- 4 rule YAMLs are bundled at `app/src/main/res/raw/sigma_androdr_07{9,80,81,82}_data_broker_*.yml`.
- 4 Gate-4 fixtures are at `app/src/test/resources/gate4-fixtures/{outlogic,venntel,predicio,cuebiq}-broker-sdk.yml`.
- `./gradlew testDebugUnitTest lintDebug` green on `main`.
- On-device dry-run evidence captured in the AndroDR PR description: zero firings for androdr-079..082 on the Z Fold 2's installed apps.
- Two-reviewer cycle (spec-compliance + harsh-quality) passed.
- Both PRs admin-merged.
