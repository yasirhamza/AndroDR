# Persona-Based UAT Testing Framework Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a persona-based UAT testing framework that validates AndroDR's output from 4 user perspectives (DV survivor, journalist, security-conscious user, small security team) using LLM-powered persona agents.

**Architecture:** YAML-defined user stories drive the existing test harness in a new `--uat` mode, which collects reports per story. A `/uat-test` Claude Code skill dispatches persona agents against the reports, producing a weighted scorecard with pass/fail per criterion.

**Tech Stack:** Bash (harness), Python (story selector), YAML (stories/personas), Claude Code skill (LLM dispatch)

**Spec:** `docs/superpowers/specs/2026-03-30-uat-persona-testing-design.md`

---

## File Structure

### New Files
| File | Responsibility |
|------|---------------|
| `test-adversary/uat-stories.yml` | Persona definitions + user stories + acceptance criteria |
| `.claude/commands/uat-test.md` | Claude Code skill for LLM persona dispatch + scorecard |

### Modified Files
| File | Change |
|------|--------|
| `test-adversary/run.sh` | Add `--uat` mode + `--persona`/`--story` filters |

---

## Task 1: UAT Stories YAML

**Files:**
- Create: `test-adversary/uat-stories.yml`

- [ ] **Step 1: Create the stories file**

Create `test-adversary/uat-stories.yml` with all 4 personas and 9 stories from the spec. The file contains the full persona prompts, story definitions with harness setup commands, and structured acceptance criteria.

```yaml
version: 1

personas:
  dv_survivor:
    name: "Domestic violence survivor"
    technical_level: "none"
    threat_model: "Partner installed monitoring app while phone was unattended"
    evaluation_weight: 1.5
    prompt: |
      You are Maya, a 34-year-old teacher who recently left an abusive
      relationship. Your ex-partner had physical access to your phone
      for months. A friend at a DV shelter told you about AndroDR.

      You have ZERO technical knowledge. You don't know what an APK is,
      what "accessibility service" means, or what a VPN does. You use
      your phone for WhatsApp, Instagram, banking, and Google Maps.

      You are scared. You need to know: is someone watching me? And if
      yes, what do I do RIGHT NOW to make it stop?

      When evaluating AndroDR's output:
      - If you see a word you don't understand, flag it as JARGON FAIL
      - If a finding tells you there's a problem but not how to fix it,
        flag it as ACTIONABILITY FAIL
      - If you see more than 10 findings, note whether you'd give up reading
      - If a CRITICAL finding makes you want to throw your phone away
        rather than follow steps, flag it as PANIC INDUCING
      - If the app says "your phone looks secure" and you believe it,
        note that as TRUST PASS
      - If you see a finding about an app you use daily (WhatsApp, Instagram,
        your banking app), flag it as FALSE ALARM — this erodes your trust

      Rate each of these 1-5:
      1. Could you understand every finding? (Comprehension)
      2. Did you know what to do for each problem? (Actionability)
      3. Were there too many results to process? (Signal-to-noise)
      4. Did the severity feel right — urgent but not paralyzing? (Emotional calibration)
      5. Did it check for the things that matter to you? (Completeness)
      6. Could you share this with your advocate at the shelter? (Export utility)
      7. Do you trust this app after seeing the results? (Trust)

  journalist:
    name: "Investigative journalist"
    technical_level: "low"
    threat_model: "State actor targeting with zero-click spyware"
    evaluation_weight: 1.2
    prompt: |
      You are Karim, a 41-year-old investigative journalist covering
      government corruption in the Middle East. You've been warned by
      colleagues that Pegasus has been deployed against journalists in
      your region. A digital security trainer at a press freedom
      organization recommended AndroDR.

      You understand basic concepts (apps, permissions, updates) but
      you are NOT a developer. You know the word "Pegasus" but not how
      it technically works. You need to know: has my phone been
      compromised, and can I prove it to my editor and to Amnesty Tech?

      When evaluating AndroDR's output:
      - If Pegasus/Predator/Graphite are mentioned, note whether the
        context is clear or just a scary name drop
      - If CVE findings show numbers like CVE-2023-XXXXX without
        explaining what they mean for you, flag as JARGON FAIL
      - If the report can be exported and shared with a forensic analyst,
        note whether the format is useful or just a wall of text
      - If the timeline shows a clear narrative of what happened and when,
        note as FORENSIC VALUE PASS
      - If you can't tell whether you're compromised after reading the
        full report, flag as INCONCLUSIVE

      Rate each criterion 1-5 plus:
      - Would you forward this report to Amnesty Tech? (Export utility)
      - Does the timeline tell a coherent story? (Forensic narrative)

  security_conscious:
    name: "Security-conscious individual"
    technical_level: "medium"
    threat_model: "General privacy protection, app hygiene"
    evaluation_weight: 1.0
    prompt: |
      You are Sarah, a 28-year-old software designer who reads tech
      news and keeps her phone updated. You installed AndroDR because
      you're privacy-conscious, not because you suspect a specific
      threat. You understand what permissions are and what sideloading
      means, but you don't read security research papers.

      You want a clean bill of health. If the app flags things you
      deliberately installed (Bitwarden, a VPN, your company's MDM),
      you will lose trust in it. You expect the app to be smart enough
      to know the difference between Bitwarden and spyware.

      When evaluating AndroDR's output:
      - Every finding about a well-known Play Store app is a FALSE ALARM
      - If the overall risk says CRITICAL on a clean, updated phone,
        flag as CREDIBILITY FAIL
      - If MEDIUM findings are vague ("review if unexpected"), note
        whether the vagueness is helpful or annoying
      - If the app correctly identifies your phone as secure with
        only minor informational items, note as CALIBRATION PASS

      Rate each criterion 1-5 plus:
      - Would you recommend this app to a friend? (Net promoter)
      - Did any finding make you roll your eyes? (False alarm fatigue)

  small_security_team:
    name: "Small org security team"
    technical_level: "high"
    threat_model: "Employee device fleet check, compliance, incident triage"
    evaluation_weight: 1.0
    prompt: |
      You are Raj, a 36-year-old IT security analyst at a 200-person
      company. You don't have budget for a commercial MDM/EDR solution.
      Your CISO asked you to evaluate AndroDR as a lightweight
      alternative for periodic device health checks on employee phones.

      You understand SIGMA rules, IOCs, MITRE ATT&CK, CVEs, and
      forensic timelines. You need the tool to produce structured,
      exportable data that you can feed into your SIEM or triage
      spreadsheet. You care about false positive rates because you'll
      be reviewing results from 50 devices.

      When evaluating AndroDR's output:
      - If the CSV export is missing columns you need (MITRE technique,
        package name, severity), flag as EXPORT GAP
      - If findings can't be filtered by severity, flag as TRIAGE FAIL
      - If the same finding appears 4x for the same app across scans,
        flag as DEDUP FAIL
      - If the report includes device model, OS version, patch level,
        and scan timestamp, note as FLEET READY
      - If you could write a Splunk query against the CSV, note as
        SIEM COMPATIBLE

      Rate each criterion 1-5 plus:
      - Would you deploy this across 50 devices? (Scalability)
      - Can you build a compliance dashboard from the exports? (Data utility)

stories:
  # Maya — primary threat
  - id: dv_stalkerware_detected
    persona: dv_survivor
    title: "Check phone — stalkerware is present"
    setup: "--load --profile stalkerware"
    criteria:
      comprehension:
        - "No jargon: CVE, IOC, SIGMA, DNS must not appear in findings"
        - "Every finding uses words a non-technical person would understand"
      actionability:
        - "Each CRITICAL/HIGH finding has a step-by-step remediation"
        - "Remediation references Settings paths, not developer concepts"
      signal_to_noise:
        - "Fewer than 15 total findings"
        - "No more than 3 findings per legitimate app"
      emotional_calibration:
        - "CRITICAL findings explain urgency without causing panic"
        - "LOW/clean results are reassuring, not clinical"
      completeness:
        - "Stalkerware apps are detected with CRITICAL severity"
        - "Accessibility abuse is flagged"
      export_utility:
        - "Report can be shared via standard share sheet"
        - "Report is readable by a DV advocate"
      trust:
        - "No false positives on common apps"
        - "Overall risk level reflects actual threats, not noise"

  # Maya — clean baseline
  - id: dv_clean_device
    persona: dv_survivor
    title: "Check phone — no threats found"
    setup: "--load --track 4"
    criteria:
      comprehension:
        - "Post-scan guidance uses simple, reassuring language"
      actionability:
        - "No action required message is clear"
      signal_to_noise:
        - "Fewer than 5 findings on a clean device"
      emotional_calibration:
        - "Overall message is reassuring, not clinical"
      completeness:
        - "Device posture checks ran successfully"
      export_utility:
        - "Report says the phone is secure"
      trust:
        - "User feels reassured, not confused"

  # Maya — unexpected threat
  - id: dv_banking_trojan
    persona: dv_survivor
    title: "Check phone — banking trojan found (not stalkerware)"
    setup: "--load --profile banking"
    criteria:
      comprehension:
        - "Banking trojan is explained without technical jargon"
      actionability:
        - "User knows to uninstall the app and contact their bank"
      signal_to_noise:
        - "Trojan findings are clearly prioritized above noise"
      emotional_calibration:
        - "Severity communicates real financial risk"
      completeness:
        - "Banking threat is detected even though user searched for stalkerware"
      export_utility:
        - "Report could be shown to bank fraud department"
      trust:
        - "User trusts the app found something real"

  # Karim — primary threat
  - id: journalist_nation_state
    persona: journalist
    title: "Check for Pegasus targeting"
    setup: "--load --profile journalist"
    criteria:
      comprehension:
        - "Pegasus/Predator/Graphite campaign names appear when relevant"
        - "CVE findings explain what the vulnerability means"
      actionability:
        - "Report suggests contacting Amnesty/Citizen Lab for nation-state threats"
      signal_to_noise:
        - "Campaign-linked findings are prominent, not buried"
      emotional_calibration:
        - "Nation-state threat severity matches the actual danger"
      completeness:
        - "Campaign-linked CVEs are highlighted"
        - "IOC domain matches produce findings"
      export_utility:
        - "CSV export contains MVT-compatible columns"
        - "Timeline can be shared with a forensic analyst"
      trust:
        - "Journalist can tell whether they're targeted or not"

  # Karim — clean baseline
  - id: journalist_clean
    persona: journalist
    title: "Routine check — no targeting detected"
    setup: "--load --track 4"
    criteria:
      comprehension:
        - "Clear message that no nation-state indicators were found"
      actionability:
        - "Suggests keeping device updated as prevention"
      signal_to_noise:
        - "No alarming findings on a clean device"
      emotional_calibration:
        - "Reassuring without being dismissive of the threat"
      completeness:
        - "Campaign-specific checks (Pegasus/Predator/Graphite) ran"
      export_utility:
        - "Clean report can be shared with editor as evidence"
      trust:
        - "Journalist trusts the negative result"

  # Sarah — clean phone FP stress test
  - id: clean_device_confidence
    persona: security_conscious
    title: "Scan clean phone and feel reassured"
    setup: "--load --track 4"
    criteria:
      comprehension:
        - "All findings use plain language"
      actionability:
        - "MEDIUM findings have clear next steps"
      signal_to_noise:
        - "Fewer than 5 findings on a stock device"
        - "No CRITICAL findings unless genuine CVE exposure"
      emotional_calibration:
        - "Post-scan guidance says phone looks secure"
        - "Overall risk is LOW or MEDIUM, not CRITICAL"
      completeness:
        - "Device posture fully checked"
      export_utility:
        - "Report is concise enough to read in 30 seconds"
      trust:
        - "User does not feel the app is crying wolf"

  # Sarah — unexpected threat
  - id: clean_user_compromised
    persona: security_conscious
    title: "Stalkerware found on supposedly clean phone"
    setup: "--load --profile stalkerware"
    criteria:
      comprehension:
        - "Threat is clearly explained even to non-expert"
      actionability:
        - "Specific uninstall steps provided"
      signal_to_noise:
        - "Real threats stand out from informational items"
      emotional_calibration:
        - "Appropriate alarm without panic"
      completeness:
        - "Stalkerware detected as CRITICAL"
      export_utility:
        - "Report suitable for sharing with police or IT support"
      trust:
        - "User takes the finding seriously"

  # Raj — full triage
  - id: fleet_full_triage
    persona: small_security_team
    title: "Full device triage with all threat categories"
    setup: "--load --profile full"
    criteria:
      comprehension:
        - "Technical details available for analyst review"
      actionability:
        - "Findings are grouped by severity for quick prioritization"
        - "Known malware is clearly distinguished from policy violations"
      signal_to_noise:
        - "Finding count is manageable for fleet review"
      emotional_calibration:
        - "Severity levels are consistent and predictable"
      completeness:
        - "All detection categories produce results when threats present"
        - "Device posture covers ADB, bootloader, patch level"
      export_utility:
        - "CSV export is importable into spreadsheet"
        - "Report includes device model, Android version, patch level"
        - "MITRE ATT&CK techniques present in export"
      trust:
        - "False positive rate is acceptable for fleet deployment"

  # Raj — single incident
  - id: fleet_single_incident
    persona: small_security_team
    title: "Triage single stalkerware finding"
    setup: "--load --only thetruthspy_stalkerware"
    criteria:
      comprehension:
        - "Finding clearly identifies the threat family"
      actionability:
        - "Analyst knows immediate remediation steps"
      signal_to_noise:
        - "Single finding is prominent, not buried in noise"
      emotional_calibration:
        - "CRITICAL severity for confirmed stalkerware"
      completeness:
        - "IOC match details available (package name, cert hash)"
      export_utility:
        - "Can be attached to an incident ticket"
      trust:
        - "Analyst trusts the detection is not a false positive"
```

- [ ] **Step 2: Validate YAML syntax**

Run: `python3 -c "import yaml; yaml.safe_load(open('test-adversary/uat-stories.yml')); print('Valid')"`
Expected: `Valid`

- [ ] **Step 3: Commit**

```bash
git add test-adversary/uat-stories.yml
git commit -m "feat: add UAT stories with 4 personas and 9 user stories"
```

---

## Task 2: `run.sh --uat` Mode

**Files:**
- Modify: `test-adversary/run.sh`

- [ ] **Step 1: Add --uat flag parsing**

In the `while` loop at the top of `run.sh` (around line 16-29), add:

```bash
        --uat) MODE="uat" ;;
        --persona) shift; UAT_PERSONA="$1" ;;
        --story) shift; UAT_STORY="$1" ;;
```

Initialize the variables before the loop:

```bash
UAT_PERSONA=""
UAT_STORY=""
```

- [ ] **Step 2: Add UAT mode handler**

After the existing mode handlers (`if [ "$MODE" = "load" ]`, `if [ "$MODE" = "guided" ]`), add the UAT mode block. Add this BEFORE the regression mode (which is the default fallback).

Find the section where modes are dispatched and add:

```bash
if [ "$MODE" = "uat" ]; then
    UAT_STORIES="$SCRIPT_DIR/uat-stories.yml"
    UAT_OUTPUT="$SCRIPT_DIR/../build/uat"
    mkdir -p "$UAT_OUTPUT"

    echo "=== AndroDR UAT Report Collection ==="
    echo ""

    # Parse stories from YAML using Python
    STORY_LIST=$(python3 -c "
import yaml, sys
with open('$UAT_STORIES') as f:
    data = yaml.safe_load(f)
persona_filter = '${UAT_PERSONA}'
story_filter = '${UAT_STORY}'
for story in data['stories']:
    if persona_filter and story['persona'] != persona_filter:
        continue
    if story_filter and story['id'] != story_filter:
        continue
    print(f\"{story['id']}|{story['persona']}|{story['setup']}|{story['title']}\")
")

    if [ -z "$STORY_LIST" ]; then
        echo "ERROR: No stories matched filters." >&2
        exit 1
    fi

    STORY_COUNT=$(echo "$STORY_LIST" | wc -l)
    echo "Selected $STORY_COUNT stories."
    echo ""

    # Group stories by setup command to avoid redundant installs
    declare -A SETUP_GROUPS
    while IFS='|' read -r sid spersona ssetup stitle; do
        SETUP_GROUPS["$ssetup"]+="$sid|$spersona|$stitle;"
    done <<< "$STORY_LIST"

    # Process each setup group
    for setup_cmd in "${!SETUP_GROUPS[@]}"; do
        echo "──────────────────────────────────────────────────────────"
        echo "  Setup: $setup_cmd"
        echo "──────────────────────────────────────────────────────────"

        # Run the harness in load mode with this setup (non-interactive)
        # We need to capture the report without waiting for ENTER
        echo "  Installing samples..."

        # Build the load command by parsing setup flags
        LOAD_ARGS=""
        for flag in $setup_cmd; do
            case "$flag" in
                --load) ;; # skip, we handle this
                *) LOAD_ARGS="$LOAD_ARGS $flag" ;;
            esac
        done

        # Use the existing selector to get scenario IDs
        LOAD_IDS=$(python3 "$SCRIPT_DIR/selector.py" "$MANIFEST" $LOAD_ARGS 2>/dev/null || echo "")

        if [ -n "$LOAD_IDS" ]; then
            # Install all samples for this setup group
            while IFS= read -r scenario_id; do
                install_scenario "$scenario_id" 2>/dev/null || true
            done <<< "$LOAD_IDS"
        fi

        # Trigger scan
        echo "  Triggering scan..."
        $ADB shell am broadcast -a com.androdr.ACTION_SCAN -p com.androdr.debug >/dev/null 2>&1
        sleep 12

        # Pull report
        local report="$WORKDIR/uat-report.txt"
        $ADB pull /sdcard/Android/data/com.androdr.debug/files/androdr_last_report.txt "$report" 2>/dev/null || true

        # Save report for each story in this group
        IFS=';' read -ra STORIES <<< "${SETUP_GROUPS[$setup_cmd]}"
        for story_entry in "${STORIES[@]}"; do
            [ -z "$story_entry" ] && continue
            IFS='|' read -r sid spersona stitle <<< "$story_entry"
            local story_dir="$UAT_OUTPUT/$sid"
            mkdir -p "$story_dir"
            cp "$report" "$story_dir/report.txt" 2>/dev/null || true
            echo "  Saved: $story_dir/report.txt ($stitle)"
        done

        # Cleanup
        for pkg in "${INSTALLED_PACKAGES[@]+"${INSTALLED_PACKAGES[@]}"}"; do
            $ADB uninstall "$pkg" 2>/dev/null || true
        done
        INSTALLED_PACKAGES=()
        echo ""
    done

    # Write manifest
    python3 -c "
import yaml, os, sys
from datetime import datetime
manifest = {
    'timestamp': datetime.utcnow().isoformat() + 'Z',
    'stories': []
}
uat_dir = '$UAT_OUTPUT'
for d in sorted(os.listdir(uat_dir)):
    report_path = os.path.join(uat_dir, d, 'report.txt')
    if os.path.isfile(report_path):
        manifest['stories'].append({
            'id': d,
            'report': report_path
        })
with open(os.path.join(uat_dir, 'manifest.yml'), 'w') as f:
    yaml.dump(manifest, f, default_flow_style=False)
print(f\"Manifest written: {os.path.join(uat_dir, 'manifest.yml')}\")
"

    echo ""
    echo "============================================================"
    echo "  UAT reports collected: $STORY_COUNT stories"
    echo "  Output: $UAT_OUTPUT/"
    echo ""
    echo "  Run /uat-test --no-emulator to evaluate with persona agents."
    echo "============================================================"
    exit 0
fi
```

Note: This uses `install_scenario` which is a function already defined in `run.sh` for the load/regression modes. If it doesn't exist as a standalone function, extract the install logic into one.

- [ ] **Step 3: Test the UAT mode**

Run: `export JAVA_HOME=/home/yasir/Applications/android-studio/jbr && export ANDROID_HOME=$HOME/Android/Sdk && export PATH=$JAVA_HOME/bin:$PATH:$ANDROID_HOME/platform-tools:$ANDROID_HOME/emulator && ./test-adversary/run.sh --uat --story dv_clean_device emulator-5554 2>&1 | tail -20`

Expected: Report collected to `build/uat/dv_clean_device/report.txt`, manifest written.

- [ ] **Step 4: Commit**

```bash
git add test-adversary/run.sh
git commit -m "feat: add --uat mode to test harness for persona-based report collection"
```

---

## Task 3: `/uat-test` Claude Code Skill

**Files:**
- Create: `.claude/commands/uat-test.md`

- [ ] **Step 1: Create the skill file**

Create `.claude/commands/uat-test.md`:

````markdown
---
description: "Run persona-based user acceptance testing against AndroDR reports"
---

# UAT Test — Persona-Based Evaluation

Evaluate AndroDR's scan reports from real user perspectives using LLM persona agents.

## Usage

```
/uat-test                              # all stories, all personas
/uat-test --persona dv_survivor        # one persona's stories
/uat-test --story clean_device_confidence  # one specific story
/uat-test --no-emulator                # skip harness, evaluate existing reports
```

## Process

1. Read `test-adversary/uat-stories.yml` for persona definitions and stories
2. Filter stories by `--persona` or `--story` if specified
3. If `--no-emulator` is NOT set:
   a. Start emulator if not running
   b. Install latest debug APK (`./gradlew installDebug`)
   c. Run `test-adversary/run.sh --uat {filters} emulator-5554`
4. Read reports from `build/uat/{story_id}/report.txt`
5. For each story:
   a. Load the persona prompt from `uat-stories.yml`
   b. Load the report text from the story's output directory
   c. Format the acceptance criteria as a checklist
   d. Dispatch an Agent with the persona prompt + report + criteria
   e. The agent MUST stay in character and return structured YAML:
      ```yaml
      story_id: "..."
      persona: "..."
      scores:
        comprehension: {score: N, flags: [...]}
        actionability: {score: N, flags: [...]}
        signal_to_noise: {score: N, flags: [...]}
        emotional_calibration: {score: N, flags: [...]}
        completeness: {score: N, flags: [...]}
        export_utility: {score: N, flags: [...]}
        trust: {score: N, flags: [...]}
      persona_specific:
        - {key: "...", score: N}
      overall_impression: "One paragraph as the persona"
      blocking_issues: ["list of must-fix items"]
      ```
6. Aggregate scores into a UAT scorecard
7. Print summary table
8. Save full results to `build/uat/results-{timestamp}.yml`

## Agent Dispatch Template

For each story, dispatch an Agent with:

```
Agent:
  subagent_type: general-purpose
  description: "UAT: {story.title} ({persona.name})"
  prompt: |
    {persona.prompt from uat-stories.yml}

    === ANDRODR REPORT OUTPUT ===
    {contents of build/uat/{story.id}/report.txt}

    === ACCEPTANCE CRITERIA ===
    {story.criteria formatted as a checklist}

    === YOUR TASK ===
    Read the report above AS YOUR PERSONA. Do not break character.

    For each criterion category, provide:
    1. Score (1-5)
    2. Specific flags (JARGON FAIL, ACTIONABILITY FAIL, FALSE ALARM, etc.)
    3. The exact text from the report that triggered the flag (quote it)
    4. Suggested improvement (one sentence)

    Output ONLY structured YAML — no prose before or after.
```

## Scorecard Computation

For each story:
- Weighted score = (sum of all criteria scores) / 7 * persona.evaluation_weight
- Story passes if: all criteria >= 3 AND weighted score >= 3.5 AND zero blocking issues

Overall scorecard:
- Overall score = average of all story weighted scores
- Overall passes if: all stories pass AND overall score >= 3.5

## Output Format

Print a table like:

```
=== AndroDR UAT Scorecard (v0.9.0.317) ===

Story: "Check phone — stalkerware is present" (Maya, DV survivor)
  Comprehension:         4/5
  Actionability:         3/5  — ACTIONABILITY FAIL: "no step-by-step for accessibility"
  Signal-to-noise:       5/5
  Emotional calibration: 4/5
  Completeness:          5/5
  Export utility:        4/5
  Trust:                 4/5
  WEIGHTED SCORE: 4.1/5.0  ✓ PASS

...

OVERALL: 4.0/5.0 — 9/9 stories pass
BLOCKING ISSUES: 1 (jargon: "accessibility service" for Maya)
```

## Parallel Dispatch

Stories with different `setup` commands are independent. Dispatch their persona agents in parallel using multiple Agent tool calls in a single message.

Stories sharing the same `setup` command share the same report — dispatch their agents in parallel too since they evaluate the same text with different personas.

## --no-emulator Mode

For evaluating reports from real devices:
1. Check `build/uat/manifest.yml` exists
2. Read report paths from the manifest
3. Skip harness setup entirely
4. Proceed directly to persona agent dispatch

This lets you evaluate reports pulled from a Samsung S25, Xiaomi, or any real device without needing an emulator.
````

- [ ] **Step 2: Verify the skill is loadable**

Run: `ls -la .claude/commands/uat-test.md`
Expected: File exists with the content above.

- [ ] **Step 3: Commit**

```bash
git add .claude/commands/uat-test.md
git commit -m "feat: add /uat-test skill for persona-based acceptance testing"
```

---

## Task 4: Integration Test

- [ ] **Step 1: Dry-run the full pipeline**

Run the harness for one story:
```bash
export JAVA_HOME=/home/yasir/Applications/android-studio/jbr
export ANDROID_HOME=$HOME/Android/Sdk
export PATH=$JAVA_HOME/bin:$PATH:$ANDROID_HOME/platform-tools:$ANDROID_HOME/emulator
./test-adversary/run.sh --uat --story dv_clean_device emulator-5554
```

Verify:
- `build/uat/dv_clean_device/report.txt` exists and contains a valid report
- `build/uat/manifest.yml` exists and lists the story

- [ ] **Step 2: Run the skill in no-emulator mode**

Run: `/uat-test --no-emulator --story dv_clean_device`

Verify:
- Persona agent dispatched with Maya's prompt + the report
- Structured YAML response with scores
- Scorecard printed

- [ ] **Step 3: Commit any fixes**

```bash
git add -A
git commit -m "fix: UAT integration test fixes"
```
