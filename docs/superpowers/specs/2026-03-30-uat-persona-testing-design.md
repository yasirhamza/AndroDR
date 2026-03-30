# Persona-Based UAT Testing Framework — Design Spec

## Goal

Validate AndroDR's output from real user perspectives using LLM-powered persona agents. The current test harness answers "did the rule fire?" — this framework answers "did the user understand the result and know what to do?"

## Motivation

- Detection accuracy (31/34 pass) does not guarantee user experience quality
- False positives on a clean device erode trust faster than missed detections
- The target audience (DV survivors, journalists, activists) cannot be expected to interpret technical security findings
- Different personas need different things from the same report: a DV survivor needs "what do I do right now," a security team needs "can I feed this into Splunk"

## Non-Goals

- Automated UI testing (Espresso/Compose test) — this evaluates report TEXT, not screen rendering
- Performance testing — handled separately
- Detection accuracy regression — existing test harness handles this

---

## 1. Personas

### 1.1 Maya — Domestic Violence Survivor

- **Technical level:** None
- **Threat model:** Partner installed monitoring app while phone was unattended
- **Evaluation weight:** 1.5 (highest priority — most vulnerable user)
- **Agent prompt:**

```
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
```

### 1.2 Karim — Investigative Journalist

- **Technical level:** Low
- **Threat model:** State actor targeting with zero-click spyware
- **Evaluation weight:** 1.2

```
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
```

### 1.3 Sarah — Security-Conscious Individual

- **Technical level:** Medium
- **Threat model:** General privacy protection, app hygiene
- **Evaluation weight:** 1.0

```
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
```

### 1.4 Raj — Small Org Security Team

- **Technical level:** High
- **Threat model:** Employee device fleet check, compliance, incident triage
- **Evaluation weight:** 1.0

```
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
```

---

## 2. User Stories

### 2.1 Story Matrix

| Story ID | Persona | Threat Scenario | Harness Setup | Purpose |
|---|---|---|---|---|
| `dv_stalkerware_detected` | Maya | Stalkerware present | `--profile stalkerware` | Primary threat detection |
| `dv_clean_device` | Maya | No threats | `--track 4` | Reassurance on clean phone |
| `dv_banking_trojan` | Maya | Banking trojan (not stalkerware) | `--profile banking` | Unexpected threat communication |
| `journalist_nation_state` | Karim | Pegasus/Predator/Graphite | `--profile journalist` | Primary threat detection |
| `journalist_clean` | Karim | No targeting detected | `--track 4` | Routine check reassurance |
| `clean_device_confidence` | Sarah | Clean phone (FP stress test) | `--track 4` | False positive validation |
| `clean_user_compromised` | Sarah | Stalkerware on "clean" phone | `--profile stalkerware` | Escalation communication |
| `fleet_full_triage` | Raj | Full threat landscape | `--profile full` | Comprehensive triage |
| `fleet_single_incident` | Raj | Single stalkerware finding | `--only thetruthspy_stalkerware` | Quick incident response |

### 2.2 Story Definition Format

```yaml
stories:
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
```

---

## 3. Evaluation Criteria

Seven criteria evaluated per story, scored 1-5:

| Criterion | What it measures | Failure flags |
|---|---|---|
| **Comprehension** | Can the persona understand every finding without Googling? | JARGON FAIL |
| **Actionability** | Does each finding tell them exactly what to do? | ACTIONABILITY FAIL |
| **Signal-to-noise** | Are there too many findings? Would the persona give up? | NOISE OVERLOAD |
| **Emotional calibration** | Does severity language match actual risk? | PANIC INDUCING, COMPLACENCY RISK |
| **Completeness** | For the persona's threat model, are the right things checked? | DETECTION GAP |
| **Export utility** | Can the persona share the report with someone who can help? | EXPORT GAP |
| **Trust** | Would the persona trust this app after seeing results? | FALSE ALARM, CREDIBILITY FAIL |

Plus persona-specific bonus criteria:
- Maya: (none — the 7 core criteria cover her needs)
- Karim: Forensic narrative, Amnesty Tech shareability
- Sarah: Net promoter score, false alarm fatigue
- Raj: Scalability, SIEM compatibility, data utility

### Scoring

- **Pass threshold per criterion:** >= 3
- **Pass threshold overall (weighted):** >= 3.5
- **Blocking issue:** any criterion scoring 1, or any JARGON FAIL/FALSE ALARM/CREDIBILITY FAIL flag
- **Weights:** Maya's scores are multiplied by 1.5, Karim by 1.2, Sarah and Raj by 1.0

---

## 4. Architecture

### 4.1 Component Separation

```
test-adversary/uat-stories.yml     ← story + persona definitions (YAML)
test-adversary/run.sh --uat        ← bash: emulator + harness + report collection
.claude/commands/uat-test.md       ← skill: LLM persona dispatch + scorecard
build/uat/                         ← output: reports + evaluations + scorecard
```

The harness (bash) handles device interaction. The skill (Claude Code) handles persona evaluation. They are fully decoupled — reports from real devices can be evaluated without an emulator.

### 4.2 `run.sh --uat` Mode

```
./test-adversary/run.sh --uat emulator-5554
./test-adversary/run.sh --uat --persona dv_survivor emulator-5554
./test-adversary/run.sh --uat --story dv_clean_device emulator-5554
```

Steps:
1. Read `uat-stories.yml`, filter by `--persona` or `--story`
2. Group stories by `setup` command (avoid redundant installs)
3. For each unique setup group:
   a. Install samples via load mode
   b. Trigger scan
   c. Pull report AND timeline CSV to `build/uat/{story_id}/`
   d. Clean up before next group
4. Write `build/uat/manifest.yml` with paths to all collected reports
5. Print: `UAT reports collected. Run /uat-test --no-emulator to evaluate.`

### 4.3 `/uat-test` Skill

```
/uat-test                              # all stories, all personas
/uat-test --persona dv_survivor        # one persona
/uat-test --story clean_device_confidence  # one story
/uat-test --no-emulator                # evaluate existing reports
```

Steps:
1. Read `uat-stories.yml`
2. If `--no-emulator`, read `build/uat/manifest.yml` for report paths. Otherwise start emulator and run `run.sh --uat`
3. For each story, dispatch a persona agent with:
   - The persona's full system prompt
   - The report text
   - The timeline CSV (if available)
   - The story's acceptance criteria
4. Agent returns structured YAML with scores, flags, quotes, and suggestions
5. Aggregate into UAT scorecard
6. Save full results to `build/uat/results-{timestamp}.yml`
7. Print scorecard summary table

### 4.4 Agent Dispatch Template

```
Agent:
  subagent_type: general-purpose
  description: "UAT: {story.title} ({persona.name})"
  prompt: |
    {persona.prompt}

    === ANDRODR REPORT OUTPUT ===
    {report_text}

    === TIMELINE EXPORT ===
    {timeline_text}

    === ACCEPTANCE CRITERIA ===
    {story.criteria as checklist}

    === YOUR TASK ===
    Read the report above AS YOUR PERSONA. Do not break character.

    For each criterion category, provide:
    1. Score (1-5)
    2. Specific flags (JARGON FAIL, FALSE ALARM, etc.)
    3. The exact text that triggered the flag (quote from report)
    4. Suggested improvement (one sentence)

    Output as structured YAML:
    story_id: "{story.id}"
    persona: "{persona.name}"
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
    overall_impression: "One paragraph as your persona"
    blocking_issues: ["list of things that must be fixed"]
```

### 4.5 Parallel Dispatch

Stories sharing the same `setup` command share a single harness run. Persona agents for different stories are independent and can be dispatched in parallel.

### 4.6 Scorecard Output

```
=== AndroDR UAT Scorecard (v0.9.0.317) ===

Story: "Check phone — stalkerware is present" (Maya, DV survivor)
  Comprehension:        4/5  — 1 jargon flag: "accessibility service"
  Actionability:        3/5  — 2 findings missing step-by-step remediation
  Signal-to-noise:      5/5  — 7 findings, all relevant
  Emotional calibration: 4/5  — CRITICAL wording could be softer
  Completeness:         5/5  — stalkerware detected, accessibility flagged
  Export utility:       4/5  — shareable but no "for your advocate" framing
  Trust:                4/5  — 1 false alarm on WhatsApp
  WEIGHTED SCORE: 4.1/5.0

Story: "Scan clean phone and feel reassured" (Sarah, security-conscious)
  Comprehension:        5/5
  Actionability:        5/5
  Signal-to-noise:      4/5  — 3 MEDIUM findings on clean phone
  Emotional calibration: 5/5  — "your phone looks secure" message present
  Completeness:         5/5
  Export utility:       4/5
  Trust:                5/5  — no false alarms
  WEIGHTED SCORE: 4.7/5.0

OVERALL: 4.2/5.0 — all stories above threshold
BLOCKING ISSUES: 1 jargon failure ("accessibility service" for Maya)
```

---

## 5. File Layout

```
test-adversary/
├── uat-stories.yml          ← story + persona definitions
├── run.sh                   ← extended with --uat mode
├── manifest.yml             ← existing adversary scenarios
└── ...

.claude/commands/
└── uat-test.md              ← Claude Code skill

build/uat/                   ← output (gitignored)
├── manifest.yml             ← collected report paths
├── dv_stalkerware_detected/
│   ├── report.txt
│   └── timeline.csv
├── dv_clean_device/
│   ├── report.txt
│   └── timeline.csv
├── ...
└── results-20260330-180000.yml  ← scorecard results
```

---

## 6. Integration with Existing Harness

The `--uat` mode reuses the existing harness infrastructure:
- Same `run.sh` script, same `selector.py`, same `manifest.yml` for scenario selection
- Same emulator setup, APK installation, scan triggering, report pulling
- The `uat-stories.yml` references harness profiles/tracks via the `setup` field
- The `--uat` mode is additive — does not modify `--load`, `--guided`, or regression modes

---

## 7. Testing the UAT Framework Itself

How do we know the UAT framework is working correctly?

1. **Smoke test:** Run `/uat-test --story clean_device_confidence` — Sarah should score >= 4 on a clean emulator
2. **Sensitivity test:** Run `/uat-test --story dv_stalkerware_detected` — Maya should flag at least one actionability issue (stalkerware remediation is inherently complex)
3. **Cross-check:** Run the same report through Maya and Raj — their scores should differ (Raj cares about export format, Maya cares about jargon)
4. **Regression gate:** Add to CI as a manual step: after passing the adversary simulation harness (31/34), run UAT and require overall >= 3.5
