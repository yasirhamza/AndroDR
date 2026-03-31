---
description: "Persona-based UAT testing — evaluate AndroDR output from real user perspectives"
---

# UAT Persona Test Dispatcher

You orchestrate persona-based user acceptance testing for AndroDR. Each persona evaluates the app on TWO surfaces: what they see in the app (surface: app) and what the export recipient reads (surface: export).

## Parse Invocation

Accepted forms:
- `/uat-test` — run all stories, all personas
- `/uat-test --persona dv_survivor` — one persona's stories only
- `/uat-test --story dv_clean_app` — one specific story
- `/uat-test --no-emulator` — evaluate existing reports in `build/uat/`
- `/uat-test --report <path>` — evaluate a specific report file against all applicable stories

If `--no-emulator` is used, skip report collection and read from `build/uat/`.
If `--report <path>` is given, use that single report for all stories.

## Step 1: Read UAT Stories

1. Read `test-adversary/uat-stories.yml`
2. Parse all persona definitions and story entries
3. Filter by `--persona` or `--story` flags if provided
4. Group stories by `setup` command (stories sharing the same setup share one report)

## Step 2: Collect Reports

### If `--no-emulator`:
Read `build/uat/manifest.yml` to locate previously collected reports. If it does not exist, look for any `.txt` report files under `build/uat/`.

### If `--report <path>`:
Use the provided report file for all story evaluations.

### Otherwise (emulator mode):
For each unique `setup` command across selected stories:

1. Determine the emulator serial — run `adb devices` and pick the first `emulator-XXXX` device, or ask the user if multiple are available
2. Run the test harness:
   ```bash
   cd test-adversary && ./run.sh --no-pause <setup_flags> <serial>
   ```
3. Pull the report:
   ```bash
   adb -s <serial> pull /sdcard/Android/data/com.androdr.debug/files/androdr_last_report.txt build/uat/<story_group>/report.txt
   ```
4. Pull the timeline CSV if available:
   ```bash
   adb -s <serial> pull /sdcard/Android/data/com.androdr.debug/files/androdr_timeline.csv build/uat/<story_group>/timeline.csv
   ```
5. Run cleanup:
   ```bash
   ./test-adversary/cleanup.sh <serial>
   ```

Create `build/uat/manifest.yml` mapping story groups to report paths.

## Step 3: Dispatch Persona Agents

For each selected story, dispatch an evaluation agent. Stories with different personas or different surfaces are independent and can run in parallel.

### Surface: app (in-app experience)

Build a UI state description from the report text. The report contains all the data the app displays — translate it into what the user would see:

```
=== APP UI STATE ===

Dashboard shows:
- Overall Risk: [extract from "OVERALL RISK: X" in report] with [color based on risk level] badge
  - CRITICAL = red badge (0xFFCF6679)
  - HIGH = orange badge (0xFFFF9800)
  - MEDIUM = amber badge (0xFFE6A800)
  - LOW = teal badge (0xFF00D4AA)
- Post-scan guidance: [map risk level to guidance text]
  - CRITICAL: "Immediate action needed. Tap 'App Risks' below to see which apps should be removed."
  - HIGH: "Some issues found. Review the flagged items and follow the suggested actions."
  - MEDIUM: "Minor items to review. Your phone is mostly secure."
  - LOW: "Your phone looks secure. No urgent issues found."
- Summary cards: App Risks [N], Device Flags [N], DNS Matched [N], Last Scan [time]
- Deep Device Scan card visible at bottom

App Risks tab shows:
- [N] applications flagged
- [list app names with severity chips and reason text]
- Each finding card has: severity chip, app name, package, reasons, action button

Device tab shows:
- [N] of [M] checks triggered
- [list triggered checks with severity and description]
- [list passed checks]

Severity chips use colors:
- CRITICAL: red background
- HIGH: orange background
- MEDIUM: amber background
- LOW/INFO: grey background

Finding cards have:
- Tap to expand for details
- Remediation steps shown inline
- "How to fix" actions reference Settings paths
```

Extract the actual values from the report text to fill in the template above. This gives the persona agent a faithful representation of what they would see in the app.

### Surface: export (report text)

Pass the raw report text (and timeline CSV if available) directly. The persona agent reads the actual export output.

### Agent Prompt Template

For each story, dispatch a subagent with this prompt:

```
{persona.prompt}

=== EVALUATION SURFACE: {surface} ===

{surface_content}
  - For surface: app  -> the UI state description built above
  - For surface: export -> the raw report text + timeline CSV

=== ACCEPTANCE CRITERIA ===
Evaluate each criterion below. For each one, state whether it PASSES or FAILS,
quote the specific text/element that informed your judgment, and suggest one
improvement if it fails.

{story.criteria formatted as a checklist}

=== YOUR TASK ===
Read the output above AS YOUR PERSONA. Do not break character.

For each criterion category, provide:
1. Score (1-5)
2. Specific flags (JARGON FAIL, FALSE ALARM, PANIC INDUCING, etc.)
3. The exact text that triggered the flag (quote from the output)
4. Suggested improvement (one sentence)

Output as structured YAML:

```yaml
story_id: "{story.id}"
persona: "{persona.name}"
surface: "{story.surface}"
scores:
  comprehension: {score: N, flags: [], quotes: [], suggestions: []}
  actionability: {score: N, flags: [], quotes: [], suggestions: []}
  signal_to_noise: {score: N, flags: [], quotes: [], suggestions: []}
  emotional_calibration: {score: N, flags: [], quotes: [], suggestions: []}
  completeness: {score: N, flags: [], quotes: [], suggestions: []}
  export_utility: {score: N, flags: [], quotes: [], suggestions: []}
  trust: {score: N, flags: [], quotes: [], suggestions: []}
persona_specific:
  - {key: "persona-specific criterion name", score: N, note: "explanation"}
overall_impression: "One paragraph as your persona"
blocking_issues:
  - "List of things that must be fixed before this persona would trust the app"
```

## Step 4: Aggregate Scorecard

After all agents return, build the UAT scorecard:

1. Parse each agent's YAML output
2. Apply persona weights:
   - dv_survivor: 1.5x
   - journalist: 1.2x
   - security_conscious: 1.0x
   - small_security_team: 1.0x
3. Calculate weighted average per criterion and overall
4. Collect all blocking issues across all stories
5. Identify any criterion scoring 1 (automatic blocker)
6. Identify any JARGON FAIL, FALSE ALARM, or CREDIBILITY FAIL flags (automatic blockers)

## Step 5: Output Scorecard

Print the scorecard to the console in this format:

```
=== AndroDR UAT Scorecard ===

Story: "{title}" ({persona name}, {surface})
  Comprehension:         {score}/5  {flags if any}
  Actionability:         {score}/5  {flags if any}
  Signal-to-noise:       {score}/5  {flags if any}
  Emotional calibration: {score}/5  {flags if any}
  Completeness:          {score}/5  {flags if any}
  Export utility:        {score}/5  {flags if any}
  Trust:                 {score}/5  {flags if any}
  WEIGHTED SCORE: {weighted}/5.0

[repeat for each story]

OVERALL: {weighted_average}/5.0 — {pass/fail status}
BLOCKING ISSUES: {count}
{list each blocking issue with story ID and persona}
```

## Step 6: Save Results

Write full results to `build/uat/results-{YYYYMMDD-HHmmss}.yml` containing:
- All agent outputs (raw YAML)
- Scorecard summary
- Timestamp, AndroDR version, emulator details
- List of blocking issues

## Important Notes

- DO NOT modify `test-adversary/run.sh` — the skill orchestrates everything
- Reports are pulled from the device, not generated by the skill
- The UI state description is a TRANSLATION of the report into what the user sees — it uses knowledge of DashboardScreen.kt, severity colors, and guidance strings
- Stories sharing the same `setup` value share a single harness run — do not run the harness twice for the same setup
- When running without an emulator, any report file can be evaluated — this enables CI usage and retrospective evaluation
