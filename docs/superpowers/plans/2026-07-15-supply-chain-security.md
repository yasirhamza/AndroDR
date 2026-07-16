# Supply Chain Security Posture Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement the six-layer supply chain security posture from
`docs/superpowers/specs/2026-07-15-supply-chain-security-design.md` (#252) as
three risk-ordered PRs: CI hardening + scanning gates, release integrity,
and Gradle dependency verification.

**Architecture:** Everything is CI/config work — no app code changes. PR 1
edits the three existing workflows and adds two new ones plus docs; PR 2
rewires `release.yml` onto the existing `signingConfigs.release` and adds
SBOM + provenance; PR 3 adds `gradle/verification-metadata.xml` and a
Dependabot auto-regen workflow. Enforcement is a GitHub ruleset edit done
post-merge via `gh api`.

**Tech Stack:** GitHub Actions, GitHub rulesets API (`gh api`), Gradle 8 /
AGP 8.7.3, CodeQL (`java-kotlin`), `actions/dependency-review-action`,
`gradle/actions/dependency-submission`, CycloneDX Gradle plugin 3.3.0,
`actions/attest-build-provenance`, `apksigner`, `keytool`.

## Global Constraints

- **Env for any gradle/keytool/adb command:** `export JAVA_HOME=/home/yasir/Applications/android-studio/jbr; export ANDROID_HOME=/home/yasir/Android/Sdk; export PATH="$JAVA_HOME/bin:$ANDROID_HOME/platform-tools:$PATH"`
- **Never print secret values.** Passwords come from `~/.gradle/gradle.properties`; keystore is `release-keystore.jks` (repo root, gitignored). Pipe values straight into `gh secret set`; never echo, log, or commit them.
- **Every `uses:` must be SHA-pinned** with a trailing ` # vX.Y.Z` comment (exact pins listed in Task 1; new actions in later tasks already carry their pins).
- **Run `actionlint` after every workflow edit** (installed at `/usr/local/bin/actionlint`). Expected output: empty (exit 0).
- **All changes land via PRs to `main`; never push `main` directly.** Squash-merge. PR 1 and PR 2 bodies say `Refs #252`; PR 3 says `Closes #252`.
- **Merge PR N before starting PR N+1.**
- **After each PR's implementation is complete (before merge): run the 4-agent review ceremony** — dispatch four parallel review subagents (correctness, code-quality, architect, code-security) over the PR diff, fix confirmed findings, re-run CI. No exceptions.
- **GitHub-native-first:** the only third-party additions allowed are the CycloneDX Gradle plugin and SHA-pinned versions of actions already in use.
- Commit messages follow repo convention (`type(scope): subject`) and end with `Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>`.
- Branches: PR 1 = `feat/252-supply-chain-pr1` (already exists, spec committed on it), PR 2 = `feat/252-supply-chain-pr2-release`, PR 3 = `feat/252-supply-chain-pr3-depverify`.
- **Signing decision (maintainer, 2026-07-15): the Play upload key is NEVER stored in CI.** GitHub releases are signed by a dedicated CI release keystore (Task 8 generates it). Any step that would export, base64, or `gh secret set` the upload keystore or its `~/.gradle` passwords is a plan violation.
- **Phase 2 prerequisite:** local `gh` ≥ 2.49 (`gh attestation` does not exist in 2.45, which is currently installed). Upgrade before Task 10.

---

## Phase 1 — PR 1: CI hardening + scanning gates

### Task 1: SHA-pin every action in the three existing workflows

**Files:**
- Modify: `.github/workflows/ci.yml`
- Modify: `.github/workflows/release.yml`
- Modify: `.github/workflows/check-privacy-sync.yml`

**Interfaces:**
- Produces: the pin table below — later tasks reference these exact pins when adding new jobs/workflows.

Pin table (resolved 2026-07-15 via `gh api repos/<repo>/commits/<tag>`; Dependabot's `github-actions` updater understands SHA pins and keeps the version comments current):

| Replace | With |
|---|---|
| `actions/checkout@v4` | `actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5 # v4.3.1` |
| `actions/setup-java@v4` | `actions/setup-java@c1e323688fd81a25caa38c78aa6df2d33d3e20d9 # v4.8.0` |
| `actions/setup-python@v5` | `actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065 # v5.6.0` |
| `actions/upload-artifact@v4` | `actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02 # v4.6.2` |
| `actions/download-artifact@v4` | `actions/download-artifact@d3f86a106a0bac45b974a628896c90dbdf5c8093 # v4.3.0` |
| `actions/github-script@v7` | `actions/github-script@f28e40c7f34bde8b3046d885e986cb6290c5673b # v7.1.0` |
| `android-actions/setup-android@v3` | `android-actions/setup-android@9fc6c4e9069bf8d3d10b2204b1fb8f6ef7065407 # v3.2.2` |
| `gradle/actions/setup-gradle@v4` | `gradle/actions/setup-gradle@ed408507eac070d1f99cc633dbcf757c94c7933a # v4.4.3` |
| `reactivecircus/android-emulator-runner@v2` | `reactivecircus/android-emulator-runner@a421e43855164a8197daf9d8d40fe71c6996bb0d # v2.38.0` |
| `dorny/paths-filter@v3` | `dorny/paths-filter@d1c1ffe0248fe513906c8e24db8ea791d46f8590 # v3.0.3` |

- [ ] **Step 1: Apply the pins mechanically**

```bash
cd /home/yasir/AndroDR
for f in .github/workflows/ci.yml .github/workflows/release.yml .github/workflows/check-privacy-sync.yml; do
  sed -i \
    -e 's|actions/checkout@v4|actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5 # v4.3.1|' \
    -e 's|actions/setup-java@v4|actions/setup-java@c1e323688fd81a25caa38c78aa6df2d33d3e20d9 # v4.8.0|' \
    -e 's|actions/setup-python@v5|actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065 # v5.6.0|' \
    -e 's|actions/upload-artifact@v4|actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02 # v4.6.2|' \
    -e 's|actions/download-artifact@v4|actions/download-artifact@d3f86a106a0bac45b974a628896c90dbdf5c8093 # v4.3.0|' \
    -e 's|actions/github-script@v7|actions/github-script@f28e40c7f34bde8b3046d885e986cb6290c5673b # v7.1.0|' \
    -e 's|android-actions/setup-android@v3|android-actions/setup-android@9fc6c4e9069bf8d3d10b2204b1fb8f6ef7065407 # v3.2.2|' \
    -e 's|gradle/actions/setup-gradle@v4|gradle/actions/setup-gradle@ed408507eac070d1f99cc633dbcf757c94c7933a # v4.4.3|' \
    -e 's|reactivecircus/android-emulator-runner@v2|reactivecircus/android-emulator-runner@a421e43855164a8197daf9d8d40fe71c6996bb0d # v2.38.0|' \
    -e 's|dorny/paths-filter@v3|dorny/paths-filter@d1c1ffe0248fe513906c8e24db8ea791d46f8590 # v3.0.3|' \
    "$f"
done
```

Two caveats: `ci.yml` line 24 has a **comment** mentioning `dorny/paths-filter@v3`, and `ci.yml` line 203 has a comment mentioning `actions/checkout@v4` — the sed rewrites both. That's acceptable (comments stay truthful, verified to still pass actionlint) but check the diff reads sensibly.

- [ ] **Step 2: Verify no mutable tag remains and actionlint passes**

```bash
grep -rn "uses:.*@v[0-9]" .github/workflows/ && echo "FAIL: unpinned action remains" || echo "PASS: all pinned"
actionlint
```

Expected: `PASS: all pinned` (grep finds nothing) and actionlint exits 0 with no output. (`grep` finding `@<sha> # vX` lines is fine — the pattern above only matches `@v<digit>` immediately after `@`.)

- [ ] **Step 3: Commit**

```bash
git add .github/workflows/
git commit -m "ci(security): pin all GitHub Actions to commit SHAs

Mutable tags (@v4, @v3) are the tj-actions attack vector: a compromised
tag silently changes what runs in CI. Dependabot's github-actions updater
understands SHA pins and keeps the version comments current.

Refs #252

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 2: Outbound-leak guard (tracked-path denylist)

**Files:**
- Create: `.github/tracked-path-denylist.txt`
- Create: `.github/scripts/check-tracked-paths.sh`
- Modify: `.gitignore` (add `.env` entries)
- Modify: `.github/workflows/ci.yml` (new job + `ci-success` wiring)

**Interfaces:**
- Produces: CI job name `tracked-path-denylist` (referenced by `ci-success` needs and by `docs/supply-chain.md` in Task 5).

- [ ] **Step 1: Write the denylist file**

`.github/tracked-path-denylist.txt`:

```
# Tracked-path denylist — the outbound-leak guard's source of truth.
# One git pathspec glob per line; CI fails if any TRACKED file matches
# (git ls-files -- ':(glob,icase)PATTERN' — case-insensitive, so
# Release.JKS cannot escape). Lines starting with # are comments.
# Every pattern is **/-prefixed: root-anchored globs miss a state dir
# auto-created in a subdirectory or worktree, which is exactly the
# motivating incident's recurrence mode.
# Mirror every addition here into .gitignore so the file never gets
# tracked in the first place.
#
# NOTE: .claude/ is deliberately NOT wholesale-denylisted — the repo
# intentionally tracks .claude/commands/ (the public update-rules
# pipeline skills). Only local state is banned.
**/.memsearch/**
**/.superpowers/**
**/.claude/settings.local.json
**/*.jks
**/*.keystore
**/*.p12
**/*.pfx
**/*.pepk
**/*.bks
**/local.properties
**/.env*
```

- [ ] **Step 2: Write the checker script**

`.github/scripts/check-tracked-paths.sh`:

```bash
#!/usr/bin/env bash
# Outbound-leak guard: fail if any TRACKED file matches a denylisted
# local-state/sensitive path. gitleaks scans content; this catches whole
# state dirs / keystores that contain no classic secret pattern.
set -euo pipefail

DENYLIST="${1:-.github/tracked-path-denylist.txt}"
fail=0
while IFS= read -r pattern; do
  case "$pattern" in ''|'#'*) continue ;; esac
  matches=$(git ls-files -- ":(glob,icase)$pattern")
  if [ -n "$matches" ]; then
    echo "DENYLISTED tracked path(s) matching '$pattern':" >&2
    echo "$matches" >&2
    fail=1
  fi
done < "$DENYLIST"

if [ "$fail" -ne 0 ]; then
  echo "FAIL: sensitive/local-state paths are tracked." >&2
  echo "Untrack with 'git rm --cached <path>' and keep them in .gitignore." >&2
  exit 1
fi
echo "PASS: no tracked file matches the denylist"
```

```bash
chmod +x .github/scripts/check-tracked-paths.sh
```

- [ ] **Step 3: Run the script — expect green**

```bash
bash .github/scripts/check-tracked-paths.sh
```

Expected: `PASS: no tracked file matches the denylist` (verified 2026-07-15 that nothing tracked matches).

- [ ] **Step 4: Red test — stage a denylisted file, expect failure**

```bash
mkdir -p sub && touch .env.test sub/Fake.JKS && git add .env.test sub/Fake.JKS
bash .github/scripts/check-tracked-paths.sh; echo "exit=$?"
git rm --cached -q .env.test sub/Fake.JKS && rm .env.test sub/Fake.JKS && rmdir sub
```

Expected: matches reported for both `'**/.env*'` (`.env.test`) and `'**/*.jks'` (`sub/Fake.JKS` — proves subdirectory + case-insensitive matching), then `FAIL: ...`, `exit=1`. (Staged files appear in `git ls-files`, so this exercises the real failure path without committing.)

- [ ] **Step 5: Mirror into .gitignore**

Append to `.gitignore` (after the `.memsearch/` block; `.claude/`, `.superpowers/`, `*.jks`, `*.keystore`, `local.properties` are already ignored):

```
# Env files + key-material formats — must never be tracked
# (mirrors .github/tracked-path-denylist.txt)
.env*
*.p12
*.pfx
*.pepk
*.bks
```

- [ ] **Step 6: Add the CI job and wire it into ci-success**

In `.github/workflows/ci.yml`, add after the `submodule-check` job (always runs — no path filter, it's ~5 s):

```yaml
  tracked-path-denylist:
    runs-on: ubuntu-latest
    timeout-minutes: 5
    steps:
      - uses: actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5 # v4.3.1
      - name: Check no denylisted local-state/sensitive path is tracked
        run: bash .github/scripts/check-tracked-paths.sh
```

In the `ci-success` job: add `- tracked-path-denylist` to `needs:` and add this line alongside the other result echoes:

```yaml
            echo "needs.tracked-path-denylist.result: ${{ needs.tracked-path-denylist.result }}" >&2
```

- [ ] **Step 7: actionlint + commit**

```bash
actionlint
git add .github/tracked-path-denylist.txt .github/scripts/check-tracked-paths.sh .gitignore .github/workflows/ci.yml
git commit -m "ci(security): tracked-path denylist guard against outbound leaks

gitleaks scans diff content; it won't flag a committed state directory
(vector DB, session journal) or keystore that contains no classic secret
pattern. This job fails CI if any tracked file matches the denylist.
.claude/commands/ stays tracked deliberately (public pipeline skills).

Refs #252

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 3: Dependency graph submission + dependency-review gate

**Files:**
- Modify: `.github/workflows/ci.yml` (new `deps` filter bucket + two jobs + `ci-success` wiring)
- Create: `.github/dependency-review-config.yml`

**Interfaces:**
- Consumes: pin table from Task 1.
- Produces: CI job names `dependency-submission` and `dependency-review`, both folded into `ci-success` (skipped-counts-as-pass, same as every other path-filtered gate). **Design refinement vs the spec (ratified at plan gate):** blocking happens via the existing required `ci-success` check rather than a new required ruleset context — this reuses the repo's established path-filter pattern so docs-only PRs aren't blocked waiting for a check that never reports. Task 5's docs and the PR body must state this.

- [ ] **Step 0: Enable the dependency graph + alerts (repo settings pre-flight)**

The graph and alerts are currently DISABLED (verified at plan gate: the
compare endpoint 403s, `vulnerability-alerts` 404s). Without this, both new
jobs hard-fail inside required `ci-success` and wedge PR 1.

```bash
gh api -X PUT repos/:owner/:repo/vulnerability-alerts        # enables alerts + dependency graph
gh api -X PUT repos/:owner/:repo/automated-security-fixes    # Dependabot security updates
gh api repos/:owner/:repo/vulnerability-alerts && echo "alerts: enabled"
```

Expected: both PUTs return 204; the GET returns 204 (enabled). Then, once
alerts populate (minutes), pre-audit the standing tree:

```bash
gh api "repos/:owner/:repo/dependabot/alerts?state=open&severity=critical,high" --jq 'length'
```

Expected: `0`. If not 0, list them — fixable ones get version bumps in a
separate prior PR; genuinely unfixable ones are pre-seeded into
`allow-ghsas` (Step 3) with reason + review date, so PR 1's own gate can't
ambush us.

- [ ] **Step 1: Add the `deps` filter bucket**

In `ci.yml`, `changes` job: add `deps: ${{ steps.filter.outputs.deps }}` to `outputs:`, and add to the `filters:` block (before `rules:`):

```yaml
            deps:
              - 'gradle/libs.versions.toml'
              - 'gradle/verification-metadata.xml'
              - 'app/build.gradle.kts'
              - 'build.gradle.kts'
              - 'settings.gradle.kts'
              - '.github/workflows/ci.yml'
              - '.github/dependency-review-config.yml'
```

(The config file is in the bucket so a suppressions-only PR re-runs the
gate under the new policy.)

(`.github/workflows/ci.yml` is included so this very PR bootstraps the first graph snapshots on both the PR head and, after merge, on `main` — otherwise the first Dependabot PR would have no base snapshot to diff against.)

- [ ] **Step 2: Add the two jobs**

After `tracked-path-denylist` in `ci.yml`:

```yaml
  # Submits the resolved Gradle dependency graph to GitHub. Gradle graphs
  # aren't manifest-parseable, so PR-side submission is what gives
  # dependency-review something to diff. Fork PRs lack contents:write —
  # non-issue on this maintainer-only repo.
  dependency-submission:
    runs-on: ubuntu-latest
    needs: changes
    if: ${{ needs.changes.outputs.deps == 'true' }}
    timeout-minutes: 20
    permissions:
      contents: write
    steps:
      - uses: actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5 # v4.3.1
        with:
          submodules: true
          # This job holds a contents:write token while resolving the PR
          # branch's Gradle build — keep the token off disk. Residual
          # exposure via the action's env is an accepted trade-off; the
          # fork-safe generate-and-upload/download-and-submit split is the
          # escape hatch if it ever matters.
          persist-credentials: false
      - uses: actions/setup-java@c1e323688fd81a25caa38c78aa6df2d33d3e20d9 # v4.8.0
        with:
          java-version: '21'
          distribution: 'temurin'
          cache: 'gradle'
      - uses: android-actions/setup-android@9fc6c4e9069bf8d3d10b2204b1fb8f6ef7065407 # v3.2.2
      - uses: gradle/actions/dependency-submission@ed408507eac070d1f99cc633dbcf757c94c7933a # v4.4.3
        with:
          # Graph telemetry only — nothing built here ships. Verification
          # must be off because the action's init script injects the
          # github-dependency-graph plugin, whose artifacts are (by design)
          # not recorded in gradle/verification-metadata.xml once PR 3
          # lands. Harmless before PR 3.
          additional-arguments: --dependency-verification=off
  # Delta-only SCA gate: fails a PR that introduces/bumps a dependency
  # carrying a known Crit/High vuln. Pre-existing tree CVEs are Dependabot's
  # job (fixable -> update PR, unfixable -> Security-tab alert).
  dependency-review:
    runs-on: ubuntu-latest
    needs: [changes, dependency-submission]
    if: ${{ github.event_name == 'pull_request' && needs.changes.outputs.deps == 'true' }}
    timeout-minutes: 10
    steps:
      - uses: actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5 # v4.3.1
      - uses: actions/dependency-review-action@2031cfc080254a8a887f58cffee85186f0e49e48 # v4.9.0
        with:
          config-file: './.github/dependency-review-config.yml'
          retry-on-snapshot-warnings: true
```

- [ ] **Step 3: Write the suppressions/config file** (Shipped deviation: see Deviations register #8 — bootstrap block, removed post-merge.)

`.github/dependency-review-config.yml`:

```yaml
# Policy for actions/dependency-review-action (the delta-only SCA gate).
# Severity >= high with a fix available -> bump instead of suppressing.
# Genuinely unfixable advisories go in allow-ghsas, each with a comment:
#   reason, owner, and a review-by date. Re-review at each entry's date;
#   remove the entry when a fix ships.
fail-on-severity: high

# allow-ghsas:
#   - GHSA-xxxx-xxxx-xxxx  # <reason>; review by YYYY-MM-DD
```

- [ ] **Step 4: Wire into ci-success**

Add `- dependency-submission` and `- dependency-review` to the `ci-success` `needs:` list and add echo lines:

```yaml
            echo "needs.dependency-submission.result: ${{ needs.dependency-submission.result }}" >&2
            echo "needs.dependency-review.result:    ${{ needs.dependency-review.result }}" >&2
```

- [ ] **Step 5: actionlint + commit**

```bash
actionlint
git add .github/workflows/ci.yml .github/dependency-review-config.yml
git commit -m "ci(security): dependency graph submission + delta SCA gate on PRs

dependency-review fails any PR introducing a known Crit/High-vuln dep;
suppressions live in dependency-review-config.yml with reason + review
date. Gated behind a new 'deps' path bucket and folded into ci-success,
matching the repo's skipped-counts-as-pass pattern.

Refs #252

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 4: CodeQL workflow (first-party SAST)

**Files:**
- Create: `.github/workflows/codeql.yml`

**Interfaces:**
- Produces: code-scanning results under tool name `CodeQL`, category `/language:java-kotlin` — Task 7's ruleset rule references tool `CodeQL`.

- [ ] **Step 1: Write the workflow**

`.github/workflows/codeql.yml` (complete file):

```yaml
name: CodeQL

on:
  push:
    branches: [main]
    paths:
      - 'app/src/**/*.kt'
      - 'app/src/**/*.java'
      - 'app/build.gradle.kts'
      - 'build.gradle.kts'
      - 'settings.gradle.kts'
      - 'gradle/libs.versions.toml'
      - '.github/workflows/codeql.yml'
  pull_request:
    branches: [main]
    paths:
      - 'app/src/**/*.kt'
      - 'app/src/**/*.java'
      - 'app/build.gradle.kts'
      - 'build.gradle.kts'
      - 'settings.gradle.kts'
      - 'gradle/libs.versions.toml'
      - '.github/workflows/codeql.yml'
  schedule:
    # Weekly baseline refresh, Monday 04:23 UTC (odd minute to avoid the
    # top-of-hour scheduling stampede GitHub docs warn about).
    - cron: '23 4 * * 1'
  workflow_dispatch:

permissions:
  contents: read

concurrency:
  group: codeql-${{ github.ref }}
  cancel-in-progress: ${{ github.event_name == 'pull_request' }}

jobs:
  analyze:
    name: analyze (java-kotlin)
    runs-on: ubuntu-latest
    timeout-minutes: 60
    permissions:
      contents: read
      security-events: write
      actions: read
    steps:
      - uses: actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5 # v4.3.1
        with:
          submodules: true
      - uses: actions/setup-java@c1e323688fd81a25caa38c78aa6df2d33d3e20d9 # v4.8.0
        with:
          java-version: '21'
          distribution: 'temurin'
          cache: 'gradle'
      - uses: android-actions/setup-android@9fc6c4e9069bf8d3d10b2204b1fb8f6ef7065407 # v3.2.2
      - uses: gradle/actions/setup-gradle@ed408507eac070d1f99cc633dbcf757c94c7933a # v4.4.3
        with:
          cache-read-only: ${{ github.ref != 'refs/heads/main' }}
      - uses: github/codeql-action/init@02c5e83432fe5497fd85b873b6c9f16a8578e1d9 # v3.37.0
        with:
          languages: java-kotlin
          build-mode: manual
      - name: Build for CodeQL tracing
        # CodeQL traces compiler invocations, so every flag here exists to
        # force real compilation to happen in-process:
        #   --no-daemon: the daemon detaches compilers from the traced tree
        #   --no-build-cache: gradle.properties sets org.gradle.caching=true;
        #     a cache hit means NO compiler runs and CodeQL sees no source
        #     (guaranteed on cron runs and any PR without Kotlin changes)
        #   --no-configuration-cache: same failure mode via the config cache
        run: ./gradlew --no-daemon --no-build-cache --no-configuration-cache assembleDebug --stacktrace
      - uses: github/codeql-action/analyze@02c5e83432fe5497fd85b873b6c9f16a8578e1d9 # v3.37.0
        with:
          category: '/language:java-kotlin'
```

- [ ] **Step 2: actionlint + commit**

```bash
actionlint
git add .github/workflows/codeql.yml
git commit -m "ci(security): CodeQL java-kotlin SAST on PRs + weekly cron

Manual build mode (AGP needs the Android SDK, so autobuild can't work),
with build/config caches disabled so the traced build actually compiles.
Path-filtered to code paths; whether code-scanning merge protection
skips docs-only PRs cleanly is verified empirically after the ruleset
rule is added (Task 7), with a recorded rollback if it doesn't.

Refs #252

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 5: SECURITY.md + docs/supply-chain.md

**Files:**
- Create: `SECURITY.md`
- Create: `docs/supply-chain.md`

- [ ] **Step 1: Write SECURITY.md**

`SECURITY.md` (complete file):

```markdown
# Security Policy

## Reporting a vulnerability

**Please do not open a public issue for security vulnerabilities.**

Preferred: use GitHub's private vulnerability reporting —
**Security → Report a vulnerability** on this repository.

Alternatively, email **yhamad.dev@gmail.com** with:

- A description of the issue and its impact
- Steps to reproduce (a PoC APK, rule file, or DNS trace if relevant)
- Affected version (Settings → About in the app, or the release tag)

You can expect an acknowledgement within **72 hours**. Please allow up to
**90 days** for a coordinated fix before public disclosure; most fixes ship
much faster since releases are cut automatically from `main`.

## Supported versions

Only the **latest release** (Play Store and GitHub Releases) is supported.
The app also pulls detection rules and threat intel on a 12-hour cycle, so
many detection-content fixes reach all installs without an app update.

## Verifying release artifacts

> **Status: pending PR 2 of #252** — remove this note when it merges.

Every GitHub release ships a signed APK, a CycloneDX SBOM, and a SLSA
build-provenance attestation. See
[docs/supply-chain.md](docs/supply-chain.md) for verification commands.
The Play upload key is never stored in CI; GitHub releases are signed with
a dedicated CI release key.

## Scope notes

- The DNS-monitoring VPN is local-only; no traffic leaves the device for
  analysis. Reports of data exfiltration by the app itself are always in
  scope and taken seriously.
- Vulnerabilities in bundled detection *rules* (false negatives/positives)
  are welcome as regular issues unless exploitable.
```

- [ ] **Step 2: Write docs/supply-chain.md**

`docs/supply-chain.md` (complete file):

```markdown
# Supply Chain Security Posture

Design: `docs/superpowers/specs/2026-07-15-supply-chain-security-design.md`
(issue #252). This document is the operational reference: what each layer
guarantees, how to triage findings, and how to verify artifacts.

**What this posture is:** a strong, auditable guarantee about *known*
problems plus tamper-evidence on every input and output. It is **not** a
claim that the codebase is vulnerability-free — no scanner knows
undisclosed CVEs, and real supply chain attacks (compromised action tags,
maintainer takeovers, typosquats) don't appear in vulnerability databases
at all. Each layer below exists to make one class of those attacks either
evident or blocking.

## The six layers

| # | Layer | Mechanism | Where |
|---|-------|-----------|-------|
| 1 | Dependency integrity | Gradle checksum verification (sha256) | `gradle/verification-metadata.xml` |
| 2 | Dependency vulns (SCA) | dependency-review PR gate + Dependabot | `ci.yml`, `.github/dependency-review-config.yml`, `.github/dependabot.yml` |
| 3 | CI/build hardening | All actions SHA-pinned; least-privilege tokens | `.github/workflows/*.yml` |
| 4 | Release integrity | CI-release-key-signed APK (pinned cert digest) + CycloneDX SBOM + SLSA provenance | `release.yml` |
| 5 | First-party SAST | CodeQL `java-kotlin`, PRs + weekly | `codeql.yml` |
| 6 | Outbound-leak guard | Tracked-path denylist CI job | `.github/tracked-path-denylist.txt` + `.github/scripts/check-tracked-paths.sh` |

## SCA policy and triage (layer 2)

The PR gate (`dependency-review` job in `ci.yml`) is **delta-only**: it
fails a PR that *introduces or bumps* a dependency with a known
Critical/High advisory. It does not re-flag CVEs already in the tree, so
unfixable transitive advisories never wedge unrelated PRs.

Blocking is enforced through the required `ci-success` check: the job runs
whenever Gradle files change (the `deps` path bucket) and is skipped —
which counts as pass — otherwise, like every other path-filtered gate in
`ci.yml`.

Triage decision tree for a red `dependency-review`:

1. **A fixed version exists** → bump to it (or pick another library).
2. **No fix exists and the code path is unreachable/unused** → add the
   GHSA id to `allow-ghsas` in `.github/dependency-review-config.yml`
   with a comment: reason + review-by date. Re-review on that date.
3. **No fix exists and it's reachable** → treat as a real finding; don't
   suppress it to get a PR through.

The **standing tree** (advisories already shipped) is Dependabot's job:
fixable → grouped monthly update PRs (act); unfixable → Security-tab
alerts (tracked, non-blocking). That split *is* the "block fixable, warn
on the rest" policy — GitHub-native tooling has no per-CVE fixability
flag on a full-tree gate.

## Action pinning (layer 3)

Every `uses:` in every workflow is pinned to a full commit SHA with a
`# vX.Y.Z` comment. Dependabot's `github-actions` ecosystem updates the
SHAs monthly and preserves the comments. **Never add an action pinned to
a tag or branch** — a mutable tag is exactly the March 2025
`tj-actions/changed-files` attack vector. **Never use
`pull_request_target` with a checkout of the PR head** — it runs with
secrets against attacker-controlled content; if a workflow ever needs
secrets against PR content, use the two-workflow artifact hand-off
pattern instead.

## Release integrity (layer 4) — verifying a release

> **Status: pending PR 2 of #252** — remove this note when it merges.

Every release published by `release.yml` carries three artifacts: the
signed APK, `bom.json` (CycloneDX SBOM), and a provenance attestation
stored in the repo's attestation log. To verify a downloaded APK
(requires `gh` ≥ 2.49):

    # Provenance: proves this exact file was built by release.yml in this
    # repo at a specific commit (SLSA build attestation). This is the
    # authenticity anchor.
    gh attestation verify app-release.apk --repo yasirhamza/AndroDR

    # Signature: proves it's signed with the AndroDR CI release key.
    apksigner verify --print-certs app-release.apk

GitHub releases are signed with a **dedicated CI release key** that exists
only for this purpose; the **Play upload key is never stored in CI** (and
Google holds the actual app-signing key behind Play App Signing, a third
key). `release.yml` pins the CI key's certificate SHA-256 digest — a build
signed with any other key fails CI. Play-Store and GitHub installs have
different signatures and cannot upgrade over each other; that has always
been true.

**Key-leak runbook (CI release key):** the blast radius is "someone can
sign an APK whose signature matches GitHub releases" — provenance
verification is unaffected and still distinguishes real releases. To
rotate: (1) generate a fresh keystore (`keytool -genkeypair`, see PR 2 of
#252 for the exact recipe), (2) replace the four `RELEASE_*` GitHub
secrets and the `EXPECTED_CERT_SHA256` pin in `release.yml`, (3) note in
the next release that sideloaders must uninstall/reinstall once. No Play
Console involvement.

**Token runbook (`DEPENDABOT_REGEN_TOKEN`):** fine-grained PAT, this repo
only, Contents read/write, 90-day expiry. On expiry Dependabot PRs fail
regen with an auth error at checkout/push; renew with a fresh PAT via
`gh secret set DEPENDABOT_REGEN_TOKEN --app dependabot`. Expiry date is
recorded in #252's closing comment.

**"Am I affected?" (new CVE in some library):** download `bom.json` from
the latest release (or run `./gradlew :app:cyclonedxBom` locally) and
search it for the artifact — answer in minutes, no build required.

## Dependency checksum verification (layer 1)

> **Status: pending PR 3 of #252** — remove this note when it merges.

`gradle/verification-metadata.xml` records the sha256 of every resolved
artifact (dependencies *and* plugins). Any mismatch — tampered artifact,
typosquat, poisoned mirror — fails the build before code runs.

**What it does and does not guarantee:** for artifacts already in the
tree, any byte change is fatal. For a *newly bumped* version (Dependabot),
the regenerated checksum is trust-on-first-use — it pins whatever the
regen run downloaded. Verification protects all unchanged artifacts and
every subsequent fetch of the new one; the authenticity of the new version
itself rests on advisory data and review of the bump PR.

After **any** dependency change, regenerate:

    export JAVA_HOME=/home/yasir/Applications/android-studio/jbr  # or your JDK 21
    ./gradlew --write-verification-metadata sha256 \
      assembleDebug assembleRelease testDebugUnitTest lintDebug detekt \
      assembleDebugAndroidTest :app:cyclonedxBom

and commit the updated file. Dependabot PRs are handled automatically by
`.github/workflows/dependabot-verification-regen.yml`, which runs the same
task list with `--dry-run` added (resolution without executing the bumped
tree's code) and pushes onto the bot's branch. If a Dependabot PR stays
red after regen (an execution-only configuration the dry run can't reach),
run the command above locally and push. A red build complaining about
"Dependency verification failed" on a *non*-Dependabot branch means you
changed dependencies without regenerating (or something genuinely
tampered — check which artifact and why before regenerating).

The `dependency-submission` CI job runs with verification off by design:
it only reports the graph, and its init-script-injected plugin is not in
the metadata. **Rollback coupling:** reverting PR 2 (CycloneDX) also
requires dropping `:app:cyclonedxBom` from the command above and from the
regen workflow — the task only exists while the plugin is applied.

## Outbound-leak guard (layer 6)

Supply chain hardening usually means controlling what you *pull in*; this
layer controls what you *push out* of the machine into a public repo.
gitleaks scans diff **content**; it will not flag a committed state
directory (AI-tooling vector DB, session journal, cache) or a binary
keystore containing no classic secret pattern.

`.github/tracked-path-denylist.txt` is the source of truth: one git glob
per line; the `tracked-path-denylist` CI job fails if any **tracked** file
matches. Mirror every addition into `.gitignore` (prevention) — the CI job
is detection for when prevention fails. `.claude/commands/` is
deliberately tracked (public pipeline skills); only `.claude`'s local
state (`settings.local.json`) is denylisted.

To fix a violation: `git rm --cached <path>`, confirm `.gitignore` covers
it, and if the content was sensitive treat it as leaked (it was pushed) —
rotate/purge accordingly. This guard is **point-in-time**: a file that
ever reached a pushed commit is leaked even if since deleted — the guard
prevents recurrence; it does not audit history.

## Enforcement summary

- Ruleset "Protect main": PRs required, required check `ci-success`
  (which folds in dependency-review, the denylist guard, and all build
  gates), CodeQL code-scanning rule (blocks on new high-severity alerts),
  no force-push/deletion.
- **Known limits:** repository admins hold an always-on bypass
  (`bypass_mode: always`) — the gates constrain automation and habit, not
  a determined or deceived admin, and "run this command to merge past red
  CI" remains a live social-engineering channel. Required checks are
  non-strict, so a green `ci-success` may predate the current base.
- **Unwind order:** to disable CodeQL, delete the `code_scanning` rule
  from ruleset 14651316 *first*, or merges wedge waiting for analyses
  that never arrive.
- `release.yml` refuses to publish unless `ci-success` passed for the SHA
  and the APK signature matches the pinned certificate digest.
```

- [ ] **Step 3: Commit**

```bash
git add SECURITY.md docs/supply-chain.md
git commit -m "docs(security): SECURITY.md + supply-chain posture reference

Refs #252

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 6: Open PR 1, prove the gates on the PR itself

- [ ] **Step 1: Push and open the PR**

```bash
git push -u origin feat/252-supply-chain-pr1
gh pr create --title "ci(security): supply-chain PR 1 — CI hardening + scanning gates" --body "$(cat <<'EOF'
Implements phase 1 of the supply chain security posture (#252): SHA-pins
every action, adds CodeQL (java-kotlin) SAST, a delta-only dependency-review
SCA gate + graph submission (folded into ci-success via a new 'deps' path
bucket — design refinement over a separate required check, so docs-only PRs
aren't blocked), the tracked-path denylist outbound-leak guard, SECURITY.md,
and docs/supply-chain.md. Spec + plan ride along in docs/superpowers/.

Post-merge follow-up (not in this diff): ruleset gets a CodeQL
code-scanning rule; private vulnerability reporting gets enabled.

Refs #252

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
)"
```

- [ ] **Step 2: Watch CI — all jobs must go green**

```bash
gh pr checks --watch
```

Expected green: `ci-success` (with new jobs `tracked-path-denylist`,
`dependency-submission`, `dependency-review` all pass — the deps bucket
fires because ci.yml changed), `analyze (java-kotlin)` (CodeQL; first run
takes ~15–30 min), plus all pre-existing jobs.

First-run notes:
- `dependency-review` has no base snapshot on main yet (the submission job
  first reaches main via this PR's merge). Expected: snapshot-warning
  retries, then "Retry timeout exceeded. Proceeding...", then either a
  pass or the full head tree evaluated as "added". The Step 0 pre-audit
  guarantees no standing Crit/High ambush; record which behavior was
  observed in a PR comment (the spec wants the observation on record).
- If CodeQL reports "no source code seen during the build", the build hit
  a cache despite the flags — do NOT chase SDK/license theories first;
  verify the `--no-build-cache --no-configuration-cache` flags survived.

- [ ] **Step 3: Live red-test the denylist guard on the PR**

```bash
touch .env.cileaktest && git add -f .env.cileaktest
git commit -m "test: TEMPORARY - prove tracked-path denylist fails CI"
git push
gh pr checks --watch   # expect tracked-path-denylist FAIL -> ci-success FAIL
git revert --no-edit HEAD && git push
gh pr checks --watch   # expect all green again
```

Expected: the middle run shows `tracked-path-denylist` failing with
`DENYLISTED tracked path(s) matching '**/.env*'`; the final run is green.
Screenshot/link the failed run in a PR comment as evidence.

- [ ] **Step 4: 4-agent review ceremony**

Dispatch four parallel review subagents over the full PR diff (`gh pr diff`),
one per lens: correctness, code-quality, architect, code-security. Apply
confirmed findings, push fixes, re-run `gh pr checks --watch` until green.

- [ ] **Step 5: Squash-merge**

```bash
gh pr merge --squash --delete-branch
```

Then confirm the push-to-main run is green (`gh run list --branch main --limit 3`)
— this run also submits the first dependency-graph snapshot on `main`
(bootstrap for future Dependabot PRs).

---

### Task 7: Post-merge enforcement (ruleset + private vulnerability reporting)

**Interfaces:**
- Consumes: CodeQL tool name `CodeQL` from Task 4; existing ruleset id `14651316` ("Protect main").

- [ ] **Step 1: Verify CodeQL has produced results on main**

```bash
gh api "repos/:owner/:repo/code-scanning/analyses?per_page=3" --jq '.[].tool.name'
```

Expected: at least one `CodeQL` entry. (The rule below blocks merges until
analyses exist, so do not add it before this returns results.)

- [ ] **Step 2: Update the ruleset — add the code_scanning rule**

Write `/tmp/claude-1000/-home-yasir-AndroDR/*/scratchpad/ruleset.json` — but
first re-fetch current state **including `bypass_actors`** (do not
blind-overwrite, and do not let a jq filter hide fields):

```bash
gh api repos/:owner/:repo/rulesets/14651316 --jq '{name, target, enforcement, conditions, bypass_actors, rules}'
```

The live ruleset has `bypass_actors: [{actor_id: 5, actor_type: "RepositoryRole", bypass_mode: "always"}]`
(repo admins bypass everything). **Preserve it verbatim in the PUT** —
removing the bypass is a maintainer decision, not an implementer side
effect. (Empirically verified at plan gate: the API retains an omitted
`bypass_actors` on PUT, but be explicit rather than lean on that.)

Then PUT the same content with one addition to `rules` (keep every existing
rule byte-identical; `required_status_checks` stays `ci-success`-only per
the Task 3 design refinement):

```json
{
  "name": "Protect main",
  "target": "branch",
  "enforcement": "active",
  "conditions": { "ref_name": { "include": ["refs/heads/main"], "exclude": [] } },
  "bypass_actors": [ { "actor_id": 5, "actor_type": "RepositoryRole", "bypass_mode": "always" } ],
  "rules": [
    { "type": "pull_request", "parameters": { "allowed_merge_methods": ["merge", "squash", "rebase"], "dismiss_stale_reviews_on_push": true, "require_code_owner_review": false, "require_last_push_approval": false, "required_approving_review_count": 0, "required_review_thread_resolution": false, "required_reviewers": [] } },
    { "type": "required_status_checks", "parameters": { "do_not_enforce_on_create": false, "required_status_checks": [ { "context": "ci-success" } ], "strict_required_status_checks_policy": false } },
    { "type": "deletion" },
    { "type": "non_fast_forward" },
    { "type": "code_scanning", "parameters": { "code_scanning_tools": [ { "tool": "CodeQL", "security_alerts_threshold": "high_or_higher", "alerts_threshold": "errors" } ] } }
  ]
}
```

```bash
gh api -X PUT repos/:owner/:repo/rulesets/14651316 --input <scratchpad>/ruleset.json \
  --jq '{updated: .name, rules: [.rules[].type]}'
```

Expected: `rules` now lists `code_scanning`.

- [ ] **Step 3: Empirically verify docs-only PRs aren't blocked by the code_scanning rule**

GitHub does not document how the rule treats "CodeQL never ran because the
PR matched no analysis paths" — if it blocks waiting for results, every
docs PR wedges (admin bypass being the only relief).

```bash
git checkout -b test/codeql-rule-docs-only main
echo "" >> docs/supply-chain.md && git add docs/supply-chain.md
git commit -m "test: TEMPORARY docs-only PR to probe code_scanning rule" && git push -u origin test/codeql-rule-docs-only
gh pr create --title "test: probe code_scanning merge protection (will close unmerged)" --body "Probing whether the ruleset blocks docs-only PRs. Closes nothing."
gh pr view --json mergeStateStatus --jq .mergeStateStatus   # after ci-success reports
```

Expected: `CLEAN` (or `UNSTABLE`, but NOT `BLOCKED` once `ci-success` is
green and no CodeQL analysis is pending). Then close the PR unmerged and
delete the branch. **If BLOCKED:** rollback = re-PUT the ruleset without
the `code_scanning` rule, and record in docs/supply-chain.md that CodeQL
gating is advisory (Security tab + PR annotations) pending a
GitHub-side fix.

- [ ] **Step 4: Enable private vulnerability reporting** (referenced by SECURITY.md; addition ratified at plan gate)

```bash
gh api -X PUT repos/:owner/:repo/private-vulnerability-reporting
gh api repos/:owner/:repo/private-vulnerability-reporting --jq .enabled
```

Expected: `true`.

---

## Phase 2 — PR 2: Release integrity

### Task 8: Generate the dedicated CI release keystore + provision its secrets

**Maintainer decision (2026-07-15): the Play upload key is NOT stored in
CI.** This task creates a brand-new keystore whose only job is signing
GitHub-release APKs. Blast radius of a leak: lookalike signatures on
sideload APKs — provenance attestation remains the authenticity anchor.
Rotation: rerun this task, update the `EXPECTED_CERT_SHA256` pin.

**Interfaces:**
- Produces: `~/keystores/androdr-ci-release.jks` (local, outside the repo);
  GitHub Actions secrets `RELEASE_KEYSTORE_BASE64`, `RELEASE_STORE_PASSWORD`,
  `RELEASE_KEY_ALIAS` (= `androdr-ci`), `RELEASE_KEY_PASSWORD`; and the CI
  cert's SHA-256 hex digest (lowercase, no colons) used by Task 9's verify
  step. The upload keystore (`release-keystore.jks` at the repo root) and
  `~/.gradle/gradle.properties` are NOT read by this task at all.

- [ ] **Step 1: Generate the CI keystore (password never displayed, passed via env not argv)**

```bash
export JAVA_HOME=/home/yasir/Applications/android-studio/jbr
mkdir -p ~/keystores
export CI_STOREPASS=$(openssl rand -base64 24)
"$JAVA_HOME/bin/keytool" -genkeypair -v \
  -keystore ~/keystores/androdr-ci-release.jks -alias androdr-ci \
  -keyalg RSA -keysize 4096 -validity 10950 \
  -dname "CN=AndroDR GitHub Releases, O=AndroDR" \
  -storepass:env CI_STOREPASS -keypass:env CI_STOREPASS
```

Expected: "Generating 4,096 bit RSA key pair" + keystore written. The
password lives only in this shell's environment (`:env` keeps it out of
argv → not visible in `/proc/<pid>/cmdline`).

- [ ] **Step 2: Provision the four secrets (values piped, never displayed)**

```bash
base64 -w0 ~/keystores/androdr-ci-release.jks | gh secret set RELEASE_KEYSTORE_BASE64
printf '%s' "$CI_STOREPASS" | gh secret set RELEASE_STORE_PASSWORD
printf '%s' "$CI_STOREPASS" | gh secret set RELEASE_KEY_PASSWORD
printf '%s' 'androdr-ci'    | gh secret set RELEASE_KEY_ALIAS
gh secret list
```

Expected: all four names listed with today's timestamp. (Store password and
key password are deliberately the same random value — PKCS12 keystores
require it anyway.)

- [ ] **Step 3: Extract the CI cert digest, then drop the password from the environment**

```bash
"$JAVA_HOME/bin/keytool" -exportcert -keystore ~/keystores/androdr-ci-release.jks \
  -alias androdr-ci -storepass:env CI_STOREPASS 2>/dev/null | sha256sum | cut -d' ' -f1
unset CI_STOREPASS
```

Expected: a 64-char lowercase hex digest. **This digest is public** (it's
printable from any APK signed with the key) — record it; Task 9 embeds it
in `release.yml` as `EXPECTED_CERT_SHA256`. Loss of the keystore or
password later is a non-event: regenerate and rotate (documented in
docs/supply-chain.md).

---

### Task 9: Rewire release.yml + CycloneDX SBOM plugin

**Files:**
- Modify: `.github/workflows/release.yml`
- Modify: `gradle/libs.versions.toml` ([versions] + [plugins])
- Modify: `app/build.gradle.kts` (plugins block + task config)
- Modify: `SECURITY.md` + `docs/supply-chain.md` (delete the two
  "Status: pending PR 2 of #252" marker lines — this PR makes them true)

**Interfaces:**
- Consumes: CI-keystore secrets + cert digest from Task 8; pin table from Task 1; `actions/attest-build-provenance@96278af6caaf10aea03fd8d33a09a777ca52d62f # v3.2.0` (v3.2.0 chosen over v3.0.0 because it requires — and this plan grants — the `artifact-metadata: write` permission; pinning the older one means the first Dependabot actions bump breaks attestation by adding the requirement without the permission).
- Produces: Gradle task `:app:cyclonedxBom` emitting `app/build/reports/cyclonedx/bom.json`; release assets `app-release.apk` + `bom.json`. (The Cloudflare worker points at the separate `androdr-releases` repo's `app-debug.apk`, so this rename cannot break it — verified 2026-07-15.)

- [ ] **Step 0: Create the PR 2 branch off fresh main**

```bash
git checkout main && git pull --ff-only
git checkout -b feat/252-supply-chain-pr2-release
```

- [ ] **Step 1: Add the CycloneDX plugin**

`gradle/libs.versions.toml` — under `[versions]`:

```toml
cyclonedx = "3.3.0"
```

Under `[plugins]`:

```toml
cyclonedx-bom = { id = "org.cyclonedx.bom", version.ref = "cyclonedx" }
```

`app/build.gradle.kts` — append to the `plugins {}` block:

```kotlin
    alias(libs.plugins.cyclonedx.bom)
```

And at file scope (after the `android {}` block), configure the tasks:

```kotlin
// SBOM for release evidence (#252). Aggregate task emits JSON only; the
// direct task is restricted to what actually ships (release runtime).
tasks.cyclonedxBom {
    jsonOutput.set(layout.buildDirectory.file("reports/cyclonedx/bom.json"))
    xmlOutput.unsetConvention()
}
tasks.cyclonedxDirectBom {
    includeConfigs.set(listOf("releaseRuntimeClasspath"))
}
```

(If the generated accessors `tasks.cyclonedxBom` / `tasks.cyclonedxDirectBom`
don't resolve, use `tasks.named("cyclonedxBom") { ... }` with the same body —
the properties are on the task type, reachable via `this`.)

- [ ] **Step 2: Verify SBOM generation locally**

```bash
export JAVA_HOME=/home/yasir/Applications/android-studio/jbr
./gradlew :app:cyclonedxBom
python3 -c "import json; b=json.load(open('app/build/reports/cyclonedx/bom.json')); print(b['bomFormat'], len(b['components']), 'components')"
```

Expected: `CycloneDX <N> components` with N > 50 (the app has a large
runtime tree). If the components list is tiny or includes test-only deps,
revisit `includeConfigs`.

- [ ] **Step 3: Verify release signing mechanics locally**

```bash
export JAVA_HOME=/home/yasir/Applications/android-studio/jbr
export ANDROID_HOME=/home/yasir/Android/Sdk
./gradlew assembleRelease --stacktrace
BT=$(find "$ANDROID_HOME/build-tools" -maxdepth 1 -mindepth 1 -type d | sort -V | tail -1)
"$BT/apksigner" verify --print-certs app/build/outputs/apk/release/app-release.apk | grep -i 'SHA-256'
```

Expected: build succeeds and apksigner prints a certificate digest. NOTE:
locally this is the **upload key's** digest (local builds use your real
keystore at `release-keystore.jks` + `~/.gradle` passwords) — it will NOT
match Task 8's pinned CI digest, by design. This step proves the signing
path works; the pinned-digest match is proven by the CI dry-run (Task 10
Step 2), where the decoded keystore is the CI one.

- [ ] **Step 4: Rewrite release.yml**

Replace the `Build debug APK` step and everything from `permissions:` down
as follows. Complete new `.github/workflows/release.yml` (the checkout /
setup-java / setup-android / setup-gradle / wait-for-ci-success /
compute-version steps are IDENTICAL to the current file, SHA-pinned per
Task 1 — only the pieces shown here change or are new). Full file:

```yaml
name: Release

on:
  push:
    branches: [main]
    paths-ignore:
      - '**/*.md'
      - 'docs/**'
      - 'notes/**'
  workflow_dispatch:
    inputs:
      dry_run:
        description: 'Build, sign, verify, and generate SBOM only — do not publish a release or attestation'
        type: boolean
        default: false

# No workflow-level permissions: scoped per-job (spec: "per-job token
# scoping") so a future second job doesn't silently inherit release powers.
permissions: {}

concurrency:
  group: release
  cancel-in-progress: false

jobs:
  release:
    runs-on: ubuntu-latest
    timeout-minutes: 45
    permissions:
      contents: write            # gh release create
      actions: read              # poll ci-success
      checks: read               # poll ci-success
      id-token: write            # provenance attestation (OIDC)
      attestations: write        # provenance attestation
      artifact-metadata: write   # required by attest-build-provenance >= v3.2
    env:
      # Dedicated CI release cert (public — printable from any APK signed
      # with it; the Play upload key is never stored in CI). A build signed
      # with any other key must fail.
      EXPECTED_CERT_SHA256: '<DIGEST-FROM-TASK-8>'
    steps:
      - uses: actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5 # v4.3.1
        with:
          fetch-depth: 0
          submodules: true
      - uses: actions/setup-java@c1e323688fd81a25caa38c78aa6df2d33d3e20d9 # v4.8.0
        with:
          java-version: '21'
          distribution: 'temurin'
          cache: 'gradle'
      - uses: android-actions/setup-android@9fc6c4e9069bf8d3d10b2204b1fb8f6ef7065407 # v3.2.2
      - uses: gradle/actions/setup-gradle@ed408507eac070d1f99cc633dbcf757c94c7933a # v4.4.3
      - name: Wait for ci-success on this SHA
        uses: actions/github-script@f28e40c7f34bde8b3046d885e986cb6290c5673b # v7.1.0
        with:
          script: |
            <UNCHANGED — keep the existing polling script verbatim>
      - name: Decode release keystore
        env:
          RELEASE_KEYSTORE_BASE64: ${{ secrets.RELEASE_KEYSTORE_BASE64 }}
        run: |
          set -euo pipefail
          if [ -z "$RELEASE_KEYSTORE_BASE64" ]; then
            echo "RELEASE_KEYSTORE_BASE64 secret is not set" >&2
            exit 1
          fi
          printf '%s' "$RELEASE_KEYSTORE_BASE64" | base64 -d > release-keystore.jks
      - name: Build signed release APK
        env:
          ORG_GRADLE_PROJECT_RELEASE_STORE_PASSWORD: ${{ secrets.RELEASE_STORE_PASSWORD }}
          ORG_GRADLE_PROJECT_RELEASE_KEY_ALIAS: ${{ secrets.RELEASE_KEY_ALIAS }}
          ORG_GRADLE_PROJECT_RELEASE_KEY_PASSWORD: ${{ secrets.RELEASE_KEY_PASSWORD }}
        run: ./gradlew assembleRelease --stacktrace
      - name: Verify APK signature against pinned CI release cert
        run: |
          set -euo pipefail
          BT=$(find "$ANDROID_HOME/build-tools" -maxdepth 1 -mindepth 1 -type d | sort -V | tail -1)
          APK=app/build/outputs/apk/release/app-release.apk
          "$BT/apksigner" verify --print-certs "$APK" | tee /tmp/apksigner.out
          if ! grep -qi "certificate SHA-256 digest: ${EXPECTED_CERT_SHA256}" /tmp/apksigner.out; then
            echo "FAIL: APK is not signed by the expected CI release key" >&2
            exit 1
          fi
          echo "PASS: signature matches pinned CI release certificate"
      - name: Generate CycloneDX SBOM
        run: ./gradlew :app:cyclonedxBom
      - name: Compute version and release notes
        id: version
        run: |
          <UNCHANGED — keep the existing version/notes script verbatim>
      - name: Attest build provenance (APK + SBOM)
        # Deliberately skipped on dry-runs: attestations are permanent in
        # the repo's attestation log (declared deviation — first real
        # release is the attestation test, verified immediately post-merge).
        if: ${{ inputs.dry_run != true }}
        uses: actions/attest-build-provenance@96278af6caaf10aea03fd8d33a09a777ca52d62f # v3.2.0
        with:
          subject-path: |
            app/build/outputs/apk/release/app-release.apk
            app/build/reports/cyclonedx/bom.json
      - name: Publish release
        if: ${{ inputs.dry_run != true }}
        env:
          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        run: |
          # shellcheck disable=SC2016  # backticks in printf are literal markdown
          {
            cat /tmp/release-notes.md
            printf '\n---\nVerify this release: `gh attestation verify app-release.apk --repo %s`\nSBOM: `bom.json` (CycloneDX). Details: docs/supply-chain.md\n' "${{ github.repository }}"
          } > /tmp/release-notes-full.md
          gh release create "${{ steps.version.outputs.tag }}" \
            app/build/outputs/apk/release/app-release.apk \
            app/build/reports/cyclonedx/bom.json \
            --target "${{ github.sha }}" \
            --title "AndroDR ${{ steps.version.outputs.tag }}" \
            --notes-file /tmp/release-notes-full.md
      - name: Upload dry-run artifacts
        if: ${{ inputs.dry_run == true }}
        uses: actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02 # v4.6.2
        with:
          name: release-dry-run
          path: |
            app/build/outputs/apk/release/app-release.apk
            app/build/reports/cyclonedx/bom.json
          retention-days: 7
```

Notes for the implementer:
- `<UNCHANGED — keep ... verbatim>` means copy those two script blocks
  exactly from the current file (they are quoted in full in the repo at
  `.github/workflows/release.yml:40-75` and `:80-99`) — do not retype them.
- `<DIGEST-FROM-TASK-8>` is the literal digest recorded in Task 8.
- `inputs.dry_run != true` is `true` on push events (where `inputs` is
  empty), so pushes to main always publish — behavior preserved.

- [ ] **Step 5: Remove the "pending PR 2" markers, actionlint + commit**

Delete the `> **Status: pending PR 2 of #252** …` lines from `SECURITY.md`
and `docs/supply-chain.md` (layer-4 section) — this PR makes those sections
true.

```bash
actionlint
git add .github/workflows/release.yml gradle/libs.versions.toml app/build.gradle.kts SECURITY.md docs/supply-chain.md
git commit -m "feat(release): signed release APK + SBOM + provenance attestation

release.yml now builds assembleRelease signed with a dedicated CI release
keystore (the Play upload key is never stored in CI — maintainer decision),
hard-fails unless the signature matches the pinned CI-cert digest, attaches
a CycloneDX SBOM, and attests SLSA build provenance for both artifacts.
workflow_dispatch gains a dry_run input for branch testing.
Sideload note: previously sideloaded debug-signed GitHub APKs need a
one-time uninstall/reinstall.

Refs #252

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 10: PR 2 — dry-run proof, review, merge, verify first real release

- [ ] **Step 1: Push, open PR** (the branch was created in Task 9 Step 0)

```bash
git push -u origin feat/252-supply-chain-pr2-release
gh pr create --title "feat(release): signed APK + SBOM + provenance (supply-chain PR 2)" --body "$(cat <<'EOF'
Phase 2 of #252: release.yml switches from debug to a signed assembleRelease
APK — signed with a dedicated CI release keystore; the Play upload key is
never stored in CI (maintainer decision at plan gate). The workflow pins the
CI cert digest, generates a CycloneDX SBOM, and attests SLSA build
provenance. Dry-run evidence and CI status in comments.

Declared deviation: dry-runs skip attestation (permanent log pollution);
the first post-merge release is the attestation test, verified immediately.

Known one-time cost: previously sideloaded debug-signed GitHub APKs will
need uninstall/reinstall (signature change). Play Store unaffected.

Refs #252

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
)"
gh pr checks --watch
```

- [ ] **Step 2: Dry-run the release workflow on the branch**

```bash
gh workflow run release.yml --ref feat/252-supply-chain-pr2-release -f dry_run=true
gh run watch $(gh run list --workflow=release.yml --limit 1 --json databaseId --jq '.[0].databaseId')
```

Expected: run succeeds; `Verify APK signature` step logs
`PASS: signature matches pinned CI release certificate` — this is the
definitive proof that the decoded CI keystore, the secrets, and the pinned
digest all agree; `release-dry-run` artifact contains `app-release.apk` +
`bom.json`; **no release and no attestation were created** (declared
deviation; `gh release list --limit 1` shows no new tag).
Link the green run in a PR comment as evidence.

- [ ] **Step 3: 4-agent review ceremony** (same as Task 6 Step 4), fix, re-green.

- [ ] **Step 4: Squash-merge and verify the first signed release end-to-end**

Prerequisite check (global constraint): `gh --version` must be ≥ 2.49
(`gh attestation` doesn't exist in 2.45). If not yet upgraded: install
gh from the official apt repo or a release binary, verify
`gh attestation --help` works, then proceed.

```bash
gh pr merge --squash --delete-branch
# The merge push triggers release.yml for real. Watch it:
gh run watch $(gh run list --workflow=release.yml --branch main --limit 1 --json databaseId --jq '.[0].databaseId')
TAG=$(gh release list --limit 1 --json tagName --jq '.[0].tagName')
gh release download "$TAG" --pattern 'app-release.apk' --dir /tmp/claude-1000/-home-yasir-AndroDR/*/scratchpad/
gh attestation verify <scratchpad>/app-release.apk --repo yasirhamza/AndroDR
```

Expected: `gh attestation verify` prints a successful verification
referencing this repo and `release.yml`. Also confirm `bom.json` is listed
under the release's assets (`gh release view "$TAG"`).

- [ ] **Step 5: Add the sideload-break note to the first signed release**

```bash
gh release edit "$TAG" --notes-file <(gh release view "$TAG" --json body --jq .body; printf '\n> **Sideload note:** starting with this release, GitHub APKs are signed with a stable AndroDR CI release key instead of a per-build debug key. If you sideloaded an older GitHub APK, uninstall it once before installing this one (signature mismatch); future updates will install over this one cleanly. Play Store installs are unaffected.\n')
```

---

## Phase 3 — PR 3: Gradle dependency checksum verification

### Task 11: Generate verification metadata + local tamper proof

**Files:**
- Create: `gradle/verification-metadata.xml` (generated)

- [ ] **Step 1: Generate**

```bash
git checkout main && git pull --ff-only
git checkout -b feat/252-supply-chain-pr3-depverify
export JAVA_HOME=/home/yasir/Applications/android-studio/jbr
export ANDROID_HOME=/home/yasir/Android/Sdk
./gradlew --write-verification-metadata sha256 \
  assembleDebug assembleRelease testDebugUnitTest lintDebug detekt \
  assembleDebugAndroidTest :app:cyclonedxBom
```

Expected: BUILD SUCCESSFUL; `gradle/verification-metadata.xml` created,
containing `<verify-metadata>true</verify-metadata>` and thousands of
`<sha256 ...>` entries. The task set mirrors everything CI executes
(build, unit tests, lint, detekt, androidTest compile, SBOM) so no CI job
resolves an unrecorded configuration.

- [ ] **Step 2: Clean-build proof that verification is active and green**

```bash
./gradlew --stop && ./gradlew clean assembleDebug testDebugUnitTest lintDebug detekt --stacktrace
```

Expected: BUILD SUCCESSFUL (verification active — failures would say
"Dependency verification failed").

- [ ] **Step 3: Tamper test — flip one checksum, expect red, restore**

```bash
sed -i -E '0,/sha256 value="[0-9a-f]+"/s//sha256 value="0000000000000000000000000000000000000000000000000000000000000000"/' gradle/verification-metadata.xml
git diff --stat gradle/verification-metadata.xml   # MUST show the file changed — a no-op here invalidates the test
./gradlew assembleDebug 2>&1 | grep -m1 -i "verification failed" && echo "TAMPER DETECTED (expected)"
git checkout -- gradle/verification-metadata.xml
./gradlew assembleDebug --quiet && echo "restored: green"
```

Expected: the diff shows exactly one change (the replacement digest is a
fixed all-zeros value, so this can't silently no-op the way a
single-character flip could), then `Dependency verification failed` →
`TAMPER DETECTED (expected)`, then `restored: green`. Capture this output
for the PR body (the spec's documented tamper-case evidence).

- [ ] **Step 4: Commit**

```bash
git add gradle/verification-metadata.xml
git commit -m "build(security): enable Gradle dependency checksum verification (sha256)

Every resolved artifact (deps + plugins) now has a pinned sha256; a
tampered/typosquatted/mirror-poisoned artifact fails the build. Checksums
only, no PGP, per #252. Regen command documented in docs/supply-chain.md.

Refs #252

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 12: Dependabot auto-regen workflow

**Files:**
- Create: `.github/workflows/dependabot-verification-regen.yml`

**Interfaces:**
- Consumes: a fine-grained PAT stored as **Dependabot secret** `DEPENDABOT_REGEN_TOKEN` (Dependabot-triggered workflow runs can only read Dependabot secrets, and pushes made with the default `GITHUB_TOKEN` do not retrigger CI — a PAT push does).

- [ ] **Step 1: USER ACTION — create the PAT (requires browser)**

Ask the user to create a fine-grained PAT at
https://github.com/settings/personal-access-tokens/new with: Resource owner
= themselves; Repository access = **Only select repositories → AndroDR**;
Permissions = **Contents: Read and write** (nothing else); Expiration =
**90 days** (plan-gate security decision: this token can push branches and
create releases if stolen — short expiry bounds the window; renewal is one
`gh secret set` with a fresh token, documented in docs/supply-chain.md).
Then store it (paste into the terminal prompt, not into chat):

```bash
gh secret set DEPENDABOT_REGEN_TOKEN --app dependabot
gh secret list --app dependabot
```

Expected: `DEPENDABOT_REGEN_TOKEN` listed under Dependabot secrets.
**Fallback if the user declines the PAT:** skip this task, delete the
workflow from the plan, AND edit `docs/supply-chain.md` to replace the
"handled automatically by …dependabot-verification-regen.yml" sentence
with the manual process — Dependabot PRs then arrive red until the
maintainer runs the regen command locally and pushes. The docs must not
claim automation that doesn't exist.

- [ ] **Step 2: Write the workflow**

`.github/workflows/dependabot-verification-regen.yml` (complete file):

```yaml
name: Regenerate dependency verification metadata

# Dependabot bumps change artifact checksums, which fails the build until
# gradle/verification-metadata.xml is regenerated. This regenerates it on
# the bot's branch and pushes with a PAT (a GITHUB_TOKEN push would not
# retrigger CI). Runs ONLY for dependabot[bot] on same-repo branches.
#
# THREAT MODEL (plan-gate security review): this job processes a
# freshly-bumped, not-yet-verified dependency tree while a contents-write
# PAT exists in the repo's Dependabot secrets. A stolen PAT can push
# branches and forge releases. Mitigations, in order:
#   - checkout uses the default read-only token, persist-credentials: false
#     -> no credential on disk while Gradle runs
#   - --dry-run: dependencies resolve but NO task of the bumped tree
#     executes (residual risk: configuration-time code in settings/build
#     scripts and plugin application still runs — that code is repo-owned,
#     Dependabot only edits libs.versions.toml, but a bumped *plugin
#     version's* configuration code does run)
#   - the PAT enters exactly one step's env (the push), after Gradle exited
#   - TOFU caveat: the regenerated checksum of the new artifact pins
#     whatever this runner downloaded — see docs/supply-chain.md
#   - 90-day PAT expiry bounds the exposure window

on:
  pull_request:
    branches: [main]
    paths:
      - 'gradle/libs.versions.toml'
      - '.github/workflows/dependabot-verification-regen.yml'

permissions: {}

concurrency:
  group: dependabot-regen-${{ github.ref }}
  cancel-in-progress: true

jobs:
  regen:
    if: ${{ github.actor == 'dependabot[bot]' && github.event.pull_request.head.repo.full_name == github.repository }}
    runs-on: ubuntu-latest
    timeout-minutes: 30
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5 # v4.3.1
        with:
          ref: ${{ github.head_ref }}
          fetch-depth: 0
          submodules: true
          persist-credentials: false
      - uses: actions/setup-java@c1e323688fd81a25caa38c78aa6df2d33d3e20d9 # v4.8.0
        with:
          java-version: '21'
          distribution: 'temurin'
          cache: 'gradle'
      - uses: android-actions/setup-android@9fc6c4e9069bf8d3d10b2204b1fb8f6ef7065407 # v3.2.2
      - uses: gradle/actions/setup-gradle@ed408507eac070d1f99cc633dbcf757c94c7933a # v4.4.3
        with:
          cache-read-only: true
      - name: Regenerate verification metadata (resolution only, no task execution)
        # Same task list as the documented local command; --dry-run is the
        # ONLY difference (declared) — it resolves every configuration the
        # graph needs without executing the bumped tree's tasks. Side
        # effect: assembleRelease is safe here (its validateSigning task,
        # which would fail on the runner's missing keystore, never runs).
        run: |
          ./gradlew --dry-run --write-verification-metadata sha256 \
            assembleDebug assembleRelease testDebugUnitTest lintDebug detekt \
            assembleDebugAndroidTest :app:cyclonedxBom
      - name: Commit and push if changed
        env:
          REGEN_TOKEN: ${{ secrets.DEPENDABOT_REGEN_TOKEN }}
        run: |
          set -euo pipefail
          if git diff --quiet -- gradle/verification-metadata.xml; then
            echo "No metadata changes needed"
            exit 0
          fi
          git config user.name "github-actions[bot]"
          git config user.email "41898282+github-actions[bot]@users.noreply.github.com"
          git add gradle/verification-metadata.xml
          git commit -m "build: regenerate dependency verification metadata for Dependabot bump"
          git push "https://x-access-token:${REGEN_TOKEN}@github.com/${{ github.repository }}.git" "HEAD:${{ github.head_ref }}"
```

Notes:
- If a Dependabot PR is still red after regen ("Dependency verification
  failed" on an artifact the dry run didn't resolve — an execution-only
  configuration), the documented remedy is a local regen without
  `--dry-run` + push (docs/supply-chain.md layer 1). Expected to be rare;
  observe the first real cycle.
- The narrow `paths:` trigger is deliberate: actions-SHA bumps can't change
  Gradle checksums, so `.github/workflows/**` would only burn a ~20-min
  Gradle run to print "No metadata changes needed". The workflow's own file
  is included for self-testing on the PR that introduces or edits it —
  though as a non-Dependabot PR it skips via the `if:` guard (actionlint +
  PR 3's own CI cover it).

- [ ] **Step 3: Remove the "pending PR 3" marker, actionlint + commit**

Delete the `> **Status: pending PR 3 of #252** …` line from
`docs/supply-chain.md` (layer-1 section) — this PR makes it true.

```bash
actionlint
git add .github/workflows/dependabot-verification-regen.yml docs/supply-chain.md
git commit -m "ci(security): auto-regen verification metadata on Dependabot PRs

Hardened per plan-gate security review: read-only checkout without
persisted credentials, --dry-run regeneration so the bumped tree's tasks
never execute, and the repo-scoped fine-grained PAT (Dependabot secret,
90-day expiry) enters only the final push step's env — a PAT push is what
retriggers CI, which a GITHUB_TOKEN push would not. Guarded to
dependabot[bot] on same-repo branches only. TOFU caveat documented in
docs/supply-chain.md.

Refs #252

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 13: PR 3 — CI proof, review, merge, close out

- [ ] **Step 1: Push, open PR (this one closes the issue)**

```bash
git push -u origin feat/252-supply-chain-pr3-depverify
gh pr create --title "build(security): Gradle dependency checksum verification (supply-chain PR 3)" --body "$(cat <<'EOF'
Phase 3 of the supply chain posture: sha256 verification metadata for every
resolved artifact + auto-regen on Dependabot branches. Local tamper test
evidence in comments (flipped checksum -> 'Dependency verification failed').
[STALE AS EXECUTED — auto-regen postponed per deviation #9; the real PR #260
body describes the postponement. Kept for the historical record.]

Closes #252

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
)"
gh pr checks --watch
```

Expected: full CI green — every job (build, tests, lint, detekt, CodeQL,
emulator) now resolves dependencies under verification, **specifically
including `dependency-submission`** (this PR touches the deps bucket, so
the job runs — it must stay green thanks to its
`--dependency-verification=off` argument; if it reds on verification, that
argument regressed). A red job citing "Dependency verification failed"
means the Task 11 task set missed a configuration: regenerate with the
failing task appended, commit, push.
Post the Task 11 Step 3 tamper-test output as a PR comment.

- [ ] **Step 2: 4-agent review ceremony**, fix, re-green.

- [ ] **Step 3: Squash-merge; watch the first release under verification; verify issue closed; final acceptance sweep**

```bash
gh pr merge --squash --delete-branch
# CRITICAL: the merge push triggers release.yml — the FIRST assembleRelease
# under active dependency verification (CI never runs that path on PRs).
# Do not proceed to the AC sweep until this run is green and a NEW tag
# exists (a stale PR 2-era release would let the sweep false-pass).
gh run watch $(gh run list --workflow=release.yml --branch main --limit 1 --json databaseId --jq '.[0].databaseId')
gh release list --limit 2   # newest tag must postdate the PR 3 merge
gh issue view 252 --json state --jq .state   # expect CLOSED
```

If the release run reds with "Dependency verification failed", a
release-only configuration is missing from the metadata: regenerate
locally with the failing task appended, open a small fix PR (the plan's
safe-ordering rules apply), and re-verify.

Then walk the spec's acceptance criteria and check each against live state:

```bash
grep -rn "uses:.*@v[0-9]" .github/workflows/ || echo "AC1 PASS: all SHA-pinned"
gh api "repos/:owner/:repo/code-scanning/analyses?per_page=1" --jq '.[0].tool.name'   # AC2: CodeQL
ls .github/dependency-review-config.yml .github/tracked-path-denylist.txt SECURITY.md docs/supply-chain.md   # AC3/5/9
gh api repos/:owner/:repo/dependency-graph/snapshots 2>/dev/null || gh api "repos/:owner/:repo/dependency-graph/sbom" --jq '.sbom.packages | length'   # AC4: graph populated
gh release view --json assets --jq '.assets[].name'   # AC6/7: app-release.apk + bom.json
gh attestation verify <scratchpad>/app-release.apk --repo yasirhamza/AndroDR   # AC7
ls gradle/verification-metadata.xml   # AC8
gh api repos/:owner/:repo/rulesets/14651316 --jq '[.rules[].type]'   # AC9: includes code_scanning
```

Post a closing comment on #252 summarizing the three merged PRs, plus —
mandatory, these are declared deviations/pending items:
- AC "auto-regen works" is pending the **first real Dependabot cycle**
  (monthly) — record that it must be observed and where to look.
- The `DEPENDABOT_REGEN_TOKEN` expiry date (90 days from creation) and the
  renewal command.
- The Play upload key is NOT in CI (maintainer decision superseding the
  issue's original risk-1 mitigation); GitHub releases sign with the
  dedicated CI key, digest pinned in release.yml.
- Any follow-ups discovered (e.g., PR 3 fallback if PAT declined,
  docs-only-PR probe outcome from Task 7 Step 3).

---

## Deviations register (declared; ratified at the 2026-07-15 plan gate)

1. **`dependency-review` blocks via `ci-success`**, not a separate required
   ruleset check — a separate context would deadlock docs-only PRs. Stated
   in PR 1's body and `docs/supply-chain.md`.
2. **Signing: dedicated CI release keystore** instead of the Play upload
   key in CI (maintainer decision, supersedes issue #252's original PR-2
   design). Upload key never leaves the maintainer machine.
3. **Dry-runs skip attestation** (spec's testing section wanted it
   pre-merge) — attestations are permanent log entries; first post-merge
   release is the compensating verification, watched immediately.
4. **Metadata generation uses the full CI task set**, superseding the
   spec's original `help` bootstrap (now corrected in the spec) — `help`
   alone leaves test/lint/SBOM configurations unrecorded.
5. **AC "auto-regen works" is accepted on the first real Dependabot
   cycle** — Dependabot secrets are unreadable outside Dependabot-triggered
   runs, so the PAT push path cannot be faithfully simulated pre-merge.
   Recorded in #252's closing comment as pending observation.
   *(Superseded in part by #9: the workflow itself is postponed, so this
   acceptance moves to the follow-up PR's first cycle.)*
6. **Private vulnerability reporting enabled** (Task 7 Step 4) — addition
   beyond the issue's SECURITY.md scope, ratified at the plan gate.
7. **Regen workflow runs `--dry-run`** — the one difference from the
   documented local regen command (security: bumped tree's tasks never
   execute on the PAT-adjacent runner). Residual-risk and TOFU caveats in
   the workflow header + docs.
8. **Bootstrap suppression block (18 GHSAs)** — Task 3's config shipped with
   a clearly-marked, wholesale-removable block instead of the planned empty
   allow-ghsas: the snapshot-less first dependency-review run evaluated the
   whole standing build-classpath tree as "added" (18 distinct crit/high,
   all AGP-toolchain, enumerated via the compare API after per-run drip).
   Removed by the follow-up PR immediately after PR 1 merges; see the block
   banner in .github/dependency-review-config.yml and PR #255's evidence
   comment.
9. **Auto-regen workflow postponed** (maintainer decision 2026-07-16):
   the interactive PAT provisioning couldn't complete in-session, and the
   maintainer chose to postpone rather than block. PR 3 ships without
   `.github/workflows/dependabot-verification-regen.yml`; docs describe
   manual regen as the current process. Follow-up PR adds the workflow
   (full YAML in Task 12 above) once `DEPENDABOT_REGEN_TOKEN` exists —
   ideally before the ~2026-08-01 Dependabot cycle. Recorded in #252's
   closing comment.
10. **Task 11's tamper-test recipe corrected during execution:** the
   written recipe (flip the file's FIRST sha256) was a false negative —
   that entry was a sources jar `assembleDebug` never resolves, and
   configuration-cache reuse skipped verification entirely. Corrected
   form: zero out the digest of an artifact the build actually resolves
   (e.g. `activity-1.9.1.aar`) and run with `--no-configuration-cache`.
   Docs carry the config-cache caveat; any future copy of the recipe must
   use the corrected form.
11. **Task 11's local clean-build proof aborted mid-run** (maintainer
   wall-clock request): PR CI under active verification is the accepted
   green proof. (The build happened to finish before the abort took
   effect, so its green evidence exists anyway — see task report.)
12. **Warm-cache baseline gap, caught by PR 3's own CI + ceremony BLOCKs:**
   the locally generated metadata missed 12 parent-POM/module entries a
   cold cache resolves (local green was circular evidence — a file
   generated from cache X always verifies against cache X). Fixed
   additively via `--write-verification-metadata sha256 help
   --refresh-dependencies`; the documented regen command now mandates
   `--refresh-dependencies`. Relatedly, the graph compare API proved to
   need a snapshot for the EXACT base SHA: `dependency-submission` now
   also runs on every push to main (permanent), and `dependency-review`
   temporarily pins `base-ref` to the last snapshot-bearing main commit —
   **the pin must be removed in the auto-regen follow-up PR**.

## Plan self-review notes (already applied)

- Spec's release-notes "verify this release" snippet: implemented inline in
  the Publish step (Task 9) rather than a template file — YAGNI.
- CLAUDE.md is deliberately untouched: regen and triage live in
  `docs/supply-chain.md`, which CLAUDE.md-adjacent workflows already
  discover via the architecture-docs convention.
