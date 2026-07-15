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

One caveat: `ci.yml` line 24 has a **comment** mentioning `dorny/paths-filter@v3` — the sed will rewrite it too. That's acceptable (comment stays truthful) but check the diff reads sensibly.

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
# (git ls-files -- ':(glob)PATTERN'). Lines starting with # are comments.
# Mirror every addition here into .gitignore so the file never gets
# tracked in the first place.
#
# NOTE: .claude/ is deliberately NOT wholesale-denylisted — the repo
# intentionally tracks .claude/commands/ (the public update-rules
# pipeline skills). Only local state is banned.
.memsearch/**
.superpowers/**
.claude/settings.local.json
**/*.jks
**/*.keystore
**/local.properties
**/.env
**/.env.*
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
  matches=$(git ls-files -- ":(glob)$pattern")
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
touch .env.test && git add .env.test
bash .github/scripts/check-tracked-paths.sh; echo "exit=$?"
git rm --cached -q .env.test && rm .env.test
```

Expected: `DENYLISTED tracked path(s) matching '**/.env.*': .env.test`, `FAIL: ...`, `exit=1`. (Staged files appear in `git ls-files`, so this exercises the real failure path without committing.)

- [ ] **Step 5: Mirror into .gitignore**

Append to `.gitignore` (after the `.memsearch/` block; `.claude/`, `.superpowers/`, `*.jks`, `*.keystore`, `local.properties` are already ignored):

```
# Env files — must never be tracked (see .github/tracked-path-denylist.txt)
.env
.env.*
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
- Produces: CI job names `dependency-submission` and `dependency-review`, both folded into `ci-success` (skipped-counts-as-pass, same as every other path-filtered gate). **Design refinement vs the spec:** blocking happens via the existing required `ci-success` check rather than a new required ruleset context — this reuses the repo's established path-filter pattern so docs-only PRs aren't blocked waiting for a check that never reports. Task 5's docs and the PR body must state this.

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
```

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
      - uses: actions/setup-java@c1e323688fd81a25caa38c78aa6df2d33d3e20d9 # v4.8.0
        with:
          java-version: '21'
          distribution: 'temurin'
          cache: 'gradle'
      - uses: android-actions/setup-android@9fc6c4e9069bf8d3d10b2204b1fb8f6ef7065407 # v3.2.2
      - uses: gradle/actions/dependency-submission@ed408507eac070d1f99cc633dbcf757c94c7933a # v4.4.3
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

- [ ] **Step 3: Write the suppressions/config file**

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
        # --no-daemon: CodeQL traces compiler invocations; the Gradle
        # daemon detaches them from the traced process tree.
        run: ./gradlew --no-daemon assembleDebug --stacktrace
      - uses: github/codeql-action/analyze@02c5e83432fe5497fd85b873b6c9f16a8578e1d9 # v3.37.0
        with:
          category: '/language:java-kotlin'
```

- [ ] **Step 2: actionlint + commit**

```bash
actionlint
git add .github/workflows/codeql.yml
git commit -m "ci(security): CodeQL java-kotlin SAST on PRs + weekly cron

Manual build mode (AGP needs the Android SDK, so autobuild can't work).
Path-filtered to code; GitHub's code-scanning merge protection treats
'analysis not expected for these paths' as satisfied, so docs-only PRs
aren't blocked.

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

Every GitHub release ships a signed APK, a CycloneDX SBOM, and a SLSA
build-provenance attestation. See
[docs/supply-chain.md](docs/supply-chain.md) for verification commands.

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
| 4 | Release integrity | Upload-key-signed APK + CycloneDX SBOM + SLSA provenance | `release.yml` |
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
`tj-actions/changed-files` attack vector.

## Release integrity (layer 4) — verifying a release

Every release published by `release.yml` carries three artifacts: the
signed APK, `bom.json` (CycloneDX SBOM), and a provenance attestation
stored in the repo's attestation log. To verify a downloaded APK:

    # Provenance: proves this exact file was built by release.yml in this
    # repo at a specific commit (SLSA build attestation).
    gh attestation verify app-release.apk --repo yasirhamza/AndroDR

    # Signature: proves it's signed with the AndroDR upload key.
    apksigner verify --print-certs app-release.apk

The signing key is a **Play App Signing upload key** (Google holds the
actual app-signing key), and `release.yml` additionally pins the expected
certificate SHA-256 digest — a build signed with any other key fails CI.

**Key-leak runbook:** if the upload key or its passwords are suspected
compromised: (1) rotate the four `RELEASE_*` GitHub secrets immediately,
(2) request an upload-key reset in Play Console → Setup → App signing,
(3) re-provision secrets from the new keystore. Play Store users are
unaffected during rotation; GitHub-release sideloaders must reinstall.

**"Am I affected?" (new CVE in some library):** download `bom.json` from
the latest release (or run `./gradlew :app:cyclonedxBom` locally) and
search it for the artifact — answer in minutes, no build required.

## Dependency checksum verification (layer 1)

`gradle/verification-metadata.xml` records the sha256 of every resolved
artifact (dependencies *and* plugins). Any mismatch — tampered artifact,
typosquat, poisoned mirror — fails the build before code runs.

After **any** dependency change, regenerate:

    export JAVA_HOME=/home/yasir/Applications/android-studio/jbr  # or your JDK 21
    ./gradlew --write-verification-metadata sha256 \
      assembleDebug assembleRelease testDebugUnitTest lintDebug detekt \
      assembleDebugAndroidTest :app:cyclonedxBom

and commit the updated file. Dependabot PRs are handled automatically by
`.github/workflows/dependabot-verification-regen.yml`, which regenerates
and pushes onto the bot's branch. A red build complaining about
"Dependency verification failed" on a *non*-Dependabot branch means you
changed dependencies without regenerating (or something genuinely
tampered — check which artifact and why before regenerating).

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
rotate/purge accordingly.

## Enforcement summary

- Ruleset "Protect main": PRs required, required check `ci-success`
  (which folds in dependency-review, the denylist guard, and all build
  gates), CodeQL code-scanning rule (blocks on new high-severity alerts),
  no force-push/deletion.
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
takes ~15–30 min), plus all pre-existing jobs. If CodeQL's manual build
fails, fix before proceeding (likely SDK/licenses — compare against the
working `build-and-test` job setup).

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
`DENYLISTED tracked path(s) matching '**/.env.*'`; the final run is green.
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
first re-fetch current state (do not blind-overwrite):

```bash
gh api repos/:owner/:repo/rulesets/14651316 --jq '{name, target, enforcement, conditions, rules}'
```

Then PUT the same content with one addition to `rules` (keep every existing
rule byte-identical; `required_status_checks` stays `ci-success`-only per
the Task 3 design refinement):

```json
{
  "name": "Protect main",
  "target": "branch",
  "enforcement": "active",
  "conditions": { "ref_name": { "include": ["refs/heads/main"], "exclude": [] } },
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

- [ ] **Step 3: Enable private vulnerability reporting** (referenced by SECURITY.md)

```bash
gh api -X PUT repos/:owner/:repo/private-vulnerability-reporting
gh api repos/:owner/:repo/private-vulnerability-reporting --jq .enabled
```

Expected: `true`.

---

## Phase 2 — PR 2: Release integrity

### Task 8: Provision signing secrets + pin the expected certificate digest

**Interfaces:**
- Produces: GitHub Actions secrets `RELEASE_KEYSTORE_BASE64`, `RELEASE_STORE_PASSWORD`, `RELEASE_KEY_ALIAS`, `RELEASE_KEY_PASSWORD`; and the upload-cert SHA-256 hex digest (lowercase, no colons) used by Task 9's verify step.

- [ ] **Step 1: Set the four secrets (values never displayed)**

```bash
cd /home/yasir/AndroDR
base64 -w0 release-keystore.jks | gh secret set RELEASE_KEYSTORE_BASE64
grep '^RELEASE_STORE_PASSWORD=' ~/.gradle/gradle.properties | cut -d= -f2- | tr -d '\n' | gh secret set RELEASE_STORE_PASSWORD
grep '^RELEASE_KEY_ALIAS='      ~/.gradle/gradle.properties | cut -d= -f2- | tr -d '\n' | gh secret set RELEASE_KEY_ALIAS
grep '^RELEASE_KEY_PASSWORD='   ~/.gradle/gradle.properties | cut -d= -f2- | tr -d '\n' | gh secret set RELEASE_KEY_PASSWORD
gh secret list
```

Expected: `gh secret list` shows all four names with today's timestamp.

- [ ] **Step 2: Extract the expected signing-cert digest**

```bash
export JAVA_HOME=/home/yasir/Applications/android-studio/jbr
ALIAS=$(grep '^RELEASE_KEY_ALIAS=' ~/.gradle/gradle.properties | cut -d= -f2- | tr -d '\n')
grep '^RELEASE_STORE_PASSWORD=' ~/.gradle/gradle.properties | cut -d= -f2- | tr -d '\n' \
  | "$JAVA_HOME/bin/keytool" -exportcert -keystore release-keystore.jks -alias "$ALIAS" -storepass:file /dev/stdin 2>/dev/null \
  | sha256sum | cut -d' ' -f1
```

Expected: a 64-char lowercase hex digest. **This digest is public** (it's
printed by `apksigner` on any distributed APK) — record it; Task 9 embeds
it in `release.yml` as `EXPECTED_CERT_SHA256`.

If `-storepass:file /dev/stdin` is rejected by this keytool build, fall back
to an env var read inside a subshell so the value stays out of the transcript:
`STOREPASS=$(grep ... | cut -d= -f2-)` then `keytool ... -storepass "$STOREPASS"`.

---

### Task 9: Rewire release.yml + CycloneDX SBOM plugin

**Files:**
- Modify: `.github/workflows/release.yml`
- Modify: `gradle/libs.versions.toml` ([versions] + [plugins])
- Modify: `app/build.gradle.kts` (plugins block + task config)

**Interfaces:**
- Consumes: secrets + cert digest from Task 8; pin table from Task 1; `actions/attest-build-provenance@977bb373ede98d70efdf65b84cb5f73e068dcc2a # v3.0.0`.
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

- [ ] **Step 3: Verify release signing locally**

```bash
export JAVA_HOME=/home/yasir/Applications/android-studio/jbr
export ANDROID_HOME=/home/yasir/Android/Sdk
./gradlew assembleRelease --stacktrace
BT=$(ls "$ANDROID_HOME/build-tools" | sort -V | tail -1)
"$ANDROID_HOME/build-tools/$BT/apksigner" verify --print-certs app/build/outputs/apk/release/app-release.apk | grep -i 'SHA-256'
```

Expected: build succeeds (passwords resolve from `~/.gradle/gradle.properties`);
apksigner prints `Signer #1 certificate SHA-256 digest: <digest>` matching
Task 8's digest exactly. If they differ, STOP — wrong keystore/alias.

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

permissions:
  contents: write      # gh release create
  actions: read        # poll ci-success
  checks: read         # poll ci-success
  id-token: write      # provenance attestation (OIDC)
  attestations: write  # provenance attestation

concurrency:
  group: release
  cancel-in-progress: false

jobs:
  release:
    runs-on: ubuntu-latest
    timeout-minutes: 45
    env:
      # Play App Signing upload cert (public — printable from any shipped
      # APK). A build signed with any other key must fail.
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
      - name: Verify APK signature against pinned upload cert
        run: |
          set -euo pipefail
          BT="$ANDROID_HOME/build-tools/$(ls "$ANDROID_HOME/build-tools" | sort -V | tail -1)"
          APK=app/build/outputs/apk/release/app-release.apk
          "$BT/apksigner" verify --print-certs "$APK" | tee /tmp/apksigner.out
          if ! grep -qi "certificate SHA-256 digest: ${EXPECTED_CERT_SHA256}" /tmp/apksigner.out; then
            echo "FAIL: APK is not signed by the expected upload key" >&2
            exit 1
          fi
          echo "PASS: signature matches pinned upload certificate"
      - name: Generate CycloneDX SBOM
        run: ./gradlew :app:cyclonedxBom
      - name: Compute version and release notes
        id: version
        run: |
          <UNCHANGED — keep the existing version/notes script verbatim>
      - name: Attest build provenance (APK + SBOM)
        if: ${{ inputs.dry_run != true }}
        uses: actions/attest-build-provenance@977bb373ede98d70efdf65b84cb5f73e068dcc2a # v3.0.0
        with:
          subject-path: |
            app/build/outputs/apk/release/app-release.apk
            app/build/reports/cyclonedx/bom.json
      - name: Publish release
        if: ${{ inputs.dry_run != true }}
        env:
          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        run: |
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

- [ ] **Step 5: actionlint + commit**

```bash
actionlint
git add .github/workflows/release.yml gradle/libs.versions.toml app/build.gradle.kts
git commit -m "feat(release): signed release APK + SBOM + provenance attestation

release.yml now builds assembleRelease with the Play upload key from CI
secrets, hard-fails unless the signature matches the pinned upload-cert
digest, attaches a CycloneDX SBOM, and attests SLSA build provenance for
both artifacts. workflow_dispatch gains a dry_run input for branch testing.
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
APK (Play App Signing upload key, cert digest pinned in the workflow),
generates a CycloneDX SBOM, and attests SLSA build provenance. Dry-run
evidence and unit-test/CI status in comments.

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
`PASS: signature matches pinned upload certificate`; `release-dry-run`
artifact contains `app-release.apk` + `bom.json`; **no release and no
attestation were created** (`gh release list --limit 1` shows no new tag).
Link the green run in a PR comment as evidence.

- [ ] **Step 3: 4-agent review ceremony** (same as Task 6 Step 4), fix, re-green.

- [ ] **Step 4: Squash-merge and verify the first signed release end-to-end**

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
gh release edit "$TAG" --notes-file <(gh release view "$TAG" --json body --jq .body; printf '\n> **Sideload note:** starting with this release, APKs are signed with the AndroDR release (upload) key instead of a debug key. If you sideloaded an older GitHub APK, uninstall it once before installing this one (signature mismatch). Play Store installs are unaffected.\n')
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
sed -i '0,/sha256 value="[0-9a-f]/s//sha256 value="0/' gradle/verification-metadata.xml
./gradlew assembleDebug 2>&1 | grep -m1 -i "verification failed" && echo "TAMPER DETECTED (expected)"
git checkout -- gradle/verification-metadata.xml
./gradlew assembleDebug --quiet && echo "restored: green"
```

Expected: `Dependency verification failed` → `TAMPER DETECTED (expected)`,
then `restored: green`. Capture this output for the PR body (the spec's
documented tamper-case evidence).

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
Permissions = **Contents: Read and write** (nothing else); Expiration = 1
year. Then store it (paste into the terminal prompt, not into chat):

```bash
gh secret set DEPENDABOT_REGEN_TOKEN --app dependabot
gh secret list --app dependabot
```

Expected: `DEPENDABOT_REGEN_TOKEN` listed under Dependabot secrets.
**Fallback if the user declines the PAT:** skip this task, delete the
workflow from the plan, and document manual regen as the process (already
in `docs/supply-chain.md`) — Dependabot PRs then arrive red until the
maintainer runs the regen command locally and pushes.

- [ ] **Step 2: Write the workflow**

`.github/workflows/dependabot-verification-regen.yml` (complete file):

```yaml
name: Regenerate dependency verification metadata

# Dependabot bumps change artifact checksums, which fails the build until
# gradle/verification-metadata.xml is regenerated. This regenerates it on
# the bot's branch and pushes with a PAT (a GITHUB_TOKEN push would not
# retrigger CI). Runs ONLY for dependabot[bot] on same-repo branches.

on:
  pull_request:
    branches: [main]
    paths:
      - 'gradle/libs.versions.toml'
      - '.github/workflows/**'

permissions: {}

concurrency:
  group: dependabot-regen-${{ github.ref }}
  cancel-in-progress: true

jobs:
  regen:
    if: ${{ github.actor == 'dependabot[bot]' && github.event.pull_request.head.repo.full_name == github.repository }}
    runs-on: ubuntu-latest
    timeout-minutes: 30
    steps:
      - uses: actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5 # v4.3.1
        with:
          ref: ${{ github.head_ref }}
          fetch-depth: 0
          submodules: true
          token: ${{ secrets.DEPENDABOT_REGEN_TOKEN }}
          persist-credentials: true
      - uses: actions/setup-java@c1e323688fd81a25caa38c78aa6df2d33d3e20d9 # v4.8.0
        with:
          java-version: '21'
          distribution: 'temurin'
          cache: 'gradle'
      - uses: android-actions/setup-android@9fc6c4e9069bf8d3d10b2204b1fb8f6ef7065407 # v3.2.2
      - uses: gradle/actions/setup-gradle@ed408507eac070d1f99cc633dbcf757c94c7933a # v4.4.3
        with:
          cache-read-only: true
      - name: Regenerate verification metadata
        run: |
          ./gradlew --write-verification-metadata sha256 \
            assembleDebug assembleRelease testDebugUnitTest lintDebug detekt \
            assembleDebugAndroidTest :app:cyclonedxBom
      - name: Commit and push if changed
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
          git push
```

Notes:
- `assembleRelease` here runs unsigned-config resolution only if signing
  props are absent; Gradle only *reads* `RELEASE_*` properties at execution
  of signing tasks, and `--write-verification-metadata` with these tasks
  resolves configurations. If `assembleRelease` fails on the runner for a
  missing keystore file, drop `assembleRelease` from BOTH this workflow and
  the documented local command (Task 11 Step 1) — release resolution is
  covered by `releaseRuntimeClasspath` through `:app:cyclonedxBom`. Keep the
  two command sites identical.
- The `.github/workflows/**` path trigger exists so Dependabot's
  github-actions bumps (which can change resolved plugins? they don't touch
  Gradle) no-op quickly via "No metadata changes needed" rather than
  leaving a red build unexplained.

- [ ] **Step 3: actionlint + commit**

```bash
actionlint
git add .github/workflows/dependabot-verification-regen.yml
git commit -m "ci(security): auto-regen verification metadata on Dependabot PRs

Pushes with a repo-scoped fine-grained PAT (Dependabot secret) so the
regen commit retriggers CI; GITHUB_TOKEN pushes would leave required
checks stale. Guarded to dependabot[bot] on same-repo branches only.

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

Closes #252

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
)"
gh pr checks --watch
```

Expected: full CI green — every job (build, tests, lint, detekt, CodeQL,
emulator) now resolves dependencies under verification. A red job citing
"Dependency verification failed" means the Task 11 task set missed a
configuration: regenerate with the failing task appended, commit, push.
Post the Task 11 Step 3 tamper-test output as a PR comment.

- [ ] **Step 2: 4-agent review ceremony**, fix, re-green.

- [ ] **Step 3: Squash-merge; verify issue closed; final acceptance sweep**

```bash
gh pr merge --squash --delete-branch
gh issue view 252 --json state --jq .state   # expect CLOSED
```

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

Post a closing comment on #252 summarizing the three merged PRs and any
follow-ups discovered (e.g., first Dependabot cycle observation, PR 3
fallback if PAT declined).

---

## Plan self-review notes (already applied)

- Spec's "add `dependency-review` as a required ruleset check" is realized
  via `ci-success` (Task 3 interface note) — deliberate refinement, stated
  in PR 1's body and `docs/supply-chain.md`, so a docs-only PR is never
  blocked by a check that can't report.
- Spec's release-notes "verify this release" snippet: implemented inline in
  the Publish step (Task 9) rather than a template file — YAGNI.
- CLAUDE.md is deliberately untouched: regen and triage live in
  `docs/supply-chain.md`, which CLAUDE.md-adjacent workflows already
  discover via the architecture-docs convention.
