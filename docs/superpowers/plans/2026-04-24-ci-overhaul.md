# CI Overhaul Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace `.github/workflows/android-build.yml` with a decoupled pair of workflows (`ci.yml` for PR gates, `release.yml` for main-push releases), with parallel jobs, a stable single required check (`ci-success`), and new gates for apkanalyzer (blocking), submodule integrity, and Python pipeline scripts.

**Architecture:** Two new workflow files add parallel jobs feeding a meta-job named `ci-success` that is the only branch-protection required check. A separate `release.yml` asserts `ci-success` passed for the current SHA before building a release APK. Cutover is a two-PR rollout with a manual branch-protection flip in between, because the required-check name changes from `build` → `ci-success` and GitHub does not allow simultaneous rename + required.

**Tech Stack:** GitHub Actions, `actions/setup-java@v4`, `android-actions/setup-android@v3`, `gradle/actions/setup-gradle@v4`, `reactivecircus/android-emulator-runner@v2`, `actions/setup-python@v5`, `actions/github-script@v7`, `gitleaks` v8.18.4, `actionlint` (local only).

**Spec:** `docs/superpowers/specs/2026-04-24-ci-overhaul-design.md`.

---

## Branch layout

- **Current:** spec lives on `docs/ci-overhaul-spec`.
- **PR 1 branch:** `feat/ci-overhaul-phase-1` — adds `ci.yml` and `release.yml`, keeps `android-build.yml`.
- **PR 2 branch:** `feat/ci-overhaul-phase-2` — deletes `android-build.yml`.

This plan document is committed on `docs/ci-overhaul-spec` alongside the spec. The actual workflow files live on the phase branches.

## File changes by phase

| Phase | File | Action |
|---|---|---|
| PR 1 | `.github/workflows/ci.yml` | create |
| PR 1 | `.github/workflows/release.yml` | create |
| PR 1 | `.github/workflows/android-build.yml` | unchanged |
| Manual | branch protection | required check: `build` → `ci-success` |
| PR 2 | `.github/workflows/android-build.yml` | delete |

---

## Task 1: Preflight — verify apkanalyzer doesn't fire on current main

**Why:** Spec flips `apk-analyze` from advisory to blocking. If current main already has an exported component without a permission, this flip breaks main. Verify before touching workflows.

**Files:** none (local verification only).

- [ ] **Step 1: Ensure you're on a clean main**

Run: `git checkout main && git status`
Expected: `nothing to commit, working tree clean`.

- [ ] **Step 2: Build debug APK**

Run: `./gradlew assembleDebug`
Expected: BUILD SUCCESSFUL, `app/build/outputs/apk/debug/app-debug.apk` exists.

- [ ] **Step 3: Locate apkanalyzer**

Run: `find "$ANDROID_HOME/cmdline-tools" -name apkanalyzer -type f | head -1`
Expected: a path like `$ANDROID_HOME/cmdline-tools/latest/bin/apkanalyzer`. If empty, install Android cmdline-tools via `sdkmanager`.

- [ ] **Step 4: Run the manifest check**

Run:
```bash
APKANALYZER=$(find "$ANDROID_HOME/cmdline-tools" -name apkanalyzer -type f | head -1)
APK=app/build/outputs/apk/debug/app-debug.apk
MANIFEST=$("$APKANALYZER" manifest print "$APK")
if echo "$MANIFEST" | grep -qE 'exported="true"' && \
   ! echo "$MANIFEST" | grep -qE 'permission='; then
  echo "FAIL: exported component(s) without permission"
  exit 1
fi
echo "PASS: no exported components without permission"
```
Expected: `PASS`.

If FAIL, stop the plan and fix the exported-component issue in a preceding PR before proceeding. The spec calls this out as a risk.

- [ ] **Step 5: Record result**

No commit. Note in PR 1 body that apkanalyzer ran clean on the base commit.

---

## Task 2: Install `actionlint` locally

**Why:** Workflow YAML errors only surface when GitHub runs the file. `actionlint` catches most mistakes (syntax, bad action references, wrong `needs:`) locally, which saves round-trips.

**Files:** none (local tool).

- [ ] **Step 1: Install actionlint**

Run:
```bash
bash <(curl -sSL https://raw.githubusercontent.com/rhysd/actionlint/main/scripts/download-actionlint.bash)
sudo mv actionlint /usr/local/bin/
actionlint --version
```
Expected: version string like `1.7.x`.

Alternative if the install script is blocked: download from the releases page manually and drop the binary in `/usr/local/bin/`.

- [ ] **Step 2: Smoke-run on the existing workflow**

Run: `actionlint .github/workflows/android-build.yml`
Expected: either zero output (clean) or minor style warnings. If hard errors appear, note them but do not fix — this workflow is being deleted in Phase 2.

---

## Task 3: Create PR 1 branch

**Files:** none (git only).

- [ ] **Step 1: Branch from origin/main**

Run:
```bash
git fetch origin
git checkout -b feat/ci-overhaul-phase-1 origin/main
git status
```
Expected: "On branch feat/ci-overhaul-phase-1", clean.

---

## Task 4: Create `ci.yml` scaffold (triggers, concurrency, permissions)

**Files:**
- Create: `.github/workflows/ci.yml`

- [ ] **Step 1: Write the scaffold**

Create `.github/workflows/ci.yml` with this exact content:

```yaml
name: CI

on:
  pull_request:
    branches: [main]
  push:
    branches: [main]
  workflow_dispatch:

permissions:
  contents: read

concurrency:
  group: ci-${{ github.ref }}
  cancel-in-progress: ${{ github.event_name == 'pull_request' }}

jobs:
  # Jobs added in subsequent tasks.
  placeholder:
    runs-on: ubuntu-latest
    steps:
      - run: echo "scaffold"
```

The `placeholder` job keeps the workflow valid YAML until real jobs land. It is removed in the last `ci.yml` task.

- [ ] **Step 2: Lint the scaffold**

Run: `actionlint .github/workflows/ci.yml`
Expected: no errors.

- [ ] **Step 3: Commit**

Run:
```bash
git add .github/workflows/ci.yml
git commit -m "ci: add ci.yml scaffold (triggers, concurrency, permissions)"
```

---

## Task 5: Add `build-and-test` job

**Files:**
- Modify: `.github/workflows/ci.yml` (add job)

- [ ] **Step 1: Replace `placeholder` with `build-and-test`**

In `.github/workflows/ci.yml`, replace the `jobs:` block contents so the file ends with:

```yaml
jobs:
  build-and-test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
          submodules: true
      - uses: actions/setup-java@v4
        with:
          java-version: '21'
          distribution: 'temurin'
          cache: 'gradle'
      - uses: android-actions/setup-android@v3
      - uses: gradle/actions/setup-gradle@v4
        with:
          cache-read-only: ${{ github.ref != 'refs/heads/main' }}
      - name: Build debug APK + run unit tests
        run: ./gradlew assembleDebug test --stacktrace
      - name: Upload debug APK
        uses: actions/upload-artifact@v4
        if: always()
        with:
          name: app-debug
          path: app/build/outputs/apk/debug/app-debug.apk
          retention-days: 14
          if-no-files-found: warn
      - name: Upload unit test reports
        uses: actions/upload-artifact@v4
        if: always()
        with:
          name: unit-test-reports
          path: app/build/reports/tests/
          retention-days: 14
          if-no-files-found: warn
```

- [ ] **Step 2: Lint**

Run: `actionlint .github/workflows/ci.yml`
Expected: no errors.

- [ ] **Step 3: Commit**

```bash
git add .github/workflows/ci.yml
git commit -m "ci: add build-and-test job (compile + unit + schema + Gate4)"
```

---

## Task 6: Add `lint-and-detekt` job

**Files:**
- Modify: `.github/workflows/ci.yml`

- [ ] **Step 1: Append the job below `build-and-test`**

Insert inside `jobs:` (after `build-and-test`):

```yaml
  lint-and-detekt:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          submodules: true
      - uses: actions/setup-java@v4
        with:
          java-version: '21'
          distribution: 'temurin'
          cache: 'gradle'
      - uses: android-actions/setup-android@v3
      - uses: gradle/actions/setup-gradle@v4
        with:
          cache-read-only: ${{ github.ref != 'refs/heads/main' }}
      - name: Lint + detekt
        run: ./gradlew lintDebug detekt --stacktrace
      - name: Upload lint report
        uses: actions/upload-artifact@v4
        if: always()
        with:
          name: lint-report
          path: app/build/reports/lint-results-debug.html
          retention-days: 14
          if-no-files-found: warn
      - name: Upload detekt report
        uses: actions/upload-artifact@v4
        if: always()
        with:
          name: detekt-report
          path: app/build/reports/detekt/
          retention-days: 14
          if-no-files-found: warn
```

Note: no `needs:` — this runs in parallel with `build-and-test`. The second Gradle warm-up is intentional wall-clock optimization.

- [ ] **Step 2: Lint**

Run: `actionlint .github/workflows/ci.yml`
Expected: no errors.

- [ ] **Step 3: Commit**

```bash
git add .github/workflows/ci.yml
git commit -m "ci: add lint-and-detekt parallel job"
```

---

## Task 7: Add `apk-analyze` job (blocking)

**Files:**
- Modify: `.github/workflows/ci.yml`

- [ ] **Step 1: Append the job**

Insert inside `jobs:` (after `lint-and-detekt`):

```yaml
  apk-analyze:
    runs-on: ubuntu-latest
    needs: build-and-test
    steps:
      - uses: android-actions/setup-android@v3
      - name: Download debug APK
        uses: actions/download-artifact@v4
        with:
          name: app-debug
          path: apk/
      - name: Check manifest for exported components without permission
        run: |
          set -euo pipefail
          APKANALYZER=$(find "$ANDROID_HOME/cmdline-tools" -name apkanalyzer -type f | head -1)
          if [ -z "$APKANALYZER" ]; then
            echo "apkanalyzer not found under $ANDROID_HOME/cmdline-tools" >&2
            exit 1
          fi
          APK=apk/app-debug.apk
          MANIFEST=$("$APKANALYZER" manifest print "$APK")
          if echo "$MANIFEST" | grep -qE 'exported="true"' && \
             ! echo "$MANIFEST" | grep -qE 'permission='; then
            echo "FAIL: exported component(s) without permission" >&2
            echo "$MANIFEST"
            exit 1
          fi
          echo "PASS: no exported components without permission"
```

Critical change vs `android-build.yml`: exits with non-zero on failure. Previously the script just echoed "WARNING". `set -euo pipefail` ensures apkanalyzer failures also fail the job.

- [ ] **Step 2: Lint**

Run: `actionlint .github/workflows/ci.yml`
Expected: no errors.

- [ ] **Step 3: Commit**

```bash
git add .github/workflows/ci.yml
git commit -m "ci: add apk-analyze job (blocking — flipped from advisory)"
```

---

## Task 8: Add `secret-scan` job

**Files:**
- Modify: `.github/workflows/ci.yml`

- [ ] **Step 1: Append the job**

Insert inside `jobs:`:

```yaml
  secret-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - name: Install gitleaks
        run: |
          set -euo pipefail
          GITLEAKS_VERSION=8.18.4
          curl -sSfL "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz" \
            | tar -xz gitleaks
          sudo mv gitleaks /usr/local/bin/
      - name: Scan for secrets
        run: gitleaks detect --source . --verbose
```

Pinned to v8.18.4 matching commit `7ff121f` — earlier versions had a tar-extraction bug.

- [ ] **Step 2: Lint**

Run: `actionlint .github/workflows/ci.yml`
Expected: no errors.

- [ ] **Step 3: Commit**

```bash
git add .github/workflows/ci.yml
git commit -m "ci: add secret-scan job (gitleaks v8.18.4)"
```

---

## Task 9: Add `submodule-check` job

**Files:**
- Modify: `.github/workflows/ci.yml`

- [ ] **Step 1: Append the job**

```yaml
  submodule-check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          submodules: true
      - name: Verify submodule HEAD is reachable from upstream main
        working-directory: third-party/android-sigma-rules
        run: |
          set -euo pipefail
          git fetch origin main
          HEAD_SHA=$(git rev-parse HEAD)
          if git merge-base --is-ancestor "$HEAD_SHA" origin/main; then
            echo "PASS: submodule HEAD $HEAD_SHA is reachable from upstream main"
          else
            echo "FAIL: submodule HEAD $HEAD_SHA is NOT reachable from upstream main" >&2
            echo "Upstream may have force-pushed, or the submodule points at a dangling commit." >&2
            exit 1
          fi
```

- [ ] **Step 2: Lint**

Run: `actionlint .github/workflows/ci.yml`
Expected: no errors.

- [ ] **Step 3: Commit**

```bash
git add .github/workflows/ci.yml
git commit -m "ci: add submodule-check job (submodule HEAD reachable from upstream main)"
```

---

## Task 10: Add `python-pipeline` job

**Files:**
- Modify: `.github/workflows/ci.yml`

Important discovery from preflight: `scripts/merge-ioc-data.py` has no `--dry-run` flag; invoking it without args clones from the network and mutates `app/src/main/` IOC files. The spec's placeholder "dry-run" was replaced with a `--help` smoke + `py_compile`.

- [ ] **Step 1: Append the job**

```yaml
  python-pipeline:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.x'
      - name: Syntax-check tracked Python scripts
        run: |
          set -euo pipefail
          mapfile -t PY_FILES < <(git ls-files 'scripts/*.py')
          if [ ${#PY_FILES[@]} -eq 0 ]; then
            echo "No tracked Python scripts found"
            exit 0
          fi
          python3 -m py_compile "${PY_FILES[@]}"
          echo "PASS: ${#PY_FILES[@]} script(s) compile"
      - name: Smoke-test merge-ioc-data.py arg parsing
        run: python3 scripts/merge-ioc-data.py --help
      - name: Smoke-test generate_known_good_apps.py arg parsing
        run: python3 scripts/generate_known_good_apps.py --help || true
```

The `|| true` on `generate_known_good_apps.py` is defensive: it's a network-dependent refresh script; `--help` may or may not exist. The `py_compile` step is the real syntax gate.

- [ ] **Step 2: Lint**

Run: `actionlint .github/workflows/ci.yml`
Expected: no errors.

- [ ] **Step 3: Commit**

```bash
git add .github/workflows/ci.yml
git commit -m "ci: add python-pipeline job (py_compile + argparse smoke)"
```

---

## Task 11: Add `instrumented` job (advisory)

**Files:**
- Modify: `.github/workflows/ci.yml`

- [ ] **Step 1: Append the job**

```yaml
  instrumented:
    runs-on: ubuntu-latest
    if: github.event_name == 'pull_request'
    continue-on-error: true
    steps:
      - uses: actions/checkout@v4
        with:
          submodules: true
      - uses: actions/setup-java@v4
        with:
          java-version: '21'
          distribution: 'temurin'
          cache: 'gradle'
      - uses: gradle/actions/setup-gradle@v4
        with:
          cache-read-only: ${{ github.ref != 'refs/heads/main' }}
      - name: Enable KVM for hardware acceleration
        run: |
          echo 'KERNEL=="kvm", GROUP="kvm", MODE="0666", OPTIONS+="static_node=kvm"' \
            | sudo tee /etc/udev/rules.d/99-kvm4all.rules
          sudo udevadm control --reload-rules
          sudo udevadm trigger --name-match=kvm
      - name: Run instrumented tests on emulator
        uses: reactivecircus/android-emulator-runner@v2
        with:
          api-level: 34
          arch: x86_64
          profile: pixel_6
          force-avd-creation: false
          script: ./gradlew connectedDebugAndroidTest --stacktrace
      - name: Upload instrumented test report
        uses: actions/upload-artifact@v4
        if: always()
        with:
          name: instrumented-test-report
          path: app/build/reports/androidTests/connected/
          retention-days: 14
          if-no-files-found: warn
```

`continue-on-error: true` makes this advisory — a failure shows up in the PR but does not block `ci-success`.

- [ ] **Step 2: Lint**

Run: `actionlint .github/workflows/ci.yml`
Expected: no errors.

- [ ] **Step 3: Commit**

```bash
git add .github/workflows/ci.yml
git commit -m "ci: add instrumented job (PR-only, advisory)"
```

---

## Task 12: Add `ci-success` meta-job and remove scaffold

**Files:**
- Modify: `.github/workflows/ci.yml`

- [ ] **Step 1: Append the meta-job and delete `placeholder`**

Append inside `jobs:`:

```yaml
  ci-success:
    runs-on: ubuntu-latest
    if: always()
    needs:
      - build-and-test
      - lint-and-detekt
      - apk-analyze
      - secret-scan
      - submodule-check
      - python-pipeline
    steps:
      - name: Verify all required gates passed (belt-and-braces)
        run: |
          if [[ "${{ contains(needs.*.result, 'failure') || contains(needs.*.result, 'cancelled') || contains(needs.*.result, 'skipped') }}" == "true" ]]; then
            echo "A required gate failed, was cancelled, or was skipped" >&2
            echo "needs.build-and-test.result:   ${{ needs.build-and-test.result }}" >&2
            echo "needs.lint-and-detekt.result:  ${{ needs.lint-and-detekt.result }}" >&2
            echo "needs.apk-analyze.result:      ${{ needs.apk-analyze.result }}" >&2
            echo "needs.secret-scan.result:      ${{ needs.secret-scan.result }}" >&2
            echo "needs.submodule-check.result:  ${{ needs.submodule-check.result }}" >&2
            echo "needs.python-pipeline.result:  ${{ needs.python-pipeline.result }}" >&2
            exit 1
          fi
          echo "All required gates passed"
```

Delete the `placeholder` job block added in Task 4.

`if: always()` + explicit `needs.*.result` check is belt-and-braces: if a future change adds path filters that skip a gate, `ci-success` fails loudly rather than silently passing a half-tested PR. `instrumented` is intentionally NOT in `needs:`.

- [ ] **Step 2: Lint**

Run: `actionlint .github/workflows/ci.yml`
Expected: no errors.

- [ ] **Step 3: Verify all 8 jobs are defined**

Run:
```bash
python3 -c "
import yaml
with open('.github/workflows/ci.yml') as f:
    data = yaml.safe_load(f)
jobs = list(data['jobs'].keys())
expected = ['build-and-test', 'lint-and-detekt', 'apk-analyze', 'secret-scan',
            'submodule-check', 'python-pipeline', 'instrumented', 'ci-success']
print('Defined:', jobs)
print('Missing:', [j for j in expected if j not in jobs])
print('Extra:', [j for j in jobs if j not in expected])
assert set(jobs) == set(expected), 'Job list mismatch'
print('OK')
"
```
Expected: `OK` with no missing/extra.

- [ ] **Step 4: Commit**

```bash
git add .github/workflows/ci.yml
git commit -m "ci: add ci-success meta-job and remove scaffold"
```

---

## Task 13: Create `release.yml`

**Files:**
- Create: `.github/workflows/release.yml`

- [ ] **Step 1: Write the full file**

Create `.github/workflows/release.yml`:

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

permissions:
  contents: write    # gh release create
  actions: read      # poll ci-success
  checks: read       # poll ci-success

concurrency:
  group: release
  cancel-in-progress: false

jobs:
  release:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
          submodules: true
      - uses: actions/setup-java@v4
        with:
          java-version: '21'
          distribution: 'temurin'
          cache: 'gradle'
      - uses: android-actions/setup-android@v3
      - uses: gradle/actions/setup-gradle@v4
      - name: Wait for ci-success on this SHA
        uses: actions/github-script@v7
        with:
          script: |
            const sha = context.sha;
            // 25 min accommodates cold-cache ci.yml runs (Gradle + Android SDK +
            // unit tests + lint + detekt + emulator queue). Serial current runtime
            // is ~5 min warm; cold cache can hit ~8-10 min. 25 leaves slack without
            // burning runner minutes on a wedged CI.
            const timeoutMs = 25 * 60 * 1000;
            const pollMs = 30 * 1000;
            const deadline = Date.now() + timeoutMs;
            core.info(`Polling ci-success for ${sha}`);
            while (Date.now() < deadline) {
              const { data } = await github.rest.checks.listForRef({
                owner: context.repo.owner,
                repo: context.repo.repo,
                ref: sha,
                check_name: 'ci-success',
              });
              const runs = data.check_runs;
              if (runs.length === 0) {
                core.info('ci-success not reported yet; waiting...');
              } else {
                const run = runs[0];
                core.info(`ci-success status=${run.status} conclusion=${run.conclusion}`);
                if (run.status === 'completed') {
                  if (run.conclusion === 'success') {
                    core.info('ci-success passed; proceeding to build release');
                    return;
                  }
                  core.setFailed(`ci-success concluded '${run.conclusion}'; aborting release`);
                  return;
                }
              }
              await new Promise(r => setTimeout(r, pollMs));
            }
            core.setFailed('Timed out waiting for ci-success');
      - name: Build debug APK
        run: ./gradlew assembleDebug --stacktrace
      - name: Compute version and release notes
        id: version
        run: |
          set -euo pipefail
          BASE_VERSION=$(grep 'versionName' app/build.gradle.kts | head -1 | sed 's/.*"\([0-9.]*\)\..*/\1/')
          if [ -z "$BASE_VERSION" ]; then
            echo "ERROR: failed to extract BASE_VERSION from app/build.gradle.kts" >&2
            grep 'versionName' app/build.gradle.kts >&2
            exit 1
          fi
          BUILD=$(git rev-list --count HEAD)
          VERSION="${BASE_VERSION}.${BUILD}"
          TAG="v${VERSION}"
          PREV_TAG=$(git describe --tags --abbrev=0 HEAD^ 2>/dev/null || echo "")
          if [ -n "$PREV_TAG" ]; then
            CHANGES=$(git log "$PREV_TAG"..HEAD --pretty=format:"- %s" --no-merges)
          else
            CHANGES=$(git log -20 --pretty=format:"- %s" --no-merges)
          fi
          printf "## What's Changed\n\n%s\n\n**Full changelog**: https://github.com/%s/compare/%s...%s\n" \
            "$CHANGES" "${{ github.repository }}" "${PREV_TAG:-v0.0.0}" "$TAG" > /tmp/release-notes.md
          echo "tag=$TAG" >> "$GITHUB_OUTPUT"
      - name: Publish release
        env:
          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        run: |
          gh release create "${{ steps.version.outputs.tag }}" \
            app/build/outputs/apk/debug/app-debug.apk \
            --title "AndroDR ${{ steps.version.outputs.tag }}" \
            --notes-file /tmp/release-notes.md
```

Version and release-notes logic is ported verbatim from `android-build.yml:89-107`.

- [ ] **Step 2: Lint**

Run: `actionlint .github/workflows/release.yml`
Expected: no errors. (A warning about the `sed` regex in the shell heredoc is OK.)

- [ ] **Step 3: Commit**

```bash
git add .github/workflows/release.yml
git commit -m "ci: add release.yml (decoupled from PR gates, polls ci-success)"
```

---

## Task 14: Push PR 1 branch and observe first CI run

**Files:** none (git push).

- [ ] **Step 1: Push**

Run:
```bash
git push -u origin feat/ci-overhaul-phase-1
```
Expected: branch published, URL in output.

- [ ] **Step 2: Open a draft PR**

Run:
```bash
gh pr create --draft \
  --title "ci: overhaul to ci.yml + release.yml (phase 1)" \
  --body "$(cat <<'EOF'
## Summary
- Adds `.github/workflows/ci.yml` with parallel PR gates and a `ci-success` meta-job
- Adds `.github/workflows/release.yml` decoupled from PR gates
- Keeps `.github/workflows/android-build.yml` unchanged (deleted in PR 2)

Design: `docs/superpowers/specs/2026-04-24-ci-overhaul-design.md`
Plan: `docs/superpowers/plans/2026-04-24-ci-overhaul.md`

## Test plan
- [ ] All three workflows run on this PR
- [ ] `ci-success` reports green
- [ ] `android-build.yml` still reports green (sanity)
- [ ] `release.yml` does NOT trigger (no push to main yet)

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
)"
```

- [ ] **Step 3: Wait for all workflows to finish**

Run: `gh pr checks --watch`
Expected: `ci-success` and `build` (from old workflow) both green. `release` does not appear (not triggered by PR events).

- [ ] **Step 4: Inspect ci.yml run timings**

Run:
```bash
RUN_ID=$(gh run list --workflow=ci.yml --limit 1 --json databaseId --jq '.[0].databaseId')
gh run view "$RUN_ID" --json jobs --jq '.jobs[] | {name, conclusion, startedAt, completedAt}'
```
Expected: all jobs conclusion `success` (or `skipped` for `ci-success` if a dependency failed). Note wall-clock of slowest job; target < 3 min after cache warm-up.

- [ ] **Step 5: If any job fails, diagnose and fix**

For a job failure, read the logs (`gh run view "$RUN_ID" --log-failed`), fix in a new commit, force-push, re-observe. Common issues:
- `apk-analyze`: exported-component regression → fix in this PR, document in PR body.
- `submodule-check`: submodule points at non-upstream SHA → `git submodule update` locally, commit.
- `python-pipeline`: syntax error in a script that was added after CI was tuned → fix the script.

---

## Task 15: Validate deliberate-break scenarios (optional but recommended)

**Why:** Confirm each new gate actually catches the failure mode it's meant to catch. Done on throwaway commits of `feat/ci-overhaul-phase-1` — revert each after validation.

**Files:** temporary, all reverted.

- [ ] **Step 1: Secret-scan break**

Assemble the AWS-key-shaped token at runtime so this plan document itself
does not contain a literal AKIA-prefixed token that gitleaks would flag
when this docs PR runs through CI.

```bash
KEY="AKIA"$(printf '%s' "IOSFODNN7EXAMPLE")
echo "AWS_SECRET_ACCESS_KEY=${KEY}" > .env.example-secret
git add .env.example-secret
git commit -m "test: intentional secret (DO NOT MERGE)"
git push
```
Expected: `secret-scan` fails; `ci-success` fails.
Revert:
```bash
git reset --hard HEAD~1
git push --force-with-lease
```

- [ ] **Step 2: Submodule-check break**

Create a local-only submodule commit (not reachable from upstream `main`) and point the outer repo at it:

```bash
cd third-party/android-sigma-rules
git commit --allow-empty -m "local-only test commit (DO NOT MERGE)"
cd ../..
git add third-party/android-sigma-rules
git commit -m "test: point submodule at non-upstream commit (DO NOT MERGE)"
git push
```
Expected: `submodule-check` fails with "NOT reachable from upstream main".

Revert (outer repo):
```bash
git reset --hard HEAD~1
git push --force-with-lease
```
Revert (submodule working directory — safe to discard the empty test commit):
```bash
cd third-party/android-sigma-rules
git fetch origin main
git reset --hard origin/main
cd ../..
```

- [ ] **Step 3: Python-pipeline break**

```bash
echo "syntax error (" >> scripts/merge-ioc-data.py
git add scripts/merge-ioc-data.py
git commit -m "test: syntax error in script (DO NOT MERGE)"
git push
```
Expected: `python-pipeline` fails at `py_compile`.
Revert:
```bash
git reset --hard HEAD~1
git push --force-with-lease
```

- [ ] **Step 4: Confirm current branch is green**

Run: `gh pr checks`
Expected: `ci-success` green, `build` (old) green.

Skip this task entirely if PR-review feedback is faster than deliberate-break testing. The unit tests in `build-and-test` already exercise schema cross-check and Gate 4 fixtures.

---

## Task 16: Mark PR 1 ready for review and merge

- [ ] **Step 1: Mark ready**

Run: `gh pr ready`
Expected: PR transitions from draft to ready.

- [ ] **Step 2: Verify `build` (required check from old workflow) is green**

Run: `gh pr checks | grep -E '^build\s'`
Expected: `build  pass`.

- [ ] **Step 3: Merge**

Merge via the workflow your team uses (admin-merge per user preference, or wait for review). After merge, return to local `main`:
```bash
git checkout main
git pull origin main
```

---

## Task 17: Verify post-merge behavior on main

**Why:** The PR 1 merge commit is the first real test of `release.yml` and the `ci-success` wait logic. PR 1 touches `.github/workflows/*.yml` (non-docs path), so `release.yml` WILL trigger on the merge and attempt to publish a release. That's the test.

Expected sequence on the PR 1 merge commit SHA:
1. `ci.yml` starts immediately → publishes `ci-success` check-run.
2. `release.yml` starts in parallel → its `Wait for ci-success` step polls until step 1 finishes.
3. Once `ci-success` is green, `release.yml` builds the APK and publishes a release tag.
4. Old `android-build.yml` also runs (still present) and should pass.

- [ ] **Step 1: Observe `ci.yml` run on main**

Run: `gh run list --workflow=ci.yml --branch=main --limit 1`
Expected: a run for the merge commit, status `completed`, conclusion `success`.

- [ ] **Step 2: Observe `release.yml` run on main**

Run: `gh run list --workflow=release.yml --branch=main --limit 1`
Expected: a run for the same merge commit. It should succeed and produce a release. (It WILL trigger — PR 1 is not docs-only.)

Check the poll log:
```bash
RUN_ID=$(gh run list --workflow=release.yml --branch=main --limit 1 --json databaseId --jq '.[0].databaseId')
gh run view "$RUN_ID" --log | grep -E "Polling|not reported|passed|concluded|Timed out"
```
Expected: a sequence like "Polling → not reported yet; waiting... → status=completed conclusion=success → passed; proceeding to build release". A few minutes of "not reported yet" is normal — this is the poll racing ci.yml startup on the same SHA.

- [ ] **Step 3: Verify release was published**

Run: `gh release list --limit 1`
Expected: a tag matching the version format `v0.9.0.XXX` where XXX equals `git rev-list --count HEAD` on the merge commit.

- [ ] **Step 4: If `release.yml` fails**

Diagnose by log, in order of likelihood:

1. **Poll timed out at 25 min.** ci.yml genuinely ran longer than 25 min — cold cache + queued runners. Inspect `gh run view --log` on the ci.yml run. Fix: either raise the timeout in `release.yml` (edit the `timeoutMs` constant) OR re-trigger release via `gh workflow run release.yml` once ci.yml has finished.
2. **Poll concluded with `failure`.** A required gate failed. Fix ci.yml issue first; release is blocked by design.
3. **`gh release create` failed with 403 / permissions.** Most likely token-scope regression after the 2026-04 shadowban recovery. Check repo Settings → Actions → General → Workflow permissions. Must be "Read and write permissions". Save and re-run via `gh workflow run release.yml`.
4. **`gh release create` failed with "tag already exists".** A previous release consumed that tag. Delete the stale tag with `gh release delete v0.9.0.XXX --cleanup-tag` and re-run the workflow.

- [ ] **Step 5: Verify old workflow still succeeds**

Run: `gh run list --workflow=android-build.yml --branch=main --limit 1`
Expected: `success`. Both workflows running in parallel on main confirms they don't interfere. This is the last time `android-build.yml` needs to pass — it's deleted in PR 2.

---

## Task 18: Flip branch protection to `ci-success`

**Why:** Required check name changes from `build` → `ci-success`. One-time admin action between PR 1 and PR 2.

**Files:** none (GitHub admin action).

- [ ] **Step 1: Inspect full protection (not just required_status_checks) as a baseline**

Run:
```bash
gh api repos/yasirhamza/AndroDR/branches/main/protection > /tmp/protection-before.json
cat /tmp/protection-before.json | jq '.required_status_checks'
```
Expected: JSON including `"contexts": ["build"]`. Save `/tmp/protection-before.json` — the rollback in Step 4 uses it.

- [ ] **Step 2: Update to `ci-success` via JSON body**

The endpoint takes a JSON body, not form-encoded. Use `--input` with a heredoc:

```bash
gh api \
  -X PATCH \
  repos/yasirhamza/AndroDR/branches/main/protection/required_status_checks \
  --input - <<'JSON'
{
  "strict": true,
  "contexts": ["ci-success"]
}
JSON
```

Expected: JSON response with `"contexts": ["ci-success"]` and `"strict": true`.

If the API call fails with 422 or similar, fall back to the web UI: repo Settings → Branches → `main` → Edit → Require status checks → remove `build`, add `ci-success`.

- [ ] **Step 3: Verify the change and confirm other protection fields are intact**

Run:
```bash
gh api repos/yasirhamza/AndroDR/branches/main/protection/required_status_checks
# And diff full protection vs baseline:
gh api repos/yasirhamza/AndroDR/branches/main/protection > /tmp/protection-after.json
diff <(jq -S . /tmp/protection-before.json) <(jq -S . /tmp/protection-after.json) || true
```
Expected:
- `required_status_checks.contexts` = `["ci-success"]`.
- Diff only touches `required_status_checks`; other fields (`enforce_admins`, `required_pull_request_reviews`, etc.) unchanged.

- [ ] **Step 4: If something other than `required_status_checks` changed, restore from baseline**

Rare but possible if the PATCH silently touches unrelated fields. Replay full protection from baseline:

```bash
gh api -X PUT repos/yasirhamza/AndroDR/branches/main/protection --input /tmp/protection-before.json
# Then redo Step 2.
```

---

## Task 19: Create PR 2 branch and delete old workflow

**Files:**
- Delete: `.github/workflows/android-build.yml`

- [ ] **Step 1: Branch from latest main**

```bash
git fetch origin
git checkout -b feat/ci-overhaul-phase-2 origin/main
```

- [ ] **Step 2: Delete the old workflow**

```bash
git rm .github/workflows/android-build.yml
```

- [ ] **Step 3: Commit**

```bash
git commit -m "ci: remove android-build.yml (replaced by ci.yml + release.yml)"
```

- [ ] **Step 4: Push**

```bash
git push -u origin feat/ci-overhaul-phase-2
```

---

## Task 20: Open PR 2, verify ci-success is the only required check, merge

- [ ] **Step 1: Open PR**

```bash
gh pr create \
  --title "ci: remove android-build.yml (overhaul phase 2)" \
  --body "$(cat <<'EOF'
## Summary
- Deletes `.github/workflows/android-build.yml` — replaced by `ci.yml` and `release.yml` in phase 1 (#PR1).
- Required status check is `ci-success`; this PR's only required check will be that one.

## Test plan
- [ ] `ci-success` reports green
- [ ] No `build` check is expected (old workflow deleted)
- [ ] PR is mergeable once `ci-success` is green

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
)"
```
Replace `#PR1` with the actual PR 1 number once known.

- [ ] **Step 2: Wait for checks**

Run: `gh pr checks --watch`
Expected: only `ci-success` and optional `instrumented` (advisory). No `build` check.

- [ ] **Step 3: If `build` still appears as pending**

This means branch protection wasn't flipped. Return to Task 18. Do NOT merge while `build` is pending and required.

- [ ] **Step 4: Merge**

Once `ci-success` is green and `build` is absent, merge.

- [ ] **Step 5: Post-merge sanity**

Run: `gh run list --branch=main --limit 5`
Expected: only `ci.yml` and `release.yml` runs on main. `android-build.yml` is gone.

---

## Task 21: Ship spec + plan as their own docs PR

**Why:** Paper trail. Spec + plan are already committed on `docs/ci-overhaul-spec` and can merge independently of the implementation PRs.

**Files:** already committed during plan-writing (spec + this plan doc).

- [ ] **Step 1: Switch to the spec branch**

```bash
git checkout docs/ci-overhaul-spec
git log --oneline origin/main..HEAD
```
Expected: two commits — one for the spec, one for this plan.

- [ ] **Step 2: Push and open the docs PR**

```bash
git push -u origin docs/ci-overhaul-spec
gh pr create --title "docs: CI overhaul spec + plan" \
  --body "Design spec and implementation plan for the CI overhaul. No code changes — documentation only. Implementation lands in \`feat/ci-overhaul-phase-1\` and \`feat/ci-overhaul-phase-2\`."
```

This PR can merge before, after, or in parallel with PR 1. The implementation plan references the spec but neither workflow file needs the docs to be merged first.

---

## Success criteria (from the spec, re-stated)

After Task 20 completes:

1. PR wall-clock on warm cache < 3 min.
2. No docs-only merges appear in the release list after rollout.
3. Branch protection references a single check (`ci-success`).
4. An exported component without a permission fails a PR (verified in Task 15 Step 1 if run, or by the next real PR).
5. A syntax error in any `scripts/*.py` fails a PR.
