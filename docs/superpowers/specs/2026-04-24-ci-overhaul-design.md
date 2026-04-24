# CI Overhaul Design

**Date:** 2026-04-24
**Author:** yasirhamza (with Claude)
**Status:** Draft — pending review

## Context

AndroDR's CI (`.github/workflows/android-build.yml`) was written when the
project was a single-module Android app. It has since grown a git submodule
(`third-party/android-sigma-rules`), a SIGMA rule schema cross-check test,
a Gate 4 fixture harness, an IOC pipeline (`scripts/merge-ioc-data.py`),
adversary fixtures, and a rule-driven detection architecture. None of these
new surfaces are gated explicitly; some are covered incidentally by
`./gradlew test`, others not at all.

A recent GitHub account shadowban (ticket 4297771, lifted 2026-04-24)
surfaced a second concern: release publishing and token-scoped automation
were invisible during the outage. Coming out of the outage is a natural
point to harden the release path and decouple it from PR gates so one
broken gate never again silently blocks a release.

## Goals

1. **Speed** — parallel PR gates; PR feedback < current ~5 min serial runtime.
2. **Coverage** — explicit gates for every surface: Kotlin build, unit tests,
   lint, detekt, apkanalyzer, secret scan, submodule integrity, Python pipeline.
3. **Correctness / trust** — `apkanalyzer` flips from advisory to blocking
   (it has been "Phase 1 advisory" since 2026-03). Instrumented tests become
   advisory (flaky, slow, small coverage slice).
4. **Operational hygiene** — decouple release from PR gates; skip *release*
   on docs-only changes; add `workflow_dispatch`; stable single required
   check for branch protection.

## Non-goals

- **No new scheduled runs.** Weekly crons rejected — `/update-rules` skill
  covers pipeline refreshes interactively; the submodule is intentionally
  pinned (see "Submodule update direction" in `CLAUDE.md`). Automation that
  bumps the submodule on a schedule fights the design.
- **No Dependabot changes.** Current monthly-grouped config is already
  tuned for inbox quietness.
- **No test-adversary / emulator scenario coverage.** Out of scope — those
  fixtures are run manually during harness work, not in CI.
- **No reusable workflows / composite actions.** Two workflow files is not
  enough duplication to justify the indirection.

## File structure

```
.github/
  workflows/
    ci.yml           # PR gates + main push (parallel jobs)
    release.yml      # main push (auto-release) + workflow_dispatch
  dependabot.yml     # unchanged
```

Deletes: `.github/workflows/android-build.yml`.

## ci.yml — PR gates

### Triggers

- `pull_request` targeting `main`
- `push` to `main`
- `workflow_dispatch`

### Paths-ignore

**Not used for PR triggers.** If `paths-ignore` at the workflow level causes
ci.yml to skip on docs-only PRs, `ci-success` never reports, and branch
protection blocks the merge. GitHub has no per-path exception for required
status checks.

Two options were considered to avoid this:

1. **Path filtering inside jobs** (dorny/paths-filter + `if:` conditions).
   Complex; every job needs a conditional wrapper and `ci-success` needs
   a custom aggregator that treats "skipped" as pass.
2. **Just run CI on all PRs.** A docs-only PR consumes ~3 min of CI; docs
   PRs are rare; the simplicity wins.

Going with option 2. The path filter lives on `release.yml`'s push trigger
only — that's where the "no wasted version number on docs" behavior matters.

### Concurrency

```yaml
concurrency:
  group: ci-${{ github.ref }}
  cancel-in-progress: ${{ github.event_name == 'pull_request' }}
```

PRs cancel superseded runs on new pushes. Main never cancels — every
main commit gets a complete CI record.

### Shared setup (used by every job that invokes Gradle)

```yaml
- uses: actions/checkout@v4
  with:
    fetch-depth: 0          # needed for versionCode (git rev-list --count)
    submodules: true        # needed for rule-schema cross-check
- uses: actions/setup-java@v4
  with:
    java-version: '21'
    distribution: 'temurin'
    cache: 'gradle'
- uses: android-actions/setup-android@v3
- uses: gradle/actions/setup-gradle@v4
  with:
    cache-read-only: ${{ github.ref != 'refs/heads/main' }}
```

`cache-read-only` on non-main prevents PR-branch cache poisoning and
keeps the cache bucket small.

### Jobs

#### `build-and-test`

- Runs: `./gradlew assembleDebug test --stacktrace`
- Combines compile, unit test, schema cross-check (`BundledRulesSchemaCrossCheckTest`),
  and Gate 4 fixture harness (`GateFourFixtureTest`) in one Gradle invocation
  to share JVM warmup.
- Uploads: `app/build/outputs/apk/debug/app-debug.apk` (retention 14d),
  `app/build/reports/tests/` (retention 14d, if-no-files-found: warn).
- Blocking.

#### `lint-and-detekt`

- Parallel to `build-and-test` (own Gradle cache warm-up, ~30s overlap).
- Runs: `./gradlew lintDebug detekt --stacktrace`
- Uploads: `app/build/reports/lint-results-debug.html`,
  `app/build/reports/detekt/` (both retention 14d).
- Blocking.

Trade-off: doubles the Gradle startup cost compared to merging into one
job, but total wall-clock is faster because this job runs in parallel.
CPU-seconds is cheaper than engineer wall-clock.

#### `apk-analyze`

- `needs: build-and-test`
- Downloads the `app-debug.apk` artifact.
- Runs the apkanalyzer check currently in `android-build.yml`:
  manifest scan for exported components without permissions.
- **Blocking** (flipped from advisory). The "Phase 1 advisory" note was
  dated 2026-03; we're past it.

#### `secret-scan`

- Parallel, independent, no Gradle.
- Installs gitleaks pinned v8.18.4 (matches current).
- `gitleaks detect --source . --verbose`.
- Blocking. ~30s.

#### `submodule-check`

- Parallel, independent, no Gradle.
- Verifies `third-party/android-sigma-rules` HEAD is a commit reachable
  from upstream `main` (not a dangling/rewritten SHA):
  ```bash
  cd third-party/android-sigma-rules
  git fetch origin main
  git merge-base --is-ancestor HEAD origin/main
  ```
- Blocking. ~20s.
- Purpose: catches the failure mode where someone's local submodule
  points to a force-pushed-away commit and the build still works locally
  from a stale clone.

#### `python-pipeline`

- Parallel, independent, `actions/setup-python@v5`.
- Runs:
  - `python3 -m py_compile $(git ls-files 'scripts/*.py')` — syntax gate.
  - `python3 scripts/merge-ioc-data.py --dry-run` if the script supports
    `--dry-run`; else a `--help` smoke call. Confirmed during implementation
    (not during design).
- Blocking. ~1 min.
- Purpose: the IOC pipeline scripts are real production code, not dev tools.
  They fail silently today if someone breaks them.

#### `instrumented`

- `pull_request` only.
- `continue-on-error: true` — advisory.
- Uses `reactivecircus/android-emulator-runner@v2` (API 34, x86_64, pixel_6).
- `force-avd-creation: false` to enable AVD snapshot cache.
- Runs `./gradlew connectedDebugAndroidTest --stacktrace`.
- Uploads `app/build/reports/androidTests/connected/` (retention 14d).
- Does NOT contribute to `ci-success`.

Trade-off: losing instrumented tests as a blocking gate accepts the
risk that UI-layer regressions slip to main. Mitigation: the test still
runs on every PR, produces reports, and any engineer can look at the
artifact. The upside is PR merges are no longer blocked by a 10-minute
emulator run that fails for emulator-setup reasons more often than
for real regressions.

#### `ci-success` (meta)

- `needs: [build-and-test, lint-and-detekt, apk-analyze, secret-scan,
  submodule-check, python-pipeline]`
- Runs a trivial step (`echo "All required gates passed"`).
- Purpose: **single stable name for branch protection**. Job graph
  reshapes without touching branch protection config.

### Wall-clock target

Expected PR wall-clock on warm cache: ~3 min, bounded by the longest
job chain:

- `build-and-test` (~2.5 min) → `apk-analyze` (~20 s) = ~2.8 min
- `lint-and-detekt` (~2 min), runs in parallel
- `secret-scan` (~30 s), `submodule-check` (~20 s), `python-pipeline` (~1 min)
  run in parallel
- `instrumented` (~8 min) does not contribute to `ci-success` (advisory)

Current serial runtime is ~5 min; target is ~3 min.

## release.yml — Release workflow

### Triggers

- `push` to `main`, paths-ignore: `**/*.md`, `docs/**`, `notes/**`.
- `workflow_dispatch` (manual re-release).

### Concurrency

```yaml
concurrency:
  group: release
  cancel-in-progress: false
```

Back-to-back merges queue rather than skip — every main commit that
matters gets a release attempt.

### Job: `release`

Steps:

1. **Checkout** with `fetch-depth: 0`, `submodules: true`.
2. **Setup JDK + Android SDK + Gradle** (same block as ci.yml).
3. **Wait for ci-success on the same SHA.** Uses `actions/github-script`
   to poll `ci-success` check-run status:
   - Green → proceed.
   - Failed → exit with message.
   - Pending → wait up to 15 min, then fail.
   - Rationale: release is decoupled from ci.yml, so it must verify CI
     passed, not assume.
4. **Build APK**: `./gradlew assembleDebug --stacktrace`.
5. **Compute version**: ported verbatim from the current workflow
   (`android-build.yml` lines 89–100). Extracts `BASE_VERSION` from
   `app/build.gradle.kts` via `grep | sed`, appends `git rev-list --count HEAD`,
   prefixes `v` for the tag.
6. **Compute release notes**: commits since last tag, ported verbatim from
   the current workflow (lines 94–102). If no previous tag, falls back to
   `git log -20`.
7. **Publish**: `gh release create "$TAG" app-debug.apk --title ... --notes-file ...`.

### Permissions

```yaml
permissions:
  contents: write   # for gh release create
  actions: read     # for polling ci-success check-run
  checks: read      # same
```

### What changes vs current behavior

- Docs-only merges no longer burn version numbers.
- A flaky lint/detekt run never silently kills a release (release asserts
  ci-success green before building).
- `workflow_dispatch` provides a manual re-release button — useful when
  the auto-release fails due to token/GitHub outage (as happened during
  the 2026-04 shadowban).
- Release is no longer tied to the critical path of PR gates; you can
  reshape gates without touching release logic.

## Dependabot

**Unchanged.** Current config (`.github/dependabot.yml`) is monthly-grouped
for Gradle and GitHub Actions, tuned for inbox quietness.

- **Not adding `git-submodule` ecosystem.** The submodule is pinned by
  design; automation PRs would be closed-as-wontfix.
- **Not adding `pip` ecosystem.** No `requirements.txt` exists in
  `scripts/`. If that changes later, re-evaluate.

## Rollout plan

The required-check rename is the trickiest part. Today, branch protection
requires the check named `build` from `android-build.yml`. The new workflow
publishes `ci-success`. If we merge everything in one PR, GitHub blocks
the merge because `build` never reports on a PR whose workflow no longer
defines that job.

**Two-PR rollout:**

### PR 1 — Add new workflows alongside old

- Add `.github/workflows/ci.yml`.
- Add `.github/workflows/release.yml`.
- Leave `.github/workflows/android-build.yml` in place.
- Both old and new workflows run on the PR. Required check `build`
  still reports (from old workflow), so the PR is mergeable.

After merge, main pushes trigger all three workflows. Observe for one or
two main commits:
- `ci-success` goes green.
- `release.yml` successfully publishes an APK.
- `android-build.yml` still goes green (sanity).

### Manual step — flip branch protection

One-time admin action. Protection is a **ruleset** on this repo, not
classic branch protection:

```bash
RULESET_ID=$(gh api repos/yasirhamza/AndroDR/rulesets \
  --jq '.[] | select(.name == "Protect main") | .id')
gh api "repos/yasirhamza/AndroDR/rulesets/$RULESET_ID" > /tmp/ruleset-before.json
jq '.rules |= map(
     if .type == "required_status_checks"
     then .parameters.required_status_checks = [{"context": "ci-success"}]
     else . end
   ) | {name, target, enforcement, bypass_actors, conditions, rules}' \
   /tmp/ruleset-before.json > /tmp/ruleset-after.json
gh api -X PUT "repos/yasirhamza/AndroDR/rulesets/$RULESET_ID" \
  --input /tmp/ruleset-after.json
```

See plan Task 18 for the full discover → diff → apply → verify → rollback flow.

### PR 2 — Delete old workflow

- Delete `.github/workflows/android-build.yml`.
- Required check is now `ci-success`; reports from `ci.yml`; PR merges.

### Post-shadowban verification

On the first main push after PR 1 merges:
- Verify `gh release create` publishes (token permissions may need a
  refresh after the 2026-04 shadowban outage).
- If it fails, check `GITHUB_TOKEN` scope in repo settings → Actions → Permissions.

## Risks and mitigations

| Risk | Mitigation |
|---|---|
| `apk-analyze` flip to blocking surfaces pre-existing exported-component issues | Run the check locally on `main` before PR 1 merges to confirm no regressions. Fix any real findings in a preceding PR. |
| `python-pipeline` job fails because IOC dry-run is expensive | Confirm `scripts/merge-ioc-data.py --dry-run` exists / is fast during implementation; if not, fall back to `--help` + `py_compile`. |
| Concurrency `cancel-in-progress` on PRs cancels a run right before it would publish reports | Uploads are `if: always()` on each job — artifacts survive even on cancellation. |
| `submodule-check` fails because upstream force-pushed `main` | Intended behavior — this is exactly the signal we want. Manual remediation (update submodule to a currently-reachable commit). |
| Release job polls `ci-success` but CI takes > 15 min | Increase timeout to 30 min. 15 min is the initial estimate; we adjust based on real runs. |
| Branch protection flip between PR 1 and PR 2 leaves a window where nothing is required | Order matters: flip happens AFTER PR 1 merges and BEFORE PR 2. No main-push window without a required check. |

## Testing plan

- **PR 1 itself is the integration test.** Both old and new workflows run;
  we compare their outcomes on the same SHA.
- **Scenarios to exercise before PR 1 is merged**:
  - Normal PR with Kotlin + test changes → all gates green.
  - PR touching only `docs/**` → CI does not run at all (paths-ignore).
  - PR touching a Python script → `python-pipeline` gates it.
  - PR pointing the submodule to a non-upstream commit → `submodule-check`
    fails.
  - `workflow_dispatch` on `release.yml` → publishes a release for the
    current `main` SHA.

## Success criteria

1. PR wall-clock drops from ~5 min to ~3 min.
2. No docs-only merges appear in the release list after rollout.
3. Branch protection references a single check (`ci-success`) instead of
   requiring knowledge of every gate.
4. A deliberately-broken apkanalyzer (exported component without permission)
   fails a PR instead of being logged as a warning.
5. A deliberately-broken Python script (syntax error in `scripts/*.py`)
   fails a PR instead of shipping to main.

## Open questions

None at design time. Any ambiguities resolved during implementation
(e.g., exact `--dry-run` support in `merge-ioc-data.py`) are called out
in the risks table.
