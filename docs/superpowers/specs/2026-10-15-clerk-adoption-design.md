# Clerk adoption, phase 1: blocking checks and lane triggers

Date: 2026-10-15. Status: design approved in conversation, awaiting written-spec review.

## 1. Purpose

AndroDR's review ceremony depends on judgment calls that have gone wrong
before: harness guards that passed without testing anything (#366), a
"small" scanner fix whose reviews found a fail-open (#387/#390), and the
proportionality rule that lets small, self-contained fixes skip the
4-reviewer ceremony on the orchestrator's say-so.

Phase 1 adopts the `superpowers-clerk` plugin for two things:

1. **Deterministic checks that block.** A finding stops the work before any
   review and before a PR is opened.
2. **Lanes as review triggers.** Which files a change touches, not the
   orchestrator's opinion of its size, decides whether the full ceremony runs.

The judge model (which could later reduce re-review rounds) is phase 2, a
separate decision.

## 2. Decisions taken

| # | Decision |
|---|----------|
| D1 | The checks run on the developer machine only. GitHub CI does not run the plugin (it is a private repository). |
| D2 | Every check blocks from day one. "Shadow" in the plugin applies only to judge templates, which phase 1 does not use. |
| D3 | A finding is cleared only by fixing it, or by an exception the owner grants. The orchestrator cannot override a finding. An exception is recorded in the PR body: check name, finding, reason. |
| D4 | Three lanes: `security`, `detection`, `gate-integrity` (§4). A change that touches any lane gets the full 4-reviewer ceremony regardless of size. |
| D5 | A change touching `gate-integrity` is itself a finding (`lane_paths --require-clean gate-integrity`), so it always needs an owner exception under D3. Loosening a gate is never incidental. |
| D6 | Cost and benefit are tracked in a local ledger that never enters the repository or GitHub (§7). |

## 3. Installation (machine-local)

- `uv`, at an exact pinned version, verified against its published checksum.
- The plugin: `claude plugin marketplace add yasirhamza/superpowers-clerk`,
  then `claude plugin install superpowers-clerk@superpowers-clerk`, version
  0.1.2. Upgrades only through `claude plugin update`.
- The CLI is invoked as `uv run --frozen --project <plugin root> clerk ...`,
  where `<plugin root>` is read from `~/.claude/plugins/installed_plugins.json`
  at each use, never written into a tracked file.

## 4. Tracked files

### 4.1 `clerk.toml`

- `project = "androdr"`.
- `[judge]`: `backend = "replay"`, `allow_external_judge = false`. No key, and
  nothing leaves the machine.
- `[escalation]`: subjects `security`, `detection`, `gate-integrity`; the
  three lanes listed under `lanes`.
- `[gates]`: the three manifest paths below.
- `[boundary]`: `workspace_allow = ["docs/superpowers/**"]`.

### 4.2 `.clerk/manifests/lanes.json`

Globs are repository-relative. `J` = `app/src/main/java/com/androdr`.

- **security**: `J/network/**`, `J/ioc/feeds/**`,
  `app/src/main/AndroidManifest.xml`, `app/proguard-rules.pro`,
  `app/src/main/res/xml/**`.
- **detection**: `J/sigma/**`, `J/scanner/**`, `J/ioc/**`,
  `app/src/main/res/raw/sigma_*.yml`, `app/src/main/res/raw/known_*.yml`,
  `third-party/android-sigma-rules`, `test-adversary/**`.
- **gate-integrity**: `.github/**`, `config/detekt.yml`,
  `app/src/test/**/*CrossCheckTest.kt`,
  `app/src/test/**/RuleManifestIntegrityTest.kt`,
  `app/src/test/**/ClerkLaneCoverageTest.kt`, `build.gradle.kts`,
  `app/build.gradle.kts`, `settings.gradle.kts`, `gradle/libs.versions.toml`,
  `gradle/verification-metadata.xml`, `clerk.toml`, `.clerk/**`.

A file may sit in more than one lane.

### 4.3 `.clerk/manifests/surfaces.json`

One sentence to start: the contact address `yhamad.dev@gmail.com` must appear
in `SECURITY.md`, `docs/PRIVACY_POLICY.md` and
`docs/AI-PIPELINE-CONVENTIONS.md`. Each later mistake of the "this statement
drifted between documents" kind adds a sentence (Regression policy).

### 4.4 `.clerk/manifests/citations.json`

Empty `entries` list. AndroDR's tracked docs quote no `file:line` today; specs
and plans written after adoption add entries for the lines they cite.

### 4.5 `ClerkLaneCoverageTest` (JVM unit test, runs in GitHub CI)

Reads `.clerk/manifests/lanes.json` and fails when:

1. a Kotlin file under `J/network/`, `J/ioc/`, `J/sigma/` or `J/scanner/`, or a
   `res/raw/sigma_*.yml` file, matches no lane glob; or
2. a lane glob matches no existing path (a stale glob silently disables its
   trigger).

It needs no plugin, so it is the part of the adoption that gates merges.

### 4.6 `docs/AI-PIPELINE-CONVENTIONS.md`

A new "Clerk checks" section stating D2–D5, the command sequence of §5, and
that PR bodies carry only the `base=`, `config_blob=` and `run=` lines from
the clerk, never local paths.

## 5. Procedure per change

1. Record `BASE`, the full 40-character SHA of `HEAD`, before any
   implementation starts. A later `BASE` makes every check pass vacuously.
2. Write the brief's file list to a workspace file.
3. After implementation:
   `clerk gate all --config clerk.toml --base <BASE> --brief-files <list> --range <BASE>..HEAD --expect-trailer "Co-Authored-By: Claude"`,
   plus `--require-clean gate-integrity`. Specs and plans pass `--spec`/`--plan`;
   a verification report passes `--report`/`--log` for `reconcile`.
4. Exit 1: findings go back to the implementer. Repeat 3 until exit 0, or
   until the owner grants an exception (D3).
5. Read the lane notes. Any lane touched: full 4-reviewer ceremony. None
   touched: the proportionality rule applies as today.
6. The PR body states the lanes touched, the clerk lines of 4.6, and any
   exception.

## 6. Verification of the adoption

On a throwaway branch, one planted mistake per check, each caught by its own
check:

| Check | Planted mistake |
|-------|-----------------|
| hygiene | a commit without the `Co-Authored-By: Claude` trailer |
| scope | a file changed that the brief does not list |
| placeholders | `TBD` in a plan |
| surfaces | the contact address removed from one document |
| lane_paths | a file under `.github/` changed |
| reconcile | a report claiming a test count the log does not show |

Then `clerk gate all` on unchanged `main` exits 0. `ClerkLaneCoverageTest`
is written red first: it must fail on a lanes manifest missing `J/scanner/**`
and on a glob that matches nothing, before the real manifest makes it pass.
`./gradlew testDebugUnitTest detekt lintDebug` stays green.

## 7. Local ledger (never tracked)

`~/.claude/projects/-home-yasir-AndroDR/clerk-ledger.csv`, one row per PR:
PR, date, checks run, findings caught, lanes touched, full ceremony
triggered (yes/no), exceptions granted, approximate tokens. The "findings
caught" column exists from the first row so the benefit side is measured,
not assumed.

## 8. Out of scope

- The judge and judged templates (phase 2).
- A pre-push hook.
- Running the plugin in GitHub CI.
- The `android-sigma-rules` repository.
