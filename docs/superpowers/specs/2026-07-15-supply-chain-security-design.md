# Supply Chain Security Posture — Design

**Date:** 2026-07-15
**Issue:** [#252](https://github.com/yasirhamza/AndroDR/issues/252)
**Status:** Approved (design locked in #252 on 2026-07-14; deltas confirmed with maintainer 2026-07-15)

## Goal

Stand up an automated, defense-in-depth supply chain security posture across
AndroDR's CI/CD, covering first-party code, upstream dependencies, **and
outbound VCS hygiene**, producing auditable evidence (SBOM, provenance,
signatures) so that when a new CVE is disclosed we can answer "are we
affected?" in minutes.

### What this is NOT

"Guarantee everything entering the codebase is vulnerability-free" is not
achievable by anyone and is not the target:

- Scanners only know *disclosed* CVEs; unknown vulns exist by definition.
- "Zero known vulns" gates block every PR (unfixable transitive CVEs) and get
  disabled — the classic failure mode.
- Real supply chain attacks (tj-actions, xz-utils, typosquats) don't show up
  in vuln scanners.

**Target:** reduce attack surface, make every input verifiable/auditable,
auto-gate *known* problems at the PR boundary with a sane triage policy, and
emit tamper-evidence.

## Current state (verified 2026-07-15)

Already present:

- Least-privilege `permissions: contents: read` in workflows
- gitleaks secret scanning, Dependabot (Gradle + Actions, monthly, grouped),
  APK manifest analysis, submodule-integrity check, lint + detekt, full test
  matrix, path-filtered gates
- Release signing fully configured in `app/build.gradle.kts`
  (`signingConfigs.release`: `storeFile = release-keystore.jks` at repo root,
  passwords via Gradle properties `RELEASE_STORE_PASSWORD` /
  `RELEASE_KEY_ALIAS` / `RELEASE_KEY_PASSWORD`)
- All dependency versions pinned in `gradle/libs.versions.toml` (no dynamic
  versions)
- `main` protected by **ruleset** "Protect main" (id 14651316): PR required,
  required status check `ci-success`, no deletion/force-push. (*Not* classic
  branch protection — enforcement changes below edit this ruleset.)

Gaps (all confirmed present as of today):

1. All actions across `ci.yml`, `release.yml`, `check-privacy-sync.yml` pinned
   to mutable tags (`@v4`, `@v3`, …), not commit SHAs.
2. `release.yml` builds and ships the **debug** APK (`assembleDebug`).
3. No Gradle dependency verification (`verification-metadata.xml`).
4. No SBOM, no provenance, no blocking SCA gate on PRs, no first-party SAST.
5. No `SECURITY.md`, no `docs/supply-chain.md`.
6. No guard against *outbound* leaks: a local tooling/state dir or keystore
   accidentally `git add`-ed would pass gitleaks (content scan) unnoticed.

### Verified facts that shape the work

- **The Play key is an upload key.** App is enrolled in Play App Signing
  (confirmed by maintainer in Play Console 2026-07-15). A CI secret leak is
  recoverable by rotating the upload key → acceptable to wire into CI.
- **No existing password leak.** The commented `RELEASE_*` lines in the
  tracked `gradle.properties` are placeholders — verified they do **not**
  unlock `release-keystore.jks`. Real credentials live untracked in
  `~/.gradle/gradle.properties` and were verified working via `keytool`.
- `release-keystore.jks` is gitignored (`.gitignore:55`) and present locally.

## Decisions locked

| Decision | Choice |
|---|---|
| SCA gate strength | Block fixable Crit/High, warn on the rest. `severity ≥ HIGH && fix exists → FAIL`; `≥ HIGH && no fix → WARN + track`; MEDIUM/LOW → report only; suppressions file entries (reason + expiry) → ignore |
| Release build | Signed release APK (upload key) + CycloneDX SBOM + SLSA provenance attestation |
| Tooling philosophy | GitHub-native first; third-party only where GitHub has no equivalent (sole exception: `org.cyclonedx.bom` Gradle plugin) |
| Secrets provisioning | Maintainer's machine has keystore + passwords; secrets set via `gh secret set` piped from local files — values never printed or committed |
| Enforcement mechanism | Edit ruleset "Protect main": add `dependency-review` required status check + native `code_scanning` rule (tool: CodeQL) |
| Sideload continuity | Accepted one-time cost: GitHub-release APKs switch from debug-signed to release-key-signed; previously sideloaded installs need uninstall/reinstall. Play Store users unaffected |

## Design — six layers → concrete tools

| # | Layer | Tool (all free on public repo) | Enforcement |
|---|-------|------|-----------------|
| 1 | Dependency integrity | Gradle `verification-metadata.xml` (sha256 only, no PGP) | Build fails if any resolved artifact's checksum differs → tamper/typosquat/mirror-poisoning evident |
| 2 | Dependency vulns (SCA) | `actions/dependency-review-action` (PR gate) + `gradle/actions/dependency-submission` (graph) + existing Dependabot | Policy mapping below |
| 3 | CI/build hardening | SHA-pin every action; keep least-privilege `permissions:`; per-job token scoping | Compromised action tag can't silently change what runs |
| 4 | Release integrity | Wire existing `assembleRelease` signing into CI + CycloneDX SBOM + `actions/attest-build-provenance` | Published APK is upload-key-signed, ships SBOM, carries verifiable SLSA attestation |
| 5 | First-party SAST | CodeQL (`java-kotlin`, manual build mode) on PRs + weekly cron | New high-severity code-scanning alerts block PRs via ruleset |
| 6 | Outbound-leak guard | `.gitignore` pre-hygiene + tracked-path denylist CI job | CI fails if any tracked file matches denylist (tooling-state dirs, keystores, `local.properties`, `.env*`) |

### How the SCA policy is actually realized (honest nuance)

- `dependency-review-action` is **delta-only** — fires only when a PR
  introduces or bumps a dep carrying a Crit/High vuln; it does not re-flag
  pre-existing transitive CVEs on every PR. That property prevents wedging.
- `fail-on-severity: high` → PR introducing a fixable Crit/High fails. If
  genuinely unfixable, add its GHSA id to `allow-ghsas` in a checked-in
  `.github/dependency-review-config.yml` with reason + review date.
- **Standing tree** is Dependabot's job: fixable → update PRs (act);
  unfixable → Security-tab alerts (warn, don't block). This split *is* the
  fixable→act / unfixable→warn behavior; documented in `docs/supply-chain.md`.

### Outbound-leak guard (layer 6) detail

Surfaced in practice 2026-07-14: the MemSearch plugin auto-created
`.memsearch/` (session summaries + vector index) untracked and un-ignored in
this public repo; one stray `git add .` from publishing it. gitleaks scans
*content* and would not flag a state directory with no classic secret pattern.

- **Denylist file** `.github/tracked-path-denylist.txt`: one glob per line —
  `.memsearch/**`, `.superpowers/**`, `.claude/settings.local.json`,
  `**/*.jks`, `**/*.keystore`, `**/local.properties`, `.env*`, plus comment
  lines. The denylist is the source of truth; `.gitignore` mirrors it.
  **Deliberately NOT `.claude/**`:** the repo intentionally tracks 24 files
  under `.claude/commands/` (the public update-rules pipeline skills);
  only the local-state file `settings.local.json` is sensitive. Verified
  2026-07-15 that no currently tracked file matches the denylist, so the
  job starts green.
- **CI job** (in `ci.yml`, no path filter — always runs, cheap): checks
  `git ls-files` output against the denylist; any match → fail with the
  offending paths listed. No external tooling.
- `.gitignore` gains pre-emptive entries for the denylisted dirs so the
  untracked-and-committable window never opens (`.memsearch/` done in #253;
  add the rest).

## Rollout — three risk-ordered PRs

Each independently mergeable and CI-gated. All three approved for this cycle,
executed in sequence (merge N before starting N+1).

### PR 1 — CI hardening + scanning gates (safe, additive, no build changes)

- SHA-pin **all** actions across `ci.yml`, `release.yml`,
  `check-privacy-sync.yml`, with `# vX.Y.Z` version comments (Dependabot's
  `github-actions` updater understands SHA pins and keeps comments current).
- Add `.github/workflows/codeql.yml`: `languages: java-kotlin`,
  `build-mode: manual` → `./gradlew assembleDebug`; triggers: PR (code
  path-filter) + weekly cron + push to main.
- Add `dependency-submission` job (push to main **and** PR — Gradle graphs
  aren't manifest-parseable, so PR-side submission is what lets
  `dependency-review` diff the graph) + `dependency-review` job (PR,
  `fail-on-severity: high`) + `.github/dependency-review-config.yml`
  with empty `allow-ghsas` and the reason/review-date convention documented.
- Outbound-leak guard: denylist file + CI job + `.gitignore` pre-hygiene
  (as specified above).
- Add `SECURITY.md`: supported versions, disclosure policy →
  yhamad.dev@gmail.com (never @androdr.dev), response expectations.
- Add `docs/supply-chain.md`: the six-layer posture, SCA triage process,
  suppressions convention, outbound-leak surface, verification commands.
- **Enforcement (post-merge, via `gh api`):** update ruleset "Protect main"
  to require `dependency-review` + add `code_scanning` rule (CodeQL,
  block on new high-severity alerts). Done after first green runs exist so
  required checks don't wedge unrelated PRs.

### PR 2 — Release integrity

- Provision GitHub secrets from maintainer machine via `gh secret set`
  (values piped from files, never displayed): `RELEASE_KEYSTORE_BASE64`,
  `RELEASE_STORE_PASSWORD`, `RELEASE_KEY_ALIAS`, `RELEASE_KEY_PASSWORD`.
- `release.yml`: `assembleDebug` → `assembleRelease`; decode keystore to
  `release-keystore.jks`; pass credentials via `ORG_GRADLE_PROJECT_*` env
  (matches existing `signingConfigs.release` property names).
- Gate: `apksigner verify --print-certs` on the output APK.
- Add `org.cyclonedx.bom` Gradle plugin (the one justified non-native piece);
  generate `bom.json`; attach APK + SBOM to the GitHub release.
- `actions/attest-build-provenance` for APK + SBOM (`id-token: write`,
  `attestations: write` — job-scoped).
- Release notes template gains a "verify this release" snippet
  (`gh attestation verify <apk> --repo yasirhamza/AndroDR`).
- Document the sideload signature break in the release notes of the first
  release-signed build.

### PR 3 — Dependency verification (highest maintenance, last)

- Generate via `./gradlew --write-verification-metadata sha256 help`;
  commit `gradle/verification-metadata.xml`; verification is active by the
  file's presence.
- Add auto-regen workflow: on Dependabot branches, regenerate the metadata
  and commit back to the PR branch, so monthly bumps don't leave the build
  red. (Needs `contents: write` scoped to that job; triggers only for
  `dependabot[bot]` actor.)
- CI must demonstrate a tamper case fails (one-off local test during
  development, documented in the PR, not a standing CI job).

## Error handling / failure modes

- **CodeQL manual build fails** → job fails visibly; PR gate only becomes
  *required* (ruleset) after first green runs, so no wedge window.
- **dependency-review on non-dep PRs** → action no-ops (delta-only); path
  filtering unnecessary.
- **Denylist job false positive** → fix is a one-line denylist edit in the
  same PR; the job prints exactly which tracked path matched which pattern.
- **Secret rotation** (upload key leak) → documented in
  `docs/supply-chain.md`: request upload-key reset in Play Console, replace
  the four secrets.
- **verification-metadata drift** (non-Dependabot dep change) → build fails
  locally with instructions; regen command documented in CLAUDE.md-adjacent
  docs (`docs/supply-chain.md`).
- **Fork-PR limitation:** `dependency-submission` needs `contents: write`,
  withheld from fork PRs. Non-issue on a solo/maintainer repo; noted for
  completeness.
- **CodeQL Kotlin maturity:** supported but younger than Java coverage —
  expect solid but not exhaustive first-party findings.

## Testing

- **PR 1:** all existing CI green on the PR itself (proves SHA pins correct);
  CodeQL run completes with results in Security tab; dependency-review job
  visible green; denylist job green, and demonstrated red in a scratch commit
  (add a dummy tracked `.env` file, observe failure, revert) before merge.
- **PR 2:** `workflow_dispatch` dry-run of `release.yml` on the PR branch:
  APK produced, `apksigner verify` passes, SBOM generated, attestation
  created; `gh attestation verify` succeeds against the artifact.
- **PR 3:** full local build with verification on; local tamper test (flip
  one checksum → build fails); simulated Dependabot regen run.

## Acceptance criteria

- [ ] All GitHub Actions across all three workflows pinned to commit SHAs
      (with version comments).
- [ ] CodeQL (`java-kotlin`) running on PRs + weekly; results in Security tab.
- [ ] `dependency-review` blocks PRs introducing Crit/High vulns;
      `allow-ghsas` suppressions file exists with reason + review-date
      convention.
- [ ] `dependency-submission` populates the dependency graph on main.
- [ ] CI fails if any denylisted local-state/sensitive path (`.memsearch/`,
      `.superpowers/`, `.claude/settings.local.json`, `*.jks`, `*.keystore`,
      `local.properties`, `.env*`) is tracked; `.gitignore` pre-ignores them.
- [ ] `release.yml` publishes an upload-key-signed (Play App Signing)
      `assembleRelease` APK; `apksigner verify` passes in CI.
- [ ] Each release has an attached CycloneDX SBOM and a verifiable provenance
      attestation (`gh attestation verify <apk> --repo yasirhamza/AndroDR`).
- [ ] Gradle `verification-metadata.xml` (sha256) enabled; Dependabot bumps
      don't leave the build red (auto-regen works).
- [ ] `SECURITY.md` + `docs/supply-chain.md` committed; ruleset "Protect
      main" requires the new gates.

## Explicitly out of scope (YAGNI)

- Gradle dependency version-locking (`gradle.lockfile`) — redundant given
  fully-pinned catalog versions.
- PGP-signature verification in `verification-metadata.xml` — checksum-only
  for lower maintenance.
- Third-party scanners (Trivy/Grype/Semgrep/OWASP dependency-check) —
  GitHub-native covers the layers; revisit only on a demonstrated gap.
- IP-based / runtime supply chain monitoring.
- Signing-key rotation away from the current upload key — recoverable by
  design; rotate only on suspicion of compromise.
