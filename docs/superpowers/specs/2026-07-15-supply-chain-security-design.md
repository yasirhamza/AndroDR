# Supply Chain Security Posture — Design

**Date:** 2026-07-15
**Issue:** [#252](https://github.com/yasirhamza/AndroDR/issues/252)
**Status:** Approved (design locked in #252 on 2026-07-14; deltas confirmed with maintainer 2026-07-15; revised same day after the 4-agent plan-gate review and the maintainer's decision to keep the Play upload key out of CI)

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
- gitleaks secret scanning, Dependabot **version updates** (Gradle + Actions,
  monthly, grouped), APK manifest analysis, submodule-integrity check,
  lint + detekt, full test matrix, path-filtered gates
- **Caveat found at plan-gate review:** the repo's dependency graph,
  vulnerability alerts, and Dependabot security updates are **disabled**
  (`gh api .../dependency-graph/sbom` → 404, `.../vulnerability-alerts` →
  404). The "standing tree → Security-tab alerts" leg of the SCA policy has
  therefore never been active; PR 1 must enable these before the new SCA
  jobs can work at all (`dependency-review` calls the graph compare
  endpoint, which 403s while the graph is off)
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

- **The Play key is an upload key** (App enrolled in Play App Signing,
  confirmed by maintainer in Play Console 2026-07-15). **Maintainer decision
  2026-07-15: the upload key is nevertheless NOT stored in CI.** GitHub
  releases are signed with a **dedicated CI release keystore** generated for
  that purpose only; the upload key and its passwords never leave the
  maintainer's machine. Authenticity of GitHub releases is anchored in the
  SLSA provenance attestation (binds the APK to this repo's workflow); the
  CI key provides a *stable* sideload signature (today's debug-signed
  releases are signed by ephemeral runner keys, so every release already
  breaks sideload updates). CI-key rotation is trivial: regenerate, replace
  secrets, sideloaders reinstall once — no Play Console involvement.
- **No existing password leak.** The commented `RELEASE_*` lines in the
  tracked `gradle.properties` are placeholders — verified they do **not**
  unlock `release-keystore.jks`. Real credentials live untracked in
  `~/.gradle/gradle.properties` and were verified working via `keytool`.
- `release-keystore.jks` is gitignored (`.gitignore:55`) and present locally.

## Decisions locked

| Decision | Choice |
|---|---|
| SCA gate strength | Block fixable Crit/High, warn on the rest. `severity ≥ HIGH && fix exists → FAIL`; `≥ HIGH && no fix → WARN + track`; MEDIUM/LOW → report only; suppressions file entries (reason + expiry) → ignore |
| Release build | Signed release APK (**dedicated CI release keystore** — maintainer decision 2026-07-15: Play upload key never stored in CI) + CycloneDX SBOM + SLSA provenance attestation |
| Tooling philosophy | GitHub-native first; third-party only where GitHub has no equivalent (sole exception: `org.cyclonedx.bom` Gradle plugin) |
| Secrets provisioning | CI keystore generated locally (`keytool -genkeypair`, random password); its base64 + passwords set via `gh secret set` piped from process substitution — values never printed or committed. Upload-key material is never provisioned anywhere |
| Enforcement mechanism | Edit ruleset "Protect main": add native `code_scanning` rule (tool: CodeQL). `dependency-review` blocks via the existing required `ci-success` check (path-filtered, skipped-counts-as-pass) rather than a separate required context — a separate context would deadlock docs-only PRs. Ratified at plan gate |
| Sideload continuity | Accepted one-time cost: GitHub-release APKs switch from (per-release-unstable) debug signing to the stable CI release key; previously sideloaded installs need one uninstall/reinstall. Play Store users unaffected |

## Design — six layers → concrete tools

| # | Layer | Tool (all free on public repo) | Enforcement |
|---|-------|------|-----------------|
| 1 | Dependency integrity | Gradle `verification-metadata.xml` (sha256 only, no PGP) | Build fails if any resolved artifact's checksum differs → tamper/typosquat/mirror-poisoning evident |
| 2 | Dependency vulns (SCA) | `actions/dependency-review-action` (PR gate) + `gradle/actions/dependency-submission` (graph) + existing Dependabot | Policy mapping below |
| 3 | CI/build hardening | SHA-pin every action; keep least-privilege `permissions:`; per-job token scoping | Compromised action tag can't silently change what runs |
| 4 | Release integrity | Wire `assembleRelease` signing (dedicated CI keystore) into CI + CycloneDX SBOM + `actions/attest-build-provenance` | Published APK is CI-release-key-signed with a pinned cert digest, ships SBOM, carries verifiable SLSA attestation |
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
  `**/.memsearch/**`, `**/.superpowers/**`, `**/.claude/settings.local.json`,
  `**/*.jks`, `**/*.keystore`, `**/*.p12`, `**/*.pfx`, `**/*.pepk`,
  `**/*.bks`, `**/local.properties`, `**/.env*`, plus comment lines.
  Patterns are `**/`-prefixed (root-anchored globs miss a state dir created
  in a subdirectory) and matched **case-insensitively** (`:(glob,icase)` —
  `Release.JKS` must not escape); the key-material extensions cover PKCS12
  and Play `pepk` exports, not just JKS. The denylist is the source of
  truth; `.gitignore` mirrors it.
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

- **Pre-flight (repo settings, before the PR):** enable the dependency graph
  + vulnerability alerts (`gh api -X PUT repos/:owner/:repo/vulnerability-alerts`)
  and Dependabot security updates; confirm the graph compare endpoint
  returns 200. Without this every SCA job 403s.
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
  with an initially-empty `allow-ghsas` (shipped with a temporary 18-entry
  bootstrap block for the snapshot-less first run — deviation #8 in the
  plan's register, removed post-merge) and the reason/review-date
  convention documented.
  The submission job checks out with `persist-credentials: false` (it holds
  a `contents: write` token on PR-triggered Gradle resolution) and runs with
  dependency verification off (graph telemetry only — required once PR 3
  lands, because the action's init-script-injected graph plugin resolves
  artifacts that the checked-in verification metadata does not record).
- Outbound-leak guard: denylist file + CI job + `.gitignore` pre-hygiene
  (as specified above).
- Add `SECURITY.md`: supported versions, disclosure policy →
  yhamad.dev@gmail.com (never @androdr.dev), response expectations, and
  GitHub **private vulnerability reporting** as the preferred channel
  (enabled via API post-merge — addition ratified at plan gate).
- Add `docs/supply-chain.md`: the six-layer posture, SCA triage process,
  suppressions convention, outbound-leak surface, verification commands.
  Sections describing PR 2/PR 3 capabilities carry an explicit
  "Status: pending PR N of #252" marker, removed by the PR that makes them
  true — the docs must never claim capabilities the repo doesn't have yet.
- **Enforcement (post-merge, via `gh api`):** update ruleset "Protect main"
  to require `dependency-review` + add `code_scanning` rule (CodeQL,
  block on new high-severity alerts). Done after first green runs exist so
  required checks don't wedge unrelated PRs.

### PR 2 — Release integrity

- **Prerequisite:** upgrade local `gh` to ≥ 2.49 (`gh attestation` shipped
  in 2.49; this machine has 2.45 — verified at plan gate).
- Generate a **dedicated CI release keystore** locally
  (`keytool -genkeypair`, RSA-4096, random password, stored outside the
  repo); provision **its** material via `gh secret set` (values piped,
  never displayed): `RELEASE_KEYSTORE_BASE64`, `RELEASE_STORE_PASSWORD`,
  `RELEASE_KEY_ALIAS`, `RELEASE_KEY_PASSWORD`. The Play upload key is never
  provisioned.
- `release.yml`: `assembleDebug` → `assembleRelease`; decode keystore to
  `release-keystore.jks`; pass credentials via `ORG_GRADLE_PROJECT_*` env
  (matches existing `signingConfigs.release` property names — no build-file
  change; local Play builds keep using the real upload keystore at the same
  path).
- Gate: `apksigner verify --print-certs` on the output APK **plus a pinned
  expected certificate SHA-256 digest** (the CI key's) — a build signed by
  any other key fails.
- Add `org.cyclonedx.bom` Gradle plugin (the one justified non-native piece);
  generate `bom.json`; attach APK + SBOM to the GitHub release.
- `actions/attest-build-provenance` for APK + SBOM (job-scoped
  `id-token: write`, `attestations: write`, `artifact-metadata: write` —
  the third is required by the action's v3.2 line, pinned deliberately so a
  Dependabot bump can't strand the permissions).
- Release notes template gains a "verify this release" snippet
  (`gh attestation verify <apk> --repo yasirhamza/AndroDR`).
- Document the sideload signature break in the release notes of the first
  release-signed build.
- **Declared deviation (testing):** the `workflow_dispatch` dry-run skips
  the attestation step — attestations are permanent in the repo's
  attestation log and dry-run entries would pollute it. Attestation is
  verified on the first real post-merge release instead (compensating
  control), immediately after merge.

### PR 3 — Dependency verification (highest maintenance, last)

- Generate via `./gradlew --write-verification-metadata sha256 <full CI
  task set>` (assembleDebug, assembleRelease, testDebugUnitTest, lintDebug,
  detekt, assembleDebugAndroidTest, :app:cyclonedxBom) — **supersedes the
  originally noted `help` bootstrap**, which would leave test/lint/SBOM
  configurations unrecorded and redden CI. Commit
  `gradle/verification-metadata.xml`; verification is active by the file's
  presence.
- Add auto-regen workflow for Dependabot branches, **hardened** (plan-gate
  security finding): checkout with the read-only default token and
  `persist-credentials: false`; regenerate with `--dry-run` so the bumped
  dependency tree's tasks never execute (configuration-time plugin code
  still runs — documented residual risk); the contents-write PAT
  (fine-grained, this repo only, 90-day expiry, stored as a **Dependabot
  secret**) is injected only into the final push step's environment. PAT
  push (not `GITHUB_TOKEN`) is what retriggers CI on the regen commit.
- **Trust-on-first-use caveat (documented honestly):** for a Dependabot
  bump, the regenerated checksum of the *new* artifact version is recorded
  from whatever the regen run downloaded. Verification protects all
  unchanged artifacts and every subsequent fetch — not the authenticity of
  the newly bumped version; that is what advisory data and bump-PR review
  are for.
- CI must demonstrate a tamper case fails (one-off local test during
  development, documented in the PR, not a standing CI job).
- **Declared deviation (testing):** the regen workflow's end-to-end path
  (Dependabot trigger → PAT push → CI retrigger) cannot be faithfully
  simulated pre-merge (Dependabot secrets are only readable in
  Dependabot-triggered runs). AC "auto-regen works" is accepted on the
  first real monthly Dependabot cycle; #252's closing comment records this
  as pending observation.

## Error handling / failure modes

- **CodeQL manual build fails** → job fails visibly; PR gate only becomes
  *required* (ruleset) after first green runs, so no wedge window.
- **dependency-review on non-dep PRs** → action no-ops (delta-only); path
  filtering unnecessary.
- **Denylist job false positive** → fix is a one-line denylist edit in the
  same PR; the job prints exactly which tracked path matched which pattern.
- **Secret rotation** (CI key leak) → documented in `docs/supply-chain.md`:
  regenerate the CI keystore, replace the four secrets, note the one-time
  sideloader reinstall. No Play Console involvement (the upload key is not
  in CI). The `DEPENDABOT_REGEN_TOKEN` PAT (90-day expiry) also gets a
  runbook entry with its renewal command and expiry date.
- **Enforcement limits (documented, not fixed):** ruleset "Protect main"
  grants Repository-admin an always-on bypass, so the gates constrain
  automation and habit, not a determined or deceived admin; required checks
  are non-strict, so a green `ci-success` may predate the current base.
  Preserving the bypass is deliberate — removing it is a separate
  maintainer decision.
- **Unwind order:** if `codeql.yml` is ever disabled, the ruleset's
  `code_scanning` rule must be dropped first, or merges wedge waiting for
  analyses that never arrive.
- **Rollback coupling:** reverting PR 2 after PR 3 has merged also requires
  dropping `:app:cyclonedxBom` from the regen workflow and the documented
  regen command (the task exists only while the CycloneDX plugin is
  applied). Stated in `docs/supply-chain.md`.
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
  CodeQL run completes with results in Security tab (build runs with
  `--no-build-cache --no-configuration-cache` — a cache-hit build compiles
  nothing and CodeQL sees no source); dependency-review job visible green
  (first run has no base snapshot on main — expected: retry-timeout then
  proceed; if the whole tree reports as "added" and a standing High reds
  the gate, triage per policy before merge); denylist job green, and
  demonstrated red in a scratch commit (add a dummy tracked `.env` file,
  observe failure, revert) before merge. After the ruleset gains the
  `code_scanning` rule: verify empirically that a docs-only PR is NOT
  blocked waiting for CodeQL (undocumented GitHub behavior — if it blocks,
  the recorded rollback is re-PUTting the ruleset without that rule).
- **PR 2:** `workflow_dispatch` dry-run of `release.yml` on the PR branch:
  APK produced, `apksigner verify` passes **with the pinned CI-key digest**,
  SBOM generated. Attestation is deliberately not created on dry-runs (see
  declared deviation); `gh attestation verify` runs against the first real
  release immediately after merge.
- **PR 3:** full local build with verification on; local tamper test (flip
  one checksum → build fails); regen *command* proven locally; the regen
  *workflow* end-to-end is accepted on the first real Dependabot cycle
  (declared deviation). Post-merge: watch the main-branch `release.yml` run
  triggered by PR 3's merge — it is the first `assembleRelease` under
  active verification, and CI never runs that path on PRs.

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
      `*.p12`/`*.pfx`/`*.pepk`/`*.bks`, `local.properties`, `.env*` — at any
      depth, case-insensitive) is tracked; `.gitignore` pre-ignores them.
- [ ] Dependency graph + vulnerability alerts + Dependabot security updates
      enabled on the repo (pre-flight for the SCA gates).
- [ ] `release.yml` publishes an `assembleRelease` APK signed with the
      dedicated CI release key; `apksigner verify` passes in CI **and** the
      certificate digest matches the pinned value. The Play upload key is
      not stored in CI (verifiable: the pinned digest differs from the Play
      upload-cert digest).
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
- Proactive rotation of the Play upload key — it never enters CI, so this
  effort creates no new reason to rotate it. The CI release key rotates
  only on suspicion of compromise (trivial by design).
