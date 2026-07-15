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
