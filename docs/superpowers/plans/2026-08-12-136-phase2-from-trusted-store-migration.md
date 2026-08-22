# Phase 2 — Migrate rules off `from_trusted_store` onto `trusted_installer_db` (#136) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans. Steps use `- [ ]` checkboxes. Full 4-agent ceremony per PR (these ARE the detection rules — security-critical).

**Goal:** Free the `from_trusted_store` field entirely: every bundled/delivered rule that uses it moves to `installer|ioc_lookup: trusted_installer_db` (the device-conditional lookup shipped in Phase 1b), so Phase 3 can delete the `from_trusted_store` emitted boolean. Semantics preserved exactly. The `from_trusted_store` boolean stays emitted during this phase (strangler-fig).

**Architecture:** Two usage shapes migrate differently. (b) `from_trusted_store: true` inside a `filter_*` block → 1-line swap to `installer|ioc_lookup: trusted_installer_db` (same meaning: installer is a trusted store). (a) `from_trusted_store: false` in a positive selection → move it out into a dedicated `store_installed` selection and negate it in the condition (`... and not store_installed`); `from_trusted_store: false` ≡ `not (installer is a trusted store)`. A registry + cross-check guards against a mistyped lookup name silently making a negated selection always-true. The audit's 4-entry `trusted_installers` drop rides the same rules-repo change and go-live.

**Tech Stack:** SIGMA YAML rules, Kotlin (SigmaRuleEvaluator, cross-check tests), snakeyaml-engine, JDK 21/Gradle; `android-sigma-rules` submodule (rules + `rules.sha256` + `ioc-lookup-definitions.yml` + `known-oem-prefixes.yml`).

## Global Constraints
- **JDK 21** for gradle: `export JAVA_HOME=/home/yasir/Applications/android-studio/jbr; export ANDROID_HOME=/home/yasir/Android/Sdk; export PATH="$JAVA_HOME/bin:$ANDROID_HOME/platform-tools:$PATH"`.
- **No new deps.** Detekt + Android Lint clean (run `./gradlew testDebugUnitTest lintDebug detekt` — detekt is a CI gate).
- **Semantic equivalence is mandatory.** Each migrated rule must fire / not-fire identically to its pre-migration form for: a sideloaded app (fires), a genuinely store-installed app (exempt/not-fired), a null-installer app (treated as not-from-store), and the known-good-impersonation backstop. Prove per rule with evaluator tests.
- **Bundled ↔ mirror byte-equal** (`BundledMirrorParityTest`): every rule edit is applied identically to `app/src/main/res/raw/sigma_androdr_NNN_*.yml` AND `third-party/android-sigma-rules/app_scanner/androdr_NNN_*.yml`.
- **Regenerate `rules.sha256`** after editing any `rules.txt`-listed file (recipe in CLAUDE.md); a stale manifest silently drops the rule on-device (fail-closed).
- **Full 4-agent ceremony** (correctness, code-quality, architect, code-security) per PR — security-critical (detection logic). Code-security lens must verify the negated-lookup restructure can't invert a gate (over-fire) or drop a gate (miss).
- **Safe-ordering + go-live gated on user** (12h wholesale feed fetch; same as Phase 1b PR B). PR A's parser (v0.9.0.606, already live) makes `trusted_installer_db` resolvable on-device.
- **Commit trailers:** `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>` / `Claude-Session: https://claude.ai/code/session_01JD52ChA3BtfEYtVi2Uz61H`.

## The two transforms (applied per the rule table)

**Transform B — filter swap** (rules where `from_trusted_store: true` sits in a `filter_*` block): replace the line `from_trusted_store: true` with `installer|ioc_lookup: trusted_installer_db`. Condition unchanged. (011 `filter_known_good`, 089 `filter_known_good`, 068 `filter_trusted_store`.)

**Transform A — selection restructure** (rules where `from_trusted_store: false` sits in a positive selection `S`): (1) delete the `from_trusted_store: false` line from `S`; (2) add a new sibling selection `store_installed:` with a single matcher `installer|ioc_lookup: trusted_installer_db`; (3) in `condition:`, insert `and not store_installed` immediately after the reference to `S`. Example for androdr-010 (selection `selection`, condition `selection and not filter_known_good`):
```yaml
detection:
    selection:
        is_system_app: false
        is_known_oem_app: false
    store_installed:
        installer|ioc_lookup: trusted_installer_db
    filter_known_good:
        package_name|ioc_lookup: known_good_app_db
    condition: selection and not store_installed and not filter_known_good
```
For androdr-016 the positive block is `selection_untrusted` and condition `selection_untrusted and selection_name` → becomes `selection_untrusted and not store_installed and selection_name`.

## Rule table (which transforms apply)

| Rule | Transform A (selection) | Transform B (filter) | Notes |
|---|---|---|---|
| androdr-010 | selection | — | |
| androdr-011 | selection | filter_known_good | **both** |
| androdr-012 | selection | — | |
| androdr-013 | selection | — | |
| androdr-014 | selection | — | condition is bare `selection` → `selection and not store_installed` |
| androdr-016 | selection_untrusted | — | condition `selection_untrusted and selection_name` |
| androdr-017 | selection | — | |
| androdr-068 | — | filter_trusted_store | 068's positive selection has no from_trusted_store |
| androdr-069 | selection | — | |
| androdr-089 | — | filter_known_good | positive selection uses `is_sideloaded: true` (untouched) |

## File structure
- `app/src/main/res/raw/sigma_androdr_{010,011,012,013,014,016,017,068,069,089}_*.yml` + byte-equal mirrors `third-party/android-sigma-rules/app_scanner/androdr_{...}.yml` — the migration.
- `third-party/android-sigma-rules/rules.sha256` — regenerated.
- `third-party/android-sigma-rules/validation/ioc-lookup-definitions.yml` — add `trusted_installer_db`.
- `third-party/android-sigma-rules/ioc-data/known-oem-prefixes.yml` + bundled + fixture — audit's 4-entry drop.
- `app/src/test/java/com/androdr/sigma/`: `BundledRulesSchemaCrossCheckTest.kt` (fix `blockEstablishesSideload`), `IocLookupDefinitionsCrossCheckTest.kt` (add lookup + rule-usage cross-check), `SigmaRuleEvaluatorTest.kt` (011-pattern + new semantic-equivalence cases), `Rule089OtpTheftTest.kt` (installer-based records), `OemPrefixResolverTest.kt` (drop assertions).

---

## Task 1: Lookup registry + rule-usage cross-check (guards the migration)

**Files:** `third-party/android-sigma-rules/validation/ioc-lookup-definitions.yml` (submodule — controller commits); `app/src/test/java/com/androdr/sigma/IocLookupDefinitionsCrossCheckTest.kt`.

- [ ] **Step 1: Failing cross-check test.** In `IocLookupDefinitionsCrossCheckTest`, add `trusted_installer_db` to the expected `kotlinLookupNames` set, and add a new test asserting every `|ioc_lookup: NAME` occurrence in the bundled rules resolves to a name in the definitions set:
```kotlin
    @Test
    fun `every ioc_lookup name used by a bundled rule is a registered lookup`() {
        val defined = loadDefinitionNames() + "trusted_installer_db" // registered lookups
        val used = File("app/src/main/res/raw").listFiles { f -> f.name.startsWith("sigma_androdr_") }
            .orEmpty().flatMap { f ->
                Regex("""\|ioc_lookup:\s*([a-z_]+)""").findAll(f.readText()).map { it.groupValues[1] }
            }.toSet()
        val unknown = used - defined
        assertTrue("Rules reference unregistered ioc_lookup names (typo → silent over-fire on negated use): $unknown", unknown.isEmpty())
    }
```
(Adapt `loadDefinitionNames()`/paths to the file's existing helpers.)
- [ ] **Step 2:** Run it → FAIL (`trusted_installer_db` not yet in `ioc-lookup-definitions.yml`, and the existing keys test may need the set updated).
- [ ] **Step 3:** Add `trusted_installer_db` to `ioc-lookup-definitions.yml` with a note it is a pure-emitter (non-ioc-data-backed) lookup over the emitted `installer` field, resolved by `OemPrefixResolver.isTrustedInstaller(installer, device)` (#136 Phase 2). Update the `kotlinLookupNames` set + `IocLookupDefinitionsCrossCheckTest` accordingly.
- [ ] **Step 4:** Run → PASS. Commit (controller handles the submodule file; see Task 4).

## Task 2: Fix `blockEstablishesSideload` to recognize the lookup

**Files:** `app/src/test/java/com/androdr/sigma/BundledRulesSchemaCrossCheckTest.kt`.

- [ ] **Step 1:** `blockEstablishesSideload` (~L251-260) currently returns true only if a block literally contains `from_trusted_store: false/true` or `is_sideloaded: …`. A rule migrated to `installer|ioc_lookup: trusted_installer_db` must still be recognized as establishing sideload. Extend the check so a block establishes sideload if it contains any of: `from_trusted_store` (either bool), `is_sideloaded`, OR an `installer|ioc_lookup: trusted_installer_db` matcher (used positively in a filter, or negated in a `store_installed`-style selection referenced under `not` in the condition). Keep the existing markers (parallel-run: some rules may still carry them until Phase 3).
- [ ] **Step 2:** This test can only be validated GREEN after Task 3's rule edits exist; write the logic now, run the class → expect it still passes on the CURRENT (un-migrated) rules (backward-compatible extension). Commit.

## Task 3: Migrate the 11 rule usages (bundled + mirror) + per-rule evaluator equivalence tests

**Files:** the 10 `sigma_androdr_*.yml` (bundled) + their `androdr_*.yml` mirrors; `SigmaRuleEvaluatorTest.kt`; `Rule089OtpTheftTest.kt`.

- [ ] **Step 1: Semantic-equivalence tests FIRST (TDD).** In `SigmaRuleEvaluatorTest`, for a representative of each transform, add a test that loads the MIGRATED rule text and asserts identical firing to the old semantics over records: `{installer=null,...}` (sideloaded → fires for type-A rules), `{installer="com.android.vending",...}` (store → not fired / exempt), `{installer="com.evil",...}` (→ fires). Use the existing `trusted_installer_db` lookup stand-in pattern at `SigmaRuleEvaluatorTest.kt:113-131`. Cover androdr-010 (A), androdr-011 (A+B), androdr-089 (B with `is_sideloaded` selection), androdr-068 (B, separate filter). Run → FAIL (rules not yet migrated).
- [ ] **Step 2: Apply Transform A** to {010,011,012,013,014,016,017,069} in BOTH copies (bundled + mirror), per the transform + rule table. Apply **Transform B** to {011,068,089} in BOTH copies.
- [ ] **Step 3: Update `Rule089OtpTheftTest`** — it builds records with `"from_trusted_store" to !sideloaded`; change the impersonation-backstop assertion to drive the exemption via `"installer"` (`com.android.vending` = exempt/store; a non-store installer on a sideloaded impersonator = still fires). Update the `SigmaRuleEvaluatorTest` "rule 011 pattern" regression similarly (installer-based).
- [ ] **Step 4:** Run `SigmaRuleEvaluatorTest`, `Rule089OtpTheftTest`, `BundledRulesSchemaCrossCheckTest`, `BundledMirrorParityTest` → all GREEN (parity holds because both copies edited identically). If parity fails, a copy diverged — reconcile.
- [ ] **Step 5: Commit** the bundled-side files + tests (AndroDR-tracked). Mirror files are edited in the working tree but committed in the submodule by the controller (Task 4). `git status` should show the submodule dirty.

## Task 4: Audit drop + submodule orchestration + manifest

**Files:** `known-oem-prefixes.yml` (3 copies); submodule git; `rules.sha256`.

- [ ] **Step 1:** Apply the audit's 4-entry `trusted_installers` drop — remove `com.samsung.android.scloud`, `com.samsung.android.spay`, `com.sec.android.app.sbrowser` from the samsung block and `com.coloros.safecenter` from the oppo block — in all THREE `known_oem_prefixes.yml` copies (bundled + fixture + submodule mirror), byte-equal. Keep `updatecenter`, `watchmanager`, `facebook.system`. Update `OemPrefixResolverTest` assertions for the dropped entries.
- [ ] **Step 2 (controller/submodule):** On an `android-sigma-rules` branch `feat/136-phase2-trusted-installer-rules`: stage the migrated `app_scanner/androdr_*.yml` mirror rules, `ioc-lookup-definitions.yml`, and `ioc-data/known-oem-prefixes.yml`. Regenerate `rules.sha256`:
```bash
cd third-party/android-sigma-rules
while read -r f; do printf '%s  %s\n' "$(sha256sum "$f" | cut -d' ' -f1)" "$f"; done < rules.txt > rules.sha256
```
Commit + push the branch. Bump the AndroDR submodule pointer to that branch commit; commit in the AndroDR PR branch.
- [ ] **Step 3:** `./gradlew testDebugUnitTest lintDebug detekt` on the branch-pinned state → all GREEN, including `RuleManifestIntegrityTest` (manifest now matches), `BundledMirrorParityTest`, the cross-checks. (submodule-check will be red until go-live re-point — by design.)

## Task 5: Ceremony, PR, gated go-live, on-device, close

- [ ] **Step 1:** Push the AndroDR PR B branch; open PR (base main), body `Refs #136` (Phase 3 closes #136); note the batched audit drop, the go-live gate, and submodule-on-branch.
- [ ] **Step 2:** Full 4-agent ceremony on the PR diff. Reconcile findings (one fix wave + one scoped re-review).
- [ ] **Step 3:** Confirm CI: build-and-test + lint-and-detekt + instrumented green; submodule-check red-by-design.
- [ ] **Step 4: ⛔ GATED go-live** (user confirms it's OK to make the feed live): merge `android-sigma-rules` branch → main with a **merge commit** (preserve reachability). Re-point the AndroDR submodule to the rules-main commit on the PR branch; CI goes fully green; merge the AndroDR PR.
- [ ] **Step 5: On-device (Fold 2):** `pm clear`, install a sideloaded fixture (null/`com.evil` installer) → confirm the migrated rules (e.g. androdr-011) still fire; install with `-i com.sec.android.app.samsungapps` → confirm exempt. Confirm `feed_health` shows the fresh rules fetch. (Cross-vendor rejection: unit-proven; redaction caveat per [[reference_installer_name_redaction]].)
- [ ] **Step 6:** Comment on #136 (Phase 2 done; Phase 3 = delete the `from_trusted_store` boolean now that no rule references it; then is_sideloaded/is_known_oem_app). File any residual.

## Self-review
- Every `from_trusted_store` usage covered: type-A {010,011,012,013,014,016,017,069}, type-B {011,068,089}; 089's `is_sideloaded` selection intentionally untouched (Phase 3/cluster work). ✔
- `blockEstablishesSideload` extended before rules change (backward-compatible), preventing a mid-migration cross-check break. ✔
- Typo/over-fire risk guarded by the registry cross-check (Task 1). ✔
- Manifest regen + parity for the rule files (in `rules.txt`), unlike the audit's YAML. ✔
- Audit drop batched into the same go-live. ✔
- `from_trusted_store` boolean stays emitted (parallel run); Phase 3 removes it. ✔
