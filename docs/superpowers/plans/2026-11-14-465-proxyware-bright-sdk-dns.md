# Bright SDK DNS Detection (PROXYWARE) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Put Bright SDK's infrastructure domains on the threat list under a new `PROXYWARE` category and reword `androdr-003` so it distinguishes C2, data-broker and residential-proxy entries.

**Architecture:** Data and rule text live in the `android-sigma-rules` repo and reach devices through the 12-hour feed. AndroDR pins that repo as a submodule; its unit tests gate the change before the rules branch merges (safe ordering). One Kotlin line changes because a test requires the app's category set to equal the schema's.

**Tech Stack:** YAML + JSON Schema + Python validators (rules repo); Kotlin + JUnit (AndroDR).

**Spec:** `docs/superpowers/specs/2026-11-14-465-proxyware-bright-sdk-dns-design.md`

## Global Constraints

- Category string is exactly `PROXYWARE`; family is exactly `Bright SDK (residential proxy)`; entry severity `HIGH`; `source: "threat_research"`; `block_by_default: true`.
- Exactly fourteen indicators: `brdtnet.com`, `bright-sdk.com`, `luminatinet.com`, `luminati-china.io`, `brdtest.com`, `l-err.biz`, `cdn-cloud.b-cdn.net`, and the exact hosts `perr.l-agent.me`, `p.l-conn.net`, `zagent108/110/111/112/113.l-cdn.com` (owner ruling at the build gate).
- Must NOT be listed: `brightdata.com`, `luminati.io`, `b-cdn.net`, and the parents `l-agent.me`, `l-conn.net`, `l-cdn.com`.
- `validation/allowed-sources.json` gains `https://blog.includesecurity.com/` and `https://blazskufca.com/projects/webos-brightdata/` (owner-approved).
- `androdr-003` keeps its title, `level: critical`, detection and display category. Only `description`, `display.guidance` and `remediation` change, to the exact text in the spec.
- No household or LAN detail (dates, flow counts, device roles) in any committed file; references are public URLs only.
- Safe ordering: rules branch → AndroDR PR on that branch commit → `build-and-test` green → merge rules → re-point submodule.
- JDK 21 is the Temurin under `~/.gradle/jdks`, not Android Studio's.

## Review Focus

- A lookup of `www.brightdata.com` or `luminati.io` must not match (Task 2 test asserts absence).
- A lookup of another BunnyCDN tenant (`other.b-cdn.net`) must not match: only the exact host is listed (Task 2 test asserts `b-cdn.net` absent).
- An install on an older build drops the unknown category; the family string alone must still tell the person what kind of threat it is (Task 2 test pins the family text).
- A rule edited without a regenerated manifest is silently dropped on devices (`RuleManifestIntegrityTest`, `IocDataManifestIntegrityTest` run in Task 2).
- The bundled rule copy drifting from the delivered rule (Task 2 test compares remediation text of both).

---

### Task 1: Rules repo — category, entries, rule text, manifests

**Files** (all under `third-party/android-sigma-rules/`, branch `feat/proxyware-bright-sdk` from `origin/main`):
- Modify: `validation/ioc-entry-schema.json` (category enum)
- Modify: `ioc-data/c2-domains.yml` (append section)
- Modify: `validation/blocked-baseline.txt` (fourteen domains)
- Modify: `dns_monitor/androdr_003_domain_ioc.yml`
- Regenerate: `rules.sha256`, `ioc-data.sha256`

- [ ] **Step 1:** Add `"PROXYWARE"` after `"DATA_BROKER_SDK"` in the schema enum.
- [ ] **Step 2:** Append the fourteen entries to `c2-domains.yml` under a comment header `# Residential-proxy SDK — Bright SDK (Bright Data, formerly Luminati) — AndroDR #465`, each with the shared fields from Global Constraints, a one-line description of the host's role, and a reference: the Include Security post for `brdtnet.com`, `bright-sdk.com`, `luminatinet.com`; the webOS teardown for the other four.
- [ ] **Step 3:** Add the fourteen domains to `validation/blocked-baseline.txt`.
- [ ] **Step 4:** Replace `description`, `display.guidance` and `remediation` in `androdr_003_domain_ioc.yml` with the spec's text.
- [ ] **Step 5:** Regenerate both manifests with the two commands in `CLAUDE.md`.
- [ ] **Step 6:** Verify locally, expecting all to pass:
  `python3 validation/validate-ioc-data.py ioc-data/c2-domains.yml`;
  `python3 validation/validate-ioc-complementarity.py --file ioc-data/c2-domains.yml --mode strict`;
  `python3 validation/validate-rule.py dns_monitor/androdr_003_domain_ioc.yml`;
  `python3 -m pytest -q validation/test_blocking_baseline.py validation/test_cold_start_seeds.py validation/test_check_reference.py`;
  `sha256sum -c rules.sha256 --strict --quiet && sha256sum -c ioc-data.sha256 --strict --quiet`.
- [ ] **Step 7:** Commit, push the branch, open the rules PR (do not merge).

### Task 2: AndroDR — category, bundled copies, regression gate

**Files** (branch `feat/465-proxyware-bright-sdk`):
- Create: `app/src/test/java/com/androdr/ioc/ProxywareBrightSdkIocTest.kt`
- Modify: `app/src/main/java/com/androdr/ioc/IocSanitizer.kt` (CATEGORIES)
- Modify: `app/src/main/res/raw/sigma_androdr_003_domain_ioc.yml` (copy of the submodule file)
- Modify: `app/src/main/res/raw/known_bad_domains.json` (via `scripts/merge-ioc-data.py`, only if the script adds them)
- Modify: `app/src/test/java/com/androdr/reporting/DnsAttributionReportTest.kt:58` (guidance string)
- Modify: submodule pointer; add the spec and this plan.

- [ ] **Step 1: Write the failing test** `ProxywareBrightSdkIocTest`, reading the pinned submodule files the way `IocDataManifestIntegrityTest` locates them:
  - `bright sdk domains are listed as proxyware`: for each of the fourteen indicators, the `c2-domains.yml` entry exists with `category == "PROXYWARE"`, `family == "Bright SDK (residential proxy)"`, `severity == "HIGH"`.
  - `corporate, shared-cdn and unverified domains are not listed`: none of the six forbidden domains is an indicator.
  - `sanitizer keeps the proxyware category`: `IocSanitizer.sanitize` of an indicator with category `PROXYWARE` returns `PROXYWARE`.
  - `androdr-003 tells proxy sdk apart from c2`: the submodule rule's remediation contains a line containing `Residential-proxy SDK` and `Uninstall that app`; its guidance does not contain `known C2 server`; the bundled `res/raw` copy has byte-identical content to the submodule rule.
- [ ] **Step 2:** Bump the submodule to the Task 1 commit; run the new test class; expect the sanitizer and bundled-copy tests to FAIL.
- [ ] **Step 3:** Add `"PROXYWARE"` to `IocSanitizer.CATEGORIES`; copy the rule file to `res/raw`; run `python3 scripts/merge-ioc-data.py` in the mode its `check` expects and keep its output; fix the string in `DnsAttributionReportTest`.
- [ ] **Step 4:** Run `./gradlew testDebugUnitTest detekt lintDebug` (delete `app/build/test-results` first); expect green.
- [ ] **Step 5:** Commit, push, open the AndroDR PR with `Refs #465` (the app-scan rule keeps the issue open).

### Task 3: Land in safe order

- [ ] **Step 1:** Wait for AndroDR `build-and-test` green (`submodule-check` red is expected).
- [ ] **Step 2:** Wait for rules `validate` green; merge the rules PR.
- [ ] **Step 3:** Re-point the submodule at rules main, push, wait for `ci-success`, merge the AndroDR PR.
