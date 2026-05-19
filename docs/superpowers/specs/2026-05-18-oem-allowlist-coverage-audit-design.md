# Spec: OEM allowlist coverage audit + Honor data fix

**Issue:** TBD (file before plan execution; covers the tester-reported `androdr-015` FP storm on an Honor device).
**Scope of this spec:** Fill missing prefixes in every conditional block of `known_oem_prefixes.yml` (Honor-first, all-OEM second) and build a repeatable audit script. No mechanism changes.
**Out of scope:** Modifying `androdr-015`. Changing `OemPrefixResolver` API or its conditional-matching mechanism. Cert-based OEM trust validation. Any UI for viewing applied allowlists.
**Date:** 2026-05-18

---

## Why

A tester running AndroDR on an Honor device reported the `androdr-015` "Unrecognized System App" rule firing many times. The rule fires on `is_system_app && !is_known_oem_app`; the `huawei` conditional block in `known_oem_prefixes.yml` matches `manufacturer/brand=honor` correctly but only lists `com.huawei.` and `com.honor.` as prefixes. Modern Honor devices (post-2020 spinoff from Huawei) ship with MagicOS, whose system packages live under `com.hihonor.*`, `com.magic.*`, `com.gtp.*`, and other namespaces — none currently allowlisted.

The infrastructure to prevent this class of FP exists and is correct (built in #90, April 2026):

- `OemPrefixResolver` takes a `DeviceIdentity (manufacturer, brand)` at every call site.
- YAML schema splits `unconditional:` (AOSP, chipset, custom-ROM, trusted installers) from `conditional:` per-vendor blocks gated by `manufacturer_match` / `brand_match`.
- Remote refresh path (`PREFIXES_URL`) lets the YAML update without an app release.

The bug is purely **data coverage**: the `huawei` block doesn't enumerate Honor's modern prefix families, so legitimate Honor system apps fall through to `androdr-015`. The same gap likely exists for other OEMs whose prefix lists haven't been audited since #90 landed. The fix is to (a) close the Honor gap, (b) audit every conditional block once against authoritative sources, and (c) leave behind a repeatable script so future audits — when a new OEM release ships, when a new vendor enters the market — produce a reviewable diff in minutes.

## Non-goals

- **No rule changes.** `androdr-015` was already softened in #147 (HIGH "Firmware Implant" → LOW "Unrecognized System App"). Post-data-fix residual hits will genuinely mean "system app the allowlist doesn't know about," which is correct LOW-severity informational behavior.
- **No `OemPrefixResolver` API change.** Conditional matching, `DeviceIdentity`-aware lookups, and the remote refresh path are all working.
- **No mechanism additions** (cert-based trust, signing-validation, etc.). Worthwhile follow-up; outside this scope.
- **No LLM-assisted prefix discovery.** Authoritative sources only — UAD-list, plexus-data, vendor developer docs.
- **No new tooling beyond the one audit script.** Specifically no Gradle task wrapping it (the script is occasional human-run, not part of CI).

## Architecture

Two artifacts ship together:

1. **Updated `app/src/main/res/raw/known_oem_prefixes.yml`** — same schema, expanded conditional blocks. Bumped `version:` field.
2. **`scripts/audit_oem_prefixes.py`** — repeatable diff tool. Fetches UAD-list (and optionally plexus-data), maps UAD vendor tags onto our conditional blocks, computes per-block additions, prints a Markdown report.

`OemPrefixResolver`, scanners, rule engine, and bugreport modules are unchanged.

## The audit script

### Inputs

- Universal Android Debloater (UAD) Next-Gen repo's per-vendor JSON files at `https://raw.githubusercontent.com/Universal-Debloater-Alliance/universal-android-debloater-next-generation/main/resources/assets/uad_lists.json` (single consolidated JSON; cached in `build/audit-cache/uad_lists.json` with HTTP ETag respect).
- Local `app/src/main/res/raw/known_oem_prefixes.yml`.
- Optional: plexus-data per-package JSON (URL TBD by implementer; if rate-limited or unstable, skip on first iteration — UAD coverage is the primary signal).

### Vendor-tag → conditional-block mapping

A static mapping table inside the script translates UAD's vendor field (`samsung`, `huawei`, `oneplus`, `oppo`, `xiaomi`, etc.) onto our YAML's conditional-block keys. Special cases:

- UAD `huawei` → our `huawei` block (covers both `manufacturer=huawei` and `manufacturer=honor`).
- UAD `oneplus` → our `oneplus` block (today separate from `oppo`).
- UAD entries with vendor `aosp` / `google` are routed to a "skip; covered unconditionally" bucket and not proposed for any conditional block.
- UAD entries with no clear vendor mapping land in an "unmapped" bucket and are reported separately so the human can decide.

### Prefix derivation

For each UAD package name (`com.example.subpackage.Foo`), derive prefix down to the second segment: `com.example.`. Group by `(vendor, prefix)`. Deduplicate.

### Diff and output

For each conditional block:

```
## huawei  (manufacturer_match: huawei, honor)

Currently allowlisted (2):
  - com.huawei.
  - com.honor.

Proposed additions from UAD (N):
  - com.hihonor.    # from: com.hihonor.appmarket, com.hihonor.calendar, com.hihonor.android.launcher (3 packages)
  - com.magic.      # from: com.magic.recommend (1 package)
  - com.gtp.        # from: com.gtp.nextlauncher (1 package)
  ...

Currently allowlisted but absent from UAD (N):
  - com.huawei.     # 0 UAD packages match (likely fine — UAD focuses on debloat targets, not all system apps)
```

Output is human-readable Markdown to `build/oem-audit-report.md` and stdout. Exit code 0 always — the script reports, it doesn't enforce.

### Repeatability

The script can be re-run any time. The cached UAD JSON is refreshed when ETag changes. The mapping table evolves as UAD adds vendors. Committed alongside the YAML for next-time use.

### Script test

`scripts/test_audit_oem_prefixes.py` uses a fixture UAD JSON + minimal YAML and asserts the diff output matches an expected golden file. Run via `python3 -m unittest scripts/test_audit_oem_prefixes.py` from the repo root. No new gradle task.

## YAML changes

For each conditional block in `known_oem_prefixes.yml`, add prefixes the audit surfaces. Concrete plan: run the script first, then edit the YAML based on the report. Likely additions, sight-unseen:

| Block | Existing | Likely additions |
|---|---|---|
| `huawei` (incl. Honor) | `com.huawei.`, `com.honor.` | `com.hihonor.`, `com.magic.`, `com.gtp.`, possibly `com.huawei.android.` (already covered by prefix) |
| `samsung` | full set from #90 | likely complete; audit confirms |
| `xiaomi` | `com.miui.`, `com.xiaomi.`, `com.mi.`, `com.duokan.`, `com.mipay.` | possibly `com.poco.`, `com.redmi.`-specific apps |
| `oppo` | `com.oppo.`, `com.coloros.`, `com.heytap.`, `com.oplus.` | likely complete |
| `oneplus` | `com.oneplus.` | audit may surface OnePlus partnership apps |
| `vivo` | `com.vivo.` | audit may surface IQOO-specific prefixes |
| `asus` | `com.asus.` | likely complete |
| others | per #90 | audit confirms |

May add **new conditional blocks** for vendors the audit surfaces but the YAML doesn't currently model:

- `nothing` (`com.nothing.*`)
- `transsion` / `tecno` / `infinix` (African/SEA market — `com.transsion.`, `com.tecno.`, `com.infinix.`)
- Any other vendor with ≥ 3 UAD entries.

Each new block follows the existing schema (`manufacturer_match`, `brand_match`, `strict_prefixes`).

Top-of-file `version:` field bumped to the merge date.

### Comment convention

Each added prefix gets a trailing comment with provenance:

```yaml
- "com.hihonor."   # UAD: appmarket, calendar, launcher (3 packages)
```

Makes future audits easy to read; cites why each entry exists.

## Rule-repo mirror

Per project convention, the YAML is mirrored to the upstream rule repo so devices that have downloaded the remote prefix list pick up the additions on next refresh.

Confirmed target: `OemPrefixResolver.PREFIXES_URL` points at `https://raw.githubusercontent.com/android-sigma-rules/rules/main/ioc-data/known-oem-prefixes.yml`. That is the same repo the `third-party/android-sigma-rules` submodule tracks. Mirror workflow:

1. In the submodule worktree at `third-party/android-sigma-rules/`, edit `ioc-data/known-oem-prefixes.yml` to match the bundled version. Open a PR against `android-sigma-rules/rules` upstream; merge.
2. Optionally bump the submodule pointer in AndroDR in a separate commit.

The submodule pointer bump is **not required** for the fix to work on-device — the remote-fetch path uses `PREFIXES_URL` directly, not the submodule. The pointer bump is for build-time validation tests that load the submodule YAML.

The submodule pointer bump is **not required** for the fix to work on-device — the remote-fetch path uses the URL directly, not the submodule pointer. The pointer bump is for build-time validation tests that load the submodule YAML.

## Testing

### `OemPrefixCoverageRegressionTest` (new)

Parameterized JUnit test in `app/src/test/java/com/androdr/ioc/OemPrefixCoverageRegressionTest.kt`. Each parameter is a `(deviceIdentity, expectedAllowedPackage)` pair drawn from the audit report. The test asserts `OemPrefixResolver.isOemPrefix(expectedAllowedPackage, deviceIdentity)` returns true.

Representative fixture cases:

```kotlin
listOf(
    Case(DeviceIdentity("honor", "honor"), "com.hihonor.appmarket"),
    Case(DeviceIdentity("huawei", "huawei"), "com.huawei.systemmanager"),
    Case(DeviceIdentity("samsung", "samsung"), "com.samsung.android.sm"),
    Case(DeviceIdentity("xiaomi", "redmi"), "com.miui.gallery"),
    Case(DeviceIdentity("nothing", "nothing"), "com.nothing.launcher"),
    // ... one per conditional block, drawn from the audit report's "Proposed additions"
)
```

Locks coverage. A future YAML edit that accidentally drops a prefix breaks the build with a precise message.

### Existing tests

`OemPrefixResolverTest`, parser tests, conditional-matching tests — all continue to pass. Schema is unchanged; we're only adding entries to existing collections.

### Adversary regression

The `androdr-015` FP doesn't have a dedicated adversary harness fixture; the regression test above is the contract. If issue #90's adversary fixture exists in `test-adversary/`, no changes needed — those tests verify the prefix-spoofing defense, which our additions don't weaken (every prefix we add is gated to its correct vendor block).

## Rollout

Single PR targeting `main`. Branch: `fix/oem-allowlist-audit`. Sequence:

1. Land the audit script + script test.
2. Run the script. Capture `build/oem-audit-report.md`. (Not committed; build/ is gitignored.)
3. Edit `known_oem_prefixes.yml` per report. Bump `version:` field.
4. Add `OemPrefixCoverageRegressionTest` with cases drawn from the audit.
5. Run `./gradlew :app:testDebugUnitTest` — all pass.
6. Mirror to `android-sigma-rules` upstream as a separate PR; merge.
7. Optionally bump submodule pointer in this PR or a follow-up.

No feature flag, no migration. The change is additive: existing devices keep working; Honor (and other under-served devices) get cleaner findings.

## Risks

- **UAD-list accuracy.** UAD's catalog includes some questionable entries — packages marked "Aggressive" removal that are sometimes legitimate, vendor-injected ads with reverse-DNS that resembles OEM namespaces. The human review step exists exactly to catch this. Don't auto-import.
- **New conditional blocks for under-modelled vendors** (Nothing, Transsion, etc.) introduce more YAML — verify the mapping table doesn't accidentally bucket their packages elsewhere.
- **Prefix granularity.** Down-to-second-segment grouping (`com.hihonor.`) can occasionally over-allowlist (e.g., a hypothetical `com.hihonor.malicioustracking` would be classified as OEM). This is the existing trade-off the conditional-matching design accepts — not introduced by this work. Document as a known limitation in the YAML header.
- **Remote-fetch update visibility.** Devices that have already downloaded the remote YAML will keep using the cached copy until the next refresh. The refresh interval is governed by `OemPrefixResolver`'s own cache logic; users with stale caches see the fix on next manual update or next scheduled refresh. No code change needed in this PR.

## Acceptance criteria

- [ ] `scripts/audit_oem_prefixes.py` runs on a clean checkout, produces a Markdown report against the current YAML.
- [ ] `scripts/test_audit_oem_prefixes.py` passes locally.
- [ ] `known_oem_prefixes.yml` includes Honor/MagicOS prefixes (`com.hihonor.`, `com.magic.`, `com.gtp.` at minimum) under the `huawei` block.
- [ ] Every other conditional block has been reviewed against the audit report; gaps closed.
- [ ] `OemPrefixCoverageRegressionTest` passes with at least one case per conditional block.
- [ ] Existing `OemPrefixResolverTest` still passes.
- [ ] YAML `version:` field bumped.
- [ ] Mirror PR opened against `android-sigma-rules` upstream (link in PR body).
- [ ] Tester re-confirmation pending post-merge — flagged in PR description, not blocking.
