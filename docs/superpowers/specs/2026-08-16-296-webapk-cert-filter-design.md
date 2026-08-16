# #296 — WebAPK false positive: cert-anchored filter on androdr-010

**Date:** 2026-08-16
**Issue:** #296 — WebAPKs (`org.chromium.webapk.*`) flagged as "Sideloaded Application" (androdr-010)
**Status:** Approved design, pre-implementation

## Problem

PWAs installed via Chrome are minted as WebAPKs by Google's WebAPK minting
service. Their package names are per-device randomized
(`org.chromium.webapk.<hash>`), so no package-name allowlist can ever cover
them; their installer is not a store, so `from_trusted_store` is false; and
they are not system apps. androdr-010's selection therefore matches every
installed PWA — high-volume false positive affecting every public tester
(first observed on a real device report, 2026-08-15, WebAPK "Idraa").

Hard constraints:

- **Cert-anchored only.** The package prefix is spoofable by any sideloaded
  APK. The one unforgeable property of a minted WebAPK is its signing cert:
  all WebAPKs are signed by Google's minting service.
- **Chrome must NOT become a trusted installer** (#284 rationale: trusting a
  browser as installer exempts every browser-downloaded APK).
- **R1 capability constraint** (`validation/ioc-lookup-definitions.yml`): no
  new `ioc_lookup` name may appear in a delivered rule until R1 rollout is
  fleet-uniform.
- **Emitter purity** (#136/R1 direction): the emitter reports facts; trust
  judgments live in the rule engine.

## Decision

Add a cert-anchored exemption filter to androdr-010 itself. No emitter
change, no new `ioc_lookup` name, no new parser construct.

```yaml
detection:
    selection:
        is_system_app: false
        from_trusted_store: false
        is_known_oem_app: false
    filter_known_good:
        package_name|ioc_lookup: known_good_app_db
    filter_verified_webapk:
        package_name|startswith: "org.chromium.webapk."
        cert_hash: "<Google WebAPK minter cert SHA-256, lowercase hex>"
    condition: selection and not filter_known_good and not filter_verified_webapk
```

Two entries in one selection map AND together: the exemption requires both
the WebAPK namespace and Google's minting cert. If Chromium documents
multiple valid minter certs, `cert_hash` becomes a YAML list (OR semantics).

The cert placeholder above is intentional until the ground-truth procedure
below has produced a double-confirmed value.

### Approaches considered and rejected

- **Emitter-side exemption** (fold cert check into `is_known_oem_app` in
  `AppScanner`, cert data in `known-oem-prefixes.yml`): rejected on the
  emitter-purity principle — it reintroduces a trust judgment into the
  emitter that #136/R1 deliberately removed, and it silently exempts minted
  WebAPKs from the full 15-rule trust family (including impersonation rules
  014/077, which should stay live on WebAPKs: any website can get a PWA
  minted under an arbitrary display name).
- **Hardcoded cert constant in Kotlin**: same objections plus cert rotation
  requires an app release.
- **New `webapk_minter_cert_db` ioc_lookup + rule filter**: R1 constraint —
  current 610/611 binaries would fail-closed skip androdr-010 entirely
  (detection regression + "RULES NOT EVALUATED" in every report) until the
  fleet reaches a binary registering the name.

## Why this is fleet-safe (verified against source, not assumed)

- `startswith` has been in `SigmaRuleParser` since the commit that created
  the parser (8411738) and is used by delivered rules androdr-066/077 —
  every fielded binary parses it.
- Multi-`not` conditions are fielded (androdr-062/066/068).
- Exact match is case-insensitive (`SigmaRuleEvaluator`), and the emitter
  produces lowercase hex anyway.
- Remote rules replace bundled same-id rules (`SigmaRuleEngine.setRemoteRules`),
  so the feed-delivered edited rule takes effect on every fielded binary
  within the 12h fetch cycle — **no app release is required for the fix to
  reach the fleet**, including pre-R1 binaries.
- No new lookup name → the R1 constraint is untouched; no fail-closed skips
  anywhere; no Play per-version-install check needed.

## Field-contract audit (emitter → rule engine)

Five of the six field dependencies are empirically proven by the FP itself
(the rule fired on a real WebAPK, so `is_system_app: false`,
`from_trusted_store: false`, `is_known_oem_app: false` matched, and
`package_name` carried the WebAPK name; `filter_known_good` correctly stayed
non-matching).

The one new dependency is `cert_hash`:

- Batch query requests signing info (`GET_SIGNING_CERTIFICATES`, pre-P
  fallback `GET_SIGNATURES`) — `AppScanner.kt`.
- `extractCertHashes` hashes the first signer from
  `signingInfo.apkContentsSigners` → SHA-256 lowercase hex — the same path
  `cert_hash_ioc_db` malware matching uses in production today. WebAPKs are
  ordinary single-signer APKs.
- Null `cert_hash` cannot NPE the evaluator (`Any?.toString()` → `"null"`,
  no match) — the filter simply doesn't apply and the rule fires.

Known degradations, both fail-safe (more alerts, never less detection):

1. If the extended `getInstalledPackages` call fails, the fallback requests
   only `GET_PERMISSIONS` → `cert_hash` null for that scan → exemption
   lapses → status-quo FP for that scan. Pre-existing accepted degradation
   (equally disables malware-cert matching for that scan).
2. Per-package cert extraction failure → null → status-quo FP for that app.

The single unproven link — emitted `cert_hash` for a real on-device WebAPK
equals the apksigner-derived minter cert — is exactly what the on-device
positive test proves before anything merges to rules main.

## Cert ground truth (gate: both sources must agree)

1. Pull a real minted WebAPK from the Fold 2 (SM-F916B):
   `pm list packages | grep webapk` → `pm path` → `adb pull` →
   `apksigner verify --print-certs` → SHA-256.
2. Independently obtain Chromium's `WebApkValidator` expected-signature
   constant from Chromium source.
3. The value enters the rule YAML only if both agree. Disagreement stops the
   work for investigation. If Chromium documents multiple valid certs, all
   go into the list.

## Failure behavior

Every failure direction lands on status-quo FP, never lost detection:
wrong/rotated cert → filter never matches → FP persists; malformed rule edit
→ caught by rules-repo `validate` CI, `RuleManifestIntegrityTest`, and
AndroDR unit tests before reaching main; feed unreachable → bundled old rule
persists.

Spoof safety: `org.chromium.webapk.evil` signed by anything other than the
minter cert fails the `cert_hash` conjunct → androdr-010 fires. The minter
cert on a non-WebAPK package name fails the prefix conjunct → fires
(conservative by construction).

## Rollout — CLAUDE.md safe-ordering, manifest regen required

androdr-010 is listed in `rules.txt`, so the edit requires regenerating
`rules.sha256` and the strict ordering:

1. `android-sigma-rules` branch: edit `app_scanner/androdr_010_sideloaded_app.yml`
   + regenerate `rules.sha256`.
2. AndroDR PR: bump submodule to the branch commit; mirror the edit into
   bundled `app/src/main/res/raw/sigma_androdr_010_sideloaded_app.yml`
   (cold-start parity); add tests. CI green (`RuleManifestIntegrityTest`,
   `BundledRulesSchemaCrossCheckTest`).
3. On-device verification on the Fold 2 (debug build, bundled rule) — see
   Testing. Only after it passes:
4. Merge the rules-repo branch to main (12h feed goes live for the fleet).
5. Re-point the submodule at the resulting main commit; merge the AndroDR PR.

Bundled copy ships in the next release (612+); the feed covers all fielded
binaries meanwhile.

## Testing

- **Rule-level unit tests** (evaluator with crafted field maps against the
  updated bundled rule): verified-WebAPK map (prefix + minter cert) →
  silent; spoof (prefix, wrong cert) → fires; minter cert on non-WebAPK
  package → fires; null `cert_hash` → fires; plain sideload → fires
  (regression guard); known-good app → silent (existing filter intact).
- **Taxonomy check**: `cert_hash` and `package_name` registered as
  `app_scanner` fields in `logsource-taxonomy.yml` (expected already true;
  verify, since #268 made the taxonomy the field-lint trust root).
- **On-device (Fold 2), before rules-main merge**: install a PWA from
  Chrome → scan → no androdr-010 for it; adb-install a debug-signed fake
  `org.chromium.webapk.evil` → androdr-010 fires (adb leaves installer
  null → `from_trusted_store` false — the reliable on-device negative, per
  the installer-name-redaction constraint).
- Existing cross-check and manifest tests stay green.

## Out of scope

- Other trust-family rules (011–017, 067–069, 077, 087–089) keep seeing
  WebAPKs as sideloaded facts — deliberately: impersonation rules stay live
  on minted WebAPKs. If WebAPK FPs surface on specific rules later, the same
  filter pattern applies per-rule as pure feed updates.
- No changes to `trusted_installers` (Chrome stays untrusted), the
  `known_good_app_db` closure, `ioc-lookup-definitions.yml`, or any emitter
  code.
- #136 Phase 2/3 remain parked; this design intentionally leaves
  `from_trusted_store` untouched so the Phase-2 migration is unaffected.

## Process

Implementation via subagent-driven execution; full 4-agent review ceremony
(correctness, code-quality, architect, code-security — the security reviewer
specifically prompted to attack the filter's spoofability). PR targets
`main` with `Closes #296`.
