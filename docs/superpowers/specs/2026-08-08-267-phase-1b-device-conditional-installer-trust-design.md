# Phase 1b — Device-Conditional Trusted-Installer Data (Design)

**Issue:** #280 (Phase 1b of #267 / #136). Follows Phase 1 (PR #279, merged as `935c182`).

## Problem

Phase 1 made `from_trusted_store` rest on exact membership in a **flat, unconditional** `trusted_installers` list, killing the *prefix* forgery (`com.google.play.svcupdate`). The residual: because the list is device-independent, naming an installer `com.sec.android.app.samsungapps` on a **non-Samsung** device still confers trust — an OEM store is trusted on every device, not just its own ecosystem. This is the *exact-name cross-device* forgery.

The fix is to make installer trust **device-conditional**, reusing the machinery that already gates OEM package *prefixes* per device (`known_oem_prefixes.yml` conditional blocks keyed on `manufacturer_match`/`brand_match`, #90). Play (and other genuinely cross-vendor installers) stay unconditional; OEM stores become trusted only on their own ecosystem.

## Deployment constraint (shapes the whole design)

The app fetches `ioc-data/known-oem-prefixes.yml` from `android-sigma-rules` **main every 12h and replaces the allowlist wholesale** (`OemPrefixResolver.refresh` → `data.set(parsed)`). `OemPrefixMirrorParityTest` enforces bundled == mirror byte-equality at all times. Therefore, moving OEM stores out of the flat list and into conditional blocks in one shot would make **un-updated apps** (whose parser reads only the flat `unconditional.trusted_installers`) stop trusting OEM stores the moment they fetch the new YAML — over-flagging OEM-store installs as sideloaded until the app updates.

**Chosen migration strategy: parser-first, accept the small window.** Ship the device-conditional parser first; flip the YAML only after the parser is deployed. The transitional regression is an **over-flag** (annoying), not a detection miss, and the user base is small and self-updating, so the window is low-impact. Rejected alternatives: dual-location transitional YAML (zero window but adds parser precedence logic and a temporarily redundant feed) and app-side-only data (avoids the hazard but fragments the single-source-of-truth mirror architecture).

## Architecture — two sequenced deliverables (own PRs)

### 1b-i — Parser capability (AndroDR-only; no YAML/mirror/submodule change)

Extend the existing per-device prefix machinery to installers:

- **`parseOemPrefixYaml`** learns a per-block `trusted_installers:` list inside each conditional block, parsed with the same guards as the top-level list (`length >= MIN_INSTALLER_LEN`, contains `.`). The top-level `unconditional.trusted_installers` continues to parse exactly as today.
- **`ConditionalBlock`** gains `installers: Set<String>`.
- **`ApplicablePrefixes`** gains `installers: Set<String>`.
- **`applicablePrefixesFor(device)`** additionally unions unconditional installers + the installers of every matching conditional block — mirroring how it already unions `strict` prefixes, sharing the same `perDeviceCache`.
- **`isTrustedInstaller(installer: String, device: DeviceIdentity): Boolean`** returns `installer in applicablePrefixesFor(device).installers`. The `device` parameter returns (Phase 1 dropped it; the Phase 1 comment-fix forecast this).
- **Callers updated** to pass `localDevice`: `AppScanner` (`fromTrustedStore` computation) and the `trusted_installer_db` `ioc_lookup` closure in `ScanOrchestrator` (already has `localDevice` in scope).
- **Remote sanity caps** (`MAX_INSTALLER_COUNT`, the `refresh()` acceptance count) extended to include per-block installers so the feed-health signal stays accurate.
- **YAML unchanged in this PR:** all 16 installers remain top-level unconditional, so on-device behavior is byte-identical to today; the device-conditional installer path is dormant, exercised only by synthetic unit-test YAML. This is what gets the parser onto devices before any feed change.

### 1b-ii — YAML flip (bundled + mirror + test fixture, parity-gated)

Restructure `known_oem_prefixes.yml` (all three copies identically — `res/raw`, `ioc-data/known-oem-prefixes.yml` mirror, `src/test/resources/raw`):

| Installer | Destination |
|---|---|
| `com.android.vending` | stays `unconditional.trusted_installers` |
| `com.facebook.system` | stays `unconditional.trusted_installers` (cross-OEM partner installer) |
| `com.sec.android.app.samsungapps`, `com.samsung.android.app.updatecenter`, `com.samsung.android.app.watchmanager`, `com.samsung.android.scloud`, `com.samsung.android.themestore`, `com.samsung.android.spay`, `com.sec.android.app.sbrowser` | samsung block `trusted_installers` |
| `com.xiaomi.market`, `com.xiaomi.mipicks` | xiaomi block `trusted_installers` |
| `com.heytap.market`, `com.coloros.safecenter` | oppo block `trusted_installers` |
| `com.huawei.appmarket` | huawei block `trusted_installers` |
| `com.bbk.appstore` | vivo block `trusted_installers` |
| `com.miui.packageinstaller` | **DROPPED** — MIUI sideload-confirmation UI, not a store (same class Phase 1 excluded for `com.android.packageinstaller`) |

- Not in `rules.txt` → **no `rules.sha256` regen** (CLAUDE.md: manifest regen only for `rules.txt`-listed files).
- **Safe-ordering:** edit mirror on an `android-sigma-rules` branch → bump AndroDR submodule to that branch commit in an AndroDR PR → confirm `RuleManifestIntegrityTest` + `OemPrefixMirrorParityTest` green → merge the rules branch to main → re-point submodule at the main commit. **1b-i must be deployed on-device before the mirror change reaches rules-main** (the accepted window).

## Data flow (after both land)

`AppScanner.collectTelemetry`: `fromTrustedStore = installerPackage != null && oemPrefixResolver.isTrustedInstaller(installerPackage, localDevice)` → `isSideloaded = !isSystemApp && !fromTrustedStore && !isKnownOemApp`. A dropper-installed payload whose `installingPackageName` is a foreign OEM store (`com.sec.android.app.samsungapps` on a non-Samsung device) is not in that device's applicable installer set → not trusted → sideloaded → sideload-gated rules fire. Play is trusted on every device.

## Error handling

- Missing per-block `trusted_installers` key → empty set (default), no failure.
- Malformed entries filtered by the existing length/dot guards.
- Legacy-flat YAML path (`parseLegacyFlat`) is unaffected — it has no conditional blocks, so per-block installers are simply absent; its top-level `trusted_installers` still parse as unconditional.
- A conditional block with installers but no `strict_prefixes` must still be retained (today a block is only kept when `strictPrefixes.isNotEmpty()`); the retention condition becomes "has prefixes OR has installers" so an installers-only block isn't dropped. (All Phase 1b blocks also have prefixes, but the guard must not silently drop a future installers-only block.)

## Testing

**Unit (1b-i):**
- `parseOemPrefixYaml` parses a per-block `trusted_installers` list (synthetic YAML).
- `applicablePrefixesFor(device).installers` = unconditional ∪ matching-conditional installers.
- `isTrustedInstaller`: Galaxy Store trusted on a Samsung device, **not** on a Motorola device; Play trusted on both; a foreign-OEM store rejected cross-device (the #280 regression).
- Guard: against the **current** bundled YAML (all 16 top-level), every installer is still trusted on every device (proves 1b-i ships zero behavior change until the flip).
- Block-retention: an installers-only conditional block is retained.

**Unit (1b-ii):**
- `OemPrefixMirrorParityTest` green (bundled == mirror == fixture, byte-equal).
- `OemPrefixResolverTest` updated to assert device-conditional store trust against the **restructured** bundled YAML: Galaxy Store trusted on Samsung, not on Motorola; `com.miui.packageinstaller` no longer trusted anywhere.

**On-device (Fold 2 is Samsung):**
- Install a fixture with `-i com.heytap.market` (OPPO store on a Samsung device) → expect sideloaded (cross-vendor rejection proven on available hardware).
- Install with `-i com.sec.android.app.samsungapps` (home-ecosystem store) → expect trusted, not flagged.
- Driven headlessly via `adb` + `uiautomator` + `input tap` (as in Phase 1), reading the Room DB.

## Review (mandatory)

Both deliverables are security-sensitive (installer trust anchor). Each PR gets the **full 4-agent parallel review ceremony** — **correctness, code-quality, architect, code-security** as four independent adversarial lenses — not the lighter per-task-plus-one-final model that subagent-driven-development defaults to. Size does not reduce this: a small diff on a trust boundary still gets the ceremony. The code-security lens specifically attempts to defeat the device-conditional check (e.g., can a foreign-OEM store name still be trusted cross-device? can an installers-only or malformed block bypass the union? does the remote-feed cap still bound per-block installers?). Findings are reconciled before merge; on-device proof (below) plus green CI are the authoritative gates.

## Scope boundaries & follow-ups

- **In scope:** device-conditional restructure + dropping the one clear sideload-UI entry (`com.miui.packageinstaller`).
- **Follow-up (new issue):** audit the remaining ambiguous Samsung-service entries (`scloud`/`spay`/`sbrowser`/`updatecenter`/`watchmanager`) — kept as-is here, device-gated to Samsung.
- **Not here:** Phase 2 (migrate rules onto `trusted_installer_db`) and Phase 3 (retire the judgment booleans) — tracked under #136.
