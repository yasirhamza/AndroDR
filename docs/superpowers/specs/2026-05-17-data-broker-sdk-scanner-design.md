# Spec: Scanner extension — embedded-SDK signals for data-broker detection

**Issue:** [#168](https://github.com/yasirhamza/AndroDR/issues/168) (parent: data-broker SDK detection rule pack).
**Scope of this spec:** **only** the scanner extension that emits embedded-SDK signals from installed apps. The accompanying rule packs (`installed_app`, `dns`, combination) are explicitly out of scope; they get their own spec→plan→PR cycles in subsequent sessions. This spec is a prerequisite for all of them.
**Date:** 2026-05-17

---

## Why

AndroDR can already see *app-level* signals (package name, cert hash, surveillance permissions, accessibility, device-admin) but cannot see what is *embedded inside* an app. Ad-broker SDKs — X-Mode/Outlogic, Venntel, Mobilewalla, Adsquare, Predicio, Cuebiq, Gravy Analytics, Babel Street — ship as libraries bundled into otherwise-mainstream apps (weather, classifieds, dating, games). Without telemetry from *inside* the APK, the broker pipeline is invisible to us regardless of how good our rule corpus becomes.

The threat model in issue #168 maps to AndroDR's high-risk-user thesis (dissidents, journalists, soldiers, EU/US officials), so closing this gap is detection-strategic, not opportunistic.

## Non-goals

- **No judgment about which SDKs are bad** in the scanner. The scanner emits raw signals (component class names, native library names). The judgment "this class-name pattern is the X-Mode SDK" lives in SIGMA rules, authored separately, against the new fields.
- **No DNS work.** That's a separate sub-project under #168.
- **No dex string scanning.** Deferred to a phase-2 spec if intel coverage gaps emerge. Reason: ~5-10× the per-app CPU cost of the chosen signals, against marginal coverage gain (most broker SDKs register components or ship native libs).
- **No new permissions.** Everything in scope is reachable via existing PackageManager API and world-readable APK paths on non-root stock Android.
- **No root or device-admin elevation.** Confirmed: `applicationInfo.publicSourceDir` returns world-readable APK paths, `PackageInfo.services|receivers|activities|providers` are public API.
- **No retroactive scan of uninstalled apps.** New signals appear on the next full scan after this lands.

## Telemetry schema additions

Two new fields on `AppTelemetry`, both list-type:

| Field (Kotlin)               | Wire name in SIGMA              | Type            | Description                                                                                       |
|------------------------------|----------------------------------|-----------------|---------------------------------------------------------------------------------------------------|
| `embeddedComponentClasses`   | `embedded_component_class`       | `List<String>`  | Concatenation of `.name` from `PackageInfo.services`, `receivers`, `activities`, `providers`. Each entry is a fully-qualified class name (e.g., `com.outlogic.collector.GeoSyncService`). Deduplicated. Capped at `MAX_COMPONENTS_PER_APP=1024` per app to bound memory. |
| `embeddedNativeLibs`         | `embedded_native_lib`            | `List<String>`  | Filenames of `lib/*/*.so` entries inside the APK. ABI prefix stripped — we report `libfoo.so`, not `lib/arm64-v8a/libfoo.so`. Deduplicated across ABIs. Capped at `MAX_NATIVE_LIBS_PER_APP=128`.                                  |

Both fields default to `emptyList()` so the model is fully backward-compatible (no migration of in-place code that constructs `AppTelemetry`).

### Why lists, not booleans

Rules need to match *specific* substrings (e.g., `embedded_component_class|contains: "com.outlogic."`). The SIGMA modifier set already supports `|contains`/`|startswith`/`|all` on list fields (see `permissions` and `service_permissions` precedent).

### Why no provider/receiver/service split

A separate field per component kind would 4× the schema surface and rule complexity for no detection gain — SDK-fingerprinting rules care about the *class name pattern*, not which manifest tag declared it. If we ever need that distinction we add it later (additive change, no migration).

## Scanner changes

Module: `app/src/main/java/com/androdr/scanner/AppScanner.kt`.

Inside the existing `collectTelemetry()` loop, after the current per-app PackageInfo fetch:

```kotlin
val componentClasses = extractComponentClassNames(packageInfo)   // new
val nativeLibs       = extractNativeLibFileNames(applicationInfo) // new
```

Two new package-private functions on `AppScanner`:

- `extractComponentClassNames(packageInfo: PackageInfo): List<String>`
  Iterates `services`, `receivers`, `activities`, `providers`. For each non-null `ComponentInfo`, reads `.name`. Filters blanks. Deduplicates. Caps at `MAX_COMPONENTS_PER_APP`. Returns sorted list (stable output for diffing in scan history).
  Failure mode: if any sub-array is null on this Android version, just skip it; never throw.

- `extractNativeLibFileNames(applicationInfo: ApplicationInfo): List<String>`
  Opens `ZipFile(applicationInfo.publicSourceDir)`, iterates entries matching `Regex("""lib/[^/]+/lib[^/]+\.so""")`, extracts the leaf filename, deduplicates, caps at `MAX_NATIVE_LIBS_PER_APP`, sorts.
  Failure modes: `IOException` (APK unreadable, e.g. some OEM-protected system apps) → log at `Log.w`, return `emptyList()`. `SecurityException` → same. The scan must continue past one bad APK without bailing.

Both functions are `internal` so the existing `AppScannerTest` source-set pattern can reach them.

### Performance budget

Expressed per-app so the budget scales correctly across the wide spread of real-device app counts (median ~80-150 apps; high-risk users ~50-150; power users ~300-500; the project's existing `ScanOrchestrator.kt` comment anchors at ~500 as the conservative ceiling):

- **Manifest components:** PackageInfo is already fetched today for permissions; reading `.services[i].name` is O(1) per component. **Negligible** added cost — sub-millisecond per app.
- **Native libs:** opening a ZipFile is ~5-15 ms on a Z Fold 2; iterating the central directory is another ~1-5 ms; we never decompress. Adds **~20 ms per app worst case**, often less for tiny apps.
- We open the ZipFile once per app, NOT per-rule. Persisted output is reused at rule-evaluation time.

| Device profile | Apps | Added scan time |
|---|---|---|
| Test phone (constrained) | <50 | <1 s |
| Median user | 80-150 | 1.6-3 s |
| Power user | 300-500 | 6-10 s |
| Hard ceiling | 500 (per existing comment) | ~10 s |

Current full scan baseline on a 500-app device: ~14 s. New ceiling after this change: ~24 s. Median users will see scan time go from ~5 s to ~7 s.

The dex-string path was rejected on this exact budget; revisit only if rule-coverage gaps demand it.

### On-device validation against a test phone

The Samsung Z Fold 2 (R3CR300WRRH) attached to the dev VM is a *test* phone with fewer installed apps than a real-user phone. Use it to verify correctness (`embeddedComponentClasses` non-empty for the launcher activity, native libs non-empty for at least Google Play Services) — NOT as a stress test of the perf budget. Stress testing against a 500-app device is out of scope for this spec's acceptance criteria.

### Decoupling guarantee

`AppScanner` has zero knowledge of which class-name patterns or .so filenames are interesting. That intel lives in the SIGMA rule corpus authored separately. This preserves the existing decoupled-telemetry architecture (telemetry collectors are pure emitters; rule engine does all the matching).

## Persistence

`AppTelemetry` is currently persisted via Room as part of `ScanResult` (JSON serialization through the existing converter).

The new fields are list-of-strings, which the existing converter already handles for `permissions`/`service_permissions`/`receiver_permissions`. No schema migration is needed: the JSON column gains two new keys, and missing keys deserialize to `emptyList()` on read.

Confirmed by reading `ScanResult.kt` — it stores `findings: List<Finding>`, not `appTelemetry: List<AppTelemetry>` directly. AppTelemetry is transient (collected per scan, fed to the rule engine, not persisted as a separate table). So **no Room migration is required.**

That said: forensic export *does* surface telemetry-derived findings. The display of those findings is rule-domain, not scanner-domain, so it's also out of scope here.

## Schema cross-check coordination

`logsource-taxonomy.yml` in the `android-sigma-rules` submodule defines the canonical field set per service. `BundledRulesSchemaCrossCheckTest` in AndroDR fails if Kotlin properties drift from the taxonomy.

### Coordinated PR sequence

1. **Submodule PR (in `android-sigma-rules`)**: add two entries to `app_scanner.fields`:
   ```yaml
   embedded_component_class:
     type: list
     description: "Class names from manifest services/receivers/activities/providers; used for embedded-SDK fingerprinting"
   embedded_native_lib:
     type: list
     description: "Native .so filenames inside the APK (ABI prefix stripped); used for embedded-SDK fingerprinting"
   ```
2. **AndroDR PR**: bumps the submodule pointer to the merged commit, adds the two new fields to `AppTelemetry`, adds the two new functions to `AppScanner`, adds tests. `BundledRulesSchemaCrossCheckTest` passes because Kotlin and YAML now agree.

The submodule PR must merge first. AndroDR PR is a single squash commit so the change is reviewable as one diff post-bump.

## Testing

### Unit (`AppScannerTest.kt`)
- `extractComponentClassNames` given a PackageInfo with services + receivers + activities + providers → returns deduped, sorted list. Use `mockk` for PackageInfo (matches existing AppScannerTest pattern).
- `extractComponentClassNames` given a PackageInfo with all null sub-arrays → returns `emptyList()`, no NPE.
- `extractComponentClassNames` given >`MAX_COMPONENTS_PER_APP` components → output is truncated, no exception.
- `extractNativeLibFileNames` given a real test-fixture APK in `app/src/test/resources/` containing two `lib/arm64-v8a/lib*.so` and one `lib/x86_64/lib*.so` (different names) → returns deduped leaf names sorted.
- `extractNativeLibFileNames` given a non-existent path → returns `emptyList()`, logs warning, no throw.
- `extractNativeLibFileNames` given a corrupt zip → returns `emptyList()`, no throw.

### Integration (`AppScannerIntegrationTest.kt`, existing)
- Add a check that the collected `AppTelemetry` for an installed test app includes a non-empty `embeddedComponentClasses` (every real app has at least its launcher activity).
- New field `embeddedNativeLibs` may be empty for pure-Java/Kotlin apps — assert "non-null list", not "non-empty".

### Schema parity (`BundledRulesSchemaCrossCheckTest`)
- After submodule bump, the test must pass without modification. If it fails, the submodule PR shipped the wrong field names; fix in coordination.

## Open decisions (not blocking implementation)

1. **Component-kind subfields:** the unified `embedded_component_class` field collapses services/receivers/activities/providers. If rule authors later need to distinguish "broker SDK declared as a service" vs "as a receiver", we add `embedded_service_class` etc. as additive fields. Not doing it now (YAGNI).
2. **Multi-ABI native libs:** today we dedupe by leaf filename, so a SDK shipping both arm64 and x86_64 variants of the same `.so` produces one entry. If a broker SDK ever ships *different filenames* per ABI we'd see both; that's correct.
3. **Obfuscation:** SDKs that are run through R8/ProGuard before bundling have their class names mangled. The scanner emits the mangled names; rules will under-match. This is intentional — pretending we can de-obfuscate is harder than the user's threat model warrants. Native lib names are NOT renamed by R8, so they remain a reliable channel.

## Acceptance criteria

- [ ] Submodule PR adds `embedded_component_class` + `embedded_native_lib` to `app_scanner.fields` and is merged.
- [ ] AndroDR PR bumps submodule pointer, adds the two `AppTelemetry` fields, adds the two `AppScanner` extraction functions with proper failure handling.
- [ ] `BundledRulesSchemaCrossCheckTest` passes.
- [ ] New unit tests pass.
- [ ] `./gradlew assembleDebug testDebugUnitTest lintDebug` green.
- [ ] On-device sanity: install on Samsung Z Fold 2 (R3CR300WRRH), trigger a full scan from the Dashboard, watch `adb logcat -s AppScanner:D` for a one-time debug log (added in the implementation PR) reporting per-app counts of embedded components and native libs across the run. Confirm: `embeddedComponentClasses` is non-empty for the overwhelming majority of installed apps (launcher activity alone guarantees this); `embeddedNativeLibs` is non-empty for Google Play Services and at least a few other native-using apps; scan total runtime stays under the 30 s headroom of today's ~14 s baseline + the 10 s budgeted addition.
- [ ] Two-reviewer cycle (spec compliance + harsh quality) on the AndroDR PR.

## What lands next (NOT in this spec)

- Spec for SIR research on the named broker SDKs (X-Mode, Outlogic, Venntel, Mobilewalla, Adsquare, Predicio, Cuebiq, Gravy Analytics, Babel Street).
- Spec for the `installed_app` rule pack consuming the new fields.
- Spec for the DNS broker-hostname rule pack.
- Spec for the combination rule (sensitive location permission + broker SDK).

Each is sized to a separate brainstorming session.
