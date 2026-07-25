# Input-Method (IME) Detection — Design Spec

**Date:** 2026-07-25
**Status:** approved, pending implementation plan
**Origin:** OPPO CPH2735 field scan (issue #263 triage) — Baidu IME installed, unreported

## 1. Motivation

An input method sits between the user and every text field on the device: messages,
search queries, card numbers, and passwords typed on the soft keyboard. Android
cannot hide password fields from the keyboard — the keyboard renders the keys and
receives the taps — which is why the OS gates enablement behind an explicit warning
that the input method "may be able to collect all the text you type, including
personal data like passwords and credit card numbers."

No AndroDR rule keys on `BIND_INPUT_METHOD`. On the CPH2735 field scan, Baidu IME
(`com.baidu.input`) was present and drew no finding. It is the highest-capability
component on that device and we are blind to it.

Cloud-based keyboards additionally transmit typed content to servers for prediction.
Published research across the major Chinese keyboard vendors found several
transmitting keystrokes with encryption weak or absent enough to be recoverable by a
passive network observer. That is a data-exposure concern independent of whether the
app is malicious.

## 2. Key finding (shapes the design)

Installed ≠ enabled ≠ active, and the distinction decides whether there is any risk
at all. An IME that is installed but never enabled cannot observe input.

Ground truth from the attached test device (Samsung SM-F916B, Galaxy Z Fold 2):

```
ENABLED                                          ACTIVE
com.samsung.android.honeyboard/...HoneyBoard     <- default
com.google.android.tts/...VoiceInputMethodSvc     no
com.touchtype.swiftkey/com.touchtype.KeyboardSvc  no
```

A real device carries a third-party keyboard **enabled but dormant**. A rule that
flags "declares an IME service" would fire on SwiftKey here, and on Gboard sitting
in any system image — the exact false-positive class removed in #263.

Note `com.touchtype.swiftkey` is one of the `partner_preinstall_prefixes` restored
to the OEM allowlist on 2026-07-25 (rules#47). Without that fix an IME rule would
have false-positived on SwiftKey across every Samsung and HONOR device.

## 3. Telemetry — two booleans on `AppTelemetry`

| Field | Type | Meaning |
|---|---|---|
| `is_enabled_ime` | boolean | package appears in the enabled input-method list |
| `is_active_ime` | boolean | package is the currently selected keyboard |

Both default to `false`.

**Invariant:** `is_active_ime` implies `is_enabled_ime`. Android requires enablement
before selection. Asserted by test.

### Why `AppTelemetry` and not a new logsource

Rejected: a new `input_method` logsource with its own `InputMethodTelemetry`,
mirroring `accessibility_audit`.

That logsource would carry no `is_known_oem_app` and no `from_trusted_store`, so the
rule could not suppress SwiftKey, HoneyBoard, or Google's voice IME without
duplicating the classification logic. This is the same defect that makes
`androdr-066` unfixable in YAML (`ReceiverTelemetry` has no sideload field) and the
reason `androdr-012` / `androdr-017` key off `has_accessibility_service` on
`AppTelemetry` rather than the `accessibility_audit` logsource. Precedent is
consistent: the "does this app do X" boolean belongs on the app record.

Placing the state on `AppTelemetry` means both rules inherit every guard fixed in
#263 and #265, and remain pure YAML — future tuning ships on the 12h feed with no
app release.

## 4. Scanner — `InputMethodScanner`

New file, `app/src/main/java/com/androdr/scanner/InputMethodScanner.kt`, following
the `AccessibilityAuditScanner` shape.

```kotlin
@Singleton
class InputMethodScanner @Inject constructor(@ApplicationContext context: Context) {
    data class ImeState(val enabledPackages: Set<String>, val activePackage: String?)
    fun currentState(): ImeState
}
```

- Enabled set: `InputMethodManager.getEnabledInputMethodList()`, mapped to package names.
- Active: `Settings.Secure.getString(resolver, Settings.Secure.DEFAULT_INPUT_METHOD)`
  returns `pkg/.ServiceClass`; the package is `substringBefore('/')`. Verified against
  the Fold 2's live output.

Both are public APIs requiring no permission.

Injected into `AppScanner` the same way `oemPrefixResolver` and `knownAppResolver`
are, and called **once per scan**, hoisted out of the per-package loop. Keeps
`InputMethodManager` specifics out of the telemetry builder and keeps it mockable.

## 5. The rules

Two rules, because `level` is a rule-scoped field and there is no severity-boost
primitive (tracked separately as #230).

### `androdr-0XX` — Third-party keyboard enabled (`level: medium`)

```yaml
detection:
    selection:
        is_enabled_ime: true
        is_active_ime: false          # the active case belongs to the high rule
        is_known_oem_app: false
    filter_known_good:
        package_name|ioc_lookup: known_good_app_db
        from_trusted_store: true
    condition: selection and not filter_known_good
level: medium
```

### `androdr-0XY` — Third-party keyboard in use (`level: high`)

Identical, with `is_active_ime: true` and no `is_enabled_ime` clause (implied by the
invariant).

### Two deliberate departures from androdr-011/012/013

**No `from_trusted_store: false` gate.** A keyboard installed from Play sees typed
input exactly as a sideloaded one does. Baidu IME is most likely a Play install, so
gating on sideloading would miss the case that motivated this work. A consequence is
that `filter_known_good` is genuinely reachable here, unlike in `androdr-011` — which
is correct: the ADR #51 impersonation concern applies to claiming an app is
sideloaded, and these rules make no such claim.

**No `is_system_app: false` gate.** A preinstalled keyboard is a real supply-chain
risk and devices carry only one to three IMEs, so the noise ceiling is low. The OEM
and known-good guards already suppress legitimate preloads.

### Expected outcomes

| Device | Package | Result |
|---|---|---|
| Fold 2 | `com.samsung.android.honeyboard` | suppressed — `com.samsung.` prefix |
| Fold 2 | `com.google.android.tts` | suppressed — `com.google.` prefix |
| Fold 2 | `com.touchtype.swiftkey` | suppressed — `partner_preinstall_prefixes` |
| CPH2735 | ColorOS keyboard | suppressed — `com.coloros.` prefix |
| CPH2735 | `com.baidu.input` | **flagged** — medium if enabled, high if selected |

Zero findings on the Fold 2. This is the acceptance criterion.

## 6. Degradation

- `InputMethodManager` unavailable or throwing: empty state, both flags false,
  neither rule fires. Silence over guessing, consistent with other scanners
  returning `emptyList()`.
- **Bugreport path:** `AppTelemetry` built from a bugreport has no IME state, so both
  flags are false and the rules stay silent. Stated explicitly rather than discovered
  later. `dumpsys input_method` does appear in bugreports and is a viable follow-up;
  out of scope for v1.

## 7. Tests & verification

- `InputMethodScanner`: `pkg/.Class` parsing; null/blank default setting; null
  `InputMethodManager`.
- `AppScanner`: flags land on the correct packages; active-implies-enabled invariant.
- Gate-4 fixtures for both rules. True negatives taken verbatim from the Fold 2
  (`honeyboard`, `google.android.tts`, `swiftkey`); true positive `com.baidu.input`.
  Real device output as fixture data.
- `LogsourceTaxonomyCrossCheckTest` will fail unless the taxonomy carries both new
  fields — this is the lockstep gate, not an optional step.
- On-device verification against the attached Fold 2: expect zero IME findings.

## 8. Delivery

`LogsourceTaxonomyCrossCheckTest` validates `logsource-taxonomy.yml` against
`toFieldMap()` output, so the taxonomy and the Kotlin change must land together.

1. Rules-repo PR: `validation/logsource-taxonomy.yml` gains both fields under
   `app_scanner`; both rule YAMLs added; `rules.txt` + regenerated `rules.sha256`.
2. AndroDR PR: submodule pinned to that branch, plus scanner, telemetry fields,
   bundled rules, fixtures.
3. AndroDR CI green — `submodule-check` red until step 4, expected per CLAUDE.md.
4. Merge rules PR, repoint submodule at main, merge AndroDR PR.

## 9. Out of scope (deferred)

- IME state from bugreports via `dumpsys input_method`.
- Per-IME inventory section in the report (a `input_method` logsource could serve
  this later; additive, nothing depends on it now).
- Cloud-keyboard-specific IOC matching (naming known-vulnerable keyboard builds).
- `androdr-066` boot-persistence fix — same class of missing telemetry, tracked
  separately.
