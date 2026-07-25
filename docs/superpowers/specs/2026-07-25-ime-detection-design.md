# Input-Method (IME) Detection — Design Spec

**Date:** 2026-07-25
**Status:** revised after 4-agent plan gate; androdr-092 scope decision open
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
before selection. Enforced by construction in §4, not merely asserted — the two
underlying reads fail independently.

### Why `AppTelemetry` and not a new logsource

Rejected: a new `input_method` logsource with its own `InputMethodTelemetry`,
mirroring `accessibility_audit`.

An earlier draft justified this by asserting a narrow logsource *cannot* carry
`is_known_oem_app` / `from_trusted_store`. That is false — it describes today's
wiring, not a constraint. `ReceiverAuditScanner` already holds a `PackageManager`;
injecting `KnownAppResolver` + `OemPrefixResolver` would put those fields on
`ReceiverTelemetry` and make `androdr-066` fixable in YAML. The real reasons are:

- **A planned family, not a one-off.** #180 already plans `is_default_sms_handler`,
  `has_notification_listener` and `is_default_nfc_payment_app` as `app_scanner`
  booleans. IME state is the first member of that family.
- **The dormant case is unrepresentable in a narrow logsource.** A per-IME record
  cannot express "installed but never enabled" — the safe state, and the one that
  decides whether there is any exposure at all, is simply an absent row.
- **Composability.** A future keyboard-plus-accessibility co-occurrence (#230)
  needs both signals on the same record.

Note this is genuinely a new *category* of field on `AppTelemetry`: device-wide
selection state joined onto packages, unlike `has_accessibility_service`, which is
an intrinsic manifest declaration. It is the third such field group planned, so the
tripwire is: **at the third device-state field, extract a nested value object** with
a flat field map (keys stay flat, so the taxonomy and rules are unaffected).

## 4. Scanner — `InputMethodScanner`

New file, `app/src/main/java/com/androdr/scanner/InputMethodScanner.kt`.

```kotlin
@Singleton
class InputMethodScanner @Inject constructor(@ApplicationContext context: Context) {
    data class ImeState(val enabledPackages: Set<String>, val activePackage: String?) {
        fun isEnabled(pkg: String) = pkg in enabledPackages
        fun isActive(pkg: String) = pkg == activePackage
        companion object { val EMPTY = ImeState(emptySet(), null) }
    }
    fun currentState(): ImeState
}
```

- Enabled set: `InputMethodManager.getEnabledInputMethodList()`, mapped to package names.
- Active: `Settings.Secure.getString(resolver, Settings.Secure.DEFAULT_INPUT_METHOD)`
  returns `pkg/.ServiceClass`; the package is `substringBefore('/')`. Verified against
  the Fold 2's live output and against `android-36/android.jar`.

Both are public APIs requiring no permission.

**The invariant is enforced by construction, not asserted after the fact:**

```kotlin
return ImeState(enabledPackages = enabled + listOfNotNull(active), activePackage = active)
```

The two reads fail independently, so a thrown enabled-list read with a readable
default setting would otherwise yield `is_active_ime: true` alongside
`is_enabled_ime: false` — a state §3 declares impossible, and one that `androdr-091`
fires on because it deliberately omits `is_enabled_ime`. Folding `active` into the
enabled set preserves the true signal while making the invariant hold structurally.

The join lives in `ScanOrchestrator`, **not** inside `AppScanner`:

```kotlin
val ime = imeStateDeferred.await()
val appTelemetry = appTelemetryDeferred.await()
    .map { it.copy(isEnabledIme = ime.isEnabled(it.packageName), isActiveIme = ime.isActive(it.packageName)) }
```

`InputMethodScanner` is registered as a ninth tracked scanner (`SCANNER_COUNT` 8 → 9).
Injecting it into `AppScanner` instead would nest it inside
`trackedAsync("appScanner", scannerErrors, emptyList())`, so a thrown IME read would
zero out **all** app telemetry and silence every `app_scanner` rule — the
detection-evasion hazard `trackScanner` exists to prevent. Tracking it separately also
yields a `ScannerFailure` row and the partial-scan banner when the read fails, so
"we could not check your keyboard" is reported rather than silently indistinguishable
from "your keyboard is fine".

## 5. The rules

Severity follows the **mandatory** multi-condition rule in
`.claude/commands/update-rules-author.md:165` — a behavioral rule resting on one
independent signal is `medium` at most. `androdr-060` is the governing precedent: an
*active accessibility service*, a strictly more powerful capability, is `medium`.

### `androdr-090` — Third-party keyboard enabled (`level: low`)

```yaml
detection:
    selection:
        is_enabled_ime: true
        is_active_ime: false          # the active case belongs to androdr-091
        is_known_oem_app: false
    filter_known_good:
        package_name|ioc_lookup: known_good_ime_db
    condition: selection and not filter_known_good
level: low
```

No ATT&CK tag. Per the precedent set in `androdr-015`, `attack.t1417.001` (Input
Capture: Keylogging) implies malicious intent that a `low` informational finding
cannot support without corroborating signals.

### `androdr-091` — Third-party keyboard in use (`level: medium`)

Identical selection with `is_active_ime: true` and no `is_enabled_ime` clause
(implied by the §4 invariant), plus `tags: [attack.t1417.001]`.

### `androdr-092` — Keyboard claiming a manufacturer namespace (`level: high`) — SCOPE DECISION PENDING

```yaml
detection:
    selection:
        is_enabled_ime: true
        is_known_oem_app: true
        is_system_app: false
        from_trusted_store: false
    condition: selection
level: high
```

`is_known_oem_app` is a package-*name* test with no signature binding: `isOemPrefix`
is a bare `startsWith`, and `com.android.`, `com.google.` and `android.` are
**unconditional** prefixes applying on every device. A keyboard sideloaded as
`com.google.android.inputmethod.latin2` therefore satisfies `is_known_oem_app: true`
and is exempted from androdr-090/091 — and from androdr-010/011/012/013/014/016/017
and 089, all of which carry the same guard. There is no backstop rule today.

This rule keys the anomaly instead of the name: legitimate manufacturer software is
either preinstalled (`is_system_app: true`) or store-installed
(`from_trusted_store: true`). A squatter is neither. It earns `high` on two
independent conditions — namespace claim, and absence of both legitimate provenance
paths — comparable to `androdr-016` (system name disguise), also `high`.

**This is an addition beyond the approved scope and needs an explicit decision.** The
security review made it a condition of clearing its FAIL verdict.

### Exemption model — `known_good_ime_db`

`known_good_app_db` is unusable here, for two independent reasons:

1. **It exempts the threat.** `known_good_apps.json` classifies `com.baidu.input_mi`,
   `_huawei`, `_vivo`, five Sogou variants and `com.iflytek.inputmethod.miui` as
   category `OEM`, which sets `is_known_oem_app: true` on every device. One of those
   rows cites the Citizen Lab research §1 uses as motivation.
2. **`USER_APP` is a catch-all.** `PlexusKnownAppFeed` writes every fetched entry as
   `USER_APP`, and `TRUSTED_CATEGORIES` includes `USER_APP`. On any device that has
   refreshed the Plexus feed, a Play-installed `com.baidu.input` satisfies both
   `known_good_app_db` and `from_trusted_store: true` — the filter matches and the
   motivating case goes silent.

A keyboard allowlist is a different editorial judgment than a general app allowlist:
roughly 50 entries, not 14,343, and it must include FOSS keyboards that no
installer-provenance gate can vouch for. New `ioc-data/known-good-imes.yml` declared
in `validation/ioc-lookup-definitions.yml` and wired in
`ScanOrchestrator.initRuleEngine()`, cross-checked by
`IocLookupDefinitionsCrossCheckTest`.

Because the filter no longer gates on `from_trusted_store`, it is reachable — which
is the point. ADR #51's concern is name-only exemption of *sideloaded* apps; a
curated, keyboard-specific list is a narrower and deliberately maintained surface.
`from_trusted_store` could not have served as the anchor anyway: `isTrustedInstaller`
accepts any OEM-prefixed installer name, and `getInstallerPackageName` falls back to
`initiatingPackageName`, so a dropper named `com.google.play.svcupdate` forges it.
That weakness is pre-existing and tracked separately.

Initial `known-good-imes.yml` must include, at minimum: Gboard, Samsung HoneyBoard,
SwiftKey, the Google TTS voice IME, the ColorOS/MIUI/Vivo/HONOR stock keyboards, and
the FOSS set — OpenBoard, HeliBoard, FUTO, AnySoftKeyboard, Simple Keyboard,
Hacker's Keyboard, Unexpected Keyboard. It must **not** include the Baidu, Sogou,
iFlytek, TouchPal or Simeji families.

### Expected outcomes

| Device | Package | Result |
|---|---|---|
| Fold 2 | `com.samsung.android.honeyboard` | suppressed — `com.samsung.` prefix |
| Fold 2 | `com.google.android.tts` | suppressed — `com.google.` prefix |
| Fold 2 | `com.touchtype.swiftkey` | suppressed — `partner_preinstall_prefixes` |
| CPH2735 | ColorOS keyboard | suppressed — `com.coloros.` prefix |
| CPH2735 | `com.baidu.input` | **flagged** — low if dormant, medium if selected |
| any | `com.baidu.input_mi` and vendor variants | **flagged** — absent from `known_good_ime_db` |
| any | OpenBoard/HeliBoard from F-Droid | suppressed — on the curated list |
| any | sideloaded `com.google.android.inputmethod.latin2` | **flagged** by androdr-092 |

Acceptance requires **both**: zero findings on the Fold 2, and a confirmed true
positive. A negative-only criterion is satisfied by an implementation that never
sets either flag.

### False positives to name explicitly in the rules

`falsepositives` must cover: a deliberately installed second keyboard for another
language or layout; accessibility keyboards (switch-access, scanning, large-key);
MDM-deployed corporate keyboards, which the user cannot remove; and regional OEM
stock keyboards on devices whose manufacturer string matches no conditional block.

Remediation must say a keyboard **can** read what you type, not that it **is**. The
Settings path varies by manufacturer — Samsung and ColorOS both differ from AOSP —
so guidance stays path-agnostic, and adds: "If your employer manages this device,
contact your IT administrator before removing it."

## 6. Degradation

The two reads fail independently; §4's construction is what keeps that safe.

- `InputMethodManager` unavailable: `ImeState.EMPTY`, both flags false, no findings.
- Enabled-list read throws, default setting readable: the active package is folded
  into the enabled set, so the invariant holds and `androdr-091` fires on a true
  signal rather than a contradictory one.
- Default-setting read fails: `activePackage` is null; only `androdr-090` can fire.
- The scanner is separately tracked, so any failure surfaces as a `ScannerFailure`
  row and the partial-scan banner rather than silent absence.

**Bugreport path:** no bugreport module emits `app_scanner` telemetry at all —
`AppTelemetry` is constructed in exactly one place in `main`. These rules therefore
cannot fire on an imported bugreport, and no defaulting behaviour needs testing.

**Forward compatibility:** an older APK receiving these rules from the 12h feed has
no `is_enabled_ime` key; `matchEquals` returns false for a missing field, so the
rules stay silent rather than false-positiving. Fail-closed by construction.

## 7. Tests & verification

- `InputMethodScanner`: `pkg/.Class` parsing; null/blank default; null
  `InputMethodManager`; throwing enabled-list. The invariant is asserted here, across
  all four degradation paths — this is where it can actually be violated.
- **Real-classification test:** run `com.baidu.input_mi`,
  `com.google.android.inputmethod.latin2` and `com.samsung.evilkeyboard` through the
  actual `KnownAppResolver` / `OemPrefixResolver` and assert the resulting
  `is_known_oem_app`. Gate-4 fixtures feed field values verbatim and are structurally
  blind to this entire class.
- **Orchestrator join:** assert flags land on the right packages via
  `AppScannerTelemetryTest`'s existing harness, and `verify(exactly = 1)` on
  `currentState()` — the only mechanical check that it is hoisted out of the loop.
- Gate-4 fixtures for each rule. SwiftKey's true-negative record must carry
  `is_known_oem_app: true` (its real value, via `partner_preinstall_prefixes`), with
  the `known_good_ime_db` path covered by a separate, explicitly synthetic package.
- **Adversary fixture** `test-adversary/fixtures/mercenary/ime-abuse`: a minimal
  `InputMethodService`, enabled via `adb shell ime enable` / `ime set`, scanned,
  asserted, then `adb shell ime reset`. Every recent behavioral rule has one.
- On-device: zero findings on the Fold 2 **and** a true positive from the adversary
  fixture or a deliberately installed F-Droid keyboard.
- Bundled↔mirror↔fixture parity for `known-good-imes.yml`, mirroring the gate added
  for `known_oem_prefixes.yml` in #265.

**Gap worth closing here:** no gate checks that a rule's detection field names exist
in the taxonomy for its logsource. A typo like `is_ime_enabled` passes Gate 1, Gate 4,
schema cross-check, mirror parity and manifest integrity, and is dead on-device
because `matchEquals` returns false for a missing field — the same silent-dead-rule
class #225 closed for permission literals. Two new fields entering by hand is the
moment to close it.

## 8. Delivery

1. Rules-repo PR: taxonomy fields; `ioc-data/known-good-imes.yml`; the
   `known_good_ime_db` entry in `ioc-lookup-definitions.yml`; rule YAMLs; `rules.txt`
   and regenerated `rules.sha256`.
2. AndroDR PR: submodule pinned to that branch, scanner, orchestrator registration
   and join, telemetry fields, the IOC lookup wiring, bundled rules, fixtures,
   adversary fixture.
3. AndroDR CI green — `submodule-check` red until step 4, expected per CLAUDE.md.
4. Merge rules PR, repoint submodule at main, merge AndroDR PR.

## 9. Out of scope (deferred, with rationale)

- **`is_known_oem_app` trust conflation** — the DB's `OEM` category means "vendor
  preload you may want to debloat", not "trustworthy", and it is package-name-only.
  Fixing it at `AppScanner.kt:253` changes `is_sideloaded` on real devices and
  affects ten rules; it needs its own plan and a device sweep. Tracked in #263.
  `androdr-092` is the local mitigation.
- **`isTrustedInstaller` accepting OEM-prefixed installer names**, and the
  `initiatingPackageName` fallback, which together make `from_trusted_store`
  forgeable by a dropper. Pre-existing, repo-wide blast radius.
- **Per-user blindness:** both reads are per-user, so a malicious IME in a work
  profile or secondary user is invisible. No mitigation available via public API.
- IME state from bugreports via `dumpsys input_method`.
- Cloud-keyboard IOC list naming known-vulnerable keyboard builds — the natural home
  for a `high`/`critical` tier under the multi-condition convention's exception.
- `androdr-066` boot-persistence fix.

## 10. Review record

Four-agent plan gate, 2026-07-25. Verdicts: security **FAIL**; spec-compliance,
technical-accuracy and architect **PASS-WITH-FIXES**. This revision addresses the
findings. The Plexus `USER_APP` catch-all and the vendor-variant `OEM` classification
were each confirmed directly against shipped data before being accepted.
