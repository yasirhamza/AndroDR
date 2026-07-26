# Input-Method (IME) Detection — Design Spec

**Date:** 2026-07-25, rewritten 2026-07-26
**Status:** **PROPOSAL — not scheduled.** Supersedes the 2026-07-25 draft, which had
two blocking defects (see §11).
**Origin:** OPPO CPH2735 field scan (issue #263 triage) — Baidu IME installed, unreported

## 1. Motivation

An input method sits between the user and every text field on the device: messages,
search queries, card numbers, passwords typed on the soft keyboard. Android cannot
hide password fields from the keyboard — the keyboard renders the keys and receives
the taps — which is why the OS gates enablement behind an explicit warning that the
input method "may be able to collect all the text you type, including personal data
like passwords and credit card numbers."

No AndroDR rule keys on `BIND_INPUT_METHOD`. On the CPH2735 scan, Baidu IME
(`com.baidu.input`) was present and drew no finding.

Cloud-based keyboards transmit typed content to servers for prediction. Published
research across the major Chinese keyboard vendors found several transmitting
keystrokes with encryption weak or absent enough to be recoverable by a passive
network observer — a data-exposure concern independent of whether the app is
malicious.

## 2. The constraint that shapes the whole design

**`is_known_oem_app` cannot be used for IME detection, in either polarity.** Every
other design decision follows from this, so the evidence comes first.

`known_good_apps.json` classifies the vendor cloud keyboards as category `OEM`:

```
com.baidu.input_mi        OEM   "Baidu IME … YOU SHOULD NEVER USE A CLOSED-SOURCE KEYBOARD"
com.baidu.input_huawei    OEM
com.baidu.input_vivo      OEM
com.sohu.inputmethod.sogou.{xiaomi,meizu,nubia,oem}   OEM
com.sohu.inputmethod.sogouoem                          OEM
com.iflytek.inputmethod.miui                           OEM
com.emoji.keyboard.touchpal                            OEM
```

Category `OEM` sets `is_known_oem_app: true` on **every** device (`AppScanner.kt:253`
— the DB-category path is not device-conditional). Therefore:

- **As a guard** (`is_known_oem_app: false`, the shape every sideload-gated rule uses)
  it suppresses exactly the threat class this feature exists to find. A rule carrying
  that guard cannot flag any vendor Baidu/Sogou/iFlytek variant, no matter what
  exemption list it uses — selection fails before the filter is consulted.
- **As a trigger** (`is_known_oem_app: true`) it selects the OPPO preload shape.
  ColorOS preloads carry `is_system_app: false` + `from_trusted_store: false` +
  `is_known_oem_app: true` — that triple *is* the false positive #264 fixed, and OPPO
  ships qualifying keyboards (`com.coloros.securitykeyboard`,
  `com.oplus.securitykeyboard`, both category `OEM`).

There is no third polarity. The field is unusable here and the design does not
reference it.

## 3. What the field data shows

Attached test device (Samsung SM-F916B, Galaxy Z Fold 2):

```
ENABLED                                           ACTIVE
com.samsung.android.honeyboard/...HoneyBoard      <- default
com.google.android.tts/...VoiceInputMethodSvc      no
com.touchtype.swiftkey/com.touchtype.KeyboardSvc   no
```

Two things follow. A real device carries a third-party keyboard **enabled but
dormant** — so enablement state is a genuine discriminator, not a theoretical one.
And all three of these are legitimate, so any workable rule must suppress all three
while still flagging `com.baidu.input` on the CPH2735.

## 4. Design — a curated keyboard allowlist is the only exemption

Given §2, the exemption cannot be derived from OEM namespaces, installer provenance,
or the general app allowlist. It has to be an explicit, maintained list of keyboards:
`known_good_ime_db`, keyed on **exact package name**.

Exact matching is load-bearing. It is what makes a namespace squatter fall out for
free: `com.google.android.inputmethod.latin` is on the list,
`com.google.android.inputmethod.latin2` is not, so the squatter is flagged by the
ordinary rule with no special-case rule and no reference to `is_known_oem_app`.

**No `is_system_app` exemption.** A preinstalled keyboard is not presumed safe here,
because the preinstalled vendor cloud keyboards are precisely the threat — suppressing
system apps would silence `com.baidu.input_mi` on the devices that ship it. This is
the deliberate cost of the design: a stock keyboard absent from the list produces a
`low` finding until it is added.

**No `from_trusted_store` gate.** A Play-installed keyboard reads typed input exactly
as a sideloaded one does. (It could not serve as a trust anchor regardless —
`isTrustedInstaller` accepts any OEM-prefixed installer name and
`getInstallerPackageName` falls back to `initiatingPackageName`, so a dropper forges
it. Pre-existing; tracked in #267.)

## 5. Phase 1 — detection with no scan-pipeline change

`service_permissions` is already on `AppTelemetry` (`:62`) and already in the
taxonomy (`:33`), and `androdr-089` already ships this matcher shape in production.
So the detection lands as YAML plus one IOC list — **no scanner, no telemetry field,
no taxonomy change, no `SCANNER_COUNT` change.**

### `androdr-090` — Unreviewed keyboard installed (`level: low`)

```yaml
detection:
    selection:
        service_permissions|contains: "BIND_INPUT_METHOD"
    filter_known_good:
        package_name|ioc_lookup: known_good_ime_db
    condition: selection and not filter_known_good
level: low
```

No ATT&CK tag. Per the `androdr-015` precedent, `attack.t1417.001` (Input Capture:
Keylogging) implies intent that a `low` informational finding cannot support.

**Known weakness, and the reason Phase 2 exists:** this fires on a keyboard that is
installed but never enabled, which has no capability at all, and on apps that bundle
an IME service for a niche feature. The remediation text below is written to stay
truthful under that ambiguity, but Phase 2 is what removes it.

### Wiring `known_good_ime_db`

Modelled on `OemPrefixResolver`, which #265 already proved and gated:

- `ioc-data/known-good-imes.yml` in the rules repo; bundled seed at
  `res/raw/known_good_imes.yml`.
- Declared in `validation/ioc-lookup-definitions.yml`; cross-checked against the
  Kotlin registry by `IocLookupDefinitionsCrossCheckTest`.
- One entry in the `setIocLookups` map in `ScanOrchestrator.initRuleEngine()`.
- `KnownGoodImeResolver`: bundled load + 12h remote refresh, so adding a keyboard
  ships without an app release.

**The parity gate is mandatory, not optional.** `refresh()` replaces the in-memory
list wholesale, so a mirror missing an entry silently *removes* an exemption and
manufactures false positives on every device within 12h. That is exactly how #203's
HONOR fix died in the field for two months. Extend `OemPrefixMirrorParityTest`'s
three-way check (bundle ↔ mirror ↔ test fixture) to this file, and add it to the
`mirror-drift.yml` daily job added in #265.

## 6. Phase 2 — enabled/active state

Phase 2 replaces the ambiguity in §5 with the distinction that decides whether there
is any exposure: installed ≠ enabled ≠ active.

### Telemetry

| Field | Type | Meaning |
|---|---|---|
| `is_enabled_ime` | boolean | package is in the enabled input-method list |
| `is_active_ime` | boolean | package is the currently selected keyboard |

Both default `false`, so an older APK receiving the Phase 2 rules from the 12h feed
matches nothing (`matchEquals` returns false for a missing field) rather than
false-positiving. Fail-closed.

### Scanner

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

Enabled set from `InputMethodManager.getEnabledInputMethodList()`; active from
`Settings.Secure.getString(resolver, Settings.Secure.DEFAULT_INPUT_METHOD)`, which
returns `pkg/.ServiceClass` — take `substringBefore('/')`. Both are public APIs
needing no permission; both verified against the Fold 2's live output and
`android-36/android.jar`.

The two reads fail independently. If the enabled-list read throws while the default
setting is readable, fold the active package into the enabled set —
`enabled + listOfNotNull(active)`. That is a sound inference rather than invented
data: Android requires enablement before selection, so a package named as the default
*is* enabled. It costs one line and keeps exported telemetry self-consistent.

### The join belongs in `ScanOrchestrator`, not `AppScanner`

```kotlin
val ime = imeStateDeferred.await()
val appTelemetry = appTelemetryDeferred.await()
    .map { it.copy(isEnabledIme = ime.isEnabled(it.packageName), isActiveIme = ime.isActive(it.packageName)) }
```

Registered as a ninth tracked scanner (`SCANNER_COUNT` 8 → 9, `ScanOrchestrator.kt:607`).
Injecting it into `AppScanner` would nest the read inside
`trackedAsync("appScanner", scannerErrors, emptyList())`, so a throw would zero **all**
app telemetry and silence every `app_scanner` rule — the detection-evasion hazard
`trackScanner` exists to prevent. Separate tracking also yields a `ScannerFailure` row
and the partial-scan banner, so "we could not check your keyboard" is distinguishable
from "your keyboard is fine".

### Rules after Phase 2

`androdr-090` gains `is_enabled_ime: true` + `is_active_ime: false` and keeps
`level: low`. A new `androdr-091` takes the active case at `level: medium` with
`tags: [attack.t1417.001]`, selecting `is_active_ime: true` and the same
`known_good_ime_db` filter.

Severity follows the **mandatory** multi-condition rule at
`.claude/commands/update-rules-author.md:165` — one independent signal is `medium` at
most. `androdr-060` is the governing precedent, verified: an *active accessibility
service*, a strictly more powerful capability, is `medium`.

## 7. The allowlist is the product — governance

The list is now the load-bearing artifact, so its editorial rule must be explicit.

**Include** a keyboard when any of: it is a stock keyboard shipped on its own
vendor's platform; it is widely used with no published evidence of insecure keystroke
transmission; or it is open-source with reproducible builds.

**Exclude** keyboards with published research showing recoverable keystroke exposure —
the Baidu, Sogou, iFlytek, TouchPal and Simeji families.

Initial contents, at minimum: Gboard, Samsung HoneyBoard, the Google TTS voice IME,
SwiftKey, the ColorOS/MIUI/vivo/HONOR stock and security keyboards, and the FOSS set —
OpenBoard, HeliBoard, FUTO, AnySoftKeyboard, Simple Keyboard, Hacker's Keyboard,
Unexpected Keyboard, FlorisBoard.

**Absence from the list is "not reviewed", not "malicious."** That is why severity
caps at `medium`, and it governs the wording: the finding says a keyboard **can** read
what you type, never that it **is**. The Settings path varies by manufacturer, so
guidance stays path-agnostic and adds: "If your employer manages this device, contact
your IT administrator before removing it."

`falsepositives` must name: a deliberately installed second keyboard for another
language or layout; accessibility keyboards (switch-access, scanning, large-key);
MDM-deployed corporate keyboards the user cannot remove; and regional stock keyboards
not yet on the list.

## 8. Expected outcomes

| Device | Package | Phase 1 | Phase 2 |
|---|---|---|---|
| Fold 2 | `com.samsung.android.honeyboard` | suppressed — on list | suppressed |
| Fold 2 | `com.google.android.tts` | suppressed — on list | suppressed |
| Fold 2 | `com.touchtype.swiftkey` | suppressed — on list | suppressed |
| CPH2735 | ColorOS stock/security keyboard | suppressed — on list | suppressed |
| CPH2735 | `com.baidu.input` | **low** | **low** dormant / **medium** if selected |
| any | `com.baidu.input_mi` + vendor variants | **low** | **low** / **medium** |
| any | OpenBoard, HeliBoard from F-Droid | suppressed — on list | suppressed |
| any | sideloaded `…inputmethod.latin2` | **low** — exact-match miss | **low** / **medium** |

Acceptance requires **both**: zero findings on the Fold 2, and a confirmed true
positive. A negative-only criterion is satisfied by an implementation that never
fires.

Note the vendor variants row — this is the concrete improvement over the superseded
draft, which could not flag them (§11).

## 9. Degradation

- Phase 1 inherits `AppScanner`'s behaviour; `service_permissions` already falls back
  to per-package `getPackageInfo` when `getInstalledPackages` truncates component
  arrays on Binder limits (`AppScanner.kt:275-293`).
- Phase 2: `InputMethodManager` unavailable → `ImeState.EMPTY`, both flags false, no
  findings. Default-setting read fails → `activePackage` null, only the dormant rule
  can fire. Enabled-list read throws → §6's fold keeps the state consistent.
- Separate scanner tracking surfaces any failure as a `ScannerFailure` row rather than
  silent absence.
- **Bugreport path:** no bugreport module emits `app_scanner` telemetry —
  `AppTelemetry` is constructed in exactly one place in `main`. These rules cannot
  fire on an imported bugreport; no defaulting behaviour needs testing.

## 10. Tests

- **Allowlist parity:** three-way byte equality (bundle ↔ mirror ↔ test fixture) plus
  the `mirror-drift.yml` daily live check. Non-negotiable per §5.
- **Real-classification test:** run `com.baidu.input_mi`,
  `com.google.android.inputmethod.latin2` and `com.samsung.evilkeyboard` through the
  actual resolvers and assert the resulting exemption decision. Gate-4 fixtures feed
  field values verbatim and are structurally blind to this class (#269).
- Gate-4 fixtures per rule, with true negatives taken from the Fold 2's real output.
- **Adversary fixture** `test-adversary/fixtures/mercenary/ime-abuse`: Phase 1 needs
  only an app declaring an `InputMethodService`; Phase 2 adds `adb shell ime enable` /
  `ime set`, then `ime reset`.
- Phase 2 only: scanner unit tests for `pkg/.Class` parsing, null/blank default, null
  `InputMethodManager`, throwing enabled-list; orchestrator join asserted through
  `AppScannerTelemetryTest`'s harness with `verify(exactly = 1)` on `currentState()` —
  the only mechanical check that the read is hoisted out of the per-package loop.

## 11. What changed from the 2026-07-25 draft, and why

Both defects were verified against shipped data before this rewrite.

**`androdr-092` is deleted.** Its selection was
`is_known_oem_app: true` + `is_system_app: false` + `from_trusted_store: false` — the
exact OPPO preload shape #264 had just excluded, at `level: high`. It would have
re-fired that false positive on OPPO's own security keyboards. Its purpose (catching
namespace squatters) is served for free by exact-match allowlisting (§4).

**The `is_known_oem_app: false` guard is dropped from all rules.** The draft correctly
diagnosed that `known_good_app_db` is poisoned for keyboards, then replaced only the
*exemption* while leaving the guard that causes the same suppression. Its
expected-outcomes table claimed the Baidu vendor variants would be flagged; the rule
as written could not flag them.

**The cheap path is now Phase 1.** The draft dismissed a `BIND_INPUT_METHOD` rule as
firing on SwiftKey and Gboard — true only without an exemption, which the proposed
rules also carried. It costs no scan-pipeline change and catches the motivating case.

**The invariant is one line, not four sections.** No rule reads both booleans in a way
the contradictory state could mislead; `androdr-091` firing when a package genuinely
is the active keyboard is correct behaviour.

## 12. Out of scope

- **`is_known_oem_app` trust conflation** — the DB's `OEM` category means "vendor
  preload you may want to debloat", not "trustworthy". Fixing it at `AppScanner.kt:253`
  changes `is_sideloaded` on real devices and affects ten rules. Tracked in #263. This
  design is immune by not using the field.
- **`from_trusted_store` forgeability** — #267.
- **Taxonomy field-name gate** — a rule naming a field that does not exist passes every
  current gate and is silently dead on-device. #268. Phase 2 adding two fields by hand
  is a good moment to close it, but it is not this design's job.
- **Gate-4 fixture blindness** — #269.
- **Per-user blindness:** both Phase 2 reads are per-user, so a malicious IME in a work
  profile or secondary user is invisible. No mitigation via public API.
- IME state from bugreports via `dumpsys input_method`.
- **Cloud-keyboard IOC denylist** naming known-vulnerable keyboard builds. Complementary
  to the allowlist: an exact match against curated known-bad data is the convention's
  explicit exception to the multi-condition rule, so it is the natural home for a
  `high` tier.
