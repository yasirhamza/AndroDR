# IME Detection — Phase 1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship `androdr-090` — flag any installed app that declares an input-method service and is not on a curated keyboard allowlist — so AndroDR stops being blind to keyboards.

**Architecture:** One SIGMA rule, no Kotlin beyond a single registry line. `service_permissions` is already on `AppTelemetry` and already in the logsource taxonomy, and `androdr-089` already ships this matcher shape in production, so the detection needs no scanner, no telemetry field and no taxonomy change. The allowlist is a plain list inside the rule; rules ship on the 12h feed, so adding a keyboard reaches devices without an app release.

**Tech Stack:** SIGMA YAML delivered via the `android-sigma-rules` submodule; Kotlin/JUnit4 for the existing gates.

**Spec:** `docs/superpowers/specs/2026-07-25-ime-detection-design.md` (rewritten 2026-07-26)

**Phase 2 is out of scope.** The `InputMethodScanner`, the `is_enabled_ime` / `is_active_ime` telemetry fields and the dormant/active severity split get their own plan once Phase 1 has field data. Do not build them here.

## Global Constraints

- Build env for every gradle command: `export JAVA_HOME=/home/yasir/Applications/android-studio/jbr && export ANDROID_HOME=/home/yasir/Android/Sdk && export PATH="$JAVA_HOME/bin:$ANDROID_HOME/platform-tools:$PATH"`
- **Every command block runs from `/home/yasir/AndroDR`.** Submodule work uses `git -C third-party/android-sigma-rules …` — never a bare `cd`, which strands later commands in the wrong directory.
- Rule ID is **androdr-090**. 089 is the highest in use; 084 is the only retired ID.
- **The rule must never reference `is_known_oem_app`, in either polarity.** That field is `true` for the Baidu/Sogou/iFlytek vendor variants this rule exists to catch, and `true` for the ColorOS preloads whose false positive #264 fixed. See spec §2.
- **No `is_system_app` and no `from_trusted_store` clause either.** The preinstalled vendor cloud keyboards are the threat; a Play-installed keyboard reads input identically.
- Bundled rules must be **byte-equal** to their mirror counterpart (`BundledMirrorParityTest`). Mirror path strips the `sigma_` prefix and uses the logsource service as the directory: `app_scanner/androdr_090_unreviewed_keyboard.yml`.
- Manifest regeneration uses `LC_ALL=C sort` — `rules.txt` is C-collated and the default locale reorders it.
- Verification is `./gradlew testDebugUnitTest lintDebug detekt` — CI runs `detekt` (`ci.yml:140`).
- Delivery follows the safe ordering in CLAUDE.md. `submodule-check` is red by construction while the submodule is pinned to a rules-repo branch — expected, not a failure.

- [ ] **Task 0: Create the working branches**

```bash
cd /home/yasir/AndroDR && git checkout -b feat/ime-detection-phase-1
git -C third-party/android-sigma-rules checkout -b feat/ime-detection-phase-1
```

---

### Task 1: Finalise the allowlist from real data

The allowlist is the product (spec §7). Every false positive and every miss routes through it, so it is built from shipped data and live devices — not from memory.

**Files:** none yet. This task produces the verified package list Task 2 embeds.

**Interfaces:**
- Produces: the final `filter_known_good.package_name` list used verbatim in Task 2.

- [ ] **Step 1: Confirm the seed set against shipped data**

```bash
cd /home/yasir/AndroDR && python3 -c "
import json,re
apps=json.load(open('app/src/main/res/raw/known_good_apps.json'))
pat=re.compile(r'(inputmethod|keyboard|\.ime\b|honeyboard|swiftkey)',re.I)
for a in sorted((x for x in apps if pat.search(x['packageName'])), key=lambda x:x['packageName']):
    print(f\"{a['packageName']:48} {a['category']}\")
"
```

Expected: 73 keyboard-ish packages. This is the menu the seed list below was drawn from — re-run it because the bundled DB may have been regenerated since this plan was written.

- [ ] **Step 2: Harvest stock keyboards from every device you can reach**

The seed list cannot cover vendor stock keyboards that were never in the DB. For each attached device:

```bash
export ANDROID_HOME=/home/yasir/Android/Sdk && export PATH="$ANDROID_HOME/platform-tools:$PATH"
adb devices -l
adb shell ime list -a -s          # every installed IME, one component per line
adb shell settings get secure default_input_method
```

Take the package part (`substringBefore('/')`) of each line. Add any **vendor stock** keyboard to the allowlist. Do **not** add a package just because it is preinstalled — if it belongs to the Baidu, Sogou, iFlytek, TouchPal, Simeji or Kika families it stays off the list, even when it is the device's default keyboard. That is the whole point of the design.

If the OPPO CPH2735 is reachable, this is the step that captures its ColorOS stock IME package. If it is not reachable, ship without it: the consequence is one `low` "not reviewed" finding on ColorOS devices until someone adds it, which the severity and wording are designed to tolerate.

- [ ] **Step 3: Record the exclusions explicitly**

These are keyboard packages that appear in the shipped DB and **must not** be allowlisted. Confirm each is absent from your list before continuing:

```
com.emoji.keyboard.touchpal                 TouchPal
com.iflytek.inputmethod.miui                iFlytek
com.simejikeyboard                          Simeji (Baidu-operated)
com.sohu.inputmethod.sogou.meizu            Sogou
com.sohu.inputmethod.sogou.nubia            Sogou
com.sohu.inputmethod.sogou.oem              Sogou
com.sohu.inputmethod.sogou.xiaomi           Sogou
com.sohu.inputmethod.sogouoem               Sogou
com.kikaoem.hw.qisiemoji.inputmethod        Kika
com.baidu.input                             Baidu  (the motivating case)
com.baidu.input_mi / _huawei / _vivo        Baidu vendor builds
```

- [ ] **Step 4: No commit**

This task produces a list, not a file. It is a separate task because getting it wrong is the single largest risk in Phase 1, and a reviewer should be able to reject the list without rejecting the rule.

---

### Task 2: The rule, its mirror, and registration

These land in one commit. `BundledMirrorParityTest` asserts every bundled rule has a byte-equal mirror counterpart, so a bundled-only commit fails the build; and `BundledRulesManifestCompletenessTest` fails for any rule not in `BUNDLED_RULE_IDS`.

**Files:**
- Create: `app/src/main/res/raw/sigma_androdr_090_unreviewed_keyboard.yml`
- Create: `third-party/android-sigma-rules/app_scanner/androdr_090_unreviewed_keyboard.yml` (byte-equal)
- Modify: `app/src/main/java/com/androdr/sigma/SigmaRuleEngine.kt` (`BUNDLED_RULE_IDS`, after line 356)
- Modify: `third-party/android-sigma-rules/rules.txt`, `third-party/android-sigma-rules/rules.sha256`
- Create: `app/src/test/resources/gate4-fixtures/unreviewed-keyboard.yml`

**Interfaces:**
- Consumes: the allowlist from Task 1.
- Produces: a finding titled "Unreviewed Keyboard", `level: low`, from the `app_scanner` logsource.

- [ ] **Step 1: Write the rule**

Create `app/src/main/res/raw/sigma_androdr_090_unreviewed_keyboard.yml`. Replace the `package_name` list with Task 1's final list; the entries below are the verified seed set.

```yaml
title: Unreviewed keyboard installed
id: androdr-090
status: experimental
category: incident
description: >
    An app declares an input-method service and is not on the reviewed-keyboard
    list. A keyboard sits between the user and every text field on the device —
    passwords included, because Android cannot hide password input from the
    keyboard that renders it. This finding means "not reviewed", not "malicious":
    the app may simply be a keyboard nobody has assessed yet.
author: AndroDR
date: 2026/07/26
logsource:
    product: androdr
    service: app_scanner
detection:
    selection:
        service_permissions|contains: "BIND_INPUT_METHOD"
    filter_known_good:
        package_name:
            # AOSP / Google
            - com.android.inputmethod.latin
            - com.google.android.inputmethod.latin
            - com.google.android.inputmethod.japanese
            - com.google.android.inputmethod.korean
            - com.google.android.inputmethod.pinyin
            - com.google.android.apps.inputmethod.hindi
            - com.google.android.apps.handwriting.ime
            - com.google.android.tts
            # Samsung
            - com.samsung.android.honeyboard
            - com.sec.android.inputmethod
            - com.sec.android.inputmethod.beta
            - com.sec.android.inputmethod.iwnnime.japan
            # Partner preinstall
            - com.touchtype.swiftkey
            # OEM stock and secure keyboards
            - com.coloros.securitykeyboard
            - com.oplus.securitykeyboard
            - com.miui.securityinputmethod
            - com.huawei.ohos.inputmethod
            - com.lge.ime
            - com.blackberry.keyboard
            # Open source
            - org.dslul.openboard.inputmethod.latin
            - helium314.keyboard
            - org.futo.inputmethod.latin
            - com.menny.android.anysoftkeyboard
            - rkr.simplekeyboard.inputmethod
            - org.pocketworkstation.pckeyboard
            - com.simplemobiletools.keyboard
            - juloo.keyboard2
            - dev.patrickgold.florisboard
            - abk.keyboard
            - com.goodwy.keyboard
    condition: selection and not filter_known_good
level: low
display:
    category: app_risk
    icon: keyboard
    triggered_title: "Unreviewed Keyboard"
    evidence_type: none
    guidance: "REVIEW -- this app is a keyboard that has not been assessed"
falsepositives:
    - A keyboard deliberately installed for another language or layout
    - Accessibility keyboards (switch-access, scanning, large-key)
    - MDM-deployed corporate keyboards, which the user cannot remove
    - Regional OEM stock keyboards not yet on the reviewed list
    - An app that bundles an input-method service for a niche feature but is not used as a keyboard
remediation:
    - "This app is a keyboard. If you have enabled it, it can read everything you type, including passwords and card numbers."
    - "Check which keyboards are enabled in your device settings (the exact path varies by manufacturer) and remove any you did not add deliberately."
    - "If your employer manages this device, contact your IT administrator before removing it."
```

No ATT&CK tag. Per the `androdr-015` precedent, `attack.t1417.001` (Input Capture: Keylogging) implies intent that a `low` informational finding cannot support.

- [ ] **Step 2: Register the rule in the loader manifest**

In `app/src/main/java/com/androdr/sigma/SigmaRuleEngine.kt`, immediately after `R.raw.sigma_androdr_089_sms_notification_otp_theft,` (line ~356, before the `// Atom rules` comment):

```kotlin
            R.raw.sigma_androdr_090_unreviewed_keyboard,
```

`BUNDLED_RULE_IDS` is an explicit R8-safe list. Skipping this ships a rule in the APK that never loads, and makes Task 3's on-device check pass vacuously.

- [ ] **Step 3: Mirror the rule and regenerate the manifest**

```bash
cd /home/yasir/AndroDR
cp app/src/main/res/raw/sigma_androdr_090_unreviewed_keyboard.yml \
   third-party/android-sigma-rules/app_scanner/androdr_090_unreviewed_keyboard.yml
printf 'app_scanner/androdr_090_unreviewed_keyboard.yml\n' >> third-party/android-sigma-rules/rules.txt
LC_ALL=C sort -o third-party/android-sigma-rules/rules.txt third-party/android-sigma-rules/rules.txt
( cd third-party/android-sigma-rules && while read -r f; do printf '%s  %s\n' "$(sha256sum "$f" | cut -d' ' -f1)" "$f"; done < rules.txt > rules.sha256 )
python3 third-party/android-sigma-rules/validation/validate-rule.py \
   third-party/android-sigma-rules/app_scanner/androdr_090_unreviewed_keyboard.yml
python3 third-party/android-sigma-rules/validation/validate-delivery-set.py
```

Expected: `PASS` from both validators.

- [ ] **Step 4: Write the gate-4 fixture**

Create `app/src/test/resources/gate4-fixtures/unreviewed-keyboard.yml`. True negatives are the Fold 2's real enabled input methods; the fixture needs no `ioc_stubs` because the rule uses no `ioc_lookup`.

```yaml
# Fixture for androdr-090. True negatives are the actual enabled input methods on
# the attached Samsung SM-F916B, so the allowlist is exercised against a real
# device rather than invented packages.
#
# service_permissions carries fully-qualified permission names exactly as
# AppScanner emits them (AppTelemetry.toFieldMap), and the rule matches with
# |contains — the same shape androdr-089 ships in production.
rule_file: sigma_androdr_090_unreviewed_keyboard.yml
service: app_scanner

true_positives:
  # The motivating case — CPH2735 field scan
  - package_name: "com.baidu.input"
    service_permissions:
      - "android.permission.BIND_INPUT_METHOD"
  # Vendor build of the same engine. The superseded draft could not flag this,
  # because category OEM set is_known_oem_app: true and the old selection
  # carried is_known_oem_app: false. Nothing here reads that field.
  - package_name: "com.baidu.input_mi"
    service_permissions:
      - "android.permission.BIND_INPUT_METHOD"
  # Namespace squatter — caught by exact-match allowlisting, no special rule
  - package_name: "com.google.android.inputmethod.latin2"
    service_permissions:
      - "android.permission.BIND_INPUT_METHOD"

true_negatives:
  # Fold 2, enabled + active
  - package_name: "com.samsung.android.honeyboard"
    service_permissions:
      - "android.permission.BIND_INPUT_METHOD"
  # Fold 2, enabled
  - package_name: "com.google.android.tts"
    service_permissions:
      - "android.permission.BIND_INPUT_METHOD"
  # Fold 2, enabled but dormant — would have false-positived before rules#47
  # restored partner_preinstall_prefixes
  - package_name: "com.touchtype.swiftkey"
    service_permissions:
      - "android.permission.BIND_INPUT_METHOD"
  # FOSS keyboard from F-Droid — no installer-provenance gate can vouch for it,
  # which is why the allowlist names it directly
  - package_name: "org.dslul.openboard.inputmethod.latin"
    service_permissions:
      - "android.permission.BIND_INPUT_METHOD"
  # Not a keyboard — declares a different BIND_* service permission
  - package_name: "com.example.notificationreader"
    service_permissions:
      - "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE"
  # Not a keyboard — declares no service permissions at all
  - package_name: "com.example.plainapp"
    service_permissions: []
```

- [ ] **Step 5: Run the gates**

```bash
cd /home/yasir/AndroDR
export JAVA_HOME=/home/yasir/Applications/android-studio/jbr && export ANDROID_HOME=/home/yasir/Android/Sdk && export PATH="$JAVA_HOME/bin:$PATH"
./gradlew testDebugUnitTest --tests 'com.androdr.sigma.*'
```

Expected: `BUILD SUCCESSFUL`. Gate-4 fixture count rises by one. `BundledMirrorParityTest`, `RuleManifestIntegrityTest` and `BundledRulesManifestCompletenessTest` all pass — a parity failure means Step 3's `cp` did not run or the bundled file was edited afterwards; a completeness failure means Step 2 was skipped.

- [ ] **Step 6: Full suite and commit**

```bash
cd /home/yasir/AndroDR && ./gradlew testDebugUnitTest lintDebug detekt
git -C third-party/android-sigma-rules add -A
git -C third-party/android-sigma-rules commit -m "feat(rules): androdr-090 unreviewed keyboard detection"
git add app/src/main/res/raw/sigma_androdr_090_unreviewed_keyboard.yml \
        app/src/main/java/com/androdr/sigma/SigmaRuleEngine.kt \
        app/src/test/resources/gate4-fixtures/unreviewed-keyboard.yml \
        third-party/android-sigma-rules
git commit -m "feat(detection): flag keyboards that have not been reviewed (androdr-090)

Keys on service_permissions|contains: BIND_INPUT_METHOD, which is already on
AppTelemetry and already in the taxonomy, so this needs no scanner, no
telemetry field and no taxonomy change.

Deliberately references neither is_known_oem_app nor is_system_app nor
from_trusted_store: the first is true for the Baidu/Sogou/iFlytek vendor
variants this rule exists to catch, and the preinstalled vendor cloud
keyboards are the threat rather than the exemption. Exemption is an exact-match
allowlist inside the rule, which also retires the need for a namespace-squatter
rule — a squatter's package name simply is not on the list."
```

---

### Task 3: On-device verification

Gate-4 feeds field values verbatim, so it proves the rule's boolean logic and nothing about real devices (#269). This task is the only evidence the rule behaves on hardware.

**Files:** none modified.

- [ ] **Step 1: Install and scan the Fold 2**

```bash
cd /home/yasir/AndroDR
export JAVA_HOME=/home/yasir/Applications/android-studio/jbr && export ANDROID_HOME=/home/yasir/Android/Sdk && export PATH="$JAVA_HOME/bin:$ANDROID_HOME/platform-tools:$PATH"
adb devices -l          # expect R3CR300WRRH (SM_F916B)
adb shell ime list -a -s
./gradlew installDebug
```

Run a scan in the app.

- [ ] **Step 2: Assert zero false positives, from the database rather than by eye**

```bash
adb exec-out run-as com.androdr.debug cat databases/androdr.db     > /tmp/androdr.db
adb exec-out run-as com.androdr.debug cat databases/androdr.db-wal > /tmp/androdr.db-wal
```

Pull the `-wal` sidecar or recent writes are invisible. Then assert **both**: no `androdr-090` finding exists, **and** the scan produced findings overall — otherwise an empty or failed scan masquerades as a clean result.

Expected: all three of the Fold 2's enabled keyboards are on the allowlist, so zero `androdr-090` findings.

- [ ] **Step 3: Prove a true positive without building an APK**

A negative-only criterion is satisfied by a rule that can never fire, so a true positive is required. Phase 1 does not need an adversary fixture for this — temporarily removing one entry turns a real keyboard on a real device into a true positive:

```bash
cd /home/yasir/AndroDR
# Temporarily drop SwiftKey from the allowlist
python3 - <<'PY'
import pathlib
p = pathlib.Path("app/src/main/res/raw/sigma_androdr_090_unreviewed_keyboard.yml")
t = p.read_text()
assert "            - com.touchtype.swiftkey\n" in t
p.write_text(t.replace("            - com.touchtype.swiftkey\n", "", 1))
print("swiftkey temporarily removed")
PY
./gradlew installDebug
```

Re-scan and confirm `androdr-090` now fires for `com.touchtype.swiftkey` at `level: low`, with the "Unreviewed Keyboard" title and the remediation text from Task 2.

- [ ] **Step 4: Restore and reinstall**

```bash
cd /home/yasir/AndroDR
git checkout app/src/main/res/raw/sigma_androdr_090_unreviewed_keyboard.yml
git diff --exit-code app/src/main/res/raw/sigma_androdr_090_unreviewed_keyboard.yml && echo "allowlist restored"
./gradlew installDebug
```

Re-scan once more and confirm the finding is gone. **Do not skip this** — a commit containing the temporary removal ships a false positive to every Samsung and HONOR device.

---

### Task 4: Delivery

**Files:** none modified beyond the submodule pointer.

- [ ] **Step 1: Push both branches and open both PRs**

```bash
cd /home/yasir/AndroDR
git -C third-party/android-sigma-rules push -u origin feat/ime-detection-phase-1
git push -u origin feat/ime-detection-phase-1
gh pr create --repo android-sigma-rules/rules --base main --head feat/ime-detection-phase-1 \
  --title "feat(rules): androdr-090 unreviewed keyboard detection"
gh pr create --repo yasirhamza/AndroDR --base main --head feat/ime-detection-phase-1 \
  --title "feat(detection): flag keyboards that have not been reviewed (androdr-090)"
```

PR bodies are written at creation time from spec §1 (motivation), §2 (why the rule references no OEM field), and the Task 3 evidence.

- [ ] **Step 2: Safe ordering per CLAUDE.md**

1. AndroDR CI green. `submodule-check` and `ci-success` are red while the submodule is pinned to the rules branch — expected; the gate that matters is `build-and-test`.
2. Merge the rules PR.
3. Repoint the submodule at the resulting main commit, commit, push; CI goes fully green.
4. Merge the AndroDR PR.

- [ ] **Step 3: Confirm live delivery**

```bash
curl -fsSL "https://raw.githubusercontent.com/android-sigma-rules/rules/main/rules.txt" | grep keyboard
```

Expected: `app_scanner/androdr_090_unreviewed_keyboard.yml` listed. Devices pick it up within 12h — including devices running an older APK, which is safe because the rule reads only `service_permissions`, a field that has shipped for many releases.

---

## Self-Review

**Spec coverage.** §5's rule → Task 2 Step 1. §5's inline-allowlist decision → Task 2 Step 1 (`filter_known_good.package_name`), with the rejected IOC-lookup alternative deliberately not built. §7's governance → Task 1, including the explicit exclusion list. §8's expected outcomes → Task 3 (Fold 2 zero findings; `com.baidu.input`, `com.baidu.input_mi` and the `latin2` squatter as gate-4 true positives). §10's tests → Task 2 Step 4 and Task 3. §11's deleted `androdr-092` and dropped `is_known_oem_app` guard → enforced by Global Constraints and asserted by the `com.baidu.input_mi` true positive, which the superseded design could not flag.

Deliberately **not** covered, per the spec: the scanner, the two telemetry booleans, the taxonomy change, the `androdr-091` active-case rule, and the adversary fixture — all Phase 2. Task 3 Step 3 replaces the adversary fixture for Phase 1 with a cheaper true-positive proof that needs no APK.

**Placeholders.** None. Task 1 produces a list rather than a file, which is a deliverable, not a TBD — its output is consumed verbatim by Task 2 Step 1, and the seed list there is complete and runnable as written if no additional devices are reachable.

**Type consistency.** The rule filename `sigma_androdr_090_unreviewed_keyboard.yml`, its mirror `app_scanner/androdr_090_unreviewed_keyboard.yml`, the `R.raw.sigma_androdr_090_unreviewed_keyboard` registry entry, the `rules.txt` path and the fixture's `rule_file` all use the same stem. `service_permissions` and `package_name` match the field names in `AppTelemetry.toFieldMap()` and the logsource taxonomy.

**Verified against source while writing:** `BUNDLED_RULE_IDS` ends at `sigma_androdr_089_sms_notification_otp_theft` before the atom-rule block (`SigmaRuleEngine.kt:356`); `service_permissions` is at `AppTelemetry.kt:62` and `logsource-taxonomy.yml:33`; `androdr-089` already ships `service_permissions|contains`; a bare list on a string field is already used by `androdr-066` (`intent_action`); and every allowlist and exclusion package above was read out of the shipped `known_good_apps.json`.

**Dry-run evidence (2026-07-26).** The rule and fixture in Task 2 were extracted from this plan verbatim, staged into `res/raw` and `gate4-fixtures/`, and run through the real gates before being reverted:

- `validate-rule.py` → `PASS` (Gate 1 schema).
- `GateFourFixtureTest[unreviewed-keyboard]` → **passed**, which confirms the rule parses in `SigmaRuleParser`, a bare `package_name` list works inside a filter block, all three true positives fire — including `com.baidu.input_mi`, the case the superseded design could not flag — and all six true negatives are suppressed.

So Task 2's central artifacts are known-good as written. What remains genuinely unverified is Task 1's device harvest and Task 3's on-device behaviour, which no amount of desk checking can establish.
