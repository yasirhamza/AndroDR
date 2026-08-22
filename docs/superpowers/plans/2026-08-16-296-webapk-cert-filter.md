# #296 WebAPK Cert-Anchored Filter Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Stop androdr-010 ("Sideloaded Application") false-positives on Google-minted WebAPKs by adding a cert-anchored exemption filter to the rule itself.

**Architecture:** Pure rule-side fix per the approved spec (`docs/superpowers/specs/2026-08-16-296-webapk-cert-filter-design.md`): androdr-010 gains a `filter_verified_webapk` selection requiring BOTH `package_name|startswith: "org.chromium.webapk."` AND `cert_hash` equal to Google's WebAPK minting cert. No emitter change, no new `ioc_lookup` name. The edit ships to the whole fielded fleet via the 12h rule feed once merged to the rules repo's main; the bundled copy is updated byte-equal for cold-start parity.

**Tech Stack:** SIGMA YAML rules (AndroDR dialect), Kotlin/JUnit4 unit tests, git submodule (`third-party/android-sigma-rules` → github.com/android-sigma-rules/rules), adb/apksigner/aapt2 for on-device work.

## Global Constraints

- Working directory for ALL commands: `/home/yasir/AndroDR/.claude/worktrees/phase2-from-trusted-store` (a git worktree — never cd to `/home/yasir/AndroDR`). AndroDR branch: `fix/296-webapk-cert-filter` (already created, tracks origin/main, spec committed).
- Env block required before any gradle/adb/apksigner command:
  ```bash
  export JAVA_HOME=/home/yasir/Applications/android-studio/jbr
  export ANDROID_HOME=/home/yasir/Android/Sdk
  export PATH="$JAVA_HOME/bin:$ANDROID_HOME/platform-tools:$HOME/.local/bin:$PATH"
  ```
- The bundled rule `app/src/main/res/raw/sigma_androdr_010_sideloaded_app.yml` and the mirror `third-party/android-sigma-rules/app_scanner/androdr_010_sideloaded_app.yml` MUST stay byte-equal (`BundledMirrorParityTest` enforces this).
- Any change to a `rules.txt`-listed file requires regenerating `rules.sha256` (recipe in Task 3) — a stale manifest silently drops the rule fleet-wide.
- Safe-ordering (spec): rules-repo main merge happens ONLY after AndroDR CI is green, on-device verification passed, and the review ceremony is clean.
- Chrome must NOT be added to `trusted_installers`. No emitter (`AppScanner`/`AppTelemetry`) changes. No new `ioc_lookup` name. No changes to `ioc-lookup-definitions.yml` or `logsource-taxonomy.yml` (`cert_hash` and `package_name` are already registered active `app_scanner` raw facts).
- The minter cert SHA-256 enters any file ONLY after Task 1's two independent sources agree. `<CERT_SHA256>` below always means the Task-1-confirmed value (64 lowercase hex chars) stored in `/tmp/claude-1000/-home-yasir-AndroDR--claude-worktrees-phase2-from-trusted-store/3a72f155-94b1-4c49-b673-38b5e37749b1/scratchpad/webapk-minter-cert.txt`.
- Debug app package id: `com.androdr.debug`. Verification device: Samsung Fold 2 (SM-F916B), attached via USB.

---

### Task 1: Cert ground truth — device extraction + Chromium cross-check

**Files:**
- Create: `/tmp/claude-1000/-home-yasir-AndroDR--claude-worktrees-phase2-from-trusted-store/3a72f155-94b1-4c49-b673-38b5e37749b1/scratchpad/webapk-minter-cert.txt` (the confirmed cert, one line, 64 lowercase hex chars)

**Interfaces:**
- Consumes: nothing (first task).
- Produces: `webapk-minter-cert.txt` — consumed by Tasks 2 and 3 as `<CERT_SHA256>`.

- [ ] **Step 1: Confirm the Fold 2 is attached and has a real WebAPK**

```bash
export ANDROID_HOME=/home/yasir/Android/Sdk
export PATH="$ANDROID_HOME/platform-tools:$PATH"
adb devices                      # expect one 'device' entry (SM-F916B)
adb shell pm list packages | grep org.chromium.webapk
```

Expected: at least one `package:org.chromium.webapk.<suffix>` line. If NONE: stop and ask the user to install any PWA from Chrome on the Fold 2 (open e.g. https://squoosh.app in Chrome → menu → "Install app", wait ~1 min for WebAPK minting), then re-run. A real WebAPK is also required by Task 5's positive test, so this is a hard prerequisite.

- [ ] **Step 2: Pull the WebAPK and extract its signing-cert SHA-256**

```bash
PKG=$(adb shell pm list packages | grep org.chromium.webapk | head -1 | sed 's/^package://' | tr -d '\r')
APK=$(adb shell pm path "$PKG" | head -1 | sed 's/^package://' | tr -d '\r')
adb pull "$APK" /tmp/claude-1000/-home-yasir-AndroDR--claude-worktrees-phase2-from-trusted-store/3a72f155-94b1-4c49-b673-38b5e37749b1/scratchpad/webapk-real.apk
BT=$ANDROID_HOME/build-tools/$(ls $ANDROID_HOME/build-tools | sort -V | tail -1)
$BT/apksigner verify --print-certs /tmp/claude-1000/-home-yasir-AndroDR--claude-worktrees-phase2-from-trusted-store/3a72f155-94b1-4c49-b673-38b5e37749b1/scratchpad/webapk-real.apk
```

Record the `Signer #1 certificate SHA-256 digest` value (lowercase, strip colons if any). This is candidate A.

- [ ] **Step 3: Independently derive the cert from Chromium source**

Fetch Chromium's WebAPK validator (the client that hard-codes the minting server's expected signature):

```bash
curl -s "https://chromium.googlesource.com/chromium/src/+/main/components/webapk/android/libs/client/src/org/chromium/webapk/lib/client/WebApkValidator.java?format=TEXT" | base64 -d > /tmp/claude-1000/-home-yasir-AndroDR--claude-worktrees-phase2-from-trusted-store/3a72f155-94b1-4c49-b673-38b5e37749b1/scratchpad/WebApkValidator.java
```

If that path 404s, locate the current path by fetching `https://source.chromium.org/search?q=EXPECTED_SIGNATURE%20webapk` via WebFetch/WebSearch, or try the legacy path `chrome/android/webapk/libs/client/src/org/chromium/webapk/lib/client/WebApkValidator.java`. In the file, find the expected-signature/cert constant (historically `EXPECTED_SIGNATURE` byte array = DER-encoded signing cert). Reconstruct the bytes and hash them:

```bash
# after extracting the java byte array into a python list `der`:
python3 -c "import hashlib; der=bytes([...]); print(hashlib.sha256(der).hexdigest())"
```

If the constant is a cert fingerprint rather than DER bytes, compare directly. If neither is extractable, use WebSearch for the documented WebAPK signing-cert SHA-256 fingerprint from an authoritative source (Chromium docs / Google developer docs) as candidate B. This is candidate B.

- [ ] **Step 4: The agreement gate**

Compare candidate A (device) and candidate B (Chromium). They MUST be identical. If they differ — STOP THE ENTIRE PLAN and report to the user; do not proceed with either value. If Chromium documents multiple valid minter certs (e.g. rotation), record all of them, one per line, device-observed cert first.

```bash
echo "<the agreed 64-hex lowercase value>" > /tmp/claude-1000/-home-yasir-AndroDR--claude-worktrees-phase2-from-trusted-store/3a72f155-94b1-4c49-b673-38b5e37749b1/scratchpad/webapk-minter-cert.txt
cat /tmp/claude-1000/-home-yasir-AndroDR--claude-worktrees-phase2-from-trusted-store/3a72f155-94b1-4c49-b673-38b5e37749b1/scratchpad/webapk-minter-cert.txt | grep -cE '^[0-9a-f]{64}$'   # expect >= 1
```

No commit (no repo files changed).

---

### Task 2: TDD — rule-level tests + the rule edit (both byte-equal copies)

**Files:**
- Create: `app/src/test/java/com/androdr/sigma/Rule010WebApkFilterTest.kt`
- Modify: `app/src/main/res/raw/sigma_androdr_010_sideloaded_app.yml`
- Modify: `third-party/android-sigma-rules/app_scanner/androdr_010_sideloaded_app.yml` (byte-equal copy; committed submodule-side in Task 3)

**Interfaces:**
- Consumes: `<CERT_SHA256>` from Task 1's `webapk-minter-cert.txt`.
- Produces: the final androdr-010 YAML content (identical in both files) that Tasks 3–5 deliver and verify; test class `Rule010WebApkFilterTest`.

- [ ] **Step 1: Write the failing test**

Create `app/src/test/java/com/androdr/sigma/Rule010WebApkFilterTest.kt`. Replace `<CERT_SHA256>` with the Task-1 value:

```kotlin
package com.androdr.sigma

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * Rule-level tests for androdr-010's cert-anchored WebAPK exemption (#296).
 * Loads the ACTUAL bundled rule file so the tests gate the shipped artifact,
 * not a hand-built copy. The minter cert is duplicated here on purpose: if
 * the rule file's cert value drifts, these tests fail.
 */
class Rule010WebApkFilterTest {

    private val minterCert = "<CERT_SHA256>"

    private fun loadRule(): SigmaRule {
        val f = listOf(
            File("app/src/main/res/raw/sigma_androdr_010_sideloaded_app.yml"),
            File("src/main/res/raw/sigma_androdr_010_sideloaded_app.yml"),
        ).firstOrNull { it.isFile }
            ?: error("bundled androdr-010 not found from ${File(".").absolutePath}")
        return SigmaRuleParser.parse(f.readText())
            ?: error("androdr-010 failed to parse")
    }

    // known_good_app_db MUST be present: the R1 fail-closed evaluator skips
    // any rule referencing a lookup name absent from this map.
    private val lookups = mapOf<String, (Any) -> Boolean>(
        "known_good_app_db" to { pkg -> pkg.toString() == "com.x8bit.bitwarden" }
    )

    private fun fires(record: Map<String, Any?>): Boolean =
        SigmaRuleEvaluator.evaluate(listOf(loadRule()), listOf(record), "app_scanner", lookups)
            .any { it.triggered }

    private fun app(pkg: String, cert: String?) = mapOf(
        "package_name" to pkg,
        "is_system_app" to false,
        "from_trusted_store" to false,
        "is_known_oem_app" to false,
        "cert_hash" to cert,
    )

    @Test
    fun `google minted webapk is exempt`() =
        assertFalse(fires(app("org.chromium.webapk.a1b2c3d4", minterCert)))

    @Test
    fun `webapk prefix with wrong cert still fires`() =
        assertTrue(fires(app("org.chromium.webapk.evil", "deadbeef".repeat(8))))

    @Test
    fun `minter cert on non webapk package still fires`() =
        assertTrue(fires(app("com.evil.app", minterCert)))

    @Test
    fun `webapk prefix with null cert still fires`() =
        assertTrue(fires(app("org.chromium.webapk.evil", null)))

    @Test
    fun `plain sideload still fires`() =
        assertTrue(fires(app("com.random.sideload", "ab".repeat(32))))

    @Test
    fun `known good app stays exempt`() =
        assertFalse(fires(app("com.x8bit.bitwarden", "ab".repeat(32))))

    @Test
    fun `cert match is case insensitive`() =
        assertFalse(fires(app("org.chromium.webapk.a1b2c3d4", minterCert.uppercase())))
}
```

- [ ] **Step 2: Run the tests — verify the exemption cases fail**

```bash
export JAVA_HOME=/home/yasir/Applications/android-studio/jbr
export PATH="$JAVA_HOME/bin:$PATH"
./gradlew testDebugUnitTest --tests 'com.androdr.sigma.Rule010WebApkFilterTest' 2>&1 | tail -20
```

Expected: `google minted webapk is exempt` and `cert match is case insensitive` FAIL (the filter doesn't exist yet, so the rule fires). The five "still fires"/"stays exempt" tests already PASS (they document current behavior and become regression guards).

- [ ] **Step 3: Edit the rule — write the identical content to BOTH files**

Full new content for `app/src/main/res/raw/sigma_androdr_010_sideloaded_app.yml` (replace `<CERT_SHA256>`; the ONLY changes vs current are the `filter_verified_webapk` block and the `condition` line — keep everything else byte-identical):

```yaml
title: App installed from untrusted source
id: androdr-010
status: production
description: App was not installed via a trusted app store.
author: AndroDR
date: 2026/03/27
tags:
    - attack.t1476
logsource:
    product: androdr
    service: app_scanner
detection:
    selection:
        is_system_app: false
        from_trusted_store: false
        is_known_oem_app: false
    filter_known_good:
        package_name|ioc_lookup: known_good_app_db
    # WebAPK exemption (#296): PWAs minted by Google's WebAPK service have
    # per-device randomized package names, so no allowlist can cover them.
    # Trust is anchored on the minting service's signing cert — the prefix
    # alone is spoofable, the cert is not. Both conjuncts must match.
    filter_verified_webapk:
        package_name|startswith: "org.chromium.webapk."
        cert_hash: "<CERT_SHA256>"
    condition: selection and not filter_known_good and not filter_verified_webapk
level: medium
category: incident
display:
    category: app_risk
    icon: download
    triggered_title: "Sideloaded Application"
    evidence_type: none
    guidance: "REVIEW -- sideloaded app with elevated permissions; verify intentional"
remediation:
    - "This app was not installed from a trusted app store. Verify you intended to install it."
implies_flags:
    - sideloaded
```

If Task 1 produced multiple certs, `cert_hash` becomes a YAML list (one quoted hex value per `- ` line, device-observed cert first).

Then copy byte-equal to the mirror:

```bash
cp app/src/main/res/raw/sigma_androdr_010_sideloaded_app.yml third-party/android-sigma-rules/app_scanner/androdr_010_sideloaded_app.yml
diff app/src/main/res/raw/sigma_androdr_010_sideloaded_app.yml third-party/android-sigma-rules/app_scanner/androdr_010_sideloaded_app.yml && echo BYTE-EQUAL
```

- [ ] **Step 4: Run the new tests plus the sigma gate — all green**

```bash
./gradlew testDebugUnitTest --tests 'com.androdr.sigma.Rule010WebApkFilterTest' 2>&1 | tail -5
./gradlew testDebugUnitTest 2>&1 | tail -15
```

Expected: all 7 new tests PASS; full unit suite PASS. `BundledMirrorParityTest` will FAIL at this point ONLY if the mirror copy was missed — but note `RuleManifestIntegrityTest` is EXPECTED to fail now (manifest not yet regenerated; that is Task 3's first step and the reason Tasks 2+3 land as one PR). If the full suite fails only on `RuleManifestIntegrityTest`, proceed to Task 3.

- [ ] **Step 5: Commit (AndroDR side only)**

```bash
git add app/src/main/res/raw/sigma_androdr_010_sideloaded_app.yml app/src/test/java/com/androdr/sigma/Rule010WebApkFilterTest.kt
git commit -m "fix(detection): androdr-010 cert-anchored WebAPK exemption filter (#296)

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01NahFvjzP3RaHfJAYhbWMDa"
```

(The mirror file lives in the submodule working tree and is committed there in Task 3.)

---

### Task 3: Rules-repo branch — manifest regen + PR

**Files:**
- Modify (in submodule `third-party/android-sigma-rules`, new branch `fix/webapk-cert-filter`): `app_scanner/androdr_010_sideloaded_app.yml` (already edited on disk by Task 2), `rules.sha256` (regenerated)

**Interfaces:**
- Consumes: the edited mirror file from Task 2.
- Produces: pushed rules-repo branch `fix/webapk-cert-filter` + its PR (validate CI green) + the branch head SHA — consumed by Task 4's submodule bump.

- [ ] **Step 1: Create the submodule branch and regenerate the manifest**

```bash
git -C third-party/android-sigma-rules checkout -b fix/webapk-cert-filter
git -C third-party/android-sigma-rules status --short   # expect: M app_scanner/androdr_010_sideloaded_app.yml
```

Regenerate `rules.sha256` (CLAUDE.md recipe — must run with the submodule as working directory; use a subshell so the session stays in the worktree):

```bash
(cd third-party/android-sigma-rules && while read -r f; do printf '%s  %s\n' "$(sha256sum "$f" | cut -d' ' -f1)" "$f"; done < rules.txt > rules.sha256)
git -C third-party/android-sigma-rules diff --stat   # expect exactly 2 files: the rule + rules.sha256
```

- [ ] **Step 2: Verify the manifest gate passes locally**

```bash
export JAVA_HOME=/home/yasir/Applications/android-studio/jbr
export PATH="$JAVA_HOME/bin:$PATH"
./gradlew testDebugUnitTest --tests 'com.androdr.sigma.RuleManifestIntegrityTest' --tests 'com.androdr.sigma.BundledMirrorParityTest' 2>&1 | tail -5
```

Expected: PASS.

- [ ] **Step 3: Commit and push the rules-repo branch, open its PR**

```bash
git -C third-party/android-sigma-rules add app_scanner/androdr_010_sideloaded_app.yml rules.sha256
git -C third-party/android-sigma-rules commit -m "fix(androdr-010): cert-anchored WebAPK exemption filter

WebAPK package names are per-device randomized; trust anchors on the
Google WebAPK minting cert, not the (spoofable) package prefix.
AndroDR#296.

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01NahFvjzP3RaHfJAYhbWMDa"
git -C third-party/android-sigma-rules push -u origin fix/webapk-cert-filter
export PATH="$HOME/.local/bin:$PATH"
gh pr create -R android-sigma-rules/rules --head fix/webapk-cert-filter \
  --title "fix(androdr-010): cert-anchored WebAPK exemption filter" \
  --body "Exempts Google-minted WebAPKs from androdr-010 via a package-prefix AND signing-cert conjunction. Cert double-confirmed from a real device WebAPK and Chromium source. Companion app PR: AndroDR fix/296-webapk-cert-filter (Closes AndroDR#296 there). DO NOT MERGE until the AndroDR PR is CI-green and on-device verification has passed (safe-ordering)."
```

- [ ] **Step 4: Wait for the rules-repo `validate` check — green required**

```bash
gh pr checks -R android-sigma-rules/rules fix/webapk-cert-filter --watch
```

Expected: `validate` green. Red → read the log (`gh run view`), fix, push, re-watch. Do NOT merge this PR yet (Task 7 does, after gates).

---

### Task 4: AndroDR PR — submodule bump + full local gate

**Files:**
- Modify: `third-party/android-sigma-rules` (gitlink → Task 3 branch head)

**Interfaces:**
- Consumes: Task 3's pushed branch head.
- Produces: AndroDR PR (number recorded for Tasks 6–7) on branch `fix/296-webapk-cert-filter`, CI build check green.

- [ ] **Step 1: Bump the submodule pointer and run the full local gate**

```bash
git -C third-party/android-sigma-rules rev-parse HEAD   # record: BRANCH_SHA
git add third-party/android-sigma-rules
export JAVA_HOME=/home/yasir/Applications/android-studio/jbr
export PATH="$JAVA_HOME/bin:$PATH"
./gradlew testDebugUnitTest lintDebug 2>&1 | tail -10
```

Expected: full suite + lint PASS (manifest and parity tests now see the regenerated manifest via the bumped pointer).

- [ ] **Step 2: Commit, push, open the AndroDR PR**

```bash
git commit -m "fix(detection): bump sigma-rules submodule for androdr-010 WebAPK filter (#296)

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01NahFvjzP3RaHfJAYhbWMDa"
git push -u origin fix/296-webapk-cert-filter
export PATH="$HOME/.local/bin:$PATH"
gh pr create --base main --head fix/296-webapk-cert-filter \
  --title "fix(detection): cert-anchored WebAPK exemption on androdr-010" \
  --body "$(cat <<'EOF'
Google-minted WebAPKs (org.chromium.webapk.*, per-device randomized names) no longer fire androdr-010: the rule gains a filter requiring BOTH the WebAPK package prefix AND the Google minting-cert SHA-256 (double-confirmed from a real device WebAPK + Chromium source). Pure rule-side fix — no emitter change, no new ioc_lookup name, Chrome stays untrusted. Feed-delivers to all fielded binaries; bundled copy updated byte-equal for cold start. Spec: docs/superpowers/specs/2026-08-16-296-webapk-cert-filter-design.md

Safe-ordering note: submodule points at rules-repo branch fix/webapk-cert-filter until on-device verification + review ceremony pass; then the rules PR merges and the pointer moves to rules main (final commit on this PR).

Closes #296

🤖 Generated with [Claude Code](https://claude.com/claude-code)

https://claude.ai/code/session_01NahFvjzP3RaHfJAYhbWMDa
EOF
)"
gh pr checks --watch
```

Expected: the `build` check green. The `submodule-check` job may be RED at this stage BY DESIGN (submodule points at a rules branch mid-safe-ordering); `build`/tests are the real gate here.

---

### Task 5: On-device verification — Fold 2

**Files:**
- Create: `/tmp/claude-1000/-home-yasir-AndroDR--claude-worktrees-phase2-from-trusted-store/3a72f155-94b1-4c49-b673-38b5e37749b1/scratchpad/evil-webapk/` (throwaway spoof-APK build dir)

**Interfaces:**
- Consumes: Task 2's edited bundled rule (via a fresh debug install); the real WebAPK from Task 1.
- Produces: pass/fail evidence for the positive (no FP) and negative (spoof fires) cases — gate for Task 7.

- [ ] **Step 1: Build the spoof APK (`org.chromium.webapk.evil`, debug-signed, no code)**

```bash
export ANDROID_HOME=/home/yasir/Android/Sdk
export JAVA_HOME=/home/yasir/Applications/android-studio/jbr
export PATH="$JAVA_HOME/bin:$ANDROID_HOME/platform-tools:$PATH"
BT=$ANDROID_HOME/build-tools/$(ls $ANDROID_HOME/build-tools | sort -V | tail -1)
PLATFORM=$ANDROID_HOME/platforms/$(ls $ANDROID_HOME/platforms | sort -V | tail -1)
D=/tmp/claude-1000/-home-yasir-AndroDR--claude-worktrees-phase2-from-trusted-store/3a72f155-94b1-4c49-b673-38b5e37749b1/scratchpad/evil-webapk
mkdir -p "$D" && cat > "$D/AndroidManifest.xml" <<'EOF'
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="org.chromium.webapk.evil">
  <application android:hasCode="false" android:label="Evil WebAPK"/>
</manifest>
EOF
$BT/aapt2 link -o "$D/evil-unsigned.apk" --manifest "$D/AndroidManifest.xml" \
  -I "$PLATFORM/android.jar" --min-sdk-version 26 --target-sdk-version 34 \
  --version-code 1 --version-name 1.0
$BT/zipalign -f 4 "$D/evil-unsigned.apk" "$D/evil-aligned.apk"
$BT/apksigner sign --ks ~/.android/debug.keystore --ks-pass pass:android \
  --ks-key-alias androiddebugkey --out "$D/evil.apk" "$D/evil-aligned.apk"
$BT/apksigner verify --print-certs "$D/evil.apk" | head -5   # debug cert, NOT the minter cert
```

- [ ] **Step 2: Fresh debug install with network off (so the old feed rule can't replace the edited bundled rule)**

The engine replaces bundled rules with same-id remote copies on fetch; the feed still serves the OLD androdr-010 until Task 7. Force bundled-only evaluation:

```bash
./gradlew installDebug
adb shell pm clear com.androdr.debug          # drop any cached remote rules
adb shell svc wifi disable
adb shell svc data disable
adb install "$D/evil.apk"
adb shell monkey -p com.androdr.debug -c android.intent.category.LAUNCHER 1
```

Then run a scan in the app (tap "Scan" in the AndroDR debug UI on the device — ask the user if a hand is needed; the device is attached and unlocked for this session).

- [ ] **Step 3: Verify both cases from the on-device DB**

```bash
adb shell run-as com.androdr.debug ls databases   # discover the Room DB filename
DB=<name from above>
for s in "" -wal -shm; do adb shell run-as com.androdr.debug cat "databases/$DB$s" > "$D/db$s" 2>/dev/null; done
sqlite3 "$D/db" ".tables"                          # discover the findings table/schema
sqlite3 "$D/db" "select * from <findings-table> where <rule-id-col> like '%androdr-010%';"
```

(The `-wal` sidecar pull is mandatory — recent writes are invisible without it.)

PASS criteria — BOTH must hold:
1. **Positive:** NO androdr-010 finding for the real WebAPK package (`org.chromium.webapk.<Task-1 suffix>`).
2. **Negative:** an androdr-010 finding EXISTS for `org.chromium.webapk.evil`.

If the positive case fails, the likely cause is the emitted `cert_hash` differing from the Task-1 value — dump it (`select package_name, cert_hash from <apps/telemetry table> where package_name like 'org.chromium.webapk%';`), compare, STOP and report if they differ (this is the spec's "single unproven link" check).

- [ ] **Step 4: Restore the device**

```bash
adb uninstall org.chromium.webapk.evil
adb shell svc wifi enable
adb shell svc data enable
```

No commit (no repo files changed). Report the evidence (both query outputs) in the task result.

---

### Task 6: 4-agent review ceremony

**Files:** none modified unless findings require fixes.

**Interfaces:**
- Consumes: the AndroDR PR diff, the rules-repo PR diff, and the spec.
- Produces: consolidated verdict; any fixes committed and re-gated. Gate for Task 7.

- [ ] **Step 1: Dispatch four parallel review subagents** (single message, four Agent calls), each given: the spec path (`docs/superpowers/specs/2026-08-16-296-webapk-cert-filter-design.md`), both diffs (`git diff origin/main...HEAD` in the worktree and `git -C third-party/android-sigma-rules diff origin/main...HEAD`), and one mandate each:

1. **Correctness:** does the filter implement the spec exactly (conjunction semantics, condition string, case handling, null handling)? Do the tests actually prove it (run them)?
2. **Code quality:** test design, YAML style vs sibling rules, comment quality, no dead artifacts.
3. **Architect:** spec conformance, safe-ordering soundness, bundled↔mirror↔manifest coherence, Phase-2 (#136) non-interference, blast-radius containment to androdr-010.
4. **Code security (attack the filter):** try to defeat the exemption — package-name tricks (case, unicode, prefix boundaries like `org.chromium.webapkX`), cert-field forgery routes (can any attacker-controlled input reach `cert_hash`?), feed-poisoning surface, and whether the exemption could ever suppress a TRUE positive.

- [ ] **Step 2: Consolidate findings; fix anything actionable; re-run the full gate (`./gradlew testDebugUnitTest lintDebug`); push. If the RULE CONTENT changed, repeat Task 5 (on-device) before proceeding.**

---

### Task 7: Safe-ordering merge sequence

**Files:**
- Modify: `third-party/android-sigma-rules` (gitlink → rules main head, final commit)

**Interfaces:**
- Consumes: green gates from Tasks 4, 5, 6.
- Produces: both PRs merged; fix live on the feed within 12h.

- [ ] **Step 1: Merge the rules-repo PR** (only now — all gates green)

```bash
export PATH="$HOME/.local/bin:$PATH"
gh pr merge -R android-sigma-rules/rules fix/webapk-cert-filter --squash --delete-branch
```

- [ ] **Step 2: Re-point the submodule at the resulting rules main commit**

```bash
git -C third-party/android-sigma-rules fetch origin main
git -C third-party/android-sigma-rules checkout origin/main
git add third-party/android-sigma-rules
./gradlew testDebugUnitTest --tests 'com.androdr.sigma.RuleManifestIntegrityTest' --tests 'com.androdr.sigma.BundledMirrorParityTest' 2>&1 | tail -5
git commit -m "build: re-point sigma-rules submodule at main (androdr-010 WebAPK filter merged)

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01NahFvjzP3RaHfJAYhbWMDa"
git push
```

- [ ] **Step 3: Merge the AndroDR PR once the build check is green**

```bash
gh pr checks --watch      # build must be green (submodule-check should now also recover)
gh pr merge --squash --delete-branch=false   # keep local branch; worktree cleanup is manual
```

- [ ] **Step 4: Report completion** — the fix reaches all fielded binaries on their next 12h feed cycle; the bundled copy ships in the next release (612+). Note for the user: after the next feed refresh on the daily phone (0.9.0.611), the Idraa-class FP should disappear without an app update.

---

## Self-review notes (completed)

- Spec coverage: rule edit (T2), fleet-safety/no-new-lookup (design-time, enforced by T2 diff scope), cert ground truth + agreement gate (T1), manifest regen + safe-ordering (T3/T7), bundled parity (T2/T3), on-device positive+negative (T5), emitted-cert-equality check (T5 step 3 failure path), ceremony (T6), out-of-scope guards (Global Constraints). No gaps found.
- The `<CERT_SHA256>` token is a runtime-derived value with an exact derivation procedure and storage location, not an unspecified placeholder.
- Names used consistently: `Rule010WebApkFilterTest`, `filter_verified_webapk`, branch names `fix/296-webapk-cert-filter` (AndroDR) / `fix/webapk-cert-filter` (rules repo), scratchpad cert path identical in T1/T2.
