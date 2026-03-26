# Threat Remediation Guidance Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace expandable app risk cards with compact tap targets that open a Material3 ModalBottomSheet showing threat details, remediation steps, and an uninstall action button.

**Architecture:** Single-file modification to `AppScanScreen.kt`. Remove expand/collapse pattern, add `ModalBottomSheet` with `remediationSteps()` pure function. No backend changes.

**Tech Stack:** Jetpack Compose, Material3 `ModalBottomSheet`, Android `Settings.ACTION_APPLICATION_DETAIL_SETTINGS` intent

**Spec:** `docs/superpowers/specs/2026-03-26-threat-remediation-design.md`

---

## File Structure

```
# Modified files
app/src/main/java/com/androdr/ui/apps/AppScanScreen.kt    # all UI changes

# New test file
app/src/test/java/com/androdr/ui/apps/RemediationStepsTest.kt
```

---

### Task 1: Add `remediationSteps()` pure function + tests

**Files:**
- Modify: `app/src/main/java/com/androdr/ui/apps/AppScanScreen.kt`
- Create: `app/src/test/java/com/androdr/ui/apps/RemediationStepsTest.kt`

- [ ] **Step 1: Write the test file**

```kotlin
// app/src/test/java/com/androdr/ui/apps/RemediationStepsTest.kt
package com.androdr.ui.apps

import com.androdr.data.model.AppRisk
import com.androdr.data.model.RiskLevel
import org.junit.Assert.assertTrue
import org.junit.Test

class RemediationStepsTest {

    private fun risk(
        reasons: List<String> = emptyList(),
        isKnownMalware: Boolean = false,
        isSideloaded: Boolean = false
    ) = AppRisk(
        packageName = "com.test.app",
        appName = "Test",
        riskLevel = RiskLevel.HIGH,
        reasons = reasons,
        isKnownMalware = isKnownMalware,
        isSideloaded = isSideloaded,
        dangerousPermissions = emptyList()
    )

    @Test
    fun `known malware produces uninstall immediately step`() {
        val steps = remediationSteps(risk(isKnownMalware = true))
        assertTrue(steps.any { "Uninstall this app immediately" in it })
    }

    @Test
    fun `signing certificate reason produces developer warning`() {
        val steps = remediationSteps(risk(
            reasons = listOf("Known malicious signing certificate (Cerberus)")
        ))
        assertTrue(steps.any { "known malware developer" in it })
    }

    @Test
    fun `accessibility service reason produces disable instruction`() {
        val steps = remediationSteps(risk(
            reasons = listOf("Registered as an accessibility service")
        ))
        assertTrue(steps.any { "Accessibility" in it })
    }

    @Test
    fun `device administrator reason produces remove admin instruction`() {
        val steps = remediationSteps(risk(
            reasons = listOf("Registered as a device administrator")
        ))
        assertTrue(steps.any { "Device Admin" in it || "device administrator" in it.lowercase() })
    }

    @Test
    fun `surveillance permissions reason produces review instruction`() {
        val steps = remediationSteps(risk(
            reasons = listOf("Holds 4 sensitive surveillance-capable permissions simultaneously: RECORD_AUDIO, CAMERA, ACCESS_FINE_LOCATION, READ_CONTACTS")
        ))
        assertTrue(steps.any { "surveillance" in it.lowercase() })
    }

    @Test
    fun `sideloaded only produces verify instruction`() {
        val steps = remediationSteps(risk(
            isSideloaded = true,
            reasons = listOf("App was not installed via a trusted app store (installer: unknown)")
        ))
        assertTrue(steps.any { "trusted app store" in it.lowercase() || "not installed" in it.lowercase() })
    }

    @Test
    fun `always ends with run another scan step`() {
        val steps = remediationSteps(risk())
        assertTrue(steps.last().contains("scan"))
    }
}
```

- [ ] **Step 2: Add `remediationSteps()` function to `AppScanScreen.kt`**

Add at the bottom of the file, after the `riskLevelColor()` function:

```kotlin
/** Derives actionable remediation steps from an [AppRisk]'s flags and reasons. */
internal fun remediationSteps(risk: AppRisk): List<String> {
    val steps = mutableListOf<String>()
    val reasonsJoined = risk.reasons.joinToString(" ")

    if (risk.isKnownMalware) {
        steps.add("Uninstall this app immediately \u2014 it matches a known malware database entry.")
    }

    if ("signing certificate" in reasonsJoined) {
        steps.add("This app is signed by a known malware developer. Uninstall it even if the app name looks legitimate.")
    }

    if ("accessibility service" in reasonsJoined.lowercase()) {
        steps.add("This app can read your screen content. Go to Settings \u2192 Accessibility and disable its service before uninstalling.")
    }

    if ("device administrator" in reasonsJoined.lowercase()) {
        steps.add("This app has prevented its own uninstallation. Go to Settings \u2192 Security \u2192 Device Admin Apps and remove it first.")
    }

    if ("surveillance-capable permissions" in reasonsJoined) {
        steps.add("This app has extensive surveillance capabilities. If you did not install it intentionally, uninstall it.")
    }

    if (risk.isSideloaded && steps.isEmpty()) {
        steps.add("This app was not installed from a trusted app store. Verify you intended to install it.")
    }

    if (steps.isEmpty()) {
        steps.add("Review this app and decide whether to keep it.")
    }

    steps.add("Run another scan after taking action to confirm the threat is resolved.")
    return steps
}
```

- [ ] **Step 3: Run tests**

Run: `export JAVA_HOME=/home/yasir/Applications/android-studio/jbr && ./gradlew testDebugUnitTest --tests "com.androdr.ui.apps.RemediationStepsTest"`
Expected: 7 tests PASS

- [ ] **Step 4: Commit**

```bash
git add app/src/main/java/com/androdr/ui/apps/AppScanScreen.kt \
       app/src/test/java/com/androdr/ui/apps/RemediationStepsTest.kt
git commit -m "feat: add remediationSteps() pure function with tests"
```

---

### Task 2: Replace expandable card with compact tap target + ModalBottomSheet

**Files:**
- Modify: `app/src/main/java/com/androdr/ui/apps/AppScanScreen.kt`

This is the main UI change. Read the file first, then make these changes:

- [ ] **Step 1: Add new imports**

Add these imports at the top of the file (merge with existing):

```kotlin
import android.content.Intent
import android.net.Uri
import android.provider.Settings
import androidx.compose.foundation.clickable
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.TextButton
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.ui.platform.LocalContext
```

Remove unused imports:
```kotlin
// Remove these:
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.material.icons.filled.ExpandLess
import androidx.compose.material.icons.filled.ExpandMore
```

- [ ] **Step 2: Add `selectedRisk` state and bottom sheet to `AppScanScreen`**

In the `AppScanScreen` composable, after `val filterLevel` line, add:

```kotlin
var selectedRisk by remember { mutableStateOf<AppRisk?>(null) }
```

After the closing brace of the `Column` (the main column that wraps everything), but still inside the `AppScanScreen` function, add the bottom sheet:

```kotlin
selectedRisk?.let { risk ->
    AppRiskDetailSheet(
        risk = risk,
        onDismiss = { selectedRisk = null }
    )
}
```

Update the `AppRiskCard` call inside `items(filteredRisks)` to pass an `onClick`:

Replace:
```kotlin
items(filteredRisks) { appRisk ->
    AppRiskCard(appRisk = appRisk)
}
```

With:
```kotlin
items(filteredRisks) { appRisk ->
    AppRiskCard(
        appRisk = appRisk,
        onClick = { selectedRisk = appRisk }
    )
}
```

- [ ] **Step 3: Rewrite `AppRiskCard` as compact non-expandable card**

Replace the entire `AppRiskCard` composable with:

```kotlin
@Composable
private fun AppRiskCard(appRisk: AppRisk, onClick: () -> Unit) {
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onClick),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.surfaceContainer
        )
    ) {
        Row(
            modifier = Modifier
                .padding(16.dp)
                .fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically
        ) {
            // App icon placeholder
            Box(
                modifier = Modifier
                    .size(44.dp)
                    .background(
                        color = riskLevelColor(appRisk.riskLevel).copy(alpha = 0.25f),
                        shape = CircleShape
                    ),
                contentAlignment = Alignment.Center
            ) {
                Text(
                    text = appRisk.appName.firstOrNull()?.uppercase() ?: "?",
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Bold,
                    color = riskLevelColor(appRisk.riskLevel)
                )
            }

            Spacer(modifier = Modifier.width(12.dp))

            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = appRisk.appName,
                    style = MaterialTheme.typography.titleSmall,
                    fontWeight = FontWeight.SemiBold
                )
                Text(
                    text = appRisk.packageName,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                if (appRisk.isKnownMalware || appRisk.isSideloaded) {
                    Spacer(modifier = Modifier.height(4.dp))
                    Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                        if (appRisk.isKnownMalware) {
                            SuggestionChip(
                                onClick = {},
                                label = { Text(stringResource(R.string.badge_known_malware), style = MaterialTheme.typography.labelSmall) },
                                colors = SuggestionChipDefaults.suggestionChipColors(
                                    containerColor = Color(0xFFCF6679).copy(alpha = 0.2f),
                                    labelColor = Color(0xFFCF6679)
                                )
                            )
                        }
                        if (appRisk.isSideloaded) {
                            SuggestionChip(
                                onClick = {},
                                label = { Text(stringResource(R.string.badge_sideloaded), style = MaterialTheme.typography.labelSmall) },
                                colors = SuggestionChipDefaults.suggestionChipColors(
                                    containerColor = Color(0xFFFF9800).copy(alpha = 0.2f),
                                    labelColor = Color(0xFFFF9800)
                                )
                            )
                        }
                    }
                }
            }

            RiskChip(riskLevel = appRisk.riskLevel)
        }
    }
}
```

- [ ] **Step 4: Add `AppRiskDetailSheet` composable**

Add this new composable after `AppRiskCard`:

```kotlin
@OptIn(ExperimentalMaterial3Api::class, ExperimentalLayoutApi::class)
@Composable
private fun AppRiskDetailSheet(risk: AppRisk, onDismiss: () -> Unit) {
    val sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true)
    val context = LocalContext.current
    val steps = remember(risk) { remediationSteps(risk) }

    ModalBottomSheet(
        onDismissRequest = onDismiss,
        sheetState = sheetState,
        containerColor = MaterialTheme.colorScheme.surfaceContainerHigh
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 24.dp)
                .padding(bottom = 32.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            // Header
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Box(
                    modifier = Modifier
                        .size(48.dp)
                        .background(
                            color = riskLevelColor(risk.riskLevel).copy(alpha = 0.25f),
                            shape = CircleShape
                        ),
                    contentAlignment = Alignment.Center
                ) {
                    Text(
                        text = risk.appName.firstOrNull()?.uppercase() ?: "?",
                        style = MaterialTheme.typography.titleLarge,
                        fontWeight = FontWeight.Bold,
                        color = riskLevelColor(risk.riskLevel)
                    )
                }
                Spacer(modifier = Modifier.width(16.dp))
                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        text = risk.appName,
                        style = MaterialTheme.typography.titleMedium,
                        fontWeight = FontWeight.Bold
                    )
                    Text(
                        text = risk.packageName,
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
                RiskChip(riskLevel = risk.riskLevel)
            }

            HorizontalDivider()

            // Why it's flagged
            Text(
                text = "Why it\u2019s flagged",
                style = MaterialTheme.typography.titleSmall,
                fontWeight = FontWeight.SemiBold
            )
            risk.reasons.forEach { reason ->
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    Icon(
                        imageVector = Icons.Filled.Warning,
                        contentDescription = null,
                        tint = riskLevelColor(risk.riskLevel),
                        modifier = Modifier.size(16.dp)
                    )
                    Text(
                        text = reason,
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurface
                    )
                }
            }

            HorizontalDivider()

            // What to do
            Text(
                text = "What to do",
                style = MaterialTheme.typography.titleSmall,
                fontWeight = FontWeight.SemiBold
            )
            steps.forEachIndexed { index, step ->
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text(
                        text = "${index + 1}.",
                        style = MaterialTheme.typography.bodySmall,
                        fontWeight = FontWeight.Bold,
                        color = MaterialTheme.colorScheme.primary
                    )
                    Text(
                        text = step,
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurface
                    )
                }
            }

            // Permissions
            if (risk.dangerousPermissions.isNotEmpty()) {
                HorizontalDivider()
                Text(
                    text = stringResource(R.string.label_dangerous_permissions),
                    style = MaterialTheme.typography.titleSmall,
                    fontWeight = FontWeight.SemiBold
                )
                FlowRow(
                    horizontalArrangement = Arrangement.spacedBy(6.dp),
                    verticalArrangement = Arrangement.spacedBy(4.dp)
                ) {
                    risk.dangerousPermissions.forEach { perm ->
                        AssistChip(
                            onClick = {},
                            label = { Text(perm.substringAfterLast('.'), style = MaterialTheme.typography.labelSmall) },
                            colors = AssistChipDefaults.assistChipColors(
                                containerColor = Color(0xFFFF9800).copy(alpha = 0.15f),
                                labelColor = Color(0xFFFF9800)
                            )
                        )
                    }
                }
            }

            Spacer(modifier = Modifier.height(8.dp))

            // Uninstall button
            Button(
                onClick = {
                    val intent = Intent(Settings.ACTION_APPLICATION_DETAIL_SETTINGS).apply {
                        data = Uri.parse("package:${risk.packageName}")
                    }
                    context.startActivity(intent)
                },
                modifier = Modifier.fillMaxWidth(),
                colors = ButtonDefaults.buttonColors(
                    containerColor = riskLevelColor(risk.riskLevel)
                )
            ) {
                Icon(
                    imageVector = Icons.Filled.Delete,
                    contentDescription = null,
                    modifier = Modifier.size(18.dp)
                )
                Spacer(modifier = Modifier.width(8.dp))
                Text("Uninstall App")
            }

            // Dismiss
            TextButton(
                onClick = onDismiss,
                modifier = Modifier.fillMaxWidth()
            ) {
                Text("Dismiss")
            }
        }
    }
}
```

- [ ] **Step 5: Build and run all tests**

Run: `export JAVA_HOME=/home/yasir/Applications/android-studio/jbr && ./gradlew detekt lintDebug testDebugUnitTest`
Expected: BUILD SUCCESSFUL

- [ ] **Step 6: Commit**

```bash
git add app/src/main/java/com/androdr/ui/apps/AppScanScreen.kt
git commit -m "feat: replace expandable cards with compact tap targets + remediation bottom sheet (#12)"
```

---

### Task 3: Verify + push

- [ ] **Step 1: Run full test suite**

Run: `export JAVA_HOME=/home/yasir/Applications/android-studio/jbr && ./gradlew detekt lintDebug testDebugUnitTest assembleDebug`
Expected: BUILD SUCCESSFUL

- [ ] **Step 2: Push**

```bash
git push origin main
```
