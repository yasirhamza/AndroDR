# Threat Remediation Guidance — Design Spec

## Goal

Replace the expandable app risk cards with compact tap targets that open a Material3 ModalBottomSheet showing threat details, remediation steps, and an uninstall action button.

## Motivation

The current Apps screen shows flagged apps as expandable cards with reasons and permissions. Users see what was detected but get no guidance on what to do. Competitive analysis showed this is the biggest UX gap vs Certo AntiSpy (which offers automated removal). Modern Android security apps (Play Protect, Samsung Knox, Microsoft Defender) use a tap-to-detail pattern with action-focused remediation.

---

## Architecture

Single-file change to `AppScanScreen.kt`. No new data models, no backend changes, no new files.

---

## Components

### 1. Compact `AppRiskCard`

Remove the expand/collapse toggle and `AnimatedVisibility` section. The card becomes a compact, non-expandable tap target.

**Shows:**
- App icon (circle with first letter)
- App name
- Package name
- RiskChip (CRITICAL/HIGH/MEDIUM/LOW)
- Badges row: "Known Malware", "Sideloaded" (existing chips)

**On tap:** Opens `AppRiskDetailSheet` for that app.

### 2. `AppRiskDetailSheet` (ModalBottomSheet)

New composable using Material3 `ModalBottomSheet`. Displayed when user taps a card.

**Layout (top to bottom):**

```
┌─────────────────────────────────────┐
│  ─── drag handle ───                │
│                                     │
│  [icon] App Name          [CRITICAL]│
│  com.example.package                │
│                                     │
│  ── Why it's flagged ──────────────│
│  • Package name matches known...    │
│  • Known malicious signing cert...  │
│                                     │
│  ── What to do ────────────────────│
│  1. Uninstall this app immediately  │
│  2. Run another scan to confirm     │
│                                     │
│  ── Permissions ───────────────────│
│  [CAMERA] [LOCATION] [CONTACTS]     │
│                                     │
│  ┌─────────────────────────────────┐│
│  │       Uninstall App             ││
│  └─────────────────────────────────┘│
│         Dismiss                      │
└─────────────────────────────────────┘
```

### 3. `remediationSteps()` function

Pure function that derives remediation steps from `AppRisk` fields. No new data model needed.

```kotlin
fun remediationSteps(risk: AppRisk): List<String> {
    val steps = mutableListOf<String>()

    if (risk.isKnownMalware) {
        steps.add("Uninstall this app immediately — it matches a known malware database entry.")
    }

    val reasons = risk.reasons.joinToString(" ")

    if ("signing certificate" in reasons) {
        steps.add("This app is signed by a known malware developer. Uninstall it even if the app name looks legitimate.")
    }

    if ("accessibility service" in reasons) {
        steps.add("This app can read your screen content. Go to Settings > Accessibility and disable its service before uninstalling.")
    }

    if ("device administrator" in reasons) {
        steps.add("This app has prevented its own uninstallation. Go to Settings > Security > Device Admin Apps and remove it first.")
    }

    if ("surveillance-capable permissions" in reasons) {
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

### 4. Uninstall deep link

Primary action button opens Android's app detail settings:

```kotlin
val intent = Intent(Settings.ACTION_APPLICATION_DETAIL_SETTINGS).apply {
    data = Uri.parse("package:${risk.packageName}")
}
context.startActivity(intent)
```

This opens the system app info page where the user can tap "Uninstall". We don't try to uninstall programmatically — that requires Device Admin or root.

### 5. State management

Add to `AppScanScreen`:
```kotlin
var selectedRisk by remember { mutableStateOf<AppRisk?>(null) }
```

Card tap sets `selectedRisk`. When non-null, the ModalBottomSheet is shown. Sheet dismiss or "Dismiss" button sets it back to null.

---

## Testing

- Visual: verify on emulator that bottom sheet opens, shows correct data, uninstall button launches Settings
- Adversary simulation: no changes needed — the harness tests detection, not UI flow
- Unit test: `remediationSteps()` is a pure function — test each reason type produces correct steps

---

## Out of Scope

- Automated uninstall (requires Device Admin or root)
- "Ignore" / whitelist functionality (future feature)
- Push notifications for new threats
- Remediation for device posture flags (separate from app risks)
