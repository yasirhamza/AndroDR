# Accessibility Service & Device Admin Abuse Detection — Design Spec

## Goal

Flag non-system apps that register an `AccessibilityService` or `DeviceAdminReceiver` — high-confidence persistence and surveillance TTPs used by stalkerware and mercenary spyware.

## Motivation

Stalkerware almost universally abuses AccessibilityService to read screen content, intercept keystrokes, and exfiltrate data from other apps without root. Device Admin registration prevents uninstallation. Neither requires dangerous runtime permissions — both bypass normal Android permission controls entirely.

---

## Architecture

No new files. Single modification to `AppScanner.kt`:

1. Add `GET_SERVICES` and `GET_RECEIVERS` to `getInstalledPackages()` flags
2. New check after cert hash IOC check, before permission scoring
3. Check `PackageInfo.services` for `BIND_ACCESSIBILITY_SERVICE` permission
4. Check `PackageInfo.receivers` for `BIND_DEVICE_ADMIN` permission
5. Only flag non-system apps (system apps like TalkBack, MDM agents are legitimate)
6. Risk level: HIGH by default; CRITICAL if also sideloaded

## Detection Logic

```kotlin
// ── 1c. Accessibility service abuse ──────────────────────
if (!isSystemApp) {
    val hasAccessibilityService = pkg.services?.any { svc ->
        svc.permission == "android.permission.BIND_ACCESSIBILITY_SERVICE"
    } == true
    if (hasAccessibilityService) {
        val newLevel = if (isSideloaded) RiskLevel.CRITICAL else RiskLevel.HIGH
        if (newLevel.score > riskLevel.score) riskLevel = newLevel
        reasons.add("Registered as an accessibility service")
    }

    val hasDeviceAdmin = pkg.receivers?.any { recv ->
        recv.permission == "android.permission.BIND_DEVICE_ADMIN"
    } == true
    if (hasDeviceAdmin) {
        val newLevel = if (isSideloaded) RiskLevel.CRITICAL else RiskLevel.HIGH
        if (newLevel.score > riskLevel.score) riskLevel = newLevel
        reasons.add("Registered as a device administrator")
    }
}
```

## PackageManager Flag Change

Current:
```kotlin
pm.getInstalledPackages(PackageManager.GET_PERMISSIONS or signingFlag)
```

New:
```kotlin
pm.getInstalledPackages(
    PackageManager.GET_PERMISSIONS or signingFlag
        or PackageManager.GET_SERVICES or PackageManager.GET_RECEIVERS
)
```

Same OEM fallback pattern as the signing flag — if combined flags fail, retry without.

## Ordering Issue

The accessibility/admin check references `isSideloaded`, which is computed in check #3 (sideload detection, later in the loop). Two options:

**A)** Move the check after sideload detection (check #3) — simplest, but changes scan order
**B)** Compute `isSideloaded` early (just the boolean, not the reason string) — keeps check order but adds a pre-computation

**Chosen: A.** Place the accessibility/admin check after sideload detection. The scan loop already mixes detection and scoring — adding it after sideload detection is cleaner than pre-computing.

## Reason Strings

Must match adversary simulation expected patterns exactly:
- `"Registered as an accessibility service"` — matches `mercenary_accessibility.patterns`
- `"Registered as a device administrator"` — matches `mercenary_device_admin.patterns`

## Testing

- `mercenary_accessibility` scenario transitions from EXPECTED FAIL to PASS
- `mercenary_device_admin` scenario transitions from EXPECTED FAIL to PASS
- Existing AppScanner unit tests must still pass (mock PackageInfo has null services/receivers by default)

## Out of Scope

- Checking if the accessibility service is actually enabled (runtime state) — we only check manifest declaration
- Listing what capabilities the accessibility service requests
- Blocking or disabling the accessibility service
