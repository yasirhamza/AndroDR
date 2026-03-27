// app/src/test/java/com/androdr/sigma/FindingMapperTest.kt
package com.androdr.sigma

import com.androdr.data.model.AppTelemetry
import com.androdr.data.model.RiskLevel
import com.androdr.data.model.Severity
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class FindingMapperTest {

    @Test
    fun `maps findings to AppRisk with correct risk level`() {
        val telemetry = listOf(AppTelemetry(
            packageName = "com.evil.app", appName = "Evil", certHash = null,
            isSystemApp = false, fromTrustedStore = false, installer = null,
            isSideloaded = true, isKnownOemApp = false,
            permissions = listOf("CAMERA"), surveillancePermissionCount = 1,
            hasAccessibilityService = false, hasDeviceAdmin = false,
            knownAppCategory = null
        ))
        val findings = listOf(Finding(
            ruleId = "androdr-010", title = "Sideloaded app",
            level = "medium", tags = emptyList(),
            remediation = listOf("Review this app"),
            matchedRecord = mapOf("package_name" to "com.evil.app")
        ))

        val risks = FindingMapper.toAppRisks(telemetry, findings)
        assertEquals(1, risks.size)
        assertEquals("com.evil.app", risks[0].packageName)
        assertEquals(RiskLevel.MEDIUM, risks[0].riskLevel)
        assertTrue(risks[0].isSideloaded)
    }

    @Test
    fun `multiple findings for same package merge into one AppRisk`() {
        val telemetry = listOf(AppTelemetry(
            packageName = "com.evil.app", appName = "Evil", certHash = "abc",
            isSystemApp = false, fromTrustedStore = false, installer = null,
            isSideloaded = true, isKnownOemApp = false,
            permissions = emptyList(), surveillancePermissionCount = 0,
            hasAccessibilityService = true, hasDeviceAdmin = false,
            knownAppCategory = null
        ))
        val findings = listOf(
            Finding("androdr-002", "Cert hash match", "critical", emptyList(), emptyList(),
                mapOf("package_name" to "com.evil.app")),
            Finding("androdr-012", "Accessibility abuse", "high", emptyList(), emptyList(),
                mapOf("package_name" to "com.evil.app"))
        )

        val risks = FindingMapper.toAppRisks(telemetry, findings)
        assertEquals(1, risks.size)
        assertEquals(RiskLevel.CRITICAL, risks[0].riskLevel)
        assertEquals(2, risks[0].reasons.size)
    }

    @Test
    fun `maps device findings to DeviceFlags with correct triggered state`() {
        val findings = listOf(
            Finding("androdr-040", "USB Debugging enabled", "high",
                listOf("attack.t1404"), listOf("Disable USB Debugging"),
                mapOf("adb_enabled" to true)),
            Finding("androdr-043", "No screen lock", "critical",
                emptyList(), emptyList(),
                mapOf("screen_lock_enabled" to false))
        )
        val flags = FindingMapper.toDeviceFlags(emptyList(), findings)

        assertEquals(7, flags.size)

        val adb = flags.find { it.id == "adb_enabled" }!!
        assertTrue(adb.isTriggered)
        assertEquals("USB Debugging", adb.title)
        assertEquals(Severity.HIGH, adb.severity)

        val screenLock = flags.find { it.id == "no_screen_lock" }!!
        assertTrue(screenLock.isTriggered)
        assertEquals(Severity.CRITICAL, screenLock.severity)

        val wifiAdb = flags.find { it.id == "wifi_adb_enabled" }!!
        assertFalse(wifiAdb.isTriggered)
    }
}
