package com.androdr.scanner

import android.content.Context
import com.androdr.data.repo.CveRepository
import io.mockk.mockk
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/**
 * Covers [DeviceAuditor.interpretVerifiedBootState] — the decision logic for the
 * authoritative `ro.boot.verifiedbootstate` property (issue #86). Reflection into
 * `android.os.SystemProperties` is not reachable on the JVM test runtime, so the
 * boot-state interpretation is extracted into a pure function and verified here
 * across all four documented states plus the fall-through cases.
 */
class DeviceAuditorBootStateTest {

    private val auditor = DeviceAuditor(
        context = mockk<Context>(relaxed = true),
        cveRepository = mockk<CveRepository>(relaxed = true)
    )

    @Test
    fun `orange means bootloader unlocked`() {
        assertEquals(true, auditor.interpretVerifiedBootState("orange"))
    }

    @Test
    fun `green means bootloader locked`() {
        assertEquals(false, auditor.interpretVerifiedBootState("green"))
    }

    @Test
    fun `yellow means bootloader locked`() {
        assertEquals(false, auditor.interpretVerifiedBootState("yellow"))
    }

    @Test
    fun `red means bootloader locked`() {
        assertEquals(false, auditor.interpretVerifiedBootState("red"))
    }

    @Test
    fun `state is case-insensitive`() {
        assertEquals(true, auditor.interpretVerifiedBootState("ORANGE"))
        assertEquals(false, auditor.interpretVerifiedBootState("Green"))
    }

    @Test
    fun `null state falls through to heuristic`() {
        assertNull(auditor.interpretVerifiedBootState(null))
    }

    @Test
    fun `blank state falls through to heuristic`() {
        assertNull(auditor.interpretVerifiedBootState(""))
        assertNull(auditor.interpretVerifiedBootState("   "))
    }

    @Test
    fun `unrecognised state falls through to heuristic`() {
        assertNull(auditor.interpretVerifiedBootState("purple"))
    }
}
