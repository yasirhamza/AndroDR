package com.androdr.ui.bugreport

import com.androdr.data.model.ScanResult
import com.androdr.data.model.TelemetryState
import com.androdr.scanner.ImportPreflight
import com.androdr.scanner.WriteResult
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** A7c: the import card's numbers and notices come straight from the session's [WriteResult]. */
class ImportCardTest {

    private val scan = ScanResult(
        id = 1L, timestamp = 1L, findings = emptyList(), bugReportFindings = emptyList(),
        riskySideloadCount = 0, knownMalwareCount = 0,
    )

    private fun write(state: TelemetryState = TelemetryState.STORED, space: Long = 0L) = WriteResult(
        newFacts = 7, alreadyStored = 5, duplicatesDropped = 3, telemetryState = state, scan = scan,
        spaceToFree = space,
    )

    @Test
    fun `counts are the write result's, not recomputed`() {
        val card = ImportCard.from(write(), truncated = false, boundTrips = emptyList())!!
        assertEquals(7, card.newFacts)
        assertEquals(5, card.alreadyStored)
        assertEquals(3, card.duplicatesDropped)
        assertEquals(ImportNotice.None, card.notice)
        assertTrue(card.trippedBounds.isEmpty())
    }

    @Test
    fun `a result not produced by a session has no card`() {
        assertNull(ImportCard.from(null, truncated = true, boundTrips = listOf("x")))
    }

    @Test
    fun `tripped bounds come from truncated and the bug report's bound trips`() {
        val trip = "InstallTimeModule: stopped at 5 records"
        val card = ImportCard.from(write(), truncated = true, boundTrips = listOf(trip))!!
        assertEquals(listOf(ImportCard.INTRUSION_LIMIT, trip), card.trippedBounds)
    }

    @Test
    fun `a reserve breach says how much space to free`() {
        val card = ImportCard.from(write(TelemetryState.FAILED, space = 42L), false, emptyList())!!
        assertEquals(ImportNotice.FreeSpace(42L), card.notice)
    }

    @Test
    fun `a failed store without a reserve breach says the records were not stored`() {
        val card = ImportCard.from(write(TelemetryState.FAILED), false, emptyList())!!
        assertEquals(ImportNotice.NotStored, card.notice)
    }

    @Test
    fun `archive sizes sum, and any unknown size makes the estimate unknown`() {
        assertEquals(60L, ImportPreflight.sumSizes(sequenceOf(10L, 20L, 30L)))
        assertEquals(0L, ImportPreflight.sumSizes(emptySequence()))
        assertNull(ImportPreflight.sumSizes(sequenceOf(10L, -1L)))
        assertNull(ImportPreflight.sumSizes(sequenceOf(Long.MAX_VALUE, 1L)))
    }
}
