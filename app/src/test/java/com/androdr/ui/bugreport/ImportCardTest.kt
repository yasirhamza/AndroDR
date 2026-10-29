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
        id = 1L, timestamp = 1L, bugReportFindings = emptyList(),
        riskySideloadCount = 0, knownMalwareCount = 0,
    )

    private fun write(state: TelemetryState = TelemetryState.STORED, space: Long = 0L) = WriteResult(
        newFacts = 7, alreadyStored = 5, duplicatesDropped = 3, telemetryState = state, scan = scan,
        spaceToFree = space,
    )

    /** R27: an import note (e.g. times assumed UTC) reaches the card. */
    @Test
    fun `import notes reach the card`() {
        val card = ImportCard.from(write(), truncated = false, boundTrips = emptyList(), notes = listOf("note"))!!
        assertEquals(listOf("note"), card.notes)
    }

    /** Review Minor E: the unsaved findings' counts by level reach the card, most severe first. */
    @Test
    fun `unsaved findings show their counts by level, most severe first`() {
        val unsaved = com.androdr.scanner.UnsavedSummary(9L,
            mapOf(("a" to "low") to 2L, ("b" to "critical") to 3L, ("c" to "high") to 1L, ("d" to "critical") to 3L),
            emptyList())
        val card = ImportCard.from(write(space = 5L).copy(unsaved = unsaved), truncated = false,
            boundTrips = emptyList())!!
        assertEquals(listOf("critical" to 6L, "high" to 1L, "low" to 2L), card.unsavedByLevel)
        assertEquals("critical", card.mostSevereUnsaved)
        assertEquals(9L, card.unsavedFindings)
    }

    /** Review Minor F: "free at least X", and never "free 0 B" when the amount is unknown. */
    @Test
    fun `the amount to free is "at least" and unknown when the shortfall is 0`() {
        val unsaved = com.androdr.scanner.UnsavedSummary(1L, mapOf(("a" to "high") to 1L), emptyList())
        val known = ImportCard.from(write(space = 5L).copy(unsaved = unsaved), false, emptyList())!!
        val unknown = ImportCard.from(write(space = 0L).copy(unsaved = unsaved), false, emptyList())!!
        assertTrue(known.freeAmountKnown)
        assertTrue(!unknown.freeAmountKnown)
        val strings = java.io.File("src/main/res/values/strings.xml").readText()
        val known1 = Regex("""<plurals name="import_card_findings_unsaved">([\s\S]*?)</plurals>""").find(strings)!!
        assertTrue("says at least", known1.groupValues[1].contains("free at least %2\$s"))
        val unknown1 = Regex("""<plurals name="import_card_findings_unsaved_unknown">([\s\S]*?)</plurals>""")
            .find(strings)!!.groupValues[1]
        assertTrue("names no amount", !unknown1.contains("%2") && unknown1.contains("free more space"))
        val ui = java.io.File("src/main/java/com/androdr/ui/bugreport/ImportComposables.kt").readText()
        assertTrue("the unknown wording is chosen from freeAmountKnown",
            ui.contains("if (card.freeAmountKnown)") && ui.contains("R.plurals.import_card_findings_unsaved_unknown"))
    }

    // Final review M5: under ruling R38 a no-fact write that itself fills the disk shows only counts and
    // a display sample, so the preflight must not promise that every finding is still shown.
    @Test
    fun `the import preflight promises every finding is counted, never that every finding is shown`() {
        val strings = java.io.File("src/main/res/values/strings.xml").readText()
        for (name in listOf("import_preflight_body_estimate", "import_preflight_body_unknown",
            "import_preflight_body_unknown_nofree")) {
            val body = Regex("""<string name="$name">([^<]*)</string>""").find(strings)!!.groupValues[1]
            assertTrue("$name: $body", body.contains("still counts every finding"))
            assertTrue("$name: $body", !body.contains("shows every finding"))
        }
    }

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
        val failed = write(TelemetryState.FAILED, space = 42L)
        val card = ImportCard.from(failed, false, emptyList(), estimateBytes = 900L)!!
        assertEquals("says how many were stored before storage ran low, and how much the whole import needs",
            ImportNotice.LowSpace(storedFacts = 7, freeAtLeastBytes = 42L, wholeImportBytes = 900L), card.notice)
    }

    @Test
    fun `a failed store without a reserve breach never claims low space and keeps the stored count`() {
        val card = ImportCard.from(write(TelemetryState.FAILED), false, emptyList())!!
        assertEquals(ImportNotice.NotFullyStored(storedFacts = 7), card.notice)
    }

    @Test
    fun `archive sizes sum, and any unknown size makes the estimate unknown`() {
        assertEquals(60L, ImportPreflight.sumSizes(sequenceOf(10L, 20L, 30L)))
        assertEquals(0L, ImportPreflight.sumSizes(emptySequence()))
        assertNull(ImportPreflight.sumSizes(sequenceOf(10L, -1L)))
        assertNull(ImportPreflight.sumSizes(sequenceOf(Long.MAX_VALUE, 1L)))
    }
}
