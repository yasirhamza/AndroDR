package com.androdr.sigma

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * Spec §6 gate: `signal_member` is the only store of a signal's members. No `main` source names the
 * legacy `member_event_ids` list except the one-time backfill that moves it, and every former reader
 * of that list resolves members through `SignalMemberDao` (or reads only the `member_count`).
 */
class MemberIdsConsumersGateTest {

    private val legacyKey = "member_event_ids"
    private val allowListed = setOf("data/db/SignalMemberBackfill.kt")

    private fun root(): File = listOf(File("src/main/java/com/androdr"), File("app/src/main/java/com/androdr"))
        .first { it.isDirectory }

    private fun mentions(root: File): Set<String> = root.walkTopDown()
        .filter { it.isFile && it.extension == "kt" && it.readText().contains(legacyKey) }
        .map { it.relativeTo(root).invariantSeparatorsPath }
        .toSet()

    @Test
    fun `no main source mentions the legacy member list except the backfill`() {
        assertEquals(emptySet<String>(), mentions(root()) - allowListed)
        assertTrue("the backfill still names it (else the gate guards nothing)",
            mentions(root()).containsAll(allowListed))
    }

    @Test
    fun `former readers resolve members through SignalMemberDao or read member_count`() {
        val root = root()
        fun text(path: String) = File(root, path).readText()
        // The Timeline loads a signal's members page by page from signal_member.
        assertTrue(text("ui/timeline/ClusterMembers.kt").contains("SignalMemberDao"))
        assertTrue(text("ui/timeline/TimelineClusters.kt").contains("ClusterMembers"))
        // The CSV's member_refs come from signal_member.
        assertTrue(text("ui/timeline/TimelineViewModel.kt").contains("existingRefs"))
        // The finding and the report carry and print the count only.
        assertTrue(text("sigma/CorrelationFindings.kt").contains("member_count"))
        assertTrue(text("reporting/ReportFormatter.kt").contains("MEMBER_COUNT"))
    }

    @Test
    fun `the gate sees a planted mention`() {
        val dir = kotlin.io.path.createTempDirectory("gate").toFile()
        try {
            File(dir, "ui").mkdirs()
            File(dir, "ui/Reader.kt").writeText("val ids = details[\"$legacyKey\"]")
            File(dir, "ui/Clean.kt").writeText("val n = 1")
            assertEquals(setOf("ui/Reader.kt"), mentions(dir))
        } finally {
            dir.deleteRecursively()
        }
    }
}
