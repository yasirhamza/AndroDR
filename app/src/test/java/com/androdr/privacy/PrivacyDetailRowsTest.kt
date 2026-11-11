package com.androdr.privacy

import com.androdr.privacy.NetworkEvidenceCorrelator.DomainEvidence
import com.androdr.privacy.NetworkEvidenceCorrelator.Key
import com.androdr.privacy.model.CodeMatch
import com.androdr.privacy.model.SignatureKind
import com.androdr.privacy.model.Tracker
import com.androdr.privacy.model.TrackerCategory
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class PrivacyDetailRowsTest {

    private fun tracker(id: Int) = Tracker(
        id = id, name = "T$id", website = "", categories = setOf(TrackerCategory.ANALYTICS),
        rawCategories = listOf("Analytics"), codePrefixes = emptyList(), codeSegments = emptyList(),
        domainSuffixes = emptyList(), domainLabels = emptyList(), domainPatterns = emptyList(),
    )

    private fun pkgs(prefix: String, n: Int) = List(n) { "$prefix.p${"%04d".format(it)}" }

    private fun match(id: Int, signature: String, n: Int) =
        CodeMatch(tracker(id), SignatureKind.CODE_PREFIX, signature, pkgs(signature, n))

    @Test fun `more than 200 matching packages are stored as 200 with the true number`() {
        val row = PrivacyDetailRows.code(1, "app", listOf(match(1, "com.a", 260))).single()
        assertEquals(260, row.packageCount)
        assertEquals(PrivacyDetailRows.MAX_PACKAGES_PER_TRACKER, PrivacyDetailRows.packagesOf(row).size)
        assertEquals(pkgs("com.a", 200), PrivacyDetailRows.packagesOf(row))
    }

    @Test fun `the 200 package names of one tracker are shared across its signatures`() {
        val rows = PrivacyDetailRows.code(1, "app", listOf(match(1, "com.a", 150), match(1, "com.b", 150)))
        assertEquals(listOf(150, 50), rows.map { PrivacyDetailRows.packagesOf(it).size })
        assertEquals(listOf(150, 150), rows.map { it.packageCount })
    }

    @Test fun `another tracker gets its own 200`() {
        val rows = PrivacyDetailRows.code(1, "app", listOf(match(1, "com.a", 250), match(2, "com.b", 250)))
        assertEquals(listOf(200, 200), rows.map { PrivacyDetailRows.packagesOf(it).size })
    }

    @Test fun `one app stores at most 2000 package names across trackers`() {
        val rows = PrivacyDetailRows.code(1, "app", (1..15).map { match(it, "com.t$it", 200) })
        assertEquals(PrivacyDetailRows.MAX_PACKAGES_PER_APP, rows.sumOf { PrivacyDetailRows.packagesOf(it).size })
        assertTrue(rows.all { it.packageCount == 200 })
        assertEquals(15, rows.size)
    }

    @Test fun `a row whose names were all left out still says how many matched`() {
        val rows = PrivacyDetailRows.code(1, "app", (1..11).map { match(it, "com.t$it", 200) })
        assertEquals(emptyList<String>(), PrivacyDetailRows.packagesOf(rows.last()))
        assertEquals(200, rows.last().packageCount)
    }

    @Test fun `a name longer than 254 characters is stored cut with a visible mark`() {
        val long = "a".repeat(400)
        assertEquals("a".repeat(254) + "…", PrivacyDetailRows.cut(long))
        assertEquals("b".repeat(254), PrivacyDetailRows.cut("b".repeat(254)))
        val row = PrivacyDetailRows.code(
            1, "app", listOf(CodeMatch(tracker(1), SignatureKind.CODE_SEGMENT, "x", listOf("q.x.$long"))),
        ).single()
        assertTrue(PrivacyDetailRows.packagesOf(row).single().endsWith("…"))
        assertEquals(255, PrivacyDetailRows.packagesOf(row).single().length)
    }

    @Test fun `cutting never splits a character outside the basic plane`() {
        val text = "\uD83D\uDE00".repeat(300)
        val cut = PrivacyDetailRows.cut(text)
        assertEquals(255, cut.codePointCount(0, cut.length))
        assertTrue(cut.endsWith("\uD83D\uDE00…"))
    }

    @Test fun `domain rows keep their counts and unknown background as null`() {
        val ev = DomainEvidence(Key("app", 7), "X.Flurry.com.", SignatureKind.DOMAIN_SUFFIX, "flurry.com", 4, 2, null,
            10, 20)
        val row = PrivacyDetailRows.domains(3, listOf(ev)).single()
        assertNull(row.background)
        assertEquals("X.Flurry.com.", row.domain)
        assertEquals(listOf(3L, 7L, 4L, 2L, 10L, 20L),
            listOf(row.scanId, row.trackerId.toLong(), row.lookups.toLong(), row.lookupDays.toLong(), row.firstSeen,
                row.lastSeen))
        assertEquals("DOMAIN_SUFFIX", row.kind)
    }
}
