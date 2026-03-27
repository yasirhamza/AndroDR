package com.androdr.data.repo

import com.androdr.data.model.CveEntity
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class CveRepositoryTest {

    @Test
    fun `merge prefers OSV fixedInPatchLevel over CISA dateAdded`() {
        val cisaEntries = listOf(
            CveEntity("CVE-2024-001", "desc", "CRITICAL", "", "2024-11-01", true, "Google", "Android", 0)
        )
        val osvEntries = listOf(
            CveEntity("CVE-2024-001", "desc", "HIGH", "2024-06-05", "", false, "Google", "Android", 0)
        )
        val merged = CveRepository.mergeEntries(cisaEntries, osvEntries)
        assertEquals(1, merged.size)
        assertEquals("2024-06-05", merged[0].fixedInPatchLevel)
        assertEquals("HIGH", merged[0].severity)
        assertTrue(merged[0].isActivelyExploited)
        assertEquals("2024-11-01", merged[0].cisaDateAdded)
    }

    @Test
    fun `CISA-only entry falls back to dateAdded as fixedInPatchLevel`() {
        val cisaEntries = listOf(
            CveEntity("CVE-2024-002", "desc", "CRITICAL", "", "2024-09-15", true, "Google", "Android", 0)
        )
        val merged = CveRepository.mergeEntries(cisaEntries, emptyList())
        assertEquals(1, merged.size)
        assertEquals("2024-09-15", merged[0].fixedInPatchLevel)
        assertTrue(merged[0].isActivelyExploited)
    }

    @Test
    fun `OSV-only entry marked as not actively exploited`() {
        val osvEntries = listOf(
            CveEntity("CVE-2024-003", "desc", "MEDIUM", "2024-07-01", "", false, "Google", "Android", 0)
        )
        val merged = CveRepository.mergeEntries(emptyList(), osvEntries)
        assertEquals(1, merged.size)
        assertTrue(!merged[0].isActivelyExploited)
    }

    @Test
    fun `merge handles multiple entries`() {
        val cisaEntries = listOf(
            CveEntity("CVE-A", "a", "CRITICAL", "", "2024-01-01", true, "Google", "Android", 0),
            CveEntity("CVE-B", "b", "CRITICAL", "", "2024-02-01", true, "Google", "Android", 0)
        )
        val osvEntries = listOf(
            CveEntity("CVE-A", "a", "HIGH", "2023-11-05", "", false, "Google", "Android", 0),
            CveEntity("CVE-C", "c", "LOW", "2024-03-05", "", false, "Google", "Android", 0)
        )
        val merged = CveRepository.mergeEntries(cisaEntries, osvEntries)
        assertEquals(3, merged.size)
        val cveA = merged.find { it.cveId == "CVE-A" }!!
        assertEquals("2023-11-05", cveA.fixedInPatchLevel)
        assertTrue(cveA.isActivelyExploited)
        val cveB = merged.find { it.cveId == "CVE-B" }!!
        assertEquals("2024-02-01", cveB.fixedInPatchLevel)
        val cveC = merged.find { it.cveId == "CVE-C" }!!
        assertTrue(!cveC.isActivelyExploited)
    }
}
