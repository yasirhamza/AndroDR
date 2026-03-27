package com.androdr.ioc

import com.androdr.data.model.CveEntry
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.lang.reflect.Field

class CveDatabaseTest {

    private lateinit var db: CveDatabase

    private val testEntries = listOf(
        CveEntry("CVE-2024-001", "CRITICAL", "Old exploit", "2024-06-15", true),
        CveEntry("CVE-2024-002", "CRITICAL", "Mid exploit", "2024-09-20", true),
        CveEntry("CVE-2025-001", "CRITICAL", "New exploit", "2025-01-10", true),
        CveEntry("CVE-2025-002", "CRITICAL", "Newest exploit", "2025-03-05", true)
    )

    @Before
    fun setup() {
        db = CveDatabase()
        // Inject test entries via reflection
        val field: Field = CveDatabase::class.java.getDeclaredField("androidCveEntries")
        field.isAccessible = true
        field.set(db, testEntries)
    }

    @Test
    fun `returns only CVEs after device patch level`() {
        val unpatched = db.getUnpatchedCves("2024-09-01")
        assertEquals(3, unpatched.size)
        assertTrue(unpatched.any { it.cveId == "CVE-2024-002" })
        assertTrue(unpatched.any { it.cveId == "CVE-2025-001" })
        assertTrue(unpatched.any { it.cveId == "CVE-2025-002" })
    }

    @Test
    fun `returns empty list when device is fully patched`() {
        val unpatched = db.getUnpatchedCves("2025-04-01")
        assertEquals(0, unpatched.size)
    }

    @Test
    fun `returns all CVEs for very old patch level`() {
        val unpatched = db.getUnpatchedCves("2024-01-01")
        assertEquals(4, unpatched.size)
    }

    @Test
    fun `returns empty list for invalid patch level`() {
        val unpatched = db.getUnpatchedCves("invalid")
        assertEquals(0, unpatched.size)
    }

    @Test
    fun `returns empty list when no CVEs loaded`() {
        val emptyDb = CveDatabase()
        val unpatched = emptyDb.getUnpatchedCves("2024-01-01")
        assertEquals(0, unpatched.size)
    }

    @Test
    fun `getActivelyExploitedCount returns correct count`() {
        assertEquals(4, db.getActivelyExploitedCount())
    }
}
