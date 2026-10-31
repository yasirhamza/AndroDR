package com.androdr.data.db

import androidx.room.testing.MigrationTestHelper
import com.androdr.data.model.ScanResult
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import java.io.File

@RunWith(RobolectricTestRunner::class)
class RoomJvmHarnessTest {
    @get:Rule val helper: MigrationTestHelper = RoomTestDb.migrationHelper()

    @Test
    fun `in-memory database round-trips a ScanResult`() = runBlocking {
        val db = RoomTestDb.inMemory()
        try {
            val scan = ScanResult(
                id = 42L, timestamp = 1_700_000_000_000L,
                bugReportFindings = listOf("a"), riskySideloadCount = 2, knownMalwareCount = 1
            )
            db.scanResultDao().insert(scan)
            val back = db.scanResultDao().getLatestTwo().single()
            assertEquals(scan, back)
        } finally {
            db.close()
        }
    }

    @Test
    fun `migration helper opens schema 19`() {
        val db = helper.createDatabase("harness-v19", 19)
        try {
            assertEquals(19, db.version)
        } finally {
            db.close()
        }
    }

    /**
     * [MigrationTestHelper] is a JUnit TestWatcher: only its `finished()` closes the databases it
     * opened, and JUnit calls that only for a `@get:Rule`. A helper held in a plain field or a local
     * is never finished, so a test failing before its own `close()` leaks the database.
     */
    @Test
    fun `every migration helper is a JUnit rule`() {
        val call = "RoomTestDb." + "migrationHelper()"
        val roots = listOf(File("src/test/java"), File("app/src/test/java")).filter { it.isDirectory }
        val uses = roots.flatMap { r -> r.walkTopDown().filter { it.extension == "kt" }.toList() }
            .flatMap { f -> f.readLines().filter { call in it }.map { "${f.name}: ${it.trim()}" } }
        assertTrue("no migration helper uses found", uses.size >= 3)
        val bad = uses.filterNot { Regex(": @get:Rule val \\w+: MigrationTestHelper = ").containsMatchIn(it) }
        assertTrue("migration helper outside a @get:Rule:\n" + bad.joinToString("\n"), bad.isEmpty())
    }
}
