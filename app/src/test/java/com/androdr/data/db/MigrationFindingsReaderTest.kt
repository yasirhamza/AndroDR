package com.androdr.data.db

import android.content.Context
import androidx.room.testing.MigrationTestHelper
import androidx.sqlite.db.SupportSQLiteDatabase
import androidx.test.core.app.ApplicationProvider
import kotlinx.serialization.json.JsonPrimitive
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

/** [MigrationFindingsReader]'s size cap counts UTF-8 bytes, and chunked reads keep multi-byte text intact. */
@RunWith(RobolectricTestRunner::class)
class MigrationFindingsReaderTest {
    private val name = "migration-findings-reader"

    @get:Rule val helper: MigrationTestHelper = RoomTestDb.migrationHelper()

    @After fun tearDown() {
        ApplicationProvider.getApplicationContext<Context>().deleteDatabase(name)
    }

    private fun withScan(findings: String, block: (SupportSQLiteDatabase) -> Unit) {
        val db = helper.createDatabase(name, 20)
        try {
            db.execSQL(
                "INSERT INTO ScanResult (id, timestamp, findings, bugReportFindings, riskySideloadCount, " +
                    "knownMalwareCount, scannerErrors, source, state, telemetryState) " +
                    "VALUES (1, 1, ?, '[]', 0, 0, '[]', 'LIVE_SCAN', 'COMPLETE', 'STORED')",
                arrayOf<Any>(findings)
            )
            block(db)
        } finally {
            db.close()
        }
    }

    private fun findings(title: String) = """[{"ruleId":"r","title":"$title","level":"high"}]"""

    @Test
    fun `a value under the cap in characters but over it in UTF-8 bytes is refused`() {
        // 800 000 three-byte characters: 0.8 M characters (a character cap let it through), 2.4 MB.
        val title = "€".repeat(800_000)
        val text = findings(title)
        assertTrue(text.length < MigrationFindingsReader.MAX_BYTES)
        assertTrue(text.toByteArray(Charsets.UTF_8).size > MigrationFindingsReader.MAX_BYTES)
        withScan(text) { db -> assertNull(MigrationFindingsReader.readOrNull(db, 1L)) }
    }

    @Test
    fun `multi-byte text under the cap reads back whole across chunk boundaries`() {
        // Spans several CHUNK_CHARS chunks, with four-byte characters (a surrogate pair each in Kotlin).
        val title = ("€é" + String(Character.toChars(0x1F512))).repeat(150_000)
        val text = findings(title)
        assertTrue(text.length > 2 * MigrationFindingsReader.CHUNK_CHARS)
        assertTrue(text.toByteArray(Charsets.UTF_8).size < MigrationFindingsReader.MAX_BYTES)
        withScan(text) { db ->
            val read = MigrationFindingsReader.readOrNull(db, 1L)!!
            assertEquals(title, (read.single()["title"] as JsonPrimitive).content)
        }
    }
}
