package com.androdr.data.db

import androidx.sqlite.db.SupportSQLiteDatabase
import com.androdr.data.model.TelemetrySource
import io.mockk.every
import io.mockk.mockk
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * JVM guard for MIGRATION_17_18 (#356): `ScanResult.source`.
 *
 * Room's own [androidx.room.testing.MigrationTestHelper] needs real SQLite, so
 * the executing migration test lives in androidTest
 * (`Migration17To18Test`) alongside every other migration test in this project
 * and only runs on a device. This test is the part that CAN run in the JVM gate,
 * and it covers the two mistakes that would ship a crash-on-open build:
 *
 *  - the migration statement itself (wrong table, nullable column, or a default
 *    that is not a [TelemetrySource] constant — old rows would then decode to
 *    something the converter has to fall back on);
 *  - drift between the entity and the migration: the exported schema is
 *    generated from the ENTITY, so asserting the exported 18.json carries a
 *    NOT NULL TEXT `source` column catches "version bumped, field forgotten"
 *    and "field added, version not bumped" without a device.
 */
class Migration17To18SqlTest {

    @Test
    fun `migration adds a non-null source column defaulted to LIVE_SCAN`() {
        val statements = mutableListOf<String>()
        val db = mockk<SupportSQLiteDatabase>(relaxed = true)
        every { db.execSQL(capture(statements)) } returns Unit

        MIGRATION_17_18.migrate(db)

        assertEquals("the migration must be a single additive statement", 1, statements.size)
        assertEquals(
            "ALTER TABLE ScanResult ADD COLUMN source TEXT NOT NULL DEFAULT " +
                "'${TelemetrySource.LIVE_SCAN.name}'",
            statements.single()
        )
    }

    @Test
    fun `exported schema 18 carries the source column and 17 does not`() {
        val v18 = JSONObject(schemaFile("18.json").readText()).getJSONObject("database")
        assertEquals(18, v18.getInt("version"))

        val source = scanResultField(v18, "source")
        assertEquals("TEXT", source.getString("affinity"))
        assertTrue("source must be NOT NULL, matching the migration", source.getBoolean("notNull"))

        val v17 = JSONObject(schemaFile("17.json").readText()).getJSONObject("database")
        assertTrue(
            "17 must lack the column — otherwise the migration is not what added it",
            scanResultFieldOrNull(v17, "source") == null
        )
    }

    private fun scanResultField(database: JSONObject, name: String): JSONObject =
        requireNotNull(scanResultFieldOrNull(database, name)) { "ScanResult.$name missing from schema" }

    private fun scanResultFieldOrNull(database: JSONObject, name: String): JSONObject? {
        val entities = database.getJSONArray("entities")
        for (i in 0 until entities.length()) {
            val entity = entities.getJSONObject(i)
            if (entity.getString("tableName") != "ScanResult") continue
            val fields = entity.getJSONArray("fields")
            for (f in 0 until fields.length()) {
                val field = fields.getJSONObject(f)
                if (field.getString("columnName") == name) return field
            }
        }
        return null
    }

    /** Unit tests run from the module dir in Gradle and the repo root in some IDEs. */
    private fun schemaFile(name: String): File = listOf(
        File("schemas/com.androdr.data.db.AppDatabase/$name"),
        File("app/schemas/com.androdr.data.db.AppDatabase/$name")
    ).firstOrNull { it.isFile } ?: error("exported Room schema $name not found")
}
