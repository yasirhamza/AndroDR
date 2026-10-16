package com.androdr.data.db

import androidx.sqlite.db.SupportSQLiteDatabase
import io.mockk.every
import io.mockk.mockk
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

class Migration18To19SqlTest {
    @Test
    fun `migration is DDL only - drop and recreate, no row copy`() {
        val sql = mutableListOf<String>()
        val db = mockk<SupportSQLiteDatabase>(relaxed = true)
        every { db.execSQL(capture(sql)) } returns Unit
        MIGRATION_18_19.migrate(db)
        assertEquals(2, sql.size)
        assertEquals("DROP TABLE IF EXISTS `indicators`", sql[0])
        assertTrue(sql[1].startsWith("CREATE TABLE IF NOT EXISTS `indicators`"))
        assertTrue(sql.none { it.startsWith("INSERT") })
    }

    @Test
    fun `migration CREATE TABLE equals the schema 19 createSql`() {
        val sql = mutableListOf<String>()
        val db = mockk<SupportSQLiteDatabase>(relaxed = true)
        every { db.execSQL(capture(sql)) } returns Unit
        MIGRATION_18_19.migrate(db)
        val v19 = JSONObject(schema("19.json").readText()).getJSONObject("database")
        val e = (0 until v19.getJSONArray("entities").length())
            .map { v19.getJSONArray("entities").getJSONObject(it) }.single { it.getString("tableName") == "indicators" }
        assertEquals(e.getString("createSql").replace("\${TABLE_NAME}", "indicators"), sql[1])
    }

    @Test
    fun `schema 19 indicators columns`() {
        val v19 = JSONObject(schema("19.json").readText()).getJSONObject("database")
        val e = (0 until v19.getJSONArray("entities").length())
            .map { v19.getJSONArray("entities").getJSONObject(it) }.single { it.getString("tableName") == "indicators" }
        val fields = e.getJSONArray("fields")
        val cols = (0 until fields.length()).map { fields.getJSONObject(it).getString("columnName") }
        assertEquals(listOf("type", "value", "family", "category", "campaignKey", "severity", "description",
            "source", "reference", "fetchedAt"), cols)
    }

    private fun schema(n: String) = listOf(File("schemas/com.androdr.data.db.AppDatabase/$n"),
        File("app/schemas/com.androdr.data.db.AppDatabase/$n")).first { it.isFile }
}
