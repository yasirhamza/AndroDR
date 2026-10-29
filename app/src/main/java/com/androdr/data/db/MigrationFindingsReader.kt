package com.androdr.data.db

import android.util.Log
import androidx.sqlite.db.SupportSQLiteDatabase
import kotlinx.serialization.SerializationException
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject

/**
 * Reads a legacy `ScanResult.findings` JSON column inside a migration without ever loading the
 * whole value into one cursor row: the length is read first, then the text in [CHUNK_CHARS]
 * `substr` chunks (a single row larger than the 2 MB CursorWindow would throw). A row longer than
 * [MAX_CHARS], or one that is not a JSON array, yields no findings, so a migration that uses this
 * always completes. Shared by MIGRATION_19_20 (`level` backfill) and MIGRATION_20_21.
 *
 * Findings are returned as raw [JsonObject]s, not decoded [com.androdr.sigma.Finding]s, so the
 * migration does not depend on today's model classes.
 */
object MigrationFindingsReader {
    const val CHUNK_CHARS = 256 * 1024
    const val MAX_CHARS = 2 * 1024 * 1024

    private val json = Json { ignoreUnknownKeys = true }

    fun read(db: SupportSQLiteDatabase, scanId: Long): List<JsonObject> = readOrNull(db, scanId).orEmpty()

    /**
     * [read], but null when the value exists and cannot be read (over [MAX_CHARS], or not a JSON
     * array), so a caller can say that findings were lost; an absent or empty value is an empty list.
     */
    fun readOrNull(db: SupportSQLiteDatabase, scanId: Long): List<JsonObject>? {
        val length = db.query("SELECT length(findings) FROM ScanResult WHERE id = ?", arrayOf<Any>(scanId))
            .use { c -> if (c.moveToFirst() && !c.isNull(0)) c.getLong(0) else null }
        if (length == null || length == 0L) return emptyList()
        if (length > MAX_CHARS) {
            Log.w(TAG, "scan $scanId findings too large ($length chars)")
            return null
        }
        val text = StringBuilder(length.toInt())
        var start = 1L
        while (start <= length) {
            db.query(
                "SELECT substr(findings, ?, ?) FROM ScanResult WHERE id = ?",
                arrayOf<Any>(start, CHUNK_CHARS, scanId)
            ).use { c -> if (c.moveToFirst() && !c.isNull(0)) text.append(c.getString(0)) }
            start += CHUNK_CHARS
        }
        return parse(scanId, text.toString())
    }

    private fun parse(scanId: Long, text: String): List<JsonObject>? = try {
        (json.parseToJsonElement(text) as? JsonArray)?.filterIsInstance<JsonObject>()
    } catch (e: SerializationException) {
        Log.w(TAG, "scan $scanId findings unreadable: ${e.message}")
        null
    } catch (e: IllegalArgumentException) {
        Log.w(TAG, "scan $scanId findings unreadable: ${e.message}")
        null
    }

    private const val TAG = "MigrationFindings"
}
