package com.androdr.data.db

import androidx.room.RoomDatabase
import androidx.sqlite.db.SupportSQLiteDatabase

/**
 * Caps the WAL file left behind after a checkpoint at 64 MB: large telemetry imports would
 * otherwise leave a WAL as big as the largest transaction on disk indefinitely.
 */
object JournalSizeLimitCallback : RoomDatabase.Callback() {
    const val LIMIT_BYTES = 67_108_864L

    override fun onOpen(db: SupportSQLiteDatabase) {
        // The PRAGMA returns a row, so it is run as a query rather than execSQL.
        db.query("PRAGMA journal_size_limit = $LIMIT_BYTES").use { it.moveToFirst() }
    }
}
