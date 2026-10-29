package com.androdr.data.db

import com.androdr.data.model.ScanResult
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

@RunWith(RobolectricTestRunner::class)
class RoomJvmHarnessTest {
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
        val helper = RoomTestDb.migrationHelper()
        val db = helper.createDatabase("harness-v19", 19)
        try {
            assertEquals(19, db.version)
        } finally {
            db.close()
        }
    }
}
