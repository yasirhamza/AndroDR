package com.androdr.data.repo

import androidx.datastore.preferences.core.PreferenceDataStoreFactory
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

/** Spec §5.1 Retention: snapshot telemetry is kept for the newest N live scans, default 20. */
class SettingsRepositorySnapshotRetentionTest {

    @get:Rule val tmp = TemporaryFolder()

    private val repo by lazy {
        SettingsRepository(
            PreferenceDataStoreFactory.create(produceFile = { java.io.File(tmp.root, "s.preferences_pb") })
        )
    }

    @Test
    fun `snapshotRetentionScans defaults to 20`() = runBlocking {
        assertEquals(20, repo.snapshotRetentionScans.first())
    }

    @Test
    fun `snapshotRetentionScans round-trips`() = runBlocking {
        repo.setSnapshotRetentionScans(7)
        assertEquals(7, repo.snapshotRetentionScans.first())
    }

    @Test
    fun `snapshotRetentionScans below one is refused`() {
        assertTrue(runCatching { runBlocking { repo.setSnapshotRetentionScans(0) } }.isFailure)
    }
}
