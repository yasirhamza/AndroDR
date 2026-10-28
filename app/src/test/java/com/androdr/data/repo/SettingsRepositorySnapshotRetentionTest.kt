package com.androdr.data.repo

import androidx.datastore.preferences.core.PreferenceDataStoreFactory
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.intPreferencesKey
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

    private val dataStore by lazy {
        PreferenceDataStoreFactory.create(produceFile = { java.io.File(tmp.root, "s.preferences_pb") })
    }
    private val repo by lazy { SettingsRepository(dataStore) }

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

    /** D4 fix m6: a stored value below one (bypassing the setter) reads as one, never zero. */
    @Test
    fun `a stored snapshotRetentionScans below one reads as one`() = runBlocking {
        for (stored in listOf(0, -5)) {
            dataStore.edit { it[intPreferencesKey("snapshot_retention_scans")] = stored }
            assertEquals(1, repo.snapshotRetentionScans.first())
        }
    }
}
