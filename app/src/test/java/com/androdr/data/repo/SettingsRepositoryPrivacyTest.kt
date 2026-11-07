package com.androdr.data.repo

import androidx.datastore.preferences.core.PreferenceDataStoreFactory
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.stringSetPreferencesKey
import com.androdr.privacy.model.TrackerCategory
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

/** The privacy threshold (refused tracker categories) and the system-apps toggle. */
class SettingsRepositoryPrivacyTest {

    @get:Rule val tmp = TemporaryFolder()

    private val dataStore by lazy {
        PreferenceDataStoreFactory.create(produceFile = { java.io.File(tmp.root, "p.preferences_pb") })
    }
    private val repo by lazy { SettingsRepository(dataStore) }

    @Test
    fun `default refuses everything except crash reporting and other, uncategorised included`() = runBlocking {
        val refused = repo.refusedTrackerCategories.first()
        assertTrue(TrackerCategory.UNCATEGORISED in refused)
        assertFalse(TrackerCategory.CRASH_REPORTING in refused)
        assertFalse(TrackerCategory.OTHER in refused)
        assertEquals(
            TrackerCategory.entries.toSet() - TrackerCategory.CRASH_REPORTING - TrackerCategory.OTHER,
            refused
        )
    }

    @Test
    fun `refused categories round-trip, including an empty set`() = runBlocking {
        repo.setRefusedTrackerCategories(setOf(TrackerCategory.LOCATION, TrackerCategory.OTHER))
        assertEquals(setOf(TrackerCategory.LOCATION, TrackerCategory.OTHER), repo.refusedTrackerCategories.first())
        repo.setRefusedTrackerCategories(emptySet())
        assertEquals(emptySet<TrackerCategory>(), repo.refusedTrackerCategories.first())
    }

    @Test
    fun `an unknown stored category name is ignored`() = runBlocking {
        dataStore.edit {
            it[stringSetPreferencesKey("privacy_refused_categories")] = setOf("LOCATION", "NOT_A_CATEGORY")
        }
        assertEquals(setOf(TrackerCategory.LOCATION), repo.refusedTrackerCategories.first())
    }

    @Test
    fun `privacyShowSystemApps defaults false and round-trips`() = runBlocking {
        assertFalse(repo.privacyShowSystemApps.first())
        repo.setPrivacyShowSystemApps(true)
        assertTrue(repo.privacyShowSystemApps.first())
    }
}
