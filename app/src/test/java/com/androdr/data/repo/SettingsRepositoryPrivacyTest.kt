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
        repo.setRefusedTrackerCategories(setOf(TrackerCategory.LOCATION))
        dataStore.edit {
            it[stringSetPreferencesKey("privacy_refused_categories")] = setOf("LOCATION", "NOT_A_CATEGORY")
        }
        assertEquals(setOf(TrackerCategory.LOCATION), repo.refusedTrackerCategories.first())
    }

    /** What an install that customised its threshold on an earlier build holds after the update. */
    private suspend fun storedByAnEarlierBuild(vararg names: String) {
        dataStore.edit { it[stringSetPreferencesKey("privacy_refused_categories")] = names.toSet() }
    }

    @Test
    fun `a threshold saved before proxyware existed refuses it until the next save`() = runBlocking {
        storedByAnEarlierBuild("LOCATION")
        assertEquals(setOf(TrackerCategory.LOCATION, TrackerCategory.PROXYWARE), repo.refusedTrackerCategories.first())
        storedByAnEarlierBuild()
        assertEquals(setOf(TrackerCategory.PROXYWARE), repo.refusedTrackerCategories.first())
    }

    @Test
    fun `proxyware switched off by the person stays off`() = runBlocking {
        storedByAnEarlierBuild("LOCATION")
        repo.setTrackerCategoryRefused(TrackerCategory.PROXYWARE, false)
        assertEquals(setOf(TrackerCategory.LOCATION), repo.refusedTrackerCategories.first())
        repo.setRefusedTrackerCategories(emptySet())
        assertEquals(emptySet<TrackerCategory>(), repo.refusedTrackerCategories.first())
    }

    @Test
    fun `changing another category keeps proxyware refused on an earlier threshold`() = runBlocking {
        storedByAnEarlierBuild("LOCATION")
        repo.setTrackerCategoryRefused(TrackerCategory.ANALYTICS, true)
        assertEquals(
            setOf(TrackerCategory.LOCATION, TrackerCategory.ANALYTICS, TrackerCategory.PROXYWARE),
            repo.refusedTrackerCategories.first(),
        )
    }

    @Test
    fun `one category is changed from what is stored, not from what a screen showed`() = runBlocking {
        // #470 review: the sheet could be tapped before the stored threshold was read, and it then
        // saved "nothing refused, plus or minus one" over the real threshold.
        repo.setTrackerCategoryRefused(TrackerCategory.CRASH_REPORTING, true)
        assertEquals(
            SettingsRepository.DEFAULT_REFUSED_CATEGORIES + TrackerCategory.CRASH_REPORTING,
            repo.refusedTrackerCategories.first(),
        )
        repo.setTrackerCategoryRefused(TrackerCategory.LOCATION, false)
        assertEquals(
            SettingsRepository.DEFAULT_REFUSED_CATEGORIES + TrackerCategory.CRASH_REPORTING - TrackerCategory.LOCATION,
            repo.refusedTrackerCategories.first(),
        )
    }

    @Test
    fun `the categories of earlier builds are the ones the app had before proxyware`() {
        // A category added later must not be added to this list: it would then never be refused
        // for a threshold saved earlier.
        assertEquals(
            TrackerCategory.entries.map { it.name }.toSet() - "PROXYWARE",
            setOf("ADVERTISEMENT", "PROFILING", "IDENTIFICATION", "LOCATION", "ANALYTICS",
                "CRASH_REPORTING", "UNCATEGORISED", "OTHER"),
        )
    }

    @Test
    fun `proxyware is refused by default`() = runBlocking {
        assertTrue(TrackerCategory.PROXYWARE in repo.refusedTrackerCategories.first())
    }

    @Test
    fun `privacyShowSystemApps defaults false and round-trips`() = runBlocking {
        assertFalse(repo.privacyShowSystemApps.first())
        repo.setPrivacyShowSystemApps(true)
        assertTrue(repo.privacyShowSystemApps.first())
    }
}
