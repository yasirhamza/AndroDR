package com.androdr.data.repo

import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.PreferenceDataStoreFactory
import com.androdr.ui.theme.ThemeMode
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

class SettingsRepositoryThemeModeTest {

    @get:Rule val tmp = TemporaryFolder()

    private lateinit var dataStore: DataStore<Preferences>
    private lateinit var repo: SettingsRepository

    @Before
    fun setUp() {
        val file = java.io.File(tmp.root, "test.preferences_pb")
        dataStore = PreferenceDataStoreFactory.create(produceFile = { file })
        repo = SettingsRepository(dataStore)
    }

    @After
    fun tearDown() {
        // TemporaryFolder rule handles cleanup
    }

    @Test
    fun `default themeMode is AUTO`() = runBlocking {
        assertEquals(ThemeMode.AUTO, repo.themeMode.first())
    }

    @Test
    fun `setThemeMode round-trips LIGHT`() = runBlocking {
        repo.setThemeMode(ThemeMode.LIGHT)
        assertEquals(ThemeMode.LIGHT, repo.themeMode.first())
    }

    @Test
    fun `setThemeMode round-trips DARK`() = runBlocking {
        repo.setThemeMode(ThemeMode.DARK)
        assertEquals(ThemeMode.DARK, repo.themeMode.first())
    }

    @Test
    fun `setThemeMode round-trips back to AUTO`() = runBlocking {
        repo.setThemeMode(ThemeMode.DARK)
        repo.setThemeMode(ThemeMode.AUTO)
        assertEquals(ThemeMode.AUTO, repo.themeMode.first())
    }
}
