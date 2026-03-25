package com.androdr.data.repo

import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.booleanPreferencesKey
import androidx.datastore.preferences.core.edit
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.map
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Persists two DNS policy settings in Jetpack DataStore (Preferences):
 *
 * - [blocklistBlockMode]: `true` = NXDOMAIN for static blocklist hits; `false` = detect-only
 * - [domainIocBlockMode]: `true` = NXDOMAIN for IOC domain hits; `false` = detect-only (default)
 */
@Singleton
class SettingsRepository @Inject constructor(
    private val dataStore: DataStore<Preferences>
) {

    val blocklistBlockMode: Flow<Boolean> = dataStore.data
        .map { prefs -> prefs[KEY_BLOCKLIST_BLOCK_MODE] ?: true }

    val domainIocBlockMode: Flow<Boolean> = dataStore.data
        .map { prefs -> prefs[KEY_DOMAIN_IOC_BLOCK_MODE] ?: false }

    suspend fun setBlocklistBlockMode(value: Boolean) {
        dataStore.edit { it[KEY_BLOCKLIST_BLOCK_MODE] = value }
    }

    suspend fun setDomainIocBlockMode(value: Boolean) {
        dataStore.edit { it[KEY_DOMAIN_IOC_BLOCK_MODE] = value }
    }

    companion object {
        private val KEY_BLOCKLIST_BLOCK_MODE  = booleanPreferencesKey("blocklist_block_mode")
        private val KEY_DOMAIN_IOC_BLOCK_MODE = booleanPreferencesKey("domain_ioc_block_mode")
    }
}
