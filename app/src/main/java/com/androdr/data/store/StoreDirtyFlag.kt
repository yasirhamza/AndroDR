package com.androdr.data.store

import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.booleanPreferencesKey
import androidx.datastore.preferences.core.edit
import com.androdr.di.StoreDataStore
import kotlinx.coroutines.flow.first
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Persistent "the store may hold garbage" flag (DataStore boolean `telemetry_store_dirty`).
 * Set by any `deleteScanTelemetry` or retention batch that throws; while it is set the startup
 * sweep runs [TelemetryStore.gcUnobservedUnpinned], which clears it after a completed pass.
 */
@Singleton
class StoreDirtyFlag @Inject constructor(@StoreDataStore private val dataStore: DataStore<Preferences>) {

    suspend fun set() {
        dataStore.edit { it[KEY] = true }
    }

    suspend fun clear() {
        dataStore.edit { it.remove(KEY) }
    }

    suspend fun isSet(): Boolean = dataStore.data.first()[KEY] == true

    private companion object {
        val KEY = booleanPreferencesKey("telemetry_store_dirty")
    }
}
