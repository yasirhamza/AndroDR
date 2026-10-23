package com.androdr.data.store

import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.booleanPreferencesKey
import androidx.datastore.preferences.core.edit
import com.androdr.di.StoreDataStore
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.map
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Persistent "the database could not even take a scan's findings" flag (DataStore boolean
 * `storage_health_failed`, spec §5.2): set when a session that already fell back to
 * evaluate-only on `SQLiteFullException` fails again writing its findings. Kept outside the
 * database on purpose — the database is the thing that is full.
 */
@Singleton
class StorageHealthFlag @Inject constructor(@StoreDataStore private val dataStore: DataStore<Preferences>) {

    suspend fun set() {
        dataStore.edit { it[KEY] = true }
    }

    suspend fun clear() {
        dataStore.edit { it.remove(KEY) }
    }

    /** Live view of the flag, for the Dashboard banner. */
    val isSetFlow: Flow<Boolean> = dataStore.data.map { it[KEY] == true }

    suspend fun isSet(): Boolean = dataStore.data.first()[KEY] == true

    private companion object {
        val KEY = booleanPreferencesKey("storage_health_failed")
    }
}
