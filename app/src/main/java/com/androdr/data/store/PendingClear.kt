package com.androdr.data.store

import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.longPreferencesKey
import com.androdr.di.StoreDataStore
import kotlinx.coroutines.flow.first
import javax.inject.Inject
import javax.inject.Singleton

/**
 * A "Clear all" that has run its first transaction but may not have finished (spec §5.4): DataStore
 * long `pending_clear_max_row_id`, the newest `forensic_timeline` id at that transaction
 * (`clearMaxRowId`). "Clear all" saves it right after its first transaction, still under the writer
 * lock, and removes it when done; `StartupSweep` finishes a pending clear's scan-less rows
 * (`scanResultId = -1`, `id <= clearMaxRowId`) and removes it. Its `DELETING` scans are swept like
 * any interrupted delete.
 */
@Singleton
class PendingClear @Inject constructor(@StoreDataStore private val dataStore: DataStore<Preferences>) {

    suspend fun save(clearMaxRowId: Long) {
        dataStore.edit { it[KEY] = clearMaxRowId }
    }

    suspend fun get(): Long? = dataStore.data.first()[KEY]

    suspend fun clear() {
        dataStore.edit { it.remove(KEY) }
    }

    private companion object {
        val KEY = longPreferencesKey("pending_clear_max_row_id")
    }
}
