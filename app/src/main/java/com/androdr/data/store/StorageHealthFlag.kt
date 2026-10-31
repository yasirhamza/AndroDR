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
 *
 * Beside it, `scan_not_saved` (#418): a live scan ran but is not in history for any other reason (a
 * writer error), so after a restart the Dashboard still says a recent scan is missing instead of
 * showing the earlier, saved scan as if it were the latest. It clears on the next saved scan; the
 * storage flag only on the next fully stored one ([recordScan]).
 */
@Singleton
class StorageHealthFlag @Inject constructor(@StoreDataStore private val dataStore: DataStore<Preferences>) {

    suspend fun set() {
        dataStore.edit { it[KEY] = true }
    }

    /**
     * Records a finished live scan: unsaved sets the not-saved marker; saved clears it (the newest
     * scan is in history, even if partly stored, so "an earlier scan is shown" would be false); saved
     * with all its records ([fullyStored]) also clears the storage flag.
     */
    suspend fun recordScan(saved: Boolean, fullyStored: Boolean) {
        dataStore.edit {
            if (saved) it.remove(NOT_SAVED_KEY) else it[NOT_SAVED_KEY] = true
            if (saved && fullyStored) it.remove(KEY)
        }
    }

    /** Live view of the flag, for the Dashboard banner. */
    val isSetFlow: Flow<Boolean> = dataStore.data.map { it[KEY] == true }

    /** Live view of the "a recent scan was not saved" marker. */
    val scanNotSavedFlow: Flow<Boolean> = dataStore.data.map { it[NOT_SAVED_KEY] == true }

    suspend fun isSet(): Boolean = dataStore.data.first()[KEY] == true

    private companion object {
        val KEY = booleanPreferencesKey("storage_health_failed")
        val NOT_SAVED_KEY = booleanPreferencesKey("scan_not_saved")
    }
}
