package com.androdr.data.store

import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.longPreferencesKey
import com.androdr.di.StoreDataStore
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.map
import javax.inject.Inject
import javax.inject.Singleton

/** How many DNS events the VPN log had to discard, and when it last did. */
data class DnsDropState(val total: Long, val lastDropAt: Long) {
    val any: Boolean get() = total > 0
}

/**
 * Lasting record that the DNS event buffer dropped events (it holds at most a bounded number while the
 * database keeps failing). Kept in DataStore, outside the database that is the likeliest cause, and
 * never cleared by a later successful flush: only the user's dismissal clears it.
 */
@Singleton
class DnsDropLog @Inject constructor(@StoreDataStore private val dataStore: DataStore<Preferences>) {

    val state: Flow<DnsDropState> = dataStore.data.map {
        DnsDropState(it[TOTAL] ?: 0L, it[LAST_AT] ?: 0L)
    }

    suspend fun record(count: Int, at: Long) {
        dataStore.edit {
            it[TOTAL] = (it[TOTAL] ?: 0L) + count
            it[LAST_AT] = at
        }
    }

    suspend fun clear() {
        dataStore.edit {
            it.remove(TOTAL)
            it.remove(LAST_AT)
        }
    }

    private companion object {
        val TOTAL = longPreferencesKey("dns_events_dropped_total")
        val LAST_AT = longPreferencesKey("dns_events_dropped_last_at")
    }
}
