package com.androdr.ioc

import com.androdr.data.db.IndicatorDao
import com.androdr.data.model.Indicator

/**
 * In-memory [IndicatorDao] shared by the ioc tests. REPLACE semantics keyed by (type, value);
 * [ownedValues] and [deleteStaleEntriesOfType] mirror the SQL in IndicatorDao. MockK cannot
 * exercise these, so tests that depend on write precedence or eviction use this fake.
 */
class FakeIndicatorDao : IndicatorDao {
    private val store: MutableMap<Pair<String, String>, Indicator> = mutableMapOf()

    fun snapshot(): Map<Pair<String, String>, Indicator> = store.toMap()

    override suspend fun upsertAll(entries: List<Indicator>) {
        entries.forEach { store[it.type to it.value] = it }
    }

    override suspend fun deleteStaleEntries(source: String, olderThan: Long): Int {
        val victims = store.entries
            .filter { it.value.source == source && it.value.fetchedAt < olderThan }
            .map { it.key }
        victims.forEach { store.remove(it) }
        return victims.size
    }

    override suspend fun deleteStaleEntriesOfType(source: String, type: String, olderThan: Long): Int {
        val victims = store.entries
            .filter { it.value.source == source && it.value.type == type && it.value.fetchedAt < olderThan }
            .map { it.key }
        victims.forEach { store.remove(it) }
        return victims.size
    }

    override suspend fun ownedValues(type: String, sources: List<String>, includeMvt: Boolean): List<String> =
        store.values.filter {
            it.type == type && (it.source in sources || (includeMvt && it.source.startsWith("mvt_")))
        }.map { it.value }

    override suspend fun lookup(type: String, value: String): Indicator? = store[type to value]

    override suspend fun getAllByType(type: String): List<Indicator> =
        store.values.filter { it.type == type }

    override suspend fun getValuesByType(type: String): List<String> =
        store.values.filter { it.type == type }.map { it.value }

    override suspend fun getAll(): List<Indicator> = store.values.toList()

    override suspend fun count(): Int = store.size

    override suspend fun countByType(type: String): Int = store.values.count { it.type == type }

    override suspend fun lastFetchTime(source: String): Long? =
        store.values.filter { it.source == source }.maxOfOrNull { it.fetchedAt }

    override suspend fun lastFetchTimeGlobal(): Long? = store.values.maxOfOrNull { it.fetchedAt }

    override suspend fun allSources(): List<String> = store.values.map { it.source }.distinct().sorted()

    override suspend fun hasSource(source: String): Boolean = store.values.any { it.source == source }

    override suspend fun hasSourcePrefix(prefix: String): Boolean = store.values.any { it.source.startsWith(prefix) }
}
