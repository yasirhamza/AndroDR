package com.androdr.ioc

import android.content.Context
import com.androdr.R
import com.androdr.data.model.KnownAppEntry
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.serialization.json.Json
import javax.inject.Inject
import javax.inject.Singleton

@Singleton
class KnownAppDatabase @Inject constructor(
    @ApplicationContext private val context: Context,
) {
    private val json = Json { ignoreUnknownKeys = true }

    private val entries: List<KnownAppEntry> by lazy {
        val raw = context.resources
            .openRawResource(R.raw.known_good_apps)
            .bufferedReader()
            .use { it.readText() }
        json.decodeFromString(raw)
    }

    private val map: HashMap<String, KnownAppEntry> by lazy {
        HashMap<String, KnownAppEntry>(entries.size * 2).also { m ->
            entries.forEach { e -> m[e.packageName] = e }
        }
    }

    /** Number of bundled entries. Used to initialise UI counters before remote feeds load. */
    val size: Int get() = entries.size

    fun lookup(packageName: String): KnownAppEntry? = map[packageName]
    fun getAll(): List<KnownAppEntry> = entries
}
