package com.androdr.ioc

import android.content.Context
import android.util.Log
import com.androdr.R
import com.androdr.data.model.Indicator
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import java.util.Locale
import javax.inject.Inject
import javax.inject.Singleton

@Serializable
data class BundledDomainInfo(
    val domain: String,
    val familyName: String = "",
    val category: String = "",
    val campaign: String = "",
    val severity: String = "HIGH",
    val description: String = "",
    val reference: String = "",
    val blockByDefault: Boolean = false,
)

/**
 * Bundled known-bad domains (`R.raw.known_bad_domains`, generated from `ioc-data`).
 *
 * Every entry is used for attribution and cold start ([lookup]); only entries with
 * `blockByDefault == true` are blocked by the VPN ([blockedDomains]). The resource is
 * decoded once, on first use, into in-memory collections: after that first load a lookup
 * is a HashMap read with no I/O.
 */
@Singleton
open class BundledDomainDatabase @Inject constructor(
    @ApplicationContext private val context: Context
) {
    private val json = Json { ignoreUnknownKeys = true }

    private val loaded: Pair<Map<String, Indicator>, Set<String>> by lazy { load() }

    open fun lookup(domain: String): Indicator? = loaded.first[domain.lowercase(Locale.ROOT)]

    open fun blockedDomains(): Set<String> = loaded.second

    @Suppress("TooGenericExceptionCaught")
    private fun load(): Pair<Map<String, Indicator>, Set<String>> = try {
        val raw = context.resources.openRawResource(R.raw.known_bad_domains)
            .bufferedReader().use { it.readText() }
        val entries = json.decodeFromString<List<BundledDomainInfo>>(raw)
        val blocked = entries.filter { it.blockByDefault }
            .map { it.domain.lowercase(Locale.ROOT) }.toSet()
        entries.associate { e ->
            val d = e.domain.lowercase(Locale.ROOT)
            d to Indicator(
                IndicatorResolver.TYPE_DOMAIN, d, family = e.familyName,
                category = e.category, campaignKey = e.campaign,
                severity = e.severity, description = e.description,
                source = "bundled", reference = e.reference, fetchedAt = 0L
            )
        } to blocked
    } catch (e: Exception) {
        Log.w("BundledDomainDatabase", "load failed: ${e.message}")
        emptyMap<String, Indicator>() to emptySet()
    }
}
