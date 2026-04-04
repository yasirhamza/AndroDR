package com.androdr.ioc

import android.content.Context
import android.util.Log
import com.androdr.R
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.snakeyaml.engine.v2.api.Load
import org.snakeyaml.engine.v2.api.LoadSettings
import java.net.HttpURLConnection
import java.net.URL
import java.util.concurrent.atomic.AtomicReference
import javax.inject.Inject
import javax.inject.Singleton

@Singleton
class OemPrefixResolver @Inject constructor(
    @ApplicationContext private val context: Context
) {

    private val data = AtomicReference<ParsedOemData>(loadBundledData())

    @Suppress("TooGenericExceptionCaught")
    private fun loadBundledData(): ParsedOemData {
        return try {
            val yaml = context.resources.openRawResource(R.raw.known_oem_prefixes)
                .bufferedReader().use { it.readText() }
            parseOemPrefixYaml(yaml)
        } catch (e: Exception) {
            Log.w(TAG, "Failed to load bundled OEM prefixes: ${e.message}")
            ParsedOemData(emptySet(), emptySet(), emptySet())
        }
    }

    /** Returns true if the package matches a strict OEM prefix (always OEM regardless of FLAG_SYSTEM). */
    fun isOemPrefix(packageName: String): Boolean =
        data.get().strictPrefixes.any { packageName.startsWith(it) }

    /** Returns true if the package matches a strict OEM prefix. Alias for [isOemPrefix]. */
    fun isStrictOemPrefix(packageName: String): Boolean =
        data.get().strictPrefixes.any { packageName.startsWith(it) }

    /** Returns true if the package matches a partnership prefix (only OEM when app has FLAG_SYSTEM). */
    fun isPartnershipPrefix(packageName: String): Boolean =
        data.get().partnershipPrefixes.any { packageName.startsWith(it) }

    fun isTrustedInstaller(installer: String): Boolean =
        installer in data.get().installers || isOemPrefix(installer)

    /**
     * Fetches the latest OEM prefix list from the public rules repo.
     * On success, replaces the in-memory cache. On failure, keeps existing data.
     */
    @Suppress("TooGenericExceptionCaught")
    suspend fun refresh() = withContext(Dispatchers.IO) {
        try {
            val yaml = fetchUrl(PREFIXES_URL) ?: return@withContext
            val parsed = parseOemPrefixYaml(yaml)

            // Sanity checks — reject obviously malicious remote data
            val allPrefixes = parsed.strictPrefixes + parsed.partnershipPrefixes
            if (allPrefixes.any { it.length < 4 }) {
                Log.w(TAG, "Remote OEM prefix feed rejected: prefix too short (possible wildcard attack)")
                return@withContext
            }
            if (allPrefixes.size > 500) {
                Log.w(TAG, "Remote OEM prefix feed rejected: too many prefixes (${allPrefixes.size})")
                return@withContext
            }

            if (allPrefixes.isNotEmpty() || parsed.installers.isNotEmpty()) {
                val current = data.get()
                data.set(ParsedOemData(
                    strictPrefixes = if (parsed.strictPrefixes.isNotEmpty()) {
                        parsed.strictPrefixes
                    } else {
                        current.strictPrefixes
                    },
                    partnershipPrefixes = if (parsed.partnershipPrefixes.isNotEmpty()) {
                        parsed.partnershipPrefixes
                    } else {
                        current.partnershipPrefixes
                    },
                    installers = if (parsed.installers.isNotEmpty()) {
                        parsed.installers
                    } else {
                        current.installers
                    }
                ))
                val updated = data.get()
                Log.i(
                    TAG,
                    "OEM data refreshed: ${updated.strictPrefixes.size} strict + " +
                        "${updated.partnershipPrefixes.size} partnership prefixes, " +
                        "${updated.installers.size} installers"
                )
            }
        } catch (e: Exception) {
            Log.w(TAG, "OEM prefix refresh failed: ${e.message}")
        }
    }

    internal data class ParsedOemData(
        val strictPrefixes: Set<String>,
        val partnershipPrefixes: Set<String>,
        val installers: Set<String>
    )

    @Suppress("UNCHECKED_CAST", "TooGenericExceptionCaught")
    internal fun parseOemPrefixYaml(yamlContent: String): ParsedOemData {
        return try {
            val settings = LoadSettings.builder()
                .setAllowDuplicateKeys(false)
                .setMaxAliasesForCollections(10)
                .build()
            val load = Load(settings)
            val doc = load.loadFromString(yamlContent) as? Map<*, *>
                ?: return ParsedOemData(emptySet(), emptySet(), emptySet())

            // Collect prefix lists: keys containing "partner" go to partnership, others to strict
            val strictPrefixes = mutableSetOf<String>()
            val partnershipPrefixes = mutableSetOf<String>()
            for ((key, value) in doc) {
                val keyStr = key.toString()
                if (keyStr.endsWith("_prefixes") && value is List<*>) {
                    val prefixes = value.filterIsInstance<String>()
                    if (keyStr.contains("partner")) {
                        partnershipPrefixes.addAll(prefixes)
                    } else {
                        strictPrefixes.addAll(prefixes)
                    }
                }
            }

            // Collect trusted installers
            val installerList = (doc["trusted_installers"] as? List<*>)
                ?.filterIsInstance<String>()
                ?.filter { it.length >= 10 && it.contains('.') }
                ?.take(MAX_INSTALLER_COUNT)
                ?.toSet() ?: emptySet()

            ParsedOemData(strictPrefixes, partnershipPrefixes, installerList)
        } catch (e: Exception) {
            Log.w(TAG, "Failed to parse OEM prefix YAML: ${e.message}")
            ParsedOemData(emptySet(), emptySet(), emptySet())
        }
    }

    @Suppress("TooGenericExceptionCaught", "SwallowedException")
    private fun fetchUrl(url: String): String? {
        val conn = try {
            URL(url).openConnection() as HttpURLConnection
        } catch (e: Exception) { return null }
        return try {
            conn.connectTimeout = TIMEOUT_MS
            conn.readTimeout = TIMEOUT_MS
            conn.setRequestProperty("User-Agent", "AndroDR/1.0")
            if (conn.responseCode == HttpURLConnection.HTTP_OK) {
                val body = conn.inputStream.bufferedReader().use { it.readText() }
                if (body.length > MAX_RESPONSE_SIZE) {
                    Log.w(TAG, "Response too large: ${body.length} bytes")
                    return null
                }
                body
            } else null
        } catch (e: Exception) { null }
        finally { conn.disconnect() }
    }

    companion object {
        private const val TAG = "OemPrefixResolver"
        private const val PREFIXES_URL =
            "https://raw.githubusercontent.com/android-sigma-rules/rules/main/ioc-data/known-oem-prefixes.yml"
        private const val TIMEOUT_MS = 10_000
        private const val MAX_RESPONSE_SIZE = 100_000
        private const val MAX_INSTALLER_COUNT = 50
    }
}
