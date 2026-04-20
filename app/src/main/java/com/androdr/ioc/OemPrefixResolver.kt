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
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicReference
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Resolves whether a package name belongs to the OEM/system allowlist for
 * a given device identity. See [DeviceIdentity] for the manufacturer/brand
 * model and #90 for the prefix-spoofing attack this prevents.
 *
 * The allowlist YAML (`res/raw/known_oem_prefixes.yml`) has two top-level
 * sections:
 * - `unconditional:` — prefixes that apply to every device (AOSP, chipset,
 *   trusted installers, Android Go, custom ROMs).
 * - `conditional:` — per-vendor blocks keyed by `manufacturer_match` and
 *   `brand_match`. Only blocks whose match list contains the current
 *   device's manufacturer or brand contribute prefixes.
 *
 * Every public query method takes a [DeviceIdentity]. Runtime callers pass
 * [DeviceIdentity.local]; bugreport callers pass
 * [DeviceIdentity.fromSystemProperties].
 *
 * The applicable prefix set for each unique [DeviceIdentity] is cached
 * in [perDeviceCache] to avoid recomputing on every call.
 */
@Singleton
class OemPrefixResolver @Inject constructor(
    @ApplicationContext private val context: Context,
) {

    private val data = AtomicReference<ParsedOemData>(loadBundledData())

    /** Per-(manufacturer,brand) cache of applicable prefix sets. */
    private val perDeviceCache = ConcurrentHashMap<DeviceIdentity, ApplicablePrefixes>()

    @Suppress("TooGenericExceptionCaught")
    private fun loadBundledData(): ParsedOemData {
        return try {
            val yaml = context.resources.openRawResource(R.raw.known_oem_prefixes)
                .bufferedReader().use { it.readText() }
            parseOemPrefixYaml(yaml)
        } catch (e: Exception) {
            Log.w(TAG, "Failed to load bundled OEM prefixes: ${e.message}")
            ParsedOemData.empty()
        }
    }

    /**
     * Returns true iff [packageName] is a strict OEM prefix in the applicable
     * set for [device]. A strict prefix classifies the app as OEM regardless
     * of its FLAG_SYSTEM status.
     */
    fun isOemPrefix(packageName: String, device: DeviceIdentity): Boolean =
        applicablePrefixesFor(device).strict.any { packageName.startsWith(it) }

    /** Alias for [isOemPrefix], preserved for readability. */
    fun isStrictOemPrefix(packageName: String, device: DeviceIdentity): Boolean =
        isOemPrefix(packageName, device)

    /**
     * Returns true iff [installer] is a trusted app store. Trusted installers
     * are unconditional (every device), so [device] is accepted but only used
     * for the fallback `isOemPrefix` call.
     */
    fun isTrustedInstaller(installer: String, device: DeviceIdentity): Boolean {
        val d = data.get()
        return installer in d.trustedInstallers ||
            isOemPrefix(installer, device)
    }

    /**
     * Returns the applicable prefix set for [device]: unconditional prefixes
     * plus any conditional blocks whose `manufacturer_match` / `brand_match`
     * contains [device]'s manufacturer or brand.
     */
    fun applicablePrefixesFor(device: DeviceIdentity): ApplicablePrefixes =
        perDeviceCache.getOrPut(device) {
            val d = data.get()
            val strict = mutableSetOf<String>()

            // Unconditional always applies
            strict.addAll(d.unconditionalStrict)

            // Conditional blocks apply iff manufacturer OR brand matches
            for (block in d.conditional) {
                if (block.matches(device)) {
                    strict.addAll(block.strictPrefixes)
                }
            }

            ApplicablePrefixes(strict = strict.toSet())
        }

    /**
     * Fetches the latest OEM prefix list from the public rules repo.
     * On success, replaces the in-memory cache AND invalidates [perDeviceCache]
     * so subsequent queries re-derive the applicable set.
     */
    @Suppress("TooGenericExceptionCaught", "ReturnCount")
    suspend fun refresh() = withContext(Dispatchers.IO) {
        try {
            val yaml = fetchUrl(PREFIXES_URL) ?: return@withContext
            val parsed = parseOemPrefixYaml(yaml)

            // Sanity checks — reject obviously malicious remote data
            val allPrefixes = parsed.unconditionalStrict +
                parsed.conditional.flatMap { it.strictPrefixes }
            if (allPrefixes.any { it.length < 4 }) {
                Log.w(TAG, "Remote OEM prefix feed rejected: prefix too short")
                return@withContext
            }
            if (allPrefixes.size > MAX_PREFIX_COUNT) {
                Log.w(TAG, "Remote OEM prefix feed rejected: too many prefixes (${allPrefixes.size})")
                return@withContext
            }

            if (allPrefixes.isNotEmpty() || parsed.trustedInstallers.isNotEmpty()) {
                data.set(parsed)
                perDeviceCache.clear()
                Log.i(
                    TAG,
                    "OEM data refreshed: ${parsed.unconditionalStrict.size} unconditional + " +
                        "${parsed.conditional.size} conditional blocks, " +
                        "${parsed.trustedInstallers.size} installers",
                )
            }
        } catch (e: Exception) {
            Log.w(TAG, "OEM prefix refresh failed: ${e.message}")
        }
    }

    // ─── Data classes ──────────────────────────────────────────────────────

    /** Raw parsed YAML data. */
    internal data class ParsedOemData(
        val unconditionalStrict: Set<String>,
        val conditional: List<ConditionalBlock>,
        val trustedInstallers: Set<String>,
    ) {
        companion object {
            fun empty() = ParsedOemData(emptySet(), emptyList(), emptySet())
        }
    }

    /** A single conditional block from the YAML. */
    internal data class ConditionalBlock(
        val id: String,
        val manufacturerMatch: Set<String>,
        val brandMatch: Set<String>,
        val strictPrefixes: Set<String>,
    ) {
        /**
         * A block matches a device iff the device's manufacturer is in
         * [manufacturerMatch] OR the device's brand is in [brandMatch].
         * Either condition is sufficient — allows carrier-branded builds
         * to match on brand even if manufacturer is generic.
         */
        fun matches(device: DeviceIdentity): Boolean =
            device.manufacturer in manufacturerMatch ||
                device.brand in brandMatch
    }

    /** The effective allowlist for a specific device identity. */
    data class ApplicablePrefixes(
        val strict: Set<String>,
    )

    // ─── YAML parsing ──────────────────────────────────────────────────────

    @Suppress("UNCHECKED_CAST", "TooGenericExceptionCaught", "LongMethod", "NestedBlockDepth")
    internal fun parseOemPrefixYaml(yamlContent: String): ParsedOemData {
        return try {
            val settings = LoadSettings.builder()
                .setAllowDuplicateKeys(false)
                .setMaxAliasesForCollections(10)
                .build()
            val load = Load(settings)
            val doc = load.loadFromString(yamlContent) as? Map<*, *>
                ?: return ParsedOemData.empty()

            // Parse unconditional section; fall back to legacy flat structure
            // if the new key is absent (forward-compat for remote feeds).
            val unconditionalMap = doc["unconditional"] as? Map<*, *>
                ?: return parseLegacyFlat(doc)
            val unconditionalStrict = mutableSetOf<String>()
            for ((key, value) in unconditionalMap) {
                val keyStr = key.toString()
                if (keyStr == "trusted_installers") continue
                if (value is List<*>) {
                    unconditionalStrict.addAll(value.filterIsInstance<String>())
                }
            }

            // Parse trusted installers
            val installers = (unconditionalMap["trusted_installers"] as? List<*>)
                ?.filterIsInstance<String>()
                ?.filter { it.length >= MIN_INSTALLER_LEN && it.contains('.') }
                ?.take(MAX_INSTALLER_COUNT)
                ?.toSet() ?: emptySet()

            // Parse conditional blocks
            val conditionalMap = doc["conditional"] as? Map<*, *> ?: emptyMap<Any, Any>()
            val conditionalBlocks = mutableListOf<ConditionalBlock>()
            for ((blockKey, blockValue) in conditionalMap) {
                val blockId = blockKey.toString()
                val block = blockValue as? Map<*, *> ?: continue
                val manufacturerMatch = (block["manufacturer_match"] as? List<*>)
                    ?.filterIsInstance<String>()
                    ?.map { it.lowercase() }
                    ?.toSet() ?: emptySet()
                val brandMatch = (block["brand_match"] as? List<*>)
                    ?.filterIsInstance<String>()
                    ?.map { it.lowercase() }
                    ?.toSet() ?: emptySet()
                val strictPrefixes = (block["strict_prefixes"] as? List<*>)
                    ?.filterIsInstance<String>()
                    ?.toSet() ?: emptySet()

                // `partnership_prefixes` is parsed-and-ignored for forward-compat with
                // older bundled/remote YAML that still carries the block — see #147 for
                // why the concept was retired (hand-maintained allowlist produced FPs;
                // known_good_apps.json is the canonical trust anchor).
                if (strictPrefixes.isNotEmpty()) {
                    conditionalBlocks += ConditionalBlock(
                        id = blockId,
                        manufacturerMatch = manufacturerMatch,
                        brandMatch = brandMatch,
                        strictPrefixes = strictPrefixes,
                    )
                }
            }

            ParsedOemData(
                unconditionalStrict = unconditionalStrict,
                conditional = conditionalBlocks,
                trustedInstallers = installers,
            )
        } catch (e: Exception) {
            Log.w(TAG, "Failed to parse OEM prefix YAML: ${e.message}")
            ParsedOemData.empty()
        }
    }

    /**
     * Fallback parser for the legacy flat YAML structure (pre-#90).
     * Every prefix becomes unconditional. Used when a remote feed hasn't
     * been updated to the new structure yet — maintains forward-compat.
     */
    @Suppress("UNCHECKED_CAST")
    private fun parseLegacyFlat(doc: Map<*, *>): ParsedOemData {
        val strictPrefixes = mutableSetOf<String>()
        for ((key, value) in doc) {
            val keyStr = key.toString()
            // Accept any `*_prefixes` list (oem, chipset, partnership, etc.) as
            // unconditional in the legacy flat layout. Partnership semantics were
            // retired in #147 — on the legacy path we can't know device manufacturer
            // so treating them as unconditional is acceptable.
            if (keyStr.endsWith("_prefixes") && value is List<*>) {
                strictPrefixes.addAll(value.filterIsInstance<String>())
            }
        }
        val installers = (doc["trusted_installers"] as? List<*>)
            ?.filterIsInstance<String>()
            ?.filter { it.length >= MIN_INSTALLER_LEN && it.contains('.') }
            ?.take(MAX_INSTALLER_COUNT)
            ?.toSet() ?: emptySet()

        return ParsedOemData(
            unconditionalStrict = strictPrefixes,
            conditional = emptyList(),
            trustedInstallers = installers,
        )
    }

    // ─── HTTP fetch (unchanged) ────────────────────────────────────────────

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
        private const val MAX_PREFIX_COUNT = 500
        private const val MIN_INSTALLER_LEN = 10
    }
}
