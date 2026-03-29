package com.androdr.ioc

import android.util.Log
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
class OemPrefixResolver @Inject constructor() {

    private val prefixes = AtomicReference<Set<String>>(BUNDLED_PREFIXES)
    private val installers = AtomicReference<Set<String>>(BUNDLED_INSTALLERS)

    fun isOemPrefix(packageName: String): Boolean =
        prefixes.get().any { packageName.startsWith(it) }

    fun isTrustedInstaller(installer: String): Boolean =
        installer in installers.get() || isOemPrefix(installer)

    /**
     * Fetches the latest OEM prefix list from the public rules repo.
     * On success, replaces the in-memory cache. On failure, keeps existing data.
     */
    @Suppress("TooGenericExceptionCaught")
    suspend fun refresh() = withContext(Dispatchers.IO) {
        try {
            val yaml = fetchUrl(PREFIXES_URL) ?: return@withContext
            val parsed = parseOemPrefixYaml(yaml)
            if (parsed.prefixes.isNotEmpty()) {
                prefixes.set(parsed.prefixes)
                Log.i(TAG, "OEM prefixes refreshed: ${parsed.prefixes.size} prefixes")
            }
            if (parsed.installers.isNotEmpty()) {
                installers.set(parsed.installers)
                Log.i(TAG, "Trusted installers refreshed: ${parsed.installers.size} installers")
            }
        } catch (e: Exception) {
            Log.w(TAG, "OEM prefix refresh failed: ${e.message}")
        }
    }

    internal data class ParsedOemData(
        val prefixes: Set<String>,
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
                ?: return ParsedOemData(emptySet(), emptySet())

            // Collect all prefix lists (any key ending in _prefixes)
            val allPrefixes = mutableSetOf<String>()
            for ((key, value) in doc) {
                if (key.toString().endsWith("_prefixes") && value is List<*>) {
                    value.filterIsInstance<String>().forEach { allPrefixes.add(it) }
                }
            }

            // Collect trusted installers
            val installerList = (doc["trusted_installers"] as? List<*>)
                ?.filterIsInstance<String>()?.toSet() ?: emptySet()

            ParsedOemData(allPrefixes, installerList)
        } catch (e: Exception) {
            Log.w(TAG, "Failed to parse OEM prefix YAML: ${e.message}")
            ParsedOemData(emptySet(), emptySet())
        }
    }

    @Suppress("TooGenericExceptionCaught")
    private fun fetchUrl(url: String): String? {
        val conn = try {
            URL(url).openConnection() as HttpURLConnection
        } catch (e: Exception) { return null }
        return try {
            conn.connectTimeout = TIMEOUT_MS
            conn.readTimeout = TIMEOUT_MS
            conn.setRequestProperty("User-Agent", "AndroDR/1.0")
            if (conn.responseCode == HttpURLConnection.HTTP_OK) {
                conn.inputStream.bufferedReader().use { it.readText() }
            } else null
        } catch (e: Exception) { null }
        finally { conn.disconnect() }
    }

    companion object {
        private const val TAG = "OemPrefixResolver"
        private const val PREFIXES_URL =
            "https://raw.githubusercontent.com/android-sigma-rules/rules/main/ioc-data/known-oem-prefixes.yml"
        private const val TIMEOUT_MS = 10_000

        // Bundled fallback — used before first remote fetch succeeds
        private val BUNDLED_PREFIXES = setOf(
            "com.android.", "com.google.", "android",
            "com.qualcomm.", "com.qti.", "vendor.qti.",
            "com.mediatek.", "com.mtk.",
            "com.bsp.", "com.wingtech.", "com.longcheer.",
            "com.samsung.", "com.sec.", "com.osp.", "com.knox.",
            "com.skms.", "com.mygalaxy.", "com.monotype.", "com.hiya.",
            "com.sem.", "com.swiftkey.",
            "com.wsomacp", "com.wssyncmldm",
            "com.microsoft.", "com.touchtype.", "com.facebook.",
            "com.miui.", "com.xiaomi.", "com.mi.",
            "com.duokan.", "com.mipay.",
            "com.tmobile.", "com.sprint.",
            "com.att.", "com.vzw.", "com.verizon.",
            "com.dti.",
            "com.amazon.",
            "com.motorola.", "com.oneplus.", "com.lge.",
            "com.htc.", "com.sony.", "com.huawei.", "com.asus.",
            "com.oppo.", "com.realme.", "com.vivo.",
            "com.coloros.", "com.heytap.", "com.oplus.",
            "org.lineageos.", "com.cyanogenmod."
        )

        private val BUNDLED_INSTALLERS = setOf(
            "com.android.vending",
            "com.sec.android.app.samsungapps",
            "com.xiaomi.market",
            "com.xiaomi.mipicks",
            "com.miui.packageinstaller",
            "com.heytap.market",
            "com.coloros.safecenter",
            "com.huawei.appmarket",
            "com.bbk.appstore"
        )
    }
}
