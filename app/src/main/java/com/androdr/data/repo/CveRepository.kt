package com.androdr.data.repo

import android.content.Context
import android.util.Log
import com.androdr.R
import com.androdr.data.db.CveDao
import com.androdr.data.model.CveEntity
import com.androdr.util.BodyTooLargeException
import com.androdr.util.readTextCapped
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject
import java.io.BufferedInputStream
import java.io.IOException
import java.io.InputStream
import java.net.HttpURLConnection
import java.net.URL
import java.util.zip.ZipInputStream
import javax.inject.Inject
import javax.inject.Singleton

@Singleton
class CveRepository @Inject constructor(
    @ApplicationContext private val context: Context,
    private val cveDao: CveDao,
    private val settings: SettingsRepository
) {
    /** Loads bundled CVE snapshot into Room if DB is empty (offline/first-launch). */
    @Suppress("TooGenericExceptionCaught")
    suspend fun loadBundledIfEmpty() = withContext(Dispatchers.IO) {
        if (cveDao.getTotalCount() > 0) return@withContext
        try {
            val raw = context.resources.openRawResource(R.raw.known_exploited_cves)
                .bufferedReader().use { it.readText() }
            val arr = JSONArray(raw)
            val now = System.currentTimeMillis()
            val entries = (0 until arr.length()).map { i ->
                val obj = arr.getJSONObject(i)
                CveEntity(
                    cveId = obj.getString("cveId"),
                    description = obj.optString("description", ""),
                    severity = obj.optString("severity", "CRITICAL"),
                    fixedInPatchLevel = obj.optString("fixedInPatchLevel", ""),
                    cisaDateAdded = obj.optString("cisaDateAdded", ""),
                    isActivelyExploited = obj.optBoolean("isActivelyExploited", true),
                    vendorProject = obj.optString("vendorProject", ""),
                    product = obj.optString("product", ""),
                    lastUpdated = now
                )
            }
            cveDao.upsertAll(entries)
            Log.i(TAG, "Loaded ${entries.size} bundled CVEs")
        } catch (e: Exception) {
            Log.w(TAG, "Failed to load bundled CVEs: ${e.message}")
        }
    }

    /**
     * @return a this-run health signal for feed tracking (#236): >0 when the
     * primary CISA feed was reachable this cycle — either freshly fetched OR a
     * 304 Not-Modified (cache still authoritative) — and 0 when CISA errored
     * (empty). Keyed on CISA (the actively-exploited source), not a standing DB
     * total, so a swallowed HTTP/TLS error can't false-green the feed. OSV is
     * best-effort and does not gate the signal.
     */
    suspend fun refresh(): Int = withContext(Dispatchers.IO) {
        val cisaResult = fetchCisaKev()  // null=304, empty=error, non-empty=fetched
        val osvResult = fetchOsvAndroid()
        // On 304 (null), fall back to cached Room data so the merge preserves enrichment
        val cisaEntries = cisaResult ?: cveDao.getActivelyExploited()
        val osvEntries = osvResult ?: emptyList()
        // CISA reachable this cycle = fetched (non-empty) OR 304 (null). Errored = empty.
        val cisaReachable = cisaResult == null || cisaResult.isNotEmpty()
        if (cisaResult == null && osvResult == null) {
            Log.i(TAG, "CVE refresh: both feeds unchanged (ETag hit)")
            return@withContext if (cisaReachable) cisaEntries.size.coerceAtLeast(1) else 0
        }
        val merged = mergeEntries(cisaEntries, osvEntries)
        if (merged.isNotEmpty()) {
            cveDao.upsertAll(merged)
        }
        Log.i(TAG, "CVE refresh: ${cisaEntries.size} CISA + ${osvEntries.size} OSV → ${merged.size} merged")
        if (cisaReachable) merged.size.coerceAtLeast(1) else 0
    }

    suspend fun getUnpatchedCves(devicePatchLevel: String): List<CveEntity> =
        cveDao.getUnpatchedCves(devicePatchLevel)

    suspend fun getActivelyExploitedCount(): Int =
        cveDao.getActivelyExploitedCount()

    suspend fun getTotalCount(): Int =
        cveDao.getTotalCount()

    /** Returns null on 304 Not Modified, emptyList on error, or the parsed entries on 200. */
    /** [url] is a parameter only so a unit test can point this at a loopback server. */
    @Suppress("TooGenericExceptionCaught")
    internal suspend fun fetchCisaKev(url: String = CISA_KEV_URL): List<CveEntity>? {
        val conn = URL(url).openConnection() as HttpURLConnection
        return try {
            conn.connectTimeout = TIMEOUT_MS
            conn.readTimeout = TIMEOUT_MS
            conn.setRequestProperty("User-Agent", "AndroDR/1.0")
            settings.getEtag(ETAG_CISA)?.let {
                conn.setRequestProperty("If-None-Match", it)
            }
            if (conn.responseCode == HttpURLConnection.HTTP_NOT_MODIFIED) {
                Log.i(TAG, "CISA KEV not modified (ETag hit)")
                return null
            }
            if (conn.responseCode != HttpURLConnection.HTTP_OK) {
                Log.w(TAG, "CISA KEV fetch failed: HTTP ${conn.responseCode}")
                return emptyList()
            }
            val body = conn.inputStream.bufferedReader().use { it.readTextCapped(MAX_KEV_CHARS) }
            val json = JSONObject(body)
            val vulnerabilities = json.getJSONArray("vulnerabilities")
            val now = System.currentTimeMillis()
            val entries = mutableListOf<CveEntity>()
            for (i in 0 until vulnerabilities.length()) {
                val vuln = vulnerabilities.getJSONObject(i)
                val vendor = vuln.optString("vendorProject", "").lowercase()
                val product = vuln.optString("product", "").lowercase()
                if (vendor.contains("android") || vendor.contains("google") ||
                    product.contains("android") || product.contains("chromium")) {
                    entries.add(CveEntity(
                        cveId = vuln.getString("cveID"),
                        description = vuln.optString("shortDescription", "Actively exploited vulnerability").take(500),
                        severity = "CRITICAL",
                        fixedInPatchLevel = "",
                        cisaDateAdded = vuln.optString("dateAdded", ""),
                        isActivelyExploited = true,
                        vendorProject = vuln.optString("vendorProject", ""),
                        product = vuln.optString("product", ""),
                        lastUpdated = now
                    ))
                }
            }
            // Only a body that parsed to rows is remembered as current (same rule as OSV
            // below): an empty result is reported as errored this cycle and must not 304
            // green on the next.
            if (entries.isNotEmpty()) conn.getHeaderField("ETag")?.let { settings.setEtag(ETAG_CISA, it) }
            entries
        } catch (e: Exception) {
            Log.w(TAG, "CISA KEV fetch failed: ${e.message}")
            emptyList()
        } finally {
            conn.disconnect()
        }
    }

    /**
     * Returns null on 304 Not Modified, emptyList on error, or the parsed entries on 200.
     *
     * [url] and [maxEntryChars] are parameters only so a unit test can point this
     * at a local server and a small cap; production callers use the defaults.
     */
    @Suppress("TooGenericExceptionCaught")
    internal suspend fun fetchOsvAndroid(
        url: String = OSV_ANDROID_URL,
        maxEntryChars: Int = MAX_OSV_ENTRY_CHARS,
    ): List<CveEntity>? {
        val conn = URL(url).openConnection() as HttpURLConnection
        return try {
            conn.connectTimeout = TIMEOUT_MS
            conn.readTimeout = TIMEOUT_MS
            conn.setRequestProperty("User-Agent", "AndroDR/1.0")
            settings.getEtag(ETAG_OSV)?.let {
                conn.setRequestProperty("If-None-Match", it)
            }
            if (conn.responseCode == HttpURLConnection.HTTP_NOT_MODIFIED) {
                Log.i(TAG, "OSV Android not modified (ETag hit)")
                return null
            }
            if (conn.responseCode != HttpURLConnection.HTTP_OK) {
                Log.w(TAG, "OSV fetch failed: HTTP ${conn.responseCode}")
                return emptyList()
            }
            val entries = readOsvZip(BufferedInputStream(conn.inputStream), System.currentTimeMillis(), maxEntryChars)
            // Only a zip that parsed to real rows is remembered as current (PASTA
            // F-005): storing the ETag first cached a bomb or a truncated body as
            // Not-Modified, so every later cycle would 304 against poison; a zip that
            // parses to nothing is not worth 304-ing against either.
            if (entries.isNotEmpty()) conn.getHeaderField("ETag")?.let { settings.setEtag(ETAG_OSV, it) }
            entries
        } catch (e: Exception) {
            Log.w(TAG, "OSV Android fetch failed: ${e.message}")
            emptyList()
        } finally {
            conn.disconnect()
        }
    }

    companion object {
        private const val TAG = "CveRepository"
        private const val CISA_KEV_URL =
            "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
        // storage.googleapis.com is intentionally NOT certificate-pinned: Google
        // serves it from many POPs with varying cert chains, so any pin breaks
        // per-device. Do not "fix" an OSV TLS failure by adding a pin — see the
        // rationale in res/xml/network_security_config.xml.
        private const val OSV_ANDROID_URL =
            "https://osv-vulnerabilities.storage.googleapis.com/Android/all.zip"
        private const val TIMEOUT_MS = 30_000
        private const val ETAG_CISA = "cve_cisa"
        private const val ETAG_OSV = "cve_osv"

        /**
         * Inflation caps for the OSV zip (PASTA F-005). The feed comes from an
         * unpinned host and is inflated into memory entry by entry, so a
         * high-ratio bomb was a memory DoS. These bound UNBOUNDED input; they are
         * not a heap budget -- a body just under a cap is still that large.
         *  - Per entry: an over-cap entry is skipped (not fatal), so this only needs
         *    to clear the largest real entry (4.18 MiB, 2026-11-06) and small enough
         *    that one hostile entry's StringBuilder stays well inside a 256 MB heap.
         *  - Total: the abort. >= 4x over the live feed (35.6 MiB inflated, 4,073
         *    entries) -- a tight cap would abort every cycle and silently stop CVE
         *    enrichment, the failure this app most needs to avoid.
         * CveRepositoryOsvFetchTest pins both headrooms.
         */
        internal const val MAX_OSV_ENTRY_CHARS = 8 * 1024 * 1024
        internal const val MAX_OSV_TOTAL_CHARS = 256L * 1024 * 1024
        /** CISA KEV JSON (live 1.8 MB, 2026-11). Bounds unbounded input; see MAX_OSV_ENTRY_CHARS. */
        private const val MAX_KEV_CHARS = 16 * 1024 * 1024
        private val PATCH_DATE = Regex("""\d{4}-\d{2}-\d{2}""")

        /**
         * Inflates every `.json` entry of an OSV zip into [CveEntity] rows, with a
         * per-entry and a total cap on inflated characters.
         *
         * @throws IOException when an entry, or all entries together, inflate past
         *   the cap — the fetch's catch turns that into "nothing fetched".
         */
        internal fun readOsvZip(
            input: InputStream,
            now: Long,
            maxEntryChars: Int = MAX_OSV_ENTRY_CHARS,
            maxTotalChars: Long = MAX_OSV_TOTAL_CHARS,
        ): List<CveEntity> {
            val entries = mutableListOf<CveEntity>()
            var total = 0L
            ZipInputStream(input).use { zis ->
                var entry = zis.nextEntry
                while (entry != null) {
                    if (entry.name.endsWith(".json")) {
                        // An over-cap entry is skipped, not fatal: one odd entry must not
                        // stop the feed. It still counts its cap toward the total, so N
                        // oversized entries are not free. (nextEntry drains the rest.)
                        val content = try {
                            zis.bufferedReader().readTextCapped(maxEntryChars)
                        } catch (e: BodyTooLargeException) {
                            Log.w(TAG, "OSV entry ${entry.name} skipped: ${e.message}")
                            total += maxEntryChars
                            null
                        }
                        total += content?.length ?: 0
                        if (total > maxTotalChars) {
                            throw IOException("OSV zip inflates past $maxTotalChars chars in total")
                        }
                        content?.let { c -> parseOsvEntry(c, now)?.let { entries.add(it) } }
                    }
                    entry = zis.nextEntry
                }
            }
            return entries
        }

        // Parsing function uses early returns for invalid data and nested loops for JSON traversal
        @Suppress("TooGenericExceptionCaught", "ReturnCount", "NestedBlockDepth", "SwallowedException")
        private fun parseOsvEntry(json: String, now: Long): CveEntity? {
            return try {
                val obj = JSONObject(json)
                val id = obj.optString("id", "")
                if (!id.startsWith("CVE-") && !id.startsWith("A-")) return null
                val aliases = obj.optJSONArray("aliases")
                val cveId = if (id.startsWith("CVE-")) id
                else (0 until (aliases?.length() ?: 0))
                    .map { aliases!!.getString(it) }
                    .firstOrNull { it.startsWith("CVE-") } ?: return null
                val summary = obj.optString("summary", obj.optString("details", ""))
                val severity = obj.optJSONArray("severity")?.let { sevArr ->
                    (0 until sevArr.length()).map { sevArr.getJSONObject(it) }
                        .firstOrNull { it.optString("type") == "CVSS_V3" }
                        ?.optString("score", "")
                }?.let { cvssToSeverity(it) } ?: "MEDIUM"
                var fixedPatchLevel = ""
                val affected = obj.optJSONArray("affected")
                if (affected != null && affected.length() > 0) {
                    for (i in 0 until affected.length()) {
                        val aff = affected.getJSONObject(i)
                        val ranges = aff.optJSONArray("ranges") ?: continue
                        for (j in 0 until ranges.length()) {
                            val range = ranges.getJSONObject(j)
                            val events = range.optJSONArray("events") ?: continue
                            for (k in 0 until events.length()) {
                                val event = events.getJSONObject(k)
                                val fixed = event.optString("fixed", "")
                                if (fixed.matches(PATCH_DATE)) {
                                    fixedPatchLevel = fixed
                                }
                            }
                        }
                    }
                }
                if (fixedPatchLevel.isEmpty()) return null
                CveEntity(
                    cveId = cveId, description = summary.take(500), severity = severity,
                    fixedInPatchLevel = fixedPatchLevel, cisaDateAdded = "",
                    isActivelyExploited = false, vendorProject = "Google", product = "Android",
                    lastUpdated = now
                )
            } catch (e: Exception) { null }
        }

        private fun cvssToSeverity(cvssScore: String): String {
            val score = cvssScore.substringBefore("/").toDoubleOrNull()
                ?: cvssScore.toDoubleOrNull() ?: return "MEDIUM"
            return when {
                score >= 9.0 -> "CRITICAL"
                score >= 7.0 -> "HIGH"
                score >= 4.0 -> "MEDIUM"
                else -> "LOW"
            }
        }

        fun mergeEntries(cisaEntries: List<CveEntity>, osvEntries: List<CveEntity>): List<CveEntity> {
            val now = System.currentTimeMillis()
            val osvByCveId = osvEntries.associateBy { it.cveId }
            val cisaByCveId = cisaEntries.associateBy { it.cveId }
            val allCveIds = cisaByCveId.keys + osvByCveId.keys
            return allCveIds.map { cveId ->
                val cisa = cisaByCveId[cveId]
                val osv = osvByCveId[cveId]
                when {
                    cisa != null && osv != null -> CveEntity(
                        cveId = cveId,
                        description = cisa.description.ifEmpty { osv.description },
                        severity = osv.severity,
                        fixedInPatchLevel = osv.fixedInPatchLevel,
                        cisaDateAdded = cisa.cisaDateAdded,
                        isActivelyExploited = true,
                        vendorProject = cisa.vendorProject,
                        product = cisa.product,
                        lastUpdated = now
                    )
                    cisa != null -> cisa.copy(fixedInPatchLevel = cisa.cisaDateAdded, lastUpdated = now)
                    osv != null -> osv.copy(lastUpdated = now)
                    else -> error("Unreachable")
                }
            }
        }
    }
}
