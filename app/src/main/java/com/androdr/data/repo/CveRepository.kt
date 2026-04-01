package com.androdr.data.repo

import android.content.Context
import android.util.Log
import com.androdr.R
import com.androdr.data.db.CveDao
import com.androdr.data.model.CveEntity
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject
import java.io.BufferedInputStream
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

    suspend fun refresh() = withContext(Dispatchers.IO) {
        val cisaResult = fetchCisaKev()
        val osvResult = fetchOsvAndroid()
        // On 304 (null), fall back to cached Room data so the merge preserves enrichment
        val cisaEntries = cisaResult ?: cveDao.getActivelyExploited()
        val osvEntries = osvResult ?: emptyList()
        if (cisaResult == null && osvResult == null) {
            Log.i(TAG, "CVE refresh: both feeds unchanged (ETag hit)")
            return@withContext
        }
        val merged = mergeEntries(cisaEntries, osvEntries)
        if (merged.isNotEmpty()) {
            cveDao.upsertAll(merged)
        }
        Log.i(TAG, "CVE refresh: ${cisaEntries.size} CISA + ${osvEntries.size} OSV → ${merged.size} merged")
    }

    suspend fun getUnpatchedCves(devicePatchLevel: String): List<CveEntity> =
        cveDao.getUnpatchedCves(devicePatchLevel)

    suspend fun getActivelyExploitedCount(): Int =
        cveDao.getActivelyExploitedCount()

    suspend fun getTotalCount(): Int =
        cveDao.getTotalCount()

    /** Returns null on 304 Not Modified, emptyList on error, or the parsed entries on 200. */
    @Suppress("TooGenericExceptionCaught")
    private suspend fun fetchCisaKev(): List<CveEntity>? {
        val conn = URL(CISA_KEV_URL).openConnection() as HttpURLConnection
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
            conn.getHeaderField("ETag")?.let { settings.setEtag(ETAG_CISA, it) }
            val body = conn.inputStream.bufferedReader().use { it.readText() }
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
            entries
        } catch (e: Exception) {
            Log.w(TAG, "CISA KEV fetch failed: ${e.message}")
            emptyList()
        } finally {
            conn.disconnect()
        }
    }

    /** Returns null on 304 Not Modified, emptyList on error, or the parsed entries on 200. */
    @Suppress("TooGenericExceptionCaught", "NestedBlockDepth")
    private suspend fun fetchOsvAndroid(): List<CveEntity>? {
        val conn = URL(OSV_ANDROID_URL).openConnection() as HttpURLConnection
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
            conn.getHeaderField("ETag")?.let { settings.setEtag(ETAG_OSV, it) }
            val now = System.currentTimeMillis()
            val entries = mutableListOf<CveEntity>()
            ZipInputStream(BufferedInputStream(conn.inputStream)).use { zis ->
                var entry = zis.nextEntry
                while (entry != null) {
                    if (entry.name.endsWith(".json")) {
                        val content = zis.bufferedReader().use { it.readText() }
                        parseOsvEntry(content, now)?.let { entries.add(it) }
                    }
                    entry = zis.nextEntry
                }
            }
            entries
        } catch (e: Exception) {
            Log.w(TAG, "OSV Android fetch failed: ${e.message}")
            emptyList()
        } finally {
            conn.disconnect()
        }
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
                            if (fixed.matches(Regex("""\d{4}-\d{2}-\d{2}"""))) {
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

    companion object {
        private const val TAG = "CveRepository"
        private const val CISA_KEV_URL =
            "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
        private const val OSV_ANDROID_URL =
            "https://osv-vulnerabilities.storage.googleapis.com/Android/all.zip"
        private const val TIMEOUT_MS = 30_000
        private const val ETAG_CISA = "cve_cisa"
        private const val ETAG_OSV = "cve_osv"

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
