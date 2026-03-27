package com.androdr.data.repo

import android.util.Log
import com.androdr.data.db.CveDao
import com.androdr.data.model.CveEntity
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.io.BufferedInputStream
import java.net.HttpURLConnection
import java.net.URL
import java.util.zip.ZipInputStream
import javax.inject.Inject
import javax.inject.Singleton

@Singleton
class CveRepository @Inject constructor(
    private val cveDao: CveDao
) {
    suspend fun refresh() = withContext(Dispatchers.IO) {
        val cisaEntries = fetchCisaKev()
        val osvEntries = fetchOsvAndroid()
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

    @Suppress("TooGenericExceptionCaught")
    private fun fetchCisaKev(): List<CveEntity> {
        return try {
            val conn = URL(CISA_KEV_URL).openConnection() as HttpURLConnection
            conn.connectTimeout = TIMEOUT_MS
            conn.readTimeout = TIMEOUT_MS
            conn.setRequestProperty("User-Agent", "AndroDR/1.0")
            if (conn.responseCode != HttpURLConnection.HTTP_OK) {
                Log.w(TAG, "CISA KEV fetch failed: HTTP ${conn.responseCode}")
                return emptyList()
            }
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
        }
    }

    @Suppress("TooGenericExceptionCaught", "NestedBlockDepth")
    private fun fetchOsvAndroid(): List<CveEntity> {
        return try {
            val conn = URL(OSV_ANDROID_URL).openConnection() as HttpURLConnection
            conn.connectTimeout = TIMEOUT_MS
            conn.readTimeout = TIMEOUT_MS
            conn.setRequestProperty("User-Agent", "AndroDR/1.0")
            if (conn.responseCode != HttpURLConnection.HTTP_OK) {
                Log.w(TAG, "OSV fetch failed: HTTP ${conn.responseCode}")
                return emptyList()
            }
            val now = System.currentTimeMillis()
            val entries = mutableListOf<CveEntity>()
            val zis = ZipInputStream(BufferedInputStream(conn.inputStream))
            var entry = zis.nextEntry
            while (entry != null) {
                if (entry.name.endsWith(".json")) {
                    val content = zis.bufferedReader().use { it.readText() }
                    parseOsvEntry(content, now)?.let { entries.add(it) }
                }
                entry = zis.nextEntry
            }
            zis.close()
            entries
        } catch (e: Exception) {
            Log.w(TAG, "OSV Android fetch failed: ${e.message}")
            emptyList()
        }
    }

    @Suppress("TooGenericExceptionCaught")
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
