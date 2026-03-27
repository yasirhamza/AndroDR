package com.androdr.ioc

import android.util.Log
import com.androdr.data.model.CveEntry
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URL
import java.time.LocalDate
import java.time.format.DateTimeFormatter
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Fetches the CISA Known Exploited Vulnerabilities (KEV) catalog and provides
 * patch-level-aware filtering to identify CVEs that are unpatched on a given device.
 *
 * Each CVE entry includes a `dateAdded` field indicating when CISA added it to the
 * catalog. CVEs added after the device's security patch level date are considered
 * unpatched — the device was not protected when the exploit was publicly known.
 */
@Singleton
class CveDatabase @Inject constructor() {

    @Volatile
    private var androidCveEntries: List<CveEntry> = emptyList()

    suspend fun refresh() = withContext(Dispatchers.IO) {
        fetchCisaKev()
        Log.i(TAG, "CVE database refreshed: ${androidCveEntries.size} Android CVEs from CISA KEV")
    }

    /**
     * Returns CVEs that are unpatched on a device with the given [devicePatchLevel].
     * A CVE is considered unpatched if its CISA dateAdded is AFTER the device's patch level,
     * meaning the device was not patched when the exploit became publicly known.
     */
    @Suppress("TooGenericExceptionCaught", "SwallowedException")
    fun getUnpatchedCves(devicePatchLevel: String): List<CveEntry> {
        if (androidCveEntries.isEmpty()) return emptyList()

        val deviceDate = try {
            LocalDate.parse(devicePatchLevel, DATE_FORMATTER)
        } catch (e: Exception) {
            Log.w(TAG, "Cannot parse device patch level '$devicePatchLevel': ${e.message}")
            return emptyList()
        }

        return androidCveEntries.filter { cve ->
            try {
                val cveDate = LocalDate.parse(cve.patchLevel, DATE_FORMATTER)
                cveDate.isAfter(deviceDate)
            } catch (e: Exception) {
                false
            }
        }
    }

    fun getActivelyExploitedCount(): Int = androidCveEntries.size

    @Suppress("TooGenericExceptionCaught")
    private fun fetchCisaKev() {
        try {
            val conn = URL(CISA_KEV_URL).openConnection() as HttpURLConnection
            conn.connectTimeout = TIMEOUT_MS
            conn.readTimeout = TIMEOUT_MS
            conn.setRequestProperty("User-Agent", "AndroDR/1.0")

            if (conn.responseCode != HttpURLConnection.HTTP_OK) {
                Log.w(TAG, "CISA KEV fetch failed: HTTP ${conn.responseCode}")
                return
            }

            val body = conn.inputStream.bufferedReader().use { it.readText() }
            val json = JSONObject(body)
            val vulnerabilities = json.getJSONArray("vulnerabilities")

            val entries = mutableListOf<CveEntry>()
            for (i in 0 until vulnerabilities.length()) {
                val vuln = vulnerabilities.getJSONObject(i)
                val vendor = vuln.optString("vendorProject", "").lowercase()
                val product = vuln.optString("product", "").lowercase()

                if (vendor.contains("android") || vendor.contains("google") ||
                    product.contains("android") || product.contains("chromium")
                ) {
                    entries.add(
                        CveEntry(
                            cveId = vuln.getString("cveID"),
                            severity = "CRITICAL",
                            description = vuln.optString(
                                "shortDescription",
                                "Actively exploited vulnerability"
                            ),
                            patchLevel = vuln.optString("dateAdded", ""),
                            isActivelyExploited = true
                        )
                    )
                }
            }

            androidCveEntries = entries
        } catch (e: Exception) {
            Log.w(TAG, "CISA KEV fetch failed: ${e.message}")
        }
    }

    companion object {
        private const val TAG = "CveDatabase"
        private const val CISA_KEV_URL =
            "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
        private const val TIMEOUT_MS = 15_000
        private val DATE_FORMATTER = DateTimeFormatter.ofPattern("yyyy-MM-dd")
    }
}
