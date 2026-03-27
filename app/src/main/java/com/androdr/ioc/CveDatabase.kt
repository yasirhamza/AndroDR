package com.androdr.ioc

import android.util.Log
import com.androdr.data.model.CveEntry
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URL
import javax.inject.Inject
import javax.inject.Singleton

@Singleton
class CveDatabase @Inject constructor() {

    private var activelyExploitedCves: Set<String> = emptySet()

    suspend fun refresh() = withContext(Dispatchers.IO) {
        fetchCisaKev()
        Log.i(TAG, "CVE database refreshed: ${activelyExploitedCves.size} actively exploited Android CVEs")
    }

    fun getUnpatchedCves(devicePatchLevel: String): List<CveEntry> {
        Log.d(TAG, "Checking CVEs for device patch level: $devicePatchLevel")
        return activelyExploitedCves.map { cveId ->
            CveEntry(
                cveId = cveId,
                severity = "CRITICAL",
                description = "Actively exploited vulnerability (CISA KEV)",
                patchLevel = "",
                isActivelyExploited = true
            )
        }
    }

    fun getActivelyExploitedCount(): Int = activelyExploitedCves.size

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

            val androidCves = mutableSetOf<String>()
            for (i in 0 until vulnerabilities.length()) {
                val vuln = vulnerabilities.getJSONObject(i)
                val vendor = vuln.optString("vendorProject", "").lowercase()
                val product = vuln.optString("product", "").lowercase()
                if (vendor.contains("android") || vendor.contains("google") ||
                    product.contains("android") || product.contains("chromium")
                ) {
                    androidCves.add(vuln.getString("cveID"))
                }
            }

            activelyExploitedCves = androidCves
        } catch (e: Exception) {
            Log.w(TAG, "CISA KEV fetch failed: ${e.message}")
        }
    }

    companion object {
        private const val TAG = "CveDatabase"
        private const val CISA_KEV_URL =
            "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
        private const val TIMEOUT_MS = 15_000
    }
}
