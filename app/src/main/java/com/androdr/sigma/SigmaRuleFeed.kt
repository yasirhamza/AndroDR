package com.androdr.sigma

import android.util.Log
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.net.HttpURLConnection
import java.net.URL
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Fetches SIGMA rules from the public android-sigma-rules/rules GitHub repo.
 * Returns parsed rules that can be merged into [SigmaRuleEngine] via [setRemoteRules].
 */
@Singleton
class SigmaRuleFeed @Inject constructor() {

    @Suppress("TooGenericExceptionCaught")
    suspend fun fetch(): List<SigmaRule> = withContext(Dispatchers.IO) {
        val rules = mutableListOf<SigmaRule>()
        try {
            val manifest = fetchUrl(MANIFEST_URL) ?: return@withContext emptyList()
            val ruleFiles = manifest.lines()
                .map { it.trim() }
                .filter { it.endsWith(".yml") }

            for (file in ruleFiles) {
                val yaml = fetchUrl("$BASE_URL$file") ?: continue
                SigmaRuleParser.parse(yaml)?.let { rules.add(it) }
            }
            Log.i(TAG, "Fetched ${rules.size} remote SIGMA rules")
        } catch (e: Exception) {
            Log.w(TAG, "Failed to fetch remote SIGMA rules: ${e.message}")
        }
        rules
    }

    @Suppress("TooGenericExceptionCaught")
    private fun fetchUrl(url: String): String? {
        return try {
            val conn = URL(url).openConnection() as HttpURLConnection
            conn.connectTimeout = TIMEOUT_MS
            conn.readTimeout = TIMEOUT_MS
            if (conn.responseCode == HttpURLConnection.HTTP_OK) {
                conn.inputStream.bufferedReader().use { it.readText() }
            } else {
                null
            }
        } catch (e: Exception) {
            Log.w(TAG, "HTTP fetch failed for $url: ${e.message}")
            null
        }
    }

    companion object {
        private const val TAG = "SigmaRuleFeed"
        private const val BASE_URL =
            "https://raw.githubusercontent.com/android-sigma-rules/rules/main/"
        private const val MANIFEST_URL = "${BASE_URL}rules.txt"
        private const val TIMEOUT_MS = 10_000
    }
}
