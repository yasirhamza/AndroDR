package com.androdr.sigma

import android.util.Log
import com.androdr.data.repo.SettingsRepository
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.net.HttpURLConnection
import java.net.URL
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Fetches SIGMA rules from the default public repo and any custom rule URLs
 * configured in settings. Returns parsed rules for [SigmaRuleEngine.setRemoteRules].
 */
@Singleton
class SigmaRuleFeed @Inject constructor(
    private val settingsRepository: SettingsRepository
) {

    @Suppress("TooGenericExceptionCaught")
    suspend fun fetch(): List<SigmaRule> = withContext(Dispatchers.IO) {
        val allRules = mutableListOf<SigmaRule>()

        // Default public repo
        allRules.addAll(fetchFromRepo(DEFAULT_BASE_URL))

        // Custom rule URLs from settings
        @Suppress("TooGenericExceptionCaught", "SwallowedException")
        val customUrls = try {
            settingsRepository.getCustomRuleUrlsList()
        } catch (e: Exception) {
            Log.w(TAG, "Failed to read custom rule URLs: ${e.message}")
            emptyList()
        }
        for (url in customUrls) {
            val baseUrl = if (url.endsWith("/")) url else "$url/"
            allRules.addAll(fetchFromRepo(baseUrl))
        }

        Log.i(TAG, "Fetched ${allRules.size} remote SIGMA rules from ${1 + customUrls.size} source(s)")
        allRules
    }

    @Suppress("TooGenericExceptionCaught")
    private fun fetchFromRepo(baseUrl: String): List<SigmaRule> {
        val rules = mutableListOf<SigmaRule>()
        try {
            val manifest = fetchUrl("${baseUrl}rules.txt") ?: return emptyList()
            val ruleFiles = manifest.lines()
                .map { it.trim() }
                .filter { it.endsWith(".yml") }

            for (file in ruleFiles) {
                val yaml = fetchUrl("$baseUrl$file") ?: continue
                SigmaRuleParser.parse(yaml)?.let { rules.add(it) }
            }
        } catch (e: Exception) {
            Log.w(TAG, "Failed to fetch rules from $baseUrl: ${e.message}")
        }
        return rules
    }

    @Suppress("TooGenericExceptionCaught")
    private fun fetchUrl(url: String): String? {
        return try {
            val conn = URL(url).openConnection() as HttpURLConnection
            conn.connectTimeout = TIMEOUT_MS
            conn.readTimeout = TIMEOUT_MS
            conn.setRequestProperty("User-Agent", "AndroDR/1.0")
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
        private const val DEFAULT_BASE_URL =
            "https://raw.githubusercontent.com/android-sigma-rules/rules/main/"
        private const val TIMEOUT_MS = 10_000
    }
}
