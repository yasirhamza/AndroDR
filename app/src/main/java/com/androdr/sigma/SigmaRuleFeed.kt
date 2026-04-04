package com.androdr.sigma

import android.util.Log
import com.androdr.data.repo.SettingsRepository
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.net.HttpURLConnection
import java.net.URL
import java.security.MessageDigest
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
        val failedUrls = mutableListOf<String>()
        for (url in customUrls) {
            val baseUrl = if (url.endsWith("/")) url else "$url/"
            val rules = fetchFromRepo(baseUrl)
            if (rules.isEmpty()) failedUrls.add(url)
            allRules.addAll(rules)
        }

        if (failedUrls.isNotEmpty()) {
            Log.e(TAG, "Failed to fetch from ${failedUrls.size} custom rule URL(s): $failedUrls")
        }
        Log.i(TAG, "Fetched ${allRules.size} remote SIGMA rules from ${1 + customUrls.size} source(s)")
        allRules
    }

    @Suppress("TooGenericExceptionCaught")
    private fun fetchFromRepo(baseUrl: String): List<SigmaRule> {
        val rules = mutableListOf<SigmaRule>()
        try {
            val manifest = fetchUrl("${baseUrl}rules.txt") ?: return emptyList()
            val ruleFiles = parseManifest(manifest)

            val hashManifest = fetchUrl("${baseUrl}rules.sha256")
            val expectedHashes = if (hashManifest != null) parseHashManifest(hashManifest) else emptyMap()

            for (file in ruleFiles) {
                val yaml = fetchUrl("$baseUrl$file") ?: continue
                if (expectedHashes.isNotEmpty()) {
                    val actual = sha256(yaml)
                    val expected = expectedHashes[file]
                    if (expected != null && !actual.equals(expected, ignoreCase = true)) {
                        Log.e(TAG, "Integrity check FAILED for $file: " +
                            "expected=$expected actual=$actual — skipping")
                        continue
                    }
                }
                SigmaRuleParser.parse(yaml)?.let { rules.add(it) }
            }
        } catch (e: Exception) {
            Log.w(TAG, "Failed to fetch rules from $baseUrl: ${e.message}")
        }
        return rules
    }

    @Suppress("TooGenericExceptionCaught")
    private fun fetchUrl(url: String): String? {
        val conn = try {
            URL(url).openConnection() as HttpURLConnection
        } catch (e: Exception) {
            Log.w(TAG, "Failed to open connection to $url: ${e.message}")
            return null
        }
        return try {
            conn.connectTimeout = TIMEOUT_MS
            conn.readTimeout = TIMEOUT_MS
            conn.instanceFollowRedirects = false
            conn.setRequestProperty("User-Agent", "AndroDR/1.0")
            if (conn.responseCode == HttpURLConnection.HTTP_OK) {
                val body = conn.inputStream.bufferedReader().use { it.readText() }
                if (body.length > MAX_RESPONSE_SIZE) {
                    Log.w(TAG, "Response too large: ${body.length} bytes, limit $MAX_RESPONSE_SIZE")
                    null
                } else body
            } else {
                null
            }
        } catch (e: Exception) {
            Log.w(TAG, "HTTP fetch failed for $url: ${e.message}")
            null
        } finally {
            conn.disconnect()
        }
    }

    companion object {
        private const val TAG = "SigmaRuleFeed"
        private const val DEFAULT_BASE_URL =
            "https://raw.githubusercontent.com/android-sigma-rules/rules/main/"
        private const val TIMEOUT_MS = 10_000
        private const val MAX_RESPONSE_SIZE = 500_000 // 500 KB per rule file

        /** Parse a rules.txt manifest into a list of .yml file paths. */
        fun parseManifest(manifest: String): List<String> =
            manifest.lines()
                .map { it.trim() }
                .filter { it.endsWith(".yml") && !it.startsWith("#") }

        /** Parse a rules.sha256 manifest into a map of filename → expected hash. */
        fun parseHashManifest(manifest: String): Map<String, String> =
            manifest.lines()
                .map { it.trim() }
                .filter { it.isNotEmpty() && !it.startsWith("#") }
                .mapNotNull { line ->
                    // Format: sha256hash  filename (two-space separator per sha256sum convention)
                    val parts = line.split("  ", limit = 2)
                    if (parts.size == 2) parts[1] to parts[0] else null
                }
                .toMap()

        private fun sha256(content: String): String {
            val digest = MessageDigest.getInstance("SHA-256")
            return digest.digest(content.toByteArray()).joinToString("") { "%02x".format(it) }
        }
    }
}
