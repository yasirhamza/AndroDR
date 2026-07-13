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

        // Default public repo — manifest REQUIRED (fail closed if absent).
        allRules.addAll(fetchFromRepo(DEFAULT_BASE_URL, requireManifest = true))

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
            // Custom feeds are user-chosen and may not ship a hash manifest; stay lenient.
            val rules = fetchFromRepo(baseUrl, requireManifest = false)
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
    private fun fetchFromRepo(baseUrl: String, requireManifest: Boolean): List<SigmaRule> {
        val rules = mutableListOf<SigmaRule>()
        try {
            val manifest = fetchUrl("${baseUrl}rules.txt") ?: return emptyList()
            val ruleFiles = parseManifest(manifest)

            val hashManifest = fetchUrl("${baseUrl}rules.sha256")
            val expectedHashes = if (hashManifest != null) parseHashManifest(hashManifest) else emptyMap()
            // Fail CLOSED for the trusted default repo: no usable hash manifest means
            // we cannot verify integrity, so we ship nothing rather than accept
            // unverified rules. This covers BOTH a missing/unfetchable rules.sha256
            // AND a present-but-unparseable one (an attacker who can tamper with the
            // channel could otherwise drop OR corrupt rules.sha256 to disable the
            // check — a corrupt manifest parses to an empty map, so guard on that).
            if (expectedHashes.isEmpty() && requireManifest) {
                Log.e(TAG, "No usable hash manifest (rules.sha256) for $baseUrl — " +
                    "refusing to load unverified rules (fail closed)")
                return emptyList()
            }

            for (file in ruleFiles) {
                val yaml = fetchUrl("$baseUrl$file") ?: continue
                when (val decision = decideRuleFile(file, yaml, expectedHashes, requireManifest)) {
                    is RuleFileDecision.Accept -> SigmaRuleParser.parse(yaml)?.let { rules.add(it) }
                    is RuleFileDecision.Skip -> Log.e(TAG, decision.reason)
                }
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

    /** Outcome of the per-file integrity decision. */
    sealed interface RuleFileDecision {
        object Accept : RuleFileDecision
        data class Skip(val reason: String) : RuleFileDecision
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

        /**
         * Pure integrity decision for a single fetched rule file. Kept separate
         * from the network glue so the fail-closed behaviour is unit-tested.
         *
         * Three cases:
         *  1. File has a hash in the map → content must match it (else Skip),
         *     independent of [requireManifest].
         *  2. File is not in the map — either the map is empty (missing or corrupt
         *     rules.sha256) or the manifest lists other files but not this one →
         *     Skip when [requireManifest] (default repo: unverified is untrusted),
         *     Accept when not (custom feeds may ship no manifest at all).
         *
         * fetchFromRepo additionally aborts the whole repo up front when the map
         * is empty and a manifest is required; this function stays correct on its
         * own regardless of that caller guard.
         */
        fun decideRuleFile(
            file: String,
            yaml: String,
            expectedHashes: Map<String, String>,
            requireManifest: Boolean,
        ): RuleFileDecision {
            val expected = expectedHashes[file]
            if (expected == null) {
                return if (requireManifest) {
                    RuleFileDecision.Skip("No verified hash for $file — skipping (fail closed)")
                } else {
                    RuleFileDecision.Accept
                }
            }
            val actual = sha256(yaml)
            return if (actual.equals(expected, ignoreCase = true)) {
                RuleFileDecision.Accept
            } else {
                RuleFileDecision.Skip(
                    "Integrity check FAILED for $file: expected=$expected actual=$actual — skipping",
                )
            }
        }
    }
}
