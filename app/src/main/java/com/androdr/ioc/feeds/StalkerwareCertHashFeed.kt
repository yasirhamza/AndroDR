package com.androdr.ioc.feeds

import android.util.Log
import com.androdr.data.model.CertHashIocEntry
import com.androdr.ioc.CertHashIocFeed
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.net.HttpURLConnection
import java.net.URL

/**
 * Fetches signing-certificate SHA-1 IOCs from the community-maintained
 * AssoEchap/stalkerware-indicators GitHub repository, companion to
 * [StalkerwareIndicatorsFeed] (which consumes the `packages:` field).
 *
 * `ioc.yaml` entries carry a `certificates:` list of 40-char hex SHA-1
 * fingerprints of the dev's signing certificate — stable across stalkerware
 * versions and therefore a stronger pivot than package names. MVT and other
 * mobile-forensics tooling converge on SHA-1 cert matching (see #151).
 *
 *   - name: TheTruthSpy
 *     type: stalkerware
 *     certificates:
 *     - 31A6ECECD97CF39BC4126B8745CD94A7C30BF81C
 *     - ...
 */
class StalkerwareCertHashFeed : CertHashIocFeed {

    override val sourceId = SOURCE_ID

    @Suppress("TooGenericExceptionCaught")
    override suspend fun fetch(): List<CertHashIocEntry> = withContext(Dispatchers.IO) {
        try {
            val connection = (URL(YAML_URL).openConnection() as HttpURLConnection).apply {
                connectTimeout = 15_000
                readTimeout = 15_000
                requestMethod = "GET"
                setRequestProperty("User-Agent", "AndroDR/1.0")
            }
            try {
                if (connection.responseCode != HttpURLConnection.HTTP_OK) {
                    Log.w(TAG, "HTTP ${connection.responseCode} from stalkerware-indicators")
                    return@withContext emptyList()
                }
                val now = System.currentTimeMillis()
                parseYaml(connection.inputStream.bufferedReader().readText(), now)
            } finally {
                connection.disconnect()
            }
        } catch (e: Exception) {
            Log.e(TAG, "Failed to fetch stalkerware cert indicators: ${e.message}")
            emptyList()
        }
    }

    /**
     * Delegates the YAML walk to [StalkerwareYamlParser], then filters each
     * family's `certificates:` entries to valid SHA-1 fingerprints before
     * emitting [CertHashIocEntry]. Keeping parse and validation separate lets
     * the sibling [StalkerwareIndicatorsFeed] reuse the same parser without
     * inheriting cert-specific validation.
     */
    internal fun parseYaml(yaml: String, fetchedAt: Long): List<CertHashIocEntry> {
        val results = mutableListOf<CertHashIocEntry>()
        for (family in StalkerwareYamlParser.parse(yaml)) {
            val category = categoryFor(family.type)
            val familyName = family.name.ifBlank { "Unknown stalkerware family" }
            for (cert in family.certificates) {
                if (!isValidSha1Hex(cert)) continue
                results += CertHashIocEntry(
                    certHash = cert,
                    familyName = familyName,
                    category = category,
                    severity = "CRITICAL",
                    description = "Signing cert SHA-1 listed in stalkerware-indicators " +
                        "(type: ${family.type}). " +
                        "See https://github.com/AssoEchap/stalkerware-indicators",
                    source = sourceId,
                    fetchedAt = fetchedAt,
                )
            }
        }
        return results
    }

    private fun categoryFor(type: String): String = when {
        type.contains("stalker", ignoreCase = true) -> "STALKERWARE"
        type.contains("spy", ignoreCase = true)     -> "SPYWARE"
        type.contains("monitor", ignoreCase = true) -> "MONITORING"
        else -> "STALKERWARE"
    }

    /**
     * Accepts only 40-char lowercase hex strings with enough character
     * diversity to rule out obvious garbage (upstream poisoning defence:
     * a malicious PR to AssoEchap that inserts `0000…` should not match
     * every unsigned app's default cert).
     */
    private fun isValidSha1Hex(cert: String): Boolean {
        if (cert.length != SHA1_HEX_LEN) return false
        if (!cert.all { it in '0'..'9' || it in 'a'..'f' }) return false
        // Reject low-entropy fingerprints (e.g. all-zeros, all-ones, "abab…").
        return cert.toSet().size >= MIN_UNIQUE_HEX_CHARS
    }

    companion object {
        private const val TAG = "StalkerwareCertHashFeed"
        const val SOURCE_ID = "stalkerware_indicators_certs"
        private const val SHA1_HEX_LEN = 40
        // Real SHA-1 fingerprints of signing certs typically contain 13-16
        // distinct hex chars out of 16. 4 is a very forgiving floor that still
        // rejects synthetic low-entropy strings like "abab..." or "0000…" or
        // "1111…f000…".
        private const val MIN_UNIQUE_HEX_CHARS = 4
        private const val YAML_URL =
            "https://raw.githubusercontent.com/AssoEchap/stalkerware-indicators/master/ioc.yaml"
    }
}
