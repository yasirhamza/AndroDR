package com.androdr.ioc

import android.util.Log
import com.androdr.integrity.ManifestVerifier
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import javax.inject.Inject
import javax.inject.Singleton

/** Shared base URL for every default-repo fetcher, so manifest and files cannot drift apart. */
const val RULES_REPO_BASE_URL = "https://raw.githubusercontent.com/android-sigma-rules/rules/main/"

/** Network seam: returns the body at [url], or null on any failure. */
fun interface RemoteText {
    suspend fun get(url: String): String?
}

/** Production fetcher: [SafeHttpFetch] with the 1 MB cap the ioc-data fetchers have always used. */
object SafeRemoteText : RemoteText {
    private const val MAX_BYTES = 1_000_000
    private const val TIMEOUT_MS = 15_000
    override suspend fun get(url: String): String? =
        SafeHttpFetch.fetch(url, maxBytes = MAX_BYTES, timeoutMs = TIMEOUT_MS)
}

/**
 * Fail-closed verification of default-repo ioc-data YAML files against `ioc-data.sha256`.
 *
 * [verified] returns a file's content only when its SHA-256 equals the manifest entry.
 * A missing, unfetchable or empty/corrupt manifest means NO remote file is used.
 * The manifest is cached 10 minutes, and only when it parsed non-empty.
 */
@Singleton
class IocDataManifest(
    private val remote: RemoteText,
    private val clock: () -> Long = System::currentTimeMillis,
) {
    @Inject constructor() : this(SafeRemoteText)

    private val mutex = Mutex()
    private var cached: Map<String, String>? = null
    private var cachedAt = 0L

    /** [path] is repo-relative, e.g. `ioc-data/c2-domains.yml`. Null = unusable, keep last good data. */
    suspend fun verified(path: String, maxChars: Int = Int.MAX_VALUE): String? {
        val expected = expectedHash(path) ?: return null
        val body = fetchBody(path) ?: return null
        val actual = ManifestVerifier.sha256(body)
        return when {
            body.length > maxChars -> {
                Log.w(TAG, "$path too large: ${body.length} chars, limit $maxChars")
                null
            }
            !actual.equals(expected, ignoreCase = true) -> {
                Log.e(TAG, "Integrity check FAILED for $path: expected=$expected actual=$actual - skipping")
                null
            }
            else -> body
        }
    }

    private suspend fun expectedHash(path: String): String? {
        val hashes = hashes()
        val expected = hashes[path]
        when {
            hashes.isEmpty() ->
                Log.e(TAG, "No usable hash manifest (ioc-data.sha256) - refusing unverified $path (fail closed)")
            expected == null -> Log.e(TAG, "No verified hash for $path - skipping (fail closed)")
        }
        return expected
    }

    @Suppress("TooGenericExceptionCaught")
    private suspend fun fetchBody(path: String): String? = try {
        remote.get("$RULES_REPO_BASE_URL$path")
    } catch (e: Exception) {
        Log.w(TAG, "Fetch failed for $path: ${e.message}")
        null
    }

    @Suppress("TooGenericExceptionCaught")
    private suspend fun hashes(): Map<String, String> = mutex.withLock {
        cached?.let { if (clock() - cachedAt < TTL_MS) return it }
        val parsed = try {
            remote.get("${RULES_REPO_BASE_URL}ioc-data.sha256")?.let(ManifestVerifier::parse).orEmpty()
        } catch (e: Exception) {
            Log.w(TAG, "Manifest fetch failed: ${e.message}")
            emptyMap()
        }
        if (parsed.isEmpty()) {
            cached = null
        } else {
            cached = parsed
            cachedAt = clock()
        }
        parsed
    }

    companion object {
        private const val TAG = "IocDataManifest"
        private const val TTL_MS = 10 * 60 * 1000L
    }
}
