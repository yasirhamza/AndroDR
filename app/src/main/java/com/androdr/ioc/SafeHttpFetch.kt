package com.androdr.ioc

import android.util.Log
import java.net.HttpURLConnection
import java.net.URL

/**
 * Shared HTTP fetch utility with response size limiting.
 * Prevents OOM from oversized responses across all IOC feeds.
 */
object SafeHttpFetch {

    private const val TAG = "SafeHttpFetch"

    /**
     * Fetches a URL with size and timeout guards. Returns null on failure.
     * @param maxBytes Maximum response body size (default 10MB)
     * @param timeoutMs Connection and read timeout (default 15s)
     */
    @Suppress("TooGenericExceptionCaught", "ReturnCount")
    fun fetch(
        url: String,
        maxBytes: Int = DEFAULT_MAX_BYTES,
        timeoutMs: Int = DEFAULT_TIMEOUT_MS
    ): String? {
        val conn = try {
            URL(url).openConnection() as HttpURLConnection
        } catch (e: Exception) {
            Log.w(TAG, "Connection failed for $url: ${e.message}")
            return null
        }
        return try {
            conn.connectTimeout = timeoutMs
            conn.readTimeout = timeoutMs
            conn.instanceFollowRedirects = false
            conn.setRequestProperty("User-Agent", "AndroDR/1.0")
            if (conn.responseCode != HttpURLConnection.HTTP_OK) {
                Log.w(TAG, "HTTP ${conn.responseCode} from $url")
                return null
            }
            val contentLength = conn.contentLength
            if (contentLength > maxBytes) {
                Log.w(TAG, "Response too large: $contentLength bytes (limit $maxBytes) from $url")
                return null
            }
            val body = conn.inputStream.bufferedReader().use { it.readText() }
            if (body.length > maxBytes) {
                Log.w(TAG, "Response body exceeded limit: ${body.length} bytes from $url")
                return null
            }
            body
        } catch (e: Exception) {
            Log.w(TAG, "Fetch failed for $url: ${e.message}")
            null
        } finally {
            conn.disconnect()
        }
    }

    private const val DEFAULT_MAX_BYTES = 10_000_000 // 10 MB
    private const val DEFAULT_TIMEOUT_MS = 15_000
}
