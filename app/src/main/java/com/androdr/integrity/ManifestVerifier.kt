package com.androdr.integrity

import java.security.MessageDigest

/**
 * The one hashing and manifest-parsing path for every remote file the app verifies
 * against a `sha256sum`-format manifest (`rules.sha256` for rules, `ioc-data.sha256`
 * for IOC data). Nothing else computes a manifest hash.
 */
object ManifestVerifier {

    /** Parse a sha256sum-format manifest into a map of filename to expected hash. */
    fun parse(manifest: String): Map<String, String> =
        manifest.lines()
            .map { it.trim() }
            .filter { it.isNotEmpty() && !it.startsWith("#") }
            .mapNotNull { line ->
                // Format: sha256hash  filename (two-space separator per sha256sum convention)
                val parts = line.split("  ", limit = 2)
                if (parts.size == 2) parts[1] to parts[0] else null
            }
            .toMap()

    /** Lower-case hex SHA-256 of [content] encoded as UTF-8 (the device's hashing path). */
    fun sha256(content: String): String =
        MessageDigest.getInstance("SHA-256").digest(content.toByteArray(Charsets.UTF_8))
            .joinToString("") { "%02x".format(it) }
}
