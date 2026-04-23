package com.androdr.ioc

import org.junit.Assert.assertEquals
import org.junit.Test
import org.snakeyaml.engine.v2.api.Load
import org.snakeyaml.engine.v2.api.LoadSettings
import java.io.File

/**
 * Build-time cross-check: the set of Kotlin bypass feed classes that
 * directly fetch upstream IOCs MUST match the entries in
 * validation/kotlin-mirror-feeds.yml. Drift fails the build.
 *
 * URL constants remain private inside each feed class — URLs are
 * authoritative only in the YAML; this test uses class-name-based
 * correspondence via a declarative feed-id list below.
 *
 * To add a new bypass feed, add it to KOTLIN_BYPASS_FEED_IDS below AND to
 * validation/kotlin-mirror-feeds.yml in the submodule (same PR).
 */
class KotlinMirrorFeedsCrossCheckTest {

    // The feed IDs in validation/kotlin-mirror-feeds.yml that correspond to
    // actively-wired Kotlin bypass feed classes. Out-of-scope feeds (HaGeZi,
    // UAD, Plexus, Zimperium, MalwareBazaarCertFeed-stub) are NOT listed.
    private val kotlinBypassFeedIds = setOf(
        "stalkerware-indicators",  // StalkerwareIndicatorsFeed.kt
        "mvt-indicators",          // MvtIndicatorsFeed.kt
        "threatfox",               // ThreatFoxDomainFeed.kt
    )

    private fun mirrorFeedsFile(): File {
        val candidates = listOf(
            File("third-party/android-sigma-rules/validation/kotlin-mirror-feeds.yml"),
            File("../third-party/android-sigma-rules/validation/kotlin-mirror-feeds.yml"),
            File("/home/yasir/AndroDR/third-party/android-sigma-rules/validation/kotlin-mirror-feeds.yml"),
        )
        return candidates.firstOrNull { it.isFile }
            ?: error("kotlin-mirror-feeds.yml not found. Run: git submodule update --init")
    }

    @Test
    fun `kotlin-mirror-feeds ids match the KOTLIN_BYPASS_FEED_IDS set`() {
        val settings = LoadSettings.builder().setAllowDuplicateKeys(false).build()
        val load = Load(settings)

        @Suppress("UNCHECKED_CAST")
        val doc = load.loadFromString(mirrorFeedsFile().readText()) as Map<String, Any?>
        @Suppress("UNCHECKED_CAST")
        val feeds = doc["feeds"] as List<Map<String, Any?>>
        val yamlFeedIds = feeds.map { it["id"] as String }.toSet()

        assertEquals(
            "kotlin-mirror-feeds.yml ids must exactly match KOTLIN_BYPASS_FEED_IDS.\n" +
                "Kotlin test: $kotlinBypassFeedIds\n" +
                "YAML:        $yamlFeedIds\n" +
                "Missing from YAML: ${kotlinBypassFeedIds - yamlFeedIds}\n" +
                "Extra in YAML:     ${yamlFeedIds - kotlinBypassFeedIds}",
            kotlinBypassFeedIds,
            yamlFeedIds,
        )
    }
}
