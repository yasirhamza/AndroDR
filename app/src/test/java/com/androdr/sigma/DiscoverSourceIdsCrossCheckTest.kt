package com.androdr.sigma

import com.fasterxml.jackson.databind.ObjectMapper
import org.junit.Assert.assertEquals
import org.junit.Assume.assumeTrue
import org.junit.Test
import java.io.File

/**
 * Build-time cross-check: the 5 discover source IDs in
 * update-rules-discover.md MUST match feed-state-schema.json's
 * discover.sources.properties. Drift fails the build.
 */
class DiscoverSourceIdsCrossCheckTest {

    private val skillSourceIds = setOf(
        "securelist", "welivesecurity", "zimperium", "lookout", "google-tag",
    )

    private fun schemaFile(): File? {
        val candidates = listOf(
            File("third-party/android-sigma-rules/validation/feed-state-schema.json"),
            File("../third-party/android-sigma-rules/validation/feed-state-schema.json"),
            File("/home/yasir/AndroDR/third-party/android-sigma-rules/validation/feed-state-schema.json"),
        )
        return candidates.firstOrNull { it.isFile }
    }

    @Test
    fun `feed-state schema discover source IDs match the skill`() {
        val schema = schemaFile()
        assumeTrue("Skipping: submodule not initialized.", schema != null && schema!!.isFile)

        val root = ObjectMapper().readTree(schema!!)
        val discoverSources = root.path("properties").path("discover")
            .path("properties").path("sources").path("properties")

        val yamlSourceIds = mutableSetOf<String>()
        discoverSources.fieldNames().forEach { yamlSourceIds.add(it) }

        assertEquals(
            "Set of discover source IDs must match between skill and schema.\n" +
                "Skill:  $skillSourceIds\n" +
                "Schema: $yamlSourceIds",
            skillSourceIds, yamlSourceIds,
        )
    }
}
