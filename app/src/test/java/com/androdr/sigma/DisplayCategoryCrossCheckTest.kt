package com.androdr.sigma

import com.fasterxml.jackson.databind.ObjectMapper
import org.junit.Assert.assertEquals
import org.junit.Assume.assumeTrue
import org.junit.Test
import java.io.File

/**
 * Build-time cross-check: the set of display buckets the Kotlin runtime knows
 * ([FindingCategory]) must equal the set the rule schema allows
 * (`display.category` enum in rule-schema.json). Exactly -- not a subset either way.
 *
 * A value in the schema but not in Kotlin would be accepted upstream and then
 * rejected on-device (fail-closed drop, silent). A value in Kotlin but not in the
 * schema is a bucket no rule can ever be authored into -- dead code that a
 * renderer might still be written for. `network` was the second kind for months.
 */
class DisplayCategoryCrossCheckTest {

    private fun schemaFile(): File? = listOf(
        File("third-party/android-sigma-rules/validation/rule-schema.json"),
        File("../third-party/android-sigma-rules/validation/rule-schema.json"),
        File("/home/yasir/AndroDR/third-party/android-sigma-rules/validation/rule-schema.json"),
    ).firstOrNull { it.isFile }

    @Test
    fun `FindingCategory equals the schema display category enum`() {
        val schema = schemaFile()
        assumeTrue("android-sigma-rules submodule not checked out", schema != null)

        val schemaEnum = ObjectMapper().readTree(schema!!)
            .path("properties").path("display").path("properties").path("category").path("enum")
            .map { it.asText() }
            .toSet()
        val kotlinEnum = FindingCategory.values().map { it.name.lowercase() }.toSet()

        assertEquals(
            "display.category buckets drifted between rule-schema.json and FindingCategory",
            schemaEnum,
            kotlinEnum,
        )
    }
}
