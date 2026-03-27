package com.androdr.sigma

import org.junit.Assert.assertEquals
import org.junit.Test

class SigmaRuleFeedTest {

    @Test
    fun `parseManifest filters yml lines and ignores comments`() {
        val manifest = """
            # AndroDR SIGMA Rules Manifest
            rules/production/app_risk/androdr-060.yml
            rules/production/device_posture/androdr-061.yml

            # Some comment
            not-a-yml-file.txt
        """.trimIndent()

        val files = SigmaRuleFeed.parseManifest(manifest)

        assertEquals(2, files.size)
        assertEquals("rules/production/app_risk/androdr-060.yml", files[0])
        assertEquals("rules/production/device_posture/androdr-061.yml", files[1])
    }

    @Test
    fun `parseManifest handles flat filenames for backward compatibility`() {
        val manifest = """
            androdr-001.yml
            androdr-002.yml
        """.trimIndent()

        val files = SigmaRuleFeed.parseManifest(manifest)

        assertEquals(2, files.size)
        assertEquals("androdr-001.yml", files[0])
    }

    @Test
    fun `parseManifest returns empty for blank manifest`() {
        val files = SigmaRuleFeed.parseManifest("")
        assertEquals(0, files.size)
    }
}
