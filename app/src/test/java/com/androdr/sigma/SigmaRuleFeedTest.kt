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

    @Test
    fun `parseHashManifest parses sha256sum format`() {
        val manifest = """
            abc123def456  app_scanner/androdr_010.yml
            789fed  device_auditor/androdr_040.yml
            # comment
        """.trimIndent()

        val hashes = SigmaRuleFeed.parseHashManifest(manifest)

        assertEquals(2, hashes.size)
        assertEquals("abc123def456", hashes["app_scanner/androdr_010.yml"])
        assertEquals("789fed", hashes["device_auditor/androdr_040.yml"])
    }

    @Test
    fun `parseHashManifest returns empty for blank input`() {
        assertEquals(0, SigmaRuleFeed.parseHashManifest("").size)
    }
}
