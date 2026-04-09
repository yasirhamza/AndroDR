package com.androdr.ioc

import android.content.Context
import android.content.res.Resources
import com.androdr.R
import io.mockk.every
import io.mockk.mockk
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class KnownSpywareArtifactsResolverTest {

    private val sampleYaml = """
        version: "2026-04-09"
        artifacts:
          - path: "/data/local/tmp/.raptor"
            family: "pegasus"
            source: "citizen-lab"
          - path: "/data/local/tmp/.stat"
            family: "pegasus"
            source: "mvt"
          - path: "{ext_storage}/.hidden_config"
            family: "generic_stalkerware"
            source: "androdr-research"
    """.trimIndent()

    private fun buildResolver(): KnownSpywareArtifactsResolver {
        val context: Context = mockk(relaxed = true)
        val resources: Resources = mockk(relaxed = true)
        every { context.resources } returns resources
        // openRawResource is not called in these tests; we exercise parseAndResolve directly.
        return KnownSpywareArtifactsResolver(context)
    }

    @Test
    fun `parseAndResolve loads paths and resolves ext_storage template`() {
        val resolver = buildResolver()
        val paths = resolver.parseAndResolve(sampleYaml, "/storage/emulated/0")

        assertEquals(3, paths.size)
        assertTrue(paths.contains("/data/local/tmp/.raptor"))
        assertTrue(paths.contains("/data/local/tmp/.stat"))
        assertTrue(paths.contains("/storage/emulated/0/.hidden_config"))
    }

    @Test
    fun `parseAndResolve returns empty list on malformed yaml`() {
        val resolver = buildResolver()
        val paths = resolver.parseAndResolve("not: [valid: yaml", "/storage/emulated/0")
        assertEquals(0, paths.size)
    }

    @Test
    fun `parseAndResolve returns empty list when artifacts key is missing`() {
        val resolver = buildResolver()
        val paths = resolver.parseAndResolve("version: \"2026-04-09\"", "/storage/emulated/0")
        assertEquals(0, paths.size)
    }

    @Test
    fun `parseAndResolve handles the 5 historical hardcoded paths`() {
        // Regression test: these are the paths that were previously hardcoded in
        // FileArtifactScanner.kt before the YAML migration. If the bundled resource
        // changes, this list should still parse identically.
        val historicalYaml = """
            version: "2026-04-09"
            artifacts:
              - path: "/data/local/tmp/.raptor"
                family: "pegasus"
              - path: "/data/local/tmp/.stat"
                family: "pegasus"
              - path: "/data/local/tmp/.mobilesoftwareupdate"
                family: "pegasus"
              - path: "{ext_storage}/.hidden_config"
                family: "generic_stalkerware"
              - path: "{ext_storage}/Android/data/.system_update"
                family: "generic_stalkerware"
        """.trimIndent()

        val resolver = buildResolver()
        val paths = resolver.parseAndResolve(historicalYaml, "/sdcard")

        assertEquals(5, paths.size)
        assertTrue(paths.contains("/data/local/tmp/.raptor"))
        assertTrue(paths.contains("/data/local/tmp/.stat"))
        assertTrue(paths.contains("/data/local/tmp/.mobilesoftwareupdate"))
        assertTrue(paths.contains("/sdcard/.hidden_config"))
        assertTrue(paths.contains("/sdcard/Android/data/.system_update"))
    }
}
