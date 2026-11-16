package com.androdr.util

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * The visible version is set by hand in `app/build.gradle.kts`, and `release.yml` reads that line
 * as text to name the GitHub release. These tests fail if the line stops being a plain
 * `versionName = "X.Y.Z"`, which would leave the release workflow without a version.
 */
class VersionNameShapeTest {
    private val gradleFile: File =
        listOf(File("build.gradle.kts"), File("app/build.gradle.kts")).first {
            it.isFile && it.readText().contains("applicationId")
        }

    /** The same match release.yml makes with sed. */
    private val line = Regex("""^ *versionName = "([0-9][0-9.]*)" *$""")

    @Test
    fun `the version name is one hand-set X_Y_Z line`() {
        val versions = gradleFile.readLines().mapNotNull { line.find(it)?.groupValues?.get(1) }
        assertEquals("exactly one versionName line release.yml can read", 1, versions.size)
        assertTrue(versions.single(), Regex("""\d+\.\d+\.\d+""").matches(versions.single()))
    }

    @Test
    fun `the release workflow reads the version with the pattern pinned here`() {
        val workflow = generateSequence(gradleFile.absoluteFile.parentFile) { it.parentFile }
            .map { File(it, ".github/workflows/release.yml") }.first { it.isFile }.readText()
        assertTrue(workflow.contains("""sed -n 's/^ *versionName = "\([0-9][0-9.]*\)" *$/\1/p' app/build.gradle.kts"""))
        assertTrue(workflow.contains("""TAG="v${'$'}{BASE_VERSION}-b${'$'}{BUILD}""""))
    }

    @Test
    fun `the report label names the version and the build`() {
        assertEquals("0.9.1 (build 1012)", AppVersion(name = "0.9.1", code = 1012).label)
    }
}
