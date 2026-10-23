package com.androdr.ioc

import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * Owner decision (R8): regenerating the bundle from `ioc-data` must not change what the VPN
 * blocks by default, and must not silently drop a previously bundled indicator.
 */
class BlockingSetUnchangedTest {

    private fun firstDirectory(vararg paths: String): File =
        paths.map(::File).firstOrNull { it.isDirectory }
            ?: error("Could not locate any of: ${paths.toList()}")

    private val rawDir by lazy { firstDirectory("app/src/main/res/raw", "src/main/res/raw") }
    private val baselineDir by lazy {
        firstDirectory("third-party/android-sigma-rules/validation", "../third-party/android-sigma-rules/validation")
    }

    private fun field(file: String, key: String, lower: Boolean): Set<String> {
        val arr = JSONArray(File(rawDir, file).readText())
        return (0 until arr.length()).map { arr.getJSONObject(it).getString(key) }
            .map { if (lower) it.lowercase() else it }.toSet()
    }

    @Test
    fun `default-blocked domains equal the rules-repo blocked baseline`() {
        val arr = JSONArray(File(rawDir, "known_bad_domains.json").readText())
        val blocked = (0 until arr.length()).map { arr.getJSONObject(it) }
            .filter { it.optBoolean("blockByDefault", false) }
            .map { it.getString("domain").lowercase() }.toSet()
        val baseline = File(baselineDir, "blocked-baseline.txt").readLines()
            .map { it.trim().lowercase() }.filter { it.isNotEmpty() && !it.startsWith("#") }.toSet()
        assertEquals(baseline, blocked)
    }

    @Test
    fun `every pre-regeneration bundled entry is still present unless deliberately removed`() {
        val base = JSONObject(
            javaClass.classLoader!!.getResourceAsStream("bundle-baseline-2026-10-15.json")!!
                .bufferedReader().use { it.readText() }
        )
        val removed = removedByKind()
        val lists = mapOf(
            "domains" to Triple("known_bad_domains.json", "domain", true),
            "packages" to Triple("known_bad_packages.json", "packageName", false),
            "certs" to Triple("known_bad_certs.json", "certHash", true),
            "apkHashes" to Triple("known_bad_apk_hashes.json", "apkHash", true),
        )
        for ((name, spec) in lists) {
            val (file, key, lower) = spec
            val had = base.getJSONArray(name).let { a -> (0 until a.length()).map { a.getString(it) } }
            val missing = had.filter { it.lowercase() !in removed.getValue(name) } - field(file, key, lower)
            assertTrue("$name dropped from the bundle without an entry in removed-fabricated-iocs.txt: $missing",
                missing.isEmpty())
        }
    }

    private fun removedByKind(): Map<String, Set<String>> {
        val sections = mutableMapOf<String, MutableSet<String>>()
        var current = ""
        javaClass.classLoader!!.getResourceAsStream("removed-fabricated-iocs.txt")!!.bufferedReader().forEachLine {
            val line = it.trim()
            when {
                line.isEmpty() || line.startsWith("#") -> Unit
                line.startsWith("[") -> current = line.trim('[', ']')
                else -> sections.getOrPut(current) { mutableSetOf() }.add(line.lowercase())
            }
        }
        return mapOf(
            "domains" to sections["domains"].orEmpty(), "packages" to sections["packages"].orEmpty(),
            "certs" to sections["certs"].orEmpty(), "apkHashes" to sections["apk_hashes"].orEmpty(),
        )
    }
}
