package com.androdr.data.repo

import android.content.Context
import com.androdr.data.db.CveDao
import io.mockk.coEvery
import io.mockk.coVerify
import io.mockk.mockk
import kotlinx.coroutines.test.runTest
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.net.InetAddress
import java.net.ServerSocket
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream
import kotlin.concurrent.thread

/**
 * The OSV `all.zip` is fetched from a deliberately unpinned host and inflated
 * entry by entry into memory. Two things were unbounded (PASTA F-005): the size
 * of what gets inflated, and the order of "remember this ETag" versus "did the
 * body parse" -- a bomb or truncated zip was cached as Not-Modified forever.
 */
class CveRepositoryOsvFetchTest {

    private fun osvEntry(id: String, fixed: String = "2024-03-01", padding: Int = 0) = """
        {"id":"$id","summary":"s","severity":[{"type":"CVSS_V3","score":"9.8"}],
         "affected":[{"ranges":[{"events":[{"introduced":"0"},{"fixed":"$fixed"}]}]}],
         "pad":"${" ".repeat(padding)}"}
    """.trimIndent()

    private fun zip(vararg entries: Pair<String, String>): ByteArray {
        val out = ByteArrayOutputStream()
        ZipOutputStream(out).use { z ->
            for ((name, body) in entries) {
                z.putNextEntry(ZipEntry(name)); z.write(body.toByteArray()); z.closeEntry()
            }
        }
        return out.toByteArray()
    }

    // ── readOsvZip ─────────────────────────────────────────────────────────────

    @Test
    fun `a well-formed zip yields one entity per CVE entry`() {
        val bytes = zip("CVE-2024-0001.json" to osvEntry("CVE-2024-0001"), "readme.txt" to "ignored",
            "CVE-2024-0002.json" to osvEntry("CVE-2024-0002", fixed = "2024-04-01"))

        val entities = CveRepository.readOsvZip(ByteArrayInputStream(bytes), now = 7L)

        assertEquals(listOf("CVE-2024-0001", "CVE-2024-0002"), entities.map { it.cveId })
        assertEquals("2024-04-01", entities[1].fixedInPatchLevel)
        assertEquals("CRITICAL", entities[0].severity)
    }

    @Test
    fun `an entry inflating past the per-entry cap aborts the zip`() {
        val bytes = zip("CVE-2024-0001.json" to osvEntry("CVE-2024-0001", padding = 5_000))
        try {
            CveRepository.readOsvZip(ByteArrayInputStream(bytes), now = 0L, maxEntryChars = 4_000)
            fail("expected IOException")
        } catch (e: IOException) {
            assertTrue(e.message.orEmpty(), e.message.orEmpty().contains("4000"))
        }
    }

    @Test
    fun `entries that are each small but together exceed the total cap abort the zip`() {
        val entries = (1..10).map { i ->
            "CVE-2024-%04d.json".format(i) to osvEntry("CVE-2024-%04d".format(i), padding = 500)
        }
        val bytes = zip(*entries.toTypedArray())
        // Each entry is ~700 chars; ten of them pass a per-entry cap of 4 000 but not a total of 3 000.
        try {
            CveRepository.readOsvZip(
                ByteArrayInputStream(bytes), now = 0L, maxEntryChars = 4_000, maxTotalChars = 3_000,
            )
            fail("expected IOException")
        } catch (e: IOException) {
            assertTrue(e.message.orEmpty(), e.message.orEmpty().contains("3000"))
        }
    }

    @Test
    fun `the caps leave headroom over the live feed, so hardening cannot disable it`() {
        // Measured 2026-11-06 from the live all.zip: 4,073 .json entries, 35.6 MiB
        // inflated, largest entries ASB-A-412662901 (4.18 MiB) and ASB-A-430889718
        // (3.13 MiB). A 1 MiB per-entry cap would have aborted every cycle -- the
        // false-reassurance failure this app most needs to avoid (security review B1).
        val largestLiveEntryChars = 4_400_000
        val liveTotalChars = 37_400_000L
        assertTrue(CveRepository.MAX_OSV_ENTRY_CHARS >= 4 * largestLiveEntryChars)
        assertTrue(CveRepository.MAX_OSV_TOTAL_CHARS >= 4 * liveTotalChars)
    }

    // ── fetchOsvAndroid / fetchCisaKev: ETag only after a successful parse ─────

    // Android unit tests compile against android.jar, so the JDK's httpserver
    // module is not on the classpath; a one-shot ServerSocket is enough here.
    private var server: ServerSocket? = null
    private var serverError: Throwable? = null

    @After fun stop() {
        server?.close()
        serverError?.let { throw AssertionError("test server failed", it) }
    }

    private fun serve(body: ByteArray, etag: String, path: String = "/all.zip"): String {
        val s = ServerSocket(0, 1, InetAddress.getLoopbackAddress())
        server = s
        thread(isDaemon = true) {
            runCatching {
                s.accept().use { client ->
                    val reader = client.getInputStream().bufferedReader()
                    while (reader.readLine().orEmpty().isNotEmpty()) { /* drain request headers */ }
                    client.getOutputStream().apply {
                        write(("HTTP/1.1 200 OK\r\nETag: $etag\r\nContent-Type: application/octet-stream\r\n" +
                            "Content-Length: ${body.size}\r\nConnection: close\r\n\r\n").toByteArray())
                        write(body); flush()
                    }
                }
            }.onFailure { serverError = it }
        }
        return "http://127.0.0.1:${s.localPort}$path"
    }

    private fun repo(settings: SettingsRepository) =
        CveRepository(mockk<Context>(relaxed = true), mockk<CveDao>(relaxed = true), settings)

    @Test
    fun `a zip that fails the cap is not remembered as the current ETag`() = runTest {
        val settings = mockk<SettingsRepository>(relaxed = true) { coEvery { getEtag(any()) } returns null }
        val url = serve(zip("CVE-2024-0001.json" to osvEntry("CVE-2024-0001", padding = 5_000)), etag = "\"bomb\"")

        val result = repo(settings).fetchOsvAndroid(url, maxEntryChars = 4_000)

        assertEquals(emptyList<Any>(), result)
        coVerify(exactly = 0) { settings.setEtag(any(), any()) }
    }

    @Test
    fun `a zip that parses is remembered by its ETag`() = runTest {
        val settings = mockk<SettingsRepository>(relaxed = true) { coEvery { getEtag(any()) } returns null }
        val url = serve(zip("CVE-2024-0001.json" to osvEntry("CVE-2024-0001")), etag = "\"good\"")

        val result = repo(settings).fetchOsvAndroid(url)

        assertEquals(listOf("CVE-2024-0001"), result?.map { it.cveId })
        // "cve_osv" is the persisted preference key (CveRepository.ETAG_OSV); pinned on purpose.
        coVerify(exactly = 1) { settings.setEtag("cve_osv", "\"good\"") }
    }

    @Test
    fun `a zip that parses to no CVE at all is not remembered by its ETag`() = runTest {
        // A valid zip of non-CVE advisories "parses" fine and yields nothing. Caching
        // its ETag would 304 against an empty feed for as long as the server kept it.
        val settings = mockk<SettingsRepository>(relaxed = true) { coEvery { getEtag(any()) } returns null }
        val url = serve(zip("GHSA-xxxx.json" to osvEntry("GHSA-xxxx")), etag = "\"empty\"")

        val result = repo(settings).fetchOsvAndroid(url)

        assertEquals(emptyList<Any>(), result)
        coVerify(exactly = 0) { settings.setEtag(any(), any()) }
    }

    private fun kev(vararg cves: String) = buildString {
        append("""{"vulnerabilities":[""")
        append(cves.joinToString(",") {
            """{"cveID":"$it","vendorProject":"Google","product":"Android",""" +
                """"shortDescription":"d","dateAdded":"2024-01-02"}"""
        })
        append("]}")
    }

    @Test
    fun `a KEV body that does not parse is not remembered as the current ETag`() = runTest {
        // Same ordering bug as OSV, one method up (architect review S2): the ETag was
        // stored before the JSON was read, so a truncated body was cached as current.
        val settings = mockk<SettingsRepository>(relaxed = true) { coEvery { getEtag(any()) } returns null }
        val truncated = kev("CVE-2024-0001").dropLast(20).toByteArray()
        val url = serve(truncated, etag = "\"trunc\"", path = "/kev.json")

        val result = repo(settings).fetchCisaKev(url)

        assertEquals(emptyList<Any>(), result)
        coVerify(exactly = 0) { settings.setEtag(any(), any()) }
    }

    @Test
    fun `a KEV body that parses is remembered by its ETag`() = runTest {
        val settings = mockk<SettingsRepository>(relaxed = true) { coEvery { getEtag(any()) } returns null }
        val url = serve(kev("CVE-2024-0001", "CVE-2024-0002").toByteArray(), etag = "\"kev\"", path = "/kev.json")

        val result = repo(settings).fetchCisaKev(url)

        assertEquals(listOf("CVE-2024-0001", "CVE-2024-0002"), result?.map { it.cveId })
        coVerify(exactly = 1) { settings.setEtag("cve_cisa", "\"kev\"") }
    }
}
