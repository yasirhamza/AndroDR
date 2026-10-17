package com.androdr.ioc

import com.androdr.integrity.ManifestVerifier
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/** Test helpers: a network stub plus a matching `ioc-data.sha256`. */
class FakeRemote(
    files: Map<String, String>,
    manifestBody: String? = manifestFor(files),
) : RemoteText {
    private val bodies = HashMap<String, String>()
    val calls = ArrayList<String>()

    init {
        files.forEach { (path, body) -> bodies["$RULES_REPO_BASE_URL$path"] = body }
        manifestBody?.let { bodies["${RULES_REPO_BASE_URL}ioc-data.sha256"] = it }
    }

    fun set(path: String, body: String) { bodies["$RULES_REPO_BASE_URL$path"] = body }
    fun setManifest(body: String?) {
        if (body == null) bodies.remove("${RULES_REPO_BASE_URL}ioc-data.sha256")
        else bodies["${RULES_REPO_BASE_URL}ioc-data.sha256"] = body
    }

    override suspend fun get(url: String): String? { calls += url; return bodies[url] }

    companion object {
        fun manifestFor(files: Map<String, String>): String =
            files.entries.joinToString("\n") { "${ManifestVerifier.sha256(it.value)}  ${it.key}" }
    }
}

class IocDataManifestTest {

    private val path = "ioc-data/c2-domains.yml"

    @Test
    fun `matching hash returns content`() = runBlocking {
        val remote = FakeRemote(mapOf(path to "a: 1"))
        assertEquals("a: 1", IocDataManifest(remote).verified(path))
    }

    @Test
    fun `hash mismatch returns null`() = runBlocking {
        val remote = FakeRemote(mapOf(path to "a: 1"))
        remote.set(path, "a: 2")
        assertNull(IocDataManifest(remote).verified(path))
    }

    @Test
    fun `file absent from manifest returns null`() = runBlocking {
        val remote = FakeRemote(mapOf("ioc-data/other.yml" to "x"))
        remote.set(path, "a: 1")
        assertNull(IocDataManifest(remote).verified(path))
    }

    @Test
    fun `missing manifest returns null`() = runBlocking {
        val remote = FakeRemote(mapOf(path to "a: 1"), manifestBody = null)
        assertNull(IocDataManifest(remote).verified(path))
    }

    @Test
    fun `empty or corrupt manifest returns null`() = runBlocking {
        assertNull(IocDataManifest(FakeRemote(mapOf(path to "a: 1"), manifestBody = "")).verified(path))
        assertNull(IocDataManifest(FakeRemote(mapOf(path to "a: 1"), manifestBody = "garbage no sep")).verified(path))
    }

    @Test
    fun `failed manifest fetch is not cached`() = runBlocking {
        val remote = FakeRemote(mapOf(path to "a: 1"), manifestBody = null)
        val manifest = IocDataManifest(remote)
        assertNull(manifest.verified(path))
        remote.setManifest(FakeRemote.manifestFor(mapOf(path to "a: 1")))
        assertEquals("a: 1", manifest.verified(path))
        assertEquals(2, remote.calls.count { it.endsWith("ioc-data.sha256") })
    }

    @Test
    fun `good manifest is cached for ten minutes then refetched`() = runBlocking {
        var now = 0L
        val remote = FakeRemote(mapOf(path to "a: 1"))
        val manifest = IocDataManifest(remote) { now }
        manifest.verified(path)
        now = 9 * 60_000L
        manifest.verified(path)
        assertEquals(1, remote.calls.count { it.endsWith("ioc-data.sha256") })
        now = 11 * 60_000L
        manifest.verified(path)
        assertEquals(2, remote.calls.count { it.endsWith("ioc-data.sha256") })
    }

    @Test
    fun `oversize content returns null`() = runBlocking {
        val remote = FakeRemote(mapOf(path to "0123456789"))
        assertNull(IocDataManifest(remote).verified(path, maxChars = 5))
    }

    // Final review item 8: a cancelled fetch must cancel, not read as "unusable manifest".

    @Test(expected = kotlinx.coroutines.CancellationException::class)
    fun `cancellation during the manifest fetch is rethrown`(): Unit = runBlocking {
        val remote = RemoteText { throw kotlinx.coroutines.CancellationException("stop") }
        IocDataManifest(remote).verified(path)
        Unit
    }

    @Test(expected = kotlinx.coroutines.CancellationException::class)
    fun `cancellation during the file fetch is rethrown`(): Unit = runBlocking {
        val good = FakeRemote(mapOf(path to "a: 1"))
        val remote = RemoteText { url ->
            if (url.endsWith("ioc-data.sha256")) good.get(url)
            else throw kotlinx.coroutines.CancellationException("stop")
        }
        IocDataManifest(remote).verified(path)
        Unit
    }
}
