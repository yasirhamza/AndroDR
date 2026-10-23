package com.androdr.data.db

import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class ChunkedInTest {
    @Test
    fun `5000 keys are split into calls of at most 900`() = runBlocking {
        val sizes = mutableListOf<Int>()
        val out = chunkedIn((1..5000).toList()) { chunk ->
            sizes += chunk.size
            chunk.map { it * 2 }
        }
        assertTrue(sizes.all { it <= 900 })
        assertEquals(listOf(900, 900, 900, 900, 900, 500), sizes)
        assertEquals((1..5000).map { it * 2 }, out)
    }

    @Test
    fun `empty keys make no query`() = runBlocking {
        var calls = 0
        val out = chunkedIn(emptyList<Int>()) { calls++; listOf(1) }
        assertEquals(0, calls)
        assertTrue(out.isEmpty())
    }

    @Test
    fun `custom size is honoured and keys are deduplicated in order`() = runBlocking {
        val seen = mutableListOf<List<Int>>()
        chunkedIn(listOf(1, 2, 2, 3, 1, 4), size = 2) { seen += it; emptyList<Int>() }
        assertEquals(listOf(listOf(1, 2), listOf(3, 4)), seen)
    }

    @Test
    fun `chunkedEach covers every key exactly once with chunks of at most 900`() = runBlocking {
        val seen = mutableListOf<Int>()
        var maxChunk = 0
        chunkedEach((1..2000).toList()) { chunk -> maxChunk = maxOf(maxChunk, chunk.size); seen += chunk }
        assertEquals(900, maxChunk)
        assertEquals((1..2000).toList(), seen)
    }

    @Test(expected = IllegalArgumentException::class)
    fun `size above 900 is rejected`() {
        runBlocking { chunkedIn(listOf(1), size = 901) { emptyList<Int>() } }
    }
}
