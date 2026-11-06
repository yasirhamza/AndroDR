package com.androdr.util

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.io.IOException
import java.io.StringReader

/**
 * Feed bodies are read into memory before they are parsed. `readText()` has no
 * ceiling, so a hostile or compromised endpoint can hand the app an arbitrarily
 * large body (PASTA F-003/F-004/F-005). [readTextCapped] stops reading at the
 * cap and throws, so the fetch's catch turns the body into "nothing fetched"
 * instead of an OutOfMemoryError.
 */
class CappedReadTest {

    @Test
    fun `a body under the cap is returned whole`() {
        assertEquals("hello", StringReader("hello").readTextCapped(maxChars = 5))
        assertEquals("hello", StringReader("hello").readTextCapped(maxChars = 50))
        assertEquals("", StringReader("").readTextCapped(maxChars = 1))
    }

    @Test
    fun `a body over the cap throws instead of being buffered`() {
        try {
            StringReader("x".repeat(10_001)).readTextCapped(maxChars = 10_000)
            fail("expected IOException")
        } catch (e: IOException) {
            assertTrue("the message names the cap: ${e.message}", e.message.orEmpty().contains("10000"))
        }
    }

    @Test
    fun `the cap is checked as the stream is read, not after it is buffered`() {
        // A reader that never ends: without a streaming check this would spin
        // until the heap is gone. With one, it stops just past the cap.
        var served = 0L
        val endless = object : java.io.Reader() {
            override fun read(cbuf: CharArray, off: Int, len: Int): Int {
                cbuf.fill(' ', off, off + len); served += len; return len
            }
            override fun close() = Unit
        }
        try {
            endless.readTextCapped(maxChars = 1_000)
            fail("expected IOException")
        } catch (e: IOException) {
            assertTrue("read ~the cap, not megabytes: served=$served (${e.message})", served < 64 * 1024)
        }
    }
}
