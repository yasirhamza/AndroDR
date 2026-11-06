package com.androdr.util

import java.io.IOException
import java.io.Reader

/**
 * Reads this reader to its end like `readText()`, but refuses to buffer more
 * than [maxChars]: the check runs as the stream is read, so an endless or
 * oversized body costs at most one buffer past the cap, never the heap.
 *
 * Feed bodies are read whole before they are parsed. Without a ceiling a
 * hostile or compromised endpoint can hand the app an arbitrarily large body
 * (PASTA F-003/F-004/F-005). Throwing lets each fetch's existing catch turn
 * the body into "nothing fetched" rather than an OutOfMemoryError.
 *
 * Counts UTF-16 chars, not wire bytes: the heap cost is the chars. The cap is a
 * bound on unbounded input, not a heap budget -- a body just under a large cap is
 * still that large in memory, so callers size their caps to their heap.
 *
 * @throws BodyTooLargeException (an [IOException]) when the body exceeds [maxChars].
 */
fun Reader.readTextCapped(maxChars: Int): String {
    val sb = StringBuilder()
    val buf = CharArray(BUFFER_CHARS)
    while (true) {
        val n = read(buf)
        if (n < 0) break
        if (sb.length + n > maxChars) throw BodyTooLargeException(maxChars)
        sb.appendRange(buf, 0, n)
    }
    return sb.toString()
}

/** The body passed the cap. A subclass so a caller can skip the item rather than the fetch. */
class BodyTooLargeException(maxChars: Int) : IOException("response body exceeds $maxChars chars")

private const val BUFFER_CHARS = 8 * 1024
