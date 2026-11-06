package com.androdr.privacy

import java.io.File
import java.io.IOException
import java.util.BitSet
import java.util.regex.Pattern
import java.util.zip.ZipFile

/**
 * Hardened reader for the class-name tables of an installed APK's dex files.
 *
 * The APK is attacker-controlled: every size is derived from bytes actually read, every table
 * is bounded by the array, and every loop honours the shared [ReadBudget] deadline. A bad dex
 * costs only that dex ([DexOutcome.MALFORMED]); the reader never throws for dex content.
 *
 * Registry-independent by design: it returns package names and knows nothing about trackers.
 */
object DexPackageReader {
    enum class DexOutcome { READ, SKIPPED_OVER_CAP, MALFORMED, TIME_LIMIT }

    data class Result(
        val packages: Set<String>,
        val dexOutcomes: Map<String, DexOutcome>,
        val packageCapHit: Boolean,
        val bytesRead: Long,
    ) {
        val partial: Boolean get() = packageCapHit || dexOutcomes.values.any { it != DexOutcome.READ }
    }

    /** One per app, shared by its base and split APKs. [nanoTime] is injectable for tests. */
    class ReadBudget(
        val deadlineNanos: Long,
        var remainingAppBytes: Long = MAX_APP_BYTES,
        var remainingPackages: Int = MAX_PACKAGES,
        val nanoTime: () -> Long = System::nanoTime,
    ) {
        fun expired(): Boolean = nanoTime() >= deadlineNanos
    }

    class ApkUnreadableException(message: String, cause: Throwable? = null) : Exception(message, cause)

    const val MAX_DEX_BYTES = 32 * 1024 * 1024 // largest real dex measured: 9.7 MB
    const val MAX_APP_BYTES = 256L * 1024 * 1024
    const val MAX_PACKAGES = 20_000 // largest real app measured: 2,724 packages
    const val MAX_DEX_FILES = 100
    const val MAX_DESCRIPTOR_CHARS = 512

    private const val CHUNK = 64 * 1024

    /** Test hook: receives the number of bytes scanned for each descriptor's NUL terminator. */
    @Volatile internal var scanProbe: ((Int) -> Unit)? = null

    /**
     * Reads only the dex files Android loads: classes.dex, then classes2.dex, classes3.dex, …
     * stopping at the first gap.
     */
    fun read(
        apk: File,
        budget: ReadBudget,
        maxDexBytes: Int = MAX_DEX_BYTES,
        maxDexFiles: Int = MAX_DEX_FILES,
    ): Result {
        val zip = try {
            ZipFile(apk)
        } catch (e: IOException) {
            throw ApkUnreadableException("cannot open ${apk.name} as a zip", e)
        } catch (e: IllegalArgumentException) {
            throw ApkUnreadableException("cannot open ${apk.name} as a zip", e)
        }
        zip.use { return readAll(it, budget, maxDexBytes, maxDexFiles) }
    }

    private fun loadedNames(zip: ZipFile, maxDexFiles: Int): Pair<List<String>, String?> {
        val names = ArrayList<String>()
        var index = 1
        while (names.size <= maxDexFiles) {
            val name = if (index == 1) "classes.dex" else "classes$index.dex"
            if (zip.getEntry(name) == null) break
            names.add(name)
            index++
        }
        return if (names.size > maxDexFiles) {
            names.subList(0, maxDexFiles).toList() to names[maxDexFiles]
        } else {
            names to null
        }
    }

    private fun readAll(zip: ZipFile, budget: ReadBudget, maxDexBytes: Int, maxDexFiles: Int): Result {
        val (names, overCap) = loadedNames(zip, maxDexFiles)
        val outcomes = LinkedHashMap<String, DexOutcome>()
        val packages = LinkedHashSet<String>()
        var capHit = false
        var bytes = 0L
        var timedOut = false
        for (name in names) {
            if (timedOut || budget.expired()) {
                timedOut = true
                outcomes[name] = DexOutcome.TIME_LIMIT
                continue
            }
            val fetched = fetch(zip, name, budget, maxDexBytes)
            bytes += fetched.bytes
            var outcome = fetched.outcome
            if (fetched.data != null) {
                val parsed = DexTables(fetched.data, budget, packages, scanProbe).parse()
                outcome = parsed.outcome
                if (outcome == DexOutcome.READ || outcome == DexOutcome.TIME_LIMIT) {
                    merge(parsed.packages, packages, budget)
                    capHit = parsed.capHit || capHit
                }
            }
            if (outcome == DexOutcome.TIME_LIMIT) timedOut = true
            outcomes[name] = outcome
        }
        if (overCap != null) outcomes[overCap] = DexOutcome.SKIPPED_OVER_CAP
        return Result(packages, outcomes, capHit, bytes)
    }

    /**
     * Adds [local] to [global] and charges the shared budget. [DexTables] already bounded [local] by
     * the remaining budget and excluded packages in [global], so this never exceeds the cap.
     */
    private fun merge(local: Set<String>, global: MutableSet<String>, budget: ReadBudget) {
        for (p in local) {
            if (global.add(p)) budget.remainingPackages--
        }
    }

    private class Fetched(val data: ByteArray?, val outcome: DexOutcome, val bytes: Long)

    /** Reads one entry with counted chunks; never consults the (forgeable) declared uncompressed size. */
    private fun fetch(zip: ZipFile, name: String, budget: ReadBudget, maxDexBytes: Int): Fetched {
        val entry = zip.getEntry(name)
        return when {
            entry == null -> Fetched(null, DexOutcome.MALFORMED, 0L)
            entry.compressedSize > maxDexBytes -> Fetched(null, DexOutcome.SKIPPED_OVER_CAP, 0L)
            else -> countedRead(zip, entry, budget, maxDexBytes)
        }
    }

    private fun countedRead(
        zip: ZipFile,
        entry: java.util.zip.ZipEntry,
        budget: ReadBudget,
        maxDexBytes: Int,
    ): Fetched {
        var total = 0L
        var stop: DexOutcome? = null
        val sink = java.io.ByteArrayOutputStream()
        try {
            zip.getInputStream(entry).use { input ->
                val buf = ByteArray(CHUNK)
                while (stop == null) {
                    val n = input.read(buf)
                    if (n < 0) break
                    total += n
                    budget.remainingAppBytes -= n
                    stop = when {
                        total > maxDexBytes || budget.remainingAppBytes < 0 -> DexOutcome.SKIPPED_OVER_CAP
                        budget.expired() -> DexOutcome.TIME_LIMIT
                        else -> null
                    }
                    if (stop == null) sink.write(buf, 0, n)
                }
            }
        } catch (_: IOException) {
            return Fetched(null, DexOutcome.MALFORMED, total)
        }
        val failed = stop
        return if (failed != null) Fetched(null, failed, total) else Fetched(sink.toByteArray(), DexOutcome.READ, total)
    }

    /** Test hook: receives the final size of each dex's local package set (never above the budget). */
    @Volatile internal var localSetProbe: ((Int) -> Unit)? = null

    internal class ParsedDex(val outcome: DexOutcome, val packages: Set<String>, val capHit: Boolean = false)

    /** Thrown inside [DexTables] for structural violations; carries no stack trace. */
    private class DexFormatException : RuntimeException(null, null, false, false)

    private class DexTables(
        private val d: ByteArray,
        private val budget: ReadBudget,
        private val global: Set<String>,
        private val probe: ((Int) -> Unit)?,
    ) {
        /** Packages new to this dex; never grows past the app's remaining package budget. */
        private val packages = LinkedHashSet<String>()
        private var capHit = false

        fun parse(): ParsedDex = try {
            parseTables().also { localSetProbe?.invoke(packages.size) }
        } catch (_: DexFormatException) {
            ParsedDex(DexOutcome.MALFORMED, emptySet())
        }

        private fun malformed(): Nothing = throw DexFormatException()

        private fun u4(off: Long): Long {
            if (off < 0 || off + 4 > d.size) malformed()
            val o = off.toInt()
            return (d[o].toLong() and 0xFF) or ((d[o + 1].toLong() and 0xFF) shl 8) or
                ((d[o + 2].toLong() and 0xFF) shl 16) or ((d[o + 3].toLong() and 0xFF) shl 24)
        }

        private fun checkHeader() {
            if (d.size < HEADER_SIZE) malformed()
            val ok = d[0] == 'd'.code.toByte() && d[1] == 'e'.code.toByte() && d[2] == 'x'.code.toByte() &&
                d[3] == '\n'.code.toByte() && d[7] == 0.toByte() && versionOk(d[4].toInt(), d[5].toInt(), d[6].toInt())
            if (!ok) malformed()
        }

        private fun versionOk(a: Int, b: Int, c: Int): Boolean {
            val digits = a in '0'.code..'9'.code && b in '0'.code..'9'.code && c in '0'.code..'9'.code
            if (!digits) return false
            val v = (a - '0'.code) * 100 + (b - '0'.code) * 10 + (c - '0'.code)
            return v in 35..41
        }

        private fun requireTable(off: Long, size: Long) {
            if (size > 0 && off + 4 * size > d.size) malformed()
        }

        private fun parseTables(): ParsedDex {
            checkHeader()
            val stringSize = u4(STRING_IDS_SIZE)
            val stringOff = u4(STRING_IDS_OFF)
            val typeSize = u4(TYPE_IDS_SIZE)
            val typeOff = u4(TYPE_IDS_OFF)
            requireTable(stringOff, stringSize)
            requireTable(typeOff, typeSize)
            val seen = BitSet()
            var i = 0L
            while (i < typeSize) {
                if (i > 0 && i % CHECK_EVERY == 0L && budget.expired()) {
                    return ParsedDex(DexOutcome.TIME_LIMIT, packages, capHit)
                }
                val idx = u4(typeOff + 4 * i)
                if (idx >= stringSize) malformed()
                if (!seen.get(idx.toInt())) {
                    seen.set(idx.toInt())
                    val dataOff = u4(stringOff + 4 * idx)
                    if (dataOff >= d.size) malformed()
                    decode(dataOff.toInt())?.let { addPackage(it) }
                }
                i++
            }
            return ParsedDex(DexOutcome.READ, packages, capHit)
        }

        /** Returns the uleb128 value at [pos] and advances [cursor]; malformed if > 5 bytes or out of range. */
        private fun uleb(pos: Int, cursor: IntArray): Int {
            var result = 0L
            for (k in 0 until MAX_ULEB_BYTES) {
                if (pos + k >= d.size) malformed()
                val b = d[pos + k].toInt() and 0xFF
                result = result or ((b and 0x7F).toLong() shl (7 * k))
                if (b and 0x80 == 0) {
                    cursor[0] = pos + k + 1
                    return result.coerceAtMost(Int.MAX_VALUE.toLong()).toInt()
                }
            }
            malformed()
        }

        /** Decodes the string at [pos], or null when it is over-long, unterminated within the bound, or invalid. */
        private fun decode(pos: Int): String? {
            val cursor = IntArray(1)
            val chars = uleb(pos, cursor)
            return if (chars > MAX_DESCRIPTOR_CHARS) null else decodeBounded(cursor[0])
        }

        private fun decodeBounded(start: Int): String? {
            val limit = minOf(d.size.toLong(), start.toLong() + 3 * MAX_DESCRIPTOR_CHARS + 1).toInt()
            var end = start
            while (end < limit && d[end] != 0.toByte()) end++
            probe?.invoke(end - start)
            return if (end >= limit) null else Mutf8.decode(d, start, end)
        }

        private fun addPackage(descriptor: String) {
            val dotted = packageOf(descriptor)
            if (dotted == null || dotted in global || dotted in packages) return
            if (packages.size >= budget.remainingPackages) capHit = true else packages.add(dotted)
        }

        /** Dotted package of a class descriptor, or null for non-class, default-package or odd names. */
        private fun packageOf(descriptor: String): String? {
            val isClass = descriptor.length in 3..MAX_DESCRIPTOR_CHARS &&
                descriptor[0] == 'L' && descriptor.last() == ';'
            val slash = if (isClass) descriptor.lastIndexOf('/') else -1
            val pkg = if (slash > 1) descriptor.substring(1, slash) else null
            val valid = pkg != null && pkg.split('/').all { SEGMENT.matcher(it).matches() }
            return if (valid) pkg?.replace('/', '.') else null
        }
    }

    private object Mutf8 {
        /** Strict MUTF-8 decode of d[from, to); null on any invalid sequence. */
        fun decode(d: ByteArray, from: Int, to: Int): String? {
            val sb = StringBuilder(to - from)
            var i = from
            while (i < to) {
                val b = d[i].toInt() and 0xFF
                val len = when {
                    b in 0x01..0x7F -> 1
                    b in 0xC0..0xDF -> 2
                    b in 0xE0..0xEF -> 3
                    else -> 0
                }
                val c = if (len == 0 || i + len > to) null else decodeOne(d, i, len)
                if (c == null) return null
                sb.append(c)
                i += len
            }
            return sb.toString()
        }

        private fun cont(d: ByteArray, i: Int): Int? {
            val b = d[i].toInt() and 0xFF
            return if (b and 0xC0 == 0x80) b and 0x3F else null
        }

        private fun decodeOne(d: ByteArray, i: Int, len: Int): Char? {
            val b = d[i].toInt() and 0xFF
            return when (len) {
                1 -> b.toChar()
                2 -> cont(d, i + 1)?.let { (((b and 0x1F) shl 6) or it).toChar() }
                else -> {
                    val c1 = cont(d, i + 1)
                    val c2 = cont(d, i + 2)
                    if (c1 == null || c2 == null) null else (((b and 0x0F) shl 12) or (c1 shl 6) or c2).toChar()
                }
            }
        }
    }

    private const val HEADER_SIZE = 0x70
    private const val STRING_IDS_SIZE = 0x38L
    private const val STRING_IDS_OFF = 0x3CL
    private const val TYPE_IDS_SIZE = 0x40L
    private const val TYPE_IDS_OFF = 0x44L
    private const val MAX_ULEB_BYTES = 5
    private const val CHECK_EVERY = 4096L
    private val SEGMENT: Pattern = Pattern.compile("^[\\p{L}\\p{N}_$-]+$")
}
