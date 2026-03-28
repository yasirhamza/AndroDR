package com.androdr.scanner.bugreport

import java.io.BufferedReader
import java.io.InputStream
import java.io.InputStreamReader
import java.util.zip.ZipInputStream

class DumpsysSectionParser {

    companion object {
        private val DUMP_HEADER = Regex("""^-*\s*DUMP OF SERVICE (\S+?):\s*$""")
        private val DASHED_HEADER = Regex("""^-+ SERVICE (\S+?) -+$""")
        private val SYSTEM_PROPS_HEADER = Regex("""^-+\s*SYSTEM PROPERTIES\s*-+$""")
        private val GENERIC_DASHED_SECTION = Regex("""^-{3,}\s*\S.*\S\s*-{3,}$""")

        private fun isDelimiter(line: String): Boolean =
            DUMP_HEADER.containsMatchIn(line) || DASHED_HEADER.containsMatchIn(line)

        private fun isSectionBoundary(line: String): Boolean =
            isDelimiter(line) || GENERIC_DASHED_SECTION.containsMatchIn(line)

        private fun extractServiceName(line: String): String? =
            DUMP_HEADER.find(line)?.groupValues?.get(1)
                ?: DASHED_HEADER.find(line)?.groupValues?.get(1)
    }

    fun extractSection(stream: InputStream, serviceName: String): String? =
        extractSections(stream, setOf(serviceName))[serviceName]

    fun extractSections(
        stream: InputStream,
        serviceNames: Set<String>
    ): Map<String, String> {
        val results = mutableMapOf<String, StringBuilder>()
        var currentSection: String? = null

        BufferedReader(InputStreamReader(stream, Charsets.UTF_8)).use { reader ->
            reader.forEachLine { line ->
                val name = extractServiceName(line)
                if (name != null) {
                    currentSection = if (name in serviceNames) {
                        results[name] = StringBuilder()
                        name
                    } else {
                        null
                    }
                } else if (currentSection != null) {
                    results[currentSection!!]!!.appendLine(line)
                }
            }
        }

        return results.mapValues { it.value.toString() }
    }

    fun extractSystemProperties(stream: InputStream): String? {
        val sb = StringBuilder()
        var inSection = false

        BufferedReader(InputStreamReader(stream, Charsets.UTF_8)).use { reader ->
            var line = reader.readLine()
            while (line != null) {
                when {
                    !inSection && SYSTEM_PROPS_HEADER.containsMatchIn(line) -> inSection = true
                    inSection && (isSectionBoundary(line) || SYSTEM_PROPS_HEADER.containsMatchIn(line)) ->
                        return sb.toString()
                    inSection -> sb.appendLine(line)
                }
                line = reader.readLine()
            }
        }

        return if (inSection) sb.toString() else null
    }

    fun iterateZipEntries(
        zipStream: ZipInputStream,
        namePattern: Regex
    ): Sequence<Pair<String, InputStream>> = sequence {
        var entry = try { zipStream.nextEntry } catch (_: Exception) { null }
        while (entry != null) {
            if (!entry.isDirectory && namePattern.containsMatchIn(entry.name)) {
                yield(entry.name to (zipStream as InputStream))
            }
            try { zipStream.closeEntry() } catch (_: Exception) { }
            entry = try { zipStream.nextEntry } catch (_: Exception) { null }
        }
    }
}
