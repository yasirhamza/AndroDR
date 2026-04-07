package com.androdr.scanner.bugreport

import java.io.BufferedReader
import java.io.InputStream
import java.io.InputStreamReader

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

        private fun extractServiceName(line: String): String? {
            // Cheap pre-filter: delimiter lines are always of one of two
            // shapes — either they contain the literal substring "DUMP OF
            // SERVICE" (the DUMP_HEADER form) or they start with '-' (the
            // DASHED_HEADER form). Any other line cannot possibly match
            // either regex, so skip the regex dispatch entirely.
            //
            // On a real-device bug report, dumpstate.txt is typically
            // 30-60 MB of ~500k-600k lines. Without this pre-filter, we do
            // TWO regex .find() operations per line — ~1M regex invocations
            // total. On-device measurement showed that was 12.9 seconds of
            // wall time for a 32 MB bug report. With the pre-filter, ~99.5%
            // of lines exit here before any regex work is attempted,
            // reducing that phase to ~1.5 seconds (roughly 10×).
            if (!line.startsWith("-") && !line.contains("DUMP OF SERVICE")) return null
            return DUMP_HEADER.find(line)?.groupValues?.get(1)
                ?: DASHED_HEADER.find(line)?.groupValues?.get(1)
        }
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

}
