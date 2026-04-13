package com.androdr.scanner.bugreport

import com.androdr.data.model.SystemPropertySnapshot
import com.androdr.data.model.TelemetrySource
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Parses the `getprop` section of a bugreport into [SystemPropertySnapshot]
 * telemetry. Used by [com.androdr.scanner.BugReportAnalyzer] to extract
 * the source device's manufacturer and brand for device-conditional
 * OEM classification (#90).
 *
 * Expected line format from bugreport `dumpsys` / `getprop` output:
 *
 *     [ro.product.manufacturer]: [Samsung]
 *     [ro.product.brand]: [samsung]
 *     [ro.build.fingerprint]: [samsung/a51/a51:11/...]
 *
 * The parser also accepts the alternative format sometimes seen in older
 * bugreports:
 *
 *     ro.product.manufacturer=Samsung
 *
 * Lines that don't match either format are ignored silently.
 */
@Singleton
class GetpropParser @Inject constructor() {

    /**
     * Parses [lines] and returns a list of [SystemPropertySnapshot] for every
     * recognized property.
     */
    fun parse(lines: Sequence<String>, capturedAt: Long): List<SystemPropertySnapshot> {
        val results = mutableListOf<SystemPropertySnapshot>()
        for (line in lines) {
            val parsed = parseLine(line) ?: continue
            val (key, value) = parsed
            results += SystemPropertySnapshot(
                key = key,
                value = value,
                source = TelemetrySource.BUGREPORT_IMPORT,
                capturedAt = capturedAt,
            )
        }
        return results
    }

    /**
     * Extracts the manufacturer and brand from a getprop sequence.
     * Returns a Pair(manufacturer, brand). Missing keys default to empty.
     */
    fun extractManufacturerAndBrand(lines: Sequence<String>): Pair<String, String> {
        var manufacturer = ""
        var brand = ""
        for (line in lines) {
            val parsed = parseLine(line)
            if (parsed != null) {
                when (parsed.first) {
                    "ro.product.manufacturer" -> manufacturer = parsed.second
                    "ro.product.brand" -> brand = parsed.second
                }
                if (manufacturer.isNotEmpty() && brand.isNotEmpty()) break
            }
        }
        return manufacturer to brand
    }

    private fun parseLine(line: String): Pair<String, String>? {
        val bracketMatch = BRACKET_REGEX.find(line)
        if (bracketMatch != null) {
            return bracketMatch.groupValues[1] to bracketMatch.groupValues[2]
        }
        val eqMatch = EQUALS_REGEX.find(line)
        if (eqMatch != null) {
            return eqMatch.groupValues[1] to eqMatch.groupValues[2]
        }
        return null
    }

    private companion object {
        // [ro.product.manufacturer]: [Samsung]
        val BRACKET_REGEX = Regex("""^\s*\[([^\]]+)\]:\s*\[([^\]]*)\]\s*$""")
        // ro.product.manufacturer=Samsung
        val EQUALS_REGEX = Regex("""^\s*([a-zA-Z][a-zA-Z0-9_.]*)\s*=\s*(.*?)\s*$""")
    }
}
