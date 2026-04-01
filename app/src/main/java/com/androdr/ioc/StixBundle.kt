package com.androdr.ioc

import com.androdr.data.model.Indicator
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import java.util.UUID

private val stixJson = Json { ignoreUnknownKeys = true; prettyPrint = true }

// -- STIX2 data classes (minimal subset for indicator bundles) --

@Serializable
data class StixBundle(
    val type: String = "bundle",
    val id: String = "bundle--${UUID.randomUUID()}",
    val objects: List<StixObject>
)

@Serializable
data class StixObject(
    val type: String,
    val id: String = "",
    @SerialName("spec_version") val specVersion: String = "2.1",
    val created: String = "",
    val modified: String = "",
    val name: String = "",
    val description: String = "",
    val pattern: String = "",
    @SerialName("pattern_type") val patternType: String = "",
    @SerialName("valid_from") val validFrom: String = "",
    @SerialName("indicator_types") val indicatorTypes: List<String> = emptyList()
)

// -- Export: Indicator → STIX2 bundle --

fun List<Indicator>.toStixBundle(): String {
    val objects = map { ind ->
        val ts = java.time.Instant.ofEpochMilli(ind.fetchedAt).toString()
        StixObject(
            type = "indicator",
            id = "indicator--${UUID.randomUUID()}",
            created = ts,
            modified = ts,
            name = ind.name.ifEmpty { "${ind.type}: ${ind.value}" },
            description = ind.description,
            pattern = ind.toStixPattern(),
            patternType = "stix",
            validFrom = ts,
            indicatorTypes = listOf("malicious-activity")
        )
    }
    return stixJson.encodeToString(StixBundle.serializer(), StixBundle(objects = objects))
}

private fun Indicator.toStixPattern(): String = when (type) {
    IndicatorResolver.TYPE_PACKAGE -> "[software:name = '${escapeStix(value)}']"
    IndicatorResolver.TYPE_DOMAIN -> "[domain-name:value = '${escapeStix(value)}']"
    IndicatorResolver.TYPE_CERT_HASH -> "[x509-certificate:hashes.'SHA-256' = '${escapeStix(value)}']"
    IndicatorResolver.TYPE_APK_HASH -> "[file:hashes.'SHA-256' = '${escapeStix(value)}']"
    else -> "[software:name = '${escapeStix(value)}']"
}

private fun escapeStix(s: String) = s.replace("\\", "\\\\").replace("'", "\\'")

// -- Import: STIX2 bundle → Indicator list --

private val patternExtractors = listOf(
    Regex("""\[file:hashes\.'SHA-256'\s*=\s*'([^']+)'\]""") to IndicatorResolver.TYPE_APK_HASH,
    Regex("""\[domain-name:value\s*=\s*'([^']+)'\]""") to IndicatorResolver.TYPE_DOMAIN,
    Regex("""\[software:name\s*=\s*'([^']+)'\]""") to IndicatorResolver.TYPE_PACKAGE,
    Regex("""\[x509-certificate:hashes\.'SHA-256'\s*=\s*'([^']+)'\]""") to IndicatorResolver.TYPE_CERT_HASH,
    // MVT process name indicators (used for iOS, skip for Android)
)

fun parseStixBundle(json: String, source: String): List<Indicator> {
    val bundle = stixJson.decodeFromString(StixBundle.serializer(), json)
    val now = System.currentTimeMillis()
    return bundle.objects
        .filter { it.type == "indicator" && it.pattern.isNotEmpty() }
        .mapNotNull { obj ->
            val (type, value) = extractIndicator(obj.pattern) ?: return@mapNotNull null
            Indicator(
                type = type, value = value,
                name = obj.name, campaign = "",
                severity = "HIGH", description = obj.description,
                source = source, fetchedAt = now
            )
        }
}

private fun extractIndicator(pattern: String): Pair<String, String>? {
    for ((regex, type) in patternExtractors) {
        val match = regex.find(pattern) ?: continue
        return type to match.groupValues[1]
    }
    return null
}
