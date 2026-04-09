// app/src/main/java/com/androdr/sigma/SigmaRuleParser.kt
package com.androdr.sigma

import org.snakeyaml.engine.v2.api.Load
import org.snakeyaml.engine.v2.api.LoadSettings
import android.util.Log

/**
 * Thrown when a SIGMA rule document contains a required-field violation that must
 * surface loudly to the developer (e.g. missing or invalid 'category').  Unlike a
 * generic parse failure, this exception is NOT swallowed by the outer try/catch
 * in [SigmaRuleParser.parse] / [SigmaRuleParser.parseAll] — it propagates to the
 * caller so that bundled rules with bad metadata are impossible to ship silently.
 */
class SigmaRuleParseException(message: String) : RuntimeException(message)

object SigmaRuleParser {

    private const val TAG = "SigmaRuleParser"
    internal const val MAX_REGEX_LENGTH = 500
    private const val CORRELATION_TIMESPAN_CAP_DAYS = 90
    private val TIMESPAN_REGEX = Regex("""^(\d+)([smhd])$""")
    private val settings = LoadSettings.builder()
        .setMaxAliasesForCollections(10)
        .setAllowDuplicateKeys(false)
        .build()

    @Suppress("CyclomaticComplexMethod", "LongMethod", "ThrowsCount")
    fun parseCorrelation(yaml: String): CorrelationRule {
        val load = Load(settings)
        @Suppress("UNCHECKED_CAST")
        val root = load.loadFromString(yaml) as? Map<String, Any?>
            ?: throw CorrelationParseException.InvalidGrammar("<unknown>", "top-level YAML is not a map")
        val id = root["id"] as? String
            ?: throw CorrelationParseException.InvalidGrammar("<unknown>", "missing id")
        val title = root["title"] as? String ?: id

        val corr = root["correlation"].asStringMap(id, "correlation")

        val typeStr = corr["type"] as? String
            ?: throw CorrelationParseException.InvalidGrammar(id, "missing correlation.type")
        val type = when (typeStr) {
            "temporal_ordered" -> CorrelationType.TEMPORAL_ORDERED
            "event_count"      -> CorrelationType.EVENT_COUNT
            "temporal"         -> CorrelationType.TEMPORAL
            else -> throw CorrelationParseException.UnsupportedType(id, typeStr)
        }

        val rules = corr["rules"].asStringList(id, "rules")
        if (rules.isEmpty()) {
            throw CorrelationParseException.InvalidGrammar(id, "rules list is empty")
        }

        val timespanStr = corr["timespan"] as? String
            ?: throw CorrelationParseException.InvalidGrammar(id, "missing timespan")
        val timespanMs = parseTimespan(id, timespanStr)

        val groupBy = if (corr.containsKey("group-by")) {
            corr["group-by"].asStringList(id, "group-by")
        } else {
            emptyList()
        }

        val minEvents = if (type == CorrelationType.EVENT_COUNT) {
            val cond = corr["condition"].asStringMap(id, "condition")
            (cond["gte"] as? Number)?.toInt()
                ?: throw CorrelationParseException.InvalidGrammar(
                    id,
                    "event_count requires condition.gte (Int), got ${cond["gte"]}"
                )
        } else {
            1
        }

        val display = if (root.containsKey("display")) {
            root["display"].asStringMap(id, "display")
        } else {
            emptyMap()
        }
        val severity = display["severity"] as? String ?: "medium"
        val label = display["label"] as? String ?: title
        val category = display["category"] as? String ?: "correlation"

        return CorrelationRule(
            id = id,
            title = title,
            type = type,
            referencedRuleIds = rules,
            timespanMs = timespanMs,
            groupBy = groupBy,
            minEvents = minEvents,
            severity = severity,
            displayLabel = label,
            displayCategory = category
        )
    }

    @Suppress("ThrowsCount") // each throw reports a distinct grammar error for rule authors
    private fun parseTimespan(ruleId: String, raw: String): Long {
        val m = TIMESPAN_REGEX.matchEntire(raw.trim())
            ?: throw CorrelationParseException.InvalidGrammar(ruleId, "invalid timespan '$raw'")
        val value = m.groupValues[1].toLong()
        val unit = m.groupValues[2]
        val ms = when (unit) {
            "s" -> value * 1_000L
            "m" -> value * 60_000L
            "h" -> value * 3_600_000L
            "d" -> value * 86_400_000L
            else -> throw CorrelationParseException.InvalidGrammar(ruleId, "invalid timespan unit '$unit'")
        }
        if (ms > CORRELATION_TIMESPAN_CAP_DAYS * 86_400_000L) {
            throw CorrelationParseException.TimespanExceeded(ruleId, raw, CORRELATION_TIMESPAN_CAP_DAYS)
        }
        return ms
    }

    @Suppress("UNCHECKED_CAST", "TooGenericExceptionCaught")
    fun parse(yamlContent: String): SigmaRule? {
        return try {
            val load = Load(settings)
            val doc = load.loadFromString(yamlContent) as? Map<String, Any> ?: return null
            parseDocument(doc)
        } catch (e: SigmaRuleParseException) {
            throw e
        } catch (e: Exception) {
            Log.w(TAG, "Failed to parse SIGMA rule: ${e.message}")
            null
        }
    }

    @Suppress("UNCHECKED_CAST", "TooGenericExceptionCaught")
    fun parseAll(yamlContent: String): List<SigmaRule> {
        return try {
            val load = Load(settings)
            load.loadAllFromString(yamlContent)
                .filterIsInstance<Map<String, Any>>()
                .mapNotNull { parseDocument(it) }
        } catch (e: SigmaRuleParseException) {
            throw e
        } catch (e: Exception) {
            Log.w(TAG, "Failed to parse SIGMA rules: ${e.message}")
            emptyList()
        }
    }

    @Suppress("TooGenericExceptionCaught", "ReturnCount", "ThrowsCount")
    private fun parseDocument(doc: Map<String, Any>): SigmaRule? {
        return try {
            val logsource = doc["logsource"] as? Map<*, *> ?: return null
            val detectionMap = doc["detection"] as? Map<*, *> ?: return null

            val ruleId = doc["id"]?.toString() ?: return null
            val level = doc["level"]?.toString() ?: "medium"

            val categoryString = doc["category"] as? String
                ?: throw SigmaRuleParseException(
                    "Rule $ruleId is missing required 'category' field. " +
                    "Must declare 'category: incident' or 'category: device_posture'. " +
                    "See docs/detection-rules-catalog.md for the categorization principle."
                )

            val category = when (categoryString.lowercase()) {
                "incident" -> RuleCategory.INCIDENT
                "device_posture" -> RuleCategory.DEVICE_POSTURE
                else -> throw SigmaRuleParseException(
                    "Rule $ruleId has invalid category '$categoryString'. " +
                    "Must be 'incident' or 'device_posture'."
                )
            }

            val enabled = (doc["enabled"] as? Boolean) ?: true

            SigmaRule(
                id = ruleId,
                title = doc["title"]?.toString() ?: "",
                status = doc["status"]?.toString() ?: "experimental",
                description = doc["description"]?.toString() ?: "",
                product = logsource["product"]?.toString() ?: "",
                service = logsource["service"]?.toString() ?: "",
                level = level,
                category = category,
                tags = (doc["tags"] as? List<*>)?.map { it.toString() } ?: emptyList(),
                detection = parseDetection(detectionMap),
                falsepositives = (doc["falsepositives"] as? List<*>)?.map { it.toString() } ?: emptyList(),
                remediation = (doc["remediation"] as? List<*>)?.map { it.toString() } ?: emptyList(),
                display = parseDisplay(doc["display"] as? Map<*, *>),
                enabled = enabled
            )
        } catch (e: SigmaRuleParseException) {
            throw e
        } catch (e: Exception) {
            Log.w(TAG, "Failed to parse SIGMA document: ${e.message}")
            null
        }
    }

    private fun parseDetection(detectionMap: Map<*, *>): SigmaDetection {
        val condition = detectionMap["condition"]?.toString() ?: "selection"
        val selections = mutableMapOf<String, SigmaSelection>()

        for ((key, value) in detectionMap) {
            val keyStr = key.toString()
            if (keyStr == "condition") continue
            if (value is Map<*, *>) {
                selections[keyStr] = parseSelection(value)
            }
        }

        return SigmaDetection(selections = selections, condition = condition)
    }

    private fun parseSelection(selectionMap: Map<*, *>): SigmaSelection {
        val matchers = mutableListOf<SigmaFieldMatcher>()

        for ((key, value) in selectionMap) {
            val keyStr = key.toString()
            val (fieldName, modifier) = parseFieldAndModifier(keyStr)

            val values: List<Any> = when (value) {
                is List<*> -> value.filterNotNull()
                null -> emptyList()
                else -> listOf(value)
            }

            // Validate regex patterns at parse time: reject patterns that are
            // too long (> MAX_REGEX_LENGTH chars) to reduce ReDoS surface area.
            if (modifier == SigmaModifier.RE) {
                val validValues = values.filter { pattern ->
                    val p = pattern.toString()
                    if (p.length > MAX_REGEX_LENGTH) {
                        Log.w(TAG, "Rejecting regex pattern exceeding $MAX_REGEX_LENGTH chars: ${p.take(50)}...")
                        false
                    } else {
                        true
                    }
                }
                if (validValues.isEmpty()) {
                    Log.w(TAG, "All regex patterns rejected for field '$fieldName'; skipping matcher")
                    continue
                }
                matchers.add(SigmaFieldMatcher(
                    fieldName = fieldName,
                    modifier = modifier,
                    values = validValues
                ))
            } else {
                matchers.add(SigmaFieldMatcher(
                    fieldName = fieldName,
                    modifier = modifier,
                    values = values
                ))
            }
        }

        return SigmaSelection(fieldMatchers = matchers)
    }

    private fun parseDisplay(displayMap: Map<*, *>?): SigmaDisplay {
        if (displayMap == null) return SigmaDisplay()
        return SigmaDisplay(
            category = displayMap["category"]?.toString() ?: "device_posture",
            icon = displayMap["icon"]?.toString() ?: "",
            triggeredTitle = displayMap["triggered_title"]?.toString() ?: "",
            safeTitle = displayMap["safe_title"]?.toString() ?: "",
            evidenceType = displayMap["evidence_type"]?.toString() ?: "none",
            summaryTemplate = displayMap["summary_template"]?.toString() ?: "",
            guidance = displayMap["guidance"]?.toString() ?: ""
        )
    }

    private fun Any?.asStringMap(ruleId: String, field: String): Map<String, Any?> {
        @Suppress("UNCHECKED_CAST")
        return (this as? Map<String, Any?>)
            ?: throw CorrelationParseException.InvalidGrammar(
                ruleId,
                "$field: expected mapping, got ${this?.javaClass?.simpleName ?: "null"}"
            )
    }

    private fun Any?.asStringList(ruleId: String, field: String): List<String> {
        val list = (this as? List<*>)
            ?: throw CorrelationParseException.InvalidGrammar(
                ruleId,
                "$field: expected list, got ${this?.javaClass?.simpleName ?: "null"}"
            )
        return list.mapIndexed { idx, item ->
            item as? String
                ?: throw CorrelationParseException.InvalidGrammar(ruleId, "$field[$idx] must be a string")
        }
    }

    private fun parseFieldAndModifier(key: String): Pair<String, SigmaModifier> {
        val parts = key.split("|")
        val fieldName = parts[0]
        val modifier = if (parts.size > 1) {
            when (parts[1].lowercase()) {
                "contains" -> SigmaModifier.CONTAINS
                "startswith" -> SigmaModifier.STARTSWITH
                "endswith" -> SigmaModifier.ENDSWITH
                "re" -> SigmaModifier.RE
                "gte" -> SigmaModifier.GTE
                "lte" -> SigmaModifier.LTE
                "gt" -> SigmaModifier.GT
                "lt" -> SigmaModifier.LT
                "ioc_lookup" -> SigmaModifier.IOC_LOOKUP
                else -> SigmaModifier.EQUALS
            }
        } else {
            SigmaModifier.EQUALS
        }
        return fieldName to modifier
    }
}
