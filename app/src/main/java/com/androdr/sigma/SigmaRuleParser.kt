// app/src/main/java/com/androdr/sigma/SigmaRuleParser.kt
package com.androdr.sigma

import org.snakeyaml.engine.v2.api.Load
import org.snakeyaml.engine.v2.api.LoadSettings
import android.util.Log

object SigmaRuleParser {

    private const val TAG = "SigmaRuleParser"
    internal const val MAX_REGEX_LENGTH = 500
    private val settings = LoadSettings.builder()
        .setMaxAliasesForCollections(10)
        .setAllowDuplicateKeys(false)
        .build()

    @Suppress("UNCHECKED_CAST", "TooGenericExceptionCaught")
    fun parse(yamlContent: String): SigmaRule? {
        return try {
            val load = Load(settings)
            val doc = load.loadFromString(yamlContent) as? Map<String, Any> ?: return null
            parseDocument(doc)
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
        } catch (e: Exception) {
            Log.w(TAG, "Failed to parse SIGMA rules: ${e.message}")
            emptyList()
        }
    }

    @Suppress("TooGenericExceptionCaught", "ReturnCount")
    private fun parseDocument(doc: Map<String, Any>): SigmaRule? {
        return try {
            val logsource = doc["logsource"] as? Map<*, *> ?: return null
            val detectionMap = doc["detection"] as? Map<*, *> ?: return null

            SigmaRule(
                id = doc["id"]?.toString() ?: return null,
                title = doc["title"]?.toString() ?: "",
                status = doc["status"]?.toString() ?: "experimental",
                description = doc["description"]?.toString() ?: "",
                product = logsource["product"]?.toString() ?: "",
                service = logsource["service"]?.toString() ?: "",
                level = doc["level"]?.toString() ?: "medium",
                tags = (doc["tags"] as? List<*>)?.map { it.toString() } ?: emptyList(),
                detection = parseDetection(detectionMap),
                falsepositives = (doc["falsepositives"] as? List<*>)?.map { it.toString() } ?: emptyList(),
                remediation = (doc["remediation"] as? List<*>)?.map { it.toString() } ?: emptyList(),
                display = parseDisplay(doc["display"] as? Map<*, *>)
            )
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
