// app/src/main/java/com/androdr/sigma/SigmaRuleEvaluator.kt
package com.androdr.sigma

@kotlinx.serialization.Serializable
data class Finding(
    val ruleId: String,
    val title: String,
    val description: String = "",
    val level: String,
    val category: FindingCategory = FindingCategory.DEVICE_POSTURE,
    val tags: List<String> = emptyList(),
    val remediation: List<String> = emptyList(),
    val iconHint: String = "",
    val safeTitle: String = "",
    val triggered: Boolean = true,
    val evidence: Evidence = Evidence.None,
    val matchContext: Map<String, String> = emptyMap()
)

/**
 * Evaluates SIGMA rules against telemetry field maps.
 * Pure function: (rules, telemetry) → findings.
 */
object SigmaRuleEvaluator {

    private val regexCache = java.util.concurrent.ConcurrentHashMap<String, Regex>()
    private val invalidPatterns = java.util.Collections.newSetFromMap(
        java.util.concurrent.ConcurrentHashMap<String, Boolean>()
    )
    private const val REGEX_TIMEOUT_MS = 1000L
    private const val MAX_REGEX_LENGTH = SigmaRuleParser.MAX_REGEX_LENGTH
    private const val MAX_REGEX_CACHE_SIZE = 256

    /** Modifiers that operate on string values and support list-aware element-wise matching. */
    private val STRING_MODIFIERS = setOf(
        SigmaModifier.EQUALS, SigmaModifier.CONTAINS,
        SigmaModifier.STARTSWITH, SigmaModifier.ENDSWITH, SigmaModifier.RE
    )

    // Defensive regex matching with multiple bail-out points for safety
    @Suppress("ReturnCount", "TooGenericExceptionCaught", "SwallowedException")
    private fun safeRegexMatch(pattern: String, input: String): Boolean {
        if (pattern.length > MAX_REGEX_LENGTH) return false
        if (pattern in invalidPatterns) return false

        // Evict cache if it grows beyond bound (defense against rule-sourced DoS)
        if (regexCache.size > MAX_REGEX_CACHE_SIZE) regexCache.clear()

        val regex = regexCache.getOrPut(pattern) {
            try {
                Regex(pattern)
            } catch (e: Exception) {
                invalidPatterns.add(pattern)
                return false
            }
        }

        // Run match with timeout to prevent ReDoS
        val future = java.util.concurrent.ForkJoinPool.commonPool().submit<Boolean> {
            regex.containsMatchIn(input)
        }
        return try {
            future.get(REGEX_TIMEOUT_MS, java.util.concurrent.TimeUnit.MILLISECONDS)
        } catch (e: java.util.concurrent.TimeoutException) {
            future.cancel(true)
            android.util.Log.w("SigmaRuleEvaluator", "Regex timed out (possible ReDoS): ${pattern.take(50)}...")
            false
        } catch (e: Exception) {
            false
        }
    }

    fun evaluate(
        rules: List<SigmaRule>,
        records: List<Map<String, Any?>>,
        service: String,
        iocLookups: Map<String, (Any) -> Boolean> = emptyMap(),
        evidenceProviders: Map<String, EvidenceProvider> = emptyMap()
    ): List<Finding> {
        val matchingRules = rules.filter { it.service == service }
        val findings = mutableListOf<Finding>()
        for (record in records) {
            for (rule in matchingRules) {
                val matched = evaluateCondition(rule.detection, record, iocLookups)
                val category = parseCategory(rule.display.category)
                if (matched) {
                    val evidenceType = rule.display.evidenceType
                    val provider = evidenceProviders[evidenceType]
                    if (provider != null && evidenceType != "none") {
                        val results = provider.provide(rule, record)
                        for (result in results) {
                            findings.add(buildFinding(rule, category, true, record, result))
                        }
                        if (results.isEmpty()) {
                            findings.add(buildFinding(rule, category, true, record, null))
                        }
                    } else {
                        findings.add(buildFinding(rule, category, true, record, null))
                    }
                } else if (category == FindingCategory.DEVICE_POSTURE) {
                    findings.add(buildFinding(rule, category, false, record, null))
                }
            }
        }
        return findings
    }

    private fun buildFinding(
        rule: SigmaRule, category: FindingCategory, triggered: Boolean,
        record: Map<String, Any?>, evidenceResult: EvidenceResult?
    ): Finding {
        val titleTemplate = if (triggered) {
            rule.display.triggeredTitle.ifEmpty { rule.title }
        } else {
            rule.display.safeTitle.ifEmpty { rule.title }
        }
        // Record fields provide fallback vars for templates (e.g., {file_path}),
        // evidence provider vars take precedence when present
        val recordVars = record.filterValues { it !is List<*> && it !is Map<*, *> }
            .mapValues { (_, v) -> v?.toString() ?: "" }
        val titleVars = recordVars + (evidenceResult?.titleVars ?: emptyMap())
        val remediationVars = recordVars + (evidenceResult?.remediationVars ?: emptyMap())
        return Finding(
            ruleId = rule.id,
            title = TemplateResolver.resolve(titleTemplate, titleVars),
            description = rule.description,
            level = rule.level,
            category = category,
            tags = rule.tags,
            remediation = TemplateResolver.resolveAll(rule.remediation, remediationVars),
            iconHint = rule.display.icon,
            safeTitle = TemplateResolver.resolve(rule.display.safeTitle, titleVars),
            triggered = triggered,
            evidence = evidenceResult?.evidence ?: Evidence.None,
            matchContext = record.filterValues { it !is List<*> && it !is Map<*, *> }
                .mapValues { (_, v) -> v?.toString() ?: "" }
        )
    }

    private fun parseCategory(category: String): FindingCategory = when (category.lowercase()) {
        "device_posture" -> FindingCategory.DEVICE_POSTURE
        "app_risk" -> FindingCategory.APP_RISK
        "network" -> FindingCategory.NETWORK
        else -> FindingCategory.DEVICE_POSTURE
    }

    private fun evaluateCondition(
        detection: SigmaDetection,
        record: Map<String, Any?>,
        iocLookups: Map<String, (Any) -> Boolean>
    ): Boolean {
        val selectionResults = detection.selections.mapValues { (_, selection) ->
            evaluateSelection(selection, record, iocLookups)
        }
        return evaluateConditionExpression(detection.condition, selectionResults)
    }

    private fun evaluateSelection(
        selection: SigmaSelection,
        record: Map<String, Any?>,
        iocLookups: Map<String, (Any) -> Boolean>
    ): Boolean {
        return selection.fieldMatchers.all { matcher ->
            evaluateFieldMatcher(matcher, record, iocLookups)
        }
    }

    @Suppress("CyclomaticComplexMethod", "ReturnCount")
    private fun evaluateFieldMatcher(
        matcher: SigmaFieldMatcher,
        record: Map<String, Any?>,
        iocLookups: Map<String, (Any) -> Boolean>
    ): Boolean {
        val fieldValue = record[matcher.fieldName]

        // List-aware matching: when fieldValue is a List, apply the modifier
        // element-wise and return true if ANY element matches.
        if (fieldValue is List<*> && matcher.modifier in STRING_MODIFIERS) {
            val elements = fieldValue.filterNotNull().map { it.toString() }
            return when (matcher.modifier) {
                SigmaModifier.EQUALS -> matcher.values.any { expected ->
                    elements.any { it.equals(expected.toString(), ignoreCase = true) }
                }
                SigmaModifier.CONTAINS -> matcher.values.any { expected ->
                    val exp = expected.toString().lowercase()
                    elements.any { it.lowercase().contains(exp) }
                }
                SigmaModifier.STARTSWITH -> matcher.values.any { expected ->
                    val exp = expected.toString().lowercase()
                    elements.any { it.lowercase().startsWith(exp) }
                }
                SigmaModifier.ENDSWITH -> matcher.values.any { expected ->
                    val exp = expected.toString().lowercase()
                    elements.any { it.lowercase().endsWith(exp) }
                }
                SigmaModifier.RE -> matcher.values.any { pattern ->
                    elements.any { safeRegexMatch(pattern.toString(), it) }
                }
                else -> false
            }
        }

        return when (matcher.modifier) {
            SigmaModifier.EQUALS -> {
                matcher.values.any { expected ->
                    matchEquals(fieldValue, expected)
                }
            }
            SigmaModifier.CONTAINS -> {
                val strValue = fieldValue?.toString()?.lowercase() ?: return false
                matcher.values.any { expected ->
                    strValue.contains(expected.toString().lowercase())
                }
            }
            SigmaModifier.STARTSWITH -> {
                val strValue = fieldValue?.toString()?.lowercase() ?: return false
                matcher.values.any { expected ->
                    strValue.startsWith(expected.toString().lowercase())
                }
            }
            SigmaModifier.ENDSWITH -> {
                val strValue = fieldValue?.toString()?.lowercase() ?: return false
                matcher.values.any { expected ->
                    strValue.endsWith(expected.toString().lowercase())
                }
            }
            SigmaModifier.RE -> {
                val strValue = fieldValue?.toString() ?: return false
                matcher.values.any { pattern ->
                    safeRegexMatch(pattern.toString(), strValue)
                }
            }
            SigmaModifier.GTE -> {
                val numValue = (fieldValue as? Number)?.toDouble() ?: return false
                matcher.values.any { (it as? Number)?.toDouble()?.let { e -> numValue >= e } == true }
            }
            SigmaModifier.LTE -> {
                val numValue = (fieldValue as? Number)?.toDouble() ?: return false
                matcher.values.any { (it as? Number)?.toDouble()?.let { e -> numValue <= e } == true }
            }
            SigmaModifier.GT -> {
                val numValue = (fieldValue as? Number)?.toDouble() ?: return false
                matcher.values.any { (it as? Number)?.toDouble()?.let { e -> numValue > e } == true }
            }
            SigmaModifier.LT -> {
                val numValue = (fieldValue as? Number)?.toDouble() ?: return false
                matcher.values.any { (it as? Number)?.toDouble()?.let { e -> numValue < e } == true }
            }
            SigmaModifier.IOC_LOOKUP -> {
                val lookupName = matcher.values.firstOrNull()?.toString() ?: return false
                val lookup = iocLookups[lookupName] ?: return false
                fieldValue?.let { lookup(it) } ?: false
            }
        }
    }

    @Suppress("ReturnCount")
    private fun matchEquals(fieldValue: Any?, expected: Any): Boolean {
        if (fieldValue == null) return false
        if (fieldValue is Boolean && expected is Boolean) return fieldValue == expected
        if (fieldValue is Boolean) return fieldValue == (expected.toString().toBoolean())
        if (fieldValue is Number && expected is Number) return fieldValue.toDouble() == expected.toDouble()
        return fieldValue.toString().lowercase() == expected.toString().lowercase()
    }

    internal fun evaluateConditionExpression(
        condition: String,
        selectionResults: Map<String, Boolean>
    ): Boolean {
        val tokens = condition.trim().split("\\s+".toRegex())

        if (tokens.size == 1) {
            return selectionResults[tokens[0]] ?: false
        }

        // Split into OR groups first so AND binds tighter (standard precedence)
        val orGroups = mutableListOf<List<String>>()
        var currentGroup = mutableListOf<String>()
        for (token in tokens) {
            if (token.lowercase() == "or") {
                orGroups.add(currentGroup)
                currentGroup = mutableListOf()
            } else {
                currentGroup.add(token)
            }
        }
        orGroups.add(currentGroup)

        return orGroups.any { group -> evaluateAndGroup(group, selectionResults) }
    }

    @Suppress("LoopWithTooManyJumpStatements") // Parsing loop handles "and", "not", and operands
    private fun evaluateAndGroup(
        tokens: List<String>,
        selectionResults: Map<String, Boolean>
    ): Boolean {
        if (tokens.isEmpty()) return false
        var result = true
        var i = 0
        while (i < tokens.size) {
            val token = tokens[i]
            if (token.lowercase() == "and") { i++; continue }
            val negate = token.lowercase() == "not"
            if (negate) i++
            if (i >= tokens.size) break
            var value = selectionResults[tokens[i]] ?: false
            if (negate) value = !value
            result = result && value
            i++
        }
        return result
    }
}
