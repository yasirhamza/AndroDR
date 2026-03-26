// app/src/main/java/com/androdr/sigma/SigmaRuleEvaluator.kt
package com.androdr.sigma

data class Finding(
    val ruleId: String,
    val title: String,
    val level: String,
    val tags: List<String>,
    val remediation: List<String>,
    val matchedRecord: Map<String, Any?>
)

/**
 * Evaluates SIGMA rules against telemetry field maps.
 * Pure function: (rules, telemetry) → findings.
 */
object SigmaRuleEvaluator {

    fun evaluate(
        rules: List<SigmaRule>,
        records: List<Map<String, Any?>>,
        service: String,
        iocLookups: Map<String, (Any) -> Boolean> = emptyMap()
    ): List<Finding> {
        val matchingRules = rules.filter { it.service == service }
        val findings = mutableListOf<Finding>()

        for (record in records) {
            for (rule in matchingRules) {
                if (evaluateCondition(rule.detection, record, iocLookups)) {
                    findings.add(Finding(
                        ruleId = rule.id,
                        title = rule.title,
                        level = rule.level,
                        tags = rule.tags,
                        remediation = rule.remediation,
                        matchedRecord = record
                    ))
                }
            }
        }

        return findings
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

    @Suppress("CyclomaticComplexMethod")
    private fun evaluateFieldMatcher(
        matcher: SigmaFieldMatcher,
        record: Map<String, Any?>,
        iocLookups: Map<String, (Any) -> Boolean>
    ): Boolean {
        val fieldValue = record[matcher.fieldName]

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
                    Regex(pattern.toString()).containsMatchIn(strValue)
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

        var result = selectionResults[tokens[0]] ?: false
        var i = 1
        while (i < tokens.size - 1) {
            val operator = tokens[i].lowercase()
            val operand = selectionResults[tokens[i + 1]] ?: false
            result = when (operator) {
                "and" -> result && operand
                "or" -> result || operand
                else -> result
            }
            i += 2
        }

        return result
    }
}
