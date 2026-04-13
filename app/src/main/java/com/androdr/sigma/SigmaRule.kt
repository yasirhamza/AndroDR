// app/src/main/java/com/androdr/sigma/SigmaRule.kt
package com.androdr.sigma

data class SigmaRule(
    val id: String,
    val title: String,
    val status: String,
    val description: String,
    val product: String,
    val service: String,
    val level: String,
    val category: RuleCategory,
    val tags: List<String>,
    val detection: SigmaDetection,
    val falsepositives: List<String>,
    val remediation: List<String>,
    val display: SigmaDisplay = SigmaDisplay(),
    val enabled: Boolean = true,
    val reportSafeState: Boolean = false
)

data class SigmaDetection(
    val selections: Map<String, SigmaSelection>,
    val condition: String
)

data class SigmaSelection(
    val fieldMatchers: List<SigmaFieldMatcher>
)

data class SigmaFieldMatcher(
    val fieldName: String,
    val modifier: SigmaModifier,
    val values: List<Any>
)

enum class SigmaModifier {
    EQUALS,
    CONTAINS,
    STARTSWITH,
    ENDSWITH,
    RE,
    GTE,
    LTE,
    GT,
    LT,
    IOC_LOOKUP
}

data class SigmaDisplay(
    val category: String = "device_posture",
    val icon: String = "",
    val triggeredTitle: String = "",
    val safeTitle: String = "",
    val evidenceType: String = "none",
    val summaryTemplate: String = "",
    val guidance: String = ""
)
