package com.androdr.sigma

sealed class CorrelationParseException(message: String) : RuntimeException(message) {
    class UnsupportedType(ruleId: String, type: String) :
        CorrelationParseException("Rule $ruleId uses unsupported correlation type '$type'. Supported: temporal_ordered, event_count, temporal.")

    class TimespanExceeded(ruleId: String, requested: String, capDays: Int) :
        CorrelationParseException("Rule $ruleId timespan '$requested' exceeds the engine cap of $capDays days.")

    class UnresolvedRule(ruleId: String, missing: String) :
        CorrelationParseException("Rule $ruleId references unknown rule '$missing'. Make sure the referenced rule is loaded.")

    class InvalidGrammar(ruleId: String, detail: String) :
        CorrelationParseException("Rule $ruleId has invalid correlation grammar: $detail")
}
