package com.androdr.sigma

/**
 * One telemetry record as it is evaluated and stored: its field map plus, when the
 * producer supplies one, a stable key for the source event.
 *
 * The record builders (`*RecordBuilders`) project typed models through their
 * `toFieldMap()`; [SigmaRuleEngine.evaluateRecords] evaluates exactly these maps.
 */
data class StoreRecord(val fields: Map<String, Any?>, val sourceEventKey: String? = null)
