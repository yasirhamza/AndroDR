package com.androdr.data.model

/**
 * One Advanced Protection Intrusion Logging security_event record (#342).
 * `securityData` is the tag-specific value array emitted verbatim — typed
 * per-tag extraction is deferred until real fixtures validate the layouts
 * (spec 2026-08-22-intrusion-log-import §11.1).
 */
data class SecurityLogEvent(
    val timestamp: Long,
    val tag: Int,
    val tagName: String,
    val securityData: List<String>,
    val source: TelemetrySource,
    val capturedAt: Long
)
