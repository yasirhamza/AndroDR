package com.androdr.data.model

import kotlinx.serialization.Serializable

/**
 * Provenance classification for every telemetry row. Identifies where the
 * data came from so analysts and rules can filter by source when needed.
 *
 * Telemetry is source-agnostic by design: the same canonical type (e.g.
 * [AppOpsTelemetry]) can be produced by multiple sources. A live-device
 * scanner emits `LIVE_SCAN`; a bugreport parser emits `BUGREPORT_IMPORT`.
 * Rules evaluate the telemetry uniformly regardless of source.
 *
 * **Every telemetry data class has a required `source: TelemetrySource`
 * field with no default.** Each constructor call must name it explicitly —
 * this prevents accidental "implicit LIVE_SCAN" drift and makes the source
 * visible in code review.
 *
 * See `docs/superpowers/specs/2026-04-09-unified-telemetry-findings-refactor-design.md`
 * §4 for the full rationale.
 */
@Serializable
enum class TelemetrySource {
    /**
     * Produced by a runtime scanner against the current device state.
     * Examples: [AppTelemetry] from `AppScanner`, [DeviceTelemetry] from
     * `DeviceAuditor`, [ForensicTimelineEvent] from `UsageStatsScanner`.
     */
    LIVE_SCAN,

    /**
     * Produced by parsing an imported Android bugreport file. Plan 5 wires
     * up the first producers. Existing rule code paths must not assume
     * LIVE_SCAN without checking this field.
     */
    BUGREPORT_IMPORT,
}
