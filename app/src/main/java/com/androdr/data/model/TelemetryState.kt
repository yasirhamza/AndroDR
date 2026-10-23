package com.androdr.data.model

import kotlinx.serialization.Serializable

/**
 * What a [ScanResult] holds in the telemetry store (spec §4, §5.2). [NONE]: the scan predates
 * the store (its rows are its only record). [STORED]: every observation was written.
 * [PARTIAL_RETENTION]: retention removed some observations. [FAILED]: storage failed and the
 * scan finished evaluate-only. Persisted by name.
 */
@Serializable
enum class TelemetryState { NONE, STORED, PARTIAL_RETENTION, FAILED }
