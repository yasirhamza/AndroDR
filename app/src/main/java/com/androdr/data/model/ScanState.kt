package com.androdr.data.model

import kotlinx.serialization.Serializable

/**
 * Lifecycle of a [ScanResult] row (telemetry store, spec §5.1–5.2). Only [COMPLETE] scans are
 * visible to readers; [IN_PROGRESS] (a writer session is open, or was killed) and [DELETING]
 * (a delete started) are hidden and finished by the startup sweep. Persisted by name.
 */
@Serializable
enum class ScanState { IN_PROGRESS, COMPLETE, DELETING }
