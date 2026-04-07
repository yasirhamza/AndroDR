package com.androdr.scanner

/**
 * Snapshot of an in-progress (or idle) scan for the UI.
 *
 * The previous UX was a single spinning button with no indication of what was
 * happening. This model exposes stage + completion count so the Dashboard can
 * render a real progress bar and let the user see whether the scan is making
 * forward progress or stuck.
 *
 * Progress is published by [ScanOrchestrator] as a `StateFlow<ScanProgress>`.
 * The three terminal/near-terminal states are:
 *
 *  - [Idle] — no scan in progress. The initial and post-scan state.
 *  - [Running] — a scan is active. Fields describe current phase and how many
 *    individual scanners have completed out of the total.
 *
 * There is no dedicated `Completed` or `Failed` state because the scan result
 * (and any scanner failures it contains) is delivered via a separate
 * mechanism (`ScanResult` saved to Room + observed through a Flow). Collapsing
 * success/failure into the progress model would conflate "is a scan running"
 * with "what was the outcome of the last scan", which different UI components
 * want to react to independently.
 */
sealed class ScanProgress {
    object Idle : ScanProgress()

    data class Running(
        val phase: Phase,
        val completedScanners: Int,
        val totalScanners: Int
    ) : ScanProgress() {
        /**
         * Coarse scan phase. We deliberately keep this small — finer-grained
         * "which scanner is currently running" state would be unstable under
         * parallel execution (multiple scanners are running at once) and noisy
         * for the UI to follow.
         */
        enum class Phase {
            /** Running all the per-scanner telemetry collectors in parallel. */
            COLLECTING_TELEMETRY,

            /** Running SIGMA rules over the collected telemetry. */
            EVALUATING_RULES,

            /** Persisting the ScanResult and forensic timeline to Room. */
            SAVING_RESULTS
        }
    }
}
