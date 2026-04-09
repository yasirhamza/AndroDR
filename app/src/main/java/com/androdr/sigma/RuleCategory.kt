package com.androdr.sigma

/**
 * Policy-level classification of a SIGMA rule. Drives severity cap enforcement
 * and correlation rule category propagation.
 *
 * This is DISTINCT from [FindingCategory] (DEVICE_POSTURE / APP_RISK / NETWORK),
 * which drives UI display and scoring. A rule may be classified as [INCIDENT]
 * (uncapped) while producing findings with [FindingCategory.APP_RISK] (shown on
 * the Apps screen). The two concepts are orthogonal.
 *
 * See `docs/superpowers/specs/2026-04-09-unified-telemetry-findings-refactor-design.md`
 * §6 for the full rationale.
 */
enum class RuleCategory {
    /**
     * Evidence that something happened or is actively happening: an IOC matched,
     * an app with surveillance permissions is installed, a spyware file artifact
     * exists, a known-bad domain was contacted. Attributable to a specific app,
     * event, or actor. Uncapped — may declare any severity.
     */
    INCIDENT,

    /**
     * A condition that enables future compromise but is not itself an incident:
     * bootloader unlocked, no screen lock, ADB enabled, outdated security patch,
     * exploitable CVE present. Not attributable to an active actor.
     *
     * Capped at `medium` severity regardless of declared `level:`. The engine
     * clamps findings from these rules to `min(declared, medium)` at build
     * time via [SeverityCapPolicy].
     */
    DEVICE_POSTURE,
}
