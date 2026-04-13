package com.androdr.data.model

/**
 * Read-time correlationId resolution used by every consumer that groups
 * forensic timeline rows (Timeline UI, detail-sheet Linked Evidence,
 * CSV/text export). The precedence is:
 *
 *  1. The stamped `correlationId` on the row — currently `dns:<matched_domain>`
 *     set by TimelineAdapter for DNS-sourced findings, or a SIGMA correlation
 *     engine signal id like `androdr-corr-004:1,2,3`.
 *  2. `pkg:<packageName>` for any row tied to an installed package at write
 *     time.
 *  3. `pkg:<package>` recovered by parsing a structured description like
 *     `"com.example.foo used READ_CONTACTS at 2026-04-08 10:15:00"`. This
 *     catches legacy rows that lost their packageName field before commit
 *     2a6e3071 (PR #76) when AppOpsModule started stamping it explicitly.
 *
 * Why read-time instead of a write-time stamp: no migrations needed, no
 * fan-out to every module that builds a ForensicTimelineEvent, and the key
 * is idempotent and stable across reads. Timeline clustering, detail-sheet
 * Linked Evidence, and CSV export all see the same grouping.
 *
 * Lives in the `data.model` package (rather than the `ui.timeline` or
 * `reporting` packages that consume it) so both can depend on it without
 * a cross-layer import.
 */
fun ForensicTimelineEvent.effectiveCorrelationId(): String = when {
    correlationId.isNotBlank() -> correlationId
    packageName.isNotBlank() -> "pkg:$packageName"
    else -> effectivePackageFromDescription()?.let { "pkg:$it" } ?: ""
}

/**
 * Attempts to recover a package name from structured description strings
 * like `"com.example.foo used READ_CONTACTS at 2026-04-08 10:15:00"` or
 * `"Package installed: com.example.foo"`. Returns null if the description
 * doesn't match the expected prefix shape.
 *
 * Intentionally strict: the token must look like a dotted Android package
 * (lowercase leading segment, at least one dot, followed by whitespace) so
 * that free-text descriptions like `"Graphite/Paragon Spyware"` do not
 * accidentally produce a fake cluster key.
 */
private val PACKAGE_DESCRIPTION_REGEX =
    Regex("""^([a-z][a-zA-Z0-9_]*(?:\.[a-zA-Z][a-zA-Z0-9_]*)+)\s""")

fun ForensicTimelineEvent.effectivePackageFromDescription(): String? {
    if (description.isBlank()) return null
    return PACKAGE_DESCRIPTION_REGEX.find(description)?.groupValues?.get(1)
}
