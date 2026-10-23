package com.androdr.data.db

import com.androdr.data.model.SignalMember

/**
 * The fact pin test (spec §5.1 Pins): a fact is pinned while a `forensic_timeline` row, a
 * `signal_member` fact ref, a triggered `scan_finding` or an `alert` points at it. One fragment
 * shared by every reader and by [TelemetryFactDao.deleteUnobservedUnpinned].
 *
 * **Fixed alias:** every fragment here refers to the fact as [ALIAS] (`f`), so a query using
 * them must name the fact table `telemetry_record f`. Room needs compile-time constant SQL, so
 * the alias is fixed rather than a parameter.
 */
object PinnedFact {
    const val ALIAS = "f"

    const val SQL = "(EXISTS (SELECT 1 FROM forensic_timeline p WHERE p.recordId = f.id) " +
        "OR EXISTS (SELECT 1 FROM signal_member m WHERE m.kind = ${SignalMember.KIND_FACT} AND m.refId = f.id) " +
        "OR EXISTS (SELECT 1 FROM scan_finding pf WHERE pf.recordId = f.id AND pf.triggered = 1) " +
        "OR EXISTS (SELECT 1 FROM alert pa WHERE pa.recordId = f.id))"

    /** True when no observation (of any scan) refers to the fact `f`. */
    const val UNOBSERVED = "NOT EXISTS (SELECT 1 FROM scan_record u WHERE u.recordId = f.id)"
}

/**
 * Fact visibility (spec §5.1 Visibility) for a fact aliased `f`: visible when an observation's
 * scan is `COMPLETE`, or when it has no observation at all **and** is pinned. An unpinned
 * orphan is never visible.
 */
object VisibleFact {
    /** The pinned-orphan half of the rule on its own (for reads that want only orphans). */
    const val PINNED_ORPHAN = "(${PinnedFact.UNOBSERVED} AND ${PinnedFact.SQL})"

    const val SQL = "(EXISTS (SELECT 1 FROM scan_record vo JOIN ScanResult vs ON vs.id = vo.scanId " +
        "WHERE vo.recordId = f.id AND vs.state = 'COMPLETE') OR $PINNED_ORPHAN)"
}

/**
 * Scan-scoped reads: the observation's own scan, joined as `ScanResult s ON s.id = o.scanId`,
 * must be `COMPLETE` (`IN_PROGRESS` and `DELETING` scans are hidden).
 */
object CompleteScan {
    const val SQL = "s.state = 'COMPLETE'"
}

/**
 * `forensic_timeline` row visibility (spec §5.1), for a row aliased [ALIAS] (`r`): persistent
 * rows, scan-less rows (`scanResultId = -1`), and rows of a `COMPLETE` scan. Used from Task C2 on.
 */
object VisibleRow {
    const val ALIAS = "r"

    const val SQL = "(r.persistent = 1 OR r.scanResultId = -1 OR EXISTS (SELECT 1 FROM ScanResult rs " +
        "WHERE rs.id = r.scanResultId AND rs.state = 'COMPLETE'))"
}
