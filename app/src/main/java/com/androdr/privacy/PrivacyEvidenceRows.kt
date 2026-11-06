package com.androdr.privacy

import com.androdr.data.model.PrivacyAppResult
import com.androdr.data.model.PrivacyTrackerEvidence
import com.androdr.privacy.NetworkEvidenceCorrelator.Key
import com.androdr.privacy.NetworkEvidenceCorrelator.NetworkEvidence
import com.androdr.privacy.model.Tracker
import com.androdr.privacy.model.TrackerSet

/** Merges a scan's in-code and network findings into stored evidence rows. */
internal object PrivacyEvidenceRows {
    const val CATEGORY_SEPARATOR = "\u001F"

    fun build(
        scanId: Long,
        set: TrackerSet,
        inCode: Map<String, Set<Tracker>>,
        network: Map<Key, NetworkEvidence>,
        isNew: (key: Key, inCode: Boolean) -> Boolean,
    ): List<PrivacyTrackerEvidence> {
        val byId = HashMap<Int, Tracker>()
        for (t in set.trackers) byId.putIfAbsent(t.id, t)
        val codeKeys = inCode.flatMapTo(HashSet()) { (pkg, trackers) -> trackers.map { Key(pkg, it.id) } }
        return (codeKeys + network.keys).mapNotNull { key ->
            val tracker = byId[key.trackerId] ?: return@mapNotNull null
            val net = network[key]
            PrivacyTrackerEvidence(
                scanId = scanId,
                packageName = key.packageName,
                trackerId = tracker.id,
                trackerName = tracker.name,
                website = tracker.website,
                categories = tracker.rawCategories.joinToString(CATEGORY_SEPARATOR),
                inCode = key in codeKeys,
                lookups = net?.lookups ?: 0,
                lookupDays = net?.days ?: 0,
                background = net?.background,
                firstSeen = net?.first,
                lastSeen = net?.last,
                newSinceLastScan = isNew(key, key in codeKeys),
            )
        }
    }

    /**
     * New = absent from the previous completed scan's evidence for an app that scan fully INSPECTED. Nothing is new
     * on a first scan, for an app the previous scan did not have, or one it could not fully inspect. A network-only
     * pair is never new unless the previous scan's network step was COMPLETE ([previousNetworkComplete]): a truncated
     * or failed step may simply have missed it.
     */
    fun newSince(
        previousResults: List<PrivacyAppResult>?,
        previousEvidence: List<PrivacyTrackerEvidence>?,
        previousNetworkComplete: Boolean,
    ): (key: Key, inCode: Boolean) -> Boolean {
        if (previousResults == null || previousEvidence == null) return { _, _ -> false }
        val inspected = previousResults.filter { it.outcome == InspectOutcome.INSPECTED.name }
            .mapTo(HashSet()) { it.packageName }
        val before = previousEvidence.mapTo(HashSet()) { Key(it.packageName, it.trackerId) }
        return { key, inCode ->
            (inCode || previousNetworkComplete) && key.packageName in inspected && key !in before
        }
    }
}
