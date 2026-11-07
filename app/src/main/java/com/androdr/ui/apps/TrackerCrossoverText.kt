package com.androdr.ui.apps

import android.content.res.Resources
import com.androdr.R
import com.androdr.privacy.AppPrivacyRow
import com.androdr.privacy.InspectOutcome

/**
 * The Apps-tab tracker line. Facts only (spec §4.2): the "in code" count covers only trackers found in the app's
 * code; trackers seen only on the network are a separate "looked up domains of" clause, never counted as code;
 * a partly inspected app says so, and an app whose code was not read never states a code count.
 */
object TrackerCrossoverText {

    fun line(row: AppPrivacyRow, res: Resources): String {
        val inCode = row.trackers.count { it.inCode }
        val networkOnly = row.trackers.size - inCode
        return buildString {
            if (row.outcome == InspectOutcome.COULD_NOT_INSPECT) {
                append(res.getString(R.string.apps_tracker_not_inspected))
                if (networkOnly > 0) {
                    append(res.getQuantityString(R.plurals.apps_tracker_network_only, networkOnly, networkOnly))
                }
            } else {
                append(res.getQuantityString(R.plurals.apps_tracker_line, row.refusedInCode, inCode, row.refusedInCode))
                if (networkOnly > 0) append(res.getString(R.string.apps_tracker_network_more, networkOnly))
                if (row.outcome == InspectOutcome.PARTIAL) {
                    append(" (").append(res.getString(R.string.privacy_partly_inspected_tag)).append(')')
                }
            }
        }
    }
}
