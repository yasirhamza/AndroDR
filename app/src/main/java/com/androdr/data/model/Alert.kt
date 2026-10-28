package com.androdr.data.model

import androidx.room.ColumnInfo
import androidx.room.Entity
import androidx.room.Index
import androidx.room.PrimaryKey

/**
 * The lasting record of one incident (spec §5.4 `alert`): opened by the first finding with its
 * [alertKey], kept across scans, closed only by a person. Never deleted — deleting scans or
 * "Clear all" keeps it, its [evidenceJson] and the fact its [recordId] pins.
 *
 * @property evidenceJson the authoritative evidence: the opening finding, with its `matchContext`.
 * @property lastActivityAt when a finding last attached; re-surfaces the alert in the list.
 * @property matchedValue the evidence's matched value (the alert-key discriminator's value): the
 *   open-alerts list groups by rule and this, so a flood of one indicator cannot bury another.
 */
@Entity(
    tableName = "alert",
    indices = [
        Index(value = ["alertKey"], unique = true),
        Index(value = ["ruleId", "status"]),
        Index("recordId"),
        Index(value = ["status", "lastActivityAt"]),
        Index(value = ["status", "ruleId", "matchedValue", "lastActivityAt"]),
    ],
)
@Suppress("LongParameterList")
class Alert(
    @PrimaryKey(autoGenerate = true)
    val id: Long = 0,
    val alertKey: ByteArray,
    val ruleId: String,
    val status: AlertStatus,
    val openedAt: Long,
    val openedScanId: Long,
    val lastActivityAt: Long,
    val closedAt: Long? = null,
    val closedReason: String? = null,
    @ColumnInfo(defaultValue = "0")
    val closedWithCredential: Boolean = false,
    val level: String,
    val recordId: Long?,
    val evidenceJson: String,
    @ColumnInfo(defaultValue = "")
    val matchedValue: String = "",
)
