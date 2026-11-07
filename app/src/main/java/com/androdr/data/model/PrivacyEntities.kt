package com.androdr.data.model

import androidx.room.Entity
import androidx.room.PrimaryKey

/** State of the optional network step of a privacy scan; stored in [PrivacyScan.networkStatus] as `name`. */
enum class NetworkStatus { PENDING, COMPLETE, TRUNCATED, FAILED }

/** One privacy scan. Separate from [ScanResult]; never part of History or exports. */
@Entity(tableName = "privacy_scan")
data class PrivacyScan(
    @PrimaryKey(autoGenerate = true) val id: Long = 0,
    val startedAt: Long,
    val finishedAt: Long?,
    val appsTotal: Int,
    val appsInspected: Int,
    val appsPartial: Int,
    val appsFailed: Int,
    val registrySize: Int,
    val registrySha256: String,
    val dnsWindowStart: Long,
    /** UTC calendar days in the window with at least one attributed lookup. */
    val dnsCoverageDays: Int,
    /** Oldest usage event available; null = no usage access. */
    val usageCoverageFrom: Long?,
    /** [NetworkStatus] name; inserted as PENDING. */
    val networkStatus: String
)

@Entity(tableName = "privacy_app_result", primaryKeys = ["scanId", "packageName"])
data class PrivacyAppResult(
    val scanId: Long,
    val packageName: String,
    val versionCode: Long,
    val appLabel: String,
    val isSystemApp: Boolean,
    /** InspectOutcome name. */
    val outcome: String,
    val reason: String?
)

@Entity(tableName = "privacy_tracker_evidence", primaryKeys = ["scanId", "packageName", "trackerId"])
data class PrivacyTrackerEvidence(
    val scanId: Long,
    val packageName: String,
    val trackerId: Int,
    val trackerName: String,
    val website: String,
    /** Raw labels, joined with U+001F. */
    val categories: String,
    val inCode: Boolean,
    val lookups: Int,
    val lookupDays: Int,
    /** Null = unknown. */
    val background: Int?,
    val firstSeen: Long?,
    val lastSeen: Long?,
    val newSinceLastScan: Boolean
)

/** Per-app cache of the code packages read from an APK; never selected by UI queries. */
@Entity(tableName = "privacy_package_set", primaryKeys = ["packageName"])
data class PrivacyPackageSet(
    val packageName: String,
    val versionCode: Long,
    val lastUpdateTime: Long,
    val readerVersion: Int,
    /** Packages joined with newline. */
    val packagesText: String
)
