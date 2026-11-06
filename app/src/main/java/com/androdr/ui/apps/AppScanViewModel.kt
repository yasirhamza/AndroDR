package com.androdr.ui.apps

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.androdr.data.db.PrivacyDao
import com.androdr.data.repo.FindingsRepository
import com.androdr.data.repo.SettingsRepository
import com.androdr.privacy.AppPrivacyRow
import com.androdr.privacy.InstalledVersions
import com.androdr.privacy.PrivacyRanking
import com.androdr.sigma.Finding
import com.androdr.sigma.FindingCategory
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.flatMapLatest
import kotlinx.coroutines.flow.flowOf
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.stateIn
import javax.inject.Inject

@HiltViewModel
class AppScanViewModel @Inject constructor(
    private val findings: FindingsRepository,
    privacyDao: PrivacyDao,
    settings: SettingsRepository,
    private val installedVersions: InstalledVersions
) : ViewModel() {

    /**
     * The last privacy scan's tracker rows, keyed by package, kept only where the stored version is the one
     * installed now: an app updated since the scan has no row (its stored evidence describes older code).
     * Only apps with tracker evidence get a line, so only those are looked up in the package manager; Room
     * re-emits equal lists while a new privacy scan writes its rows, which [distinctUntilChanged] absorbs.
     */
    @OptIn(ExperimentalCoroutinesApi::class)
    val privacyByPackage: StateFlow<PrivacyCrossover> = privacyDao.latestCompleted()
        .distinctUntilChanged()
        .flatMapLatest { scan ->
            if (scan == null) {
                flowOf(PrivacyCrossover(null, emptyMap()))
            } else {
                combine(
                    privacyDao.results(scan.id).distinctUntilChanged(),
                    privacyDao.evidence(scan.id).distinctUntilChanged(),
                    settings.refusedTrackerCategories.distinctUntilChanged()
                ) { results, evidence, refused ->
                    val rows = PrivacyRanking.rows(results, evidence, refused, showSystemApps = true)
                        .flatMap { it.second }
                        .filter { it.trackers.isNotEmpty() }
                    val installed = installedVersions.versionCodes(rows.map { it.packageName })
                    PrivacyCrossover(
                        scannedAt = scan.finishedAt ?: scan.startedAt,
                        byPackage = rows.filter { installed[it.packageName] == it.versionCode }
                            .associateBy { it.packageName }
                    )
                }
            }
        }
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), PrivacyCrossover(null, emptyMap()))

    /**
     * Risks attributable to a specific installed app from the latest runtime scan.
     *
     * A finding appears here only if it carries a `package_name` in its
     * matchContext — i.e. some SIGMA rule matched on an `AppTelemetry`
     * record. DNS-sourced rules (androdr-003 Malicious
     * Domain, etc.) fire on `DnsEvent` records that have no associated
     * package (UID = -1 on the VPN path), so they are filtered out of the
     * Apps screen and remain visible on the Timeline + Network screens.
     *
     * This keeps the Apps screen dedicated to genuine app issues —
     * detected malware, dangerous permissions, sideloads, impersonators —
     * instead of mixing in a bogus "Network Detections" bucket for every
     * blocked domain.
     */
    val appFindings: StateFlow<List<Finding>> = findings.latestLive()
        .map { latest ->
            latest?.findings
                ?.filter { finding ->
                    finding.category == FindingCategory.APP_RISK &&
                        finding.matchContext["package_name"]?.isNotBlank() == true
                }
                ?: emptyList()
        }
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), emptyList())

    private val _filterLevel = MutableStateFlow<String?>(null)

    /** The currently active risk-level filter; null means show all. */
    val filterLevel: StateFlow<String?> = _filterLevel.asStateFlow()

    /**
     * Findings grouped by package name, filtered by [filterLevel], and sorted
     * by highest severity across the group descending.
     */
    val filteredGroupedApps: StateFlow<List<AppGroup>> =
        combine(appFindings, _filterLevel) { findings, level ->
            val filtered = if (level == null) findings
            else findings.filter { it.level.equals(level, ignoreCase = true) }

            // By construction `appFindings` only contains findings whose
            // matchContext carries a non-blank package_name, so the !! is
            // safe and grouping cannot produce a synthetic "unknown" bucket.
            filtered
                .groupBy { it.matchContext["package_name"]!! }
                .map { (pkg, pkgFindings) ->
                    val appName = pkgFindings.firstNotNullOfOrNull {
                        it.matchContext["app_name"]
                    } ?: pkg
                    val highestLevel = pkgFindings.maxOfOrNull { levelScore(it.level) } ?: 0
                    val highestLevelStr = pkgFindings.maxByOrNull { levelScore(it.level) }?.level ?: "low"
                    AppGroup(
                        packageName = pkg,
                        appName = appName,
                        highestLevel = highestLevelStr,
                        highestScore = highestLevel,
                        findings = pkgFindings.sortedByDescending { levelScore(it.level) }
                    )
                }
                .sortedByDescending { it.highestScore }
        }.stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), emptyList())

    /** Updates the active filter. Pass null to show all risk levels. */
    fun setFilter(level: String?) {
        _filterLevel.value = level
    }
}

/** Privacy-scan rows for packages whose installed version is the scanned one; [scannedAt] dates the scan. */
data class PrivacyCrossover(val scannedAt: Long?, val byPackage: Map<String, AppPrivacyRow>)

/** A group of findings for a single package. */
data class AppGroup(
    val packageName: String,
    val appName: String,
    val highestLevel: String,
    val highestScore: Int,
    val findings: List<Finding>
)

private fun levelScore(level: String): Int = when (level.lowercase()) {
    "critical" -> 4
    "high" -> 3
    "medium" -> 2
    else -> 1
}
