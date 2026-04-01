package com.androdr.ui.apps

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.androdr.data.repo.ScanRepository
import com.androdr.data.repo.ScanRepository.Companion.preferRuntimeScan
import com.androdr.sigma.Finding
import com.androdr.sigma.FindingCategory
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.stateIn
import javax.inject.Inject

@HiltViewModel
class AppScanViewModel @Inject constructor(
    private val repository: ScanRepository
) : ViewModel() {

    /** All APP_RISK findings from the latest runtime scan (matches dashboard). */
    val appFindings: StateFlow<List<Finding>> = repository.allScans
        .map { scans ->
            scans.preferRuntimeScan()?.findings
                ?.filter { it.category == FindingCategory.APP_RISK }
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

            filtered
                .groupBy { it.matchContext["package_name"] ?: "unknown" }
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
