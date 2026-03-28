package com.androdr.ui.bugreport

import android.content.Context
import android.net.Uri
import androidx.core.content.FileProvider
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.androdr.data.model.TimelineEvent
import com.androdr.reporting.TimelineFormatter
import com.androdr.scanner.BugReportAnalyzer
import com.androdr.scanner.ScanOrchestrator
import com.androdr.sigma.Finding
import dagger.hilt.android.lifecycle.HiltViewModel
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import javax.inject.Inject

@HiltViewModel
class BugReportViewModel @Inject constructor(
    @ApplicationContext private val appContext: Context,
    private val orchestrator: ScanOrchestrator
) : ViewModel() {

    private val _findings = MutableStateFlow<List<Finding>>(emptyList())
    val findings: StateFlow<List<Finding>> = _findings.asStateFlow()

    private val _legacyFindings = MutableStateFlow<List<BugReportAnalyzer.BugReportFinding>>(emptyList())
    val legacyFindings: StateFlow<List<BugReportAnalyzer.BugReportFinding>> = _legacyFindings.asStateFlow()

    private val _timeline = MutableStateFlow<List<TimelineEvent>>(emptyList())
    val timeline: StateFlow<List<TimelineEvent>> = _timeline.asStateFlow()

    private val _isAnalyzing = MutableStateFlow(false)
    val isAnalyzing: StateFlow<Boolean> = _isAnalyzing.asStateFlow()

    /** Emits a [Uri] when a report is ready to share; null when idle or after consumption. */
    private val _shareUri = MutableStateFlow<Uri?>(null)
    val shareUri: StateFlow<Uri?> = _shareUri.asStateFlow()

    private val _exporting = MutableStateFlow(false)
    val exporting: StateFlow<Boolean> = _exporting.asStateFlow()

    /**
     * User-facing instructions for generating a bug report.
     * Sourced from BugReportAnalyzer via the orchestrator.
     */
    val instructions: String = """
        How to generate an Android Bug Report for AndroDR analysis:

        1. Enable Developer Options (if not already enabled):
           • Open Settings → About Phone
           • Tap "Build Number" seven times until you see "You are now a developer!"

        2. Open Developer Options:
           • Go to Settings → System → Developer Options
             (on some devices: Settings → Developer Options)

        3. Generate the bug report:
           • Scroll down to find "Take Bug Report"
           • Tap it, then select "Full Report" for the most complete analysis
           • Wait for the report to be compiled (this can take 1–3 minutes)
           • When notified, tap the notification to share the report

        4. Import into AndroDR:
           • In the share sheet, choose "AndroDR" to import directly
           • Or save the .zip file and use the "Analyze Bug Report" button in AndroDR

        Note: Bug reports contain extensive system information. Only share them
        with applications you trust. AndroDR processes the report entirely on
        your device — nothing is uploaded to external servers.
    """.trimIndent()

    /**
     * Analyzes the bug report zip at the given [uri].
     * Updates [isAnalyzing], [findings], [legacyFindings], and [timeline] reactively.
     */
    fun analyzeUri(uri: Uri) {
        viewModelScope.launch {
            _isAnalyzing.value = true
            _findings.value = emptyList()
            _legacyFindings.value = emptyList()
            _timeline.value = emptyList()
            try {
                val result = orchestrator.analyzeBugReport(uri)
                _findings.value = result.findings
                _legacyFindings.value = result.legacyFindings
                _timeline.value = result.timeline
            } finally {
                _isAnalyzing.value = false
            }
        }
    }

    /**
     * Exports the current analysis results (SIGMA findings, legacy findings,
     * and timeline) to a cached text file and emits its FileProvider URI
     * via [shareUri] for sharing.
     */
    fun exportReport() {
        if (_exporting.value) return
        viewModelScope.launch {
            _exporting.value = true
            try {
                val text = TimelineFormatter.formatTimeline(
                    _timeline.value,
                    _legacyFindings.value,
                    _findings.value
                )
                _shareUri.value = withContext(Dispatchers.IO) {
                    val reportsDir = File(appContext.cacheDir, "reports").apply { mkdirs() }
                    val filenameFmt = SimpleDateFormat("yyyyMMdd_HHmmss", Locale.US)
                    val filename = "androdr_bugreport_${filenameFmt.format(Date())}.txt"
                    val reportFile = File(reportsDir, filename)
                    reportFile.writeText(text, Charsets.UTF_8)
                    FileProvider.getUriForFile(
                        appContext,
                        "${appContext.packageName}.fileprovider",
                        reportFile
                    )
                }
            } finally {
                _exporting.value = false
            }
        }
    }

    /** Call after the share intent has been launched to reset the URI state. */
    fun onShareConsumed() {
        _shareUri.value = null
    }
}
