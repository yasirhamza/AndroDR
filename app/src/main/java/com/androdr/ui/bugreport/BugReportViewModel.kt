package com.androdr.ui.bugreport

import android.net.Uri
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.androdr.scanner.BugReportAnalyzer
import com.androdr.scanner.ScanOrchestrator
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import javax.inject.Inject

@HiltViewModel
class BugReportViewModel @Inject constructor(
    private val orchestrator: ScanOrchestrator
) : ViewModel() {

    private val _findings = MutableStateFlow<List<BugReportAnalyzer.BugReportFinding>>(emptyList())
    val findings: StateFlow<List<BugReportAnalyzer.BugReportFinding>> = _findings.asStateFlow()

    private val _isAnalyzing = MutableStateFlow(false)
    val isAnalyzing: StateFlow<Boolean> = _isAnalyzing.asStateFlow()

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
     * Updates [isAnalyzing] and [findings] reactively.
     */
    fun analyzeUri(uri: Uri) {
        viewModelScope.launch {
            _isAnalyzing.value = true
            _findings.value = emptyList()
            try {
                _findings.value = orchestrator.analyzeBugReport(uri)
            } finally {
                _isAnalyzing.value = false
            }
        }
    }
}
