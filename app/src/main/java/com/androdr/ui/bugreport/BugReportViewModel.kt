package com.androdr.ui.bugreport

import android.net.Uri
import android.util.Log
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.androdr.data.model.ScanResult
import com.androdr.reporting.ReportExporter
import com.androdr.scanner.ArtifactType
import com.androdr.data.store.Preflight
import com.androdr.scanner.ImportPreflight
import com.androdr.scanner.IntrusionLogStats
import com.androdr.scanner.ScanOrchestrator
import com.androdr.sigma.Finding
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch
import javax.inject.Inject

@HiltViewModel
class BugReportViewModel @Inject constructor(
    private val orchestrator: ScanOrchestrator,
    private val importPreflight: ImportPreflight,
    private val reportExporter: ReportExporter,
) : ViewModel() {

    private val _findings = MutableStateFlow<List<Finding>>(emptyList())
    val findings: StateFlow<List<Finding>> = _findings.asStateFlow()

    /**
     * The scan the last import was saved as, or null while none has completed. Its records are in
     * the store: the screen links to the Timeline filtered to this scan (C3; the hand-built
     * bug-report timeline is retired), and Export writes this scan's report.
     */
    private val _importScan = MutableStateFlow<ScanResult?>(null)
    val importScanId: StateFlow<Long?> = _importScan.map { it?.id }
        .stateIn(viewModelScope, SharingStarted.Eagerly, null)

    /** Non-null when the most recently analyzed artifact was an intrusion-log import (#342). */
    private val _intrusionLogSummary = MutableStateFlow<IntrusionLogStats?>(null)
    val intrusionLogSummary: StateFlow<IntrusionLogStats?> = _intrusionLogSummary.asStateFlow()

    /**
     * Which artifact the sniffer actually routed the last import to (#356), or
     * null while none has completed. One screen accepts both a bug report and an
     * intrusion log export, so its result copy must name what was ACTUALLY
     * analyzed — "your system diagnostic was analyzed" over an intrusion log
     * import is not a cosmetic slip in a forensic tool, it misidentifies the
     * evidence. Reset at the start of every analysis, so a failed import cannot
     * leave the previous artifact's label standing.
     */
    private val _analyzedArtifact = MutableStateFlow<ArtifactType?>(null)
    val analyzedArtifact: StateFlow<ArtifactType?> = _analyzedArtifact.asStateFlow()

    /** What the last import stored: new / already-stored / dropped-duplicate facts, tripped bounds, space notice. */
    private val _importCard = MutableStateFlow<ImportCard?>(null)
    val importCard: StateFlow<ImportCard?> = _importCard.asStateFlow()

    /** Non-null while the storage preflight waits for the user's "Import anyway" (or cancel). */
    private val _preflightPrompt = MutableStateFlow<PreflightPrompt?>(null)
    val preflightPrompt: StateFlow<PreflightPrompt?> = _preflightPrompt.asStateFlow()

    /** True while the size preflight runs (a cloud provider can take a while); picks are ignored meanwhile. */
    private val _checkingSize = MutableStateFlow(false)
    val checkingSize: StateFlow<Boolean> = _checkingSize.asStateFlow()

    /** The preflight's estimate for the import in progress, carried into its card; null when unknown. */
    private var importEstimate: Long? = null

    private val _isAnalyzing = MutableStateFlow(false)
    val isAnalyzing: StateFlow<Boolean> = _isAnalyzing.asStateFlow()

    /** True while the size check or the analysis runs; the picker is disabled meanwhile. */
    val importBusy: StateFlow<Boolean> = combine(_checkingSize, _isAnalyzing) { a, b -> a || b }
        .stateIn(viewModelScope, SharingStarted.Eagerly, false)

    /** True once an analysis has finished (success OR failure, NOT cancellation).
     *  Used to render a completion confirmation distinct from the pre-analysis
     *  idle state — the bug in #148 was that the UI couldn't tell those apart. */
    private val _analysisFinished = MutableStateFlow(false)
    val analysisFinished: StateFlow<Boolean> = _analysisFinished.asStateFlow()

    /** Non-null when the most recent analysis threw an unrecoverable error. */
    private val _errorMessage = MutableStateFlow<String?>(null)
    val errorMessage: StateFlow<String?> = _errorMessage.asStateFlow()

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
        How to create a system diagnostic for AndroDR to scan:

        1. Enable Developer Options (if not already enabled):
           • Open Settings → About Phone
           • Tap "Build Number" seven times until you see "You are now a developer!"

        2. Open Developer Options:
           • Go to Settings → System → Developer Options
             (on some devices: Settings → Developer Options)

        3. Create the system diagnostic:
           • Scroll down to find "Take Bug Report"
           • Tap it, then select "Full Report" for the most thorough scan
           • Wait for the diagnostic to be created (this can take 1–3 minutes)
           • When notified, tap the notification to share the file

        4. Import into AndroDR:
           • In the share sheet, choose "AndroDR" to import directly
           • Or save the .zip file and use the "Select Diagnostic File" button

        Note: System diagnostics contain detailed device information. Only share
        them with applications you trust. AndroDR processes everything entirely
        on your device — nothing is uploaded to external servers.
    """.trimIndent()

    /**
     * Entry point for a picked file: runs the storage preflight first. Plenty of room starts the
     * import; a tight (or unknown) estimate raises [preflightPrompt] and waits for
     * [confirmImportAnyway] or [dismissPreflight].
     */
    @Suppress("TooGenericExceptionCaught")
    fun onFilePicked(uri: Uri) {
        if (_isAnalyzing.value || _preflightPrompt.value != null || _checkingSize.value) return
        _checkingSize.value = true
        viewModelScope.launch {
            try {
                val verdict = try {
                    importPreflight.check(uri)
                } catch (e: kotlinx.coroutines.CancellationException) {
                    throw e
                } catch (e: Exception) {
                    Log.w(TAG, "preflight failed; asking with an unknown size", e)
                    null
                }
                importEstimate = (verdict as? Preflight.Tight)?.estimate
                when (verdict) {
                    Preflight.Ok -> analyzeUri(uri)
                    is Preflight.Tight -> _preflightPrompt.value = PreflightPrompt(uri, verdict.estimate, verdict.free)
                    // The measurement itself failed: say so, and never invent a free-space figure.
                    null -> _preflightPrompt.value = PreflightPrompt(uri, null, null)
                }
            } finally {
                _checkingSize.value = false
            }
        }
    }

    /** The user chose "Import anyway" on the preflight dialog. */
    fun confirmImportAnyway() {
        val prompt = _preflightPrompt.value ?: return
        _preflightPrompt.value = null
        analyzeUri(prompt.uri)
    }

    /** The user cancelled the preflight dialog; nothing is imported. */
    fun dismissPreflight() {
        _preflightPrompt.value = null
    }

    /**
     * Analyzes the imported artifact zip at the given [uri] — either a bug report
     * or an Advanced Protection Intrusion Logging export (#342); [ScanOrchestrator.analyzeArtifact]
     * sniffs which one it is.
     * Updates [isAnalyzing], [findings], [importScanId], and [intrusionLogSummary] reactively.
     */
    @Suppress("TooGenericExceptionCaught") // Artifact analysis surfaces any IO/parse error to the user.
    fun analyzeUri(uri: Uri) {
        viewModelScope.launch {
            _isAnalyzing.value = true
            _analysisFinished.value = false
            _errorMessage.value = null
            _findings.value = emptyList()
            _importScan.value = null
            _analyzedArtifact.value = null
            _importCard.value = null
            try {
                _intrusionLogSummary.value = null
                when (val analysis = orchestrator.analyzeArtifact(uri)) {
                    is ScanOrchestrator.ArtifactAnalysis.BugReport -> {
                        _findings.value = analysis.result.findings
                        _importScan.value = analysis.result.write?.scan
                        _analyzedArtifact.value = ArtifactType.BUG_REPORT
                        _importCard.value = ImportCard.from(
                            analysis.result.write, truncated = false, boundTrips = analysis.result.boundTrips,
                            estimateBytes = importEstimate, notes = analysis.result.importNotes,
                        )
                    }
                    is ScanOrchestrator.ArtifactAnalysis.IntrusionLog -> {
                        _findings.value = analysis.result.findings.filter { it.triggered }
                        _importScan.value = analysis.result.write?.scan
                        _intrusionLogSummary.value = analysis.result.stats
                        _analyzedArtifact.value = ArtifactType.INTRUSION_LOG
                        _importCard.value = ImportCard.from(
                            analysis.result.write, analysis.result.stats.truncated, emptyList(), importEstimate
                        )
                    }
                }
                _analysisFinished.value = true
            } catch (e: kotlinx.coroutines.CancellationException) {
                throw e
            } catch (e: Exception) {
                val raw = e.message ?: e::class.simpleName ?: "Unknown error"
                // Cap to keep zip/IO exception messages (which often embed
                // long content:// URIs and stack-frame-like strings) from
                // overflowing the error card on small screens.
                _errorMessage.value = if (raw.length > MAX_ERROR_MESSAGE_LEN) {
                    raw.take(MAX_ERROR_MESSAGE_LEN) + "…"
                } else {
                    raw
                }
                _analysisFinished.value = true
            } finally {
                _isAnalyzing.value = false
            }
        }
    }

    /**
     * Exports the last import's report (its findings and its stored records) to a cached text file
     * through the one report path ([ReportExporter.export], spec §7) and emits its FileProvider URI
     * via [shareUri] for sharing. Does nothing until an import has been saved.
     */
    fun exportReport() {
        if (_exporting.value) return
        val scan = _importScan.value ?: return
        viewModelScope.launch {
            _exporting.value = true
            try {
                _shareUri.value = reportExporter.export(scan)
            } finally {
                _exporting.value = false
            }
        }
    }

    /** Call after the share intent has been launched to reset the URI state. */
    fun onShareConsumed() {
        _shareUri.value = null
    }

    private companion object {
        const val MAX_ERROR_MESSAGE_LEN = 280
        const val TAG = "BugReportViewModel"
    }
}
