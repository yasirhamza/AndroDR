package com.androdr.scanner

import android.content.Context
import android.net.Uri
import android.util.Log
import com.androdr.data.model.ForensicTimelineEvent
import com.androdr.data.model.TimelineEvent
import com.androdr.ioc.IndicatorResolver
import com.androdr.scanner.bugreport.BugreportModule
import com.androdr.scanner.bugreport.DumpsysSectionParser
import com.androdr.scanner.bugreport.InstallTimeModule
import com.androdr.sigma.Finding
import com.androdr.sigma.SigmaRuleEngine
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.InputStream
import java.util.zip.ZipInputStream
import javax.inject.Inject
import javax.inject.Singleton

@Singleton
class BugReportAnalyzer @Inject constructor(
    @ApplicationContext private val context: Context,
    private val iocResolver: IndicatorResolver,
    private val modules: Set<@JvmSuppressWildcards BugreportModule>,
    private val sigmaRuleEngine: SigmaRuleEngine
) {

    private companion object {
        private const val TAG = "BugReportAnalyzer"
    }

    data class BugReportFinding(
        val severity: String,
        val category: String,
        val description: String
    )

    data class BugReportAnalysisResult(
        val findings: List<Finding>,
        val legacyFindings: List<BugReportFinding>,
        val timeline: List<TimelineEvent>,
        val forensicEvents: List<ForensicTimelineEvent> = emptyList()
    )

    private val sectionParser = DumpsysSectionParser()
    private val installTimeModule = InstallTimeModule()

    /**
     * Analyzes a bug report zip identified by [bugReportUri].
     *
     * The method opens the zip through the [android.content.ContentResolver], iterates
     * all entries, dispatches section-targeted modules against parsed dumpsys sections
     * and raw-entry modules against all ZIP entries, then aggregates findings.
     *
     * Telemetry-producing modules have their output evaluated by the SIGMA rule engine
     * to produce [Finding] objects. Legacy modules produce [BugReportFinding] directly.
     */
    // Two-pass ZIP processing with section extraction and module dispatch — the linear flow
    // through both passes is clearer as a single function than split across helpers.
    @Suppress("LongMethod", "TooGenericExceptionCaught") // LongMethod: see above;
    // TooGenericExceptionCaught: ContentResolver and ZipInputStream can throw any IOException
    // subclass; errors are converted to BugReportFinding entries with ERROR severity.
    suspend fun analyze(bugReportUri: Uri): BugReportAnalysisResult = withContext(Dispatchers.IO) {
        val allFindings = mutableListOf<Finding>()
        val allLegacyFindings = mutableListOf<BugReportFinding>()
        val allTimelineEvents = mutableListOf<TimelineEvent>()
        val allForensicEvents = mutableListOf<ForensicTimelineEvent>()

        // Separate modules into section-targeted vs raw-entry
        val sectionModules = modules.filter { it.targetSections != null }
        val rawModules = modules.filter { it.targetSections == null }

        // Collect all target section names needed by section modules
        val neededSections = sectionModules.flatMap { it.targetSections!! }.toSet()

        // ── Pass 1: Stream through ZIP to extract dumpsys sections ───────────
        // Only the needed section strings are held in memory (a few MB each),
        // not the entire ZIP contents.
        if (sectionModules.isNotEmpty() && neededSections.isNotEmpty()) {
            val stream1 = openBugReportStream(bugReportUri, allLegacyFindings)
                ?: return@withContext BugReportAnalysisResult(
                    allFindings, allLegacyFindings, allTimelineEvents, allForensicEvents
                )

            try {
                ZipInputStream(stream1.buffered()).use { zip ->
                    var entry = zip.nextEntry
                    while (entry != null) {
                        // Match the main dumpstate file: top-level entries like
                        // "dumpstate.txt" or "bugreport-*.txt", NOT nested paths
                        // like "FS/vendor/.../dumpstate-default.xml".
                        val entryFileName = entry.name.substringAfterLast("/").lowercase()
                        val isDumpstate = !entry.isDirectory && (
                            entryFileName == "dumpstate.txt" ||
                            entryFileName.startsWith("bugreport-") &&
                                entryFileName.endsWith(".txt")
                        )
                        if (isDumpstate) {
                            Log.d(TAG, "Found dumpstate entry: ${entry.name}, needed sections: $neededSections")
                            val sections = sectionParser.extractSections(
                                zip, // stream directly — no buffering into byte[]
                                neededSections
                            )
                            Log.d(TAG, "Extracted ${sections.size} sections: ${sections.keys}, " +
                                "sizes: ${sections.mapValues { it.value.length }}")

                            // Only break if we actually found sections — otherwise
                            // try the next dumpstate-like entry.
                            if (sections.isNotEmpty()) {
                                // InstallTimeModule: parse the `package` section
                                // to emit package_install ForensicTimelineEvents.
                                // Interchangeable with runtime InstallEventEmitter
                                // output — same shape, isFromBugreport = true.
                                sections["package"]?.let { packageSection ->
                                    allForensicEvents.addAll(
                                        installTimeModule.parseSection(packageSection)
                                    )
                                }
                                for (mod in sectionModules) {
                                    for (sectionName in mod.targetSections!!) {
                                        val sectionText = sections[sectionName] ?: continue
                                        Log.d(TAG, "Dispatching section '$sectionName' " +
                                            "(${sectionText.length} chars) to ${mod.javaClass.simpleName}")
                                        val result = mod.analyze(sectionText, iocResolver)
                                        Log.d(TAG, "${mod.javaClass.simpleName} produced " +
                                            "${result.telemetry.size} telemetry, ${result.timeline.size} timeline")
                                        processModuleResult(result, allFindings, allLegacyFindings, allTimelineEvents)
                                    }
                                }
                                break
                            }
                        }
                        try {
                            zip.closeEntry()
                        } catch (_: Exception) { /* ignore close errors */ }
                        entry = try { zip.nextEntry } catch (_: Exception) { null }
                    }
                }
            } catch (e: Exception) {
                allLegacyFindings.add(
                    BugReportFinding(
                        severity = "ERROR",
                        category = "IO",
                        description = "Failed to read zip contents (pass 1): ${e.message}"
                    )
                )
                return@withContext BugReportAnalysisResult(
                    allFindings, allLegacyFindings, allTimelineEvents, allForensicEvents
                )
            }
        }

        // ── Pass 2: Re-open URI, stream raw entries to raw modules ───────────
        // Each entry is streamed directly to modules without buffering into memory.
        if (rawModules.isNotEmpty()) {
            val stream2 = openBugReportStream(bugReportUri, allLegacyFindings)
                ?: return@withContext BugReportAnalysisResult(
                    allFindings, allLegacyFindings, allTimelineEvents, allForensicEvents
                )

            try {
                ZipInputStream(stream2.buffered()).use { zip ->
                    // NOTE: The entrySequence is backed by a live ZipInputStream and can only be
                    // consumed once. This works because there is currently only one raw module
                    // (LegacyScanModule). If additional raw modules are added, entries must be
                    // buffered or the stream re-opened.
                    val entrySequence = sequence {
                        var entry = zip.nextEntry
                        while (entry != null) {
                            if (!entry.isDirectory) {
                                yield(entry.name to (zip as InputStream))
                            }
                            try {
                                zip.closeEntry()
                            } catch (_: Exception) { /* ignore close errors */ }
                            entry = try { zip.nextEntry } catch (_: Exception) { null }
                        }
                    }

                    for (mod in rawModules) {
                        val result = mod.analyzeRaw(entrySequence, iocResolver)
                        processModuleResult(result, allFindings, allLegacyFindings, allTimelineEvents)
                    }
                }
            } catch (e: Exception) {
                allLegacyFindings.add(
                    BugReportFinding(
                        severity = "ERROR",
                        category = "IO",
                        description = "Failed to read zip contents (pass 2): ${e.message}"
                    )
                )
            }
        }

        Log.d(TAG, "Collected ${allTimelineEvents.size} timeline events, " +
            "${allFindings.size} SIGMA findings, ${allLegacyFindings.size} legacy findings")
        BugReportAnalysisResult(allFindings, allLegacyFindings, allTimelineEvents, allForensicEvents)
    }

    /**
     * Processes a [com.androdr.scanner.bugreport.ModuleResult]: evaluates telemetry through
     * the SIGMA rule engine and collects legacy findings and timeline events.
     */
    private fun processModuleResult(
        result: com.androdr.scanner.bugreport.ModuleResult,
        allFindings: MutableList<Finding>,
        allLegacyFindings: MutableList<BugReportFinding>,
        allTimelineEvents: MutableList<TimelineEvent>
    ) {
        if (result.telemetry.isNotEmpty()) {
            allFindings.addAll(
                sigmaRuleEngine.evaluateGeneric(result.telemetry, result.telemetryService)
            )
        }
        allLegacyFindings.addAll(result.legacyFindings)
        allTimelineEvents.addAll(result.timeline)
    }

    /**
     * Opens the bug report URI via ContentResolver and returns the stream,
     * or adds an error finding and returns null.
     */
    // Module execution can throw any exception; errors are caught and logged rather than
    // crashing the analysis — catching Exception is intentional here.
    @Suppress("TooGenericExceptionCaught")
    private fun openBugReportStream(
        bugReportUri: Uri,
        findings: MutableList<BugReportFinding>
    ): InputStream? {
        val stream = try {
            context.contentResolver.openInputStream(bugReportUri)
        } catch (e: Exception) {
            findings.add(
                BugReportFinding(
                    severity = "ERROR",
                    category = "IO",
                    description = "Could not open bug report file: ${e.message}"
                )
            )
            return null
        }

        if (stream == null) {
            findings.add(
                BugReportFinding(
                    severity = "ERROR",
                    category = "IO",
                    description = "ContentResolver returned null stream for the provided URI"
                )
            )
        }
        return stream
    }

    /**
     * Returns user-readable instructions for generating a bug report on Android.
     *
     * These instructions guide the user through using the built-in "Share bug report"
     * feature available in Developer Options.
     */
    fun getInstructions(): String = """
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
}
