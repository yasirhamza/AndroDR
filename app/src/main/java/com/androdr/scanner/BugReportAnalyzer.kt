package com.androdr.scanner

import android.content.Context
import android.net.Uri
import android.util.Log
import com.androdr.data.model.BatteryDailyEvent
import com.androdr.data.model.DatabasePathObservation
import com.androdr.data.model.ForensicTimelineEvent
import com.androdr.data.model.PackageInstallHistoryEntry
import com.androdr.data.model.PlatformCompatChange
import com.androdr.data.model.SystemPropertySnapshot
import com.androdr.data.model.TimelineEvent
import com.androdr.data.model.TombstoneEvent
import com.androdr.data.model.WakelockAcquisition
import com.androdr.ioc.DeviceIdentity
import com.androdr.ioc.IndicatorResolver
import com.androdr.scanner.bugreport.BugreportModule
import com.androdr.scanner.bugreport.DumpsysSectionParser
import com.androdr.scanner.bugreport.GetpropParser
import com.androdr.scanner.bugreport.InstallTimeModule
import com.androdr.scanner.bugreport.TombstoneParser
import com.androdr.scanner.bugreport.WakelockParser
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
    private val sigmaRuleEngine: SigmaRuleEngine,
    private val tombstoneParser: TombstoneParser,
    private val wakelockParser: WakelockParser,
    private val getpropParser: GetpropParser,
) {

    private companion object {
        private const val TAG = "BugReportAnalyzer"
        /** Extra sections requested by plan 6 parsers (tombstone + wakelock). */
        private val EXTRA_SECTIONS = setOf("tombstone", "power")
    }

    /**
     * Telemetry collected from bugreport modules and plan-6 parsers, ready for
     * SIGMA rule evaluation. Populated from TombstoneParser / WakelockParser
     * and the ported modules' typed outputs.
     */
    data class TelemetryBundle(
        val tombstoneEvents: List<TombstoneEvent> = emptyList(),
        val wakelockAcquisitions: List<WakelockAcquisition> = emptyList(),
        val batteryDailyEvents: List<BatteryDailyEvent> = emptyList(),
        val packageInstallHistory: List<PackageInstallHistoryEntry> = emptyList(),
        val platformCompatChanges: List<PlatformCompatChange> = emptyList(),
        val databasePathObservations: List<DatabasePathObservation> = emptyList(),
        val systemPropertySnapshots: List<SystemPropertySnapshot> = emptyList(),
    )

    data class BugReportAnalysisResult(
        val findings: List<Finding>,
        val timeline: List<TimelineEvent>,
        val forensicEvents: List<ForensicTimelineEvent> = emptyList(),
        val telemetryBundle: TelemetryBundle = TelemetryBundle(),
    )

    private val sectionParser = DumpsysSectionParser()
    private val installTimeModule = InstallTimeModule()

    /**
     * Analyzes a bug report zip identified by [bugReportUri].
     *
     * Telemetry-producing modules have their output evaluated by the SIGMA
     * rule engine to produce [Finding] objects. Plan 6 deleted the legacy
     * pattern-scan path and now routes tombstone / wakelock telemetry
     * through SigmaRuleEngine as well.
     */
    @Suppress("LongMethod", "TooGenericExceptionCaught", "CyclomaticComplexMethod")
    suspend fun analyze(bugReportUri: Uri): BugReportAnalysisResult = withContext(Dispatchers.IO) {
        val allFindings = mutableListOf<Finding>()
        val allTimelineEvents = mutableListOf<TimelineEvent>()
        val allForensicEvents = mutableListOf<ForensicTimelineEvent>()
        var tombstoneEvents: List<TombstoneEvent> = emptyList()
        var wakelockEvents: List<WakelockAcquisition> = emptyList()
        var systemPropertySnapshots: List<SystemPropertySnapshot> = emptyList()
        var sourceDevice: DeviceIdentity = DeviceIdentity.UNKNOWN

        // Pre-pass: extract SYSTEM PROPERTIES section from dumpstate to derive
        // the source device identity (#90). Without this, bugreport modules
        // evaluate conditional OEM prefixes against DeviceIdentity.UNKNOWN and
        // only unconditional prefixes apply, which silently under-suppresses
        // legitimate Samsung/Xiaomi system apps on imported Samsung/Xiaomi scans.
        try {
            openBugReportStream(bugReportUri)?.use { stream0 ->
                ZipInputStream(stream0.buffered()).use { zip ->
                    var entry = zip.nextEntry
                    while (entry != null) {
                        val name = entry.name.substringAfterLast("/").lowercase()
                        val isDumpstate = !entry.isDirectory && (
                            name == "dumpstate.txt" ||
                                (name.startsWith("bugreport-") && name.endsWith(".txt"))
                        )
                        if (isDumpstate) {
                            val sysPropsText = sectionParser.extractSystemProperties(zip)
                            if (sysPropsText != null) {
                                val now = System.currentTimeMillis()
                                systemPropertySnapshots = getpropParser.parse(
                                    sysPropsText.lineSequence(), capturedAt = now
                                )
                                val (mfgRaw, brandRaw) = getpropParser.extractManufacturerAndBrand(
                                    sysPropsText.lineSequence()
                                )
                                sourceDevice = DeviceIdentity(
                                    manufacturer = mfgRaw.trim().lowercase(),
                                    brand = brandRaw.trim().lowercase(),
                                )
                                Log.d(TAG, "Source device from bugreport: $sourceDevice, " +
                                    "${systemPropertySnapshots.size} system properties")
                            }
                            break
                        }
                        try { zip.closeEntry() } catch (_: Exception) { /* ignore */ }
                        entry = try { zip.nextEntry } catch (_: Exception) { null }
                    }
                }
            }
        } catch (e: Exception) {
            Log.w(TAG, "Failed to extract source device identity: ${e.message}")
        }

        val sectionModules = modules.filter { it.targetSections != null }
        val rawModules = modules.filter { it.targetSections == null }

        // Include plan-6 EXTRA_SECTIONS so tombstone/power are parsed alongside
        // whatever ported modules declare.
        val neededSections =
            sectionModules.flatMap { it.targetSections!! }.toSet() + EXTRA_SECTIONS

        if (neededSections.isNotEmpty()) {
            val stream1 = openBugReportStream(bugReportUri)
                ?: return@withContext BugReportAnalysisResult(
                    allFindings, allTimelineEvents, allForensicEvents
                )

            try {
                ZipInputStream(stream1.buffered()).use { zip ->
                    var entry = zip.nextEntry
                    while (entry != null) {
                        val entryFileName = entry.name.substringAfterLast("/").lowercase()
                        val isDumpstate = !entry.isDirectory && (
                            entryFileName == "dumpstate.txt" ||
                            entryFileName.startsWith("bugreport-") &&
                                entryFileName.endsWith(".txt")
                        )
                        if (isDumpstate) {
                            Log.d(TAG, "Found dumpstate entry: ${entry.name}")
                            val sections = sectionParser.extractSections(zip, neededSections)
                            Log.d(TAG, "Extracted ${sections.size} sections: ${sections.keys}")

                            if (sections.isNotEmpty()) {
                                sections["package"]?.let { packageSection ->
                                    allForensicEvents.addAll(
                                        installTimeModule.parseSection(packageSection)
                                    )
                                }
                                for (mod in sectionModules) {
                                    for (sectionName in mod.targetSections!!) {
                                        val sectionText = sections[sectionName] ?: continue
                                        val result = mod.analyze(sectionText, iocResolver, sourceDevice)
                                        processModuleResult(result, allFindings, allTimelineEvents)
                                    }
                                }

                                // Plan 6 parsers: run once per analysis.
                                val now = System.currentTimeMillis()
                                sections["tombstone"]?.let { text ->
                                    tombstoneEvents = tombstoneParser.parse(
                                        text.lineSequence(), capturedAt = now
                                    )
                                }
                                sections["power"]?.let { text ->
                                    wakelockEvents = wakelockParser.parse(
                                        text.lineSequence(),
                                        bugreportTimestamp = now,
                                        capturedAt = now,
                                    )
                                }
                                break
                            }
                        }
                        try { zip.closeEntry() } catch (_: Exception) { /* ignore */ }
                        entry = try { zip.nextEntry } catch (_: Exception) { null }
                    }
                }
            } catch (e: Exception) {
                Log.w(TAG, "Failed to read zip contents (pass 1): ${e.message}")
                return@withContext BugReportAnalysisResult(
                    allFindings, allTimelineEvents, allForensicEvents
                )
            }
        }

        // Pass 2: raw-entry modules (no dispatch needed now that LegacyScanModule is gone,
        // but kept for any future raw modules registered via Hilt IntoSet).
        if (rawModules.isNotEmpty()) {
            val stream2 = openBugReportStream(bugReportUri)
                ?: return@withContext BugReportAnalysisResult(
                    allFindings, allTimelineEvents, allForensicEvents
                )
            try {
                ZipInputStream(stream2.buffered()).use { zip ->
                    val entrySequence = sequence {
                        var entry = zip.nextEntry
                        while (entry != null) {
                            if (!entry.isDirectory) {
                                yield(entry.name to (zip as InputStream))
                            }
                            try { zip.closeEntry() } catch (_: Exception) { /* ignore */ }
                            entry = try { zip.nextEntry } catch (_: Exception) { null }
                        }
                    }
                    for (mod in rawModules) {
                        val result = mod.analyzeRaw(entrySequence, iocResolver, sourceDevice)
                        processModuleResult(result, allFindings, allTimelineEvents)
                    }
                }
            } catch (e: Exception) {
                Log.w(TAG, "Failed to read zip contents (pass 2): ${e.message}")
            }
        }

        // Plan 6: evaluate new typed telemetry via the rule engine.
        val bundle = TelemetryBundle(
            tombstoneEvents = tombstoneEvents,
            wakelockAcquisitions = wakelockEvents,
            systemPropertySnapshots = systemPropertySnapshots,
        )
        allFindings.addAll(sigmaRuleEngine.evaluateTombstones(bundle.tombstoneEvents))
        allFindings.addAll(sigmaRuleEngine.evaluateWakelocks(bundle.wakelockAcquisitions))
        allFindings.addAll(sigmaRuleEngine.evaluateBatteryDaily(bundle.batteryDailyEvents))
        allFindings.addAll(sigmaRuleEngine.evaluatePackageInstallHistory(bundle.packageInstallHistory))
        allFindings.addAll(sigmaRuleEngine.evaluatePlatformCompat(bundle.platformCompatChanges))
        allFindings.addAll(
            sigmaRuleEngine.evaluateDatabasePathObservations(bundle.databasePathObservations)
        )

        Log.d(TAG, "Collected ${allTimelineEvents.size} timeline events, " +
            "${allFindings.size} SIGMA findings")
        BugReportAnalysisResult(allFindings, allTimelineEvents, allForensicEvents, bundle)
    }

    private fun processModuleResult(
        result: com.androdr.scanner.bugreport.ModuleResult,
        allFindings: MutableList<Finding>,
        allTimelineEvents: MutableList<TimelineEvent>
    ) {
        if (result.telemetry.isNotEmpty()) {
            allFindings.addAll(
                sigmaRuleEngine.evaluateGeneric(result.telemetry, result.telemetryService)
            )
        }
        allTimelineEvents.addAll(result.timeline)
    }

    @Suppress("TooGenericExceptionCaught")
    private fun openBugReportStream(bugReportUri: Uri): InputStream? {
        return try {
            context.contentResolver.openInputStream(bugReportUri)
        } catch (e: Exception) {
            Log.w(TAG, "Could not open bug report file: ${e.message}")
            null
        }
    }

    /**
     * Returns user-readable instructions for generating a bug report on Android.
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
