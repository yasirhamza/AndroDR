package com.androdr.scanner

import android.content.Context
import android.net.Uri
import android.util.Log
import com.androdr.data.model.TimelineEvent
import com.androdr.ioc.IocResolver
import com.androdr.scanner.bugreport.BugreportModule
import com.androdr.scanner.bugreport.DumpsysSectionParser
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
    private val iocResolver: IocResolver,
    private val modules: Set<@JvmSuppressWildcards BugreportModule>
) {

    data class BugReportFinding(
        val severity: String,
        val category: String,
        val description: String
    )

    private val sectionParser = DumpsysSectionParser()

    /**
     * Analyzes a bug report zip identified by [bugReportUri].
     *
     * The method opens the zip through the [android.content.ContentResolver], iterates
     * all entries, dispatches section-targeted modules against parsed dumpsys sections
     * and raw-entry modules against all ZIP entries, then aggregates findings.
     */
    // Two-pass ZIP processing with section extraction and module dispatch — the linear flow
    // through both passes is clearer as a single function than split across helpers.
    @Suppress("LongMethod", "TooGenericExceptionCaught") // LongMethod: see above;
    // TooGenericExceptionCaught: ContentResolver and ZipInputStream can throw any IOException
    // subclass; errors are converted to BugReportFinding entries with ERROR severity.
    suspend fun analyze(bugReportUri: Uri): List<BugReportFinding> = withContext(Dispatchers.IO) {
        val findings = mutableListOf<BugReportFinding>()
        val timelineEvents = mutableListOf<TimelineEvent>()

        // Separate modules into section-targeted vs raw-entry
        val sectionModules = modules.filter { it.targetSections != null }
        val rawModules = modules.filter { it.targetSections == null }

        // Collect all target section names needed by section modules
        val neededSections = sectionModules.flatMap { it.targetSections!! }.toSet()

        // ── Pass 1: Stream through ZIP to extract dumpsys sections ───────────
        // Only the needed section strings are held in memory (a few MB each),
        // not the entire ZIP contents.
        if (sectionModules.isNotEmpty() && neededSections.isNotEmpty()) {
            val stream1 = openBugReportStream(bugReportUri, findings)
                ?: return@withContext findings

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
                            val sections = sectionParser.extractSections(
                                zip, // stream directly — no buffering into byte[]
                                neededSections
                            )

                            // Only break if we actually found sections — otherwise
                            // try the next dumpstate-like entry.
                            if (sections.isNotEmpty()) {
                                for (mod in sectionModules) {
                                    for (sectionName in mod.targetSections!!) {
                                        val sectionText = sections[sectionName] ?: continue
                                        val result = mod.analyze(sectionText, iocResolver)
                                        findings.addAll(result.findings)
                                        timelineEvents.addAll(result.timeline)
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
                findings.add(
                    BugReportFinding(
                        severity = "ERROR",
                        category = "IO",
                        description = "Failed to read zip contents (pass 1): ${e.message}"
                    )
                )
                return@withContext findings
            }
        }

        // ── Pass 2: Re-open URI, stream raw entries to raw modules ───────────
        // Each entry is streamed directly to modules without buffering into memory.
        if (rawModules.isNotEmpty()) {
            val stream2 = openBugReportStream(bugReportUri, findings)
                ?: return@withContext findings

            try {
                ZipInputStream(stream2.buffered()).use { zip ->
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
                        findings.addAll(result.findings)
                        timelineEvents.addAll(result.timeline)
                    }
                }
            } catch (e: Exception) {
                findings.add(
                    BugReportFinding(
                        severity = "ERROR",
                        category = "IO",
                        description = "Failed to read zip contents (pass 2): ${e.message}"
                    )
                )
            }
        }

        Log.d("BugReportAnalyzer", "Collected ${timelineEvents.size} timeline events")
        findings
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
