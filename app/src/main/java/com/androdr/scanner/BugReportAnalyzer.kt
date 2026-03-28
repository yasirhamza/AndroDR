package com.androdr.scanner

import android.content.Context
import android.net.Uri
import com.androdr.ioc.IocResolver
import com.androdr.scanner.bugreport.BugreportModule
import com.androdr.scanner.bugreport.DumpsysSectionParser
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.ByteArrayInputStream
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
    @Suppress("TooGenericExceptionCaught") // ContentResolver and ZipInputStream can throw any
    // IOException subclass; errors are converted to BugReportFinding entries with ERROR severity.
    suspend fun analyze(bugReportUri: Uri): List<BugReportFinding> = withContext(Dispatchers.IO) {
        val findings = mutableListOf<BugReportFinding>()

        val inputStream = try {
            context.contentResolver.openInputStream(bugReportUri)
        } catch (e: Exception) {
            findings.add(
                BugReportFinding(
                    severity = "ERROR",
                    category = "IO",
                    description = "Could not open bug report file: ${e.message}"
                )
            )
            return@withContext findings
        } ?: run {
            findings.add(
                BugReportFinding(
                    severity = "ERROR",
                    category = "IO",
                    description = "ContentResolver returned null stream for the provided URI"
                )
            )
            return@withContext findings
        }

        // Separate modules into section-targeted vs raw-entry
        val sectionModules = modules.filter { it.targetSections != null }
        val rawModules = modules.filter { it.targetSections == null }

        // Collect all target section names needed by section modules
        val neededSections = sectionModules.flatMap { it.targetSections!! }.toSet()

        // Read ZIP entries into memory so we can pass them to both section and raw modules
        val entryBytes = mutableListOf<Pair<String, ByteArray>>()

        try {
            ZipInputStream(inputStream.buffered()).use { zip ->
                var entry = zip.nextEntry
                while (entry != null) {
                    if (!entry.isDirectory) {
                        val bytes = zip.readBytes()
                        entryBytes.add(entry.name to bytes)
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
                    description = "Failed to read zip contents: ${e.message}"
                )
            )
            return@withContext findings
        }

        // ── Section-targeted modules ─────────────────────────────────────────
        if (sectionModules.isNotEmpty() && neededSections.isNotEmpty()) {
            // Find the dumpstate entry (primary source of dumpsys output)
            val dumpstateEntry = entryBytes.find {
                it.first.lowercase().contains("dumpstate")
            }

            if (dumpstateEntry != null) {
                val sections = sectionParser.extractSections(
                    ByteArrayInputStream(dumpstateEntry.second),
                    neededSections
                )

                for (mod in sectionModules) {
                    for (sectionName in mod.targetSections!!) {
                        val sectionText = sections[sectionName] ?: continue
                        val result = mod.analyze(sectionText, iocResolver)
                        findings.addAll(result.findings)
                    }
                }
            }
        }

        // ── Raw-entry modules ────────────────────────────────────────────────
        for (mod in rawModules) {
            val entrySequence = entryBytes.asSequence().map { (name, bytes) ->
                name to ByteArrayInputStream(bytes) as InputStream
            }
            val result = mod.analyzeRaw(entrySequence, iocResolver)
            findings.addAll(result.findings)
        }

        findings
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
