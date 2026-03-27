package com.androdr.scanner

import android.content.Context
import android.net.Uri
import com.androdr.ioc.IocResolver
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.BufferedReader
import java.io.InputStream
import java.io.InputStreamReader
import java.util.zip.ZipInputStream
import javax.inject.Inject
import javax.inject.Singleton

@Singleton
class BugReportAnalyzer @Inject constructor(
    @ApplicationContext private val context: Context,
    private val iocResolver: IocResolver
) {

    data class BugReportFinding(
        val severity: String,
        val category: String,
        val description: String
    )

    // ── IOC regex patterns ────────────────────────────────────────────────────

    /** Matches process names associated with known spyware / stalkerware families. */
    private val spywareProcessRegex = Regex(
        """pegasus|spyware|flexispy|mspy|cerberus|droiddream|BIGPRETZEL|graphite""",
        RegexOption.IGNORE_CASE
    )

    /** Matches a suspicious base64 blob of 100+ characters appearing on a single log line. */
    private val base64BlobRegex = Regex(
        """[A-Za-z0-9+/]{100,}={0,2}"""
    )

    /** Matches log lines that suggest a periodic C2 beacon (HTTP POST loop pattern). */
    private val c2BeaconRegex = Regex(
        """HTTP.*POST.*every\s+[0-9]+""",
        RegexOption.IGNORE_CASE
    )

    /** Matches a fatal crash exception line in logcat output. */
    private val fatalExceptionRegex = Regex(
        """FATAL EXCEPTION:\s*(\S+)""",
        RegexOption.IGNORE_CASE
    )

    /** Matches wakelock acquisition log lines. */
    private val wakelockRegex = Regex(
        """WakeLock.*acquired""",
        RegexOption.IGNORE_CASE
    )

    /** Matches "package:" lines in the installed-packages section of a bug report dump. */
    private val installedPackageRegex = Regex(
        """^.*package:([a-zA-Z][a-zA-Z0-9._]+)""",
        RegexOption.MULTILINE
    )

    // ── Zip entry name patterns that contain useful text ─────────────────────

    private val relevantEntryNames = listOf("dumpstate", "logcat", "bugreport")

    /**
     * Analyzes a bug report zip identified by [bugReportUri].
     *
     * The method opens the zip through the [android.content.ContentResolver], iterates
     * all entries whose names contain "dumpstate", "logcat", or "bugreport", and applies
     * the IOC patterns above.  All findings are returned; callers are responsible for
     * presenting or filtering them.
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

        try {
            ZipInputStream(inputStream.buffered()).use { zip ->
                var entry = zip.nextEntry
                while (entry != null) {
                    val entryName = entry.name.lowercase()
                    val isRelevant = relevantEntryNames.any { entryName.contains(it) }

                    if (isRelevant && !entry.isDirectory) {
                        val entryFindings = analyzeTextEntry(entryName, zip as InputStream)
                        findings.addAll(entryFindings)
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
        }

        findings
    }

    /**
     * Reads a single text entry from an already-positioned [InputStream] and
     * returns all findings for that entry.  The stream is NOT closed by this method.
     */
    @Suppress("LongMethod", "CyclomaticComplexMethod", "TooGenericExceptionCaught")
    // Bug report analysis requires scanning for many IOC categories (spyware, base64, C2, crashes,
    // wakelocks, packages) in one pass over the stream; IOException on stream read is caught to
    // produce an ERROR finding rather than crashing the analysis.
    internal fun analyzeTextEntry(entryName: String, stream: InputStream): List<BugReportFinding> {
        val findings = mutableListOf<BugReportFinding>()

        // fatalCrashCounts maps process name → crash count
        val fatalCrashCounts = mutableMapOf<String, Int>()

        // Track wakelock acquisition timestamps for interval analysis (in lines, as a proxy)
        var wakelockCount = 0
        var firstWakelockLine = -1
        var lastWakelockLine = -1
        var lineNumber = 0

        try {
            BufferedReader(InputStreamReader(stream, Charsets.UTF_8)).forEachLine { line ->
                lineNumber++

                // ── Installed package list section ───────────────────────
                // Check IOC DB first; if a package hit is found, skip keyword matching on this
                // line to avoid double-counting (a package name like "com.flexispy.android" would
                // otherwise also fire the spyware keyword regex).
                var iocHitOnLine = false
                installedPackageRegex.findAll(line).forEach { match ->
                    val pkgName = match.groupValues[1]
                    val iocHit = iocResolver.isKnownBadPackage(pkgName)
                    if (iocHit != null) {
                        iocHitOnLine = true
                        findings.add(
                            BugReportFinding(
                                severity = iocHit.severity,
                                category = "KnownMalware",
                                description = "Known ${iocHit.category} package '$pkgName' " +
                                    "(${iocHit.name}) found in installed package list within " +
                                    "$entryName — ${iocHit.description}"
                            )
                        )
                    }
                }

                if (!iocHitOnLine) {
                    // ── Spyware/stalkerware process names ────────────────────
                    val spyMatch = spywareProcessRegex.find(line)
                    if (spyMatch != null) {
                        findings.add(
                            BugReportFinding(
                                severity = "CRITICAL",
                                category = "KnownMalware",
                                description = "Known spyware/stalkerware keyword '${spyMatch.value}' " +
                                    "detected in $entryName at line $lineNumber: " +
                                    line.take(200).trim()
                            )
                        )
                    }
                }

                // ── Suspicious base64 blobs ──────────────────────────────
                val b64Match = base64BlobRegex.find(line)
                if (b64Match != null) {
                    findings.add(
                        BugReportFinding(
                            severity = "HIGH",
                            category = "SuspiciousData",
                            description = "Suspicious large base64 blob (${b64Match.value.length} chars) " +
                                "in $entryName at line $lineNumber — possible exfiltration payload"
                        )
                    )
                }

                // ── C2 beacon patterns ───────────────────────────────────
                if (c2BeaconRegex.containsMatchIn(line)) {
                    findings.add(
                        BugReportFinding(
                            severity = "CRITICAL",
                            category = "C2Beacon",
                            description = "Potential C2 beacon pattern in $entryName at line $lineNumber: " +
                                line.take(200).trim()
                        )
                    )
                }

                // ── Crash loops ──────────────────────────────────────────
                val crashMatch = fatalExceptionRegex.find(line)
                if (crashMatch != null) {
                    val processName = crashMatch.groupValues[1].ifBlank { "unknown" }
                    fatalCrashCounts[processName] = (fatalCrashCounts[processName] ?: 0) + 1
                }

                // ── Wakelock acquisition tracking ────────────────────────
                if (wakelockRegex.containsMatchIn(line)) {
                    wakelockCount++
                    if (firstWakelockLine < 0) firstWakelockLine = lineNumber
                    lastWakelockLine = lineNumber
                }
            }
        } catch (e: Exception) {
            findings.add(
                BugReportFinding(
                    severity = "ERROR",
                    category = "IO",
                    description = "Error while reading entry '$entryName': ${e.message}"
                )
            )
        }

        // ── Aggregate crash loop findings ────────────────────────────────────
        for ((processName, count) in fatalCrashCounts) {
            if (count >= 3) {
                findings.add(
                    BugReportFinding(
                        severity = "HIGH",
                        category = "CrashLoop",
                        description = "Process '$processName' crashed $count times in $entryName — " +
                            "possible crash-loop from aggressive respawn (common in stalkerware)"
                    )
                )
            }
        }

        // ── Aggregate abnormal wakelock findings ─────────────────────────────
        // Flag if there are many acquisitions in a narrow range of lines (dense activity window).
        if (wakelockCount >= 10 && lastWakelockLine > firstWakelockLine) {
            val lineSpan = lastWakelockLine - firstWakelockLine
            // Density > 1 acquisition per 5 lines is suspicious
            val density = wakelockCount.toDouble() / lineSpan.coerceAtLeast(1)
            if (density > 0.2) {
                findings.add(
                    BugReportFinding(
                        severity = "MEDIUM",
                        category = "AbnormalWakelock",
                        description = "$wakelockCount WakeLock acquisitions over $lineSpan lines " +
                            "in $entryName — abnormally high density may indicate persistent " +
                            "background surveillance activity"
                    )
                )
            }
        }

        return findings
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
