package com.androdr.scanner.bugreport

import com.androdr.data.model.TimelineEvent
import com.androdr.ioc.IocResolver
import com.androdr.scanner.BugReportAnalyzer.BugReportFinding
import javax.inject.Inject
import javax.inject.Singleton

@Singleton
class AppOpsModule @Inject constructor() : BugreportModule {

    override val targetSections: List<String> = listOf("appops")

    private val riskyOps = setOf("REQUEST_INSTALL_PACKAGES")
    private val riskyPackages = setOf("com.android.shell")

    private val dangerousOps = setOf(
        "CAMERA", "RECORD_AUDIO", "READ_SMS", "RECEIVE_SMS", "SEND_SMS",
        "READ_CONTACTS", "READ_CALL_LOG", "ACCESS_FINE_LOCATION",
        "READ_EXTERNAL_STORAGE", "REQUEST_INSTALL_PACKAGES"
    )

    private val packageLineRegex = Regex("""^\s+Package\s+(\S+):""", RegexOption.MULTILINE)
    private val opLineRegex = Regex("""^\s+(\w+)\s+\((\w+)\):""", RegexOption.MULTILINE)
    private val accessLineRegex = Regex(
        """Access:\s+\[\S+]\s+(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})"""
    )
    private val uidLineRegex = Regex("""^Uid\s+(\d+):""", RegexOption.MULTILINE)

    override suspend fun analyze(sectionText: String, iocResolver: IocResolver): ModuleResult {
        val findings = mutableListOf<BugReportFinding>()
        val timeline = mutableListOf<TimelineEvent>()

        val uidBlocks = splitByUid(sectionText)

        for ((uid, block) in uidBlocks) {
            val isSystemUid = uid < 10000

            packageLineRegex.findAll(block).forEach pkgLoop@{ pkgMatch ->
                val packageName = pkgMatch.groupValues[1]
                val pkgStart = pkgMatch.range.last
                val pkgEnd = findNextPackageOrEnd(block, pkgStart)
                val pkgBlock = block.substring(pkgStart, pkgEnd)

                val iocHit = iocResolver.isKnownBadPackage(packageName)
                if (iocHit != null) {
                    findings.add(BugReportFinding(
                        severity = iocHit.severity,
                        category = "AppOpsAbuse",
                        description = "Known ${iocHit.category} package '$packageName' " +
                            "(${iocHit.name}) has recorded permission usage — " +
                            iocHit.description
                    ))
                }

                if (packageName in riskyPackages) {
                    opLineRegex.findAll(pkgBlock).forEach { opMatch ->
                        val opName = opMatch.groupValues[1]
                        findings.add(BugReportFinding(
                            severity = "HIGH",
                            category = "AppOpsAbuse",
                            description = "Shell process (com.android.shell) used " +
                                "permission '$opName' — may indicate ADB exploitation"
                        ))
                    }
                    return@pkgLoop
                }

                if (isSystemUid) return@pkgLoop

                opLineRegex.findAll(pkgBlock).forEach { opMatch ->
                    val opName = opMatch.groupValues[1]

                    if (opName in riskyOps) {
                        findings.add(BugReportFinding(
                            severity = "HIGH",
                            category = "AppOpsAbuse",
                            description = "App '$packageName' has $opName " +
                                "permission — can install APKs from unknown sources"
                        ))
                    }

                    if (opName in dangerousOps && opName !in riskyOps) {
                        val opStart = opMatch.range.last
                        val nextOp = opLineRegex.find(pkgBlock, opStart + 1)
                        val opEnd = nextOp?.range?.first ?: pkgBlock.length
                        val opBlock = pkgBlock.substring(opStart, opEnd)
                        val accessMatch = accessLineRegex.find(opBlock)
                        timeline.add(TimelineEvent(
                            timestamp = -1,
                            source = "appops",
                            category = "permission_use",
                            description = "$packageName used $opName" +
                                (accessMatch?.let { " at ${it.groupValues[1]}" } ?: ""),
                            severity = if (opName in riskyOps) "HIGH" else "INFO"
                        ))
                    }
                }
            }
        }

        return ModuleResult(findings = findings, timeline = timeline)
    }

    private fun splitByUid(text: String): List<Pair<Int, String>> {
        val matches = uidLineRegex.findAll(text).toList()
        if (matches.isEmpty()) return emptyList()

        return matches.mapIndexed { index, match ->
            val uid = match.groupValues[1].toIntOrNull() ?: 99999
            val start = match.range.first
            val end = if (index + 1 < matches.size) matches[index + 1].range.first else text.length
            uid to text.substring(start, end)
        }
    }

    private fun findNextPackageOrEnd(block: String, fromIndex: Int): Int {
        val next = packageLineRegex.find(block, fromIndex + 1)
        return next?.range?.first ?: block.length
    }
}
