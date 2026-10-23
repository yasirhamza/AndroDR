package com.androdr.scanner

import android.content.Context
import com.androdr.sigma.SigmaRule
import com.androdr.sigma.SigmaRuleParser
import java.io.ByteArrayOutputStream
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

/** Test helpers for intrusion-log imports through a real orchestrator and session. */
internal object IntrusionLogZips {
    /** An export ZIP with one per-day entry per (name, lines). */
    fun zip(vararg entries: Pair<String, List<String>>): ByteArray {
        val out = ByteArrayOutputStream()
        ZipOutputStream(out).use { z ->
            for ((name, lines) in entries) {
                z.putNextEntry(ZipEntry(name))
                z.write(lines.joinToString("\n").toByteArray())
                z.closeEntry()
            }
        }
        return out.toByteArray()
    }

    /** An [OrchestratorFixture] with a real [IntrusionLogAnalyzer] reading [bytes] for any URI. */
    fun fixture(engine: com.androdr.sigma.SigmaRuleEngine, bytes: () -> ByteArray): OrchestratorFixture {
        val context: Context = OrchestratorFixture.serving { bytes().inputStream() }
        return OrchestratorFixture(
            engine = engine,
            intrusionLogAnalyzer = IntrusionLogAnalyzer(context, io.mockk.mockk(relaxed = true)),
        )
    }

    fun rule(id: String, service: String, field: String, value: String, level: String = "high"): SigmaRule =
        SigmaRuleParser.parse(
            """
                title: Test $id
                id: $id
                status: experimental
                description: Test
                category: incident
                logsource:
                    product: androdr
                    service: $service
                detection:
                    selection:
                        $field: $value
                    condition: selection
                level: $level
                tags:
                    - attack.t1437
                display:
                    category: app_risk
            """.trimIndent()
        )!!

    /** A real engine with [rules] loaded as remote rules. */
    fun engine(vararg rules: SigmaRule) = com.androdr.sigma.SigmaRuleEngine(io.mockk.mockk(relaxed = true)).apply {
        setRemoteRules(rules.toList())
    }
}
