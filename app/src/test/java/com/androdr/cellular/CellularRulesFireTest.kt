package com.androdr.cellular

import com.androdr.data.model.CellularSnapshot
import com.androdr.data.model.TelemetrySource
import com.androdr.sigma.SigmaRuleEvaluator
import com.androdr.sigma.SigmaRuleParser
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * Proves every shipped cellular rule CAN fire against a snapshot the emitter
 * could actually produce, and does NOT fire on a benign one.
 *
 * This exists because androdr-101 shipped as a dead rule: it matched on
 * `bandwidth_khz`, which this hardware reports as Integer.MAX_VALUE in every
 * record, so the emitter always normalized it to null and the rule could never
 * match. A rule that cannot fire is worse than no rule — it creates a false
 * sense of coverage. Every rule here is therefore pinned to a concrete
 * triggering snapshot built from the real data class.
 */
class CellularRulesFireTest {

    private fun rawDir(): File = listOf(
        File("app/src/main/res/raw"),
        File("src/main/res/raw"),
    ).firstOrNull { it.isDirectory } ?: error("res/raw not found")

    private fun rule(name: String) =
        SigmaRuleParser.parse(File(rawDir(), name).readText())
            ?: error("failed to parse $name")

    /** A realistic, benign serving cell as measured on the reference device. */
    private fun benign() = CellularSnapshot(
        mcc = "427", mnc = "01", tac = 1437, ci = 192816407L, pci = 167,
        earfcn = 1600, bands = listOf(3),
        // Always null on real hardware — the sentinel that killed androdr-101.
        bandwidthKhz = null,
        rat = "LTE", operatorAlphaLong = "Ooredoo", operatorAlphaShort = "Ooredoo",
        additionalPlmns = emptyList(), neighborCount = 13, servingRsrp = -84,
        isRegistered = true, capturedAt = 1000L, source = TelemetrySource.LIVE_SCAN,
        previousTac = 1437, previousRat = "LTE", tacChanged = false, ratChanged = false,
        tacChangesLast5m = 0, servingMinusMaxNeighborRsrpDb = 8,
        locationMovedMLast5m = null,
    )

    private fun fires(ruleFile: String, snapshot: CellularSnapshot): Boolean =
        SigmaRuleEvaluator.evaluate(
            listOf(rule(ruleFile)), listOf(snapshot.toFieldMap()),
            "cellular_monitor", emptyMap(), emptyMap()
        ).any { it.triggered }

    @Test
    fun `androdr-102 fires on an isolated cell and not on a normal one`() {
        val f = "sigma_androdr_102_cell_isolated.yml"
        assertTrue("must fire with no neighbours", fires(f, benign().copy(neighborCount = 0)))
        assertTrue("must not fire with 13 neighbours", !fires(f, benign()))
    }

    @Test
    fun `androdr-103 fires on an LTE to GSM downgrade only`() {
        val f = "sigma_androdr_103_cell_rat_downgrade.yml"
        assertTrue(
            "must fire on LTE -> GSM",
            fires(f, benign().copy(previousRat = "LTE", rat = "GSM", ratChanged = true))
        )
        assertTrue(
            "must fire on NR -> UMTS",
            fires(f, benign().copy(previousRat = "NR", rat = "UMTS", ratChanged = true))
        )
        assertTrue("must not fire staying on LTE", !fires(f, benign()))
        assertTrue(
            "must not fire on an UPGRADE from GSM to LTE",
            !fires(f, benign().copy(previousRat = "GSM", rat = "LTE", ratChanged = true))
        )
    }

    @Test
    fun `androdr-104 fires at the churn threshold and not below it`() {
        val f = "sigma_androdr_104_cell_tac_churn.yml"
        assertTrue("must fire at 3 changes", fires(f, benign().copy(tacChangesLast5m = 3)))
        assertTrue("must fire above 3", fires(f, benign().copy(tacChangesLast5m = 7)))
        assertTrue("must not fire at 2", !fires(f, benign().copy(tacChangesLast5m = 2)))
    }

    @Test
    fun `androdr-106 fires when the operator name contradicts the PLMN`() {
        val f = "sigma_androdr_106_cell_operator_mismatch_ooredoo.yml"
        assertTrue(
            "must fire when 427-01 claims another name",
            fires(f, benign().copy(operatorAlphaLong = "Not Ooredoo"))
        )
        assertTrue("must not fire on the genuine name", !fires(f, benign()))
    }

    @Test
    fun `no cellular rule fires on an unregistered snapshot`() {
        // Every v1 rule requires is_registered: true, which is what keeps the
        // blanked-field case from producing false positives.
        val unregistered = benign().copy(
            isRegistered = false, tac = null, ci = null, neighborCount = 0,
        )
        listOf(
            "sigma_androdr_102_cell_isolated.yml",
            "sigma_androdr_104_cell_tac_churn.yml",
            "sigma_androdr_106_cell_operator_mismatch_ooredoo.yml",
        ).forEach { f ->
            assertTrue("$f must not fire when unregistered", !fires(f, unregistered))
        }
    }
}
