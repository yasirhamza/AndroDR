package com.androdr.cellular

import com.androdr.data.model.CaptureContext
import com.androdr.data.model.CellularSnapshot
import com.androdr.data.model.ServiceContext
import com.androdr.data.model.SimContext
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
    fun `androdr-102 does not count a read taken on a dark screen, but counts an unknown one`() {
        // Six of the 0.9.0.638 findings were idle-radio reads: a UE in
        // RRC_IDLE measures no neighbours, and nothing recorded that the
        // screen was off. Unknown screen state must not suppress.
        val f = "sigma_androdr_102_cell_isolated.yml"
        val isolated = benign().copy(neighborCount = 0)
        assertTrue("screen off: an idle radio, not isolation", !fires(f, isolated.copy(capture = screen(false))))
        assertTrue("screen on: counts", fires(f, isolated.copy(capture = screen(true))))
        assertTrue("screen unknown: still counts", fires(f, isolated.copy(capture = screen(null))))
    }

    private fun screen(interactive: Boolean?) = CaptureContext(screenInteractive = interactive)

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
    fun `androdr-104 is suppressed by proven travel and by nothing less`() {
        // "Strongest when stationary" was prose until location_moved_m_last_5m
        // was populated. The gate must only suppress what it can prove:
        // unknown movement (null) fires, as does a short walk.
        val f = "sigma_androdr_104_cell_tac_churn.yml"
        val churning = benign().copy(tacChangesLast5m = 4)
        assertTrue("moved 2 km: travel, not a fake cell", !fires(f, churning.copy(locationMovedMLast5m = 2_000)))
        assertTrue("moved exactly 500 m: travel", !fires(f, churning.copy(locationMovedMLast5m = 500)))
        assertTrue("moved 120 m: stationary enough", fires(f, churning.copy(locationMovedMLast5m = 120)))
        assertTrue("movement unknown: still fires", fires(f, churning.copy(locationMovedMLast5m = null)))
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
    fun `androdr-107 fires when the home network's name contradicts the SIM, on any operator`() {
        // 105 and 106 each hard-code one operator's strings; 107 asks the SIM.
        val f = "sigma_androdr_107_cell_name_sim_mismatch.yml"
        val home = benign().copy(sim = SimContext(plmnMatchesSim = true, operatorNameMatchesSim = true))
        val spoofedName = home.copy(sim = home.sim.copy(operatorNameMatchesSim = false))
        assertTrue("must fire when the code matches but the name does not", fires(f, spoofedName))
        assertTrue("must not fire when both agree", !fires(f, home))
        assertTrue(
            "a different network is not a name spoof",
            !fires(f, home.copy(sim = SimContext(plmnMatchesSim = false, operatorNameMatchesSim = false))),
        )
    }

    @Test
    fun `androdr-107 stays quiet while roaming and when either side is unreadable`() {
        val f = "sigma_androdr_107_cell_name_sim_mismatch.yml"
        val spoofedName = benign().copy(sim = SimContext(plmnMatchesSim = true, operatorNameMatchesSim = false))
        assertTrue(
            "a visited network shows its own name",
            !fires(f, spoofedName.copy(service = ServiceContext(isRoaming = true))),
        )
        assertTrue(
            "roaming unknown: the mismatch stands",
            fires(f, spoofedName.copy(service = ServiceContext(isRoaming = null))),
        )
        assertTrue("no SIM: nothing to compare", !fires(f, benign().copy(sim = SimContext())))
        assertTrue(
            "blank SIM name: cannot compare, not a mismatch",
            !fires(f, benign().copy(sim = SimContext(plmnMatchesSim = true, operatorNameMatchesSim = null))),
        )
    }

    @Test
    fun `every operator name a bundled rule expects survives the reader unchanged`() {
        // The reader normalises the network-chosen name before it becomes
        // data. If that normalisation touches a name a rule filters on, the
        // filter can never match and the rule fires on the genuine network:
        // androdr-105 did exactly that on a Vodafone Qatar cell when the
        // reader folded spaces. Read the expectations from the rules
        // themselves so a new rule is covered without anyone remembering.
        val nameFields = setOf("operator_alpha_long", "operator_alpha_short", "sim_operator_name")
        val files = rawDir().listFiles { f -> f.name.startsWith("sigma_androdr_") && f.name.endsWith(".yml") }!!
        val expected = files.flatMap { f ->
            val r = SigmaRuleParser.parse(f.readText()) ?: return@flatMap emptyList()
            if (r.service != "cellular_monitor") return@flatMap emptyList()
            r.detection.selections.values.flatMap { sel ->
                sel.fieldMatchers
                    .filter { it.fieldName in nameFields }
                    .flatMap { m -> m.values.map { f.name to it.toString() } }
            }
        }
        assertTrue(
            "no bundled cellular rule filters on an operator name -- is the field list stale?",
            expected.isNotEmpty(),
        )
        expected.forEach { (file, name) ->
            assertTrue(
                "$file expects operator name '$name' but the reader turns it into '${CellReader.name(name)}'",
                CellReader.name(name) == name,
            )
        }
    }

    @Test
    fun `no cellular rule fires on an unregistered snapshot`() {
        // The monitor now RECORDS a delivery with no registered cell (rat
        // UNKNOWN, identity null, is_registered false, previous_* from the
        // last registered read) instead of dropping it. Every bundled rule
        // must stay quiet on that shape: the ones gated on is_registered by
        // the gate, the RAT-downgrade rule because UNKNOWN is not a 2G/3G
        // technology even when the previous read was LTE.
        val unregistered = benign().copy(
            isRegistered = false, rat = "UNKNOWN", mcc = null, mnc = null, tac = null, ci = null, pci = null,
            earfcn = null, operatorAlphaLong = null, operatorAlphaShort = null, servingRsrp = null,
            neighborCount = 0, previousTac = 1437, previousRat = "LTE", tacChangesLast5m = 4,
            sim = SimContext(mcc = "427", mnc = "01", operatorName = "Ooredoo"),
            service = ServiceContext(state = "OUT_OF_SERVICE", isRoaming = false, dataNetworkType = "UNKNOWN"),
        )
        listOf(
            "sigma_androdr_102_cell_isolated.yml",
            "sigma_androdr_103_cell_rat_downgrade.yml",
            "sigma_androdr_104_cell_tac_churn.yml",
            "sigma_androdr_105_cell_operator_mismatch_vfqa.yml",
            "sigma_androdr_106_cell_operator_mismatch_ooredoo.yml",
            "sigma_androdr_107_cell_name_sim_mismatch.yml",
        ).forEach { f ->
            assertTrue("$f must not fire when unregistered", !fires(f, unregistered))
        }
    }
}
