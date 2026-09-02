package com.androdr.cellular

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/**
 * The SIM comparison behind plmn_matches_sim / operator_name_matches_sim.
 * The nulls matter: "cannot compare" must never read as "does not match",
 * or every device without a SIM name would raise a mismatch.
 */
class SimIdentityTest {

    private val ooredoo = SimIdentity(mcc = "427", mnc = "01", operatorName = "Ooredoo")

    @Test
    fun `parses a five-digit and a six-digit operator code`() {
        assertEquals(SimIdentity("427", "01", "Ooredoo"), SimIdentity.fromSimOperator("42701", "Ooredoo"))
        assertEquals(SimIdentity("310", "260", "T-Mobile"), SimIdentity.fromSimOperator("310260", "T-Mobile"))
    }

    @Test
    fun `no SIM, a blank code or a malformed one is no identity`() {
        assertNull(SimIdentity.fromSimOperator(null, "x"))
        assertNull(SimIdentity.fromSimOperator("", "x"))
        assertNull(SimIdentity.fromSimOperator("427", "x"))
        assertNull(SimIdentity.fromSimOperator("42a01", "x"))
    }

    @Test
    fun `a blank service provider name is null, not empty`() {
        assertNull(SimIdentity.fromSimOperator("42701", "  ")!!.operatorName)
    }

    @Test
    fun `the home network matches on code and name`() {
        val c = ooredoo.compare("427", "01", "Ooredoo Qatar", "Ooredoo")
        assertEquals(true, c.plmnMatchesSim)
        assertEquals(true, c.operatorNameMatchesSim)
        assertEquals("427", c.mcc)
        assertEquals("Ooredoo", c.operatorName)
    }

    @Test
    fun `a padded MNC is the same network`() {
        // The SIM record and the network may pad differently.
        assertEquals(true, ooredoo.compare("427", "001", "Ooredoo", null).plmnMatchesSim)
    }

    @Test
    fun `a different network mismatches`() {
        val c = ooredoo.compare("427", "02", "Vodafone", "VF QA")
        assertEquals(false, c.plmnMatchesSim)
        assertEquals(false, c.operatorNameMatchesSim)
    }

    @Test
    fun `the name is compared case-insensitively and either way round`() {
        assertEquals(true, ooredoo.compare("427", "01", "OOREDOO", null).operatorNameMatchesSim)
        val longerSpn = SimIdentity("427", "01", "Ooredoo Qatar")
        assertEquals(true, longerSpn.compare("427", "01", "Ooredoo", null).operatorNameMatchesSim)
        val shortOnly = ooredoo.compare("427", "01", "42701", "Ooredoo")
        assertEquals("the short name counts too", true, shortOnly.operatorNameMatchesSim)
    }

    @Test
    fun `spacing and punctuation do not make two spellings of one name differ`() {
        // The reader folds whitespace in the broadcast name to '_'.
        val spn = SimIdentity("427", "01", "Ooredoo Qatar")
        assertEquals(true, spn.compare("427", "01", "Ooredoo_Qatar", null).operatorNameMatchesSim)
        assertEquals(true, spn.compare("427", "01", "OOREDOO-QATAR", null).operatorNameMatchesSim)
    }

    @Test
    fun `a numeric or one-letter name is not comparable, so the answer is unknown`() {
        // "42701" is a PLMN code broadcast as a name; "O" is in every operator.
        // Neither can be said to match or mismatch anything.
        assertNull(ooredoo.compare("427", "01", "42701", null).operatorNameMatchesSim)
        assertNull(SimIdentity("427", "01", "42701").compare("427", "01", "Ooredoo", null).operatorNameMatchesSim)
        assertNull(ooredoo.compare("427", "01", "O", null).operatorNameMatchesSim)
        assertNull(SimIdentity("427", "01", "O").compare("427", "01", "Ooredoo", null).operatorNameMatchesSim)
    }

    @Test
    fun `missing sides compare to null rather than false`() {
        assertNull(ooredoo.compare(null, "01", "Ooredoo", null).plmnMatchesSim)
        assertNull(ooredoo.compare("427", null, "Ooredoo", null).plmnMatchesSim)
        assertNull(ooredoo.compare("427", "01", null, "").operatorNameMatchesSim)
        assertNull(SimIdentity("427", "01", null).compare("427", "01", "Ooredoo", null).operatorNameMatchesSim)
    }
}
