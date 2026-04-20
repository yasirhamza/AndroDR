package com.androdr.ioc.feeds

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class StalkerwareCertHashFeedTest {

    private val feed = StalkerwareCertHashFeed()

    @Test
    fun `parses real TheTruthSpy entry with multiple cert SHA-1s`() {
        val yaml = """
            - name: TheTruthSpy
              type: stalkerware
              packages:
              - com.apspy.app
              certificates:
              - 31A6ECECD97CF39BC4126B8745CD94A7C30BF81C
              - 36E6671BC4397F475A350905D9A649A5ADE97BB2
              websites:
              - copy9.com
        """.trimIndent()

        val results = feed.parseYaml(yaml, fetchedAt = 42L)

        assertEquals(2, results.size)
        // Hashes must be normalized to lowercase for consistent matching against
        // AppScanner telemetry (which emits lowercase hex).
        assertEquals("31a6ececd97cf39bc4126b8745cd94a7c30bf81c", results[0].certHash)
        assertEquals("36e6671bc4397f475a350905d9a649a5ade97bb2", results[1].certHash)
        assertTrue(results.all { it.familyName == "TheTruthSpy" })
        assertTrue(results.all { it.category == "STALKERWARE" })
        assertTrue(results.all { it.severity == "CRITICAL" })
        assertTrue(results.all { it.source == "stalkerware_indicators_certs" })
        assertTrue(results.all { it.fetchedAt == 42L })
    }

    @Test
    fun `skips websites and packages fields — only certificates are emitted`() {
        val yaml = """
            - name: FakeFamily
              type: stalkerware
              packages:
              - com.fake.app
              websites:
              - fake.example.com
              certificates:
              - 0123456789abcdef0123456789abcdef01234567
        """.trimIndent()

        val results = feed.parseYaml(yaml, fetchedAt = 0L)

        assertEquals(1, results.size)
        assertEquals("0123456789abcdef0123456789abcdef01234567", results[0].certHash)
    }

    @Test
    fun `multiple families each contribute their own cert hashes`() {
        val yaml = """
            - name: FamA
              type: stalkerware
              certificates:
              - 1111aaaa2222bbbb3333cccc4444dddd5555eeee
            - name: FamB
              type: spyware
              certificates:
              - 2222bbbb3333cccc4444dddd5555eeee6666ffff
        """.trimIndent()

        val results = feed.parseYaml(yaml, fetchedAt = 0L)

        assertEquals(2, results.size)
        assertEquals("FamA", results[0].familyName)
        assertEquals("STALKERWARE", results[0].category)
        assertEquals("FamB", results[1].familyName)
        assertEquals("SPYWARE", results[1].category)
    }

    @Test
    fun `rejects malformed entries — non-hex and wrong length`() {
        val yaml = """
            - name: Bad
              type: stalkerware
              certificates:
              - NOT-A-HEX-CERT-FINGERPRINT-AT-ALL
              - 1234
              - 1111aaaa2222bbbb3333cccc4444dddd5555eeee
        """.trimIndent()

        val results = feed.parseYaml(yaml, fetchedAt = 0L)

        assertEquals(1, results.size)
        assertEquals("1111aaaa2222bbbb3333cccc4444dddd5555eeee", results[0].certHash)
    }

    @Test
    fun `colons and spaces in cert strings are stripped before validation`() {
        // Some communities write SHA-1s with colons (aa:bb:cc:…). Accept that format.
        val yaml = """
            - name: Formatted
              type: stalkerware
              certificates:
              - AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01
        """.trimIndent()

        val results = feed.parseYaml(yaml, fetchedAt = 0L)

        assertEquals(1, results.size)
        assertEquals("abcdef0123456789abcdef0123456789abcdef01", results[0].certHash)
    }

    @Test
    fun `empty yaml returns empty list`() {
        assertTrue(feed.parseYaml("", fetchedAt = 0L).isEmpty())
    }

    @Test
    fun `yaml with no certificates fields returns empty list`() {
        val yaml = """
            - name: NoCerts
              type: stalkerware
              packages:
              - com.example.app
              websites:
              - example.com
        """.trimIndent()

        assertTrue(feed.parseYaml(yaml, fetchedAt = 0L).isEmpty())
    }

    @Test
    fun `entering packages block exits cert block`() {
        // Order-independence: if packages block appears after certificates in one
        // entry, we still correctly exit the cert block.
        val yaml = """
            - name: OrderTest
              type: stalkerware
              certificates:
              - 1111aaaa2222bbbb3333cccc4444dddd5555eeee
              packages:
              - com.example.app
              - 2222bbbb3333cccc4444dddd5555eeee6666ffff
        """.trimIndent()

        val results = feed.parseYaml(yaml, fetchedAt = 0L)

        assertEquals(1, results.size)
        assertEquals("1111aaaa2222bbbb3333cccc4444dddd5555eeee", results[0].certHash)
        // Must NOT ingest the 2222... as a cert — it's under `packages:` in this entry.
        assertFalse(results.any { it.certHash.startsWith("2222") })
    }

    @Test
    fun `rejects low-entropy hex — all-zeros and all-ones`() {
        // Upstream-poisoning defence: a malicious PR to AssoEchap that inserts
        // 000…0 or FFF…F as a "cert" would otherwise match every app that
        // happens to produce those digest values, plus signal-free bogus data.
        val yaml = """
            - name: Poisoned
              type: stalkerware
              certificates:
              - 0000000000000000000000000000000000000000
              - ffffffffffffffffffffffffffffffffffffffff
              - abababababababababababababababababababab
              - 1111aaaa2222bbbb3333cccc4444dddd5555eeee
        """.trimIndent()

        val results = feed.parseYaml(yaml, fetchedAt = 0L)

        // Only the high-entropy fingerprint survives.
        assertEquals(1, results.size)
        assertEquals("1111aaaa2222bbbb3333cccc4444dddd5555eeee", results[0].certHash)
    }

    @Test
    fun `c2 and distribution blocks between families do not leak into next family`() {
        // Real ioc.yaml entries carry c2 / distribution / websites blocks
        // before/after the cert block. State reset between families must survive.
        val yaml = """
            - name: FamA
              type: stalkerware
              certificates:
              - 1111aaaa2222bbbb3333cccc4444dddd5555eeee
              websites:
              - fama.example.com
              c2:
                ips:
                - 1.2.3.4
                domains:
                - c2.fama.com
              distribution:
                - app.fama.com
            - name: FamB
              type: spyware
              certificates:
              - 2222bbbb3333cccc4444dddd5555eeee6666ffff
        """.trimIndent()

        val results = feed.parseYaml(yaml, fetchedAt = 0L)

        assertEquals(2, results.size)
        assertEquals("FamA", results[0].familyName)
        assertEquals("STALKERWARE", results[0].category)
        assertEquals("FamB", results[1].familyName)
        assertEquals("SPYWARE", results[1].category)
    }

    @Test
    fun `family without explicit type defaults to stalkerware and does not inherit previous family type`() {
        // Previously the parser held a module-level currentType variable that
        // leaked across families. If FamB omits `type:`, it must default to
        // stalkerware, not inherit FamA's `spyware`.
        val yaml = """
            - name: FamA
              type: spyware
              certificates:
              - 1111aaaa2222bbbb3333cccc4444dddd5555eeee
            - name: FamB
              certificates:
              - 2222bbbb3333cccc4444dddd5555eeee6666ffff
        """.trimIndent()

        val results = feed.parseYaml(yaml, fetchedAt = 0L)

        assertEquals(2, results.size)
        assertEquals("SPYWARE", results[0].category)
        // FamB has no `type:` — must default to stalkerware, not inherit SPYWARE.
        assertEquals("STALKERWARE", results[1].category)
    }
}
