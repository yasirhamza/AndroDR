package com.androdr.scanner

import org.junit.Assert.assertEquals
import org.junit.Test

class ArtifactSnifferTest {

    @Test
    fun `dumpstate entry wins as bug report`() {
        assertEquals(
            ArtifactType.BUG_REPORT,
            ArtifactSniffer.classify(sequenceOf("dumpstate.txt", "2026-08-22.txt"))
        )
    }

    @Test
    fun `bugreport-prefixed txt is a bug report`() {
        assertEquals(
            ArtifactType.BUG_REPORT,
            ArtifactSniffer.classify(sequenceOf("bugreport-crownqltesq-2026-08-22.txt"))
        )
    }

    @Test
    fun `per-day txt at top level is an intrusion log`() {
        assertEquals(
            ArtifactType.INTRUSION_LOG,
            ArtifactSniffer.classify(sequenceOf("2026-08-22.txt"))
        )
    }

    @Test
    fun `per-day txt one directory deep matches (androidqf layout)`() {
        assertEquals(
            ArtifactType.INTRUSION_LOG,
            ArtifactSniffer.classify(sequenceOf("intrusion-logs/2026-08-21.txt"))
        )
    }

    @Test
    fun `per-day txt nested deeper does not match`() {
        assertEquals(
            ArtifactType.UNRECOGNIZED,
            ArtifactSniffer.classify(sequenceOf("a/b/2026-08-21.txt"))
        )
    }

    @Test
    fun `random zip is unrecognized`() {
        assertEquals(
            ArtifactType.UNRECOGNIZED,
            ArtifactSniffer.classify(sequenceOf("photo.jpg", "notes.txt"))
        )
    }
}
