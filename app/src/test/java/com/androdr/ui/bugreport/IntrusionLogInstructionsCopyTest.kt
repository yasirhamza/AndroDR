package com.androdr.ui.bugreport

import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * The intrusion-log help text once gave only the Pixel path (Settings → Security & privacy),
 * which is wrong on Samsung, where Advanced Protection sits under Google services → All services,
 * and Intrusion logging sits under Expert features. Pin every path so a later edit cannot drop one.
 */
class IntrusionLogInstructionsCopyTest {

    private val body: String by lazy {
        val root = listOf(File("src/main"), File("app/src/main")).firstOrNull { it.isDirectory }
            ?: error("cannot find src/main from ${File(".").absolutePath}")
        val strings = File(root, "res/values/strings.xml").readText()
        Regex("""<string name="intrusion_log_instructions_body">(.*?)</string>""", RegexOption.DOT_MATCHES_ALL)
            .find(strings)?.groupValues?.get(1) ?: error("intrusion_log_instructions_body not found")
    }

    private fun assertMentions(text: String) =
        assertTrue("instructions must mention \"$text\": $body", body.contains(text))

    @Test fun `gives the Samsung path through Google services`() {
        assertMentions("Samsung")
        assertMentions("Google services \\u2192 All services")
    }

    @Test fun `still gives the Pixel path`() {
        assertMentions("Pixel")
        assertMentions("Security &amp; privacy \\u2192 Advanced Protection")
    }

    @Test fun `falls back to searching Settings for other phones`() {
        assertMentions("search Settings for \\\"Advanced Protection\\\"")
    }

    @Test fun `says Intrusion logging may sit under Expert features`() {
        assertMentions("Expert features")
    }
}
