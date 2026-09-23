package com.androdr.sigma

import android.content.Context
import com.androdr.data.model.ForensicTimelineEvent
import io.mockk.mockk
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/**
 * One definition of "atom rule", used twice.
 *
 * `computeAtomBindings` decides which events a chain's legs can bind to;
 * `atomCategories` decides which legs coverage calls satisfied (#370). If the
 * second is looser than the first, a chain whose leg the binder rejects still
 * looks checked -- the rule silently never fires and the report says nothing,
 * which is the failure the coverage work exists to end.
 *
 * The drift is invisible in production (all bundled atoms are informational and
 * lookup-free), so it is pinned here instead.
 */
class AtomCategoriesMatchBindingsTest {

    private val mockContext = mockk<Context>(relaxed = true)
    private lateinit var engine: SigmaRuleEngine

    private fun atom(
        id: String,
        category: String,
        level: String = "informational",
        enabled: Boolean = true,
        lookupField: SigmaFieldMatcher? = null,
    ) = SigmaRule(
        id = id, title = "Atom $id", status = "production", description = "",
        product = "androdr", service = "timeline", level = level,
        category = RuleCategory.DEVICE_POSTURE, tags = emptyList(),
        detection = SigmaDetection(
            selections = mapOf(
                "selection" to SigmaSelection(
                    fieldMatchers = listOfNotNull(
                        SigmaFieldMatcher("category", SigmaModifier.EQUALS, listOf(category)),
                        lookupField,
                    )
                )
            ),
            condition = "selection",
        ),
        falsepositives = emptyList(), remediation = emptyList(),
        display = SigmaDisplay(category = null, suppressFinding = true),
        enabled = enabled,
    )

    private fun event(id: Long, category: String) = ForensicTimelineEvent(
        id = id, startTimestamp = id, source = "test", category = category, description = "",
    )

    private fun load(rules: List<SigmaRule>) {
        engine = SigmaRuleEngine(mockContext)
        for (field in listOf("bundledRules", "rules")) {
            SigmaRuleEngine::class.java.getDeclaredField(field).apply { isAccessible = true }
                .set(engine, rules)
        }
    }

    @Before
    fun setUp() = load(emptyList())

    @Test
    fun `a rule that is not informational is not an atom for either function`() {
        load(listOf(atom("atom-real", "package_install"), atom("judge", "package_install", level = "high")))

        assertEquals(setOf("atom-real"), engine.atomCategories().keys)
        val bound = engine.computeAtomBindings(listOf(event(1, "package_install"))).values.flatten().toSet()
        assertEquals(bound, engine.atomCategories().keys)
    }

    @Test
    fun `a disabled rule is not an atom for either function`() {
        load(listOf(atom("atom-real", "package_install"), atom("atom-off", "package_install", enabled = false)))

        assertEquals(setOf("atom-real"), engine.atomCategories().keys)
    }

    @Test
    fun `a rule this build cannot evaluate binds nothing, so coverage must not count it`() {
        // Fail-closed: an unresolvable ioc_lookup drops the rule from binding. If
        // atomCategories still returned its category, a chain leg pointing at it
        // would look satisfied while the chain could never fire.
        val unevaluable = atom(
            "atom-unevaluable", "package_install",
            lookupField = SigmaFieldMatcher("package_name", SigmaModifier.IOC_LOOKUP, listOf("no_such_lookup")),
        )
        load(listOf(atom("atom-real", "device_admin_grant"), unevaluable))

        assertTrue(
            "an unevaluable rule must not appear as an atom",
            "atom-unevaluable" !in engine.atomCategories().keys,
        )
        val bound = engine.computeAtomBindings(
            listOf(event(1, "package_install"), event(2, "device_admin_grant")),
        ).values.flatten().toSet()
        assertEquals(bound, engine.atomCategories().keys)
    }

    @Test
    fun `the two functions agree on the whole rule set`() {
        load(
            listOf(
                atom("atom-install", "package_install"),
                atom("atom-admin", "device_admin_grant"),
                atom("atom-perm", "permission_use"),
                atom("not-informational", "app_foreground", level = "medium"),
                atom("disabled", "network_connect", enabled = false),
            )
        )
        val events = listOf(
            event(1, "package_install"), event(2, "device_admin_grant"), event(3, "permission_use"),
            event(4, "app_foreground"), event(5, "network_connect"),
        )

        val bound = engine.computeAtomBindings(events).values.flatten().toSet()

        assertEquals(setOf("atom-install", "atom-admin", "atom-perm"), engine.atomCategories().keys)
        assertEquals(bound, engine.atomCategories().keys)
    }
}
