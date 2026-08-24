package com.androdr.scanner.intrusionlog

import android.app.admin.SecurityLog
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class SecurityLogTagRegistryTest {

    @Test
    fun `known tags resolve to snake_case names`() {
        assertEquals("adb_shell_cmd", SecurityLogTagRegistry.nameFor(SecurityLog.TAG_ADB_SHELL_CMD))
        assertEquals("adb_shell_interactive", SecurityLogTagRegistry.nameFor(SecurityLog.TAG_ADB_SHELL_INTERACTIVE))
        assertEquals("app_process_start", SecurityLogTagRegistry.nameFor(SecurityLog.TAG_APP_PROCESS_START))
        assertEquals("keyguard_dismissed", SecurityLogTagRegistry.nameFor(SecurityLog.TAG_KEYGUARD_DISMISSED))
        assertEquals(
            "cert_authority_installed",
            SecurityLogTagRegistry.nameFor(SecurityLog.TAG_CERT_AUTHORITY_INSTALLED)
        )
    }

    @Test
    fun `unknown tag falls back to unknown_N and is never dropped`() {
        assertEquals("unknown_999999", SecurityLogTagRegistry.nameFor(999999))
    }

    @Test
    fun `registry names are unique`() {
        val names = SecurityLogTagRegistry.allNames()
        assertTrue(names.size == names.toSet().size)
    }

    // #356: real Android 16 exports name the tag instead of numbering it, so the
    // parser needs the reverse lookup. Without it every real security_event lands
    // as tag -1 and no tag-keyed rule can ever match.
    @Test
    fun `idFor reverses the name map`() {
        assertEquals(SecurityLog.TAG_APP_PROCESS_START, SecurityLogTagRegistry.idFor("app_process_start"))
        assertEquals(
            SecurityLog.TAG_USER_RESTRICTION_ADDED,
            SecurityLogTagRegistry.idFor("user_restriction_added")
        )
        assertEquals(SecurityLog.TAG_KEYGUARD_DISMISSED, SecurityLogTagRegistry.idFor("keyguard_dismissed"))
    }

    @Test
    fun `idFor returns -1 for an unknown name`() {
        assertEquals(-1, SecurityLogTagRegistry.idFor("future_event"))
        assertEquals(-1, SecurityLogTagRegistry.idFor(""))
    }

    @Test
    fun `every registered name round-trips through idFor and nameFor`() {
        for (name in SecurityLogTagRegistry.allNames()) {
            assertEquals(name, SecurityLogTagRegistry.nameFor(SecurityLogTagRegistry.idFor(name)))
        }
    }
}
