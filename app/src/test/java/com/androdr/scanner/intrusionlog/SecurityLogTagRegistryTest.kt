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
        assertEquals("cert_authority_installed", SecurityLogTagRegistry.nameFor(SecurityLog.TAG_CERT_AUTHORITY_INSTALLED))
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
}
