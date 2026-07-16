package com.androdr.scanner

import android.content.Intent
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class PackageLifecycleReceiverTest {

    /**
     * The receiver's front-door guard (the defense the CodeQL
     * `java/improper-intent-verification` finding asked for, CWE-925): it must
     * act only on the package add/remove actions it registers for, and drop
     * everything else — a forged, unexpected, or null action never reaches the
     * timeline-writing path.
     */
    @Test
    fun `handlesAction accepts only package add and remove`() {
        assertTrue(PackageLifecycleReceiver.handlesAction(Intent.ACTION_PACKAGE_ADDED))
        assertTrue(PackageLifecycleReceiver.handlesAction(Intent.ACTION_PACKAGE_REMOVED))
    }

    @Test
    fun `handlesAction rejects unexpected, unrelated, and null actions`() {
        assertFalse(PackageLifecycleReceiver.handlesAction(Intent.ACTION_BOOT_COMPLETED))
        assertFalse(PackageLifecycleReceiver.handlesAction("com.evil.FORGED_ACTION"))
        assertFalse(PackageLifecycleReceiver.handlesAction(""))
        assertFalse(PackageLifecycleReceiver.handlesAction(null))
    }
}
