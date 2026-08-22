package com.androdr.cellular

import android.Manifest
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The permission the monitor needs must be a permission the app actually asks
 * for.
 *
 * These were two independent lists and they drifted: the UI requested
 * ACCESS_FINE_LOCATION and ACCESS_COARSE_LOCATION, while the monitor also
 * demanded READ_PHONE_STATE. Granting location therefore hid the request
 * button — its check only looked at location — while the monitor stayed
 * blocked on a permission nothing ever asked for. The screen reported a
 * permission problem and simultaneously removed the only way to fix it.
 *
 * It survived every on-device test because those installs used
 * `adb install -g`, which grants all runtime permissions. The bug was
 * reachable only by installing the way a real user does.
 */
class CellularPermissionContractTest {

    @Test
    fun `every required permission is also requested`() {
        val missing = CellularMonitor.REQUIRED_PERMISSIONS
            .filterNot { it in CellularMonitor.REQUESTED_PERMISSIONS }
        assertTrue(
            "These permissions are required but never requested, so the monitor " +
                "can never start on a normal install: $missing",
            missing.isEmpty(),
        )
    }

    @Test
    fun `READ_PHONE_STATE is required and requested`() {
        // Named explicitly because it is the one that was missed: it is not
        // "a location permission", but getAllCellInfo is refused without it.
        assertTrue(
            "READ_PHONE_STATE must be required",
            Manifest.permission.READ_PHONE_STATE in CellularMonitor.REQUIRED_PERMISSIONS,
        )
        assertTrue(
            "READ_PHONE_STATE must be requested",
            Manifest.permission.READ_PHONE_STATE in CellularMonitor.REQUESTED_PERMISSIONS,
        )
    }

    @Test
    fun `coarse location is requested alongside fine`() {
        // Android 12+ refuses FINE unless COARSE is requested with it.
        assertTrue(
            "ACCESS_COARSE_LOCATION must be requested alongside FINE",
            Manifest.permission.ACCESS_COARSE_LOCATION in CellularMonitor.REQUESTED_PERMISSIONS,
        )
    }
}
