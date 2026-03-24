package com.androdr

import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.BugReport
import androidx.compose.material.icons.filled.Dashboard
import androidx.compose.material.icons.filled.History
import androidx.compose.material.icons.filled.PhoneAndroid
import androidx.compose.material.icons.filled.Wifi
import androidx.compose.material.icons.outlined.Apps
import androidx.compose.material3.Icon
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.navigation.NavGraph.Companion.findStartDestination
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.currentBackStackEntryAsState
import androidx.navigation.compose.rememberNavController
import com.androdr.ui.apps.AppScanScreen
import com.androdr.ui.bugreport.BugReportScreen
import com.androdr.ui.dashboard.DashboardScreen
import com.androdr.ui.device.DeviceAuditScreen
import com.androdr.ui.history.HistoryScreen
import com.androdr.ui.network.DnsMonitorScreen
import com.androdr.ui.theme.AndroDRTheme
import android.app.Activity
import dagger.hilt.android.AndroidEntryPoint
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent

@AndroidEntryPoint
class MainActivity : ComponentActivity() {

    override fun onCreate(savedInstanceState: android.os.Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            AndroDRTheme {
                AndroDRApp()
            }
        }
    }
}

private data class NavDestination(
    val route: String,
    val label: String,
    val icon: androidx.compose.ui.graphics.vector.ImageVector
)

private val bottomNavDestinations = listOf(
    NavDestination("dashboard", "Dashboard", Icons.Filled.Dashboard),
    NavDestination("apps", "Apps", Icons.Outlined.Apps),
    NavDestination("device", "Device", Icons.Filled.PhoneAndroid),
    NavDestination("network", "Network", Icons.Filled.Wifi),
    NavDestination("history", "History", Icons.Filled.History),
)

@Composable
private fun AndroDRApp() {
    val navController = rememberNavController()

    // Track a pending VPN toggle action across the permission result callback
    var pendingVpnToggle by remember { mutableStateOf(false) }

    val vpnPermissionLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == Activity.RESULT_OK) {
            // Permission granted — navigate to network screen so the user can
            // press the toggle button; the DnsMonitorScreen handles the actual
            // service start.
            navController.navigate("network") {
                popUpTo(navController.graph.findStartDestination().id) {
                    saveState = true
                }
                launchSingleTop = true
                restoreState = true
            }
        }
        pendingVpnToggle = false
    }

    val navBackStackEntry by navController.currentBackStackEntryAsState()
    val currentRoute = navBackStackEntry?.destination?.route

    // Only show bottom bar on the main 5 destinations (not on bugreport)
    val showBottomBar = bottomNavDestinations.any { it.route == currentRoute }

    Scaffold(
        bottomBar = {
            if (showBottomBar) {
                NavigationBar {
                    bottomNavDestinations.forEach { destination ->
                        NavigationBarItem(
                            icon = {
                                Icon(
                                    imageVector = destination.icon,
                                    contentDescription = destination.label
                                )
                            },
                            label = { Text(destination.label) },
                            selected = currentRoute == destination.route,
                            onClick = {
                                navController.navigate(destination.route) {
                                    popUpTo(navController.graph.findStartDestination().id) {
                                        saveState = true
                                    }
                                    launchSingleTop = true
                                    restoreState = true
                                }
                            }
                        )
                    }
                }
            }
        }
    ) { innerPadding ->
        NavHost(
            navController = navController,
            startDestination = "dashboard",
            modifier = Modifier.padding(innerPadding)
        ) {
            composable("dashboard") {
                DashboardScreen(
                    onNavigate = { route ->
                        navController.navigate(route) {
                            popUpTo(navController.graph.findStartDestination().id) {
                                saveState = true
                            }
                            launchSingleTop = true
                            restoreState = true
                        }
                    }
                )
            }
            composable("apps") {
                AppScanScreen()
            }
            composable("device") {
                DeviceAuditScreen()
            }
            composable("network") {
                DnsMonitorScreen(
                    onRequestVpnPermission = { intent ->
                        vpnPermissionLauncher.launch(intent)
                    }
                )
            }
            composable("history") {
                HistoryScreen()
            }
            composable("bugreport") {
                BugReportScreen()
            }
        }
    }
}
