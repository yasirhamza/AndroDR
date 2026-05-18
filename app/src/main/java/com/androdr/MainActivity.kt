package com.androdr

import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Dashboard
import androidx.compose.material.icons.filled.Timeline
import androidx.compose.material.icons.filled.PhoneAndroid
import androidx.compose.material.icons.filled.Wifi
import androidx.compose.material.icons.outlined.Apps
import androidx.compose.material3.Icon
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.SideEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.luminance
import androidx.compose.ui.graphics.toArgb
import androidx.compose.ui.platform.LocalView
import androidx.core.view.WindowCompat
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.navigation.NavGraph.Companion.findStartDestination
import androidx.navigation.compose.NavHost
import androidx.navigation.NavType
import androidx.navigation.compose.composable
import androidx.navigation.compose.currentBackStackEntryAsState
import androidx.navigation.compose.rememberNavController
import androidx.navigation.navArgument
import com.androdr.ui.apps.AppScanScreen
import com.androdr.ui.bugreport.BugReportScreen
import com.androdr.ui.dashboard.DashboardScreen
import com.androdr.ui.device.DeviceAuditScreen
import com.androdr.ui.history.HistoryScreen
import com.androdr.ui.network.DnsMonitorScreen
import com.androdr.ui.timeline.TimelineScreen
import com.androdr.ui.settings.SettingsScreen
import com.androdr.data.repo.SettingsRepository
import com.androdr.ui.theme.AndroDRTheme
import com.androdr.ui.theme.ThemeMode
import android.app.Activity
import android.net.Uri
import dagger.hilt.android.AndroidEntryPoint
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import javax.inject.Inject

@AndroidEntryPoint
class MainActivity : ComponentActivity() {

    @Suppress("LateinitUsage") // Hilt field injection requires lateinit on @AndroidEntryPoint activities.
    @Inject lateinit var settingsRepository: SettingsRepository

    override fun onCreate(savedInstanceState: android.os.Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            val themeMode by settingsRepository.themeMode
                .collectAsStateWithLifecycle(initialValue = ThemeMode.AUTO)
            AndroDRTheme(themeMode = themeMode) {
                SystemBarsEffect()
                Surface(
                    modifier = Modifier.fillMaxSize(),
                    color = MaterialTheme.colorScheme.background
                ) {
                    AndroDRApp()
                }
            }
        }
    }
}

@Composable
private fun SystemBarsEffect() {
    val view = LocalView.current
    val surface = MaterialTheme.colorScheme.surface
    val surfaceArgb = surface.toArgb()
    // Drive icon brightness from the actual surface luminance — this is the
    // only truthful signal when the user has forced LIGHT on a system-dark
    // device or vice versa. isSystemInDarkTheme() lies in that case.
    val barsLookDark = surface.luminance() < 0.5f
    if (!view.isInEditMode) {
        SideEffect {
            val window = (view.context as android.app.Activity).window
            window.statusBarColor = surfaceArgb
            window.navigationBarColor = surfaceArgb
            WindowCompat.getInsetsController(window, view).apply {
                isAppearanceLightStatusBars = !barsLookDark
                isAppearanceLightNavigationBars = !barsLookDark
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
    NavDestination("timeline", "Timeline", Icons.Filled.Timeline),
)

@Suppress("LongMethod") // AndroDRApp is the root nav host; it contains the VPN permission
// launcher, bottom bar, and NavHost with all 6 destinations — inherently a longer composable.
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
    val showBottomBar = bottomNavDestinations.any {
        currentRoute?.startsWith(it.route) == true
    }

    fun navigateToTimeline(packageName: String) {
        val encoded = Uri.encode(packageName)
        navController.navigate("timeline?pkg=$encoded") {
            popUpTo(navController.graph.findStartDestination().id) { saveState = true }
            launchSingleTop = true
        }
    }

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
                            selected = currentRoute?.startsWith(destination.route) == true,
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
                AppScanScreen(onNavigateToTimeline = ::navigateToTimeline)
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
            composable(
                "timeline?pkg={pkg}",
                arguments = listOf(navArgument("pkg") {
                    type = NavType.StringType; nullable = true; defaultValue = null
                })
            ) { entry ->
                TimelineScreen(
                    initialPackage = entry.arguments?.getString("pkg"),
                    onNavigateToHistory = {
                        navController.navigate("history") {
                            launchSingleTop = true
                        }
                    }
                )
            }
            composable("bugreport") {
                BugReportScreen()
            }
            composable("settings") {
                SettingsScreen()
            }
        }
    }
}
