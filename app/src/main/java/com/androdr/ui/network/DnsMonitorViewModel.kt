package com.androdr.ui.network

import android.app.Activity
import android.content.Context
import android.content.Intent
import android.net.VpnService
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.androdr.data.model.DnsEvent
import com.androdr.data.repo.ScanRepository
import com.androdr.vpn.DnsVpnService
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.stateIn
import javax.inject.Inject

@HiltViewModel
class DnsMonitorViewModel @Inject constructor(
    private val repository: ScanRepository
) : ViewModel() {

    /** Up to 200 most recent DNS events, newest first. */
    val recentEvents: StateFlow<List<DnsEvent>> = repository.recentDnsEvents
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), emptyList())

    /** All DNS events that were blocked, newest first. */
    val blockedEvents: StateFlow<List<DnsEvent>> = repository.blockedDnsEvents
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), emptyList())

    /** Whether the DNS VPN service is currently active. */
    val isVpnRunning: StateFlow<Boolean> = DnsVpnService.isRunning
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), false)

    /**
     * Starts or stops [DnsVpnService] depending on the current [isVpnRunning] state.
     *
     * Call [requestVpnPermission] first and handle the returned [Intent] before
     * invoking this if the VPN permission has not yet been granted.
     */
    fun toggleVpn(context: Context) {
        if (isVpnRunning.value) {
            val stopIntent = Intent(context, DnsVpnService::class.java).apply {
                action = DnsVpnService.ACTION_STOP
            }
            context.startService(stopIntent)
        } else {
            val startIntent = Intent(context, DnsVpnService::class.java).apply {
                action = DnsVpnService.ACTION_START
            }
            context.startService(startIntent)
        }
    }

    /**
     * Prepares the VPN permission dialog if the OS requires it.
     *
     * Returns a non-null [Intent] that must be launched with
     * `startActivityForResult` when the user has not yet granted VPN permission;
     * returns null when permission is already granted and the VPN can be started
     * immediately.
     */
    fun requestVpnPermission(activity: Activity): Intent? =
        VpnService.prepare(activity)
}
