package com.androdr.sigma

import com.androdr.data.model.AccessibilityTelemetry
import com.androdr.data.model.AppOpsTelemetry
import com.androdr.data.model.AppTelemetry
import com.androdr.data.model.DeviceTelemetry
import com.androdr.data.model.DnsEvent
import com.androdr.data.model.FileArtifactTelemetry
import com.androdr.data.model.ProcessTelemetry
import com.androdr.data.model.ReceiverTelemetry

/** Projects live-scan telemetry to [StoreRecord]s through each type's `toFieldMap()`. */
object LiveRecordBuilders {
    const val APP_SCANNER = "app_scanner"
    const val DEVICE_AUDITOR = "device_auditor"
    const val PROCESS_MONITOR = "process_monitor"
    const val FILE_SCANNER = "file_scanner"
    const val ACCESSIBILITY_AUDIT = "accessibility_audit"
    const val RECEIVER_AUDIT = "receiver_audit"
    const val APPOPS_AUDIT = "appops_audit"
    const val DNS_MONITOR = "dns_monitor"

    fun apps(t: List<AppTelemetry>): List<StoreRecord> = t.map { StoreRecord(it.toFieldMap()) }
    fun device(t: List<DeviceTelemetry>): List<StoreRecord> = t.map { StoreRecord(it.toFieldMap()) }
    fun processes(t: List<ProcessTelemetry>): List<StoreRecord> = t.map { StoreRecord(it.toFieldMap()) }
    fun files(t: List<FileArtifactTelemetry>): List<StoreRecord> = t.map { StoreRecord(it.toFieldMap()) }
    fun accessibility(t: List<AccessibilityTelemetry>): List<StoreRecord> =
        t.map { StoreRecord(it.toFieldMap()) }
    fun receivers(t: List<ReceiverTelemetry>): List<StoreRecord> = t.map { StoreRecord(it.toFieldMap()) }
    fun appOps(t: List<AppOpsTelemetry>): List<StoreRecord> = t.map { StoreRecord(it.toFieldMap()) }
    fun dns(t: List<DnsEvent>): List<StoreRecord> = t.map { StoreRecord(it.toFieldMap()) }
}
