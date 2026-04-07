package com.androdr.network

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.util.Log
import androidx.core.app.NotificationCompat
import com.androdr.R
import com.androdr.data.model.DnsEvent
import com.androdr.data.repo.ScanRepository
import com.androdr.data.repo.SettingsRepository
import com.androdr.ioc.IndicatorResolver
import dagger.hilt.android.AndroidEntryPoint
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeoutOrNull
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.nio.ByteBuffer
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicInteger
import javax.inject.Inject

/**
 * VPN service that intercepts DNS queries (UDP port 53), parses them, and either blocks
 * or proxies them based on [BlocklistManager] and [IndicatorResolver].
 *
 * ## Battery-drain hardening
 *
 * Earlier revisions of this class spawned a coroutine per DNS query, opened a fresh
 * `DatagramSocket` (with `protect()` binder IPC) per upstream forward, and wrote one
 * Room transaction per query. Together those were the dominant battery-drain sources
 * when the network monitor was active. The current implementation:
 *
 *  1. **Batches DNS event writes** via [DnsLogBuffer] (one Room transaction per
 *     batching window or per max-batch-size, whichever comes first).
 *  2. **Reuses a single protected upstream socket** via [UpstreamResolver]; outgoing
 *     queries are demuxed by a rewritten DNS transaction id, so an unbounded number
 *     of in-flight forwards share one socket.
 *  3. **Drops per-packet coroutine fan-out**: the read loop is single-threaded and
 *     calls into the buffer / resolver synchronously. Only the resolver receive loop
 *     and the periodic flush job run as additional coroutines.
 *  4. **Runs as a foreground service** with `foregroundServiceType="specialUse"` so
 *     the OS does not kill the tunnel under memory pressure. (`systemExempted` would
 *     be the more idiomatic VPN type, but on targetSdk 34 lint requires it to be
 *     paired with `SCHEDULE_EXACT_ALARM`/`USE_EXACT_ALARM` permissions that AndroDR
 *     does not need; AndroDR is sideload/MDM-distributed and not Play-Store-reviewed,
 *     so `specialUse` is the right pragmatic choice. If the app is ever published to
 *     Play, switch to `systemExempted` and add the alarm permissions.)
 */
@Suppress("TooManyFunctions")
@AndroidEntryPoint
class DnsVpnService : VpnService() {

    companion object {
        private const val TAG = "DnsVpnService"

        const val ACTION_START = "com.androdr.START_VPN"
        const val ACTION_STOP  = "com.androdr.STOP_VPN"

        /** `true` while the tunnel is established and the read loop is active. */
        val isRunning = MutableStateFlow(false)

        // Upstream DNS resolver
        private const val UPSTREAM_DNS_HOST = "8.8.8.8"
        private const val UPSTREAM_DNS_PORT = 53

        // Virtual interface addresses
        private const val TUN_ADDRESS    = "10.0.0.2"
        private const val TUN_PREFIX_LEN = 32
        private const val DNS_SERVER_IP  = "10.0.0.1"

        // Packet parsing constants
        private const val IP_PROTOCOL_UDP: Byte = 17
        private const val DNS_PORT = 53

        // Maximum DNS UDP payload (RFC 1035 §2.3.4: 512 bytes; EDNS0 can be larger but 4 KB is safe)
        private const val MAX_DNS_PACKET_SIZE = 4096

        // Upstream resolver pending-entry timeout
        private const val UPSTREAM_TIMEOUT_MS = 5_000L

        // Hard cap on the resolver pending map. Bounds memory under sustained drop
        // conditions (e.g. upstream is offline and the sweep loop hasn't run yet).
        private const val UPSTREAM_PENDING_CAP = 1024

        // Bounded blocking flush for the final log buffer drain on shutdown.
        private const val SHUTDOWN_FLUSH_TIMEOUT_MS = 1_500L

        // Foreground service notification
        private const val NOTIFICATION_CHANNEL_ID = "androdr_vpn_channel"
        private const val NOTIFICATION_ID         = 0xD15
    }

    @Suppress("LateinitUsage") @Inject lateinit var blocklistManager: BlocklistManager
    @Suppress("LateinitUsage") @Inject lateinit var scanRepository: ScanRepository
    @Suppress("LateinitUsage") @Inject lateinit var indicatorResolver: IndicatorResolver
    @Suppress("LateinitUsage") @Inject lateinit var settingsRepository: SettingsRepository

    private var tunFd: ParcelFileDescriptor? = null
    private val serviceScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private var readLoopJob: Job? = null

    private val blocklistBlockMode = MutableStateFlow(true)
    private val domainIocBlockMode = MutableStateFlow(false)

    private var logBuffer: DnsLogBuffer? = null
    private var resolver: UpstreamResolver? = null

    /** Lock for tun-fd writes — both the read loop (NXDOMAIN responses) and the
     *  resolver receive coroutine write to the same FileOutputStream. */
    private val outputLock = Any()

    // ── Lifecycle ─────────────────────────────────────────────────────────────

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP  -> stopVpn()
            else         -> startVpn()
        }
        return START_STICKY
    }

    override fun onDestroy() {
        stopVpn()
        serviceScope.cancel()
        super.onDestroy()
    }

    override fun onRevoke() {
        stopVpn()
        super.onRevoke()
    }

    // ── VPN lifecycle ─────────────────────────────────────────────────────────

    @Suppress("ReturnCount")
    private fun startVpn() {
        if (isRunning.value) return

        @Suppress("TooGenericExceptionCaught", "SwallowedException")
        val fd = try {
            Builder()
                .addAddress(TUN_ADDRESS, TUN_PREFIX_LEN)
                .addDnsServer(DNS_SERVER_IP)
                .addRoute(DNS_SERVER_IP, 32)
                .addDisallowedApplication(packageName)
                .setSession("AndroDR DNS Filter")
                .establish()
        } catch (e: Exception) {
            Log.w(TAG, "DnsVpnService: VPN tunnel establishment failed: ${e.message}")
            return
        } ?: return

        tunFd = fd
        startForegroundCompat()
        isRunning.value = true

        val outputStream = FileOutputStream(fd.fileDescriptor)

        logBuffer = DnsLogBuffer(serviceScope, scanRepository).also { it.start() }
        resolver = UpstreamResolver(serviceScope, this, outputStream, outputLock).also {
            if (!it.start()) {
                Log.w(TAG, "DnsVpnService: upstream resolver failed to start; aborting")
                stopVpn()
                return
            }
        }

        serviceScope.launch {
            settingsRepository.blocklistBlockMode.collect { blocklistBlockMode.value = it }
        }
        serviceScope.launch {
            settingsRepository.domainIocBlockMode.collect { domainIocBlockMode.value = it }
        }
        // Note: indicator cache is already warmed at app startup (AndroDRApplication.onCreate);
        // refreshing again here was redundant and burned CPU/IO at every VPN start.

        readLoopJob = serviceScope.launch {
            runPacketLoop(fd, outputStream)
        }
    }

    private fun stopVpn() {
        if (!isRunning.value && tunFd == null && resolver == null && logBuffer == null) {
            // Already stopped — nothing to do (avoids stopForeground/stopSelf churn).
            return
        }
        isRunning.value = false
        readLoopJob?.cancel()
        readLoopJob = null
        // Tear down the resolver first so its receive coroutine stops writing to the
        // shared output stream before we close the tun fd.
        resolver?.stop()
        resolver = null
        // Synchronously drain any buffered DNS events before the service scope is
        // cancelled in onDestroy. Without this the last ~LOG_FLUSH_INTERVAL_MS of
        // events would be silently dropped.
        logBuffer?.let { buffer ->
            runBlocking {
                withTimeoutOrNull(SHUTDOWN_FLUSH_TIMEOUT_MS) { buffer.flushAndStop() }
            }
        }
        logBuffer = null
        try { tunFd?.close() } catch (_: Exception) {}
        tunFd = null
        stopForegroundCompat()
        stopSelf()
    }

    // ── Foreground service ────────────────────────────────────────────────────

    private fun startForegroundCompat() {
        ensureNotificationChannel()
        val notification = buildNotification()
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            startForeground(
                NOTIFICATION_ID,
                notification,
                ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE
            )
        } else {
            startForeground(NOTIFICATION_ID, notification)
        }
    }

    private fun stopForegroundCompat() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
            stopForeground(STOP_FOREGROUND_REMOVE)
        } else {
            @Suppress("DEPRECATION")
            stopForeground(true)
        }
    }

    private fun ensureNotificationChannel() {
        val nm = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        if (nm.getNotificationChannel(NOTIFICATION_CHANNEL_ID) != null) return
        val channel = NotificationChannel(
            NOTIFICATION_CHANNEL_ID,
            getString(R.string.vpn_notification_channel_name),
            NotificationManager.IMPORTANCE_LOW
        ).apply {
            description = getString(R.string.vpn_notification_channel_desc)
            setShowBadge(false)
        }
        nm.createNotificationChannel(channel)
    }

    private fun buildNotification(): Notification =
        NotificationCompat.Builder(this, NOTIFICATION_CHANNEL_ID)
            .setSmallIcon(R.mipmap.ic_launcher)
            .setContentTitle(getString(R.string.vpn_notification_title))
            .setContentText(getString(R.string.vpn_notification_text))
            .setOngoing(true)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .setCategory(NotificationCompat.CATEGORY_SERVICE)
            .build()

    // ── Packet processing loop ────────────────────────────────────────────────

    @Suppress("LoopWithTooManyJumpStatements")
    private suspend fun runPacketLoop(fd: ParcelFileDescriptor, outputStream: FileOutputStream) {
        val inputStream = FileInputStream(fd.fileDescriptor)
        val buffer      = ByteArray(MAX_DNS_PACKET_SIZE)

        while (serviceScope.isActive && isRunning.value) {
            @Suppress("TooGenericExceptionCaught", "SwallowedException")
            val bytesRead = try {
                inputStream.read(buffer)
            } catch (e: Exception) {
                Log.w(TAG, "DnsVpnService: tun fd read failed (VPN likely revoked): ${e.message}")
                break
            }
            if (bytesRead <= 0) continue

            val packet = buffer.copyOf(bytesRead)
            try {
                processPacket(packet, outputStream)
            } catch (_: Exception) {
                // Skip malformed packets; keep the loop alive
            }
        }

        try { inputStream.close()  } catch (_: Exception) {}
        try { outputStream.close() } catch (_: Exception) {}
    }

    @Suppress("LongMethod", "ReturnCount", "ComplexMethod")
    private fun processPacket(packet: ByteArray, outputStream: FileOutputStream) {
        if (packet.size < 20) return

        val buf = ByteBuffer.wrap(packet)
        val versionAndIhl = buf.get(0).toInt() and 0xFF
        if (versionAndIhl shr 4 != 4) return

        val ihl = (versionAndIhl and 0x0F) * 4
        if (packet.size < ihl + 8) return
        if (buf.get(9) != IP_PROTOCOL_UDP) return

        val dstPort = ((buf.get(ihl + 2).toInt() and 0xFF) shl 8) or
                       (buf.get(ihl + 3).toInt() and 0xFF)
        if (dstPort != DNS_PORT) return

        val srcPort = ((buf.get(ihl).toInt() and 0xFF) shl 8) or
                       (buf.get(ihl + 1).toInt() and 0xFF)

        val udpPayloadOffset = ihl + 8
        if (packet.size <= udpPayloadOffset) return

        val dnsPayload = packet.copyOfRange(udpPayloadOffset, packet.size)
        if (dnsPayload.size < 12) return

        val txId = ((dnsPayload[0].toInt() and 0xFF) shl 8) or
                    (dnsPayload[1].toInt() and 0xFF)

        val hostname = parseDnsHostname(dnsPayload) ?: return
        val srcIpBytes = packet.copyOfRange(12, 16)

        val isBlocklisted = blocklistManager.isBlocked(hostname)
        val iocHit = if (!isBlocklisted) indicatorResolver.isKnownBadDomain(hostname) else null
        val now = System.currentTimeMillis()

        when {
            isBlocklisted && blocklistBlockMode.value -> {
                logBuffer?.add(DnsEvent(
                    timestamp = now, domain = hostname, appUid = -1, appName = null,
                    isBlocked = true, reason = "blocklist"
                ))
                writeNxdomain(dnsPayload, txId, srcIpBytes, srcPort, outputStream)
            }
            isBlocklisted -> {
                logBuffer?.add(DnsEvent(
                    timestamp = now, domain = hostname, appUid = -1, appName = null,
                    isBlocked = false, reason = "blocklist_detect"
                ))
                resolver?.send(dnsPayload, srcIpBytes, srcPort)
            }
            iocHit != null && domainIocBlockMode.value -> {
                // Since IndicatorResolver switched to a bloom index, iocHit.campaign
                // is no longer populated on the hot path; the matched label (a parent
                // of `hostname`) is the most useful signal to record here.
                logBuffer?.add(DnsEvent(
                    timestamp = now, domain = hostname, appUid = -1, appName = null,
                    isBlocked = true, reason = "IOC: ${iocHit.value}"
                ))
                writeNxdomain(dnsPayload, txId, srcIpBytes, srcPort, outputStream)
            }
            iocHit != null -> {
                logBuffer?.add(DnsEvent(
                    timestamp = now, domain = hostname, appUid = -1, appName = null,
                    isBlocked = false, reason = "IOC_detect: ${iocHit.value}"
                ))
                resolver?.send(dnsPayload, srcIpBytes, srcPort)
            }
            else -> {
                logBuffer?.add(DnsEvent(
                    timestamp = now, domain = hostname, appUid = -1, appName = null,
                    isBlocked = false, reason = null
                ))
                resolver?.send(dnsPayload, srcIpBytes, srcPort)
            }
        }
    }

    private fun writeNxdomain(
        dnsPayload: ByteArray,
        txId: Int,
        srcIpBytes: ByteArray,
        srcPort: Int,
        outputStream: FileOutputStream
    ) {
        val nx = buildNxdomainResponse(dnsPayload, txId)
        val responsePacket = wrapInIpUdp(
            nx, intArrayOf(10, 0, 0, 1),
            byteArrayToIntArray(srcIpBytes), DNS_PORT, srcPort
        )
        synchronized(outputLock) {
            try { outputStream.write(responsePacket) } catch (_: Exception) {}
        }
    }

    // ── DNS wire-format helpers ───────────────────────────────────────────────

    @Suppress("TooGenericExceptionCaught", "SwallowedException", "ReturnCount",
        "LoopWithTooManyJumpStatements")
    private fun parseDnsHostname(dns: ByteArray): String? {
        if (dns.size < 13) return null
        val sb = StringBuilder()
        var pos = 12
        try {
            while (pos < dns.size) {
                val labelLen = dns[pos].toInt() and 0xFF
                if (labelLen == 0) break
                if (labelLen and 0xC0 == 0xC0) break
                pos++
                if (pos + labelLen > dns.size) return null
                if (sb.isNotEmpty()) sb.append('.')
                sb.append(String(dns, pos, labelLen, Charsets.US_ASCII))
                pos += labelLen
            }
        } catch (e: Exception) {
            Log.w(TAG, "DnsVpnService: DNS hostname parsing failed (malformed packet): ${e.message}")
            return null
        }
        return if (sb.isEmpty()) null else sb.toString()
    }

    @Suppress("UnusedParameter")
    private fun buildNxdomainResponse(query: ByteArray, txId: Int): ByteArray {
        val response = query.copyOf()
        val rdFlag   = (query[2].toInt() and 0x01) shl 0
        response[2]  = (0x81 or rdFlag).toByte()
        response[3]  = 0x03.toByte()
        response[6]  = 0; response[7]  = 0
        response[8]  = 0; response[9]  = 0
        response[10] = 0; response[11] = 0
        return response
    }

    /**
     * Wraps a UDP payload in IPv4 + UDP headers suitable for writing to the tun fd.
     * Internal so that [UpstreamResolver] can build response packets without duplication.
     */
    internal fun wrapInIpUdp(
        payload: ByteArray,
        srcIp:   IntArray,
        dstIp:   IntArray,
        srcPort: Int,
        dstPort: Int
    ): ByteArray {
        val udpLength = 8 + payload.size
        val ipLength  = 20 + udpLength
        val buf       = ByteBuffer.allocate(ipLength)

        buf.put(0x45.toByte())
        buf.put(0x00.toByte())
        buf.putShort(ipLength.toShort())
        buf.putShort(0x0000)
        buf.putShort(0x4000)
        buf.put(0x40.toByte())
        buf.put(IP_PROTOCOL_UDP)
        buf.putShort(0x0000)
        srcIp.forEach { buf.put(it.toByte()) }
        dstIp.forEach { buf.put(it.toByte()) }

        val ipHeaderChecksum = ipChecksum(buf.array(), 0, 20)
        buf.putShort(10, ipHeaderChecksum.toShort())

        buf.putShort(srcPort.toShort())
        buf.putShort(dstPort.toShort())
        buf.putShort(udpLength.toShort())
        buf.putShort(0x0000)
        buf.put(payload)

        return buf.array()
    }

    private fun ipChecksum(data: ByteArray, offset: Int, length: Int): Int {
        var sum = 0
        var i   = offset
        val end = offset + length
        while (i < end - 1) {
            sum += ((data[i].toInt() and 0xFF) shl 8) or (data[i + 1].toInt() and 0xFF)
            i   += 2
        }
        if (i < end) sum += (data[i].toInt() and 0xFF) shl 8
        while (sum shr 16 != 0) sum = (sum and 0xFFFF) + (sum shr 16)
        return sum.inv() and 0xFFFF
    }

    private fun byteArrayToIntArray(bytes: ByteArray): IntArray =
        IntArray(bytes.size) { bytes[it].toInt() and 0xFF }

    // ── Inner: pooled upstream resolver ───────────────────────────────────────

    /**
     * Owns a single `protect()`'d [DatagramSocket] that all DNS forwards share. Outgoing
     * queries have their 16-bit DNS transaction id rewritten to a unique value so the
     * single receive loop can demux upstream replies and route them back to the correct
     * tun source. Replaces the previous "new socket per query" hot path.
     */
    private inner class UpstreamResolver(
        private val scope: CoroutineScope,
        private val vpnService: VpnService,
        private val outputStream: FileOutputStream,
        private val outputLock: Any
    ) {
        private var socket: DatagramSocket? = null
        private var upstreamAddr: InetAddress? = null
        private val pending = ConcurrentHashMap<Int, Pending>()
        private val txIdSeq = AtomicInteger(1)
        private var receiveJob: Job? = null
        private var sweepJob: Job? = null

        fun start(): Boolean {
            @Suppress("TooGenericExceptionCaught", "SwallowedException")
            return try {
                val addr = InetAddress.getByName(UPSTREAM_DNS_HOST)
                val s = DatagramSocket()
                vpnService.protect(s)
                // connect() filters incoming datagrams at the kernel level so the receive
                // loop only ever sees packets from the configured upstream resolver. This
                // closes a spoofing window where an attacker on a shared Wi-Fi could send
                // a forged reply to our source port and have it injected into the tun.
                s.connect(addr, UPSTREAM_DNS_PORT)
                s.soTimeout = 0   // blocking; the receive loop runs on its own coroutine
                socket = s
                upstreamAddr = addr
                receiveJob = scope.launch { receiveLoop() }
                sweepJob   = scope.launch { sweepLoop() }
                true
            } catch (e: Exception) {
                Log.w(TAG, "UpstreamResolver: start failed: ${e.message}")
                false
            }
        }

        fun stop() {
            receiveJob?.cancel(); receiveJob = null
            sweepJob?.cancel();   sweepJob   = null
            try { socket?.close() } catch (_: Exception) {}
            socket = null
            pending.clear()
        }

        /** Forward a DNS query through the shared upstream socket. Non-blocking. */
        @Suppress("TooGenericExceptionCaught", "SwallowedException", "ReturnCount")
        fun send(dnsPayload: ByteArray, srcIpBytes: ByteArray, srcPort: Int) {
            val s = socket ?: return
            if (dnsPayload.size < 2) return
            // Hard cap to bound memory under sustained drop conditions (e.g. upstream
            // unreachable). Beyond the cap we drop new queries until the sweep loop
            // reclaims expired entries.
            if (pending.size >= UPSTREAM_PENDING_CAP) return

            val originalTxId = ((dnsPayload[0].toInt() and 0xFF) shl 8) or
                                (dnsPayload[1].toInt() and 0xFF)

            // Allocate a fresh upstream txId via putIfAbsent so the slot reservation
            // is atomic against any concurrent senders.
            var ourTxId = -1
            val entry = Pending(
                originalTxId = originalTxId,
                srcIpBytes   = srcIpBytes,
                srcPort      = srcPort,
                expiresAt    = System.currentTimeMillis() + UPSTREAM_TIMEOUT_MS
            )
            repeat(MAX_TXID_ATTEMPTS) {
                val candidate = (txIdSeq.getAndIncrement() and 0xFFFF).let { if (it == 0) 1 else it }
                if (pending.putIfAbsent(candidate, entry) == null) {
                    ourTxId = candidate
                    return@repeat
                }
            }
            if (ourTxId == -1) return

            val rewritten = dnsPayload.copyOf()
            rewritten[0] = ((ourTxId shr 8) and 0xFF).toByte()
            rewritten[1] = (ourTxId and 0xFF).toByte()

            try {
                // Socket is connect()'d so the destination args on the packet are ignored.
                s.send(DatagramPacket(rewritten, rewritten.size))
            } catch (e: Exception) {
                pending.remove(ourTxId)
                Log.w(TAG, "UpstreamResolver: send failed: ${e.message}")
            }
        }

        private suspend fun receiveLoop() {
            val s = socket ?: return
            val recvBuf = ByteArray(MAX_DNS_PACKET_SIZE)
            while (scope.isActive && socket != null) {
                @Suppress("TooGenericExceptionCaught", "SwallowedException")
                try {
                    val pkt = DatagramPacket(recvBuf, recvBuf.size)
                    s.receive(pkt)
                    handleResponse(recvBuf.copyOf(pkt.length))
                } catch (e: Exception) {
                    if (!scope.isActive || socket == null) break
                    Log.w(TAG, "UpstreamResolver: receive failed: ${e.message}")
                }
            }
        }

        private fun handleResponse(response: ByteArray) {
            // Need at least the 12-byte DNS header to validate the QR bit.
            if (response.size < 12) return
            // Reject packets that aren't DNS responses (QR bit = 1 in byte 2). Combined
            // with the connect()'d upstream socket this rules out garbage / spoofs.
            if ((response[2].toInt() and 0x80) == 0) return

            val ourTxId = ((response[0].toInt() and 0xFF) shl 8) or
                           (response[1].toInt() and 0xFF)
            val entry = pending.remove(ourTxId) ?: return

            // Restore the original txId so the client matches its query.
            response[0] = ((entry.originalTxId shr 8) and 0xFF).toByte()
            response[1] = (entry.originalTxId and 0xFF).toByte()

            val ipPacket = wrapInIpUdp(
                response,
                intArrayOf(10, 0, 0, 1),
                byteArrayToIntArray(entry.srcIpBytes),
                DNS_PORT,
                entry.srcPort
            )
            synchronized(outputLock) {
                try { outputStream.write(ipPacket) } catch (_: Exception) {}
            }
        }

        private suspend fun sweepLoop() {
            while (scope.isActive) {
                delay(UPSTREAM_TIMEOUT_MS)
                val now = System.currentTimeMillis()
                val expired = pending.entries.filter { it.value.expiresAt <= now }.map { it.key }
                expired.forEach { pending.remove(it) }
            }
        }
    }
}

// Limit number of attempts when probing for a free upstream txId slot.
private const val MAX_TXID_ATTEMPTS = 8

private class Pending(
    val originalTxId: Int,
    val srcIpBytes: ByteArray,
    val srcPort: Int,
    val expiresAt: Long
)

/**
 * In-memory ring of [DnsEvent]s flushed to [ScanRepository] in batches. Replaces the
 * previous "one Room transaction per DNS query" hot path.
 *
 * Thread model: [add] is called from the VPN read loop (single-threaded). [flushNow]
 * runs on the periodic flush coroutine. The buffer list is guarded by `synchronized`.
 */
private class DnsLogBuffer(
    private val scope: CoroutineScope,
    private val repository: ScanRepository
) {
    private val maxSize: Int = 100
    private val flushIntervalMs: Long = 2_000L

    private val lock = Any()
    private val buffer = ArrayList<DnsEvent>(128)
    private var flushJob: Job? = null

    fun start() {
        flushJob = scope.launch {
            while (scope.isActive) {
                delay(flushIntervalMs)
                flushNow()
            }
        }
    }

    fun stop() {
        flushJob?.cancel()
        flushJob = null
    }

    /**
     * Cancels the periodic flush job and runs one final flush *synchronously*. Called
     * from [DnsVpnService.stopVpn] inside `runBlocking { withTimeoutOrNull(...) }` so
     * the last batch of events is persisted before the service scope is cancelled.
     */
    suspend fun flushAndStop() {
        stop()
        flushNow()
    }

    fun add(event: DnsEvent) {
        val shouldFlushImmediately: Boolean
        synchronized(lock) {
            buffer.add(event)
            shouldFlushImmediately = buffer.size >= maxSize
        }
        if (shouldFlushImmediately) {
            scope.launch { flushNow() }
        }
    }

    private suspend fun flushNow() {
        val snapshot: List<DnsEvent>
        synchronized(lock) {
            if (buffer.isEmpty()) return
            snapshot = buffer.toList()
            buffer.clear()
        }
        @Suppress("TooGenericExceptionCaught", "SwallowedException")
        try {
            repository.logDnsEventsBatch(snapshot)
        } catch (e: Exception) {
            Log.w("DnsLogBuffer", "flush failed: ${e.message}")
        }
    }
}
