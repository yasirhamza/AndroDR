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
import android.system.Os
import android.system.OsConstants
import android.system.StructPollfd
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
 *     does not need, so `specialUse` is the right pragmatic choice; the subtype is
 *     justified in the Play Console special-use declaration form.)
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

        // Upstream DNS port (the resolver ADDRESS comes from UnderlyingDnsTracker — #303)
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

        // Packet-read poll timeout. Short enough that shutdown is prompt when
        // the VPN is stopped, long enough that the loop wakes up maybe a few
        // times per second when traffic is sparse.
        private const val POLL_TIMEOUT_MS = 500

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
    private var dnsTracker: UnderlyingDnsTracker? = null

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

        // #303: resolve the device's real DNS servers BEFORE establishing the
        // tunnel. No resolvers -> do not capture device DNS at all (a captured
        // tunnel with nowhere to forward would black-hole the whole device;
        // monitor-off is strictly better). There is NO hardcoded fallback.
        val tracker = UnderlyingDnsTracker(this).also { it.start() }
        if (tracker.resolvers.value.isEmpty()) {
            Log.w(TAG, "DnsVpnService: no non-VPN DNS resolvers available; not starting monitor")
            tracker.stop()
            stopSelf()
            return
        }
        // Non-clobbering: if a previous tracker is still hanging around (shouldn't
        // normally happen — guarded by isRunning/stopVpn — but belt-and-braces
        // against ever silently leaking a registered NetworkCallback here).
        dnsTracker?.stop()
        dnsTracker = tracker

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
            stopVpn()
            return
        } ?: run {
            stopVpn()
            return
        }

        tunFd = fd
        startForegroundCompat()
        isRunning.value = true

        val outputStream = FileOutputStream(fd.fileDescriptor)

        logBuffer = DnsLogBuffer(serviceScope, scanRepository).also { it.start() }
        resolver = UpstreamResolver(serviceScope, this, outputStream, outputLock, tracker.resolvers).also {
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
        if (!isRunning.value && tunFd == null && resolver == null &&
            logBuffer == null && dnsTracker == null
        ) {
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
        dnsTracker?.stop()
        dnsTracker = null
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

    /**
     * Reads raw IP packets from the tun fd, identifies UDP/53 DNS queries, and
     * hands them off to [processPacket].
     *
     * ## Why Os.poll instead of FileInputStream.read()
     *
     * VpnService hands us a non-blocking tun file descriptor. A plain
     * `FileInputStream.read()` on that fd returns zero bytes immediately when
     * no packet is available, which turns the packet read loop into a tight
     * busy-spin that burns ~100 % of a CPU core even when the device is idle
     * and the tunnel has zero traffic. That was the single biggest contributor
     * to AndroDR's VPN-mode battery drain — bigger than any of the per-query
     * issues addressed in earlier commits.
     *
     * The fix is to block-wait on the fd via `android.system.Os.poll()` before
     * calling `read()`. `Os.poll()` suspends the thread in the kernel until
     * the fd has a pending packet (or the timeout expires), so the read loop
     * uses zero CPU when the tunnel is idle. This is the same pattern
     * NetGuard uses in its native packet path, and the canonical way to
     * block-wait on a non-blocking fd from Java.
     *
     * A short timeout (not infinite) lets us periodically recheck
     * `serviceScope.isActive` / `isRunning.value` so the loop shuts down
     * promptly when the VPN is stopped.
     */
    @Suppress("LoopWithTooManyJumpStatements")
    private suspend fun runPacketLoop(fd: ParcelFileDescriptor, outputStream: FileOutputStream) {
        val inputStream = FileInputStream(fd.fileDescriptor)
        val buffer      = ByteArray(MAX_DNS_PACKET_SIZE)

        val pollfd = StructPollfd().apply {
            this.fd = fd.fileDescriptor
            events = OsConstants.POLLIN.toShort()
        }
        val fds = arrayOf(pollfd)

        while (serviceScope.isActive && isRunning.value) {
            @Suppress("TooGenericExceptionCaught", "SwallowedException")
            val ready = try {
                Os.poll(fds, POLL_TIMEOUT_MS)
            } catch (e: Exception) {
                Log.w(TAG, "DnsVpnService: Os.poll failed: ${e.message}")
                break
            }
            if (ready == 0) continue   // timeout — recheck running flag
            if ((pollfd.revents.toInt() and OsConstants.POLLIN) == 0) continue

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
     * Owns a single `protect()`'d, **`connect()`'d** [DatagramSocket] that all DNS
     * forwards share. Outgoing queries have their 16-bit DNS transaction id rewritten
     * to a unique value so the single receive loop can demux upstream replies and
     * route them back to the correct tun source.
     *
     * #303: the upstream address comes from [UnderlyingDnsTracker] (the device's own
     * configured resolvers) — never a hardcoded host. On resolver change the socket
     * is swapped atomically; in-flight queries on the old socket age out via the
     * sweep, indistinguishable from a normal timeout. If the resolver list goes
     * empty mid-session the last socket is kept (its sends fail like any dead
     * upstream) and recovery is automatic on the next tracker update. connect()
     * makes the kernel reject off-path datagrams, so spoofed responses never reach
     * [handleResponse].
     */
    private inner class UpstreamResolver(
        private val scope: CoroutineScope,
        private val vpnService: VpnService,
        private val outputStream: FileOutputStream,
        private val outputLock: Any,
        private val upstreams: kotlinx.coroutines.flow.StateFlow<List<InetAddress>>,
    ) {
        private inner class Channel(
            val socket: DatagramSocket,
            val addr: InetAddress,
            val receiveJob: Job,
        )

        private val channelRef = java.util.concurrent.atomic.AtomicReference<Channel?>(null)
        private val pending = ConcurrentHashMap<Int, Pending>()
        private val txIdSeq = AtomicInteger(1)
        private var sweepJob: Job? = null
        private var watchJob: Job? = null

        fun start(): Boolean {
            val initial = upstreams.value.firstOrNull()
            if (initial == null) {
                Log.w(TAG, "UpstreamResolver: no configured resolvers at start")
                return false
            }
            val opened = runBlocking(Dispatchers.IO) { openChannel(initial) }
            if (!opened) return false
            sweepJob = scope.launch { sweepLoop() }
            watchJob = scope.launch {
                upstreams.collect { list -> onUpstreamsChanged(list) }
            }
            return true
        }

        fun stop() {
            watchJob?.cancel(); watchJob = null
            sweepJob?.cancel();  sweepJob  = null
            channelRef.getAndSet(null)?.let { ch ->
                ch.receiveJob.cancel()
                try { ch.socket.close() } catch (_: Exception) {}
            }
            pending.clear()
        }

        private fun onUpstreamsChanged(list: List<InetAddress>) {
            val target = list.firstOrNull()
            val current = channelRef.get()
            when {
                // Empty list: keep the current channel — its sends fail like any
                // dead upstream and the next update heals it. NEVER a fallback host.
                target == null -> Log.w(TAG, "UpstreamResolver: resolver list empty; keeping last channel")
                current?.addr == target -> Unit
                else -> {
                    Log.i(TAG, "UpstreamResolver: switching upstream to $target")
                    openChannel(target)
                }
            }
        }

        /** Opens+protects+connects a socket to [addr], swaps it in, closes the old one. */
        @Suppress("TooGenericExceptionCaught")
        private fun openChannel(addr: InetAddress): Boolean {
            // Tracked outside the try so a mid-construction failure (protect()/connect()
            // throwing after the socket is allocated but before it's swapped into
            // channelRef) still gets its fd closed instead of leaking silently (#303).
            var opened: DatagramSocket? = null
            return try {
                val s = DatagramSocket()
                opened = s
                vpnService.protect(s)
                s.connect(addr, UPSTREAM_DNS_PORT)
                s.soTimeout = 0   // blocking; the receive loop runs on its own coroutine
                val job = scope.launch { receiveLoop(s) }
                channelRef.getAndSet(Channel(s, addr, job))?.let { old ->
                    old.receiveJob.cancel()
                    try { old.socket.close() } catch (_: Exception) {}
                }
                true
            } catch (e: Exception) {
                Log.w(TAG, "UpstreamResolver: channel open failed for $addr: ${e.message}")
                try { opened?.close() } catch (_: Exception) {}
                false
            }
        }

        /** Forward a DNS query through the shared upstream socket. Non-blocking. */
        @Suppress("TooGenericExceptionCaught", "SwallowedException", "ReturnCount")
        fun send(dnsPayload: ByteArray, srcIpBytes: ByteArray, srcPort: Int) {
            val ch = channelRef.get() ?: return
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
                ch.socket.send(DatagramPacket(rewritten, rewritten.size))
            } catch (e: Exception) {
                pending.remove(ourTxId)
                Log.w(TAG, "UpstreamResolver: send failed: ${e.message}")
            }
        }

        private suspend fun receiveLoop(s: DatagramSocket) {
            val recvBuf = ByteArray(MAX_DNS_PACKET_SIZE)
            while (scope.isActive && !s.isClosed) {
                @Suppress("TooGenericExceptionCaught", "SwallowedException")
                try {
                    val pkt = DatagramPacket(recvBuf, recvBuf.size)
                    s.receive(pkt)
                    handleResponse(recvBuf.copyOf(pkt.length))
                } catch (e: Exception) {
                    if (!scope.isActive || s.isClosed) break
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
