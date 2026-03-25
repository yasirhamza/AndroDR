package com.androdr.network

import android.content.Intent
import android.net.VpnService
import android.os.ParcelFileDescriptor
import com.androdr.data.model.DnsEvent
import com.androdr.data.repo.ScanRepository
import dagger.hilt.android.AndroidEntryPoint
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.nio.ByteBuffer
import kotlinx.coroutines.flow.MutableStateFlow
import javax.inject.Inject

/**
 * VPN service that intercepts all device traffic, parses DNS queries (UDP port 53),
 * and either blocks or proxies them based on [BlocklistManager].
 *
 * Blocked queries receive an immediate NXDOMAIN response; allowed queries are forwarded
 * to Google's public DNS server at 8.8.8.8 and the real reply is relayed back to the app.
 *
 * All network I/O runs on [Dispatchers.IO] inside a [CoroutineScope] that is cancelled
 * when the service is stopped.
 */
@Suppress("TooManyFunctions") // VpnService lifecycle + DNS wire-format helpers are all required in
// this class; extraction to utilities would break the VpnService.protect() call chain.
@AndroidEntryPoint
class DnsVpnService : VpnService() {

    companion object {
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
    }

    @Suppress("LateinitUsage") // Hilt @Inject requires lateinit; null-safety is guaranteed by Hilt
    @Inject lateinit var blocklistManager: BlocklistManager
    @Suppress("LateinitUsage") // Hilt @Inject requires lateinit; null-safety is guaranteed by Hilt
    @Inject lateinit var scanRepository: ScanRepository

    private var tunFd: ParcelFileDescriptor? = null
    private val serviceScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private var readLoopJob: Job? = null

    // ── Lifecycle ─────────────────────────────────────────────────────────────

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP  -> stopVpn()
            else         -> startVpn()   // ACTION_START or null (system restart)
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

    @Suppress("ReturnCount") // Multiple early returns on failure paths are idiomatic in Android
    // service startup; exceptions and null results each warrant a distinct failure return.
    private fun startVpn() {
        if (isRunning.value) return  // already running — ignore duplicate start

        @Suppress("TooGenericExceptionCaught", "SwallowedException") // VpnService.Builder.establish
        // can throw SecurityException or IllegalArgumentException; both are unrecoverable here.
        val fd = try {
            Builder()
                .addAddress(TUN_ADDRESS, TUN_PREFIX_LEN)
                .addDnsServer(DNS_SERVER_IP)
                .addRoute("0.0.0.0", 0)
                .setSession("AndroDR DNS Filter")
                .setBlocking(false)
                .establish()
        } catch (e: Exception) {
            return
        } ?: return   // establish() returns null if the user hasn't granted VPN permission

        tunFd = fd
        isRunning.value = true

        readLoopJob = serviceScope.launch {
            runPacketLoop(fd)
        }
    }

    private fun stopVpn() {
        isRunning.value = false
        readLoopJob?.cancel()
        readLoopJob = null
        try { tunFd?.close() } catch (_: Exception) {}
        tunFd = null
        stopSelf()
    }

    // ── Packet processing loop ────────────────────────────────────────────────

    /**
     * Reads raw IP packets from the tun device, identifies UDP/53 DNS queries, and
     * either responds with NXDOMAIN (blocked) or forwards to the real upstream resolver.
     *
     * Non-DNS packets are silently dropped — they will be retransmitted by the stack after
     * a timeout.  (A production implementation would forward all non-DNS packets through a
     * real tun; this implementation focuses on DNS interception only.)
     */
    @Suppress("LoopWithTooManyJumpStatements") // Packet read loop uses break on IOException (VPN
    // revoke) and continue on zero-byte reads; both are idiomatic for non-blocking tun fd polling.
    private suspend fun runPacketLoop(fd: ParcelFileDescriptor) {
        val inputStream  = FileInputStream(fd.fileDescriptor)
        val outputStream = FileOutputStream(fd.fileDescriptor)
        val buffer       = ByteArray(MAX_DNS_PACKET_SIZE)

        while (serviceScope.isActive && isRunning.value) {
            @Suppress("TooGenericExceptionCaught", "SwallowedException") // FileInputStream.read
            // on the tun fd throws IOException when the VPN is revoked; breaking the loop is correct.
            val bytesRead = try {
                inputStream.read(buffer)
            } catch (e: Exception) {
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

    /**
     * Inspects a raw IP packet.  If it is a UDP packet destined for port 53 the DNS payload
     * is extracted and handled; all other packets are silently dropped.
     */
    @Suppress("LongMethod", "ReturnCount", "LoopWithTooManyJumpStatements") // IP/UDP/DNS packet
    // parsing requires guard returns at each validation step; reducing ReturnCount here would add
    // deeply nested conditionals that are harder to follow than early-return validation guards.
    private fun processPacket(packet: ByteArray, outputStream: FileOutputStream) {
        if (packet.size < 20) return  // too short to be a valid IPv4 header

        val buf = ByteBuffer.wrap(packet)

        // Parse IPv4 header
        val versionAndIhl = buf.get(0).toInt() and 0xFF
        val version       = versionAndIhl shr 4
        if (version != 4) return   // only handle IPv4

        val ihl          = (versionAndIhl and 0x0F) * 4   // IP header length in bytes
        if (packet.size < ihl + 8) return                  // need at least IP + UDP header

        val protocol = buf.get(9)
        if (protocol != IP_PROTOCOL_UDP) return            // only care about UDP

        // Parse UDP header (starts at byte ihl)
        val dstPort = ((buf.get(ihl + 2).toInt() and 0xFF) shl 8) or
                       (buf.get(ihl + 3).toInt() and 0xFF)
        if (dstPort != DNS_PORT) return                    // only care about DNS (port 53)

        val srcPort = ((buf.get(ihl).toInt() and 0xFF) shl 8) or
                       (buf.get(ihl + 1).toInt() and 0xFF)

        // UDP payload starts after the 8-byte UDP header
        val udpPayloadOffset = ihl + 8
        if (packet.size <= udpPayloadOffset) return

        val dnsPayload = packet.copyOfRange(udpPayloadOffset, packet.size)
        if (dnsPayload.size < 12) return   // DNS header is 12 bytes

        // Extract the DNS transaction ID so we can build a matching response
        val txId = ((dnsPayload[0].toInt() and 0xFF) shl 8) or
                    (dnsPayload[1].toInt() and 0xFF)

        // Parse the queried hostname from the DNS question section
        val hostname = parseDnsHostname(dnsPayload) ?: return

        // Extract source IP address (bytes 12–15) so we can route the reply back
        val srcIpBytes = packet.copyOfRange(12, 16)

        if (blocklistManager.isBlocked(hostname)) {
            // Log the block event (fire-and-forget on IO dispatcher)
            serviceScope.launch {
                runCatching {
                    scanRepository.logDnsEvent(
                        DnsEvent(
                            timestamp = System.currentTimeMillis(),
                            domain    = hostname,
                            appUid    = -1,
                            appName   = null,
                            isBlocked = true,
                            reason    = "Domain matched blocklist"
                        )
                    )
                }
            }

            // Send NXDOMAIN response back through the tun interface
            val nxResponse = buildNxdomainResponse(dnsPayload, txId)
            val responsePacket = wrapInIpUdp(
                payload    = nxResponse,
                srcIp      = intArrayOf(10, 0, 0, 1),   // DNS_SERVER_IP virtual address
                dstIp      = byteArrayToIntArray(srcIpBytes),
                srcPort    = DNS_PORT,
                dstPort    = srcPort
            )
            try { outputStream.write(responsePacket) } catch (_: Exception) {}
        } else {
            // Forward to upstream DNS and relay the real response
            serviceScope.launch {
                val response = forwardToUpstreamDns(dnsPayload) ?: return@launch
                val responsePacket = wrapInIpUdp(
                    payload    = response,
                    srcIp      = intArrayOf(10, 0, 0, 1),
                    dstIp      = byteArrayToIntArray(srcIpBytes),
                    srcPort    = DNS_PORT,
                    dstPort    = srcPort
                )
                try { outputStream.write(responsePacket) } catch (_: Exception) {}

                // Optionally log allowed events (omit to reduce DB noise — uncomment if needed)
                // scanRepository.logDnsEvent(DnsEvent(..., isBlocked = false, ...))
            }
        }
    }

    // ── DNS wire-format helpers ───────────────────────────────────────────────

    /**
     * Parses the QNAME from the DNS question section.
     *
     * DNS message layout:
     * ```
     * bytes 0–1   : Transaction ID
     * bytes 2–3   : Flags
     * bytes 4–5   : QDCOUNT
     * bytes 6–7   : ANCOUNT
     * bytes 8–9   : NSCOUNT
     * bytes 10–11 : ARCOUNT
     * byte  12+   : Question section (QNAME labels + QTYPE + QCLASS)
     * ```
     *
     * QNAME is encoded as a sequence of length-prefixed labels terminated by a zero byte.
     */
    @Suppress("TooGenericExceptionCaught", "SwallowedException", "ReturnCount",
        "LoopWithTooManyJumpStatements") // Malformed DNS packets from the tun fd can throw
    // ArrayIndexOutOfBoundsException; guard returns and loop jumps are idiomatic for packet parsing.
    private fun parseDnsHostname(dns: ByteArray): String? {
        if (dns.size < 13) return null

        val sb = StringBuilder()
        var pos = 12   // question section starts after the 12-byte DNS header

        try {
            while (pos < dns.size) {
                val labelLen = dns[pos].toInt() and 0xFF
                if (labelLen == 0) break                   // end of QNAME

                // Handle DNS compression pointer (top two bits set = 0xC0)
                if (labelLen and 0xC0 == 0xC0) {
                    // Compression pointers are uncommon in queries but handle gracefully
                    break
                }

                pos++
                if (pos + labelLen > dns.size) return null // malformed

                if (sb.isNotEmpty()) sb.append('.')
                sb.append(String(dns, pos, labelLen, Charsets.US_ASCII))
                pos += labelLen
            }
        } catch (e: Exception) {
            return null
        }

        return if (sb.isEmpty()) null else sb.toString()
    }

    /**
     * Builds a minimal DNS NXDOMAIN response for the given query payload.
     *
     * Flags set: QR=1 (response), OPCODE=0 (QUERY), AA=0, TC=0, RD=1 (copy from query),
     * RA=0, RCODE=3 (NXDOMAIN).  The question section is echoed back; no answer records.
     */
    @Suppress("UnusedParameter") // txId is kept in the signature for DNS wire-format clarity —
    // the transaction ID is implicitly preserved by copying query bytes 0-1 into the response.
    private fun buildNxdomainResponse(query: ByteArray, txId: Int): ByteArray {
        val response = query.copyOf()   // echo the full query as the response skeleton

        // Byte 0–1: Transaction ID (already correct)
        // Byte 2–3: Flags — QR=1, OPCODE=0, AA=0, TC=0, RD=copy, RA=0, RCODE=3 (NXDOMAIN)
        val rdFlag   = (query[2].toInt() and 0x01) shl 0   // preserve RD bit
        response[2]  = (0x81 or rdFlag).toByte()           // QR + AA=0 + RD
        response[3]  = 0x03.toByte()                       // RCODE = NXDOMAIN

        // Zero out answer/authority/additional record counts (bytes 6–11)
        response[6]  = 0; response[7]  = 0   // ANCOUNT = 0
        response[8]  = 0; response[9]  = 0   // NSCOUNT = 0
        response[10] = 0; response[11] = 0   // ARCOUNT = 0

        return response
    }

    /**
     * Forwards a raw DNS query payload to [UPSTREAM_DNS_HOST] via a real UDP socket
     * (which is protected from the VPN tunnel via [VpnService.protect]) and returns
     * the upstream response payload, or `null` on error.
     */
    private fun forwardToUpstreamDns(dnsPayload: ByteArray): ByteArray? {
        @Suppress("TooGenericExceptionCaught", "SwallowedException") // DNS socket operations can
        // throw IOException (timeout), SocketException, or UnknownHostException; null = drop packet.
        return try {
            val socket = DatagramSocket()
            protect(socket)   // exclude from VPN tunnel to prevent routing loops

            val upstreamAddr = InetAddress.getByName(UPSTREAM_DNS_HOST)
            val sendPacket = DatagramPacket(
                dnsPayload, dnsPayload.size,
                upstreamAddr, UPSTREAM_DNS_PORT
            )
            socket.soTimeout = 3000
            socket.send(sendPacket)

            val responseBuffer = ByteArray(MAX_DNS_PACKET_SIZE)
            val responsePacket = DatagramPacket(responseBuffer, responseBuffer.size)
            socket.receive(responsePacket)
            socket.close()

            responseBuffer.copyOf(responsePacket.length)
        } catch (e: Exception) {
            null
        }
    }

    /**
     * Wraps a UDP payload in IPv4 + UDP headers suitable for writing to the tun fd.
     *
     * Checksums:
     * - IP checksum is computed properly (RFC 791).
     * - UDP checksum is set to 0 (optional per RFC 768; receivers must accept it).
     */
    private fun wrapInIpUdp(
        payload: ByteArray,
        srcIp:   IntArray,
        dstIp:   IntArray,
        srcPort: Int,
        dstPort: Int
    ): ByteArray {
        val udpLength  = 8 + payload.size
        val ipLength   = 20 + udpLength
        val buf        = ByteBuffer.allocate(ipLength)

        // ── IPv4 header (20 bytes, no options) ────────────────────────────────
        buf.put(0x45.toByte())                            // Version=4, IHL=5
        buf.put(0x00.toByte())                            // DSCP/ECN
        buf.putShort(ipLength.toShort())                  // Total length
        buf.putShort(0x0000)                              // Identification
        buf.putShort(0x4000)                              // Flags=DF, Fragment offset=0
        buf.put(0x40.toByte())                            // TTL = 64
        buf.put(IP_PROTOCOL_UDP)                          // Protocol = UDP
        buf.putShort(0x0000)                              // Header checksum (filled below)
        srcIp.forEach { buf.put(it.toByte()) }
        dstIp.forEach { buf.put(it.toByte()) }

        // Compute and fill IP header checksum
        val ipHeaderChecksum = ipChecksum(buf.array(), 0, 20)
        buf.putShort(10, ipHeaderChecksum.toShort())

        // ── UDP header (8 bytes) ───────────────────────────────────────────────
        buf.putShort(srcPort.toShort())
        buf.putShort(dstPort.toShort())
        buf.putShort(udpLength.toShort())
        buf.putShort(0x0000)   // UDP checksum = 0 (optional)

        // ── UDP payload ────────────────────────────────────────────────────────
        buf.put(payload)

        return buf.array()
    }

    /**
     * Computes the one's-complement Internet checksum over [length] bytes of [data]
     * starting at [offset], as required by the IPv4 header checksum field (RFC 1071).
     */
    private fun ipChecksum(data: ByteArray, offset: Int, length: Int): Int {
        var sum = 0
        var i   = offset
        val end = offset + length

        while (i < end - 1) {
            sum += ((data[i].toInt() and 0xFF) shl 8) or (data[i + 1].toInt() and 0xFF)
            i   += 2
        }
        if (i < end) {
            // Odd byte — pad with zero
            sum += (data[i].toInt() and 0xFF) shl 8
        }

        // Fold 32-bit sum into 16 bits
        while (sum shr 16 != 0) {
            sum = (sum and 0xFFFF) + (sum shr 16)
        }
        return sum.inv() and 0xFFFF
    }

    // ── Utility ───────────────────────────────────────────────────────────────

    private fun byteArrayToIntArray(bytes: ByteArray): IntArray =
        IntArray(bytes.size) { bytes[it].toInt() and 0xFF }
}
