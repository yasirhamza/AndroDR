package com.androdr.network

import android.content.Context
import android.net.ConnectivityManager
import android.os.Build
import android.util.Log
import java.net.InetSocketAddress

/** Which uid owns a socket. Android answers this for the active VPN app (API 29+). */
fun interface SocketOwnerLookup {
    fun ownerUid(protocol: Int, local: InetSocketAddress, remote: InetSocketAddress): Int
}

/** Which packages share a uid. */
fun interface UidPackageLookup {
    fun packagesForUid(uid: Int): List<String>
}

/**
 * Resolves the app behind a socket the VPN saw a packet from.
 *
 * The tunnel carries a DNS query as an IPv4/UDP packet whose source port belongs
 * to whichever socket sent it. [ConnectivityManager.getConnectionOwnerUid] maps
 * that socket to a uid -- a privilege the platform grants specifically to the
 * active VPN -- and the package manager maps the uid to a package. Until this
 * existed every DNS event was recorded as `appUid = -1, appName = null` and the
 * report read `<- unknown` on all 500 rows.
 *
 * Honesty rules: a lookup that fails or returns nothing is [Owner.UNKNOWN], never a
 * guess. A uid with no package -- [DNS_RESOLVER_UID], the resolver daemon that
 * queries on apps' behalf, or `system` -- keeps its uid so the report can label it
 * for what it is. uid -> package is cached; the socket lookup is not, because a
 * port is reused.
 */
open class ConnectionOwnerResolver(
    private val sockets: SocketOwnerLookup?,
    private val packages: UidPackageLookup,
) {
    data class Owner(val uid: Int, val packageName: String?) {
        companion object {
            val UNKNOWN = Owner(UNKNOWN_UID, null)
        }
    }

    private val packageByUid = HashMap<Int, String?>()

    @Suppress("TooGenericExceptionCaught") // a lookup failure must degrade to unknown, never stop the VPN
    open fun resolve(protocol: Int, local: InetSocketAddress, remote: InetSocketAddress): Owner {
        val lookup = sockets ?: return Owner.UNKNOWN
        val uid = try {
            lookup.ownerUid(protocol, local, remote)
        } catch (e: Exception) {
            Log.w(TAG, "socket owner lookup failed: ${e.message}")
            UNKNOWN_UID
        }
        if (uid < 0) return Owner.UNKNOWN
        val packageName = synchronized(packageByUid) {
            if (packageByUid.containsKey(uid)) {
                packageByUid[uid]
            } else {
                packages.packagesForUid(uid).minOrNull().also { packageByUid[uid] = it }
            }
        }
        return Owner(uid, packageName)
    }

    companion object {
        private const val TAG = "ConnectionOwner"

        /** No owner could be determined. Matches `Process.INVALID_UID`. */
        const val UNKNOWN_UID = -1

        /** `AID_DNS`: netd's resolver daemon, which performs DNS queries on apps' behalf. */
        const val DNS_RESOLVER_UID = 1051

        const val IPPROTO_UDP = 17

        /** The real thing: socket lookups on API 29+, none below; packages from the package manager. */
        fun fromSystem(context: Context): ConnectionOwnerResolver {
            val pm = context.packageManager
            val packages = UidPackageLookup { uid -> pm.getPackagesForUid(uid)?.toList().orEmpty() }
            val sockets = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                val cm = context.getSystemService(ConnectivityManager::class.java)
                SocketOwnerLookup { protocol, local, remote -> cm.getConnectionOwnerUid(protocol, local, remote) }
            } else {
                null
            }
            return ConnectionOwnerResolver(sockets, packages)
        }
    }
}
