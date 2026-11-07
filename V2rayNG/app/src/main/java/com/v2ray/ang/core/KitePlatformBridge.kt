package com.v2ray.ang.core

import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.os.Build
import android.system.OsConstants
import com.v2ray.ang.AppConfig
import com.v2ray.ang.contracts.TunOpener
import com.v2ray.ang.util.LogUtil
import libv2ray.KitePlatform
import libv2ray.TunConfig
import java.net.InetSocketAddress
import java.net.NetworkInterface
import java.util.concurrent.ConcurrentHashMap

/**
 * Android side of libkite's KitePlatform, used by all three cores in the daemon process:
 * socket protection through the running service, connection owner lookup, package names,
 * the sing-box VpnService, the interface list and log forwarding.
 *
 * Separate from [CoreServiceManager] because Go calls it from core threads for the lifetime of
 * the process; it holds no lifecycle state besides the current [tunOpener].
 */
class KitePlatformBridge(context: Context) : KitePlatform {

    private val appContext = context.applicationContext
    private val connectivity: ConnectivityManager? = appContext.getSystemService(ConnectivityManager::class.java)
    private val packageNames = ConcurrentHashMap<Int, String>()

    /** The VPN service while it runs a sing-box profile, null otherwise. */
    @Volatile
    var tunOpener: TunOpener? = null

    override fun protect(fd: Int): Boolean {
        val control = CoreServiceManager.serviceControl?.get() ?: return true
        return control.vpnProtect(fd)
    }

    override fun findConnectionOwner(ipProtocol: Int, srcIP: String, srcPort: Int, dstIP: String, dstPort: Int): Int {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) return -1
        val cm = connectivity ?: return -1
        val protocol = when (ipProtocol) {
            OsConstants.IPPROTO_TCP -> OsConstants.IPPROTO_TCP
            OsConstants.IPPROTO_UDP -> OsConstants.IPPROTO_UDP
            else -> return -1
        }
        return try {
            cm.getConnectionOwnerUid(protocol, InetSocketAddress(srcIP, srcPort), InetSocketAddress(dstIP, dstPort))
        } catch (_: Exception) {
            // Only the active VPN app may ask; root and proxy-only mode get no answer.
            -1
        }
    }

    override fun packageNameByUid(uid: Int): String {
        if (uid < 0) return ""
        packageNames[uid]?.let { return it }
        val name = try {
            appContext.packageManager.getPackagesForUid(uid)?.firstOrNull().orEmpty()
        } catch (_: Exception) {
            ""
        }
        if (name.isNotEmpty()) packageNames[uid] = name
        return name
    }

    override fun openTun(options: TunConfig): Int {
        val opener = tunOpener ?: throw IllegalStateException("No VPN service to open the tun interface")
        return opener.openTun(options)
    }

    override fun networkInterfaces(): String {
        val defaultName = defaultInterfaceName()
        val defaultDns = systemDnsServers()
        val defaultMetered = connectivity?.isActiveNetworkMetered == true
        val lines = mutableListOf<String>()
        try {
            val interfaces = NetworkInterface.getNetworkInterfaces() ?: return ""
            for (networkInterface in interfaces) {
                val name = networkInterface.name ?: continue
                val addresses = networkInterface.interfaceAddresses.mapNotNull { address ->
                    val host = address.address?.hostAddress?.substringBefore('%') ?: return@mapNotNull null
                    "$host/${address.networkPrefixLength}"
                }
                var flags = 0
                if (networkInterface.isUp) flags = flags or FLAG_UP or FLAG_RUNNING
                if (networkInterface.interfaceAddresses.any { it.broadcast != null }) flags = flags or FLAG_BROADCAST
                if (networkInterface.isLoopback) flags = flags or FLAG_LOOPBACK
                if (networkInterface.isPointToPoint) flags = flags or FLAG_POINT_TO_POINT
                if (networkInterface.supportsMulticast()) flags = flags or FLAG_MULTICAST
                val isDefault = name == defaultName
                val mtu = try {
                    networkInterface.mtu
                } catch (_: Exception) {
                    1500
                }
                lines.add(
                    listOf(
                        name,
                        networkInterface.index.toString(),
                        mtu.toString(),
                        flags.toString(),
                        addresses.joinToString(","),
                        if (isDefault) defaultDns else "",
                        interfaceType(name, isDefault),
                        if (isDefault && defaultMetered) "1" else "0",
                    ).joinToString("|")
                )
            }
        } catch (e: Exception) {
            LogUtil.e(AppConfig.TAG, "KitePlatform: failed to list interfaces", e)
        }
        return lines.joinToString("\n")
    }

    override fun writeLog(level: Int, message: String) {
        when (level) {
            LEVEL_DEBUG -> LogUtil.d(AppConfig.TAG, message)
            LEVEL_INFO -> LogUtil.i(AppConfig.TAG, message)
            LEVEL_WARNING -> LogUtil.w(AppConfig.TAG, message)
            else -> LogUtil.e(AppConfig.TAG, message)
        }
    }

    /**
     * Tells the cores about the underlying network: sing-box's default interface and mihomo's
     * "system" DNS servers. The app is excluded from its own VPN, so the active network seen here
     * is the physical one.
     */
    fun pushNetworkState() {
        try {
            val name = defaultInterfaceName()
            val index = name?.let { runCatching { NetworkInterface.getByName(it)?.index }.getOrNull() } ?: -1
            CoreNativeManager.updateDefaultInterface(name.orEmpty(), index)
            CoreNativeManager.updateSystemDns(systemDnsServers())
        } catch (e: Exception) {
            LogUtil.w(AppConfig.TAG, "KitePlatform: failed to push network state: ${e.message}")
        }
    }

    /** DNS servers of the active network, comma separated. */
    fun systemDnsServers(): String {
        val cm = connectivity ?: return ""
        return try {
            val network = cm.activeNetwork ?: return ""
            cm.getLinkProperties(network)?.dnsServers.orEmpty()
                .mapNotNull { it.hostAddress?.substringBefore('%') }
                .joinToString(",")
        } catch (_: Exception) {
            ""
        }
    }

    private fun defaultInterfaceName(): String? {
        val cm = connectivity ?: return null
        return try {
            val network = cm.activeNetwork ?: return null
            val capabilities = cm.getNetworkCapabilities(network)
            if (capabilities?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true) return null
            cm.getLinkProperties(network)?.interfaceName
        } catch (_: Exception) {
            null
        }
    }

    private fun interfaceType(name: String, isDefault: Boolean): String {
        if (isDefault) {
            val cm = connectivity
            val capabilities = try {
                cm?.activeNetwork?.let { cm.getNetworkCapabilities(it) }
            } catch (_: Exception) {
                null
            }
            when {
                capabilities?.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) == true -> return "wifi"
                capabilities?.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) == true -> return "cellular"
                capabilities?.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) == true -> return "ethernet"
            }
        }
        return when {
            name.startsWith("wlan") || name.startsWith("swlan") -> "wifi"
            name.startsWith("rmnet") || name.startsWith("ccmni") || name.startsWith("seth") || name.startsWith("pdp") -> "cellular"
            name.startsWith("eth") -> "ethernet"
            else -> "other"
        }
    }

    private companion object {
        // net.Flags bits in Go.
        const val FLAG_UP = 1
        const val FLAG_BROADCAST = 2
        const val FLAG_LOOPBACK = 4
        const val FLAG_POINT_TO_POINT = 8
        const val FLAG_MULTICAST = 16
        const val FLAG_RUNNING = 32

        // libkite LogLevel* constants.
        const val LEVEL_DEBUG = 0
        const val LEVEL_INFO = 1
        const val LEVEL_WARNING = 2
    }
}
