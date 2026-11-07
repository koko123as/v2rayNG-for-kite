package com.v2ray.ang.core

import com.v2ray.ang.AppConfig
import com.v2ray.ang.enums.CoreType
import libv2ray.CoreOptions

/** Run mode of the daemon, as LauncherManager picks the service. */
enum class RunMode(val value: String) {
    VPN("vpn"),
    PROXY("proxy"),
    ROOT("root"),
}

/**
 * Decides which listeners mihomo / sing-box open for a run mode. Pure, so the lifecycle decision
 * is unit-tested; [CoreServiceManager] gathers the inputs and hands the result to libkite.
 *
 * - VPN: mihomo gets the VpnService descriptor ([Input.tunFd]); sing-box opens its own tun
 *   through the platform, so it gets no descriptor. With root LAN sharing the core also opens
 *   its redirect and DNS listeners for tethered clients.
 * - Root: the redirect (TCP) and DNS listeners iptables points at. TPROXY is not used: the
 *   listener needs IP_TRANSPARENT (CAP_NET_ADMIN), which the app process does not have.
 * - Proxy only: the mixed listener, which VPN and root mode also open when the local proxy is on.
 */
object KiteRunOptions {

    data class Input(
        val mode: RunMode,
        val core: CoreType,
        val tunFd: Int = 0,
        val vpnIpv4: String = "",
        val vpnIpv6: String = "",
        val ipv6: Boolean = false,
        val mtu: Int = AppConfig.VPN_MTU,
        val bypassLan: Boolean = false,
        val vpnDns: String = "",
        val localProxyEnabled: Boolean = true,
        val proxySharing: Boolean = false,
        val socksPort: Int = AppConfig.PORT_SOCKS.toInt(),
        val socksUsername: String? = null,
        val socksPassword: String? = null,
        val rootLanSharing: Boolean = false,
        val homeDir: String = "",
        val assetDir: String = "",
        val logLevel: String = "warning",
        val systemDns: String = "",
        val sniffing: Boolean = true,
    )

    data class Spec(
        val mode: String,
        val tunFd: Int = 0,
        val tunInet4: String = "",
        val tunInet6: String = "",
        val tunMtu: Int = 0,
        val tunBypassLan: Boolean = false,
        val tunDns: String = "",
        val ipv6: Boolean = false,
        val mixedPort: Int = 0,
        val mixedListen: String = "",
        val mixedUser: String = "",
        val mixedPass: String = "",
        val redirPort: Int = 0,
        val dnsPort: Int = 0,
        val dnsListen: String = "",
        val homeDir: String = "",
        val assetDir: String = "",
        val logLevel: String = "",
        val systemDns: String = "",
        val sniffing: Boolean = true,
    )

    fun build(input: Input): Spec {
        require(input.core != CoreType.XRAY) { "Xray does not use libkite run options" }
        val mixed = input.mode == RunMode.PROXY || input.localProxyEnabled
        val credentials = input.socksUsername != null && input.socksPassword != null
        val vpn = input.mode == RunMode.VPN
        val redirect = input.mode == RunMode.ROOT || (vpn && input.rootLanSharing)
        val lanListen = input.rootLanSharing
        return Spec(
            mode = input.mode.value,
            tunFd = if (vpn && input.core == CoreType.MIHOMO) input.tunFd else 0,
            tunInet4 = if (vpn) "${input.vpnIpv4}/30" else "",
            tunInet6 = if (vpn && input.ipv6) "${input.vpnIpv6}/126" else "",
            tunMtu = if (vpn) input.mtu else 0,
            tunBypassLan = vpn && input.bypassLan,
            tunDns = if (vpn) input.vpnDns else "",
            ipv6 = input.ipv6,
            mixedPort = if (mixed) input.socksPort else 0,
            mixedListen = if (!mixed) "" else if (input.proxySharing) "0.0.0.0" else AppConfig.LOOPBACK,
            mixedUser = if (mixed && credentials) input.socksUsername.orEmpty() else "",
            mixedPass = if (mixed && credentials) input.socksPassword.orEmpty() else "",
            redirPort = if (redirect) AppConfig.PORT_ROOT_REDIR else 0,
            dnsPort = if (redirect) AppConfig.PORT_ROOT_DNS else 0,
            // Tethered clients reach the listeners on the device's LAN address.
            dnsListen = if (!redirect) "" else if (lanListen) "0.0.0.0" else AppConfig.LOOPBACK,
            homeDir = input.homeDir,
            assetDir = input.assetDir,
            logLevel = input.logLevel,
            systemDns = input.systemDns,
            sniffing = input.sniffing,
        )
    }

    /** The libkite object for [spec]. */
    fun toCoreOptions(spec: Spec): CoreOptions = CoreOptions().apply {
        mode = spec.mode
        tunFd = spec.tunFd
        tunInet4 = spec.tunInet4
        tunInet6 = spec.tunInet6
        setTunMTU(spec.tunMtu)
        tunBypassLan = spec.tunBypassLan
        setTunDNS(spec.tunDns)
        setIPv6(spec.ipv6)
        mixedPort = spec.mixedPort
        mixedListen = spec.mixedListen
        mixedUser = spec.mixedUser
        mixedPass = spec.mixedPass
        redirPort = spec.redirPort
        setTProxyListen("::")
        setDNSPort(spec.dnsPort)
        setDNSListen(spec.dnsListen)
        homeDir = spec.homeDir
        assetDir = spec.assetDir
        logLevel = spec.logLevel
        setSystemDNS(spec.systemDns)
        sniffing = spec.sniffing
    }
}
