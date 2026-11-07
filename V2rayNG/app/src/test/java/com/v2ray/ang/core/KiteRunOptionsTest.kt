package com.v2ray.ang.core

import com.v2ray.ang.AppConfig
import com.v2ray.ang.enums.CoreType
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class KiteRunOptionsTest {

    private val vpnInput = KiteRunOptions.Input(
        mode = RunMode.VPN,
        core = CoreType.MIHOMO,
        tunFd = 42,
        vpnIpv4 = "10.10.14.1",
        vpnIpv6 = "fc00::10:10:14:1",
        ipv6 = true,
        mtu = 1500,
        bypassLan = true,
        vpnDns = "1.1.1.1",
        localProxyEnabled = false,
        socksPort = 10808,
    )

    @Test
    fun `mihomo VPN mode gets the VpnService descriptor and no listeners`() {
        val spec = KiteRunOptions.build(vpnInput)

        assertEquals("vpn", spec.mode)
        assertEquals(42, spec.tunFd)
        assertEquals("10.10.14.1/30", spec.tunInet4)
        assertEquals("fc00::10:10:14:1/126", spec.tunInet6)
        assertEquals(1500, spec.tunMtu)
        assertTrue(spec.tunBypassLan)
        assertEquals(0, spec.mixedPort)
        assertEquals(0, spec.redirPort)
        assertEquals(0, spec.dnsPort)
    }

    @Test
    fun `sing-box VPN mode opens its own tun and gets no descriptor`() {
        val spec = KiteRunOptions.build(vpnInput.copy(core = CoreType.SING_BOX))

        assertEquals(0, spec.tunFd)
        assertEquals("10.10.14.1/30", spec.tunInet4)
    }

    @Test
    fun `IPv6 off leaves the tun without an IPv6 address`() {
        val spec = KiteRunOptions.build(vpnInput.copy(ipv6 = false))

        assertEquals("", spec.tunInet6)
        assertFalse(spec.ipv6)
    }

    @Test
    fun `root mode opens redirect and DNS listeners on loopback`() {
        val spec = KiteRunOptions.build(KiteRunOptions.Input(mode = RunMode.ROOT, core = CoreType.SING_BOX, localProxyEnabled = false))

        assertEquals("root", spec.mode)
        assertEquals(0, spec.tunFd)
        assertEquals("", spec.tunInet4)
        assertEquals(AppConfig.PORT_ROOT_REDIR, spec.redirPort)
        assertEquals(AppConfig.PORT_ROOT_DNS, spec.dnsPort)
        assertEquals(AppConfig.LOOPBACK, spec.dnsListen)
        assertEquals(0, spec.mixedPort)
    }

    @Test
    fun `LAN sharing makes the DNS listener reachable from clients`() {
        val root = KiteRunOptions.build(KiteRunOptions.Input(mode = RunMode.ROOT, core = CoreType.MIHOMO, rootLanSharing = true))
        assertEquals("0.0.0.0", root.dnsListen)

        val vpn = KiteRunOptions.build(vpnInput.copy(rootLanSharing = true))
        assertEquals(AppConfig.PORT_ROOT_REDIR, vpn.redirPort)
        assertEquals(AppConfig.PORT_ROOT_DNS, vpn.dnsPort)
        assertEquals("0.0.0.0", vpn.dnsListen)
    }

    @Test
    fun `proxy only mode always opens the mixed listener with credentials`() {
        val spec = KiteRunOptions.build(
            KiteRunOptions.Input(
                mode = RunMode.PROXY,
                core = CoreType.MIHOMO,
                localProxyEnabled = false,
                proxySharing = true,
                socksPort = 10809,
                socksUsername = "user",
                socksPassword = "pass",
            )
        )

        assertEquals(10809, spec.mixedPort)
        assertEquals("0.0.0.0", spec.mixedListen)
        assertEquals("user", spec.mixedUser)
        assertEquals("pass", spec.mixedPass)
        assertEquals(0, spec.redirPort)
    }

    @Test
    fun `credentials are only used when both are set`() {
        val spec = KiteRunOptions.build(KiteRunOptions.Input(mode = RunMode.PROXY, core = CoreType.SING_BOX, socksUsername = "user"))

        assertEquals("", spec.mixedUser)
        assertEquals(AppConfig.LOOPBACK, spec.mixedListen)
    }

    @Test
    fun `Xray is not started through libkite options`() {
        assertThrows(IllegalArgumentException::class.java) {
            KiteRunOptions.build(vpnInput.copy(core = CoreType.XRAY))
        }
    }
}
