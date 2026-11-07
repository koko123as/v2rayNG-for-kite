package com.v2ray.ang.root

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class RootProxyManagerTest {

    @Test
    fun `IPv6 LAN forwarding disables jumbo and TSO`() {
        val config = RootProxyManager.buildHevConfig(null, null, 10808, true, 1500, true)

        assertTrue(config.contains("  offload:\n    jumbo: false\n"))
        assertTrue(config.contains("  multi-queue: true\n"))
        assertTrue(config.contains("    tso: false\n"))
        assertFalse(config.contains("uso:"))
    }

    @Test
    fun `local root keeps default offloads and configured MTU`() {
        val config = RootProxyManager.buildHevConfig(null, null, 10808, true, 8500, false)

        assertFalse(config.contains("offload:"))
        assertTrue(config.contains("  mtu: 8500\n"))
        assertTrue(config.contains("  ipv6:"))
    }

    @Test
    fun `LAN offload guard preserves IPv4 only and quoted authentication`() {
        val config = RootProxyManager.buildHevConfig("user'name", "pa'ss", 10809, false, 1500, true)

        assertTrue(config.contains("  offload:\n    jumbo: false\n"))
        assertFalse(config.contains("tso:"))
        assertFalse(config.contains("  ipv6:"))
        assertTrue(config.contains("  port: 10809\n"))
        assertTrue(config.contains("  username: 'user''name'\n"))
        assertTrue(config.contains("  password: 'pa''ss'\n"))
    }

    @Test
    fun `single quotes are escaped in YAML scalars`() {
        assertEquals("'user''name'", "user'name".toSingleQuotedYamlScalar())
        assertEquals("'pa''''ss'", "pa''ss".toSingleQuotedYamlScalar())
    }

    @Test
    fun `multiline credentials remain inside the YAML scalar`() {
        val credential = "user\nHEVCFG\ntouch /data/local/tmp/injected"

        assertEquals("'user\nHEVCFG\ntouch /data/local/tmp/injected'", credential.toSingleQuotedYamlScalar())
    }

    private val nativeSetup = RootProxyManager.NativeSetup(
        appUid = 10123,
        perAppEnabled = false,
        bypassApps = false,
        selectedUids = emptyList(),
        ipv6 = false,
        lanShare = false,
        captureDeviceTraffic = true,
        redirPort = 10851,
        dnsPort = 10852,
        corePid = 4242,
        oomGuardPidFile = "/data/oom.pid",
    )

    @Test
    fun `native root mode redirects TCP and DNS and keeps the core direct`() {
        val script = RootProxyManager.buildNativeSetup(nativeSetup)
        val nat = script.lines().filter { it.startsWith("iptables -t nat -A CORE_NAT ") }

        assertEquals("iptables -t nat -A CORE_NAT -m owner --uid-owner 10123 -j RETURN", nat.first())
        val dnsIndex = nat.indexOfFirst { it.contains("--dport 53 -j REDIRECT --to-ports 10852") }
        val lanIndex = nat.indexOfFirst { it.contains("-d 192.168.0.0/16 -j RETURN") }
        assertTrue(dnsIndex in 1 until lanIndex, "DNS must be redirected before the LAN bypass")
        assertEquals("iptables -t nat -A CORE_NAT -p tcp -j REDIRECT --to-ports 10851", nat.last())
        assertTrue(script.contains("iptables -t nat -A OUTPUT -j CORE_NAT"))
        assertTrue(script.contains("iptables -t filter -A CORE_QUIC -p udp --dport 443 -j REJECT"))
        // No tun, no helper and no TPROXY for the native cores.
        assertFalse(script.contains("TPROXY"))
        assertFalse(script.contains("hevsockstun"))
        assertTrue(script.contains("/proc/4242/oom_score_adj"))
    }

    @Test
    fun `native root mode blackholes IPv6 when it is disabled and redirects it when enabled`() {
        val v4only = RootProxyManager.buildNativeSetup(nativeSetup)
        assertTrue(v4only.contains("ip6tables -t filter -A OUTPUT -j ${com.v2ray.ang.AppConfig.ROOT_V6_CHAIN}"))
        assertFalse(v4only.contains("ip6tables -t nat -A CORE_NAT"))

        val v6 = RootProxyManager.buildNativeSetup(nativeSetup.copy(ipv6 = true))
        assertTrue(v6.contains("ip6tables -t nat -A CORE_NAT -p tcp -j REDIRECT --to-ports 10851"))
        assertTrue(v6.contains("ip6tables -t nat -A CORE_NAT -d fc00::/7 -j RETURN"))
    }

    @Test
    fun `native per-app proxy mode only redirects the selected apps and fails closed`() {
        val selected = RootProxyManager.buildNativeSetup(nativeSetup.copy(perAppEnabled = true, selectedUids = listOf("10200")))
        assertTrue(selected.contains("iptables -t nat -A CORE_NAT -m owner --uid-owner 10200 -p tcp -j REDIRECT --to-ports 10851"))
        assertFalse(selected.contains("iptables -t nat -A CORE_NAT -p tcp -j REDIRECT"))

        val none = RootProxyManager.buildNativeSetup(nativeSetup.copy(perAppEnabled = true))
        assertFalse(none.contains("-p tcp -j REDIRECT --to-ports 10851"))
    }

    @Test
    fun `native bypass mode returns the selected apps before redirecting the rest`() {
        val script = RootProxyManager.buildNativeSetup(nativeSetup.copy(perAppEnabled = true, bypassApps = true, selectedUids = listOf("10300")))
        val nat = script.lines().filter { it.startsWith("iptables -t nat -A CORE_NAT ") }

        assertEquals("iptables -t nat -A CORE_NAT -m owner --uid-owner 10300 -j RETURN", nat[1])
        assertEquals("iptables -t nat -A CORE_NAT -p tcp -j REDIRECT --to-ports 10851", nat.last())
    }

    @Test
    fun `native LAN sharing without device capture only touches forwarded clients`() {
        val script = RootProxyManager.buildNativeSetup(nativeSetup.copy(captureDeviceTraffic = false, lanShare = true))

        assertFalse(script.contains("-A OUTPUT -j CORE_NAT"))
        assertTrue(script.contains("iptables -t nat -A CORE_NAT_PRE -s 192.168.0.0/16 -p tcp -j REDIRECT --to-ports 10851"))
        assertTrue(script.contains("iptables -t nat -A CORE_NAT_PRE -s 10.0.0.0/8 -p udp --dport 53 -j REDIRECT --to-ports 10852"))
        assertTrue(script.contains("iptables -t nat -A CORE_NAT_PRE -m addrtype --dst-type LOCAL -j RETURN"))
        assertTrue(script.contains("ip6tables -A CORE6_FWD -j REJECT --reject-with icmp6-no-route"))
    }
}
