package com.v2ray.ang.core

import com.google.gson.JsonObject
import com.v2ray.ang.AppConfig
import com.v2ray.ang.dto.entities.ProfileItem
import com.v2ray.ang.enums.EConfigType
import com.v2ray.ang.enums.NetworkType
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/** One translation per protocol for each of mihomo ([MihomoConfigBuilder]) and sing-box ([SingboxConfigBuilder]). */
class KiteProtocolTranslationTest {

    private val settings = KiteConfigSettings()

    private fun profile(type: EConfigType, block: ProfileItem.() -> Unit = {}) = ProfileItem.create(type).apply {
        server = "1.2.3.4"
        serverPort = "443"
        block()
    }

    private fun mihomo(profile: ProfileItem): JsonObject =
        requireNotNull(MihomoConfigBuilder.toProxy(profile, "node", settings)) { "mihomo skipped ${profile.configType}" }

    private fun singBox(profile: ProfileItem): JsonObject =
        requireNotNull(SingboxConfigBuilder.toNode(profile, "node", null, settings)) { "sing-box skipped ${profile.configType}" }.first

    private fun JsonObject.str(key: String): String? = get(key)?.takeIf { it.isJsonPrimitive }?.asString
    private fun JsonObject.obj(key: String): JsonObject = getAsJsonObject(key)

    private val vmessWsTls = profile(EConfigType.VMESS) {
        password = "11111111-1111-1111-1111-111111111111"
        method = "auto"
        network = NetworkType.WS.type
        host = "cdn.example.com"
        path = "/ws?ed=2048"
        security = AppConfig.TLS
        sni = "cdn.example.com"
        fingerPrint = "chrome"
    }

    private val vlessReality = profile(EConfigType.VLESS) {
        password = "22222222-2222-2222-2222-222222222222"
        flow = "xtls-rprx-vision"
        security = AppConfig.REALITY
        sni = "www.microsoft.com"
        publicKey = "pubkey"
        shortId = "abcd"
    }

    private val trojanGrpc = profile(EConfigType.TROJAN) {
        password = "secret"
        network = NetworkType.GRPC.type
        serviceName = "grpc-svc"
        security = AppConfig.TLS
        sni = "trojan.example.com"
    }

    private val shadowsocks = profile(EConfigType.SHADOWSOCKS) {
        method = "2022-blake3-aes-128-gcm"
        password = "pass"
    }

    private val socks = profile(EConfigType.SOCKS) {
        username = "user"
        password = "pw"
    }

    private val http = profile(EConfigType.HTTP) {
        username = "user"
        password = "pw"
        security = AppConfig.TLS
        sni = "proxy.example.com"
    }

    private val hysteria2 = profile(EConfigType.HYSTERIA2) {
        password = "hy2"
        sni = "hy2.example.com"
        obfsPassword = "obfs"
        portHopping = "20000-30000"
        bandwidthUp = "50"
        bandwidthDown = "100 Mbps"
    }

    private val wireguard = profile(EConfigType.WIREGUARD) {
        secretKey = "private"
        publicKey = "public"
        localAddress = "172.16.0.2/32"
        reserved = "1,2,3"
        mtu = 1280
    }

    @Test
    fun vmessWebSocketTls() {
        val m = mihomo(vmessWsTls)
        assertEquals("vmess", m.str("type"))
        assertEquals("ws", m.str("network"))
        assertEquals("/ws", m.obj("ws-opts").str("path"))
        assertEquals(2048, m.obj("ws-opts").get("max-early-data").asInt)
        assertEquals(true, m.get("tls").asBoolean)
        assertEquals("cdn.example.com", m.str("servername"))
        assertEquals("chrome", m.str("client-fingerprint"))

        val s = singBox(vmessWsTls)
        assertEquals("vmess", s.str("type"))
        assertEquals(443, s.get("server_port").asInt)
        assertEquals("ws", s.obj("transport").str("type"))
        assertEquals("/ws", s.obj("transport").str("path"))
        assertEquals(true, s.obj("tls").get("enabled").asBoolean)
        assertEquals("chrome", s.obj("tls").obj("utls").str("fingerprint"))
    }

    @Test
    fun vlessRealityVision() {
        val m = mihomo(vlessReality)
        assertEquals("vless", m.str("type"))
        assertEquals("xtls-rprx-vision", m.str("flow"))
        assertEquals("pubkey", m.obj("reality-opts").str("public-key"))
        assertEquals("abcd", m.obj("reality-opts").str("short-id"))
        // REALITY needs a uTLS fingerprint; chrome is the default.
        assertEquals("chrome", m.str("client-fingerprint"))

        val s = singBox(vlessReality)
        assertEquals("vless", s.str("type"))
        assertEquals("xtls-rprx-vision", s.str("flow"))
        assertEquals(true, s.obj("tls").obj("reality").get("enabled").asBoolean)
        assertEquals("pubkey", s.obj("tls").obj("reality").str("public_key"))
        assertEquals("www.microsoft.com", s.obj("tls").str("server_name"))
    }

    @Test
    fun vlessEncryptionIsMihomoOnly() {
        val encrypted = profile(EConfigType.VLESS) {
            password = "uuid"
            method = "mlkem768x25519plus.native.0rtt.key"
        }
        assertEquals("mlkem768x25519plus.native.0rtt.key", mihomo(encrypted).str("encryption"))
        assertNull(SingboxConfigBuilder.toNode(encrypted, "node", null, settings))
    }

    @Test
    fun trojanGrpc() {
        val m = mihomo(trojanGrpc)
        assertEquals("trojan", m.str("type"))
        assertEquals("grpc", m.str("network"))
        assertEquals("grpc-svc", m.obj("grpc-opts").str("grpc-service-name"))
        assertEquals("trojan.example.com", m.str("sni"))

        val s = singBox(trojanGrpc)
        assertEquals("trojan", s.str("type"))
        assertEquals("grpc", s.obj("transport").str("type"))
        assertEquals("grpc-svc", s.obj("transport").str("service_name"))
    }

    @Test
    fun shadowsocks() {
        val m = mihomo(shadowsocks)
        assertEquals("ss", m.str("type"))
        assertEquals("2022-blake3-aes-128-gcm", m.str("cipher"))
        assertEquals("pass", m.str("password"))

        val s = singBox(shadowsocks)
        assertEquals("shadowsocks", s.str("type"))
        assertEquals("2022-blake3-aes-128-gcm", s.str("method"))
    }

    @Test
    fun socks() {
        val m = mihomo(socks)
        assertEquals("socks5", m.str("type"))
        assertEquals("user", m.str("username"))
        assertEquals("pw", m.str("password"))

        val s = singBox(socks)
        assertEquals("socks", s.str("type"))
        assertEquals("5", s.str("version"))
        assertEquals("user", s.str("username"))
    }

    @Test
    fun httpOverTls() {
        val m = mihomo(http)
        assertEquals("http", m.str("type"))
        assertEquals(true, m.get("tls").asBoolean)
        assertEquals("proxy.example.com", m.str("sni"))

        val s = singBox(http)
        assertEquals("http", s.str("type"))
        assertEquals("proxy.example.com", s.obj("tls").str("server_name"))
    }

    @Test
    fun hysteria2() {
        val m = mihomo(hysteria2)
        assertEquals("hysteria2", m.str("type"))
        assertEquals("salamander", m.str("obfs"))
        assertEquals("20000-30000", m.str("ports"))
        assertEquals("50 Mbps", m.str("up"))
        assertEquals("100 Mbps", m.str("down"))

        val s = singBox(hysteria2)
        assertEquals("hysteria2", s.str("type"))
        assertEquals("salamander", s.obj("obfs").str("type"))
        assertEquals("20000:30000", s.getAsJsonArray("server_ports")[0].asString)
        assertEquals(50, s.get("up_mbps").asInt)
        assertEquals("h3", s.obj("tls").getAsJsonArray("alpn")[0].asString)
    }

    @Test
    fun wireguardIsAnEndpointOnSingBox() {
        val m = mihomo(wireguard)
        assertEquals("wireguard", m.str("type"))
        assertEquals("172.16.0.2", m.str("ip"))
        assertEquals("public", m.str("public-key"))
        assertEquals(3, m.getAsJsonArray("reserved").size())

        val result = requireNotNull(SingboxConfigBuilder.toNode(wireguard, "node", null, settings))
        assertTrue(result.second, "sing-box runs WireGuard as an endpoint")
        val peer = result.first.getAsJsonArray("peers")[0].asJsonObject
        assertEquals("1.2.3.4", peer.str("address"))
        assertEquals("public", peer.str("public_key"))
    }

    @Test
    fun xrayOnlyTransportsAreSkipped() {
        val kcp = profile(EConfigType.VMESS) {
            password = "uuid"
            network = NetworkType.KCP.type
        }
        assertNull(MihomoConfigBuilder.toProxy(kcp, "node", settings))
        assertNull(SingboxConfigBuilder.toNode(kcp, "node", null, settings))

        val xhttp = profile(EConfigType.VLESS) {
            password = "uuid"
            network = NetworkType.XHTTP.type
            path = "/x"
        }
        assertEquals("xhttp", mihomo(xhttp).str("network"))
        assertNull(SingboxConfigBuilder.toNode(xhttp, "node", null, settings))
    }

    @Test
    fun invalidPortIsSkipped() {
        val broken = profile(EConfigType.TROJAN) { serverPort = "0" }
        assertNull(MihomoConfigBuilder.toProxy(broken, "node", settings))
        assertNull(SingboxConfigBuilder.toNode(broken, "node", null, settings))
    }
}
