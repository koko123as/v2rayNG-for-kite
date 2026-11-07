package com.v2ray.ang.fmt

import com.v2ray.ang.AppConfig
import com.v2ray.ang.dto.entities.ProfileItem
import com.v2ray.ang.enums.EConfigType
import com.v2ray.ang.enums.NetworkType
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class NativeNodeFmtTest {

    private val clashSubscription = """
        mixed-port: 7890
        allow-lan: false
        mode: rule
        proxies:
          - name: "HK vmess ws"
            type: vmess
            server: hk.example.com
            port: 443
            uuid: 0b7a4c3e-6f1f-4c5c-9a3b-1f2e3d4c5b6a
            alterId: 0
            cipher: auto
            tls: true
            servername: cdn.example.com
            skip-cert-verify: false
            network: ws
            ws-opts:
              path: /ray
              headers:
                Host: cdn.example.com
          - {name: JP vless reality, type: vless, server: 203.0.113.7, port: 443, uuid: 5f2e3d4c-1a2b-4c3d-8e9f-0a1b2c3d4e5f, flow: xtls-rprx-vision, tls: true, servername: www.microsoft.com, client-fingerprint: chrome, reality-opts: {public-key: PbXP1oGqStTueCnuvbdxVGGzL0MQWu94BbywFUtzSr4, short-id: 0123abcd}, network: tcp}
          - name: SG trojan grpc
            type: trojan
            server: sg.example.com
            port: 8443
            password: trojan-pass
            sni: sg.example.com
            network: grpc
            grpc-opts:
              grpc-service-name: tun
          - name: US ss obfs
            type: ss
            server: 198.51.100.4
            port: 8388
            cipher: aes-256-gcm
            password: 123456
            plugin: obfs
            plugin-opts:
              mode: http
              host: bing.com
          - name: socks
            type: socks5
            server: 10.0.0.1
            port: 1080
            username: u
            password: p
          - name: http
            type: http
            server: 10.0.0.2
            port: 3128
          - name: hy2
            type: hysteria2
            server: hy.example.com
            port: 443
            ports: 20000-30000
            password: hy-pass
            obfs: salamander
            obfs-password: obfs-pass
            sni: hy.example.com
            up: "50 Mbps"
            down: "200 Mbps"
          - name: wg
            type: wireguard
            server: 162.159.192.1
            port: 2408
            ip: 172.16.0.2
            ipv6: 2606:4700:110:8f81::2
            private-key: cHJpdmF0ZS1rZXk=
            public-key: cHVibGljLWtleQ==
            reserved: [1, 2, 3]
            mtu: 1280
            udp: true
          - name: tuic node
            type: tuic
            server: tuic.example.com
            port: 443
            uuid: 5f2e3d4c-1a2b-4c3d-8e9f-0a1b2c3d4e5f
            password: p
        proxy-groups:
          - name: PROXY
            type: select
            proxies: [HK vmess ws, JP vless reality, DIRECT]
          - name: AUTO
            type: url-test
            proxies: [HK vmess ws, JP vless reality]
            url: http://www.gstatic.com/generate_204
            interval: 300
        rules:
          - DOMAIN-SUFFIX,cn,DIRECT
          - MATCH,PROXY
    """.trimIndent()

    @Test
    fun clashYamlSubscriptionGivesOneProfilePerNode() {
        val result = NativeNodeFmt.parse(clashSubscription)!!
        val nodes = result.profiles.associateBy { it.remarks }
        assertEquals(8, result.profiles.size)
        assertEquals(1, result.skipped)

        val vmess = nodes.getValue("HK vmess ws")
        assertEquals(EConfigType.VMESS, vmess.configType)
        assertEquals("hk.example.com", vmess.server)
        assertEquals("443", vmess.serverPort)
        assertEquals("0b7a4c3e-6f1f-4c5c-9a3b-1f2e3d4c5b6a", vmess.password)
        assertEquals("auto", vmess.method)
        assertEquals(NetworkType.WS.type, vmess.network)
        assertEquals("/ray", vmess.path)
        assertEquals("cdn.example.com", vmess.host)
        assertEquals(AppConfig.TLS, vmess.security)
        assertEquals("cdn.example.com", vmess.sni)

        val vless = nodes.getValue("JP vless reality")
        assertEquals(EConfigType.VLESS, vless.configType)
        assertEquals("xtls-rprx-vision", vless.flow)
        assertEquals("none", vless.method)
        assertEquals(AppConfig.REALITY, vless.security)
        assertEquals("PbXP1oGqStTueCnuvbdxVGGzL0MQWu94BbywFUtzSr4", vless.publicKey)
        assertEquals("0123abcd", vless.shortId)
        assertEquals("chrome", vless.fingerPrint)
        assertEquals(NetworkType.TCP.type, vless.network)

        val trojan = nodes.getValue("SG trojan grpc")
        assertEquals(EConfigType.TROJAN, trojan.configType)
        assertEquals(AppConfig.TLS, trojan.security)
        assertEquals(NetworkType.GRPC.type, trojan.network)
        assertEquals("tun", trojan.serviceName)

        val ss = nodes.getValue("US ss obfs")
        assertEquals(EConfigType.SHADOWSOCKS, ss.configType)
        assertEquals("aes-256-gcm", ss.method)
        assertEquals("123456", ss.password)
        assertEquals(AppConfig.HEADER_TYPE_HTTP, ss.headerType)
        assertEquals("bing.com", ss.host)

        assertEquals(EConfigType.SOCKS, nodes.getValue("socks").configType)
        assertEquals("u", nodes.getValue("socks").username)
        assertEquals(EConfigType.HTTP, nodes.getValue("http").configType)

        val hy2 = nodes.getValue("hy2")
        assertEquals(EConfigType.HYSTERIA2, hy2.configType)
        assertEquals("hy-pass", hy2.password)
        assertEquals("obfs-pass", hy2.obfsPassword)
        assertEquals("20000-30000", hy2.portHopping)
        assertEquals("50 Mbps", hy2.bandwidthUp)

        val wg = nodes.getValue("wg")
        assertEquals(EConfigType.WIREGUARD, wg.configType)
        assertEquals("cHJpdmF0ZS1rZXk=", wg.secretKey)
        assertEquals("cHVibGljLWtleQ==", wg.publicKey)
        assertEquals("172.16.0.2/32,2606:4700:110:8f81::2/128", wg.localAddress)
        assertEquals("1,2,3", wg.reserved)
        assertEquals(1280, wg.mtu)

        // Groups and rules are not nodes.
        assertNull(nodes["PROXY"])
        assertNull(nodes["AUTO"])
    }

    @Test
    fun clashProxiesOnlyYamlIsSplit() {
        val yaml = """
            proxies:
              - {name: a, type: ss, server: 1.2.3.4, port: 8388, cipher: chacha20-ietf-poly1305, password: x}
              - {name: b, type: trojan, server: 5.6.7.8, port: 443, password: y, network: ws, ws-opts: {path: /ws, max-early-data: 2048}}
        """.trimIndent()
        val result = NativeNodeFmt.parse(yaml)!!
        assertEquals(listOf("a", "b"), result.profiles.map { it.remarks })
        assertEquals("/ws?ed=2048", result.profiles[1].path)
    }

    private val singboxSubscription = """
        // exported by a sing-box client
        {
          "outbounds": [
            {"type": "selector", "tag": "proxy", "outbounds": ["auto", "vless-reality", "vmess-ws"]},
            {"type": "urltest", "tag": "auto", "outbounds": ["vless-reality", "vmess-ws"]},
            {
              "type": "vless", "tag": "vless-reality", "server": "203.0.113.10", "server_port": 443,
              "uuid": "b831381d-6324-4d53-ad4f-8cda48b30811", "flow": "xtls-rprx-vision",
              "tls": {"enabled": true, "server_name": "www.microsoft.com",
                      "utls": {"enabled": true, "fingerprint": "firefox"},
                      "reality": {"enabled": true, "public_key": "PbXP1oGqStTueCnuvbdxVGGzL0MQWu94BbywFUtzSr4", "short_id": "0123abcd"}}
            },
            {
              "type": "vmess", "tag": "vmess-ws", "server": "vm.example.com", "server_port": 443,
              "uuid": "0b7a4c3e-6f1f-4c5c-9a3b-1f2e3d4c5b6a", "security": "auto",
              "tls": {"enabled": true, "server_name": "vm.example.com", "alpn": ["h2", "http/1.1"]},
              "transport": {"type": "ws", "path": "/ray", "headers": {"Host": "vm.example.com"}, "max_early_data": 2048},
            },
            {"type": "trojan", "tag": "trojan-grpc", "server": "tr.example.com", "server_port": 443, "password": "pw",
             "tls": {"enabled": true, "server_name": "tr.example.com"}, "transport": {"type": "grpc", "service_name": "svc"}},
            {"type": "shadowsocks", "tag": "ss", "server": "198.51.100.4", "server_port": 8388, "method": "2022-blake3-aes-128-gcm", "password": "key"},
            {"type": "hysteria2", "tag": "hy2", "server": "hy.example.com", "server_port": 443, "password": "hy",
             "server_ports": ["20000:30000"], "hop_interval": "30s", "up_mbps": 50, "down_mbps": 200,
             "obfs": {"type": "salamander", "password": "ob"}, "tls": {"enabled": true, "server_name": "hy.example.com", "alpn": ["h3"]}},
            {"type": "tuic", "tag": "tuic", "server": "t.example.com", "server_port": 443, "uuid": "u", "password": "p"},
            {"type": "direct", "tag": "direct"},
            {"type": "block", "tag": "block"},
            {"type": "dns", "tag": "dns-out"},
          ],
          "endpoints": [
            {"type": "wireguard", "tag": "wg", "address": ["172.16.0.2/32"], "private_key": "cHJpdmF0ZS1rZXk=", "mtu": 1280,
             "peers": [{"address": "162.159.192.1", "port": 2408, "public_key": "cHVibGljLWtleQ==", "allowed_ips": ["0.0.0.0/0"], "reserved": [1, 2, 3]}]},
          ],
          "route": {"final": "proxy"},
        }
    """.trimIndent()

    @Test
    fun singboxSubscriptionGivesOneProfilePerNode() {
        val result = NativeNodeFmt.parse(singboxSubscription)!!
        val nodes = result.profiles.associateBy { it.remarks }
        assertEquals(listOf("vless-reality", "vmess-ws", "trojan-grpc", "ss", "hy2", "wg"), result.profiles.map { it.remarks })
        assertEquals(1, result.skipped)

        val vless = nodes.getValue("vless-reality")
        assertEquals(EConfigType.VLESS, vless.configType)
        assertEquals("203.0.113.10", vless.server)
        assertEquals("443", vless.serverPort)
        assertEquals(AppConfig.REALITY, vless.security)
        assertEquals("www.microsoft.com", vless.sni)
        assertEquals("firefox", vless.fingerPrint)
        assertEquals("0123abcd", vless.shortId)

        val vmess = nodes.getValue("vmess-ws")
        assertEquals(NetworkType.WS.type, vmess.network)
        assertEquals("/ray?ed=2048", vmess.path)
        assertEquals("vm.example.com", vmess.host)
        assertEquals("h2,http/1.1", vmess.alpn)
        assertEquals(AppConfig.TLS, vmess.security)

        assertEquals("svc", nodes.getValue("trojan-grpc").serviceName)
        assertEquals("2022-blake3-aes-128-gcm", nodes.getValue("ss").method)

        val hy2 = nodes.getValue("hy2")
        assertEquals("20000-30000", hy2.portHopping)
        assertEquals("30", hy2.portHoppingInterval)
        assertEquals("ob", hy2.obfsPassword)
        assertEquals("50", hy2.bandwidthUp)
        assertEquals(AppConfig.TLS, hy2.security)

        val wg = nodes.getValue("wg")
        assertEquals(EConfigType.WIREGUARD, wg.configType)
        assertEquals("162.159.192.1", wg.server)
        assertEquals("2408", wg.serverPort)
        assertEquals("cHVibGljLWtleQ==", wg.publicKey)
        assertEquals("1,2,3", wg.reserved)
    }

    @Test
    fun singbox114ConfigGivesItsProxyNode() {
        val result = NativeNodeFmt.parse(SINGBOX_114_CONFIG)!!
        assertEquals(1, result.profiles.size)
        val node: ProfileItem = result.profiles.single()
        assertEquals(EConfigType.VLESS, node.configType)
        assertEquals("hk-reality", node.remarks)
        assertEquals(AppConfig.REALITY, node.security)
        assertEquals(0, result.skipped)
    }

    @Test
    fun otherFormatsAreNotSplit() {
        assertNull(NativeNodeFmt.parse("vless://uuid@1.2.3.4:443?type=tcp#a\ntrojan://pw@5.6.7.8:443#b"))
        assertNull(NativeNodeFmt.parse("""{"outbounds":[{"protocol":"vless","settings":{}}],"routing":{}}"""))
        assertNull(NativeNodeFmt.parse(""))
        assertNull(NativeNodeFmt.parse(null))
    }

    @Test
    fun providerOnlyClashYamlHasNoNodes() {
        val result = NativeNodeFmt.parse("proxy-providers:\n  sub:\n    type: http\n    url: https://example.com/sub\n")!!
        assertTrue(result.profiles.isEmpty())
    }

    companion object {
        /** A sing-box 1.14 configuration as clients export it (JSONC, byte order mark). */
        val SINGBOX_114_CONFIG = "\uFEFF" + """
            {
              "${'$'}schema": "https://sing-box.sagernet.org/schema.json",
              // logging
              "log": {"level": "warn", "timestamp": true},
              "dns": {
                "servers": [
                  {"type": "https", "tag": "remote", "server": "1.1.1.1", "detour": "proxy"},
                  {"type": "local", "tag": "local"}, /* the system resolver */
                ],
                "rules": [{"rule_set": "geosite-cn", "server": "local"}],
                "final": "remote",
              },
              "inbounds": [
                {"type": "tun", "tag": "tun-in", "address": ["172.19.0.1/30", "fdfe:dcba:9876::1/126"], "auto_route": true, "strict_route": true, "stack": "mixed"},
              ],
              "outbounds": [
                {"type": "selector", "tag": "proxy", "outbounds": ["auto", "hk-reality", "direct"], "default": "auto"},
                {"type": "urltest", "tag": "auto", "outbounds": ["hk-reality"], "url": "https://www.gstatic.com/generate_204", "interval": "3m"},
                {
                  "type": "vless", "tag": "hk-reality", "server": "203.0.113.10", "server_port": 443,
                  "uuid": "b831381d-6324-4d53-ad4f-8cda48b30811", "flow": "xtls-rprx-vision",
                  "tls": {
                    "enabled": true, "server_name": "www.microsoft.com",
                    "utls": {"enabled": true, "fingerprint": "chrome"},
                    "reality": {"enabled": true, "public_key": "PbXP1oGqStTueCnuvbdxVGGzL0MQWu94BbywFUtzSr4", "short_id": "0123abcd"},
                  },
                },
                {"type": "direct", "tag": "direct"},
              ],
              "route": {
                "rule_set": [
                  {"type": "remote", "tag": "geosite-cn", "format": "binary", "url": "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-cn.srs", "download_detour": "direct"},
                ],
                "rules": [
                  {"action": "sniff"},
                  {"protocol": "dns", "action": "hijack-dns"},
                  {"rule_set": "geosite-cn", "outbound": "direct"}, // trailing comma below
                ],
                "final": "proxy",
                "default_domain_resolver": "local",
                "auto_detect_interface": true,
              },
              "experimental": {"cache_file": {"enabled": true}, "clash_api": {"external_controller": "127.0.0.1:9090"}},
            }
        """.trimIndent()
    }
}
