package com.v2ray.ang.fmt

import com.google.gson.Gson
import com.v2ray.ang.AppConfig
import com.v2ray.ang.core.NativeConfigDetector
import com.v2ray.ang.dto.entities.ProfileItem
import com.v2ray.ang.enums.CoreType
import com.v2ray.ang.enums.EConfigType
import com.v2ray.ang.enums.NetworkType
import org.snakeyaml.engine.v2.api.Load
import org.snakeyaml.engine.v2.api.LoadSettings

/**
 * Splits a Clash (mihomo) YAML or a sing-box JSON into one profile per proxy node, the way a
 * subscription in those formats is imported. Groups, rules, DNS and non-proxy outbounds (direct,
 * block, dns, selector, urltest) are dropped; each node runs on whichever core the user picks.
 * A whole configuration is stored as written only by [com.v2ray.ang.handler.AngConfigManager.importConfigFile].
 */
object NativeNodeFmt {

    /** Result of a split: the nodes, and how many proxies were left out because no profile type maps them. */
    data class Result(val profiles: List<ProfileItem>, val skipped: Int)

    private val gson = Gson()

    /** The nodes of [content], or null when it is not a Clash YAML or a sing-box JSON. */
    fun parse(content: String?): Result? {
        val text = NativeConfigDetector.stripBom(content).trim()
        return when (NativeConfigDetector.detect(text)) {
            CoreType.MIHOMO -> parseClash(text)
            CoreType.SING_BOX -> parseSingbox(text)
            else -> null
        }
    }

    // ---------- Clash / mihomo ----------

    private fun parseClash(text: String): Result? {
        val root = if (text.startsWith("{")) {
            NativeConfigDetector.parseJsonObject(text)?.let { gson.fromJson(it, Map::class.java) }
        } else {
            loadYaml(text)
        } ?: return null
        val proxies = root["proxies"] as? List<*> ?: return Result(emptyList(), 0)
        var skipped = 0
        val profiles = proxies.mapNotNull { item ->
            val proxy = item as? Map<*, *> ?: return@mapNotNull null
            runCatching { clashProxy(proxy) }.getOrNull().also { if (it == null) skipped++ }
        }
        return Result(profiles, skipped)
    }

    private fun loadYaml(text: String): Map<*, *>? {
        val settings = LoadSettings.builder()
            .setAllowDuplicateKeys(true)
            .setCodePointLimit(64 * 1024 * 1024)
            .build()
        return Load(settings).loadFromString(text) as? Map<*, *>
    }

    private fun clashProxy(p: Map<*, *>): ProfileItem? {
        val type = p.str("type")?.lowercase() ?: return null
        val configType = when (type) {
            "vmess" -> EConfigType.VMESS
            "vless" -> EConfigType.VLESS
            "trojan" -> EConfigType.TROJAN
            "ss" -> EConfigType.SHADOWSOCKS
            "socks5" -> EConfigType.SOCKS
            "http" -> EConfigType.HTTP
            "hysteria2" -> EConfigType.HYSTERIA2
            "wireguard" -> EConfigType.WIREGUARD
            // hysteria (v1), tuic, ssr, snell, anytls and the rest have no profile type here.
            else -> return null
        }
        val config = ProfileItem.create(configType)
        config.remarks = p.str("name") ?: "none"
        config.server = p.str("server")
        config.serverPort = p.str("port")
        when (configType) {
            EConfigType.VMESS -> {
                config.password = p.str("uuid") ?: return null
                config.method = p.str("cipher") ?: AppConfig.DEFAULT_SECURITY
                if (!clashTransport(config, p)) return null
                clashTls(config, p, sniKey = "servername")
            }

            EConfigType.VLESS -> {
                config.password = p.str("uuid") ?: return null
                config.flow = p.str("flow")
                config.method = p.str("encryption") ?: "none"
                if (!clashTransport(config, p)) return null
                clashTls(config, p, sniKey = "servername")
            }

            EConfigType.TROJAN -> {
                config.password = p.str("password") ?: return null
                if (!clashTransport(config, p)) return null
                // A Clash trojan node always runs over TLS.
                clashTls(config, p, sniKey = "sni", forceTls = true)
            }

            EConfigType.SHADOWSOCKS -> {
                config.method = p.str("cipher") ?: return null
                config.password = p.str("password") ?: return null
                config.network = NetworkType.TCP.type
                if (!clashShadowsocksPlugin(config, p)) return null
            }

            EConfigType.SOCKS -> {
                if (p.bool("tls")) return null
                config.username = p.str("username")
                config.password = p.str("password")
            }

            EConfigType.HTTP -> {
                config.username = p.str("username")
                config.password = p.str("password")
                if (p.bool("tls")) {
                    config.security = AppConfig.TLS
                    config.sni = p.str("sni")
                    config.insecure = p.bool("skip-cert-verify")
                }
            }

            EConfigType.HYSTERIA2 -> {
                config.password = p.str("password") ?: p.str("auth") ?: return null
                config.network = NetworkType.HYSTERIA.type
                config.security = AppConfig.TLS
                config.sni = p.str("sni")
                config.insecure = p.bool("skip-cert-verify")
                config.alpn = p.csv("alpn")
                config.pinnedCA256 = p.str("fingerprint")
                config.portHopping = p.str("ports")?.replace(":", "-")
                config.portHoppingInterval = p.str("hop-interval")
                if (p.str("obfs").isNullOrBlank() || p.str("obfs") == "salamander") {
                    config.obfsPassword = p.str("obfs-password")
                } else {
                    return null
                }
                config.bandwidthUp = p.str("up")
                config.bandwidthDown = p.str("down")
                if (config.serverPort.isNullOrBlank()) {
                    config.serverPort = config.portHopping?.split(",", "-")?.first()?.trim()
                }
            }

            EConfigType.WIREGUARD -> {
                val peer = (p["peers"] as? List<*>)?.firstOrNull() as? Map<*, *>
                if (peer != null) {
                    config.server = peer.str("server") ?: config.server
                    config.serverPort = peer.str("port") ?: config.serverPort
                }
                config.secretKey = p.str("private-key") ?: return null
                config.publicKey = (peer ?: p).str("public-key") ?: return null
                config.preSharedKey = (peer ?: p).str("pre-shared-key")
                val addresses = listOfNotNull(
                    p.str("ip")?.let { if (it.contains("/")) it else "$it/32" },
                    p.str("ipv6")?.let { if (it.contains("/")) it else "$it/128" },
                )
                config.localAddress = addresses.joinToString(",").ifEmpty { AppConfig.WIREGUARD_LOCAL_ADDRESS_V4 }
                config.reserved = reservedCsv((peer ?: p)["reserved"]) ?: "0,0,0"
                config.mtu = p.str("mtu")?.toIntOrNull() ?: AppConfig.WIREGUARD_LOCAL_MTU.toInt()
                config.remoteDNS = p.csv("dns").orEmpty()
            }

            else -> return null
        }
        if (config.server.isNullOrBlank() || config.serverPort.isNullOrBlank()) return null
        return config
    }

    /** Clash transport options into the profile. False when the profile has no equivalent. */
    private fun clashTransport(config: ProfileItem, p: Map<*, *>): Boolean {
        when (p.str("network")?.lowercase() ?: "tcp") {
            "tcp" -> config.network = NetworkType.TCP.type

            "http" -> {
                val opts = p.map("http-opts")
                config.network = NetworkType.TCP.type
                config.headerType = AppConfig.HEADER_TYPE_HTTP
                config.path = opts?.csv("path")
                config.host = (opts?.map("headers"))?.csv("Host")
            }

            "ws" -> {
                val opts = p.map("ws-opts")
                val upgrade = opts?.bool("v2ray-http-upgrade") == true
                config.network = if (upgrade) NetworkType.HTTP_UPGRADE.type else NetworkType.WS.type
                var path = opts?.str("path") ?: "/"
                val earlyData = opts?.str("max-early-data")?.toIntOrNull()
                if (!upgrade && earlyData != null && earlyData > 0 && !path.contains("ed=")) {
                    path += (if (path.contains("?")) "&" else "?") + "ed=$earlyData"
                }
                config.path = path
                config.host = opts?.map("headers")?.str("Host")
            }

            "grpc" -> {
                config.network = NetworkType.GRPC.type
                config.serviceName = p.map("grpc-opts")?.str("grpc-service-name").orEmpty()
            }

            "h2" -> {
                val opts = p.map("h2-opts")
                config.network = NetworkType.H2.type
                config.host = opts?.csv("host")
                config.path = opts?.str("path")
            }

            "xhttp" -> {
                val opts = p.map("xhttp-opts")
                config.network = NetworkType.XHTTP.type
                config.path = opts?.str("path")
                config.host = opts?.str("host")
                config.xhttpMode = opts?.str("mode")
            }

            else -> return false
        }
        return true
    }

    private fun clashTls(config: ProfileItem, p: Map<*, *>, sniKey: String, forceTls: Boolean = false) {
        val reality = p.map("reality-opts")
        if (reality != null) {
            config.security = AppConfig.REALITY
            config.publicKey = reality.str("public-key")
            config.shortId = reality.str("short-id")
        } else if (forceTls || p.bool("tls")) {
            config.security = AppConfig.TLS
        } else {
            return
        }
        config.sni = p.str(sniKey) ?: p.str("servername") ?: p.str("sni")
        config.insecure = p.bool("skip-cert-verify")
        config.alpn = p.csv("alpn")
        config.fingerPrint = p.str("client-fingerprint")
        p.map("ech-opts")?.takeIf { it.bool("enable") }?.let { config.echConfigList = it.str("config") }
    }

    private fun clashShadowsocksPlugin(config: ProfileItem, p: Map<*, *>): Boolean {
        val plugin = p.str("plugin")?.lowercase() ?: return true
        val opts = p.map("plugin-opts")
        when (plugin) {
            "obfs", "obfs-local", "simple-obfs" -> {
                if (opts?.str("mode") != "http") return false
                config.headerType = AppConfig.HEADER_TYPE_HTTP
                config.host = opts?.str("host")
            }

            "v2ray-plugin" -> {
                if ((opts?.str("mode") ?: "websocket") != "websocket") return false
                config.network = NetworkType.WS.type
                config.host = opts?.str("host")
                config.path = opts?.str("path") ?: "/"
                if (opts?.bool("tls") == true) {
                    config.security = AppConfig.TLS
                    config.sni = opts?.str("host")
                    config.insecure = opts?.bool("skip-cert-verify") == true
                }
            }

            else -> return false
        }
        return true
    }

    // ---------- sing-box ----------

    private val singboxNonProxy = setOf("direct", "block", "dns", "selector", "urltest")

    private fun parseSingbox(text: String): Result? {
        val root = NativeConfigDetector.parseJsonObject(text)?.let { gson.fromJson(it, Map::class.java) } ?: return null
        val items = (root["outbounds"] as? List<*>).orEmpty() + (root["endpoints"] as? List<*>).orEmpty()
        var skipped = 0
        val profiles = items.mapNotNull { item ->
            val node = item as? Map<*, *> ?: return@mapNotNull null
            val type = node.str("type")?.lowercase() ?: return@mapNotNull null
            if (type in singboxNonProxy) return@mapNotNull null
            runCatching { singboxNode(type, node) }.getOrNull().also { if (it == null) skipped++ }
        }
        return Result(profiles, skipped)
    }

    private fun singboxNode(type: String, n: Map<*, *>): ProfileItem? {
        val configType = when (type) {
            "vmess" -> EConfigType.VMESS
            "vless" -> EConfigType.VLESS
            "trojan" -> EConfigType.TROJAN
            "shadowsocks" -> EConfigType.SHADOWSOCKS
            "socks" -> EConfigType.SOCKS
            "http" -> EConfigType.HTTP
            "hysteria2" -> EConfigType.HYSTERIA2
            "wireguard" -> EConfigType.WIREGUARD
            // hysteria (v1), tuic, anytls, shadowtls, ssh, tor and naive have no profile type here.
            else -> return null
        }
        val config = ProfileItem.create(configType)
        config.remarks = n.str("tag") ?: "none"
        config.server = n.str("server")
        config.serverPort = n.str("server_port")
        when (configType) {
            EConfigType.VMESS -> {
                config.password = n.str("uuid") ?: return null
                config.method = n.str("security") ?: AppConfig.DEFAULT_SECURITY
                if (!singboxTransport(config, n)) return null
                singboxTls(config, n)
            }

            EConfigType.VLESS -> {
                config.password = n.str("uuid") ?: return null
                config.flow = n.str("flow")
                config.method = "none"
                if (!singboxTransport(config, n)) return null
                singboxTls(config, n)
            }

            EConfigType.TROJAN -> {
                config.password = n.str("password") ?: return null
                if (!singboxTransport(config, n)) return null
                singboxTls(config, n)
            }

            EConfigType.SHADOWSOCKS -> {
                config.method = n.str("method") ?: return null
                config.password = n.str("password") ?: return null
                config.network = NetworkType.TCP.type
                if (!singboxShadowsocksPlugin(config, n.str("plugin"), n.str("plugin_opts"))) return null
            }

            EConfigType.SOCKS -> {
                if (n.str("version").let { it != null && it != "5" }) return null
                config.username = n.str("username")
                config.password = n.str("password")
            }

            EConfigType.HTTP -> {
                config.username = n.str("username")
                config.password = n.str("password")
                singboxTls(config, n)
            }

            EConfigType.HYSTERIA2 -> {
                config.password = n.str("password") ?: return null
                config.network = NetworkType.HYSTERIA.type
                val ports = n.csv("server_ports")
                config.portHopping = ports?.replace(":", "-")
                config.portHoppingInterval = n.str("hop_interval")?.removeSuffix("s")
                if (config.serverPort.isNullOrBlank() && ports != null) {
                    config.serverPort = ports.split(",", "-", ":").first().trim()
                }
                n.map("obfs")?.let { obfs ->
                    if (obfs.str("type") != "salamander") return null
                    config.obfsPassword = obfs.str("password")
                }
                config.bandwidthUp = n.str("up_mbps")
                config.bandwidthDown = n.str("down_mbps")
                singboxTls(config, n)
                config.security = AppConfig.TLS
            }

            EConfigType.WIREGUARD -> {
                config.secretKey = n.str("private_key") ?: return null
                val peer = (n["peers"] as? List<*>)?.firstOrNull() as? Map<*, *>
                if (peer != null) {
                    // An endpoint (sing-box 1.11+): the server is the first peer.
                    config.server = peer.str("address")
                    config.serverPort = peer.str("port")
                    config.publicKey = peer.str("public_key") ?: return null
                    config.preSharedKey = peer.str("pre_shared_key")
                    config.reserved = reservedCsv(peer["reserved"]) ?: "0,0,0"
                    config.localAddress = n.csv("address")
                } else {
                    config.publicKey = n.str("peer_public_key") ?: return null
                    config.preSharedKey = n.str("pre_shared_key")
                    config.reserved = reservedCsv(n["reserved"]) ?: "0,0,0"
                    config.localAddress = n.csv("local_address")
                }
                if (config.localAddress.isNullOrBlank()) config.localAddress = AppConfig.WIREGUARD_LOCAL_ADDRESS_V4
                config.mtu = n.str("mtu")?.toIntOrNull() ?: AppConfig.WIREGUARD_LOCAL_MTU.toInt()
                config.remoteDNS = ""
            }

            else -> return null
        }
        if (config.server.isNullOrBlank() || config.serverPort.isNullOrBlank()) return null
        return config
    }

    private fun singboxTransport(config: ProfileItem, n: Map<*, *>): Boolean {
        val t = n.map("transport")
        when (t?.str("type")?.lowercase()) {
            null -> config.network = NetworkType.TCP.type

            "ws" -> {
                config.network = NetworkType.WS.type
                var path = t.str("path") ?: "/"
                val earlyData = t.str("max_early_data")?.toIntOrNull()
                if (earlyData != null && earlyData > 0 && !path.contains("ed=")) {
                    path += (if (path.contains("?")) "&" else "?") + "ed=$earlyData"
                }
                config.path = path
                config.host = t.map("headers")?.csv("Host")
            }

            "httpupgrade" -> {
                config.network = NetworkType.HTTP_UPGRADE.type
                config.path = t.str("path") ?: "/"
                config.host = t.str("host")
            }

            "grpc" -> {
                config.network = NetworkType.GRPC.type
                config.serviceName = t.str("service_name").orEmpty()
            }

            "http" -> {
                config.network = NetworkType.H2.type
                config.host = t.csv("host")
                config.path = t.str("path")
            }

            else -> return false
        }
        return true
    }

    private fun singboxTls(config: ProfileItem, n: Map<*, *>) {
        val tls = n.map("tls")?.takeIf { it.bool("enabled") } ?: return
        val reality = tls.map("reality")?.takeIf { it.bool("enabled") }
        if (reality != null) {
            config.security = AppConfig.REALITY
            config.publicKey = reality.str("public_key")
            config.shortId = reality.str("short_id")
        } else {
            config.security = AppConfig.TLS
        }
        config.sni = tls.str("server_name")
        config.insecure = tls.bool("insecure")
        config.alpn = tls.csv("alpn")
        tls.map("utls")?.takeIf { it.bool("enabled") }?.let { config.fingerPrint = it.str("fingerprint") ?: "chrome" }
        tls.map("ech")?.takeIf { it.bool("enabled") }?.let { ech ->
            // The PEM lines around a base64 ECHConfigList are dropped.
            config.echConfigList = (ech["config"] as? List<*>)?.map { it.toString().trim() }
                ?.filter { it.isNotEmpty() && !it.startsWith("-----") }
                ?.joinToString("")
                ?.takeIf { it.isNotEmpty() }
        }
    }

    private fun singboxShadowsocksPlugin(config: ProfileItem, plugin: String?, opts: String?): Boolean {
        if (plugin.isNullOrBlank()) return true
        val values = opts.orEmpty().split(";").map { it.trim() }.filter { it.isNotEmpty() }
            .associate { it.substringBefore("=") to it.substringAfter("=", "") }
        when (plugin) {
            "obfs-local" -> {
                if (values["obfs"] != "http") return false
                config.headerType = AppConfig.HEADER_TYPE_HTTP
                config.host = values["obfs-host"]
            }

            "v2ray-plugin" -> {
                if ((values["mode"] ?: "websocket") != "websocket") return false
                config.network = NetworkType.WS.type
                config.host = values["host"]
                config.path = values["path"] ?: "/"
                if (values.containsKey("tls")) {
                    config.security = AppConfig.TLS
                    config.sni = values["host"]
                }
            }

            else -> return false
        }
        return true
    }

    // ---------- value helpers ----------

    /** A scalar as text; numbers parsed by Gson as doubles lose their ".0". */
    private fun Map<*, *>.str(key: String): String? {
        val value = this[key] ?: return null
        val text = when (value) {
            is Double -> if (value % 1.0 == 0.0) value.toLong().toString() else value.toString()
            is Float -> if (value % 1f == 0f) value.toLong().toString() else value.toString()
            is Map<*, *>, is List<*> -> return null
            else -> value.toString()
        }
        return text.trim().takeIf { it.isNotEmpty() }
    }

    private fun Map<*, *>.bool(key: String): Boolean = when (val value = this[key]) {
        is Boolean -> value
        is String -> value.equals("true", ignoreCase = true)
        else -> false
    }

    private fun Map<*, *>.map(key: String): Map<*, *>? = this[key] as? Map<*, *>

    /** A list or a single value as comma-separated text. */
    private fun Map<*, *>.csv(key: String): String? {
        val value = this[key] ?: return null
        val items = if (value is List<*>) value.mapNotNull { mapOf("v" to it).str("v") } else listOfNotNull(str(key))
        return items.joinToString(",").takeIf { it.isNotEmpty() }
    }

    private fun reservedCsv(value: Any?): String? = when (value) {
        is List<*> -> value.mapNotNull { mapOf("v" to it).str("v") }.takeIf { it.size == 3 }?.joinToString(",")
        // A base64 "reserved" string is not representable as three numbers here.
        is String -> value.takeIf { it.split(",").size == 3 }
        else -> null
    }
}
