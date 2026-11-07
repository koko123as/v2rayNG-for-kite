package com.v2ray.ang.core

import com.google.gson.JsonArray
import com.google.gson.JsonObject
import com.v2ray.ang.AppConfig
import com.v2ray.ang.core.KiteProfileSupport.jsonArray
import com.v2ray.ang.core.KiteProfileSupport.jsonIntArray
import com.v2ray.ang.core.KiteProfileSupport.putIfNotBlank
import com.v2ray.ang.dto.CoreConfigContext
import com.v2ray.ang.dto.entities.ProfileItem
import com.v2ray.ang.enums.BalancerStrategyType
import com.v2ray.ang.enums.CoreResolvedType
import com.v2ray.ang.enums.EConfigType
import com.v2ray.ang.enums.NetworkType
import com.v2ray.ang.util.LogUtil

/**
 * Translates the analyzed profile plan ([CoreConfigContext], the same input [CoreConfigManager]
 * turns into Xray JSON) into a mihomo configuration.
 *
 * The output is JSON, which mihomo's YAML parser reads as YAML. Listeners and the tun are not
 * written here: libkite sets them for the run mode when the core starts.
 *
 * - Nodes become `proxies`, policy groups `proxy-groups` (url-test / load-balance), proxy chains
 *   `dialer-proxy` links, the main outbound is always named "proxy".
 * - Routing, DNS, hosts and sniffing come from [MihomoRoutingBuilder].
 */
object MihomoConfigBuilder {

    const val PROXY = AppConfig.TAG_PROXY

    /** Result of the translation; [skipped] lists nodes or rules that mihomo cannot express. */
    data class Result(val content: String, val skipped: List<String>)

    fun build(context: CoreConfigContext, settings: KiteConfigSettings, forSpeedtest: Boolean = false): Result {
        val skipped = mutableListOf<String>()
        val root = JsonObject()
        root.addProperty("mode", "rule")
        root.addProperty("log-level", logLevel(settings.logLevel))
        root.addProperty("ipv6", settings.ipv6)
        root.addProperty("unified-delay", true)
        root.addProperty("tcp-concurrent", true)
        root.addProperty("geodata-mode", true)
        root.addProperty("geo-auto-update", false)
        root.addProperty("geodata-loader", "memconservative")
        root.add("profile", JsonObject().apply { addProperty("store-selected", true) })

        val proxies = JsonArray()
        val groups = JsonArray()
        val names = mutableSetOf<String>()
        context.resolvedOutbounds.forEach { outbound ->
            addOutbound(outbound, settings, proxies, groups, names, skipped)
        }
        if (PROXY !in names) {
            error("No node of this profile can run on mihomo")
        }
        root.add("proxies", proxies)
        root.add("proxy-groups", groups)

        if (forSpeedtest) {
            root.add("rules", jsonArray(listOf("MATCH,$PROXY")))
            return Result(KiteProfileSupport.toPrettyJson(root), skipped)
        }

        root.add("rules", jsonArray(listOf("MATCH,$PROXY"))) // routing and DNS: MihomoRoutingBuilder
        return Result(KiteProfileSupport.toPrettyJson(root), skipped)
    }

    private fun logLevel(level: String): String = when (level.lowercase()) {
        "debug" -> "debug"
        "info" -> "info"
        "error" -> "error"
        "none" -> "silent"
        else -> "warning"
    }

    // ---------------------------------------------------------------- outbounds

    private fun addOutbound(
        outbound: CoreConfigContext.ResolvedOutbound,
        settings: KiteConfigSettings,
        proxies: JsonArray,
        groups: JsonArray,
        names: MutableSet<String>,
        skipped: MutableList<String>,
    ) {
        if (outbound.tag in names) return
        when (outbound.resolvedType) {
            CoreResolvedType.NORMAL -> {
                val profile = outbound.resolvedProfiles.firstOrNull() ?: return
                val proxy = toProxy(profile, outbound.tag, settings) ?: run {
                    skipped.add(profile.remarks)
                    return
                }
                proxies.add(proxy)
                names.add(outbound.tag)
            }

            CoreResolvedType.PROXYCHAIN -> {
                val hops = outbound.resolvedProfiles.mapIndexed { index, profile ->
                    val name = if (index == 0) outbound.tag else "${outbound.tag}-hop-$index"
                    toProxy(profile, name, settings) ?: run {
                        skipped.add(profile.remarks)
                        return
                    }
                }
                if (hops.any { it.get("name").asString in names }) return
                // resolvedProfiles[0] is entered first and dials through the next hop.
                for (i in 0 until hops.size - 1) {
                    hops[i].addProperty("dialer-proxy", hops[i + 1].get("name").asString)
                }
                hops.forEach {
                    proxies.add(it)
                    names.add(it.get("name").asString)
                }
            }

            CoreResolvedType.POLICYGROUP -> {
                val members = mutableListOf<String>()
                outbound.resolvedProfiles.forEachIndexed { index, profile ->
                    val name = "${AppConfig.TAG_PROXY}-${outbound.tag}-${index + 1}-${profile.remarks.trim()}"
                    if (name in names) return@forEachIndexed
                    val proxy = toProxy(profile, name, settings) ?: run {
                        skipped.add(profile.remarks)
                        return@forEachIndexed
                    }
                    proxies.add(proxy)
                    names.add(name)
                    members.add(name)
                }
                if (members.isEmpty()) {
                    LogUtil.w(AppConfig.TAG, "mihomo: policy group '${outbound.tag}' has no usable member")
                    return
                }
                groups.add(buildGroup(outbound.tag, outbound.profile, members, settings))
                names.add(outbound.tag)
            }
        }
    }

    private fun buildGroup(name: String, profile: ProfileItem, members: List<String>, settings: KiteConfigSettings): JsonObject {
        val group = JsonObject()
        group.addProperty("name", name)
        val interval = KiteProfileSupport.durationSeconds(settings.urlTestInterval)
        when (BalancerStrategyType.from(profile.policyGroupType)) {
            BalancerStrategyType.RANDOM -> {
                group.addProperty("type", "load-balance")
                group.addProperty("strategy", "consistent-hashing")
            }

            BalancerStrategyType.ROUND_ROBIN -> {
                group.addProperty("type", "load-balance")
                group.addProperty("strategy", "round-robin")
            }

            // leastPing, and leastLoad (no mihomo equivalent): pick the fastest member.
            else -> {
                group.addProperty("type", "url-test")
                group.addProperty("tolerance", 50)
            }
        }
        group.add("proxies", jsonArray(members))
        group.addProperty("url", settings.delayTestUrl)
        group.addProperty("interval", interval)
        group.addProperty("lazy", true)
        return group
    }

    /** One node as a mihomo proxy, null when mihomo cannot run it. */
    internal fun toProxy(profile: ProfileItem, name: String, settings: KiteConfigSettings): JsonObject? {
        val port = KiteProfileSupport.serverPort(profile) ?: return null
        val proxy = JsonObject()
        proxy.addProperty("name", name)
        proxy.addProperty("server", KiteProfileSupport.serverAddress(profile))
        proxy.addProperty("port", port)
        when (profile.configType) {
            EConfigType.VMESS -> {
                proxy.addProperty("type", "vmess")
                proxy.addProperty("uuid", profile.password.orEmpty())
                proxy.addProperty("alterId", 0)
                proxy.addProperty("cipher", profile.method?.takeIf { it.isNotBlank() } ?: "auto")
                proxy.addProperty("udp", true)
                if (!applyTransport(proxy, profile)) return null
                applyTls(proxy, profile, sniKey = "servername")
            }

            EConfigType.VLESS -> {
                proxy.addProperty("type", "vless")
                proxy.addProperty("uuid", profile.password.orEmpty())
                proxy.putIfNotBlank("flow", profile.flow)
                profile.method?.takeIf { it.isNotBlank() && it != "none" }?.let { proxy.addProperty("encryption", it) }
                proxy.addProperty("udp", true)
                proxy.addProperty("packet-encoding", "xudp")
                if (!applyTransport(proxy, profile)) return null
                applyTls(proxy, profile, sniKey = "servername")
            }

            EConfigType.TROJAN -> {
                proxy.addProperty("type", "trojan")
                proxy.addProperty("password", profile.password.orEmpty())
                proxy.addProperty("udp", true)
                if (!applyTransport(proxy, profile)) return null
                applyTls(proxy, profile, sniKey = "sni")
            }

            EConfigType.SHADOWSOCKS -> {
                proxy.addProperty("type", "ss")
                proxy.addProperty("cipher", profile.method.orEmpty())
                proxy.addProperty("password", profile.password.orEmpty())
                proxy.addProperty("udp", true)
                if (!applyShadowsocksPlugin(proxy, profile)) return null
            }

            EConfigType.SOCKS -> {
                proxy.addProperty("type", "socks5")
                proxy.putIfNotBlank("username", profile.username)
                if (!profile.username.isNullOrBlank()) proxy.addProperty("password", profile.password.orEmpty())
                proxy.addProperty("udp", true)
            }

            EConfigType.HTTP -> {
                proxy.addProperty("type", "http")
                proxy.putIfNotBlank("username", profile.username)
                if (!profile.username.isNullOrBlank()) proxy.addProperty("password", profile.password.orEmpty())
                if (KiteProfileSupport.isTls(profile)) {
                    proxy.addProperty("tls", true)
                    proxy.putIfNotBlank("sni", KiteProfileSupport.serverName(profile))
                    proxy.addProperty("skip-cert-verify", KiteProfileSupport.allowInsecure(profile))
                }
            }

            EConfigType.HYSTERIA2 -> {
                proxy.addProperty("type", "hysteria2")
                proxy.addProperty("password", profile.password.orEmpty())
                profile.portHopping?.takeIf { it.isNotBlank() }?.let {
                    proxy.addProperty("ports", it.replace(":", "-"))
                    proxy.addProperty("hop-interval", KiteProfileSupport.hopIntervalSeconds(profile.portHoppingInterval))
                }
                if (!profile.obfsPassword.isNullOrBlank()) {
                    proxy.addProperty("obfs", "salamander")
                    proxy.addProperty("obfs-password", profile.obfsPassword)
                }
                KiteProfileSupport.parseMbps(profile.bandwidthUp)?.let { proxy.addProperty("up", "$it Mbps") }
                KiteProfileSupport.parseMbps(profile.bandwidthDown)?.let { proxy.addProperty("down", "$it Mbps") }
                proxy.putIfNotBlank("sni", KiteProfileSupport.serverName(profile))
                proxy.addProperty("skip-cert-verify", KiteProfileSupport.allowInsecure(profile))
                proxy.add("alpn", jsonArray(KiteProfileSupport.alpn(profile).ifEmpty { listOf("h3") }))
                firstPin(profile)?.let { proxy.addProperty("fingerprint", it) }
            }

            EConfigType.HYSTERIA -> {
                proxy.addProperty("type", "hysteria")
                proxy.addProperty("auth-str", profile.password.orEmpty())
                proxy.putIfNotBlank("obfs", profile.obfsPassword)
                proxy.addProperty("up", "${KiteProfileSupport.parseMbps(profile.bandwidthUp) ?: 50} Mbps")
                proxy.addProperty("down", "${KiteProfileSupport.parseMbps(profile.bandwidthDown) ?: 100} Mbps")
                proxy.putIfNotBlank("sni", KiteProfileSupport.serverName(profile))
                proxy.addProperty("skip-cert-verify", KiteProfileSupport.allowInsecure(profile))
                KiteProfileSupport.alpn(profile).takeIf { it.isNotEmpty() }?.let { proxy.add("alpn", jsonArray(it)) }
            }

            EConfigType.WIREGUARD -> {
                proxy.addProperty("type", "wireguard")
                proxy.addProperty("private-key", profile.secretKey.orEmpty())
                proxy.addProperty("public-key", profile.publicKey.orEmpty())
                proxy.putIfNotBlank("pre-shared-key", profile.preSharedKey)
                val addresses = KiteProfileSupport.wireguardAddresses(profile, settings.ipv6)
                addresses.firstOrNull { !KiteRuleTranslator.isIpv6Cidr(it) }?.let { proxy.addProperty("ip", it.substringBefore("/")) }
                addresses.firstOrNull { KiteRuleTranslator.isIpv6Cidr(it) }?.let { proxy.addProperty("ipv6", it.substringBefore("/")) }
                KiteProfileSupport.wireguardReserved(profile)?.let { proxy.add("reserved", jsonIntArray(it)) }
                profile.mtu?.takeIf { it > 0 }?.let { proxy.addProperty("mtu", it) }
                proxy.addProperty("udp", true)
                proxy.addProperty("remote-dns-resolve", true)
                proxy.add("dns", jsonArray(KiteProfileSupport.wireguardDns(profile, settings.ipv6)))
            }

            else -> return null
        }
        return proxy
    }

    private fun firstPin(profile: ProfileItem): String? =
        KiteProfileSupport.splitCsv(profile.pinnedCA256).firstOrNull()?.replace(":", "")?.lowercase()

    /** Applies the stream transport. False when mihomo has no equivalent. */
    private fun applyTransport(proxy: JsonObject, profile: ProfileItem): Boolean {
        val hosts = KiteProfileSupport.splitCsv(profile.host)
        when (profile.network.orEmpty().ifEmpty { NetworkType.TCP.type }) {
            NetworkType.TCP.type -> if (profile.headerType == AppConfig.HEADER_TYPE_HTTP) {
                if (profile.configType == EConfigType.TROJAN) return false
                proxy.addProperty("network", "http")
                proxy.add("http-opts", JsonObject().apply {
                    addProperty("method", "GET")
                    add("path", jsonArray(KiteProfileSupport.splitCsv(profile.path).ifEmpty { listOf("/") }))
                    if (hosts.isNotEmpty()) add("headers", JsonObject().apply { add("Host", jsonArray(hosts)) })
                })
            }

            NetworkType.WS.type, NetworkType.HTTP_UPGRADE.type -> {
                val (path, earlyData) = KiteProfileSupport.splitEarlyData(profile.path)
                proxy.addProperty("network", "ws")
                proxy.add("ws-opts", JsonObject().apply {
                    addProperty("path", path)
                    hosts.firstOrNull()?.let { host -> add("headers", JsonObject().apply { addProperty("Host", host) }) }
                    if (profile.network == NetworkType.HTTP_UPGRADE.type) {
                        addProperty("v2ray-http-upgrade", true)
                        if (earlyData != null) addProperty("v2ray-http-upgrade-fast-open", true)
                    } else if (earlyData != null) {
                        addProperty("max-early-data", earlyData)
                        addProperty("early-data-header-name", "Sec-WebSocket-Protocol")
                    }
                })
            }

            NetworkType.GRPC.type -> {
                proxy.addProperty("network", "grpc")
                proxy.add("grpc-opts", JsonObject().apply {
                    addProperty("grpc-service-name", profile.serviceName.orEmpty())
                })
            }

            NetworkType.H2.type, NetworkType.HTTP.type -> {
                proxy.addProperty("network", "h2")
                proxy.add("h2-opts", JsonObject().apply {
                    if (hosts.isNotEmpty()) add("host", jsonArray(hosts))
                    addProperty("path", profile.path?.takeIf { it.isNotEmpty() } ?: "/")
                })
            }

            NetworkType.XHTTP.type -> {
                if (profile.configType != EConfigType.VLESS) return false
                proxy.addProperty("network", "xhttp")
                proxy.add("xhttp-opts", JsonObject().apply {
                    addProperty("path", profile.path?.takeIf { it.isNotEmpty() } ?: "/")
                    hosts.firstOrNull()?.let { addProperty("host", it) }
                    profile.xhttpMode?.takeIf { it.isNotBlank() }?.let { addProperty("mode", it) }
                })
            }

            else -> return false
        }
        return true
    }

    private fun applyTls(proxy: JsonObject, profile: ProfileItem, sniKey: String) {
        val reality = KiteProfileSupport.isReality(profile)
        if (!KiteProfileSupport.isTls(profile) && !reality) {
            if (profile.configType == EConfigType.TROJAN) {
                // Trojan always runs over TLS in mihomo.
                proxy.putIfNotBlank(sniKey, KiteProfileSupport.serverName(profile))
            }
            return
        }
        if (profile.configType != EConfigType.TROJAN) proxy.addProperty("tls", true)
        proxy.putIfNotBlank(sniKey, KiteProfileSupport.serverName(profile))
        KiteProfileSupport.alpn(profile).takeIf { it.isNotEmpty() }?.let { proxy.add("alpn", jsonArray(it)) }
        proxy.addProperty("skip-cert-verify", KiteProfileSupport.allowInsecure(profile))
        val fingerprint = profile.fingerPrint?.takeIf { it.isNotBlank() } ?: if (reality) "chrome" else null
        fingerprint?.let { proxy.addProperty("client-fingerprint", it) }
        firstPin(profile)?.let { proxy.addProperty("fingerprint", it) }
        profile.echConfigList?.trim()?.takeIf { it.isNotEmpty() }?.let { ech ->
            proxy.add("ech-opts", JsonObject().apply {
                addProperty("enable", true)
                // A base64 ECHConfigList is used as is; otherwise mihomo queries the HTTPS record.
                if (!ech.contains("://") && !ech.contains("+")) addProperty("config", ech)
            })
        }
        if (reality) {
            proxy.add("reality-opts", JsonObject().apply {
                addProperty("public-key", profile.publicKey.orEmpty())
                putIfNotBlank("short-id", profile.shortId)
            })
        }
    }

    private fun applyShadowsocksPlugin(proxy: JsonObject, profile: ProfileItem): Boolean {
        val network = profile.network.orEmpty().ifEmpty { NetworkType.TCP.type }
        val host = KiteProfileSupport.splitCsv(profile.host).firstOrNull()
        when {
            network == NetworkType.TCP.type && profile.headerType == AppConfig.HEADER_TYPE_HTTP -> {
                proxy.addProperty("plugin", "obfs")
                proxy.add("plugin-opts", JsonObject().apply {
                    addProperty("mode", "http")
                    host?.let { addProperty("host", it) }
                })
            }

            network == NetworkType.WS.type -> {
                proxy.addProperty("plugin", "v2ray-plugin")
                proxy.add("plugin-opts", JsonObject().apply {
                    addProperty("mode", "websocket")
                    host?.let { addProperty("host", it) }
                    addProperty("path", profile.path?.takeIf { it.isNotEmpty() } ?: "/")
                    if (KiteProfileSupport.isTls(profile)) {
                        addProperty("tls", true)
                        addProperty("skip-cert-verify", KiteProfileSupport.allowInsecure(profile))
                    }
                })
            }

            network != NetworkType.TCP.type -> return false
        }
        return true
    }
}
