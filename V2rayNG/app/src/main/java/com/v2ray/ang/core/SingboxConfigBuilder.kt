package com.v2ray.ang.core

import com.google.gson.JsonArray
import com.google.gson.JsonObject
import com.v2ray.ang.AppConfig
import com.v2ray.ang.core.KiteProfileSupport.jsonArray
import com.v2ray.ang.core.KiteProfileSupport.jsonIntArray
import com.v2ray.ang.core.KiteProfileSupport.putIfNotBlank
import com.v2ray.ang.dto.CoreConfigContext
import com.v2ray.ang.dto.entities.ProfileItem
import com.v2ray.ang.enums.CoreResolvedType
import com.v2ray.ang.enums.EConfigType
import com.v2ray.ang.enums.NetworkType
import com.v2ray.ang.util.LogUtil

/**
 * Translates the analyzed profile plan ([CoreConfigContext]) into a sing-box 1.14 configuration.
 *
 * Inbounds are not written here: libkite adds the tun / mixed / tproxy / redirect inbounds of the
 * run mode, and the sniff and DNS hijack rules, when the core starts.
 *
 * - Nodes become outbounds (WireGuard an endpoint), policy groups `urltest`, proxy chains
 *   `detour` links, the main outbound is always tagged "proxy" and is `route.final`.
 * - Routing rules, rule-sets and DNS come from [SingboxRoutingBuilder].
 */
object SingboxConfigBuilder {

    const val PROXY = AppConfig.TAG_PROXY
    const val DIRECT = AppConfig.TAG_DIRECT

    data class Result(val content: String, val skipped: List<String>)

    private class State(val settings: KiteConfigSettings) {
        val outbounds = JsonArray()
        val endpoints = JsonArray()
        val tags = mutableSetOf<String>()
        val skipped = mutableListOf<String>()
    }

    fun build(context: CoreConfigContext, settings: KiteConfigSettings, forSpeedtest: Boolean = false): Result {
        val state = State(settings)
        context.resolvedOutbounds.forEach { addOutbound(it, state) }
        if (PROXY !in state.tags) {
            error("No node of this profile can run on sing-box")
        }
        state.outbounds.add(JsonObject().apply {
            addProperty("type", "direct")
            addProperty("tag", DIRECT)
        })
        state.tags.add(DIRECT)

        val root = JsonObject()
        root.add("log", JsonObject().apply {
            addProperty("level", logLevel(settings.logLevel))
            if (settings.logLevel == "none") addProperty("disabled", true)
        })
        if (state.endpoints.size() > 0) root.add("endpoints", state.endpoints)
        root.add("outbounds", state.outbounds)
        val route = JsonObject()
        route.addProperty("final", PROXY)
        root.add("route", route)
        SingboxRoutingBuilder.apply(root, route, state.tags, settings, forSpeedtest)
        return Result(KiteProfileSupport.toPrettyJson(root), state.skipped)
    }

    private fun logLevel(level: String): String = when (level.lowercase()) {
        "debug" -> "debug"
        "info" -> "info"
        "error" -> "error"
        else -> "warn"
    }

    // ---------------------------------------------------------------- outbounds

    private fun addOutbound(outbound: CoreConfigContext.ResolvedOutbound, state: State) {
        if (outbound.tag in state.tags) return
        when (outbound.resolvedType) {
            CoreResolvedType.NORMAL -> {
                val profile = outbound.resolvedProfiles.firstOrNull() ?: return
                addNode(profile, outbound.tag, null, state)
            }

            CoreResolvedType.PROXYCHAIN -> {
                val hops = outbound.resolvedProfiles.mapIndexed { index, profile ->
                    (if (index == 0) outbound.tag else "${outbound.tag}-hop-$index") to profile
                }
                if (hops.any { it.first in state.tags }) return
                // resolvedProfiles[0] is entered first and dials through the next hop.
                val nodes = hops.mapIndexed { index, (tag, profile) ->
                    toNode(profile, tag, hops.getOrNull(index + 1)?.first, state.settings) ?: run {
                        state.skipped.add(profile.remarks)
                        return
                    }
                }
                nodes.forEach { (node, isEndpoint) -> register(node, isEndpoint, state) }
            }

            CoreResolvedType.POLICYGROUP -> {
                val members = mutableListOf<String>()
                outbound.resolvedProfiles.forEachIndexed { index, profile ->
                    val tag = "${AppConfig.TAG_PROXY}-${outbound.tag}-${index + 1}-${profile.remarks.trim()}"
                    if (tag in state.tags) return@forEachIndexed
                    if (addNode(profile, tag, null, state)) members.add(tag)
                }
                if (members.isEmpty()) {
                    LogUtil.w(AppConfig.TAG, "sing-box: policy group '${outbound.tag}' has no usable member")
                    return
                }
                // sing-box groups are selector and urltest; every Xray strategy maps to urltest.
                state.outbounds.add(JsonObject().apply {
                    addProperty("type", "urltest")
                    addProperty("tag", outbound.tag)
                    add("outbounds", jsonArray(members))
                    addProperty("url", state.settings.delayTestUrl)
                    addProperty("interval", "${KiteProfileSupport.durationSeconds(state.settings.urlTestInterval)}s")
                    addProperty("tolerance", 50)
                })
                state.tags.add(outbound.tag)
            }
        }
    }

    private fun addNode(profile: ProfileItem, tag: String, detour: String?, state: State): Boolean {
        val (node, isEndpoint) = toNode(profile, tag, detour, state.settings) ?: run {
            state.skipped.add(profile.remarks)
            return false
        }
        register(node, isEndpoint, state)
        return true
    }

    private fun register(node: JsonObject, isEndpoint: Boolean, state: State) {
        if (isEndpoint) state.endpoints.add(node) else state.outbounds.add(node)
        state.tags.add(node.get("tag").asString)
    }

    /** One node as a sing-box outbound (second = true: an endpoint), null when unsupported. */
    internal fun toNode(profile: ProfileItem, tag: String, detour: String?, settings: KiteConfigSettings): Pair<JsonObject, Boolean>? {
        val port = KiteProfileSupport.serverPort(profile) ?: return null
        val node = JsonObject()
        node.addProperty("tag", tag)
        if (profile.configType == EConfigType.WIREGUARD) {
            node.addProperty("type", "wireguard")
            node.add("address", jsonArray(KiteProfileSupport.wireguardAddresses(profile, settings.ipv6)))
            node.addProperty("private_key", profile.secretKey.orEmpty())
            profile.mtu?.takeIf { it > 0 }?.let { node.addProperty("mtu", it) }
            node.add("peers", JsonArray().apply {
                add(JsonObject().apply {
                    addProperty("address", KiteProfileSupport.serverAddress(profile))
                    addProperty("port", port)
                    addProperty("public_key", profile.publicKey.orEmpty())
                    putIfNotBlank("pre_shared_key", profile.preSharedKey)
                    add("allowed_ips", jsonArray(listOf("0.0.0.0/0", "::/0")))
                    KiteProfileSupport.wireguardReserved(profile)?.let { add("reserved", jsonIntArray(it)) }
                })
            })
            detour?.let { node.addProperty("detour", it) }
            return node to true
        }
        node.addProperty("server", KiteProfileSupport.serverAddress(profile))
        node.addProperty("server_port", port)
        when (profile.configType) {
            EConfigType.VMESS -> {
                node.addProperty("type", "vmess")
                node.addProperty("uuid", profile.password.orEmpty())
                node.addProperty("security", profile.method?.takeIf { it.isNotBlank() } ?: "auto")
                node.addProperty("alter_id", 0)
                if (!applyTransport(node, profile)) return null
                applyTls(node, profile)
            }

            EConfigType.VLESS -> {
                val encryption = profile.method.orEmpty()
                if (encryption.isNotEmpty() && encryption != "none") return null
                node.addProperty("type", "vless")
                node.addProperty("uuid", profile.password.orEmpty())
                node.putIfNotBlank("flow", profile.flow)
                node.addProperty("packet_encoding", "xudp")
                if (!applyTransport(node, profile)) return null
                applyTls(node, profile)
            }

            EConfigType.TROJAN -> {
                node.addProperty("type", "trojan")
                node.addProperty("password", profile.password.orEmpty())
                if (!applyTransport(node, profile)) return null
                applyTls(node, profile)
            }

            EConfigType.SHADOWSOCKS -> {
                node.addProperty("type", "shadowsocks")
                node.addProperty("method", profile.method.orEmpty())
                node.addProperty("password", profile.password.orEmpty())
                val network = profile.network.orEmpty().ifEmpty { NetworkType.TCP.type }
                when {
                    network == NetworkType.TCP.type && profile.headerType == AppConfig.HEADER_TYPE_HTTP -> {
                        node.addProperty("plugin", "obfs-local")
                        val host = KiteProfileSupport.splitCsv(profile.host).firstOrNull()
                        node.addProperty("plugin_opts", "obfs=http" + (host?.let { ";obfs-host=$it" } ?: ""))
                    }

                    network == NetworkType.WS.type -> {
                        node.addProperty("plugin", "v2ray-plugin")
                        val opts = mutableListOf("mode=websocket")
                        KiteProfileSupport.splitCsv(profile.host).firstOrNull()?.let { opts.add("host=$it") }
                        opts.add("path=" + (profile.path?.takeIf { it.isNotEmpty() } ?: "/"))
                        if (KiteProfileSupport.isTls(profile)) opts.add("tls")
                        node.addProperty("plugin_opts", opts.joinToString(";"))
                    }

                    network != NetworkType.TCP.type -> return null
                }
            }

            EConfigType.SOCKS -> {
                node.addProperty("type", "socks")
                node.addProperty("version", "5")
                node.putIfNotBlank("username", profile.username)
                if (!profile.username.isNullOrBlank()) node.addProperty("password", profile.password.orEmpty())
            }

            EConfigType.HTTP -> {
                node.addProperty("type", "http")
                node.putIfNotBlank("username", profile.username)
                if (!profile.username.isNullOrBlank()) node.addProperty("password", profile.password.orEmpty())
                if (KiteProfileSupport.isTls(profile)) applyTls(node, profile)
            }

            EConfigType.HYSTERIA2 -> {
                node.addProperty("type", "hysteria2")
                node.addProperty("password", profile.password.orEmpty())
                profile.portHopping?.takeIf { it.isNotBlank() }?.let { ports ->
                    node.add("server_ports", jsonArray(ports.split(",").map { it.trim().replace("-", ":") }.filter { it.isNotEmpty() }))
                    node.addProperty("hop_interval", "${KiteProfileSupport.hopIntervalSeconds(profile.portHoppingInterval)}s")
                }
                KiteProfileSupport.parseMbps(profile.bandwidthUp)?.let { node.addProperty("up_mbps", it) }
                KiteProfileSupport.parseMbps(profile.bandwidthDown)?.let { node.addProperty("down_mbps", it) }
                if (!profile.obfsPassword.isNullOrBlank()) {
                    node.add("obfs", JsonObject().apply {
                        addProperty("type", "salamander")
                        addProperty("password", profile.obfsPassword)
                    })
                }
                node.add("tls", tlsObject(profile, defaultAlpn = listOf("h3"), allowUtls = false))
            }

            EConfigType.HYSTERIA -> {
                node.addProperty("type", "hysteria")
                node.addProperty("auth_str", profile.password.orEmpty())
                node.addProperty("up_mbps", KiteProfileSupport.parseMbps(profile.bandwidthUp) ?: 50)
                node.addProperty("down_mbps", KiteProfileSupport.parseMbps(profile.bandwidthDown) ?: 100)
                node.putIfNotBlank("obfs", profile.obfsPassword)
                node.add("tls", tlsObject(profile, defaultAlpn = emptyList(), allowUtls = false))
            }

            else -> return null
        }
        detour?.let { node.addProperty("detour", it) }
        return node to false
    }

    /** Applies the V2Ray transport. False when sing-box has no equivalent. */
    private fun applyTransport(node: JsonObject, profile: ProfileItem): Boolean {
        val hosts = KiteProfileSupport.splitCsv(profile.host)
        val transport = JsonObject()
        when (profile.network.orEmpty().ifEmpty { NetworkType.TCP.type }) {
            NetworkType.TCP.type -> {
                // Xray's HTTP header obfuscation is not a sing-box transport.
                if (profile.headerType == AppConfig.HEADER_TYPE_HTTP) return false
                return true
            }

            NetworkType.WS.type -> {
                val (path, earlyData) = KiteProfileSupport.splitEarlyData(profile.path)
                transport.addProperty("type", "ws")
                transport.addProperty("path", path)
                hosts.firstOrNull()?.let { host -> transport.add("headers", JsonObject().apply { addProperty("Host", host) }) }
                if (earlyData != null) {
                    transport.addProperty("max_early_data", earlyData)
                    transport.addProperty("early_data_header_name", "Sec-WebSocket-Protocol")
                }
            }

            NetworkType.HTTP_UPGRADE.type -> {
                transport.addProperty("type", "httpupgrade")
                hosts.firstOrNull()?.let { transport.addProperty("host", it) }
                transport.addProperty("path", KiteProfileSupport.splitEarlyData(profile.path).first)
            }

            NetworkType.GRPC.type -> {
                transport.addProperty("type", "grpc")
                transport.addProperty("service_name", profile.serviceName.orEmpty())
                transport.addProperty("idle_timeout", "60s")
                transport.addProperty("ping_timeout", "20s")
            }

            NetworkType.H2.type, NetworkType.HTTP.type -> {
                transport.addProperty("type", "http")
                if (hosts.isNotEmpty()) transport.add("host", jsonArray(hosts))
                transport.addProperty("path", profile.path?.takeIf { it.isNotEmpty() } ?: "/")
            }

            else -> return false
        }
        node.add("transport", transport)
        return true
    }

    private fun applyTls(node: JsonObject, profile: ProfileItem) {
        if (!KiteProfileSupport.isTls(profile) && !KiteProfileSupport.isReality(profile)) return
        node.add("tls", tlsObject(profile, defaultAlpn = emptyList(), allowUtls = true))
    }

    private fun tlsObject(profile: ProfileItem, defaultAlpn: List<String>, allowUtls: Boolean): JsonObject = JsonObject().apply {
        addProperty("enabled", true)
        putIfNotBlank("server_name", KiteProfileSupport.serverName(profile))
        addProperty("insecure", KiteProfileSupport.allowInsecure(profile))
        KiteProfileSupport.alpn(profile).ifEmpty { defaultAlpn }.takeIf { it.isNotEmpty() }?.let { add("alpn", jsonArray(it)) }
        val reality = KiteProfileSupport.isReality(profile)
        val fingerprint = profile.fingerPrint?.takeIf { it.isNotBlank() } ?: if (reality) "chrome" else null
        if (allowUtls && fingerprint != null) {
            add("utls", JsonObject().apply {
                addProperty("enabled", true)
                addProperty("fingerprint", fingerprint)
            })
        }
        if (reality) {
            add("reality", JsonObject().apply {
                addProperty("enabled", true)
                addProperty("public_key", profile.publicKey.orEmpty())
                putIfNotBlank("short_id", profile.shortId)
            })
        }
        profile.echConfigList?.trim()?.takeIf { it.isNotEmpty() }?.let { ech ->
            add("ech", JsonObject().apply {
                addProperty("enabled", true)
                // A base64 ECHConfigList is used as is; otherwise sing-box queries the HTTPS record.
                if (!ech.contains("://") && !ech.contains("+")) {
                    add("config", jsonArray(listOf("-----BEGIN ECH CONFIGS-----", ech, "-----END ECH CONFIGS-----")))
                }
            })
        }
    }
}
