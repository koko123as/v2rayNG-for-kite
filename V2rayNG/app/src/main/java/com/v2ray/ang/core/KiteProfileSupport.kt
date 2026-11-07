package com.v2ray.ang.core

import com.google.gson.GsonBuilder
import com.google.gson.JsonArray
import com.google.gson.JsonElement
import com.google.gson.JsonObject
import com.v2ray.ang.AppConfig
import com.v2ray.ang.dto.entities.ProfileItem
import com.v2ray.ang.util.HttpUtil
import com.v2ray.ang.util.Utils

/**
 * ProfileItem helpers shared by [MihomoConfigBuilder] and [SingboxConfigBuilder]. They read the
 * same ProfileItem fields [CoreOutboundBuilder] reads for Xray, without the Xray-specific DTOs.
 */
internal object KiteProfileSupport {

    val gson = GsonBuilder().setPrettyPrinting().disableHtmlEscaping().create()

    fun toPrettyJson(element: JsonElement): String = gson.toJson(element)

    fun serverAddress(profile: ProfileItem): String {
        val server = profile.server.orEmpty().trim().trim('[', ']')
        return if (Utils.isPureIpAddress(server)) server else HttpUtil.toIdnDomain(server)
    }

    fun serverPort(profile: ProfileItem): Int? =
        profile.serverPort?.trim()?.toIntOrNull()?.takeIf { it in 1..65535 }

    fun splitCsv(value: String?): List<String> =
        value.orEmpty().split(",").map { it.trim() }.filter { it.isNotEmpty() }

    /** The TLS server name, following [CoreOutboundBuilder.populateTlsSettings]. */
    fun serverName(profile: ProfileItem): String? {
        profile.sni?.trim()?.takeIf { it.isNotEmpty() }?.let { return it }
        splitCsv(profile.host).firstOrNull()?.let { return it }
        val server = profile.server.orEmpty().trim()
        return server.takeIf { it.isNotEmpty() && !Utils.isPureIpAddress(server.trim('[', ']')) }
    }

    fun allowInsecure(profile: ProfileItem): Boolean = profile.insecure == true && profile.pinnedCA256.isNullOrEmpty()

    fun alpn(profile: ProfileItem): List<String> = splitCsv(profile.alpn)

    fun isTls(profile: ProfileItem) = profile.security == AppConfig.TLS
    fun isReality(profile: ProfileItem) = profile.security == AppConfig.REALITY

    /** WebSocket path without the "ed" query, and the early data size it carried. */
    fun splitEarlyData(path: String?): Pair<String, Int?> {
        val value = path?.takeIf { it.isNotEmpty() } ?: "/"
        val query = value.substringAfter("?", "")
        if (query.isEmpty()) return value to null
        var earlyData: Int? = null
        val rest = query.split("&").filter { part ->
            if (part.startsWith("ed=")) {
                earlyData = part.removePrefix("ed=").toIntOrNull()
                false
            } else true
        }
        val base = value.substringBefore("?")
        return (if (rest.isEmpty()) base else base + "?" + rest.joinToString("&")) to earlyData
    }

    /** "100", "100 mbps", "100Mbps" -> 100. */
    fun parseMbps(value: String?): Int? =
        value?.trim()?.let { Regex("""^(\d+)""").find(it)?.groupValues?.get(1)?.toIntOrNull() }?.takeIf { it > 0 }

    /** Hysteria2 hop interval in seconds: "30" or "5-10" (the lower bound, at least 5). */
    fun hopIntervalSeconds(value: String?): Int {
        val first = value?.trim()?.split("-")?.firstOrNull()?.trim()?.toIntOrNull() ?: return 30
        return if (first < 5) 30 else first
    }

    /** Xray duration ("3m", "30s", "1h", "500ms") in seconds, at least 1. */
    fun durationSeconds(value: String, default: Int = 180): Int {
        val match = Regex("""^(\d+)(ms|s|m|h)$""").find(value.trim()) ?: return default
        val number = match.groupValues[1].toLongOrNull() ?: return default
        val seconds = when (match.groupValues[2]) {
            "ms" -> number / 1000
            "s" -> number
            "m" -> number * 60
            "h" -> number * 3600
            else -> return default
        }
        return seconds.coerceIn(1, Int.MAX_VALUE.toLong()).toInt()
    }

    fun wireguardAddresses(profile: ProfileItem, ipv6: Boolean): List<String> {
        val raw = splitCsv(profile.localAddress).ifEmpty { listOf(AppConfig.WIREGUARD_LOCAL_ADDRESS_V4) }
        val filtered = if (ipv6) raw else raw.filter { !it.contains(":") }
        return filtered.ifEmpty { listOf(AppConfig.WIREGUARD_LOCAL_ADDRESS_V4) }
            .mapNotNull { KiteRuleTranslator.normalizeCidr(it) }
    }

    fun wireguardReserved(profile: ProfileItem): List<Int>? =
        splitCsv(profile.reserved).mapNotNull { it.toIntOrNull() }.takeIf { it.size == 3 }

    fun wireguardDns(profile: ProfileItem, ipv6: Boolean): List<String> {
        val defaults = splitCsv(AppConfig.WIREGUARD_LOCAL_REMOTE_DNS)
        val raw = splitCsv(profile.remoteDNS).ifEmpty { defaults }
        return if (ipv6) raw else raw.filter { !it.contains(":") }.ifEmpty { defaults.filter { !it.contains(":") } }
    }

    /** Hosts the app always pins (DoH servers), the same list Xray gets. */
    fun builtinDnsHosts(): Map<String, List<String>> = mapOf(
        AppConfig.DNS_ALIDNS_DOMAIN to AppConfig.DNS_ALIDNS_ADDRESSES,
        AppConfig.DNS_CISCO_SSE_DOMAIN to AppConfig.DNS_CISCO_SSE_ADDRESSES,
        AppConfig.DNS_CISCO_UMBRELLA_DOMAIN to AppConfig.DNS_CISCO_UMBRELLA_ADDRESSES,
        AppConfig.DNS_CLOUDFLARE_ONE_DOMAIN to AppConfig.DNS_CLOUDFLARE_ONE_ADDRESSES,
        AppConfig.DNS_CLOUDFLARE_ONEDOT_DNS_DOMAIN to AppConfig.DNS_CLOUDFLARE_ONEDOT_DNS_ADDRESSES,
        AppConfig.DNS_CLOUDFLARE_DNS_COM_DOMAIN to AppConfig.DNS_CLOUDFLARE_DNS_COM_ADDRESSES,
        AppConfig.DNS_CLOUDFLARE_DNS_DOMAIN to AppConfig.DNS_CLOUDFLARE_DNS_ADDRESSES,
        AppConfig.DNS_CLOUDFLARE_WARP_DOMAIN to AppConfig.DNS_CLOUDFLARE_WARP_ADDRESSES,
        AppConfig.DNS_DNSPOD_DOH_DOMAIN to AppConfig.DNS_DNSPOD_DOH_ADDRESSES,
        AppConfig.DNS_DNSPOD_DOT_DOMAIN to AppConfig.DNS_DNSPOD_DOT_ADDRESSES,
        AppConfig.DNS_GOOGLE_DOMAIN to AppConfig.DNS_GOOGLE_ADDRESSES,
        AppConfig.DNS_QUAD9_DOMAIN to AppConfig.DNS_QUAD9_ADDRESSES,
        AppConfig.DNS_SB_DOMAIN to AppConfig.DNS_SB_ADDRESSES,
        AppConfig.DNS_YANDEX_DOMAIN to AppConfig.DNS_YANDEX_ADDRESSES,
    )

    fun jsonArray(values: Iterable<String>): JsonArray = JsonArray().apply { values.forEach { add(it) } }
    fun jsonIntArray(values: Iterable<Int>): JsonArray = JsonArray().apply { values.forEach { add(it) } }

    fun JsonObject.putIfNotBlank(key: String, value: String?) {
        if (!value.isNullOrBlank()) addProperty(key, value)
    }
}
