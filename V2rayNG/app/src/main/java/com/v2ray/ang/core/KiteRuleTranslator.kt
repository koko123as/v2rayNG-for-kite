package com.v2ray.ang.core

import com.v2ray.ang.AppConfig
import com.v2ray.ang.util.Utils
import java.net.URI

/**
 * Parsing shared by [MihomoConfigBuilder] and [SingboxConfigBuilder]: v2rayNG routing rule
 * entries (Xray syntax) and DNS server addresses.
 */
internal object KiteRuleTranslator {

    /** One entry of [com.v2ray.ang.dto.entities.RulesetItem.domain]. */
    sealed interface DomainEntry {
        data class Suffix(val value: String) : DomainEntry
        data class Full(val value: String) : DomainEntry
        data class Keyword(val value: String) : DomainEntry
        data class Regex(val value: String) : DomainEntry
        /** geosite:code[@attr] from geosite.dat, or ext:file:code from another .dat file. */
        data class Geo(val file: String, val code: String) : DomainEntry
    }

    /** One entry of [com.v2ray.ang.dto.entities.RulesetItem.ip]. */
    sealed interface IpEntry {
        val negate: Boolean

        data class Cidr(val value: String, override val negate: Boolean = false) : IpEntry
        data class Private(override val negate: Boolean = false) : IpEntry
        data class Geo(val file: String, val code: String, override val negate: Boolean = false) : IpEntry
    }

    fun parseDomain(raw: String): DomainEntry? {
        val value = raw.trim()
        if (value.isEmpty()) return null
        return when {
            value.startsWith("geosite:") -> DomainEntry.Geo(AppConfig.GEOSITE_DAT, value.removePrefix("geosite:").lowercase())
            value.startsWith("ext:") -> {
                val parts = value.removePrefix("ext:").split(":", limit = 2)
                if (parts.size == 2 && parts[0].isNotBlank() && parts[1].isNotBlank()) {
                    DomainEntry.Geo(parts[0], parts[1].lowercase())
                } else null
            }
            value.startsWith("domain:") -> DomainEntry.Suffix(value.removePrefix("domain:"))
            value.startsWith("full:") -> DomainEntry.Full(value.removePrefix("full:"))
            value.startsWith("regexp:") -> DomainEntry.Regex(value.removePrefix("regexp:"))
            value.startsWith("keyword:") -> DomainEntry.Keyword(value.removePrefix("keyword:"))
            // dotless: and other Xray-only matchers have no equivalent.
            value.contains(":") -> null
            // A plain string is a substring match in Xray.
            else -> DomainEntry.Keyword(value)
        }
    }

    fun parseIp(raw: String): IpEntry? {
        var value = raw.trim()
        if (value.isEmpty()) return null
        val negate = value.startsWith("!")
        if (negate) value = value.removePrefix("!")
        return when {
            value == AppConfig.GEOIP_PRIVATE -> IpEntry.Private(negate)
            value.startsWith("geoip:") -> IpEntry.Geo(AppConfig.GEOIP_DAT, value.removePrefix("geoip:").lowercase(), negate)
            value.startsWith("ext:") -> {
                val parts = value.removePrefix("ext:").split(":", limit = 2)
                when {
                    parts.size != 2 || parts[0].isBlank() || parts[1].isBlank() -> null
                    parts[1].equals("private", true) -> IpEntry.Private(negate)
                    // The v2rayNG geoip-only-cn-private.dat codes also exist in geoip.dat.
                    parts[0] == AppConfig.GEOIP_ONLY_CN_PRIVATE_DAT -> IpEntry.Geo(AppConfig.GEOIP_DAT, parts[1].lowercase(), negate)
                    else -> IpEntry.Geo(parts[0], parts[1].lowercase(), negate)
                }
            }
            else -> normalizeCidr(value)?.let { IpEntry.Cidr(it, negate) }
        }
    }

    /** "1.2.3.4" -> "1.2.3.4/32", "1.2.3.0/24" unchanged, invalid -> null. */
    fun normalizeCidr(value: String): String? {
        val address = value.substringBefore("/")
        val prefix = value.substringAfter("/", "")
        if (!Utils.isPureIpAddress(address)) return null
        val isV6 = address.contains(":")
        val max = if (isV6) 128 else 32
        if (prefix.isEmpty()) return "$address/$max"
        val bits = prefix.toIntOrNull() ?: return null
        if (bits !in 0..max) return null
        return "$address/$bits"
    }

    fun isIpv6Cidr(value: String): Boolean = value.substringBefore("/").contains(":")

    /** A port or a port range of [com.v2ray.ang.dto.entities.RulesetItem.port]. */
    data class PortEntry(val start: Int, val end: Int) {
        val isRange get() = start != end
    }

    fun parsePorts(raw: String?): List<PortEntry> {
        if (raw.isNullOrBlank()) return emptyList()
        return raw.split(",").mapNotNull { part ->
            val item = part.trim()
            if (item.contains("-")) {
                val start = item.substringBefore("-").trim().toIntOrNull()
                val end = item.substringAfter("-").trim().toIntOrNull()
                if (start != null && end != null && start in 0..65535 && end in start..65535) PortEntry(start, end) else null
            } else {
                item.toIntOrNull()?.takeIf { it in 0..65535 }?.let { PortEntry(it, it) }
            }
        }
    }

    /** Networks of a rule ("tcp", "udp" or both), empty when the rule does not filter. */
    fun parseNetworks(raw: String?): List<String> {
        val values = raw.orEmpty().split(",").map { it.trim().lowercase() }.filter { it == "tcp" || it == "udp" }.distinct()
        return if (values.size == 2) emptyList() else values
    }

    /** A DNS server as v2rayNG writes it in the remote/domestic DNS settings. */
    data class DnsServer(val type: String, val host: String, val port: Int? = null, val path: String? = null)

    /**
     * "1.1.1.1", "1.1.1.1:53", "https://host/dns-query", "h3://host/dns-query", "tls://host",
     * "quic://host", "tcp://host", "udp://host" and "localhost". Returns null for anything else
     * (for example "fakedns").
     */
    fun parseDnsServer(raw: String): DnsServer? {
        val value = raw.trim()
        if (value.isEmpty()) return null
        if (value == "localhost" || value == "local") return DnsServer("local", "")
        if (Utils.isPureIpAddress(value)) return DnsServer("udp", value)
        if (!value.contains("://")) {
            val host = value.substringBeforeLast(":")
            val port = value.substringAfterLast(":", "").toIntOrNull()
            if (port != null && Utils.isPureIpAddress(host.trim('[', ']'))) return DnsServer("udp", host.trim('[', ']'), port)
            return null
        }
        val uri = try {
            URI(value)
        } catch (_: Exception) {
            return null
        }
        val host = uri.host?.trim('[', ']') ?: return null
        val port = uri.port.takeIf { it > 0 }
        return when (uri.scheme?.lowercase()) {
            "https", "doh" -> DnsServer("https", host, port, uri.rawPath?.takeIf { it.isNotEmpty() } ?: "/dns-query")
            "h3" -> DnsServer("h3", host, port, uri.rawPath?.takeIf { it.isNotEmpty() } ?: "/dns-query")
            "tls", "dot" -> DnsServer("tls", host, port)
            "quic", "doq" -> DnsServer("quic", host, port)
            "tcp" -> DnsServer("tcp", host, port)
            "udp" -> DnsServer("udp", host, port)
            else -> null
        }
    }
}
