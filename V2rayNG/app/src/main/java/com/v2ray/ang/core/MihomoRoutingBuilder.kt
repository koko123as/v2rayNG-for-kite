package com.v2ray.ang.core

import com.google.gson.JsonObject
import com.v2ray.ang.AppConfig
import com.v2ray.ang.core.KiteProfileSupport.jsonArray
import com.v2ray.ang.core.KiteRuleTranslator.DomainEntry
import com.v2ray.ang.core.KiteRuleTranslator.IpEntry
import com.v2ray.ang.dto.entities.RulesetItem

/**
 * Routing, DNS, hosts and sniffing of a mihomo configuration built by [MihomoConfigBuilder].
 *
 * - v2rayNG routing rules become mihomo rules (AND/OR logic rules where a rule combines fields);
 *   geosite/geoip codes read geosite.dat/geoip.dat in geodata mode, other `ext:` files become
 *   generated rule providers (libkite `kitegeo:` references). The last rule sends everything
 *   else to "proxy".
 * - DNS: remote servers answer by default and follow the rules (so they go through the proxy),
 *   domestic servers answer the domains of direct rules and resolve the proxy servers.
 */
object MihomoRoutingBuilder {

    private const val PROXY = MihomoConfigBuilder.PROXY
    private const val DIRECT = "DIRECT"
    private const val REJECT = "REJECT"

    fun apply(root: JsonObject, names: Set<String>, settings: KiteConfigSettings, skipped: MutableList<String>) {
        val providers = JsonObject()
        val rules = mutableListOf<String>()
        var usesProcess = false
        settings.rulesets.filter { it.enabled }.forEach { rule ->
            if (!rule.process.isNullOrEmpty()) usesProcess = true
            rules.addAll(translateRule(rule, names, settings, providers, skipped))
        }
        rules.add("MATCH,$PROXY")
        root.add("rules", jsonArray(rules))
        if (providers.size() > 0) root.add("rule-providers", providers)
        // With the cmfa build, process lookups ask Android for the package name of the owner uid.
        root.addProperty("find-process-mode", if (usesProcess) "strict" else "off")

        root.add("sniffer", buildSniffer(settings))
        root.add("hosts", buildHosts(settings))
        root.add("dns", buildDns(settings))
    }

    private fun target(tag: String, names: Set<String>): String = when (tag) {
        AppConfig.TAG_DIRECT -> DIRECT
        AppConfig.TAG_BLOCKED -> REJECT
        AppConfig.TAG_PROXY, "" -> PROXY
        else -> if (tag in names) tag else PROXY
    }

    /**
     * One v2rayNG rule as mihomo rules. Values of one field are alternatives, fields are combined:
     * a single field becomes one rule per value, several fields an AND rule of OR groups.
     */
    internal fun translateRule(
        rule: RulesetItem,
        names: Set<String>,
        settings: KiteConfigSettings,
        providers: JsonObject,
        skipped: MutableList<String>,
    ): List<String> {
        val noResolve = settings.domainStrategy == "AsIs"
        val groups = mutableListOf<List<String>>()
        rule.domain?.mapNotNull { domainCondition(it, providers) }?.takeIf { it.isNotEmpty() }?.let { groups.add(it) }
        rule.ip?.mapNotNull { ipCondition(it, providers, noResolve) }?.takeIf { it.isNotEmpty() }?.let { groups.add(it) }
        KiteRuleTranslator.parsePorts(rule.port).map { if (it.isRange) "DST-PORT,${it.start}-${it.end}" else "DST-PORT,${it.start}" }
            .takeIf { it.isNotEmpty() }?.let { groups.add(it) }
        KiteRuleTranslator.parseNetworks(rule.network).map { "NETWORK,${it.uppercase()}" }
            .takeIf { it.isNotEmpty() }?.let { groups.add(it) }
        rule.process?.filter { it.isNotBlank() && !it.contains(",") }?.map { "PROCESS-NAME,$it" }
            ?.takeIf { it.isNotEmpty() }?.let { groups.add(it) }
        if (!rule.protocol.isNullOrEmpty()) {
            // mihomo has no rule on the sniffed protocol (bittorrent, ...).
            skipped.add(rule.remarks ?: rule.id)
            return emptyList()
        }
        if (groups.isEmpty()) {
            return emptyList()
        }
        val target = target(rule.outboundTag, names)
        if (groups.size == 1) {
            return groups.first().map { appendTarget(it, target) }
        }
        val parts = groups.joinToString(",") { group ->
            if (group.size == 1) "(${group.first()})" else "(OR,(${group.joinToString(",") { "($it)" }}))"
        }
        return listOf("AND,($parts),$target")
    }

    /** Puts the target before a trailing ",no-resolve". */
    private fun appendTarget(condition: String, target: String): String =
        if (condition.endsWith(",no-resolve")) condition.removeSuffix(",no-resolve") + ",$target,no-resolve" else "$condition,$target"

    private fun domainCondition(raw: String, providers: JsonObject): String? {
        return when (val entry = KiteRuleTranslator.parseDomain(raw)) {
            is DomainEntry.Suffix -> "DOMAIN-SUFFIX,${entry.value}"
            is DomainEntry.Full -> "DOMAIN,${entry.value}"
            is DomainEntry.Keyword -> "DOMAIN-KEYWORD,${entry.value}"
            // A comma would split the rule.
            is DomainEntry.Regex -> if (entry.value.contains(",")) null else "DOMAIN-REGEX,${entry.value}"
            is DomainEntry.Geo -> if (entry.file == AppConfig.GEOSITE_DAT) {
                "GEOSITE,${entry.code}"
            } else {
                "RULE-SET,${geoProvider(providers, "site", entry.file, entry.code)}"
            }
            null -> null
        }
    }

    private fun ipCondition(raw: String, providers: JsonObject, noResolve: Boolean): String? {
        val entry = KiteRuleTranslator.parseIp(raw) ?: return null
        val suffix = if (noResolve) ",no-resolve" else ""
        val condition = when (entry) {
            is IpEntry.Cidr -> if (KiteRuleTranslator.isIpv6Cidr(entry.value)) "IP-CIDR6,${entry.value}$suffix" else "IP-CIDR,${entry.value}$suffix"
            is IpEntry.Private -> "GEOIP,private$suffix"
            is IpEntry.Geo -> if (entry.file == AppConfig.GEOIP_DAT) {
                "GEOIP,${entry.code}$suffix"
            } else {
                "RULE-SET,${geoProvider(providers, "ip", entry.file, entry.code)}$suffix"
            }
        }
        return if (entry.negate) "NOT,((${condition.removeSuffix(",no-resolve")}))" else condition
    }

    private fun geoProvider(providers: JsonObject, kind: String, file: String, code: String): String {
        val name = "kitegeo-$kind-${file.substringBeforeLast(".")}-$code"
        if (!providers.has(name)) {
            providers.add(name, JsonObject().apply {
                addProperty("type", "file")
                addProperty("behavior", "classical")
                addProperty("format", "text")
                // libkite generates the file from the .dat when the core starts.
                addProperty("path", "kitegeo:$kind:$file:$code")
            })
        }
        return name
    }

    // ---------------------------------------------------------------- dns etc.

    private fun buildSniffer(settings: KiteConfigSettings): JsonObject = JsonObject().apply {
        addProperty("enable", settings.sniffing || settings.fakeDns)
        addProperty("force-dns-mapping", true)
        addProperty("parse-pure-ip", true)
        addProperty("override-destination", !settings.routeOnly)
        add("sniff", JsonObject().apply {
            add("HTTP", JsonObject().apply { add("ports", jsonArray(listOf("80", "8080-8880"))) })
            add("TLS", JsonObject().apply { add("ports", jsonArray(listOf("443", "8443"))) })
            add("QUIC", JsonObject().apply { add("ports", jsonArray(listOf("443", "8443"))) })
        })
    }

    private fun buildHosts(settings: KiteConfigSettings): JsonObject {
        val hosts = JsonObject()
        KiteProfileSupport.builtinDnsHosts().forEach { (domain, addresses) -> hosts.add(domain, jsonArray(addresses)) }
        settings.dnsHosts.forEach { (domain, value) ->
            if (domain.isNotBlank() && value.isNotBlank() && !domain.contains(":")) {
                hosts.addProperty(domain, value)
            }
        }
        return hosts
    }

    internal fun dnsServer(raw: String): String? {
        val server = KiteRuleTranslator.parseDnsServer(raw) ?: return null
        val host = if (server.host.contains(":")) "[${server.host}]" else server.host
        val port = server.port?.let { ":$it" }.orEmpty()
        return when (server.type) {
            "local" -> "system"
            "udp" -> "$host$port"
            "tcp" -> "tcp://$host$port"
            "tls" -> "tls://$host$port"
            "quic" -> "quic://$host$port"
            "https" -> "https://$host$port${server.path}"
            "h3" -> "https://$host$port${server.path}#h3=true"
            else -> null
        }
    }

    private fun buildDns(settings: KiteConfigSettings): JsonObject {
        val remote = settings.remoteDns.mapNotNull { dnsServer(it) }.ifEmpty { listOf(dnsServer(AppConfig.DNS_PROXY)!!) }
        val domestic = settings.domesticDns.mapNotNull { dnsServer(it) }.ifEmpty { listOf(AppConfig.DNS_DIRECT) }
        // Plain IP servers resolve the host names of the DoH/DoT servers.
        val bootstrap = settings.domesticDns.mapNotNull { KiteRuleTranslator.parseDnsServer(it) }
            .filter { it.type == "udp" }
            .map { dnsServer(it.host)!! }
            .ifEmpty { listOf(AppConfig.DNS_DIRECT) }
        val dns = JsonObject()
        dns.addProperty("enable", true)
        dns.addProperty("ipv6", settings.ipv6)
        dns.addProperty("use-hosts", true)
        if (settings.fakeDns) {
            dns.addProperty("enhanced-mode", "fake-ip")
            dns.addProperty("fake-ip-range", "198.18.0.1/16")
            dns.add("fake-ip-filter", jsonArray(listOf("*.lan", "+.local", "+.msftconnecttest.com", "+.msftncsi.com", "time.*.com", "ntp.*.com")))
        } else {
            dns.addProperty("enhanced-mode", "redir-host")
        }
        dns.add("default-nameserver", jsonArray(bootstrap))
        dns.add("nameserver", jsonArray(remote))
        dns.add("proxy-server-nameserver", jsonArray(domestic))
        dns.add("direct-nameserver", jsonArray(domestic))
        // Queries to the remote servers go through the rules (and so the proxy).
        dns.addProperty("respect-rules", true)
        val directDomains = settings.rulesets
            .filter { it.enabled && it.outboundTag == AppConfig.TAG_DIRECT }
            .flatMap { it.domain.orEmpty() }
            .mapNotNull { policyKey(it) }
            .distinct()
        if (directDomains.isNotEmpty()) {
            dns.add("nameserver-policy", JsonObject().apply {
                add(directDomains.joinToString(","), jsonArray(domestic))
            })
        }
        return dns
    }

    /** A direct-rule domain as a nameserver-policy key. */
    private fun policyKey(raw: String): String? = when (val entry = KiteRuleTranslator.parseDomain(raw)) {
        is DomainEntry.Suffix -> "+.${entry.value}"
        is DomainEntry.Full -> entry.value
        is DomainEntry.Geo -> if (entry.file == AppConfig.GEOSITE_DAT) "geosite:${entry.code}" else null
        else -> null
    }
}
