package com.v2ray.ang.core

import com.google.gson.JsonArray
import com.google.gson.JsonObject
import com.v2ray.ang.AppConfig
import com.v2ray.ang.core.KiteProfileSupport.jsonArray
import com.v2ray.ang.core.KiteRuleTranslator.DomainEntry
import com.v2ray.ang.core.KiteRuleTranslator.IpEntry
import com.v2ray.ang.dto.entities.RulesetItem
import com.v2ray.ang.util.Utils

/**
 * Routing and DNS of a sing-box configuration built by [SingboxConfigBuilder].
 *
 * - v2rayNG routing rules become route rules; geosite/geoip codes become local rule-sets
 *   generated from the app's .dat files (libkite `kitegeo:` references, sing-box 1.14 has no
 *   geosite database); geoip:private is `ip_is_private`. Unmatched traffic goes to "proxy".
 * - Domain strategy IPIfNonMatch / IPOnDemand resolves the destination before the first IP rule.
 * - DNS: remote servers through the proxy by default, the first plain domestic server for direct
 *   domains and for resolving server addresses, built-in DoH hosts, optional fake-ip.
 */
object SingboxRoutingBuilder {

    private const val PROXY = SingboxConfigBuilder.PROXY
    private const val DIRECT = SingboxConfigBuilder.DIRECT
    private const val DNS_REMOTE = "dns-remote"
    private const val DNS_LOCAL = "dns-local"
    private const val DNS_FAKEIP = "dns-fakeip"
    private const val DNS_HOSTS = "dns-hosts"

    private class RoutingState(val settings: KiteConfigSettings, val tags: Set<String>) {
        val ruleSets = linkedMapOf<String, JsonObject>()
    }

    fun apply(root: JsonObject, route: JsonObject, tags: Set<String>, settings: KiteConfigSettings, forSpeedtest: Boolean) {
        val state = RoutingState(settings, tags)
        route.add("default_domain_resolver", JsonObject().apply { addProperty("server", DNS_LOCAL) })
        if (!forSpeedtest) {
            val rules = JsonArray()
            var resolveInserted = settings.domainStrategy == "AsIs"
            settings.rulesets.filter { it.enabled }.forEach { rule ->
                // IPIfNonMatch / IPOnDemand: resolve the destination before the first IP rule.
                if (!resolveInserted && !rule.ip.isNullOrEmpty()) {
                    rules.add(JsonObject().apply {
                        addProperty("action", "resolve")
                        if (!settings.ipv6) addProperty("strategy", "ipv4_only")
                    })
                    resolveInserted = true
                }
                translateRule(rule, state)?.let { rules.add(it) }
            }
            route.add("rules", rules)
        }
        root.add("dns", buildDns(state, forSpeedtest))
        if (state.ruleSets.isNotEmpty()) {
            route.add("rule_set", JsonArray().apply { state.ruleSets.values.forEach { add(it) } })
        }
    }

    private fun ruleSetTag(state: RoutingState, kind: String, file: String, code: String): String {
        val tag = when {
            kind == "site" && file == AppConfig.GEOSITE_DAT -> "geosite-$code"
            kind == "ip" && file == AppConfig.GEOIP_DAT -> "geoip-$code"
            else -> "ext-$kind-${file.substringBeforeLast(".")}-$code"
        }
        state.ruleSets.getOrPut(tag) {
            JsonObject().apply {
                addProperty("type", "local")
                addProperty("tag", tag)
                addProperty("format", "binary")
                // libkite generates the .srs from the .dat file when the core starts.
                addProperty("path", "kitegeo:$kind:$file:$code")
            }
        }
        return tag
    }

    private fun routeAction(rule: RulesetItem, state: RoutingState): JsonObject = JsonObject().apply {
        when (rule.outboundTag) {
            AppConfig.TAG_BLOCKED -> addProperty("action", "reject")
            AppConfig.TAG_DIRECT -> {
                addProperty("action", "route")
                addProperty("outbound", DIRECT)
            }

            else -> {
                addProperty("action", "route")
                addProperty("outbound", rule.outboundTag.takeIf { it in state.tags } ?: PROXY)
            }
        }
    }

    /**
     * One v2rayNG rule as a sing-box rule. sing-box ORs domain and IP matchers of one rule, Xray
     * ANDs them, so a rule with both (or with a negated IP) becomes a logical "and" rule.
     */
    private fun translateRule(rule: RulesetItem, state: RoutingState): JsonObject? {
        val domainPart = JsonObject()
        rule.domain?.forEach { raw ->
            when (val entry = KiteRuleTranslator.parseDomain(raw)) {
                is DomainEntry.Suffix -> appendTo(domainPart, "domain_suffix", entry.value)
                is DomainEntry.Full -> appendTo(domainPart, "domain", entry.value)
                is DomainEntry.Keyword -> appendTo(domainPart, "domain_keyword", entry.value)
                is DomainEntry.Regex -> appendTo(domainPart, "domain_regex", entry.value)
                is DomainEntry.Geo -> appendTo(domainPart, "rule_set", ruleSetTag(state, "site", entry.file, entry.code))
                null -> Unit
            }
        }
        val ipPart = JsonObject()
        val negatedIp = mutableListOf<JsonObject>()
        rule.ip?.forEach { raw ->
            val entry = KiteRuleTranslator.parseIp(raw) ?: return@forEach
            val target = if (entry.negate) JsonObject().also { negatedIp.add(it) } else ipPart
            when (entry) {
                is IpEntry.Cidr -> appendTo(target, "ip_cidr", entry.value)
                is IpEntry.Private -> target.addProperty("ip_is_private", true)
                is IpEntry.Geo -> appendTo(target, "rule_set", ruleSetTag(state, "ip", entry.file, entry.code))
            }
            if (entry.negate) target.addProperty("invert", true)
        }
        val common = JsonObject()
        val ports = KiteRuleTranslator.parsePorts(rule.port)
        ports.filter { !it.isRange }.forEach { appendInt(common, "port", it.start) }
        ports.filter { it.isRange }.forEach { appendTo(common, "port_range", "${it.start}:${it.end}") }
        KiteRuleTranslator.parseNetworks(rule.network).forEach { appendTo(common, "network", it) }
        rule.protocol?.filter { it.isNotBlank() }?.forEach { appendTo(common, "protocol", it.lowercase()) }
        rule.process?.filter { it.isNotBlank() }?.forEach { appendTo(common, "package_name", it) }

        val hasDomain = domainPart.size() > 0
        val hasIp = ipPart.size() > 0
        if (!hasDomain && !hasIp && negatedIp.isEmpty() && common.size() == 0) {
            return null
        }
        val action = routeAction(rule, state)
        val parts = mutableListOf<JsonObject>()
        if (hasDomain) parts.add(domainPart)
        if (hasIp) parts.add(ipPart)
        parts.addAll(negatedIp)
        if (parts.size <= 1) {
            val single = parts.firstOrNull() ?: JsonObject()
            common.entrySet().forEach { (key, value) -> single.add(key, value) }
            action.entrySet().forEach { (key, value) -> single.add(key, value) }
            return single
        }
        if (common.size() > 0) parts.add(common)
        return JsonObject().apply {
            addProperty("type", "logical")
            addProperty("mode", "and")
            add("rules", JsonArray().apply { parts.forEach { add(it) } })
            action.entrySet().forEach { (key, value) -> add(key, value) }
        }
    }

    private fun appendTo(target: JsonObject, key: String, value: String) {
        val array = target.getAsJsonArray(key) ?: JsonArray().also { target.add(key, it) }
        if (array.none { it.asString == value }) array.add(value)
    }

    private fun appendInt(target: JsonObject, key: String, value: Int) {
        val array = target.getAsJsonArray(key) ?: JsonArray().also { target.add(key, it) }
        array.add(value)
    }

    // ---------------------------------------------------------------------- dns

    internal fun dnsServer(raw: String, tag: String, detour: String?): JsonObject? {
        val server = KiteRuleTranslator.parseDnsServer(raw) ?: return null
        return JsonObject().apply {
            addProperty("tag", tag)
            when (server.type) {
                "local" -> addProperty("type", "local")
                else -> {
                    addProperty("type", server.type)
                    addProperty("server", server.host)
                    server.port?.let { addProperty("server_port", it) }
                    if (server.type == "https" || server.type == "h3") addProperty("path", server.path ?: "/dns-query")
                    // A DoH/DoT host name is resolved by the plain domestic server.
                    if (!Utils.isPureIpAddress(server.host) && tag != DNS_LOCAL) {
                        addProperty("domain_resolver", DNS_LOCAL)
                    }
                    detour?.let { addProperty("detour", it) }
                }
            }
        }
    }

    private fun buildDns(state: RoutingState, forSpeedtest: Boolean): JsonObject {
        val settings = state.settings
        val servers = JsonArray()
        val remote = settings.remoteDns.firstNotNullOfOrNull { dnsServer(it, DNS_REMOTE, PROXY) }
            ?: dnsServer(AppConfig.DNS_PROXY, DNS_REMOTE, PROXY)!!
        // The local server must not need another resolver: take the first plain IP one.
        val local = settings.domesticDns
            .mapNotNull { KiteRuleTranslator.parseDnsServer(it) }
            .firstOrNull { it.type == "udp" || Utils.isPureIpAddress(it.host) }
            ?.let { server ->
                JsonObject().apply {
                    addProperty("tag", DNS_LOCAL)
                    addProperty("type", server.type.takeIf { it != "local" && it != "https" && it != "h3" } ?: "udp")
                    addProperty("server", server.host.ifEmpty { AppConfig.DNS_DIRECT })
                    server.port?.let { addProperty("server_port", it) }
                }
            }
            ?: dnsServer(AppConfig.DNS_DIRECT, DNS_LOCAL, null)!!
        servers.add(remote)
        servers.add(local)
        val rules = JsonArray()
        val hosts = JsonObject()
        KiteProfileSupport.builtinDnsHosts().forEach { (domain, addresses) -> hosts.add(domain, jsonArray(addresses)) }
        settings.dnsHosts.forEach { (domain, value) ->
            if (domain.isNotBlank() && !domain.contains(":") && Utils.isPureIpAddress(value)) {
                hosts.add(domain, jsonArray(listOf(value)))
            }
        }
        servers.add(JsonObject().apply {
            addProperty("type", "hosts")
            addProperty("tag", DNS_HOSTS)
            add("predefined", hosts)
        })
        rules.add(JsonObject().apply {
            add("domain", jsonArray(hosts.keySet()))
            addProperty("server", DNS_HOSTS)
        })
        if (!forSpeedtest) {
            val directDomains = JsonObject()
            settings.rulesets.filter { it.enabled && it.outboundTag == AppConfig.TAG_DIRECT }.forEach { rule ->
                rule.domain?.forEach { raw ->
                    when (val entry = KiteRuleTranslator.parseDomain(raw)) {
                        is DomainEntry.Suffix -> appendTo(directDomains, "domain_suffix", entry.value)
                        is DomainEntry.Full -> appendTo(directDomains, "domain", entry.value)
                        is DomainEntry.Keyword -> appendTo(directDomains, "domain_keyword", entry.value)
                        is DomainEntry.Regex -> appendTo(directDomains, "domain_regex", entry.value)
                        is DomainEntry.Geo -> appendTo(directDomains, "rule_set", ruleSetTag(state, "site", entry.file, entry.code))
                        null -> Unit
                    }
                }
            }
            if (directDomains.size() > 0) {
                directDomains.addProperty("server", DNS_LOCAL)
                rules.add(directDomains)
            }
            if (settings.fakeDns) {
                servers.add(JsonObject().apply {
                    addProperty("type", "fakeip")
                    addProperty("tag", DNS_FAKEIP)
                    addProperty("inet4_range", "198.18.0.0/15")
                    if (settings.ipv6) addProperty("inet6_range", "fc00::/18")
                })
                rules.add(JsonObject().apply {
                    add("query_type", jsonArray(listOf("A", "AAAA")))
                    addProperty("server", DNS_FAKEIP)
                })
            }
        }
        return JsonObject().apply {
            add("servers", servers)
            add("rules", rules)
            addProperty("final", DNS_REMOTE)
            addProperty("strategy", if (!settings.ipv6) "ipv4_only" else if (settings.preferIpv6) "prefer_ipv6" else "prefer_ipv4")
        }
    }
}
