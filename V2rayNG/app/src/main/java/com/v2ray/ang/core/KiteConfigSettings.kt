package com.v2ray.ang.core

import com.v2ray.ang.AppConfig
import com.v2ray.ang.dto.entities.RulesetItem
import com.v2ray.ang.handler.MmkvManager
import com.v2ray.ang.handler.SettingsManager

/**
 * Settings snapshot used by [MihomoConfigBuilder] and [SingboxConfigBuilder].
 *
 * The builders only read this value object, so their translation stays a pure function of the
 * resolved profiles and these settings (and can be unit-tested without MMKV). Xray keeps reading
 * the same preferences directly in [CoreConfigManager].
 */
data class KiteConfigSettings(
    val logLevel: String = "warning",
    val ipv6: Boolean = false,
    val preferIpv6: Boolean = false,
    val sniffing: Boolean = true,
    val routeOnly: Boolean = false,
    val fakeDns: Boolean = false,
    val remoteDns: List<String> = listOf(AppConfig.DNS_PROXY),
    val domesticDns: List<String> = listOf(AppConfig.DNS_DIRECT),
    val dnsHosts: Map<String, String> = emptyMap(),
    val domainStrategy: String = "AsIs",
    val delayTestUrl: String = AppConfig.DELAY_TEST_URL,
    val urlTestInterval: String = AppConfig.OBSERVATORY_LEAST_PING_INTERVAL,
    val rulesets: List<RulesetItem> = emptyList(),
) {
    companion object {
        /** Reads the current preferences. */
        fun fromPreferences(): KiteConfigSettings {
            val userHosts = MmkvManager.decodeSettingsString(AppConfig.PREF_DNS_HOSTS).orEmpty()
                .split(",")
                .filter { it.isNotBlank() && it.contains(":") }
                .associate {
                    // Split at the first colon only, IPv6 values contain more.
                    val parts = it.split(":", limit = 2)
                    parts[0].trim() to parts[1].trim()
                }
            return KiteConfigSettings(
                logLevel = MmkvManager.decodeSettingsString(AppConfig.PREF_LOGLEVEL) ?: "warning",
                ipv6 = MmkvManager.decodeSettingsBool(AppConfig.PREF_IPV6_ENABLED),
                preferIpv6 = MmkvManager.decodeSettingsBool(AppConfig.PREF_PREFER_IPV6),
                sniffing = MmkvManager.decodeSettingsBool(AppConfig.PREF_SNIFFING_ENABLED, true),
                routeOnly = MmkvManager.decodeSettingsBool(AppConfig.PREF_ROUTE_ONLY_ENABLED, false),
                fakeDns = MmkvManager.decodeSettingsBool(AppConfig.PREF_FAKE_DNS_ENABLED),
                remoteDns = SettingsManager.getRemoteDnsServers(),
                domesticDns = SettingsManager.getDomesticDnsServers(),
                dnsHosts = userHosts,
                domainStrategy = MmkvManager.decodeSettingsString(AppConfig.PREF_ROUTING_DOMAIN_STRATEGY) ?: "AsIs",
                delayTestUrl = SettingsManager.getDelayTestUrl(),
                urlTestInterval = MmkvManager.decodeSettingsString(AppConfig.PREF_OBSERVATORY_LEAST_PING_INTERVAL)
                    ?.trim()
                    ?.takeIf { AppConfig.OBSERVATORY_DURATION_PATTERN.matches(it) }
                    ?: AppConfig.OBSERVATORY_LEAST_PING_INTERVAL,
                rulesets = MmkvManager.decodeRoutingRulesets().orEmpty(),
            )
        }
    }
}
