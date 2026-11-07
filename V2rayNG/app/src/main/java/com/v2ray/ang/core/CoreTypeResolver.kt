package com.v2ray.ang.core

import com.v2ray.ang.AppConfig
import com.v2ray.ang.R
import com.v2ray.ang.dto.entities.ProfileItem
import com.v2ray.ang.enums.CoreType
import com.v2ray.ang.enums.EConfigType
import com.v2ray.ang.enums.NetworkType
import com.v2ray.ang.handler.MmkvManager

/**
 * Decides which core runs a profile and which of the profile's Xray-only features another core
 * cannot run.
 */
object CoreTypeResolver {

    /** Features that only Xray implements. [messageRes] names the feature for the user. */
    enum class XrayOnlyFeature(val messageRes: Int) {
        XHTTP(R.string.core_feature_xhttp),
        XHTTP_EXTRA(R.string.core_feature_xhttp_extra),
        MKCP(R.string.core_feature_mkcp),
        FINAL_MASK(R.string.core_feature_final_mask),
        BROWSER_DIALER(R.string.core_feature_browser_dialer),
        TCP_HTTP_HEADER(R.string.core_feature_tcp_http_header),
        MLDSA65(R.string.core_feature_mldsa65),
        VLESS_ENCRYPTION(R.string.core_feature_vless_encryption),
        FRAGMENT(R.string.core_feature_fragment),
        MUX(R.string.core_feature_mux),
    }

    /** The global default core, Xray unless the user picked another one. */
    fun globalDefault(): CoreType =
        CoreType.fromValue(MmkvManager.decodeSettingsString(AppConfig.PREF_CORE_TYPE)) ?: CoreType.XRAY

    /** The core that runs [profile]. */
    fun resolve(profile: ProfileItem, default: CoreType = globalDefault()): CoreType =
        resolve(profile.configType, profile.coreType, default)

    /**
     * A native configuration (CUSTOM) always runs on the core it was written for, Xray for the
     * existing Xray JSON configurations. Any other profile uses its override or the default.
     */
    internal fun resolve(configType: EConfigType, coreType: String?, default: CoreType): CoreType {
        val own = CoreType.fromValue(coreType)
        if (configType == EConfigType.CUSTOM) return own ?: CoreType.XRAY
        return own ?: default
    }

    /** The core of the selected profile, null when none is selected or it cannot be read. */
    fun resolveSelected(): CoreType? {
        val guid = MmkvManager.getSelectServer() ?: return null
        val profile = MmkvManager.decodeServerConfig(guid) ?: return null
        return resolve(profile)
    }

    /**
     * Xray-only features [profile] uses that [core] cannot run. Empty for Xray and for native
     * configurations, which are written for their core.
     */
    fun unsupportedFeatures(profile: ProfileItem, core: CoreType): List<XrayOnlyFeature> {
        if (core == CoreType.XRAY || profile.configType == EConfigType.CUSTOM) return emptyList()
        if (profile.configType == EConfigType.POLICYGROUP || profile.configType == EConfigType.PROXYCHAIN) return emptyList()
        val result = mutableListOf<XrayOnlyFeature>()
        val network = profile.network.orEmpty().ifEmpty { NetworkType.TCP.type }
        val streamProtocol = profile.configType in setOf(EConfigType.VMESS, EConfigType.VLESS, EConfigType.TROJAN, EConfigType.SHADOWSOCKS)
        if (streamProtocol) {
            when (network) {
                NetworkType.XHTTP.type -> {
                    // mihomo implements XHTTP for VLESS only, sing-box not at all.
                    if (core == CoreType.SING_BOX || profile.configType != EConfigType.VLESS) {
                        result.add(XrayOnlyFeature.XHTTP)
                    } else if (!profile.xhttpExtra.isNullOrBlank()) {
                        result.add(XrayOnlyFeature.XHTTP_EXTRA)
                    }
                }
                NetworkType.KCP.type -> result.add(XrayOnlyFeature.MKCP)
                NetworkType.TCP.type -> if (profile.headerType == AppConfig.HEADER_TYPE_HTTP) {
                    // mihomo has the HTTP obfuscation for VMess/VLESS (http-opts) and SS (obfs).
                    val mihomoOk = core == CoreType.MIHOMO && profile.configType != EConfigType.TROJAN
                    val singBoxOk = core == CoreType.SING_BOX && profile.configType == EConfigType.SHADOWSOCKS
                    if (!mihomoOk && !singBoxOk) result.add(XrayOnlyFeature.TCP_HTTP_HEADER)
                }
            }
        }
        if (!profile.finalMask.isNullOrBlank()) result.add(XrayOnlyFeature.FINAL_MASK)
        if (!profile.browserDialerMode.isNullOrBlank()) result.add(XrayOnlyFeature.BROWSER_DIALER)
        if (!profile.mldsa65Verify.isNullOrBlank()) result.add(XrayOnlyFeature.MLDSA65)
        if (profile.configType == EConfigType.VLESS && core == CoreType.SING_BOX) {
            val encryption = profile.method.orEmpty()
            if (encryption.isNotEmpty() && encryption != "none") result.add(XrayOnlyFeature.VLESS_ENCRYPTION)
        }
        return result
    }

    /**
     * Global Xray-only settings that are ignored on [core]: they do not stop a profile from
     * running, the user is told they have no effect.
     */
    fun ignoredGlobalFeatures(core: CoreType, fragmentEnabled: Boolean, muxEnabled: Boolean): List<XrayOnlyFeature> {
        if (core == CoreType.XRAY) return emptyList()
        return buildList {
            if (fragmentEnabled) add(XrayOnlyFeature.FRAGMENT)
            if (muxEnabled) add(XrayOnlyFeature.MUX)
        }
    }
}
