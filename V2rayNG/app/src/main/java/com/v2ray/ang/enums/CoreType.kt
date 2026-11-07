package com.v2ray.ang.enums

/**
 * Native core that runs a profile. [value] is persisted in [com.v2ray.ang.dto.entities.ProfileItem.coreType]
 * and the global default setting, and matches the core names of libv2ray (libkite).
 */
enum class CoreType(val value: String, val displayName: String) {
    XRAY("xray", "Xray"),
    MIHOMO("mihomo", "mihomo"),
    SING_BOX("sing-box", "sing-box");

    companion object {
        /** Returns the core for a persisted value, or null for an empty or unknown value. */
        fun fromValue(value: String?): CoreType? = entries.firstOrNull { it.value == value }
    }
}
