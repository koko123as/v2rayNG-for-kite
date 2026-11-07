package com.v2ray.ang.core

import com.v2ray.ang.AppConfig
import com.v2ray.ang.core.CoreTypeResolver.XrayOnlyFeature
import com.v2ray.ang.dto.entities.ProfileItem
import com.v2ray.ang.enums.CoreType
import com.v2ray.ang.enums.EConfigType
import com.v2ray.ang.enums.NetworkType
import com.v2ray.ang.util.JsonUtil
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class CoreTypeResolverTest {

    private fun vless(network: String = NetworkType.TCP.type) = ProfileItem.create(EConfigType.VLESS).apply {
        server = "example.com"
        serverPort = "443"
        password = "uuid"
        this.network = network
    }

    @Test
    fun `profile override wins over the global default`() {
        assertEquals(CoreType.SING_BOX, CoreTypeResolver.resolve(EConfigType.VLESS, "sing-box", CoreType.MIHOMO))
        assertEquals(CoreType.MIHOMO, CoreTypeResolver.resolve(EConfigType.VLESS, null, CoreType.MIHOMO))
        assertEquals(CoreType.XRAY, CoreTypeResolver.resolve(EConfigType.VLESS, "unknown", CoreType.XRAY))
    }

    @Test
    fun `native configurations run on the core they were written for`() {
        // Existing custom configurations are Xray JSON and keep running on Xray.
        assertEquals(CoreType.XRAY, CoreTypeResolver.resolve(EConfigType.CUSTOM, null, CoreType.MIHOMO))
        assertEquals(CoreType.MIHOMO, CoreTypeResolver.resolve(EConfigType.CUSTOM, "mihomo", CoreType.SING_BOX))
    }

    @Test
    fun `profiles saved before multicore read without a core`() {
        val legacy = """{"configType":"VLESS","subscriptionId":"","remarks":"old","server":"a.com","serverPort":"443"}"""
        val profile = JsonUtil.fromJson(legacy, ProfileItem::class.java)!!

        assertNull(profile.coreType)
        assertEquals(CoreType.XRAY, CoreTypeResolver.resolve(profile, CoreType.XRAY))
    }

    @Test
    fun `xhttp is VLESS only on mihomo and unsupported on sing-box`() {
        assertEquals(emptyList<XrayOnlyFeature>(), CoreTypeResolver.unsupportedFeatures(vless(NetworkType.XHTTP.type), CoreType.MIHOMO))
        assertEquals(listOf(XrayOnlyFeature.XHTTP), CoreTypeResolver.unsupportedFeatures(vless(NetworkType.XHTTP.type), CoreType.SING_BOX))
        val vmess = vless(NetworkType.XHTTP.type).copy(configType = EConfigType.VMESS)
        assertEquals(listOf(XrayOnlyFeature.XHTTP), CoreTypeResolver.unsupportedFeatures(vmess, CoreType.MIHOMO))
        val extra = vless(NetworkType.XHTTP.type).apply { xhttpExtra = """{"xmux":{}}""" }
        assertEquals(listOf(XrayOnlyFeature.XHTTP_EXTRA), CoreTypeResolver.unsupportedFeatures(extra, CoreType.MIHOMO))
    }

    @Test
    fun `Xray-only options are reported for other cores only`() {
        val profile = vless(NetworkType.KCP.type).apply {
            finalMask = "{}"
            browserDialerMode = "webview"
            mldsa65Verify = "abc"
        }
        val features = CoreTypeResolver.unsupportedFeatures(profile, CoreType.MIHOMO)

        assertTrue(features.containsAll(listOf(XrayOnlyFeature.MKCP, XrayOnlyFeature.FINAL_MASK, XrayOnlyFeature.BROWSER_DIALER, XrayOnlyFeature.MLDSA65)))
        assertEquals(emptyList<XrayOnlyFeature>(), CoreTypeResolver.unsupportedFeatures(profile, CoreType.XRAY))
    }

    @Test
    fun `TCP HTTP header depends on core and protocol`() {
        val trojan = ProfileItem.create(EConfigType.TROJAN).apply { headerType = AppConfig.HEADER_TYPE_HTTP; network = "tcp" }
        val vmess = ProfileItem.create(EConfigType.VMESS).apply { headerType = AppConfig.HEADER_TYPE_HTTP; network = "tcp" }
        val ss = ProfileItem.create(EConfigType.SHADOWSOCKS).apply { headerType = AppConfig.HEADER_TYPE_HTTP; network = "tcp" }

        assertEquals(listOf(XrayOnlyFeature.TCP_HTTP_HEADER), CoreTypeResolver.unsupportedFeatures(trojan, CoreType.MIHOMO))
        assertEquals(emptyList<XrayOnlyFeature>(), CoreTypeResolver.unsupportedFeatures(vmess, CoreType.MIHOMO))
        assertEquals(listOf(XrayOnlyFeature.TCP_HTTP_HEADER), CoreTypeResolver.unsupportedFeatures(vmess, CoreType.SING_BOX))
        assertEquals(emptyList<XrayOnlyFeature>(), CoreTypeResolver.unsupportedFeatures(ss, CoreType.SING_BOX))
    }

    @Test
    fun `VLESS encryption is unsupported on sing-box`() {
        val profile = vless().apply { method = "mlkem768x25519plus.native.0rtt.abc" }

        assertEquals(listOf(XrayOnlyFeature.VLESS_ENCRYPTION), CoreTypeResolver.unsupportedFeatures(profile, CoreType.SING_BOX))
        assertEquals(emptyList<XrayOnlyFeature>(), CoreTypeResolver.unsupportedFeatures(vless().apply { method = "none" }, CoreType.SING_BOX))
    }

    @Test
    fun `global fragment and mux are ignored outside Xray`() {
        assertEquals(listOf(XrayOnlyFeature.FRAGMENT, XrayOnlyFeature.MUX), CoreTypeResolver.ignoredGlobalFeatures(CoreType.SING_BOX, true, true))
        assertEquals(emptyList<XrayOnlyFeature>(), CoreTypeResolver.ignoredGlobalFeatures(CoreType.XRAY, true, true))
    }
}
