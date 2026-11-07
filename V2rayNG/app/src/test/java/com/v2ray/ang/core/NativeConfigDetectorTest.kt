package com.v2ray.ang.core

import com.v2ray.ang.enums.CoreType
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Test

class NativeConfigDetectorTest {

    @Test
    fun clashYamlIsMihomo() {
        val yaml = """
            mixed-port: 7890
            proxies:
              - name: a
                type: ss
                server: 1.2.3.4
                port: 443
            proxy-groups:
              - name: PROXY
                type: select
                proxies: [a]
            rules:
              - MATCH,PROXY
        """.trimIndent()
        assertEquals(CoreType.MIHOMO, NativeConfigDetector.detect(yaml))
    }

    @Test
    fun providerOnlyYamlIsMihomo() {
        assertEquals(CoreType.MIHOMO, NativeConfigDetector.detect("proxy-providers:\n  sub:\n    type: http\n"))
    }

    @Test
    fun singBoxJson() {
        val json = """{"outbounds":[{"type":"vless","tag":"proxy","server":"1.2.3.4","server_port":443},{"type":"direct","tag":"direct"}],"route":{"final":"proxy"}}"""
        assertEquals(CoreType.SING_BOX, NativeConfigDetector.detect(json))
    }

    @Test
    fun singBoxEndpointOnlyJson() {
        assertEquals(CoreType.SING_BOX, NativeConfigDetector.detect("""{"endpoints":[{"type":"wireguard","tag":"wg"}]}"""))
    }

    @Test
    fun xrayJsonAndArray() {
        val xray = """{"inbounds":[],"outbounds":[{"protocol":"vless","tag":"proxy"}],"routing":{"rules":[]}}"""
        assertEquals(CoreType.XRAY, NativeConfigDetector.detect(xray))
        assertEquals(CoreType.XRAY, NativeConfigDetector.detect("[$xray]"))
    }

    @Test
    fun mihomoWrittenAsJson() {
        assertEquals(CoreType.MIHOMO, NativeConfigDetector.detect("""{"proxies":[{"name":"a","type":"ss"}]}"""))
    }

    @Test
    fun shareLinksAndGarbageAreNotConfigurations() {
        assertNull(NativeConfigDetector.detect("vless://uuid@1.2.3.4:443#a\ntrojan://pw@5.6.7.8:443#b"))
        assertNull(NativeConfigDetector.detect(""))
        assertNull(NativeConfigDetector.detect(null))
        assertNull(NativeConfigDetector.detect("{not json"))
        assertNull(NativeConfigDetector.detect("""{"log":{"level":"info"}}"""))
    }
}
