package com.v2ray.ang.core

import com.google.gson.JsonArray
import com.google.gson.JsonElement
import com.google.gson.JsonObject
import com.google.gson.JsonParser
import com.v2ray.ang.enums.CoreType

/**
 * Recognizes a full native configuration on import: a mihomo (Clash) YAML, a sing-box JSON or an
 * Xray JSON. Pure Kotlin so the import path does not load the native library and is unit-tested;
 * libkite's DetectCoreConfig applies the same rules on the daemon side.
 */
object NativeConfigDetector {

    private val mihomoTopLevel = Regex("""(?m)^(proxies|proxy-providers|proxy-groups)\s*:""")

    /** The core [content] is written for, or null when it is not a full configuration. */
    fun detect(content: String?): CoreType? {
        val text = content?.trim().orEmpty()
        if (text.isEmpty()) return null
        if (text.startsWith("{")) {
            val root = parseObject(text) ?: return null
            return detectJson(root)
        }
        if (text.startsWith("[")) {
            // A JSON array of Xray configurations (v2rayNG's own export).
            val array = runCatching { JsonParser.parseString(text) }.getOrNull() as? JsonArray ?: return null
            val first = array.firstOrNull() as? JsonObject ?: return null
            return detectJson(first)
        }
        return if (mihomoTopLevel.containsMatchIn(text)) CoreType.MIHOMO else null
    }

    private fun parseObject(text: String): JsonObject? =
        runCatching { JsonParser.parseString(text) }.getOrNull() as? JsonObject

    private fun detectJson(root: JsonObject): CoreType? {
        // JSON is valid YAML: a mihomo configuration written as JSON.
        if (root.get("proxies").isArrayOf() || root.get("proxy-groups").isArrayOf()) return CoreType.MIHOMO
        val outbounds = root.get("outbounds") as? JsonArray
        if (outbounds != null) {
            val objects = outbounds.mapNotNull { it as? JsonObject }
            if (objects.any { it.has("protocol") }) return CoreType.XRAY
            if (objects.any { it.has("type") }) return CoreType.SING_BOX
        }
        if (root.has("routing")) return CoreType.XRAY
        if (root.has("route") || root.has("endpoints")) return CoreType.SING_BOX
        return null
    }

    private fun JsonElement?.isArrayOf(): Boolean = this is JsonArray && this.size() > 0
}
