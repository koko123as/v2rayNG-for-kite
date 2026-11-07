package com.v2ray.ang.core

import com.google.gson.JsonArray
import com.google.gson.JsonElement
import com.google.gson.JsonObject
import com.google.gson.JsonParser
import com.google.gson.JsonPrimitive
import com.v2ray.ang.enums.CoreType

/**
 * Recognizes a full native configuration on import: a mihomo (Clash) YAML, a sing-box JSON or an
 * Xray JSON. Pure Kotlin so the import path does not load the native library and is unit-tested;
 * libkite's DetectCoreConfig applies the same rules on the daemon side.
 */
object NativeConfigDetector {

    private const val BOM = '\uFEFF'

    private val mihomoTopLevel = Regex("""(?m)^(proxies|proxy-providers|proxy-groups)\s*:""")

    /** The core [content] is written for, or null when it is not a full configuration. */
    fun detect(content: String?): CoreType? {
        var text = stripBom(content).trim()
        if (text.isEmpty()) return null
        // JSONC may open with a comment before the root object.
        if (text.startsWith("//") || text.startsWith("/*")) text = removeComments(text).trim()
        if (text.startsWith("{")) {
            val root = parseJsonObject(text) ?: return null
            return detectJson(root)
        }
        if (text.startsWith("[")) {
            // A JSON array of Xray configurations (v2rayNG's own export).
            val array = runCatching { JsonParser.parseString(normalizeJson(text)) }.getOrNull() as? JsonArray ?: return null
            val first = array.firstOrNull() as? JsonObject ?: return null
            return detectJson(first)
        }
        return if (mihomoTopLevel.containsMatchIn(text)) CoreType.MIHOMO else null
    }

    /** [content] without a leading UTF-8 byte order mark, which files saved on Windows carry. */
    fun stripBom(content: String?): String = content.orEmpty().trimStart(BOM)

    /**
     * Parses a JSON object the way sing-box reads its configuration: `//` and `/* */` comments
     * and trailing commas are accepted. Null when [text] is not a JSON object.
     */
    fun parseJsonObject(text: String): JsonObject? =
        runCatching { JsonParser.parseString(normalizeJson(text)) }.getOrNull() as? JsonObject

    /**
     * Strict JSON for [text] written as JSONC: comments and trailing commas are removed, string
     * contents are kept as written.
     */
    fun normalizeJson(text: String): String = removeTrailingCommas(removeComments(stripBom(text)))

    private fun removeComments(src: String): String {
        val out = StringBuilder(src.length)
        var i = 0
        var inString = false
        while (i < src.length) {
            val c = src[i]
            if (inString) {
                out.append(c)
                if (c == '\\' && i + 1 < src.length) {
                    out.append(src[i + 1])
                    i += 2
                    continue
                }
                if (c == '"') inString = false
                i++
                continue
            }
            val next = if (i + 1 < src.length) src[i + 1] else ' '
            when {
                c == '"' -> {
                    inString = true
                    out.append(c)
                    i++
                }

                c == '/' && next == '/' -> {
                    val end = src.indexOf('\n', i)
                    i = if (end < 0) src.length else end
                }

                c == '/' && next == '*' -> {
                    val end = src.indexOf("*/", i + 2)
                    i = if (end < 0) src.length else end + 2
                    out.append(' ')
                }

                else -> {
                    out.append(c)
                    i++
                }
            }
        }
        return out.toString()
    }

    private fun removeTrailingCommas(src: String): String {
        val out = StringBuilder(src.length)
        var i = 0
        var inString = false
        while (i < src.length) {
            val c = src[i]
            if (inString) {
                out.append(c)
                if (c == '\\' && i + 1 < src.length) {
                    out.append(src[i + 1])
                    i += 2
                    continue
                }
                if (c == '"') inString = false
                i++
                continue
            }
            if (c == '"') {
                inString = true
            } else if (c == ',') {
                var j = i + 1
                while (j < src.length && src[j].isWhitespace()) j++
                if (j < src.length && (src[j] == '}' || src[j] == ']')) {
                    i++
                    continue
                }
            }
            out.append(c)
            i++
        }
        return out.toString()
    }

    private fun detectJson(root: JsonObject): CoreType? {
        // JSON is valid YAML: a mihomo configuration written as JSON.
        if (root.get("proxies").isArrayOf() || root.get("proxy-groups").isArrayOf()) return CoreType.MIHOMO
        val outbounds = (root.get("outbounds") as? JsonArray)?.mapNotNull { it as? JsonObject }.orEmpty()
        val inbounds = (root.get("inbounds") as? JsonArray)?.mapNotNull { it as? JsonObject }.orEmpty()
        // Xray items carry "protocol", sing-box items "type"; Xray is checked first because a
        // sing-box item never has "protocol".
        if (outbounds.any { it.has("protocol") } || inbounds.any { it.has("protocol") }) return CoreType.XRAY
        if (outbounds.any { it.has("type") } || inbounds.any { it.has("type") }) return CoreType.SING_BOX
        if (root.get("endpoints").isArrayOf()) return CoreType.SING_BOX
        val schema = (root.get("\$schema") as? JsonPrimitive)?.takeIf { it.isString }?.asString.orEmpty()
        if (schema.contains("sing-box", ignoreCase = true)) return CoreType.SING_BOX
        if (root.has("routing")) return CoreType.XRAY
        if (root.has("route") || root.has("endpoints")) return CoreType.SING_BOX
        // sing-box 1.12+ DNS servers are objects with "type"; Xray's are strings or "address" objects.
        val dnsServers = ((root.get("dns") as? JsonObject)?.get("servers") as? JsonArray)?.mapNotNull { it as? JsonObject }.orEmpty()
        if (dnsServers.any { it.has("type") }) return CoreType.SING_BOX
        return null
    }

    private fun JsonElement?.isArrayOf(): Boolean = this is JsonArray && this.size() > 0
}
