package com.v2ray.ang.ui.main

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class MainCoreGroupsTest {

    @Test
    fun parsesLibkiteGroups() {
        val json = """[
            {"name":"PROXY","type":"Selector","now":"a","selectable":true,"all":["a","b"]},
            {"name":"auto","type":"URLTest","now":"b","selectable":false,"all":["a","b"]}
        ]"""
        assertEquals(
            listOf(
                CoreGroupItem("PROXY", "Selector", "a", selectable = true, members = listOf("a", "b")),
                CoreGroupItem("auto", "URLTest", "b", selectable = false, members = listOf("a", "b")),
            ),
            parseCoreGroups(json),
        )
    }

    @Test
    fun emptyOrInvalidPayloadHasNoGroups() {
        assertTrue(parseCoreGroups("[]").isEmpty())
        assertTrue(parseCoreGroups("").isEmpty())
        assertTrue(parseCoreGroups(null).isEmpty())
        assertTrue(parseCoreGroups("{\"name\":\"x\"}").isEmpty())
    }

    @Test
    fun groupsWithoutNameAreDropped() {
        assertEquals(
            listOf(CoreGroupItem("g", "", "", selectable = false, members = emptyList())),
            parseCoreGroups("""[{"type":"Selector"},{"name":"g"}]"""),
        )
    }
}
