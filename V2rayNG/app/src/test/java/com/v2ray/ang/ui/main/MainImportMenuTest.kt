package com.v2ray.ang.ui.main

import com.v2ray.ang.dto.entities.ProfileItem
import com.v2ray.ang.enums.EConfigType
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test

class MainImportMenuTest {

    @Test
    fun regularShareMenuContainsOnlyShareActions() {
        val expected = listOf(
            ServerMenuAction.ShareQRCode,
            ServerMenuAction.ShareClipboard,
            ServerMenuAction.ShareFullContent,
        )
        assertEquals(expected, serverMenuActions(isComplexProfile = false, includeManagementActions = false))
    }

    @Test
    fun regularMoreMenuContainsEveryActionInDisplayOrder() {
        assertEquals(
            ServerMenuAction.entries,
            serverMenuActions(isComplexProfile = false, includeManagementActions = true, supportsCoreSelection = true),
        )
    }

    @Test
    fun complexShareMenuContainsOnlyFullContent() {
        assertEquals(
            listOf(ServerMenuAction.ShareFullContent),
            serverMenuActions(isComplexProfile = true, includeManagementActions = false),
        )
    }

    @Test
    fun complexMoreMenuRetainsManagementActions() {
        val expected = listOf(
            ServerMenuAction.ShareFullContent,
            ServerMenuAction.Edit,
            ServerMenuAction.Delete,
        )
        assertEquals(expected, serverMenuActions(isComplexProfile = true, includeManagementActions = true))
    }

    @Test
    fun coreSelectionIsHiddenUnlessSupported() {
        assertEquals(
            false,
            serverMenuActions(isComplexProfile = false, includeManagementActions = true).contains(ServerMenuAction.SelectCore),
        )
    }

    @Test
    fun coreSelectionIsInTheShareMenuOfRegularAndComplexProfiles() {
        assertEquals(
            listOf(
                ServerMenuAction.ShareQRCode,
                ServerMenuAction.ShareClipboard,
                ServerMenuAction.ShareFullContent,
                ServerMenuAction.SelectCore,
            ),
            serverMenuActions(isComplexProfile = false, includeManagementActions = false, supportsCoreSelection = true),
        )
        assertEquals(
            listOf(ServerMenuAction.ShareFullContent, ServerMenuAction.SelectCore),
            serverMenuActions(isComplexProfile = true, includeManagementActions = false, supportsCoreSelection = true),
        )
    }

    @Test
    fun nativeConfigurationsCannotPickACore() {
        assertEquals(false, supportsCoreSelection(ProfileItem.create(EConfigType.CUSTOM)))
        assertEquals(true, supportsCoreSelection(ProfileItem.create(EConfigType.VLESS)))
        assertEquals(true, supportsCoreSelection(ProfileItem.create(EConfigType.POLICYGROUP)))
    }
}
