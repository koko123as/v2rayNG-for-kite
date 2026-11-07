package com.v2ray.ang.ui.server

import com.v2ray.ang.dto.entities.ProfileItem
import com.v2ray.ang.enums.CoreType
import com.v2ray.ang.enums.EConfigType
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Test

class ServerUiStateCoreTest {
    @Test
    fun newProfileFollowsTheDefaultCore() {
        val state = ServerUiState.fromProfileItem(ProfileItem.create(EConfigType.VLESS))

        assertEquals("", state.coreType)
        assertNull(state.toProfileItem(ProfileItem.create(EConfigType.VLESS)).coreType)
    }

    @Test
    fun chosenCoreIsSaved() {
        val initial = ProfileItem.create(EConfigType.VLESS)
        val state = ServerUiState.fromProfileItem(initial)

        state.coreType = CoreType.SING_BOX.value

        assertEquals(CoreType.SING_BOX.value, state.toProfileItem(initial).coreType)
    }

    @Test
    fun existingCoreIsLoadedAndCanBeReset() {
        val initial = ProfileItem.create(EConfigType.TROJAN).apply { coreType = CoreType.MIHOMO.value }
        val state = ServerUiState.fromProfileItem(initial)

        assertEquals(CoreType.MIHOMO.value, state.coreType)

        state.coreType = ""

        assertNull(state.toProfileItem(initial).coreType)
    }
}
