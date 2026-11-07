package com.v2ray.ang.ui.main

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.selection.selectable
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.unit.dp
import com.google.gson.JsonArray
import com.google.gson.JsonObject
import com.google.gson.JsonParser
import com.v2ray.ang.R

/** One policy group of the running mihomo / sing-box, as libkite's GetKiteGroups reports it. */
data class CoreGroupItem(
    val name: String,
    val type: String,
    val now: String,
    val selectable: Boolean,
    val members: List<String>,
)

/** Parses libkite's group JSON; an unreadable payload is an empty list. */
internal fun parseCoreGroups(json: String?): List<CoreGroupItem> {
    val array = runCatching { JsonParser.parseString(json.orEmpty()) }.getOrNull() as? JsonArray ?: return emptyList()
    return array.mapNotNull { element ->
        val group = element as? JsonObject ?: return@mapNotNull null
        val name = group.get("name")?.takeIf { it.isJsonPrimitive }?.asString?.takeIf { it.isNotEmpty() }
            ?: return@mapNotNull null
        CoreGroupItem(
            name = name,
            type = group.get("type")?.takeIf { it.isJsonPrimitive }?.asString.orEmpty(),
            now = group.get("now")?.takeIf { it.isJsonPrimitive }?.asString.orEmpty(),
            selectable = group.get("selectable")?.takeIf { it.isJsonPrimitive }?.asBoolean == true,
            members = (group.get("all") as? JsonArray)
                ?.mapNotNull { member -> member.takeIf { it.isJsonPrimitive }?.asString }
                .orEmpty(),
        )
    }
}

/**
 * Policy groups of the running mihomo / sing-box: each group shows its current member, a
 * selector group expands to pick another one through [MainAction.SelectCoreGroupMember].
 */
@Composable
fun CoreGroupsDialog(
    groups: List<CoreGroupItem>,
    onAction: (MainAction) -> Unit,
) {
    var expandedGroup by rememberSaveable { mutableStateOf<String?>(null) }
    val onDismiss = { onAction(MainAction.DismissCoreGroups) }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(stringResource(R.string.title_core_groups)) },
        text = {
            if (groups.isEmpty()) {
                Text(stringResource(R.string.core_groups_empty))
            } else {
                LazyColumn {
                    items(groups, key = { it.name }) { group ->
                        Column(Modifier.fillMaxWidth()) {
                            Column(
                                Modifier
                                    .fillMaxWidth()
                                    .clickable(enabled = group.selectable) {
                                        expandedGroup = if (expandedGroup == group.name) null else group.name
                                    }
                                    .padding(vertical = 8.dp)
                            ) {
                                Text("${group.name} (${group.type})", style = MaterialTheme.typography.bodyLarge)
                                Text(
                                    group.now,
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                                )
                            }
                            if (group.selectable && expandedGroup == group.name) {
                                group.members.forEach { member ->
                                    Row(
                                        Modifier
                                            .fillMaxWidth()
                                            .selectable(
                                                selected = member == group.now,
                                                onClick = { onAction(MainAction.SelectCoreGroupMember(group.name, member)) },
                                                role = Role.RadioButton,
                                            )
                                            .padding(start = 8.dp),
                                        verticalAlignment = Alignment.CenterVertically,
                                    ) {
                                        RadioButton(selected = member == group.now, onClick = null)
                                        Text(member, style = MaterialTheme.typography.bodyMedium)
                                    }
                                }
                            }
                        }
                    }
                }
            }
        },
        confirmButton = {
            TextButton(onClick = onDismiss) { Text(stringResource(android.R.string.ok)) }
        },
    )
}
