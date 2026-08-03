package com.aegisx.cc.ui.screens

import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material3.Icon
import androidx.compose.material3.Switch
import androidx.compose.material3.SwitchDefaults
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.aegisx.cc.state.AegisXState
import com.aegisx.cc.ui.components.GlassPanel
import com.aegisx.cc.ui.components.StatusBadge
import com.aegisx.cc.ui.theme.AegisCyan
import com.aegisx.cc.ui.theme.DeepNavy
import com.aegisx.cc.ui.theme.DeepNavy2
import com.aegisx.cc.ui.theme.FrostWhite
import com.aegisx.cc.ui.theme.MutedWhite

/**
 * Executive control center shell: ambient animated backdrop, header telemetry
 * strip, and the four primary panels arranged in a responsive grid.
 */
@Composable
fun Dashboard(state: AegisXState) {
    val connected by state.connected.collectAsState()
    val eventCount by state.eventCount.collectAsState()

    Box(
        modifier = Modifier
            .fillMaxSize()
            .background(Brush.verticalGradient(listOf(DeepNavy, DeepNavy2))),
    ) {
        // Ambient glows behind the glass.
        Canvas(Modifier.fillMaxSize()) {
            drawCircle(
                color = AegisCyan.copy(alpha = 0.06f),
                radius = size.minDimension * 0.5f,
                center = Offset(size.width * 0.15f, size.height * 0.1f),
            )
        }

        Column(Modifier.fillMaxSize().padding(20.dp)) {
            // ---- Header ----
            Row(
                Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(
                        Icons.Default.Shield,
                        contentDescription = "AegisX",
                        tint = AegisCyan,
                        modifier = Modifier.size(34.dp),
                    )
                    Text(
                        "AEGISX",
                        color = FrostWhite,
                        fontSize = 24.sp,
                        fontWeight = FontWeight.ExtraBold,
                        letterSpacing = 3.sp,
                        modifier = Modifier.padding(start = 10.dp),
                    )
                    Text(
                        "SECURITY SUITE",
                        color = MutedWhite,
                        fontSize = 12.sp,
                        letterSpacing = 2.sp,
                        modifier = Modifier.padding(start = 8.dp, top = 4.dp),
                    )
                }
                Row(horizontalArrangement = Arrangement.spacedBy(24.dp)) {
                    StatusBadge("Gateway", if (connected) "ONLINE" else "OFFLINE", if (connected) AegisCyan else Color(0xFFFF5D5D))
                    StatusBadge("Threat Index", eventCount.toString(), AegisCyan)
                }
            }

            // ---- Mitigation toggles strip ----
            MitigationStrip(state)

            // ---- Panels ----
            Row(
                Modifier.fillMaxSize(),
                horizontalArrangement = Arrangement.spacedBy(16.dp),
            ) {
                // Left column: attack feed + telemetry
                Column(
                    Modifier.weight(1.35f),
                    verticalArrangement = Arrangement.spacedBy(16.dp),
                ) {
                    GlassPanel(Modifier.weight(1f)) { AttackFeed(state) }
                    GlassPanel(Modifier.weight(0.7f)) { TelemetryPanel(state) }
                }
                // Middle: network map (largest)
                GlassPanel(Modifier.weight(1.5f)) { NetworkMap(state) }
                // Right: event log
                GlassPanel(Modifier.weight(1f)) { LogStream(state) }
            }
        }
    }
}

@Composable
private fun MitigationStrip(state: AegisXState) {
    val toggles by state.mitigation.collectAsState()
    GlassPanel(Modifier.fillMaxWidth().padding(bottom = 4.dp), cornerRadius = 14.dp) {
        Row(
            Modifier.fillMaxWidth().height(44.dp),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Text("MITIGATION CONTROLS", color = MutedWhite, fontSize = 11.sp, letterSpacing = 1.sp)
            toggles.forEach { (key, value) ->
                Column(horizontalAlignment = Alignment.CenterHorizontally, modifier = Modifier.width(96.dp)) {
                    Switch(
                        checked = value,
                        onCheckedChange = { state.toggleMitigation(key, it) },
                        colors = SwitchDefaults.colors(checkedTrackColor = AegisCyan),
                    )
                    Text(
                        key.replace("_", " "),
                        color = MutedWhite,
                        fontSize = 9.sp,
                        maxLines = 1,
                        softWrap = false,
                    )
                }
            }
        }
    }
}
