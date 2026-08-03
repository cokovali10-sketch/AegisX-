package com.aegisx.cc

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.AccountTree
import androidx.compose.material.icons.filled.Dashboard
import androidx.compose.material.icons.filled.Hub
import androidx.compose.material.icons.filled.Launch
import androidx.compose.material.icons.filled.Public
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.ShowChart
import androidx.compose.material.icons.filled.Terminal
import androidx.compose.material3.Icon
import androidx.compose.material3.NavigationRail
import androidx.compose.material3.NavigationRailItem
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.window.Window
import androidx.compose.ui.window.application
import androidx.compose.ui.window.rememberWindowState
import com.aegisx.cc.state.AegisXState
import com.aegisx.cc.ui.components.GlassPanel
import com.aegisx.cc.ui.components.GlassTitle
import com.aegisx.cc.ui.screens.AttackFeed
import com.aegisx.cc.ui.screens.AttackGlobe
import com.aegisx.cc.ui.screens.AttackGlobeHeader
import com.aegisx.cc.ui.screens.Dashboard
import com.aegisx.cc.ui.screens.LogQueryView
import com.aegisx.cc.ui.screens.LogStream
import com.aegisx.cc.ui.screens.NetworkMap
import com.aegisx.cc.ui.screens.TelemetryPanel
import com.aegisx.cc.ui.screens.TopologyMap
import com.aegisx.cc.ui.theme.AegisXTheme
import com.aegisx.cc.ui.theme.AegisCyan
import com.aegisx.cc.ui.theme.DeepNavy
import com.aegisx.cc.ui.theme.DeepNavy2
import com.aegisx.cc.ui.theme.MutedWhite

private const val GATEWAY_HOST = "127.0.0.1"
private const val GATEWAY_PORT = 8080

/** Navigation destinations for the control center rail. */
private enum class Screen(val title: String, val icon: ImageVector) {
    Dashboard("Dashboard", Icons.Default.Dashboard),
    AttackGlobe("Attack Globe", Icons.Default.Public),
    LogQuery("Log Query", Icons.Default.Search),
    Topology("Topology", Icons.Default.Hub),
    AttackFeed("Attack Feed", Icons.Default.Launch),
    NetworkMap("Network Map", Icons.Default.AccountTree),
    Telemetry("Telemetry", Icons.Default.ShowChart),
    LogStream("Log Stream", Icons.Default.Terminal),
}

fun main() = application {
    val state = remember { AegisXState(GATEWAY_HOST, GATEWAY_PORT) }
    LaunchedEffect(Unit) { state.start() }

    Window(
        onCloseRequest = {
            state.stop()
            exitApplication()
        },
        title = "AegisX Control Center",
        state = rememberWindowState(width = 1480.dp, height = 920.dp),
    ) {
        AegisXTheme {
            AppShell(state)
        }
    }
}

@Composable
private fun AppShell(state: AegisXState) {
    var current by remember { mutableStateOf(Screen.Dashboard) }

    Row(
        Modifier
            .fillMaxSize()
            .background(Brush.verticalGradient(listOf(DeepNavy, DeepNavy2))),
    ) {
        NavigationRail(
            containerColor = Color.Transparent,
            modifier = Modifier.width(88.dp).padding(top = 16.dp, bottom = 16.dp),
        ) {
            Text(
                "AEGISX",
                color = AegisCyan,
                fontSize = 12.sp,
                fontWeight = androidx.compose.ui.text.font.FontWeight.ExtraBold,
                letterSpacing = 2.sp,
            )
            Screen.entries.forEach { screen ->
                NavigationRailItem(
                    selected = current == screen,
                    onClick = { current = screen },
                    icon = {
                        Icon(
                            screen.icon,
                            contentDescription = screen.title,
                            tint = if (current == screen) AegisCyan else MutedWhite,
                        )
                    },
                    label = { Text(screen.title, fontSize = 9.sp) },
                )
            }
        }

        Row(Modifier.fillMaxSize().padding(16.dp)) {
            when (current) {
                Screen.Dashboard -> Dashboard(state)
                Screen.AttackGlobe -> Column(Modifier.fillMaxSize()) {
                    AttackGlobeHeader(state)
                    GlassPanel(Modifier.weight(1f).fillMaxWidth()) { AttackGlobe(state) }
                }
                Screen.LogQuery -> GlassPanel(Modifier.fillMaxSize()) { LogQueryView(state) }
                Screen.Topology -> Column(Modifier.fillMaxSize()) {
                    GlassTitle("SYSTEM TOPOLOGY")
                    GlassPanel(Modifier.weight(1f).fillMaxWidth()) { TopologyMap(state) }
                }
                Screen.AttackFeed -> GlassPanel(Modifier.fillMaxSize()) { AttackFeed(state) }
                Screen.NetworkMap -> GlassPanel(Modifier.fillMaxSize()) { NetworkMap(state) }
                Screen.Telemetry -> GlassPanel(Modifier.fillMaxSize()) { TelemetryPanel(state) }
                Screen.LogStream -> GlassPanel(Modifier.fillMaxSize()) { LogStream(state) }
            }
        }
    }
}
