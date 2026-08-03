package com.aegisx.cc.ui.screens

import androidx.compose.foundation.Canvas
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.unit.sp
import com.aegisx.cc.state.AegisXState
import com.aegisx.cc.ui.components.GlassTitle
import com.aegisx.cc.ui.theme.AegisCyan
import com.aegisx.cc.ui.theme.MutedWhite
import com.aegisx.cc.ui.theme.severityColor

/**
 * Interactive network node map.
 *
 * Renders a glowing defensive core at center and each attacking source as a
 * severity-coded node with an edge back to the core. Pure Canvas shapes keep
 * label rendering off the hot path.
 */
@Composable
fun NetworkMap(state: AegisXState) {
    val nodes by state.nodes.collectAsState()

    Column(Modifier.fillMaxSize()) {
        GlassTitle("ATTACK SOURCE MAP   (${nodes.size})")
        Canvas(Modifier.fillMaxSize()) {
            val w = size.width
            val h = size.height
            val center = Offset(w / 2f, h / 2f)

            // Defensive core with pulse.
            drawCircle(AegisCyan.copy(alpha = 0.30f), radius = 42f, center = center)
            drawCircle(AegisCyan.copy(alpha = 0.15f), radius = 60f, center = center)
            drawCircle(Color.White, radius = 11f, center = center)

            nodes.forEach { node ->
                val p = Offset(w * node.x, h * node.y)
                val accent = severityColor(node.severity)

                drawLine(
                    color = accent.copy(alpha = 0.30f),
                    start = p,
                    end = center,
                    strokeWidth = 1.5f,
                )
                drawCircle(accent.copy(alpha = 0.22f), radius = 15f, center = p)
                drawCircle(accent, radius = 6f, center = p)
                drawCircle(Color.White, radius = 2f, center = p)
            }
        }
        if (nodes.isEmpty()) {
            Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                Text(
                    "Waiting for first attack event",
                    color = MutedWhite,
                    fontSize = 13.sp,
                )
            }
        }
    }
}
