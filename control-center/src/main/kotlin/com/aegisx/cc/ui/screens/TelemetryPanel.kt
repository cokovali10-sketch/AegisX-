package com.aegisx.cc.ui.screens

import androidx.compose.foundation.Canvas
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.aegisx.cc.state.AegisXState
import com.aegisx.cc.ui.components.GlassTitle
import com.aegisx.cc.ui.theme.AegisCyan
import com.aegisx.cc.ui.theme.MutedWhite

/** System status: an event-rate sparkline rendered from live telemetry. */
@Composable
fun TelemetryPanel(state: AegisXState) {
    val frames by state.telemetry.collectAsState()
    val window = frames.takeLast(80)

    Column(Modifier.fillMaxSize()) {
        GlassTitle("SYSTEM TELEMETRY")
        Row(Modifier.fillMaxWidth()) {
            Text(
                "telemetry samples",
                color = MutedWhite,
                fontSize = 11.sp,
                modifier = Modifier.weight(1f),
            )
            Text("${window.size}", color = AegisCyan, fontSize = 11.sp)
        }
        Canvas(
            Modifier
                .fillMaxWidth()
                .weight(1f)
                .height(72.dp)
        ) {
            if (window.isEmpty()) return@Canvas
            val values = window.map { it.value.toFloat() }
            val minV = values.min()
            val maxV = values.max().coerceAtLeast(minV + 1f)
            val span = maxV - minV
            val stepX = size.width / (values.size - 1).coerceAtLeast(1)
            val path = Path()
            values.forEachIndexed { i, v ->
                val x = i * stepX
                val y = size.height - ((v - minV) / span) * size.height
                if (i == 0) path.moveTo(x, y) else path.lineTo(x, y)
            }
            drawPath(path, color = AegisCyan, style = Stroke(width = 2f))
        }
    }
}
