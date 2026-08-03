package com.aegisx.cc.ui.screens

import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.aegisx.cc.state.AegisXState
import com.aegisx.cc.ui.components.GlassTitle
import com.aegisx.cc.ui.theme.MutedWhite

/** Monospace, tail-following event log stream. */
@Composable
fun LogStream(state: AegisXState) {
    val lines by state.logLines.collectAsState()

    Column(Modifier.fillMaxSize()) {
        GlassTitle("LIVE LOG STREAM")
        if (lines.isEmpty()) {
            Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                Text("No log output yet", color = MutedWhite, fontSize = 12.sp)
            }
        } else {
            LazyColumn(Modifier.fillMaxSize()) {
                items(lines.reversed()) { line ->
                    Text(
                        line,
                        color = Color.White.copy(alpha = 0.85f),
                        fontFamily = FontFamily.Monospace,
                        fontSize = 11.sp,
                        lineHeight = 16.sp,
                        modifier = Modifier.padding(vertical = 1.dp),
                    )
                }
            }
        }
    }
}