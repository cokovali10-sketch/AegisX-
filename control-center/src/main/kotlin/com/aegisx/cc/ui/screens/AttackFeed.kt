package com.aegisx.cc.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.aegisx.cc.data.AttackEvent
import com.aegisx.cc.state.AegisXState
import com.aegisx.cc.ui.components.GlassTitle
import com.aegisx.cc.ui.theme.MutedWhite
import com.aegisx.cc.ui.theme.severityColor

/** Real-time attack feed with severity-coded rows. */
@Composable
fun AttackFeed(state: AegisXState) {
    val feed by state.attackFeed.collectAsState()

    Column(Modifier.fillMaxSize()) {
        GlassTitle("REAL-TIME ATTACK FEED")
        if (feed.isEmpty()) {
            Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                Text("Awaiting decoy interactions...", color = MutedWhite, fontSize = 13.sp)
            }
        } else {
            LazyColumn(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                items(feed, key = { it.eventId }) { ev -> AttackRow(ev) }
            }
        }
    }
}

@Composable
private fun AttackRow(ev: AttackEvent) {
    val accent = severityColor(ev.severity)
    Row(
        Modifier
            .fillMaxWidth()
            .background(Color.White.copy(alpha = 0.03f), CircleShape)
            .padding(horizontal = 12.dp, vertical = 8.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Box(
            Modifier
                .width(4.dp)
                .padding(vertical = 6.dp)
                .background(accent, CircleShape)
        )
        Column(Modifier.padding(start = 10.dp).weight(1f)) {
            Text(
                "${ev.protocol.uppercase()}  ${ev.sourceIp}:${ev.sourcePort} -> :${ev.targetPort}",
                color = Color.White,
                fontSize = 13.sp,
                fontWeight = FontWeight.SemiBold,
            )
            Text(ev.summary, color = MutedWhite, fontSize = 11.sp, maxLines = 2)
            if (ev.relatedCves.isNotEmpty()) {
                Text(
                    ev.relatedCves.joinToString(" "),
                    color = accent,
                    fontSize = 10.sp,
                    fontWeight = FontWeight.Bold,
                )
            }
        }
        Column(horizontalAlignment = Alignment.End) {
            Text("${ev.threatScore}", color = accent, fontSize = 16.sp, fontWeight = FontWeight.ExtraBold)
            Text(ev.severity, color = accent, fontSize = 10.sp, letterSpacing = 1.sp)
            if (ev.username.isNotBlank()) {
                Text("user: ${ev.username}", color = MutedWhite, fontSize = 9.sp)
            }
        }
    }
}