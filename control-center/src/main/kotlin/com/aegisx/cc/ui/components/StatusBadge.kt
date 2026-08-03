package com.aegisx.cc.ui.components

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

/** Small glowing status pill used for metrics and connection state. */
@Composable
fun StatusBadge(
    label: String,
    value: String,
    color: Color,
    modifier: Modifier = Modifier,
) {
    Row(
        verticalAlignment = Alignment.CenterVertically,
        modifier = modifier,
    ) {
        Box(
            Modifier
                .padding(end = 8.dp)
                .size(8.dp)
                .graphicsLayer { alpha = 0.9f }
                .background(color.copy(alpha = 0.25f), CircleShape)
                .padding(2.dp)
                .background(color, CircleShape)
        )
        Column {
            Text(label, color = Color.White.copy(alpha = 0.55f), fontSize = 11.sp)
            Text(
                value,
                color = color,
                fontSize = 16.sp,
                fontWeight = FontWeight.Bold,
            )
        }
    }
}