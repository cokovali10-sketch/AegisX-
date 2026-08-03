package com.aegisx.cc.ui.components

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.shadow
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import com.aegisx.cc.ui.theme.GlassBorder
import com.aegisx.cc.ui.theme.GlassSurface

/**
 * Glassmorphic surface primitive.
 *
 * Emulates frosted glass with a translucent vertical gradient fill, a soft
 * inner highlight along the top edge, and a hairline luminous border. The
 * layering trick (two stacked rounded boxes) produces the "bevel" common to
 * glassmorphism without relying on experimental BackdropBlur APIs.
 */
@Composable
fun GlassPanel(
    modifier: Modifier = Modifier,
    cornerRadius: Dp = 18.dp,
    tint: Color = Color.White,
    content: @Composable () -> Unit,
) {
    Box(
        modifier = modifier
            .shadow(12.dp, RoundedCornerShape(cornerRadius), spotColor = Color.Black.copy(alpha = 0.45f))
            .clip(RoundedCornerShape(cornerRadius))
            .background(
                Brush.verticalGradient(
                    0f to GlassSurface.copy(alpha = 0.28f),
                    0.25f to GlassSurface,
                    1f to Color.Black.copy(alpha = 0.18f),
                )
            )
            .border(1.dp, GlassBorder, RoundedCornerShape(cornerRadius))
            .padding(16.dp),
    ) {
        // Inner top-edge highlight bar (the "gloss").
        Box(
            Modifier
                .matchParentSize()
                .padding(top = 0.dp, start = 12.dp, end = 12.dp)
                .background(
                    Brush.horizontalGradient(
                        0f to Color.White.copy(alpha = 0.10f),
                        0.5f to Color.White.copy(alpha = 0.03f),
                        1f to Color.White.copy(alpha = 0.10f),
                    )
                )
        )
        Box(Modifier.padding(top = 2.dp)) {
            content()
        }
    }
}

/** Title bar text styling helper shared by panels. */
@Composable
fun GlassTitle(
    title: String,
    modifier: Modifier = Modifier,
) {
    androidx.compose.material3.Text(
        text = title,
        color = Color.White,
        style = androidx.compose.material3.MaterialTheme.typography.titleMedium,
        modifier = modifier.padding(bottom = 10.dp),
    )
}
