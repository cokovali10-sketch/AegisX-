package com.aegisx.cc.ui.theme

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color

// AegisX palette - deep navy glass with electric cyan/green accent.
val DeepNavy = Color(0xFF0B1020)
val DeepNavy2 = Color(0xFF101A33)
val Slate = Color(0xFF1A2540)
val FrostWhite = Color(0xFFE8EDF9)
val MutedWhite = Color(0xFF9AA6C2)

val AegisCyan = Color(0xFF2EE6C8)
val AegisTeal = Color(0xFF19C3B0)
val AegisAmber = Color(0xFFF5B942)
val AegisRed = Color(0xFFFF5D5D)
val AegisPurple = Color(0xFF8B5CF6)

// Severity -> accent mapping shared across the whole dashboard.
fun severityColor(severity: String): Color = when (severity.uppercase()) {
    "CRITICAL" -> AegisRed
    "HIGH" -> Color(0xFFF76B5E)
    "MEDIUM" -> AegisAmber
    "LOW" -> Color(0xFF4ADE80)
    else -> MutedWhite
}

val GlassLight = Color(0x55FFFFFF) // translucent top-edge highlight
val GlassSurface = Color(0x14FFFFFF)
val GlassBorder = Color(0x22FFFFFF)

private val DarkScheme = darkColorScheme(
    primary = AegisCyan,
    secondary = AegisTeal,
    tertiary = AegisPurple,
    background = DeepNavy,
    surface = Slate,
    onPrimary = DeepNavy,
    onBackground = FrostWhite,
    onSurface = FrostWhite,
)

@Composable
fun AegisXTheme(content: @Composable () -> Unit) {
    val dark = isSystemInDarkTheme() || true // always dark: night-ops aesthetic
    MaterialTheme(
        colorScheme = DarkScheme,
        typography = MaterialTheme.typography,
        content = content,
    )
}
