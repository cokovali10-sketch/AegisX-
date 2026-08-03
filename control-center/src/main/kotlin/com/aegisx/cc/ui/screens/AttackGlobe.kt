package com.aegisx.cc.ui.screens

import androidx.compose.animation.core.LinearEasing
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.gestures.detectTapGestures
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.offset
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.drawscope.DrawScope
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.layout.onSizeChanged
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.IntSize
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.aegisx.cc.data.AttackEvent
import com.aegisx.cc.state.AegisXState
import com.aegisx.cc.ui.components.GlassPanel
import com.aegisx.cc.ui.components.GlassTitle
import com.aegisx.cc.ui.theme.AegisCyan
import com.aegisx.cc.ui.theme.MutedWhite
import com.aegisx.cc.ui.theme.severityColor
import kotlin.math.PI
import kotlin.math.cos
import kotlin.math.sin
import kotlin.math.sqrt
import kotlin.random.Random

/** Minimal 3D point used for the software-projection globe. */
internal class Vec3(val x: Double, val y: Double, val z: Double) {
    operator fun plus(o: Vec3) = Vec3(x + o.x, y + o.y, z + o.z)
    operator fun times(s: Double) = Vec3(x * s, y * s, z * s)
    fun normalized(): Vec3 {
        val m = sqrt(x * x + y * y + z * z)
        return if (m == 0.0) Vec3(0.0, 1.0, 0.0) else Vec3(x / m, y / m, z / m)
    }
}

/** Homemade 3D -> 2D projection helpers. No external math library. */
internal object GlobeMath {
    fun rotateY(p: Vec3, ang: Double): Vec3 {
        val c = cos(ang); val s = sin(ang)
        return Vec3(p.x * c + p.z * s, p.y, -p.x * s + p.z * c)
    }

    fun rotateX(p: Vec3, ang: Double): Vec3 {
        val c = cos(ang); val s = sin(ang)
        return Vec3(p.x, p.y * c - p.z * s, p.y * s + p.z * c)
    }

    /** lat/lon in degrees -> unit-sphere point. */
    fun fromLonLat(lonDeg: Double, latDeg: Double): Vec3 {
        val lon = lonDeg * PI / 180.0
        val lat = latDeg * PI / 180.0
        return Vec3(cos(lat) * cos(lon), cos(lat) * sin(lon), sin(lat))
    }

    fun quadratic(p0: Vec3, c: Vec3, p1: Vec3, t: Double): Vec3 {
        val u = 1.0 - t
        return p0 * (u * u) + c * (2.0 * u * t) + p1 * (t * t)
    }

    /** Perspective projection. `scale * z / (z + d)` form: focal / (focal - z). */
    fun project(p: Vec3, angleDeg: Double, tiltDeg: Double, radius: Float, cx: Float, cy: Float): Offset {
        var q = rotateY(p, angleDeg * PI / 180.0)
        q = rotateX(q, tiltDeg * PI / 180.0)
        val focal = 2.4
        val factor = (focal / (focal - q.z)).toFloat()
        return Offset(cx + (q.x * radius * factor).toFloat(), cy - (q.y * radius * factor).toFloat())
    }

    /** Depth after the world rotation (larger = nearer the viewer). */
    fun depth(p: Vec3, angleDeg: Double, tiltDeg: Double): Float {
        var q = rotateY(p, angleDeg * PI / 180.0)
        q = rotateX(q, tiltDeg * PI / 180.0)
        return q.z.toFloat()
    }
}

/** A precomputed attack arc, cached so the render loop stays cheap. */
internal class ArcDraw(
    val ev: AttackEvent,
    val pts: List<Offset>,
    val depth: Float,
    val center: Offset,
)

/** Deterministic geolocation: a tiny bundled country map + stable hash fallback. */
internal fun geoOf(key: String): Pair<Double, Double> {
    val known = mapOf(
        "8.8.8.8" to (37.36 to -122.03),
        "1.1.1.1" to (35.35 to 103.86),
        "52.94.0.0" to (-33.86 to 151.20),
    )
    known[key]?.let { return it }
    val seed = key.removePrefix("t:").removePrefix("svc:")
    val rnd = Random(seed.hashCode())
    return rnd.nextDouble(-70.0, 70.0) to rnd.nextDouble(-180.0, 180.0)
}

/** Sample one elevated quadratic-Bezier arc in 3D and project every point. */
internal fun buildArc(
    ev: AttackEvent,
    angleDeg: Double,
    tiltDeg: Double,
    radius: Float,
    cx: Float,
    cy: Float,
): ArcDraw {
    val (aLat, aLon) = geoOf(ev.sourceIp)
    val (tLat, tLon) = geoOf("t:${ev.targetPort}")
    val p0 = GlobeMath.fromLonLat(aLon, aLat)
    val p1 = GlobeMath.fromLonLat(tLon, tLat)
    // Control point lifted 45% above the sphere surface for a visible bow.
    val mid = (p0 + p1).normalized() * 1.45 + Vec3(0.0, 0.18, 0.0)

    val count = 40
    val pts = ArrayList<Offset>(count + 1)
    val midWorld = GlobeMath.quadratic(p0, mid, p1, 0.5)
    for (i in 0..count) {
        val t = i.toDouble() / count
        val world = GlobeMath.quadratic(p0, mid, p1, t)
        pts += GlobeMath.project(world, angleDeg, tiltDeg, radius, cx, cy)
    }
    val midScreen = pts[pts.size / 2]
    return ArcDraw(ev, pts, GlobeMath.depth(midWorld, angleDeg, tiltDeg), midScreen)
}

/**
 * Hardware-accelerated 3D attack globe rendered with hand-rolled software
 * projection on a Compose Canvas. Spinning sphere + severity-coded attack
 * arcs; click an arc to inspect the event.
 */
@Composable
fun AttackGlobe(state: AegisXState) {
    val attacks by state.attackFeed.collectAsState()
    val infinite = rememberInfiniteTransition(label = "globe")
    val rotation by infinite.animateFloat(
        initialValue = 0f,
        targetValue = 360f,
        animationSpec = infiniteRepeatable(tween(durationMillis = 18000, easing = LinearEasing), RepeatMode.Restart),
        label = "globeRotation",
    )

    var size by remember { mutableStateOf(IntSize.Zero) }
    var selectedIdx by remember { mutableIntStateOf(-1) }

    val events = attacks.takeLast(60)
    val arcs = remember(events, size.width, size.height, rotation) {
        if (size.width == 0) emptyList() else {
            val radius = minOf(size.width, size.height) * 0.32f
            events.map { buildArc(it, rotation.toDouble(), 22.0, radius, size.width / 2f, size.height / 2f) }
        }
    }

    Box(Modifier.fillMaxSize()) {
        Canvas(
            Modifier
                .fillMaxSize()
                .onSizeChanged { size = it }
                .pointerInput(arcs) {
                    detectTapGestures { off ->
                        var best = -1
                        var bestD = 60f
                        arcs.forEachIndexed { i, a ->
                            val d = (a.center - off).getDistance()
                            if (d < bestD) { bestD = d; best = i }
                        }
                        selectedIdx = if (best >= 0) best else -1
                    }
                },
        ) {
            val w = size.width
            val h = size.height
            if (w == 0) return@Canvas
            val cx = w / 2f
            val cy = h / 2f
            val radius = minOf(w, h) * 0.32f
            val angle = rotation.toDouble()

            drawCircle(AegisCyan.copy(alpha = 0.06f), radius = radius * 1.7f, center = Offset(cx, cy))

            // Lat/lon wireframe graticule.
            drawGraticule(cx, cy, radius, angle)

            // Attack arcs, back-to-front.
            arcs.sortedByDescending { it.depth }.forEachIndexed { i, arc ->
                val accent = severityColor(arc.ev.severity)
                val steps = arc.pts.size - 1
                for (s in 0 until steps) {
                    val alpha = 0.25f + 0.75f * (s.toFloat() / steps.coerceAtLeast(1))
                    drawLine(
                        accent.copy(alpha = alpha),
                        arc.pts[s],
                        arc.pts[s + 1],
                        strokeWidth = if (selectedIdx == i) 3.5f else 2f,
                    )
                }
                drawCircle(accent, radius = 3f, center = arc.pts.last())
            }

            // Sphere rim.
            drawCircle(AegisCyan.copy(alpha = 0.55f), radius = radius, center = Offset(cx, cy), style = Stroke(width = 1.5f))
            drawCircle(Color.White.copy(alpha = 0.03f), radius = radius * 1.03f, center = Offset(cx, cy))
        }

        // Tooltip for the selected arc.
        if (selectedIdx in arcs.indices) {
            val arc = arcs[selectedIdx]
            val ev = arc.ev
            val accent = severityColor(ev.severity)
            Box(
                Modifier
                    .offset(x = (arc.center.x - 140).dp, y = (arc.center.y - 60).dp)
                    .widthIn(max = 320.dp),
            ) {
                GlassPanel(cornerRadius = 10.dp) {
                    Column {
                        Text(
                            "${ev.protocol.uppercase()}  ${ev.sourceIp}:${ev.sourcePort} -> :${ev.targetPort}",
                            color = accent,
                            fontWeight = FontWeight.Bold,
                            fontSize = 12.sp,
                        )
                        Text(ev.summary, color = MutedWhite, fontSize = 11.sp, maxLines = 3)
                        Text(
                            "score ${ev.threatScore}   ${ev.severity}",
                            color = accent,
                            fontSize = 11.sp,
                            modifier = Modifier.padding(top = 4.dp),
                        )
                    }
                }
            }
        }
    }
}

/** Header + severity colour legend for the globe screen. */
@Composable
fun AttackGlobeHeader(state: AegisXState) {
    val attacks by state.attackFeed.collectAsState()
    Column(Modifier.fillMaxSize()) {
        GlassTitle("ATTACK GLOBE   (${attacks.takeLast(60).size} arcs)")
        Row(Modifier.padding(bottom = 8.dp), verticalAlignment = Alignment.CenterVertically) {
            listOf(
                "CRITICAL" to severityColor("CRITICAL"),
                "HIGH" to severityColor("HIGH"),
                "MEDIUM" to severityColor("MEDIUM"),
                "LOW" to severityColor("LOW"),
            ).forEach { (label, c) ->
                Row(
                    Modifier.padding(end = 16.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Box(
                        Modifier
                            .padding(end = 5.dp)
                            .size(8.dp)
                            .background(c, CircleShape),
                    )
                    Text(label, color = c, fontSize = 10.sp)
                }
            }
        }
    }
}

/** Draws the lat/lon wireframe for the given world rotation. */
internal fun DrawScope.drawGraticule(cx: Float, cy: Float, radius: Float, angleDeg: Double) {
    val lineColor = Color.White.copy(alpha = 0.14f)
    val tilt = 22.0
    val rad = angleDeg * PI / 180.0

    // Meridians (constant longitude).
    for (lon0 in -180 until 180 step 15) {
        val path = Path()
        for (lat0 in -90..90 step 6) {
            var q = GlobeMath.rotateY(GlobeMath.fromLonLat(lon0.toDouble(), lat0.toDouble()), rad)
            q = GlobeMath.rotateX(q, tilt * PI / 180.0)
            val f = (2.4 / (2.4 - q.z)).toFloat()
            val x = cx + (q.x * radius * f).toFloat()
            val y = cy - (q.y * radius * f).toFloat()
            if (lat0 == -90) path.moveTo(x, y) else path.lineTo(x, y)
        }
        drawPath(path, color = lineColor, style = Stroke(0.8f))
    }

    // Parallels (constant latitude).
    for (lat0 in -90 until 90 step 15) {
        val path = Path()
        for (lon0 in -180 until 180 step 6) {
            var q = GlobeMath.rotateY(GlobeMath.fromLonLat(lon0.toDouble(), lat0.toDouble()), rad)
            q = GlobeMath.rotateX(q, tilt * PI / 180.0)
            val f = (2.4 / (2.4 - q.z)).toFloat()
            val x = cx + (q.x * radius * f).toFloat()
            val y = cy - (q.y * radius * f).toFloat()
            if (lon0 == -180) path.moveTo(x, y) else path.lineTo(x, y)
        }
        drawPath(path, color = lineColor, style = Stroke(0.8f))
    }
}
