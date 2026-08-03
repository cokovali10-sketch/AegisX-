package com.aegisx.cc.ui.screens

import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.gestures.detectDragGestures
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateMapOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.input.pointer.PointerEventType
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.layout.onSizeChanged
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.IntSize
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.aegisx.cc.data.EdgeModel
import com.aegisx.cc.data.NodeModel
import com.aegisx.cc.state.AegisXState
import com.aegisx.cc.ui.components.GlassPanel
import com.aegisx.cc.ui.components.GlassTitle
import com.aegisx.cc.ui.theme.AegisAmber
import com.aegisx.cc.ui.theme.AegisCyan
import com.aegisx.cc.ui.theme.AegisPurple
import com.aegisx.cc.ui.theme.MutedWhite
import com.aegisx.cc.ui.theme.severityColor
import kotlin.math.PI
import kotlin.math.cos
import kotlin.math.sin

private fun nodeColor(n: NodeModel): Color = when (n.kind) {
    "source" -> severityColor(n.severity)
    "target" -> AegisAmber
    "honeypot" -> AegisPurple
    "exec" -> if (n.severity == "HIGH") Color(0xFFFF5D5D) else Color(0xFFF5B942)
    else -> AegisCyan
}

private fun edgeColor(kind: String): Color = when (kind) {
    "scan" -> AegisCyan
    "attack" -> Color(0xFFFF5D5D)
    "exec" -> AegisAmber
    else -> Color.White.copy(alpha = 0.25f)
}

/** Deterministic radial layout: kinds placed on concentric rings. */
private fun radialLayout(nodes: List<NodeModel>): Map<String, Offset> {
    val ringRadius = mapOf(
        "source" to 0.34f,
        "target" to 0.24f,
        "honeypot" to 0.38f,
        "exec" to 0.30f,
        "host" to 0.22f,
    )
    val grouped = nodes.groupBy { it.kind }
    val out = mutableMapOf<String, Offset>()
    grouped.forEach { (kind, group) ->
        val radius = ringRadius[kind] ?: 0.3f
        group.forEachIndexed { i, n ->
            val angle = 2.0 * PI * i.toDouble() / group.size.coerceAtLeast(1) - PI / 2.0
            out[n.id] = Offset(
                (0.5f + (radius * cos(angle)).toFloat()).coerceIn(0.08f, 0.92f),
                (0.5f + (radius * sin(angle)).toFloat()).coerceIn(0.08f, 0.92f),
            )
        }
    }
    return out
}

private fun nodeAt(
    positions: Map<String, Offset>,
    nodes: List<NodeModel>,
    size: IntSize,
    p: Offset,
): String? {
    var best: String? = null
    var bestD = 24f
    nodes.forEach { n ->
        positions[n.id]?.let { f ->
            val np = Offset(f.x * size.width, f.y * size.height)
            val d = (np - p).getDistance()
            if (d < bestD) { bestD = d; best = n.id }
        }
    }
    return best
}

/**
 * Interactive system topology map. Nodes are derived from live signals and
 * rendered with a radial layout; drag to reposition, click to inspect.
 */
@Composable
fun TopologyMap(state: AegisXState) {
    val nodes by state.topologyNodes.collectAsState()
    val edges by state.topologyEdges.collectAsState()

    val layout = remember(nodes) { radialLayout(nodes) }
    val positions = remember { mutableStateMapOf<String, Offset>() }
    LaunchedEffect(nodes) {
        layout.forEach { (id, p) -> if (!positions.containsKey(id)) positions[id] = p }
    }

    var selectedId by remember { mutableStateOf<String?>(null) }
    var hoveredId by remember { mutableStateOf<String?>(null) }
    var draggingId by remember { mutableStateOf<String?>(null) }
    var size by remember { mutableStateOf(IntSize.Zero) }

    val selected = nodes.firstOrNull { it.id == selectedId }

    Row(Modifier.fillMaxSize()) {
        Box(Modifier.weight(1f)) {
            Canvas(
                Modifier
                    .fillMaxSize()
                    .onSizeChanged { size = it }
                    .pointerInput(Unit) {
                        awaitPointerEventScope {
                            while (true) {
                                val event = awaitPointerEvent()
                                if (event.type == PointerEventType.Move) {
                                    hoveredId = event.changes.firstOrNull()?.position
                                        ?.let { nodeAt(positions, nodes, size, it) }
                                }
                            }
                        }
                    }
                    .pointerInput(Unit) {
                        detectDragGestures(
                            onDragStart = { pos ->
                                val hit = nodeAt(positions, nodes, size, pos)
                                selectedId = hit
                                draggingId = hit
                            },
                            onDrag = { change, amount ->
                                change.consume()
                                val id = draggingId ?: return@detectDragGestures
                                val cur = positions[id] ?: Offset(0.5f, 0.5f)
                                positions[id] = Offset(
                                    (cur.x + amount.x / size.width.coerceAtLeast(1)).coerceIn(0.05f, 0.95f),
                                    (cur.y + amount.y / size.height.coerceAtLeast(1)).coerceIn(0.05f, 0.95f),
                                )
                            },
                            onDragEnd = { draggingId = null },
                        )
                    },
            ) {
                if (size.width == 0) return@Canvas
                val cx = size.width / 2f
                val cy = size.height / 2f
                drawCircle(AegisCyan.copy(alpha = 0.06f), radius = minOf(size.width, size.height) * 0.42f, center = Offset(cx, cy))

                // ---- Edges ----
                edges.forEach { e ->
                    val from = positions[e.from]
                    val to = positions[e.to]
                    if (from != null && to != null && e.from != e.to) {
                        drawLine(
                            edgeColor(e.kind).copy(alpha = 0.55f),
                            Offset(from.x * size.width, from.y * size.height),
                            Offset(to.x * size.width, to.y * size.height),
                            strokeWidth = 1.5f,
                        )
                    }
                }

                // ---- Nodes ----
                nodes.forEach { n ->
                    val f = positions[n.id] ?: return@forEach
                    val p = Offset(f.x * size.width, f.y * size.height)
                    val accent = nodeColor(n)
                    val isSel = n.id == selectedId
                    val isHov = n.id == hoveredId
                    drawCircle(accent.copy(alpha = if (isSel) 0.45f else 0.22f), radius = if (isSel) 22f else 16f, center = p)
                    drawCircle(accent, radius = if (isSel) 9f else 7f, center = p)
                    if (n.kind == "honeypot") drawCircle(Color.White.copy(alpha = 0.9f), radius = 2.5f, center = p)
                    if (isHov) drawCircle(Color.White.copy(alpha = 0.4f), radius = 30f, center = p, style = androidx.compose.ui.graphics.drawscope.Stroke(1f))
                }
            }

            // Hover tooltip.
            val hoverNode = nodes.firstOrNull { it.id == hoveredId }
            if (hoverNode != null) {
                val f = positions[hoverNode.id] ?: Offset(0.5f, 0.5f)
                Box(
                    Modifier
                        .padding(start = (f.x * size.width + 16).dp, top = (f.y * size.height - 24).dp)
                ) {
                    GlassPanel(cornerRadius = 8.dp) {
                        Text(
                            "${hoverNode.label}  [${hoverNode.kind}]",
                            color = nodeColor(hoverNode),
                            fontWeight = FontWeight.SemiBold,
                            fontSize = 11.sp,
                        )
                        if (hoverNode.ip.isNotBlank()) Text(hoverNode.ip, color = MutedWhite, fontSize = 10.sp)
                    }
                }
            }

            if (nodes.isEmpty()) {
                Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                    Text("No topology data yet — awaiting events", color = MutedWhite, fontSize = 13.sp)
                }
            }
        }

        // ---- Details side panel ----
        GlassPanel(Modifier.width(280.dp)) {
            Column {
                Text("SELECTED NODE", color = AegisCyan, fontSize = 11.sp, fontWeight = FontWeight.Bold, letterSpacing = 1.sp)
                if (selected == null) {
                    Text(
                        "Click a node to inspect it.\nDrag nodes to rearrange.",
                        color = MutedWhite, fontSize = 12.sp, modifier = Modifier.padding(top = 10.dp),
                    )
                } else {
                    val accent = nodeColor(selected)
                    Text(selected.label, color = accent, fontSize = 18.sp, fontWeight = FontWeight.ExtraBold, modifier = Modifier.padding(top = 10.dp))
                    DetailRow("kind", selected.kind)
                    DetailRow("ip", selected.ip.ifBlank { "—" })
                    DetailRow("severity", selected.severity)
                    DetailRow("children", selected.children.size.toString())
                    val neighbors = edges
                        .filter { it.from == selected.id || it.to == selected.id }
                        .distinctBy { listOf(it.from, it.to).sorted() }
                    Text(
                        "Relationships (${neighbors.size})",
                        color = AegisCyan, fontSize = 11.sp, fontWeight = FontWeight.Bold,
                        modifier = Modifier.padding(top = 12.dp, bottom = 4.dp),
                    )
                    neighbors.take(8).forEach { e ->
                        val other = if (e.from == selected.id) e.to else e.from
                        Row(Modifier.fillMaxWidth().padding(vertical = 2.dp), verticalAlignment = Alignment.CenterVertically) {
                            Box(
                                Modifier
                                    .padding(end = 6.dp)
                                    .background(edgeColor(e.kind), CircleShape),
                            )
                            Text(
                                "${e.kind} -> $other",
                                color = MutedWhite,
                                fontSize = 11.sp,
                                fontFamily = androidx.compose.ui.text.font.FontFamily.Monospace,
                                maxLines = 1,
                                modifier = Modifier.weight(1f),
                            )
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun DetailRow(label: String, value: String) {
    Row(Modifier.fillMaxWidth().padding(top = 6.dp)) {
        Text(label, color = MutedWhite, fontSize = 11.sp, modifier = Modifier.width(80.dp))
        Text(value, color = Color.White.copy(alpha = 0.9f), fontSize = 11.sp, maxLines = 1, modifier = Modifier.weight(1f))
    }
}
