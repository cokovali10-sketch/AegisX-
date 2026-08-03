package com.aegisx.cc.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Button
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Switch
import androidx.compose.material3.SwitchDefaults
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.aegisx.cc.data.AttackEvent
import com.aegisx.cc.data.ExecEvent
import com.aegisx.cc.state.AegisXState
import com.aegisx.cc.ui.components.GlassPanel
import com.aegisx.cc.ui.components.GlassTitle
import com.aegisx.cc.ui.theme.AegisCyan
import com.aegisx.cc.ui.theme.MutedWhite
import com.aegisx.cc.ui.theme.severityColor
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/** One parsed log row shown in the query table. */
internal data class LogEntry(
    val id: Long,
    val timestamp: String,
    val severity: String,
    val node: String,
    val message: String,
) {
    val searchText: String get() = "$timestamp $severity $node $message"
}

private val timeFmt = SimpleDateFormat("HH:mm:ss.SSS", Locale.getDefault())

private fun fmt(ts: Long): String = if (ts <= 0) "--:--:--.---" else timeFmt.format(Date(ts))

private fun formatAttack(ev: AttackEvent): String =
    "${ev.protocol.uppercase()} ${ev.sourceIp}:${ev.sourcePort} -> :${ev.targetPort} score=${ev.threatScore} ${ev.summary}"

private fun formatExec(ev: ExecEvent): String {
    val sign = if (ev.anomaly) "ANOMALY[${ev.anomalyType}]" else "exec"
    return "$sign ${ev.comm} pid=${ev.pid} ppid=${ev.ppid} user=${ev.user}${if (ev.detail.isBlank()) "" else " ${ev.detail}"}"
}

private fun buildEntries(
    lines: List<String>,
    attacks: List<AttackEvent>,
    execs: List<ExecEvent>,
): List<LogEntry> {
    val out = ArrayList<LogEntry>(lines.size + attacks.size + execs.size)
    var seq = 0L
    lines.forEachIndexed { i, line ->
        val sev = when {
            line.contains("CRITICAL", ignoreCase = true) -> "CRITICAL"
            line.contains("HIGH", ignoreCase = true) -> "HIGH"
            line.contains("MEDIUM", ignoreCase = true) -> "MEDIUM"
            line.contains("LOW", ignoreCase = true) -> "LOW"
            else -> "INFO"
        }
        out += LogEntry(seq++, "", sev, "gateway", line)
    }
    attacks.forEach { ev ->
        out += LogEntry(seq++, fmt(ev.timestamp), ev.severity.uppercase(), ev.sourceIp, formatAttack(ev))
    }
    execs.forEach { ev ->
        out += LogEntry(seq++, fmt(0), if (ev.anomaly) "HIGH" else "INFO", if (ev.node.isBlank()) "sensor" else ev.node, formatExec(ev))
    }
    return out.sortedWith(compareByDescending<LogEntry> { it.timestamp }.thenByDescending { it.id })
}

/**
 * Real-time log query engine: regex-capable filtering over the live log stream,
 * attack events and exec events, with severity highlighting and CSV/JSON export.
 */
@Composable
fun LogQueryView(state: AegisXState) {
    val lines by state.logLines.collectAsState()
    val attacks by state.attackFeed.collectAsState()
    val execs by state.execEvents.collectAsState()

    val entries = remember(lines, attacks, execs) { buildEntries(lines, attacks, execs) }

    var query by remember { mutableStateOf("") }
    var regexMode by remember { mutableStateOf(false) }
    var caseSensitive by remember { mutableStateOf(false) }
    var paused by remember { mutableStateOf(false) }
    var exported by remember { mutableStateOf<String?>(null) }

    val regexError = remember(query, regexMode, caseSensitive) {
        if (regexMode && query.isNotBlank()) {
            runCatching {
                Regex(query, if (caseSensitive) setOf() else setOf(RegexOption.IGNORE_CASE))
            }.exceptionOrNull()
        } else null
    }

    val filtered = remember(entries, query, regexMode, caseSensitive, regexError) {
        if (query.isBlank()) entries
        else if (regexMode && regexError == null) {
            val re = Regex(query, if (caseSensitive) setOf() else setOf(RegexOption.IGNORE_CASE))
            entries.filter { re.containsMatchIn(it.searchText) }
        } else {
            entries.filter { it.searchText.contains(query, ignoreCase = !caseSensitive) }
        }
    }

    // Pause buffer: while paused, incoming lines collect upstream and the table
    // freezes; resuming flushes the accumulated snapshot.
    var rendered by remember { mutableStateOf<List<LogEntry>>(emptyList()) }
    LaunchedEffect(filtered, paused) {
        if (!paused) rendered = filtered.takeLast(300)
    }

    fun export(format: String) {
        val dir = File(System.getProperty("user.home"), "Downloads")
        dir.mkdirs()
        val file = File(dir, "aegisx-logs-${System.currentTimeMillis()}.$format")
        val text = when (format) {
            "csv" -> buildCsv(filtered)
            else -> buildJson(filtered)
        }
        file.writeText(text)
        exported = file.absolutePath
    }

    Column(Modifier.fillMaxSize()) {
        GlassTitle("LOG QUERY ENGINE   (${filtered.size} of ${entries.size} entries)")

        // ---- Toolbar ----
        Row(
            Modifier.fillMaxWidth().padding(bottom = 10.dp),
            horizontalArrangement = Arrangement.spacedBy(12.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            OutlinedTextField(
                value = query,
                onValueChange = { query = it },
                modifier = Modifier.weight(1f),
                placeholder = { Text("Filter logs... (regex with /pattern/ mode on)", color = MutedWhite, fontSize = 12.sp) },
                textStyle = androidx.compose.ui.text.TextStyle(fontFamily = FontFamily.Monospace, fontSize = 12.sp),
                singleLine = true,
                isError = regexError != null,
                supportingText = {
                    if (regexError != null) {
                        Text("Invalid regex: ${regexError.message}", color = Color(0xFFFF5D5D), fontSize = 10.sp)
                    }
                },
            )
            Toggle("Regex", regexMode) { regexMode = it }
            Toggle("Case", caseSensitive) { caseSensitive = it }
            Toggle("Pause live", paused) { paused = it }
            OutlinedButton(onClick = { export("csv") }) { Text("Export CSV", fontSize = 11.sp) }
            OutlinedButton(onClick = { export("json") }) { Text("Export JSON", fontSize = 11.sp) }
        }

        if (exported != null) {
            Text(
                "Exported ${filtered.size} rows -> $exported",
                color = AegisCyan,
                fontSize = 11.sp,
                modifier = Modifier.padding(bottom = 8.dp),
            )
        }

        if (regexError != null) {
            Text(
                "Regex error: ${regexError.message}",
                color = Color(0xFFFF5D5D),
                fontSize = 11.sp,
                modifier = Modifier.padding(bottom = 6.dp),
            )
        }

        // ---- Column headers ----
        Row(Modifier.fillMaxWidth().padding(vertical = 4.dp)) {
            TableCell("TIMESTAMP", Modifier.width(110.dp), header = true)
            TableCell("SEVERITY", Modifier.width(74.dp), header = true)
            TableCell("NODE", Modifier.width(120.dp), header = true)
            TableCell("MESSAGE", Modifier.weight(1f), header = true)
        }

        // ---- Rows ----
        Box(Modifier.fillMaxWidth().weight(1f)) {
            if (rendered.isEmpty()) {
                Text("No matching log lines", color = MutedWhite, fontSize = 12.sp, modifier = Modifier.padding(12.dp))
            } else {
                LazyColumn {
                    items(rendered, key = { it.id }) { entry ->
                        LogRow(entry)
                    }
                }
            }
        }
    }
}

@Composable
private fun Toggle(label: String, value: Boolean, onChange: (Boolean) -> Unit) {
    Column(horizontalAlignment = Alignment.CenterHorizontally) {
        Switch(
            checked = value,
            onCheckedChange = onChange,
            colors = SwitchDefaults.colors(checkedTrackColor = AegisCyan),
        )
        Text(label, color = MutedWhite, fontSize = 9.sp)
    }
}

@Composable
private fun TableCell(text: String, modifier: Modifier = Modifier, header: Boolean = false) {
    Text(
        text,
        color = if (header) AegisCyan else MutedWhite,
        fontSize = if (header) 10.sp else 11.sp,
        fontWeight = if (header) FontWeight.Bold else FontWeight.Normal,
        fontFamily = FontFamily.Monospace,
        maxLines = 1,
        modifier = modifier.padding(end = 8.dp),
    )
}

@Composable
private fun LogRow(entry: LogEntry) {
    val accent = severityColor(entry.severity)
    Row(
        Modifier
            .fillMaxWidth()
            .background(Color.White.copy(alpha = 0.02f), RoundedCornerShape(6.dp))
            .padding(horizontal = 6.dp, vertical = 5.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Box(
            Modifier
                .width(2.dp)
                .padding(vertical = 4.dp)
                .background(accent, RoundedCornerShape(2.dp)),
        )
        TableCell(entry.timestamp, Modifier.width(106.dp).padding(start = 6.dp))
        TableCell(entry.severity, Modifier.width(66.dp))
        TableCell(entry.node, Modifier.width(110.dp))
        TableCell(entry.message, Modifier.weight(1f))
    }
}

private fun buildCsv(entries: List<LogEntry>): String = buildString {
    append("timestamp,severity,node,message\n")
    entries.forEach { e ->
        fun esc(s: String): String = "\"" + s.replace("\"", "\"\"") + "\""
        append(esc(e.timestamp)).append(',')
            .append(esc(e.severity)).append(',')
            .append(esc(e.node)).append(',')
            .append(esc(e.message)).append('\n')
    }
}

private fun buildJson(entries: List<LogEntry>): String = buildJsonArray {
    entries.forEach { e ->
        add(
            buildJsonObject {
                put("timestamp", e.timestamp)
                put("severity", e.severity)
                put("node", e.node)
                put("message", e.message)
            }
        )
    }
}.toString()
