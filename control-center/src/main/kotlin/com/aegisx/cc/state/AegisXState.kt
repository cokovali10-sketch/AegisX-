package com.aegisx.cc.state

import com.aegisx.cc.data.AegisXClient
import com.aegisx.cc.data.AttackEvent
import com.aegisx.cc.data.CommandAck
import com.aegisx.cc.data.EdgeModel
import com.aegisx.cc.data.ExecEvent
import com.aegisx.cc.data.NetworkNode
import com.aegisx.cc.data.NodeModel
import com.aegisx.cc.data.TelemetryFrame
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlin.random.Random

/**
 * Single source of truth for the dashboard.
 *
 * Holds the live attack feed, telemetry series, network-map nodes and the
 * mitigation toggle state; owns the background WebSocket connection.
 */
class AegisXState(
    private val host: String = "127.0.0.1",
    private val port: Int = 8080,
) {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    private val json = Json { ignoreUnknownKeys = true; isLenient = true }

    private val _attackFeed = MutableStateFlow<List<AttackEvent>>(emptyList())
    val attackFeed: StateFlow<List<AttackEvent>> = _attackFeed.asStateFlow()

    private val _telemetry = MutableStateFlow<List<TelemetryFrame>>(emptyList())
    val telemetry: StateFlow<List<TelemetryFrame>> = _telemetry.asStateFlow()

    private val _nodes = MutableStateFlow<List<NetworkNode>>(emptyList())
    val nodes: StateFlow<List<NetworkNode>> = _nodes.asStateFlow()

    private val _connected = MutableStateFlow(false)
    val connected: StateFlow<Boolean> = _connected.asStateFlow()

    // Mitigation toggles surfaced in the control panel.
    private val _mitigation = MutableStateFlow(
        mapOf(
            "ban_source_ips" to true,
            "honeypot_ssh" to true,
            "honeypot_http" to true,
            "honeypot_mysql" to true,
            "fim_watchdog" to true,
            "dns_sinkhole" to false,
        )
    )
    val mitigation: StateFlow<Map<String, Boolean>> = _mitigation.asStateFlow()

    private val _logLines = MutableStateFlow<List<String>>(emptyList())
    val logLines: StateFlow<List<String>> = _logLines.asStateFlow()

    /** Process execution events from the EDR sensor. */
    private val _execEvents = MutableStateFlow<List<ExecEvent>>(emptyList())
    val execEvents: StateFlow<List<ExecEvent>> = _execEvents.asStateFlow()

    /** SOAR playbook execution status: playbook name -> running. */
    private val _playbookStatus = MutableStateFlow<Map<String, Boolean>>(emptyMap())
    val playbookStatus: StateFlow<Map<String, Boolean>> = _playbookStatus.asStateFlow()

    /** Bundled decoy (honeypot) configuration surfaced on the topology map. */
    private val _decoys = MutableStateFlow(
        listOf(
            Triple("honeypot-ssh", "1.2.3.4", "ssh"),
            Triple("honeypot-http", "1.2.3.5", "http"),
            Triple("honeypot-mysql", "1.2.3.6", "mysql"),
        )
    )

    /** Nodes derived from live signals, merged by id. */
    val topologyNodes: StateFlow<List<NodeModel>> =
        combine(
            _attackFeed,
            _telemetry,
            _execEvents,
            _decoys,
        ) { attacks, telemetry, execs, decoys ->
            val map = mutableMapOf<String, NodeModel>()
            val counts = mutableMapOf<String, Int>()

            decoys.forEach { (id, ip, svc) ->
                map[id] = NodeModel(id = id, label = id, ip = ip, kind = "honeypot", severity = "MEDIUM")
            }

            telemetry.forEach { t ->
                if (t.node.isNotBlank()) {
                    map[t.node] = map[t.node]?.copy(kind = "host") ?: NodeModel(t.node, t.node, kind = "host")
                }
            }

            execs.forEach { e ->
                counts[e.node] = (counts[e.node] ?: 0) + 1
                if (e.node.isNotBlank()) {
                    map[e.node] = map[e.node]?.copy(kind = "exec")
                        ?: NodeModel(e.node, e.node, kind = "exec", severity = if (e.anomaly) "HIGH" else "LOW")
                }
            }

            attacks.forEach { a ->
                val src = map[a.sourceIp]
                    ?.copy(kind = "source", severity = a.severity)
                    ?: NodeModel(a.sourceIp, a.sourceIp, ip = a.sourceIp, kind = "source", severity = a.severity)
                val targetId = "svc:${a.targetPort}"
                val target = map[targetId]
                    ?.copy(kind = "target", severity = a.severity)
                    ?: NodeModel(targetId, "svc:${a.targetPort}", kind = "target", severity = a.severity)
                map[a.sourceIp] = src
                map[targetId] = target
            }

            // Merge low-signal exec hosts back into the attacker nodes when they share an ip.
            map.values.map { n ->
                if (n.kind == "exec" && (counts[n.id] ?: 0) > 0 && map.containsKey(n.id)) {
                    n.copy(children = n.children + listOf("exec:${counts[n.id]}"))
                } else n
            }
        }
        .stateIn(scope, SharingStarted.Eagerly, emptyList())

    /** Edges derived from scan/attack/exec relationships. */
    val topologyEdges: StateFlow<List<EdgeModel>> =
        combine(
            _attackFeed,
            _execEvents,
        ) { attacks, execs ->
            val edges = mutableListOf<EdgeModel>()
            attacks.forEach { a ->
                edges += EdgeModel(a.sourceIp, "svc:${a.targetPort}", "scan")
                edges += EdgeModel(a.sourceIp, a.sourceIp, "attack")
            }
            execs.forEach { e ->
                if (e.node.isNotBlank()) edges += EdgeModel(e.node, e.node, "exec")
            }
            edges.distinct().takeLast(200)
        }
        .stateIn(scope, SharingStarted.Eagerly, emptyList())

    /** Connection statistics derived from the live feed. */
    val eventCount: StateFlow<Int> = MutableStateFlow(0).also { s ->
        scope.launch {
            while (true) {
                s.value = _attackFeed.value.size
                delay(2000)
            }
        }
    }

    private var client: AegisXClient? = null
    private var seq = 0

    fun start() {
        val c = AegisXClient(host, port, scope)
        c.connect { raw ->
            dispatch(raw)
        }
        client = c

        // Synthetic heartbeat telemetry for local development when the gateway
        // is not feeding frames yet (keeps the UI "alive").
        scope.launch {
            while (true) {
                pushTelemetry(
                    TelemetryFrame(
                        node = "ui",
                        metric = "uptime",
                        value = (seq++).toDouble(),
                        timestamp = System.currentTimeMillis(),
                    )
                )
                delay(3000)
            }
        }
    }

    fun stop() {
        client?.stop()
        client = null
    }

    private fun dispatch(raw: String) {
        val type = AegisXClient.frameType(raw) ?: return
        when (type) {
            "hello" -> {
                _connected.value = true
                pushLog("gateway connected: $raw")
            }
            "attack_event" -> {
                val ev = AegisXClient.parseAttack(raw)
                if (ev != null) {
                    _attackFeed.update { (listOf(ev) + it).take(200) }
                    upsertNode(ev)
                    pushLog(formatEventLog(ev))
                }
            }
            "telemetry" -> {
                val t = runCatching {
                    json.decodeFromString(TelemetryFrame.serializer(), raw)
                }.getOrNull()
                if (t != null) pushTelemetry(t)
            }
            "command_ack" -> {
                val ack = runCatching {
                    json.decodeFromString(CommandAck.serializer(), raw)
                }.getOrNull()
                if (ack != null) pushLog("command ${ack.command} -> ${if (ack.accepted) "accepted" else "rejected"}")
            }
            "exec_event" -> {
                val ev = AegisXClient.parseExec(raw)
                if (ev != null) {
                    _execEvents.update { (listOf(ev) + it).take(400) }
                    val sign = if (ev.anomaly) "ANOMALY[${ev.anomalyType}]" else "exec"
                    pushLog("${ev.node} $sign ${ev.comm} pid=${ev.pid} ppid=${ev.ppid} user=${ev.user}${ev.detail.ifBlank { "" }}")
                }
            }
            "soar" -> {
                val d = runCatching {
                    json.parseToJsonElement(raw).jsonObject
                }.getOrNull()
                if (d != null) {
                    val playbook = d["playbook"]?.jsonPrimitive?.content ?: ""
                    val running = d["running"]?.jsonPrimitive?.content == "true"
                        || d["status"]?.jsonPrimitive?.content == "running"
                    if (playbook.isNotBlank()) {
                        _playbookStatus.update { it + (playbook to running) }
                        pushLog("soar ${if (running) "" else "(done) "}playbook: $playbook")
                    }
                }
            }
            "indicator_update" -> {
                val d = runCatching {
                    json.parseToJsonElement(raw).jsonObject
                }.getOrNull()
                if (d != null) {
                    val ioc = d["ioc"]?.jsonPrimitive?.content ?: d["indicator"]?.jsonPrimitive?.content ?: ""
                    pushLog("indicator update: ${ioc.ifBlank { "batch" }}")
                }
            }
        }
    }

    private fun pushTelemetry(t: TelemetryFrame) {
        _telemetry.update { (it + t).take(120) }
    }

    private fun pushLog(line: String) {
        _logLines.update { (it + line).take(400) }
    }

    /** Add/update the attacker node on the network map (bounded set). */
    private fun upsertNode(ev: AttackEvent) {
        _nodes.update { current ->
            val existing = current.find { it.id == ev.sourceIp }
            val ports = (existing?.ports ?: emptyList()) + ev.targetPort
            val node = NetworkNode(
                id = ev.sourceIp,
                label = ev.sourceIp,
                severity = ev.severity,
                x = Random.nextFloat() * 0.8f + 0.1f,
                y = Random.nextFloat() * 0.8f + 0.1f,
                ports = ports.distinct().take(6),
            )
            val updated = current.filterNot { it.id == ev.sourceIp } + node
            updated.takeLast(40)
        }
    }

    private fun formatEventLog(ev: AttackEvent): String =
        "${ev.timestamp} [${ev.severity}] ${ev.protocol} ${ev.sourceIp}:${ev.sourcePort} " +
            "-> :${ev.targetPort} score=${ev.threatScore} ${ev.summary}"

    /** Issue a mitigation command (fire-and-forget for now; ack updates state). */
    fun toggleMitigation(key: String, enabled: Boolean) {
        _mitigation.update { it + (key to enabled) }
        pushLog("mitigation $key ${if (enabled) "enabled" else "disabled"}")
    }
}
