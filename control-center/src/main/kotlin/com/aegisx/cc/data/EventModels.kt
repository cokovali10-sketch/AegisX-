package com.aegisx.cc.data

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/** Attack event projection received from PhishGuard over WebSocket. */
@Serializable
data class AttackEvent(
    @SerialName("event_id") val eventId: String = "",
    val protocol: String = "",
    @SerialName("source_ip") val sourceIp: String = "0.0.0.0",
    @SerialName("source_port") val sourcePort: Int = 0,
    @SerialName("target_port") val targetPort: Int = 0,
    val username: String = "",
    @SerialName("user_agent") val userAgent: String = "",
    @SerialName("threat_score") val threatScore: Double = 0.0,
    val severity: String = "LOW",
    val verdict: String = "BENIGN",
    val summary: String = "",
    val indicators: List<String> = emptyList(),
    @SerialName("related_cves") val relatedCves: List<String> = emptyList(),
    val mitigation: List<String> = emptyList(),
    val timestamp: Long = 0,
)

/** Host/system telemetry frame. */
@Serializable
data class TelemetryFrame(
    val node: String = "",
    val metric: String = "",
    val value: Double = 0.0,
    val labels: Map<String, String> = emptyMap(),
    val timestamp: Long = 0,
)

/** Command acknowledgement returned by the gateway. */
@Serializable
data class CommandAck(
    val id: String = "",
    val command: String = "",
    val target: String = "",
    val accepted: Boolean = false,
    val detail: String = "",
)

/** Visual node on the interactive network map. */
data class NetworkNode(
    val id: String,
    val label: String,
    val severity: String,
    val x: Float,
    val y: Float,
    val ports: List<Int> = emptyList(),
)

/** Process execution event reported by the sentinel/EDR sensor. */
@Serializable
data class ExecEvent(
    val pid: Long = 0,
    val ppid: Long = 0,
    val comm: String = "",
    val exe: String = "",
    val argv: List<String> = emptyList(),
    val user: String = "",
    val uid: Long = 0,
    val anomaly: Boolean = false,
    val anomalyType: String = "",
    val detail: String = "",
    val node: String = "",
)

/** A logical node on the interactive topology map. */
data class NodeModel(
    val id: String,
    val label: String,
    val ip: String = "",
    val kind: String = "host",
    val severity: String = "LOW",
    val children: List<String> = emptyList(),
)

/** A relationship edge on the interactive topology map. */
data class EdgeModel(
    val from: String,
    val to: String,
    val kind: String = "link",
)

/** Fan-out frame types the gateway may push. */
object FrameTypes {
    const val HELLO = "hello"
    const val ATTACK = "attack_event"
    const val TELEMETRY = "telemetry"
    const val COMMAND_ACK = "command_ack"
    const val EXEC = "exec_event"
    const val SOAR = "soar"
    const val INDICATOR = "indicator_update"
}