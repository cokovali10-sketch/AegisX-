package com.aegisx.cc.data

import io.ktor.client.HttpClient
import io.ktor.client.engine.cio.CIO
import io.ktor.client.plugins.websocket.WebSockets
import io.ktor.client.plugins.websocket.webSocket
import io.ktor.http.HttpMethod
import io.ktor.websocket.Frame
import io.ktor.websocket.readText
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

/**
 * Real-time event stream client.
 *
 * Connects to PhishGuard's `/ws/events` WebSocket and dispatches decoded frames
 * to the provided callback. Reconnects with bounded exponential backoff.
 */
class AegisXClient(
    private val host: String,
    private val port: Int,
    private val scope: CoroutineScope,
) {
    private val client = HttpClient(CIO) {
        install(WebSockets)
        expectSuccess = true
    }
    private val json = Json { ignoreUnknownKeys = true; isLenient = true }
    private var job: Job? = null

    /** `onFrame` receives the raw JSON string; deserialization is the caller's job. */
    fun connect(onFrame: (String) -> Unit) {
        job?.cancel()
        job = scope.launch {
            var backoffMs = 500L
            while (isActive) {
                try {
                    client.webSocket(
                        method = HttpMethod.Get,
                        host = host,
                        port = port,
                        path = "/ws/events",
                    ) {
                        backoffMs = 500L
                        for (frame in incoming) {
                            if (frame is Frame.Text) {
                                val text = frame.readText()
                                onFrame(text)
                                if (text.isNotBlank()) classify(text) // no-op helper kept
                            }
                        }
                    }
                } catch (ce: CancellationException) {
                    throw ce
                } catch (e: Exception) {
                    // Connection lost - retry after backoff.
                }
                delay(backoffMs)
                backoffMs = (backoffMs * 2).coerceAtMost(15_000)
            }
        }
    }

    fun stop() {
        job?.cancel()
        job = null
    }

    private fun classify(_text: String) {
        // Reserved: typed dispatch handled in AegisXState for cohesion.
    }

    companion object {
        /** Extract the `type` discriminator from a raw frame. */
        fun frameType(raw: String): String? = runCatching {
            Json { ignoreUnknownKeys = true }
                .parseToJsonElement(raw)
                .jsonObject["type"]?.jsonPrimitive?.content
        }.getOrNull()

        fun parseAttack(raw: String): AttackEvent? = runCatching {
            Json { ignoreUnknownKeys = true }.decodeFromString(AttackEvent.serializer(), raw)
        }.getOrNull()

        fun parseExec(raw: String): ExecEvent? = runCatching {
            Json { ignoreUnknownKeys = true }.decodeFromString(ExecEvent.serializer(), raw)
        }.getOrNull()
    }
}