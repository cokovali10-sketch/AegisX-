"""Vector similarity store for past attack signatures (ChromaDB/Qdrant).

Stores normalized attack fingerprints and answers "has anything like this been
seen before?" queries. The store is optional: when ChromaDB is not installed or
disabled, all calls are no-ops and the pipeline continues without it.
"""
from __future__ import annotations

import hashlib
import logging
from typing import Optional

logger = logging.getLogger(__name__)


class VectorStore:
    """Thin wrapper with graceful degradation to a no-op."""

    def __init__(self, persist_path: str = "/var/lib/aegisx/chroma", enabled: bool = True):
        self._client = None
        self._collection = None
        self.enabled = enabled
        if not enabled:
            logger.info("vector store disabled by configuration")
            return
        try:
            import chromadb  # type: ignore

            client = chromadb.PersistentClient(path=persist_path)
            self._collection = client.get_or_create_collection(
                name="aegisx_attack_signatures",
                metadata={"hnsw:space": "cosine"},
            )
            self._client = client
            logger.info("vector store ready at %s", persist_path)
        except Exception as exc:  # import error or runtime failure
            self.enabled = False
            logger.warning("vector store unavailable (continuing without it): %s", exc)

    def _features(self, event: dict) -> str:
        """Deterministic textual fingerprint used to build the embedding."""
        proto = event.get("protocol", "")
        payload = (event.get("payload") or "")[:2048]
        user = event.get("username", "")
        path = event.get("path", "")
        return " ".join([proto, user, path, payload]).strip()

    def add_event(self, event: dict, verdict: str) -> Optional[str]:
        """Ingest one scored event into the signature collection."""
        if not self.enabled or self._collection is None:
            return None
        doc_id = hashlib.sha256(self._features(event).encode()).hexdigest()[:16]
        try:
            self._collection.upsert(
                ids=[doc_id],
                documents=[self._features(event)],
                metadatas=[{
                    "verdict": verdict,
                    "protocol": event.get("protocol", ""),
                    "source_ip": event.get("source_ip", ""),
                }],
            )
            return doc_id
        except Exception as exc:
            logger.debug("vector upsert failed: %s", exc)
            return None

    def query_similar(self, event: dict, top_k: int = 5) -> list[dict]:
        """Return the most similar historical signatures."""
        if not self.enabled or self._collection is None:
            return []
        try:
            results = self._collection.query(
                query_texts=[self._features(event)],
                n_results=top_k,
                include=["metadatas", "distances"],
            )
            meta = results.get("metadatas", [[]])
            dist = results.get("distances", [[]])
            if not meta:
                return []
            out = []
            for m, d in zip(meta[0], dist[0] or []):
                m = dict(m)
                m["distance"] = float(d)
                out.append(m)
            return out
        except Exception as exc:
            logger.debug("vector query failed: %s", exc)
            return []

    def stats(self) -> dict:
        if self.enabled and self._collection is not None:
            try:
                return {"enabled": True, "signatures": self._collection.count()}
            except Exception:
                pass
        return {"enabled": False, "signatures": 0}
