"""Local embedding provider and vector helpers for hybrid retrieval.

Implements the provider half of ``docs/local-semantic-search.md``:

* :class:`EmbeddingProvider` is deliberately separate from the chat
  :class:`cortex.llm.base.LLMProvider` — embeddings are a deterministic
  retrieval input, not synthesis.
* :class:`OpenAICompatibleEmbeddings` calls ``POST {base_url}/embeddings`` (the
  OpenAI shape, which loopback Ollama also serves) with plain HTTPX, so Cortex
  never imports a model framework.
* Endpoint policy: loopback by default. A non-loopback ``base_url`` is refused
  unless the operator sets ``allow_remote: true``, because indexing sends note
  chunks (and queries send query text) to that endpoint.

Every response is validated before any vector is stored: matching count, one
consistent non-zero dimension (and the configured one, when set), finite values
and a bounded body size. Vectors are L2-normalized and packed as little-endian
``float32`` so cosine similarity is a dot product at query time.
"""

from __future__ import annotations

import ipaddress
import math
import operator
import os
import sys
from array import array
from collections.abc import Sequence
from typing import TYPE_CHECKING, Protocol
from urllib.parse import urlparse

import httpx

if TYPE_CHECKING:
    from .config import SemanticSearchConfig

#: Upper bound on an embeddings response body; a 32-chunk batch of 4096-dim
#: vectors serialized as JSON is well under this.
MAX_RESPONSE_BYTES = 64 * 1024 * 1024

PROVIDERS = ("openai-compatible",)


class EmbeddingError(RuntimeError):
    """The embedding endpoint failed or returned an invalid response."""


class EmbeddingProvider(Protocol):
    @property
    def identity(self) -> str:
        """Stable identifier stored with each vector (provider/model)."""
        ...

    def embed(self, texts: list[str]) -> list[list[float]]: ...


def is_loopback_url(url: str) -> bool:
    """True when ``url`` targets this host (127.0.0.0/8, ::1 or localhost)."""
    host = (urlparse(url).hostname or "").strip("[]").lower()
    if host == "localhost" or host.endswith(".localhost"):
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


class OpenAICompatibleEmbeddings:
    """``POST {base_url}/embeddings`` with ``{"model", "input"}``."""

    def __init__(
        self,
        *,
        base_url: str,
        model: str,
        api_key: str | None = None,
        dimensions: int | None = None,
        timeout_seconds: float = 30.0,
        transport: httpx.BaseTransport | None = None,
    ):
        if not model:
            raise EmbeddingError("an embedding model is required")
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.dimensions = dimensions
        headers = {"Content-Type": "application/json"}
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"
        # Loopback traffic must never be routed through an ambient HTTP proxy.
        self._client = httpx.Client(
            headers=headers,
            timeout=timeout_seconds,
            transport=transport,
            trust_env=not is_loopback_url(base_url),
        )

    @property
    def identity(self) -> str:
        return f"openai-compatible:{self.model}"

    def embed(self, texts: list[str]) -> list[list[float]]:
        if not texts:
            return []
        try:
            response = self._client.post(
                f"{self.base_url}/embeddings", json={"model": self.model, "input": texts}
            )
        except httpx.HTTPError as exc:
            raise EmbeddingError(f"embedding request failed: {type(exc).__name__}") from exc
        if len(response.content) > MAX_RESPONSE_BYTES:
            raise EmbeddingError("embedding response exceeds size limit")
        if response.status_code != 200:
            raise EmbeddingError(f"embedding endpoint returned HTTP {response.status_code}")
        try:
            payload = response.json()
            rows = payload["data"]
            ordered = sorted(rows, key=lambda row: int(row.get("index", 0)))
            vectors = [[float(x) for x in row["embedding"]] for row in ordered]
        except (ValueError, KeyError, TypeError, AttributeError) as exc:
            raise EmbeddingError("embedding response is malformed") from exc
        return validate_vectors(vectors, expected_count=len(texts), dimensions=self.dimensions)

    def close(self) -> None:
        self._client.close()


def validate_vectors(
    vectors: list[list[float]], *, expected_count: int, dimensions: int | None = None
) -> list[list[float]]:
    """Reject anything that would silently corrupt the index."""
    if len(vectors) != expected_count:
        raise EmbeddingError(
            f"embedding response has {len(vectors)} vectors for {expected_count} inputs"
        )
    if not vectors:
        return vectors
    width = len(vectors[0])
    if width == 0:
        raise EmbeddingError("embedding response contains an empty vector")
    if dimensions is not None and width != dimensions:
        raise EmbeddingError(f"embedding dimension {width} does not match configured {dimensions}")
    for vector in vectors:
        if len(vector) != width:
            raise EmbeddingError("embedding response mixes vector dimensions")
        if not all(math.isfinite(x) for x in vector):
            raise EmbeddingError("embedding response contains a non-finite value")
    return vectors


def build_embedding_provider(cfg: SemanticSearchConfig) -> EmbeddingProvider | None:
    """The configured provider, or None when semantic search is disabled.

    Configuration errors (unknown provider, remote URL without acknowledgment)
    are raised by :func:`cortex.config.load_config`; this only constructs.
    """
    if not cfg.enabled:
        return None
    api_key = cfg.api_key or (os.environ.get(cfg.api_key_env) if cfg.api_key_env else None)
    return OpenAICompatibleEmbeddings(
        base_url=cfg.base_url,
        model=cfg.model,
        api_key=api_key,
        dimensions=cfg.dimensions,
        timeout_seconds=cfg.timeout_seconds,
    )


# -- vector packing ------------------------------------------------------------


def pack_normalized(vector: Sequence[float]) -> bytes:
    """L2-normalize and pack as little-endian float32."""
    norm = math.sqrt(math.fsum(x * x for x in vector))
    if norm == 0.0 or not math.isfinite(norm):
        raise EmbeddingError("cannot normalize a zero or non-finite vector")
    packed = array("f", (x / norm for x in vector))
    if sys.byteorder != "little":  # pragma: no cover - big-endian hosts
        packed.byteswap()
    return packed.tobytes()


def unpack(blob: bytes) -> array:
    values = array("f")
    values.frombytes(blob)
    if sys.byteorder != "little":  # pragma: no cover - big-endian hosts
        values.byteswap()
    return values


if hasattr(math, "sumprod"):  # Python 3.12+: C-speed dot product

    def dot(a: Sequence[float], b: Sequence[float]) -> float:
        return math.sumprod(a, b)  # type: ignore[attr-defined, unused-ignore]

else:  # pragma: no cover - Python 3.11

    def dot(a: Sequence[float], b: Sequence[float]) -> float:
        return sum(map(operator.mul, a, b))


def normalized(vector: Sequence[float]) -> array:
    return unpack(pack_normalized(vector))
