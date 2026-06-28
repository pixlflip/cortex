"""Anthropic provider — uses the official ``anthropic`` SDK.

Selected when ``llm.provider: anthropic``. Requires the optional dependency:
``pip install cortex-memory[anthropic]``. The default provider is OpenRouter, so
the core install does not pull this in.

``semantic_search`` is a synchronous, interactive retrieval-synthesis call, so
this issues a plain completion (no extended thinking) for low latency; the model
answers from the scoped context it's given. Default model: the latest Claude
Sonnet (``claude-sonnet-4-6``).
"""

from __future__ import annotations

from .base import LLMError, LLMResult


class AnthropicProvider:
    def __init__(self, *, api_key: str, model: str, base_url: str | None = None):
        try:
            import anthropic
        except ImportError as exc:  # pragma: no cover - exercised via packaging
            raise LLMError(
                "llm.provider 'anthropic' needs the anthropic SDK: "
                "pip install 'cortex-memory[anthropic]' (or use provider 'openrouter')."
            ) from exc
        kwargs = {"api_key": api_key}
        if base_url:
            kwargs["base_url"] = base_url
        self._client = anthropic.Anthropic(**kwargs)
        self.model = model or "claude-sonnet-4-6"

    def complete(self, *, system: str, prompt: str, max_tokens: int) -> LLMResult:
        try:
            resp = self._client.messages.create(
                model=self.model,
                max_tokens=max_tokens,
                system=system,
                messages=[{"role": "user", "content": prompt}],
            )
        except Exception as exc:  # surface SDK/HTTP errors uniformly
            raise LLMError(f"Anthropic request failed: {exc}") from exc
        text = "".join(b.text for b in resp.content if getattr(b, "type", None) == "text")
        return LLMResult(text=text, model=getattr(resp, "model", self.model))
