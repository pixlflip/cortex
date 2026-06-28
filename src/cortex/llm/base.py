"""LLM provider abstraction.

A thin, synchronous ``complete(system, prompt) -> text`` interface backs the one
non-deterministic MCP tool (``semantic_search``) and, later, the Janitor.

Providers:

* ``openrouter`` *(default)* — OpenAI-compatible gateway, one key for many
  models. Default model: the latest Claude Sonnet (``anthropic/claude-sonnet-4.6``).
* ``openai`` — any OpenAI-compatible endpoint.
* ``ollama`` — local models via Ollama's OpenAI-compatible endpoint (no key).
* ``anthropic`` — the Anthropic API directly, via the official SDK.
* ``none`` — disabled; semantic search returns a clear notice instead.

The OpenAI-compatible providers use the standard library only, so the core
install stays dependency-free. The ``anthropic`` provider uses the official
``anthropic`` SDK (install the ``anthropic`` extra).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from ..config import LLMConfig

# Default model per provider when config leaves llm.model blank.
DEFAULT_MODELS = {
    "openrouter": "anthropic/claude-sonnet-4.6",  # latest Claude Sonnet
    "anthropic": "claude-sonnet-4-6",
    # openai/ollama have no universal default — the user must name a model.
}

DEFAULT_BASE_URLS = {
    "openrouter": "https://openrouter.ai/api/v1",
    "openai": "https://api.openai.com/v1",
    "ollama": "http://localhost:11434/v1",
}


class LLMError(Exception):
    """Raised for provider configuration or call failures."""


@dataclass
class LLMResult:
    text: str
    model: str


@runtime_checkable
class LLMProvider(Protocol):
    def complete(self, *, system: str, prompt: str, max_tokens: int) -> LLMResult: ...


def build_provider(cfg: LLMConfig) -> LLMProvider | None:
    """Construct the configured provider, or None if disabled (``provider: none``).

    Raises LLMError if a provider that needs a key is missing one, so the
    failure surfaces at startup rather than on the first semantic search.
    """
    provider = (cfg.provider or "none").lower()
    if provider == "none":
        return None

    model = cfg.model or DEFAULT_MODELS.get(provider, "")

    if provider in ("openrouter", "openai", "ollama"):
        from .openai_compat import OpenAICompatProvider

        base_url = cfg.base_url or DEFAULT_BASE_URLS[provider]
        # Ollama runs locally and needs no real key; the others do.
        api_key = cfg.api_key or ("ollama" if provider == "ollama" else None)
        if api_key is None:
            raise LLMError(
                f"llm.provider '{provider}' requires an API key; set "
                f"llm.api_key_env to an env var holding it."
            )
        if not model:
            raise LLMError(f"llm.provider '{provider}' requires llm.model to be set.")
        return OpenAICompatProvider(
            base_url=base_url,
            api_key=api_key,
            model=model,
            extra_headers=cfg.options.get("headers", {}) or {},
            timeout=int(cfg.options.get("timeout", 60)),
        )

    if provider == "anthropic":
        from .anthropic_provider import AnthropicProvider

        if not cfg.api_key:
            raise LLMError(
                "llm.provider 'anthropic' requires an API key; set llm.api_key_env."
            )
        return AnthropicProvider(api_key=cfg.api_key, model=model, base_url=cfg.base_url)

    raise LLMError(f"unknown llm.provider '{cfg.provider}'")
