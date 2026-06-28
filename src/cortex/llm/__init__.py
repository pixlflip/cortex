"""LLM provider layer.

Backs ``semantic_search`` and (later) the Janitor through a thin provider
interface. Default provider: OpenRouter (one key, many models), defaulting to
the latest Claude Sonnet. Providers: openrouter | openai | anthropic | ollama | none.
"""

from .base import LLMError, LLMProvider, LLMResult, build_provider

__all__ = ["LLMError", "LLMProvider", "LLMResult", "build_provider"]
