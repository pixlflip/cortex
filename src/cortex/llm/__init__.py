"""LLM provider layer (build step 7).

Backs ``semantic_search`` and the Janitor through a thin provider interface.
Default provider: OpenRouter (one key, many models), defaulting to the latest
Claude Sonnet. Providers: openrouter | openai | anthropic | ollama | none.
"""
