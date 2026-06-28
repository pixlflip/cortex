"""OpenAI-compatible chat-completions provider.

Covers OpenRouter (default), OpenAI, and Ollama — all expose the same
``POST {base_url}/chat/completions`` shape. Implemented with the standard
library so the core package needs no extra dependencies.

``temperature`` is intentionally not sent: some current models (e.g. Claude
Opus 4.8/4.7) reject sampling parameters, and synthesis doesn't need it. Add it
via config later if a use case requires it.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request

from .base import LLMError, LLMResult


class OpenAICompatProvider:
    def __init__(
        self,
        *,
        base_url: str,
        api_key: str,
        model: str,
        extra_headers: dict | None = None,
        timeout: int = 60,
    ):
        self.url = base_url.rstrip("/") + "/chat/completions"
        self.api_key = api_key
        self.model = model
        self.extra_headers = extra_headers or {}
        self.timeout = timeout

    def complete(self, *, system: str, prompt: str, max_tokens: int) -> LLMResult:
        body = json.dumps(
            {
                "model": self.model,
                "max_tokens": max_tokens,
                "messages": [
                    {"role": "system", "content": system},
                    {"role": "user", "content": prompt},
                ],
            }
        ).encode("utf-8")

        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
            # OpenRouter uses these for attribution; harmless elsewhere.
            "HTTP-Referer": "https://github.com/pixlflip/cortex",
            "X-Title": "Cortex",
            **self.extra_headers,
        }
        req = urllib.request.Request(self.url, data=body, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                data = json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", "replace")[:500]
            raise LLMError(f"LLM request failed ({exc.code}): {detail}") from exc
        except urllib.error.URLError as exc:
            raise LLMError(f"LLM request failed: {exc.reason}") from exc

        try:
            text = data["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError) as exc:
            raise LLMError(f"unexpected LLM response shape: {str(data)[:300]}") from exc
        return LLMResult(text=text or "", model=data.get("model", self.model))
