"""LLM provider layer + semantic_search wiring tests.

Network is never touched: the OpenAI-compatible HTTP call is monkeypatched, and
semantic_search is exercised against a stub provider so we can assert that
scoping is preserved (the model only ever sees notes the principal may read).
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest

from cortex.config import CortexConfig, IndexConfig, LLMConfig, Principal, VaultConfig
from cortex.llm import LLMError, LLMResult, build_provider
from cortex.server import CortexServer


# -- build_provider --------------------------------------------------------

def test_build_provider_none():
    assert build_provider(LLMConfig(provider="none")) is None


def test_build_provider_openrouter_needs_key():
    with pytest.raises(LLMError):
        build_provider(LLMConfig(provider="openrouter"))


def test_build_provider_openrouter_defaults():
    p = build_provider(LLMConfig(provider="openrouter", api_key="sk-test"))
    assert p.url == "https://openrouter.ai/api/v1/chat/completions"
    assert p.model == "anthropic/claude-sonnet-4.6"  # latest Claude Sonnet


def test_build_provider_openai_needs_model():
    with pytest.raises(LLMError):
        build_provider(LLMConfig(provider="openai", api_key="sk-test"))


def test_build_provider_unknown():
    with pytest.raises(LLMError):
        build_provider(LLMConfig(provider="bogus", api_key="x"))


# -- OpenAI-compatible HTTP (mocked) --------------------------------------

def test_openai_compat_complete(monkeypatch):
    import cortex.llm.openai_compat as oc

    captured = {}

    class FakeResp:
        def __init__(self, data: bytes):
            self._d = data

        def read(self):
            return self._d

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    def fake_urlopen(req, timeout=0):
        captured["url"] = req.full_url
        captured["body"] = json.loads(req.data.decode())
        return FakeResp(
            json.dumps(
                {"model": "served-model", "choices": [{"message": {"content": "hi"}}]}
            ).encode()
        )

    monkeypatch.setattr(oc.urllib.request, "urlopen", fake_urlopen)

    p = oc.OpenAICompatProvider(base_url="https://x/api/v1", api_key="k", model="mod")
    r = p.complete(system="S", prompt="P", max_tokens=10)

    assert r.text == "hi"
    assert r.model == "served-model"
    assert captured["url"].endswith("/chat/completions")
    assert captured["body"]["model"] == "mod"
    assert captured["body"]["messages"][0] == {"role": "system", "content": "S"}
    assert captured["body"]["messages"][1] == {"role": "user", "content": "P"}


def test_openai_compat_http_error_becomes_llmerror(monkeypatch):
    import urllib.error
    import cortex.llm.openai_compat as oc

    def boom(req, timeout=0):
        raise urllib.error.HTTPError(req.full_url, 401, "Unauthorized", {}, None)

    monkeypatch.setattr(oc.urllib.request, "urlopen", boom)
    p = oc.OpenAICompatProvider(base_url="https://x/v1", api_key="bad", model="m")
    with pytest.raises(LLMError):
        p.complete(system="s", prompt="p", max_tokens=5)


# -- semantic_search wiring (stub provider, scope-preserving) -------------

class StubProvider:
    """Records the prompt it's handed and returns a canned answer."""

    def __init__(self):
        self.last_prompt = None

    def complete(self, *, system, prompt, max_tokens):
        self.last_prompt = prompt
        return LLMResult(text="STUB ANSWER", model="stub-model")


@pytest.fixture
def vault(tmp_path: Path) -> Path:
    root = tmp_path / "vault"
    (root / "Welcome").mkdir(parents=True)
    (root / "Public").mkdir()
    (root / "Welcome" / "hello.md").write_text(
        "# Hello\n\nshared-term unique-welcome\n", encoding="utf-8"
    )
    (root / "Public" / "open.md").write_text(
        "# Open\n\nshared-term unique-public\n", encoding="utf-8"
    )
    return root


def _server(vault: Path, scopes: list[str]) -> CortexServer:
    cfg = CortexConfig(
        vault=VaultConfig(path=vault),
        # Keep the search index's SQLite file inside the tmp_path sandbox —
        # otherwise its dataclass default resolves against the test runner's
        # CWD instead of a throwaway directory.
        index=IndexConfig(path=vault.parent / "cortex.index.sqlite"),
    )  # llm defaults to provider=none
    return CortexServer(cfg, Principal(name="p", scopes=scopes))


def _call(srv: CortexServer, name: str, **kw) -> str:
    # FastMCP returns either a bare list of content blocks, or a
    # (blocks, structured_content) tuple when the tool has structured output.
    res = asyncio.run(srv.mcp.call_tool(name, kw))
    blocks = res[0] if isinstance(res, tuple) else res
    return blocks[0].text


def test_semantic_search_disabled_when_no_provider(vault: Path):
    srv = _server(vault, ["**"])
    assert srv.provider is None
    out = _call(srv, "semantic_search", question="anything")
    assert "disabled" in out.lower()


def test_semantic_search_synthesizes_with_provider(vault: Path):
    srv = _server(vault, ["**"])
    srv.provider = StubProvider()
    out = _call(srv, "semantic_search", question="shared-term")
    assert "STUB ANSWER" in out
    assert "stub-model" in out  # footer cites the model
    # Both notes are visible, so both feed the prompt.
    assert "unique-welcome" in srv.provider.last_prompt
    assert "unique-public" in srv.provider.last_prompt


def test_semantic_search_respects_scope(vault: Path):
    srv = _server(vault, ["Public/**"])  # cannot see Welcome/
    srv.provider = StubProvider()
    out = _call(srv, "semantic_search", question="shared-term")
    # The out-of-scope note must NOT reach the model.
    assert "unique-welcome" not in srv.provider.last_prompt
    assert "unique-public" in srv.provider.last_prompt
    assert "Public/open.md" in out
    assert "Welcome/hello.md" not in out


def test_semantic_search_no_matches_in_scope(vault: Path):
    srv = _server(vault, ["Public/**"])
    srv.provider = StubProvider()
    out = _call(srv, "semantic_search", question="unique-welcome")  # only in Welcome
    assert "nothing to synthesize" in out.lower()
    assert srv.provider.last_prompt is None  # model never called
