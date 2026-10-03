"""Zero-question setup: discovery finds local servers and env keys; pass-through cloud targets route by '<target>/<model>'."""

from __future__ import annotations

import httpx
import pytest
from starlette.testclient import TestClient

from endorouter import Label, decide, discover
from endorouter.config import parse_config
from endorouter.router import Router
from endorouter.server import create_app


def test_auto_config_finds_local_and_env_keys(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path))
    monkeypatch.setattr(discover, "find_local", lambda timeout=1.0: ([("ollama", "http://127.0.0.1:11434/v1", "qwen3:8b", "ollama", True)], []))
    for _, env, _ in discover.CLOUD_PROVIDERS:
        monkeypatch.delenv(env, raising=False)
    monkeypatch.setenv("OPENAI_API_KEY", "x")
    raw, notes = discover.auto_config()
    cfg = parse_config(raw)
    assert cfg.mode == "strict" and cfg.target("ollama").is_local and cfg.target("openai").model == "*"
    assert "**/.env*" in cfg.provenance.private_sources and cfg.provenance.public_sources == ()
    assert cfg.target("ollama").verify_program == "ollama"


def test_no_local_server_is_a_clear_error(monkeypatch):
    monkeypatch.setattr(discover, "find_local", lambda timeout=1.0: ([], []))
    with pytest.raises(RuntimeError, match="no verified local model server"):
        discover.auto_config()


def _cfg(tmp_path):
    return parse_config({"version": 1, "audit_log": str(tmp_path / "a.jsonl"), "targets": {
        "local": {"url": "http://local.test/v1", "model": "m", "location": "local"},
        "openai": {"url": "https://cloud.test/v1", "model": "*", "location": "cloud", "api_key_env": "K"}}})


def test_auto_never_selects_a_pass_through_target(tmp_path):
    assert decide(_cfg(tmp_path), declared=Label.PUBLIC).permitted == ("local",)


def test_pass_through_needs_public_and_sends_the_named_model(tmp_path):
    sent = []

    def up(req):
        sent.append((req.url.host, req.content))
        return httpx.Response(200, json={"choices": [{"message": {"content": "ok"}}]})

    cfg = _cfg(tmp_path)
    app = create_app(cfg, Router(cfg, client=httpx.AsyncClient(transport=httpx.MockTransport(up), trust_env=False)))
    c = TestClient(app, base_url="http://127.0.0.1", client=("127.0.0.1", 5000))
    body = {"model": "openai/gpt-5", "messages": [{"role": "user", "content": "hi"}]}
    assert c.post("/v1/chat/completions", json=body).status_code == 403 and sent == []  # unknown: refused
    r = c.post("/v1/chat/completions", json=body, headers={"x-endorouter-label": "public"})
    assert r.status_code == 200 and sent[0][0] == "cloud.test" and b'"model":"gpt-5"' in sent[0][1].replace(b" ", b"")
