"""Review round 11 (launch review, second pass): every confirmed finding reproduced, then pinned."""

from __future__ import annotations

import asyncio
import json

import httpx
import pytest
from starlette.testclient import TestClient

from endorouter import discover
from endorouter.audit import AuditError
from endorouter.classifier import classify
from endorouter.config import Classifier, Config, ConfigError, Target
from endorouter.labels import Label
from endorouter.policy import source_label
from endorouter.router import Router, SentUnrecorded
from endorouter.server import create_app
from endorouter.validate import InvalidRequest, validate
from tests.test_review_1 import _balanced
from tests.test_router import make_cfg

BODY = {"model": "auto", "messages": [{"role": "user", "content": "hi"}]}


def _client(app, **kw):
    return TestClient(app, base_url="http://127.0.0.1", **kw)


def test_an_audit_failure_after_a_fallback_says_sent_not_nothing_sent(tmp_path, monkeypatch):
    cfg = make_cfg(tmp_path, extra_local=True)
    hosts = []

    def up(req):
        hosts.append(req.url.host)
        return httpx.Response(500 if req.url.host == "local.test" else 200, json={"choices": []})

    router = Router(cfg, client=httpx.AsyncClient(transport=httpx.MockTransport(up), trust_env=False))
    real = router.audit.write
    attempts = []

    def write(rec):
        if rec.get("event") == "attempt":
            attempts.append(rec)
            if len(attempts) == 2:  # the first target already holds the prompt
                raise AuditError("disk full")
        return real(rec)

    monkeypatch.setattr(router.audit, "write", write)
    with pytest.raises(SentUnrecorded) as e:
        asyncio.run(router.route(BODY))
    assert hosts == ["local.test"] and e.value.target == "local"
    attempts.clear()
    r = _client(create_app(cfg, router)).post("/v1/chat/completions", json=BODY)
    assert r.status_code == 502 and "sent, but not recorded" in r.text


def test_a_lone_surrogate_is_refused_anywhere():
    for body in ({"messages": [{"role": "user", "content": "AKIA\ud800IOSFODNN7EXAMPLE"}]},
                 {"messages": [{"role": "user", "content": "hi"}], "metadata": {"k\udfff": "v"}}):
        assert "surrogate" in validate(body)


def test_a_lone_surrogate_never_reaches_a_target(tmp_path):
    sent = []
    router = Router(make_cfg(tmp_path), client=httpx.AsyncClient(
        transport=httpx.MockTransport(lambda r: sent.append(r) or httpx.Response(200, json={})), trust_env=False))
    with pytest.raises(InvalidRequest):
        asyncio.run(router.route({"model": "auto", "messages": [{"role": "user", "content": "x\ud800y"}]},
                                 declared=Label.PUBLIC))
    assert sent == []


@pytest.mark.parametrize("path,method", [("/v1/chat/completions", "post"), ("/v1/models", "get"), ("/healthz", "get")])
def test_a_web_page_is_refused_on_every_route(tmp_path, path, method):
    app = create_app(make_cfg(tmp_path))
    kw = {"json": BODY} if method == "post" else {}
    r = getattr(_client(app), method)(path, headers={"origin": "https://evil.example"}, **kw)
    assert r.status_code == 403
    r = getattr(TestClient(app, base_url="http://attacker.example"), method)(path, **kw)
    assert r.status_code == 421


def test_a_simple_cross_site_post_is_refused(tmp_path):
    r = _client(create_app(make_cfg(tmp_path))).post("/v1/chat/completions", content=json.dumps(BODY),
                                                     headers={"content-type": "text/plain"})
    assert r.status_code == 415


@pytest.mark.parametrize("raw", [b"[" * 100000 + b"]" * 100000, b'{"n": ' + b"9" * 5000 + b"}"])
def test_hostile_json_is_a_400_not_a_crash(tmp_path, raw):
    r = _client(create_app(make_cfg(tmp_path))).post("/v1/chat/completions", content=raw,
                                                     headers={"content-type": "application/json"})
    assert r.status_code == 400


def test_a_content_length_too_long_to_convert_is_413(tmp_path):
    from endorouter.server import _read_body

    class Req:
        headers = {"content-length": "9" * 5000}

    assert asyncio.run(_read_body(Req())) is None


def test_an_oversized_source_header_is_refused_unread(tmp_path):
    hosts = []
    cfg = make_cfg(tmp_path)
    router = Router(cfg, client=httpx.AsyncClient(
        transport=httpx.MockTransport(lambda r: hosts.append(r.url.host) or httpx.Response(200, json={})),
        trust_env=False))
    r = _client(create_app(cfg, router), client=("127.0.0.1", 1)).post(
        "/v1/chat/completions", json={**BODY, "model": "cloud/cm"},
        headers={"x-endorouter-source": "docs/public/" + "a/" * 2000 + "x.md", "x-endorouter-label": "public"})
    assert r.status_code == 400 and hosts == []


def test_a_classifier_answer_that_is_not_utf8_is_recorded(tmp_path):
    kinds = []
    client = httpx.AsyncClient(transport=httpx.MockTransport(lambda r: httpx.Response(200, content=b'{"a":"\xff"}')),
                               trust_env=False)
    assert asyncio.run(classify(_balanced(tmp_path), {"messages": [{"role": "user", "content": "hi"}]}, client,
                                on_failure=kinds.append)) is None
    assert kinds == ["malformed_response"]


def test_classifier_invariants_hold_for_a_config_built_directly():
    local = Target("l", "http://127.0.0.1/v1", "m", "local")
    cloud = Target("c", "https://c/v1", "m", "cloud")
    with pytest.raises(ConfigError, match="local target"):
        Config(targets=(local, cloud), classifier=Classifier(enabled=True, target="c"))
    with pytest.raises(ConfigError, match="balanced"):
        Config(targets=(local,), mode="balanced")


def test_a_decomposed_path_matches_its_private_pattern():
    cfg = make_cfg_with_private(["café/**"])
    assert source_label("café/plan.md", cfg)[0] is Label.PRIVATE


def make_cfg_with_private(globs):
    from endorouter.config import parse_config
    return parse_config({"version": 1, "targets": {"l": {"url": "http://127.0.0.1/v1", "model": "m", "location": "local"}},
                         "provenance": {"private_sources": globs}})


@pytest.mark.parametrize("cmd", ["/usr/bin/python3\0/usr/bin/python3 /home/me/bin/ollama serve",
                                 "/usr/bin/python3\0/usr/bin/python3 -m ollama", "/usr/bin/python3 llama-server"])
def test_a_python_program_named_after_a_native_server_is_not_it(cmd):
    assert discover._program(cmd) is None


def test_on_linux_the_executable_comes_from_the_kernel_not_the_title(monkeypatch):
    monkeypatch.setattr(discover.Path, "exists", lambda self: str(self) == "/proc/self/exe")
    monkeypatch.setattr(discover.os, "readlink", lambda p: "/usr/bin/python3.12")
    assert discover._executable("4242") == "/usr/bin/python3.12"
    monkeypatch.setattr(discover.os, "readlink", lambda p: (_ for _ in ()).throw(PermissionError()))
    assert discover._executable("4242") is None
