"""Regressions for the 2026-09-30 external review (QC round 1). Each test reproduces a finding, then pins the fix."""

from __future__ import annotations

import json

import httpx
import pytest
from starlette.testclient import TestClient

from endorouter import ConfigError, Label, decide
from endorouter.audit import AuditLog
from endorouter.classifier import classify
from endorouter.config import parse_config
from endorouter.detectors import scan_request, scan_text
from endorouter.router import Router
from endorouter.server import create_app

from tests.test_router import Upstream, make_cfg

AWS = "AKIAIOSFODNN7EXAMPLE"


def client_for(tmp_path, up, **kw):
    cfg = make_cfg(tmp_path, **kw)
    router = Router(cfg, client=httpx.AsyncClient(transport=httpx.MockTransport(up), trust_env=False))
    return TestClient(create_app(cfg, router), client=("127.0.0.1", 5000)), cfg


# 1. repeated provenance headers
def test_repeated_label_headers_combine_most_restrictive(tmp_path):
    up = Upstream()
    c, _ = client_for(tmp_path, up)
    r = c.post("/v1/chat/completions", json={"model": "cloud", "messages": [{"role": "user", "content": "hi"}]},
               headers=[("x-sovereign-label", "public"), ("x-sovereign-label", "private")])
    assert r.status_code == 403 and up.calls == []


def test_invalid_label_token_is_an_error_not_ignored(tmp_path):
    up = Upstream()
    c, _ = client_for(tmp_path, up)
    r = c.post("/v1/chat/completions", json={"model": "cloud", "messages": [{"role": "user", "content": "hi"}]},
               headers={"x-sovereign-label": "public, privtae"})
    assert r.status_code == 400 and up.calls == []


def test_repeated_source_headers_are_all_read(tmp_path):
    up = Upstream()
    c, _ = client_for(tmp_path, up)
    r = c.post("/v1/chat/completions", json={"model": "cloud", "messages": [{"role": "user", "content": "hi"}]},
               headers=[("x-sovereign-sources", "docs/public/a.md"), ("x-sovereign-sources", "clients/acme/a.md")])
    assert r.status_code == 403 and up.calls == []


# 2. forwarded headers (serve disables proxy headers; checked at the call site)
def test_serve_disables_proxy_headers():
    import inspect

    from endorouter import cli

    src = inspect.getsource(cli.cmd_serve)
    assert "proxy_headers=False" in src


# 3. injected client that follows redirects
def test_injected_redirect_following_client_still_never_follows(tmp_path):
    up = Upstream({"local.test": "redirect"})
    cfg = make_cfg(tmp_path)
    router = Router(cfg, client=httpx.AsyncClient(transport=httpx.MockTransport(up), follow_redirects=True, trust_env=False))
    r = TestClient(create_app(cfg, router)).post("/v1/chat/completions",
                                                 json={"model": "auto", "messages": [{"role": "user", "content": AWS}]})
    assert r.status_code == 502 and "evil.test" not in up.calls


# 4-6. detector gaps
@pytest.mark.parametrize("body,rule", [
    ({"messages": [{"role": "user", "content": "x"}], "response_format": {"type": "json_schema", "json_schema": {
        "schema": {"properties": {"card": {"default": 4242424242424242}}}}}}, "payment_card"),
    ({"messages": [{"role": "assistant", "content": None, "tool_calls": [{"id": "1", "type": "function", "function": {
        "name": "f", "arguments": ' {"k":"\\u0041KIAIOSFODNN7EXAMPLE"}'}}]}]}, "aws_access_key"),
])
def test_numeric_leaves_and_whitespace_prefixed_json_are_scanned(body, rule):
    assert rule in {f.rule for f in scan_request(body)}


@pytest.mark.parametrize("text", [
    "AKIA⁣IOSFODNN7EXAMPLE",          # invisible separator
    "AKIA­IOSFODNN7EXAMPLE",          # soft hyphen
    "АKIAIOSFODNN7EXAMPLE",           # Cyrillic A
    "creds: QUtJQUlPU0ZPRE5ON0VYQU1QTEU=",  # base64
])
def test_invisible_characters_confusables_and_base64_are_seen(text):
    assert any(f.rule == "aws_access_key" for f in scan_text(text, "x"))


def test_deeply_nested_json_in_a_string_counts_as_a_finding():
    deep = "[" * 100_000 + "]" * 100_000
    body = {"messages": [{"role": "assistant", "content": None, "tool_calls": [
        {"id": "1", "type": "function", "function": {"name": "f", "arguments": deep}}]}]}
    assert "undecodable_nested_json" in {f.rule for f in scan_request(body)}


# 8. URL traversal
@pytest.mark.parametrize("source", ["https://example.com/public/../private/plan", "https://example.com/public/%2e%2e/private/plan"])
def test_url_dot_segments_resolve_before_matching(source):
    c = make_cfg_url()
    assert decide(c, sources=[source]).label is Label.PRIVATE


def make_cfg_url():
    return parse_config({"version": 1, "targets": {
        "l": {"url": "http://127.0.0.1/v1", "model": "m", "location": "local"},
        "c": {"url": "https://x/v1", "model": "m", "location": "cloud"}},
        "provenance": {"public_sources": ["https://example.com/public/**"], "private_sources": ["https://example.com/private/**"]}})


# 9. classifier
def _balanced(tmp_path):
    return parse_config({"version": 1, "mode": "balanced", "audit_log": str(tmp_path / "a.jsonl"), "targets": {
        "l": {"url": "http://local.test/v1", "model": "m", "location": "local"},
        "c": {"url": "https://cloud.test/v1", "model": "m", "location": "cloud"}},
        "classifier": {"enabled": True, "target": "l"}})


def _answering(text):
    return httpx.AsyncClient(transport=httpx.MockTransport(
        lambda r: httpx.Response(200, json={"choices": [{"message": {"content": text}}]})))


@pytest.mark.parametrize("answer,expected", [("PUBLIC", Label.PUBLIC), ("public.", Label.PUBLIC), ("not PUBLIC", None),
                                             ("PUBLIC or PRIVATE", None), ("PRIVATE", Label.PRIVATE)])
def test_classifier_needs_an_exact_verdict(tmp_path, answer, expected):
    import asyncio

    got = asyncio.run(classify(_balanced(tmp_path), {"messages": [{"role": "user", "content": "hi"}]}, _answering(answer)))
    assert got is expected


def test_classifier_never_clears_text_it_did_not_read(tmp_path):
    import asyncio

    body = {"messages": [{"role": "user", "content": "benign " * 3000 + "we acquire Acme on Friday"}]}
    assert asyncio.run(classify(_balanced(tmp_path), body, _answering("PUBLIC"))) is None


# 10. config booleans
@pytest.mark.parametrize("value", ["false", "flase", 1])
def test_classifier_enabled_must_be_a_real_boolean(value):
    with pytest.raises(ConfigError, match="true or false"):
        parse_config({"version": 1, "targets": {"l": {"url": "http://127.0.0.1/v1", "model": "m", "location": "local"}},
                      "classifier": {"enabled": value, "target": "l"}})


# 11. classifier dispatch is audited first
def test_classifier_send_is_blocked_when_audit_fails(tmp_path):
    calls = []
    cfg = _balanced(tmp_path)
    client = httpx.AsyncClient(transport=httpx.MockTransport(lambda r: calls.append(r.url.host) or httpx.Response(
        200, json={"choices": [{"message": {"content": "PUBLIC"}}]})), trust_env=False)
    router = Router(cfg, client=client, audit=AuditLog(str(tmp_path / "missing" / "a.jsonl")))
    r = TestClient(create_app(cfg, router)).post("/v1/chat/completions", json={"model": "auto", "messages": [{"role": "user", "content": "hi"}]})
    assert r.status_code == 503 and calls == []


# 12. short writes
def test_short_audit_writes_are_completed(tmp_path, monkeypatch):
    import os

    real = os.write
    monkeypatch.setattr(os, "write", lambda fd, data: real(fd, bytes(data[:1])))
    log = AuditLog(str(tmp_path / "a.jsonl"))
    log.write({"event": "x", "k": "v" * 50})
    assert json.loads(open(tmp_path / "a.jsonl").read())["k"] == "v" * 50


# 13. no request text in the audit log
def test_model_name_and_capability_text_never_reach_the_audit_log(tmp_path):
    c, cfg = client_for(tmp_path, Upstream())
    c.post("/v1/chat/completions", json={"model": "secret-merger-plan", "messages": [{"role": "user", "content": "hi"}]},
           headers={"x-sovereign-capability": "secret-capability-text"})
    log = open(cfg.audit_log).read()
    assert "secret-merger-plan" not in log and "secret-capability-text" not in log


# 15. content shapes
@pytest.mark.parametrize("content", [{"type": "image_url", "image_url": {"url": "data:image/png;base64,AAAA"}},
                                     [{"type": "text", "text": "hi", "extra": 1}], 42])
def test_non_text_content_shapes_are_rejected(tmp_path, content):
    up = Upstream()
    c, _ = client_for(tmp_path, up)
    r = c.post("/v1/chat/completions", json={"model": "auto", "messages": [{"role": "user", "content": content}]})
    assert r.status_code == 400 and up.calls == []


# 16. false positives
def test_timestamps_are_not_cards_or_phones():
    rules = {f.rule for f in scan_text("The release timestamp is 1759276800000 and the epoch second is 1759276800.", "x")}
    assert "payment_card" not in rules and "phone_number" not in rules
