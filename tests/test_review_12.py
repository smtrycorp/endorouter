"""Review round 12 (launch review, Codex's second pass): each reproduction from the review, pinned."""

from __future__ import annotations

import asyncio
import json
import time

import httpx
import pytest
from starlette.testclient import TestClient

from endorouter.audit import AuditError
from endorouter.classifier import classify
from endorouter.config import parse_config
from endorouter.detectors import scan_request, scan_text
from endorouter.leakbench.runner import _case_strings, _fingerprints, _marked, _received
from endorouter.router import Router
from endorouter.server import create_app
from tests.test_review_1 import _balanced
from tests.test_router import make_cfg

BODY = {"model": "auto", "messages": [{"role": "user", "content": "hello"}]}


def _cloud_first(tmp_path, private):
    return parse_config({"version": 1, "audit_log": str(tmp_path / "a.jsonl"), "targets": {
        "cloud": {"url": "https://cloud.test/v1", "model": "cm", "location": "cloud"},
        "local": {"url": "http://local.test/v1", "model": "lm", "location": "local"}},
        "provenance": {"public_sources": ["docs/public/**"], "private_sources": private}})


def _app(cfg, hosts):
    router = Router(cfg, client=httpx.AsyncClient(transport=httpx.MockTransport(
        lambda r: hosts.append(r.url.host) or httpx.Response(200, json={"choices": []})), trust_env=False))
    return TestClient(create_app(cfg, router), base_url="http://127.0.0.1", client=("127.0.0.1", 1))


@pytest.mark.parametrize("path", ["docs/public/café/plan.md", "docs/public/café/plan.md"])
def test_a_utf8_source_header_meets_its_private_pattern(tmp_path, path):
    hosts = []
    cfg = _cloud_first(tmp_path, ["**/café/**"])
    r = _app(cfg, hosts).post("/v1/chat/completions", json=BODY,
                              headers=[(b"x-endorouter-source", path.encode("utf-8"))])
    assert r.status_code == 200 and hosts == ["local.test"]


def test_a_source_header_that_is_not_utf8_is_refused(tmp_path):
    # driven over raw ASGI: the test client re-encodes header bytes, so it cannot send invalid UTF-8
    hosts = []
    cfg = _cloud_first(tmp_path, [])
    app = _app(cfg, hosts).app
    body = json.dumps(BODY).encode()
    scope = {"type": "http", "method": "POST", "path": "/v1/chat/completions", "raw_path": b"/v1/chat/completions",
             "query_string": b"", "client": ("127.0.0.1", 1), "server": ("127.0.0.1", 8787), "scheme": "http",
             "http_version": "1.1", "headers": [(b"host", b"127.0.0.1"), (b"content-type", b"application/json"),
                                                (b"content-length", str(len(body)).encode()),
                                                (b"x-endorouter-source", b"docs/public/\xff.md")]}
    sent = []

    async def receive():
        return {"type": "http.request", "body": body, "more_body": False}

    async def send(message):
        sent.append(message)

    asyncio.run(app(scope, receive, send))
    assert sent[0]["status"] == 400 and hosts == []


def test_repeating_one_source_still_counts_against_the_limit(tmp_path):
    hosts = []
    r = _app(_cloud_first(tmp_path, []), hosts).post(
        "/v1/chat/completions", json=BODY, headers=[("x-endorouter-source", "docs/public/x")] * 65)
    assert r.status_code == 400 and hosts == []


def test_the_record_keeps_what_the_caller_declared(tmp_path):
    cfg = make_cfg(tmp_path)
    _app(cfg, []).post("/v1/chat/completions", json=BODY,
                       headers={"x-endorouter-label": "public", "x-endorouter-source": "clients/acme/brief.md"})
    rec = next(json.loads(line) for line in open(cfg.audit_log) if '"decision"' in line)
    assert rec["declared"] == "public" and rec["label"] == "private" and "source_private" in rec["reasons"]


def test_an_audit_failure_after_the_classifier_read_the_text_says_sent(tmp_path, monkeypatch):
    cfg = _balanced(tmp_path)
    router = Router(cfg, client=httpx.AsyncClient(transport=httpx.MockTransport(
        lambda r: httpx.Response(200, json={"choices": [{"message": {"content": "PRIVATE"}}]})), trust_env=False))
    real = router.audit.write
    monkeypatch.setattr(router.audit, "write", lambda rec: (_ for _ in ()).throw(AuditError("full"))
                        if rec.get("event") == "decision" else real(rec))
    r = TestClient(create_app(cfg, router), base_url="http://127.0.0.1").post("/v1/chat/completions", json=BODY)
    assert r.status_code == 502 and r.json()["error"]["target"] == "l"


def test_a_deeply_nested_classifier_answer_is_recorded(tmp_path):
    kinds = []
    client = httpx.AsyncClient(transport=httpx.MockTransport(
        lambda r: httpx.Response(200, content=b"[" * 100000 + b"]" * 100000)), trust_env=False)
    assert asyncio.run(classify(_balanced(tmp_path), BODY, client, on_failure=kinds.append)) is None
    assert kinds == ["malformed_response"]


def test_escaped_quotes_scan_in_linear_time():
    list(scan_text("warm", "x"))
    t0 = time.perf_counter()
    list(scan_text('\\"' * 64000, "x"))
    assert time.perf_counter() - t0 < 1.0  # the retrying regex took over a second at 16 k; this is 64 k


def test_the_marker_never_splits_a_key_across_messages():
    case = {"id": "s", "category": "c", "truth": "private", "label": "public",
            "messages": [{"role": "user", "content": "AK"}, {"role": "user", "content": "IAIOSFODNN7EXAMPLE"}]}
    assert scan_request({"messages": case["messages"]})
    body, _ = _marked(case)
    assert scan_request(body), "the benchmark's own marker hid the key"


def test_a_tool_call_sent_without_its_marker_is_traced_to_its_case():
    a = {"messages": [{"role": "user", "content": "deploy it"}, {"role": "assistant", "content": None, "tool_calls": [
        {"id": "c1", "type": "function", "function": {"name": "push", "arguments": "{\"key\": \"AKIAIOSFODNN7EXAMPLE\"}"}}]},
        {"role": "tool", "tool_call_id": "c1", "content": "pushed"}, {"role": "user", "content": "done?\n[lbkA]"}]}
    b = {"messages": [{"role": "user", "content": "What is the tallest mountain on Earth?\n[lbkB]"}]}
    prints = _fingerprints(_case_strings({"A": a, "B": b}, {"lbkA", "lbkB"}))
    leaked = json.dumps({"messages": [a["messages"][1], b["messages"][0]]})
    text = "\n".join(_received(leaked))
    assert any(s in text for s in prints["A"]) and any(s in text for s in prints["B"])


def test_a_string_two_cases_share_names_neither():
    shared = "You are a helpful assistant."
    prints = _fingerprints(_case_strings({"A": {"messages": [{"role": "system", "content": shared}]},
                                          "B": {"messages": [{"role": "system", "content": shared}]}}, set()))
    assert shared not in prints["A"] | prints["B"]


def test_every_label_is_true():
    from endorouter.labels import Label

    assert all(bool(lab) for lab in Label) and (Label.PUBLIC or None) is Label.PUBLIC


def test_an_untrusted_declaration_is_recorded_but_not_applied(tmp_path):
    cfg = parse_config({"version": 1, "audit_log": str(tmp_path / "a.jsonl"), "targets": {
        "l": {"url": "http://local.test/v1", "model": "m", "location": "local"},
        "c": {"url": "https://cloud.test/v1", "model": "m", "location": "cloud"}},
        "provenance": {"private_sources": ["clients/**"], "trusted_clients": []}})
    _app(cfg, []).post("/v1/chat/completions", json=BODY,
                       headers={"x-endorouter-label": "public", "x-endorouter-source": "clients/acme/brief.md"})
    rec = next(json.loads(line) for line in open(cfg.audit_log) if '"decision"' in line)
    assert rec["trusted"] is False and rec["declared"] == "public" and rec["declared_applied"] is False
    assert rec["label"] == "private"


def test_a_classifier_that_never_read_the_text_is_not_reported_as_a_recipient(tmp_path, monkeypatch):
    cfg = _balanced(tmp_path)
    posts = []
    router = Router(cfg, client=httpx.AsyncClient(transport=httpx.MockTransport(
        lambda r: posts.append(r) or httpx.Response(200, json={"choices": []})), trust_env=False))
    real = router.audit.write
    monkeypatch.setattr(router.audit, "write", lambda rec: (_ for _ in ()).throw(AuditError("full"))
                        if rec.get("event") == "decision" else real(rec))
    long = {"model": "auto", "messages": [{"role": "user", "content": "x" * 12001}]}
    r = TestClient(create_app(cfg, router), base_url="http://127.0.0.1").post("/v1/chat/completions", json=long)
    assert posts == [] and r.status_code == 503



@pytest.mark.parametrize("last", [
    {"role": "user", "content": [{"type": "text", "text": "IAIOSFODNN7EXAMPLE"}]},
    {"role": "assistant", "content": None, "tool_calls": [
        {"id": "c1", "type": "function", "function": {"name": "f", "arguments": "IAIOSFODNN7EXAMPLE"}}]},
])
def test_the_marker_never_splits_a_key_whatever_the_last_message_is(last):
    # including an assistant message with empty text and a tool call, and with no extra turn after the tool call
    case = {"id": "s", "category": "c", "truth": "private", "messages": [{"role": "user", "content": "AK"}, last]}
    assert scan_request({"messages": case["messages"]})
    body, marker = _marked(case)
    assert scan_request(body) and marker in json.dumps(body["messages"][0])  # before everything


@pytest.mark.parametrize("msgs", [
    [{"role": "user", "content": "deploy with key AK"}, {"role": "assistant", "content": "", "tool_calls": [
        {"id": "c1", "type": "function", "function": {"name": "deploy", "arguments": "IAIOSFODNN7EXAMPLE"}}]}],
    [{"role": "assistant", "content": "AK", "tool_calls": [
        {"id": "c1", "type": "function", "function": {"name": "deploy", "arguments": "IAIOSFODNN7EXAMPLE"}}]}],
])
def test_the_marker_never_splits_text_from_a_following_tool_call(msgs):
    case = {"id": "s", "category": "c", "truth": "private", "label": "public", "messages": msgs}
    assert scan_request({"messages": msgs})
    body, _ = _marked(case)
    assert scan_request(body)
    assert body["messages"][-1].get("tool_calls")  # no turn added after the tool call


def test_no_dispatch_record_when_the_classifier_is_not_sent_the_text(tmp_path):
    cfg = _balanced(tmp_path)
    router = Router(cfg, client=httpx.AsyncClient(transport=httpx.MockTransport(
        lambda r: httpx.Response(200, json={"choices": [{"message": {"content": "PRIVATE"}}]})), trust_env=False))
    asyncio.run(router.route({"model": "auto", "messages": [{"role": "user", "content": "x" * 12001}]}))
    log = open(cfg.audit_log).read()
    assert "classifier_dispatch" not in log and "too_long" in log
