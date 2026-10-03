"""Regressions for review round 2 (two external reviewers, 2026-09-30). Each test reproduces a finding, then pins the fix."""

from __future__ import annotations

import asyncio
import json

import httpx
import pytest
from starlette.testclient import TestClient

from endorouter import Label, decide
from endorouter.audit import AuditLog
from endorouter.classifier import classify
from endorouter.config import parse_config
from endorouter.detectors import scan_request, scan_text, texts_in_request
from endorouter.router import Router
from endorouter.server import create_app
from tests.test_review_1 import _answering, _balanced, client_for, make_cfg_url
from tests.test_router import Upstream, make_cfg

B64_KEY = "QUtJQUlPU0ZPRE5ON0VYQU1QTEU="  # base64 of the AWS example key


# library API: the payload is snapshotted before inspection
def test_mutating_the_body_during_classification_cannot_change_what_is_sent(tmp_path):
    sent = []
    body = {"model": "c", "messages": [{"role": "user", "content": "hello"}]}

    def upstream(req):
        if req.url.host == "local.test":  # the classifier call: mutate the caller's object while it is in flight
            body["messages"][0]["content"] = "AKIAIOSFODNN7EXAMPLE"
            return httpx.Response(200, json={"choices": [{"message": {"content": "PUBLIC"}}]})
        sent.append(req.content.decode())
        return httpx.Response(200, json={"choices": [{"message": {"content": "ok"}}]})

    cfg = _balanced(tmp_path)
    router = Router(cfg, client=httpx.AsyncClient(transport=httpx.MockTransport(upstream), trust_env=False))
    asyncio.run(router.route(body))
    assert sent and all("AKIA" not in s for s in sent)


def test_injected_client_that_trusts_the_environment_is_refused(tmp_path):
    with pytest.raises(ValueError, match="trust_env=False"):
        Router(make_cfg(tmp_path), client=httpx.AsyncClient())


def test_every_attempt_is_audited_before_it_is_sent(tmp_path):
    up = Upstream({"local.test": "503"})
    c, cfg = client_for(tmp_path, up, extra_local=True)
    c.post("/v1/chat/completions", json={"model": "auto", "messages": [{"role": "user", "content": "hi"}]})
    events = [(x["event"], x.get("target")) for x in map(json.loads, open(cfg.audit_log))]
    assert events == [("decision", None), ("attempt", "local"), ("attempt", "local2"), ("dispatched", "local2")]


def test_two_audit_writers_on_one_path_never_interleave(tmp_path, monkeypatch):
    import os
    import threading

    real = os.write
    monkeypatch.setattr(os, "write", lambda fd, data: real(fd, bytes(data[:1])))
    path = str(tmp_path / "a.jsonl")
    a, b = AuditLog(path), AuditLog(path)
    ts = [threading.Thread(target=w.write, args=({"event": n, "pad": "x" * 200},)) for w, n in ((a, "a"), (b, "b")) for _ in range(5)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    lines = open(path).read().splitlines()
    assert len(lines) == 10 and all(json.loads(x)["pad"] == "x" * 200 for x in lines)


@pytest.mark.parametrize("answer", ["¬PUBLIC", "!PUBLIC", "PUBLIC!", "(PUBLIC)", "PUBLIC PUBLIC"])
def test_classifier_rejects_anything_but_a_bare_verdict(tmp_path, answer):
    assert asyncio.run(classify(_balanced(tmp_path), {"messages": [{"role": "user", "content": "hi"}]}, _answering(answer))) is None


def test_classifier_non_string_content_is_no_verdict_not_a_crash(tmp_path):
    assert asyncio.run(classify(_balanced(tmp_path), {"messages": [{"role": "user", "content": "hi"}]}, _answering(["PUBLIC"]))) is None


# detectors
@pytest.mark.parametrize("text", [
    "AKIA͏IOSFODNN7EXAMPLE",                     # combining grapheme joiner (default-ignorable, not Cf)
    "AKIA️IOSFODNN7EXAMPLE",                     # variation selector
    "AAAAAAAAAAAAAAAA " * 300 + B64_KEY,               # decoys past the old candidate cap
    "x" + "Q" * 5000 + " " + B64_KEY,                  # a long run before the key
])
def test_ignorables_and_base64_decoys_do_not_hide_a_key(text):
    assert any(f.rule == "aws_access_key" for f in scan_text(text, "x"))


def test_integral_float_is_scanned_in_expanded_form():
    body = {"messages": [{"role": "user", "content": "x"}], "response_format": {"type": "json_schema", "json_schema": {
        "schema": {"properties": {"card": {"default": 4.000000000000512e18}}}}}}
    assert "payment_card" in {f.rule for f in scan_request(body)}


def test_uppercase_scheme_credential_url_is_found():
    assert any(f.rule == "credential_url" for f in scan_text("HTTPS://admin:hunter2@db.internal/x", "x"))


@pytest.mark.parametrize("text", ["+1 415 555 0142", "+1\t415\t555\t0142"])
def test_phone_with_other_spaces_is_found(text):
    assert any(f.rule == "phone_number" for f in scan_text(text, "x"))


def test_classifier_text_is_in_document_order():
    body = {"messages": [{"role": "system", "content": "FIRST"}, {"role": "user", "content": "SECOND"}]}
    texts = [t for _, t in texts_in_request(body)]
    assert texts.index("FIRST") < texts.index("SECOND")


# URLs
@pytest.mark.parametrize("source", [
    "https://example.com/private/plan#/../../public/post",  # fragment must not take part in path resolution
    "https://example.com/public/..;/private/plan",          # matrix parameter traversal
])
def test_url_fragments_and_matrix_params_cannot_lift_a_private_source(source):
    assert decide(make_cfg_url(), sources=[source]).label is not Label.PUBLIC


# server shapes
@pytest.mark.parametrize("msg", [
    {"role": "assistant", "content": None, "tool_calls": [{"type": "image_url", "image_url": {"url": "data:image/png;base64,AAAA"}}]},
    {"role": "assistant", "content": None, "tool_calls": [{"id": "1", "type": "function", "function": {"name": "f", "arguments": {"k": 1}}}]},
    {"role": "user", "content": "hi", "name": {"x": 1}},
])
def test_nested_non_text_shapes_are_rejected(tmp_path, msg):
    up = Upstream()
    c, _ = client_for(tmp_path, up)
    assert c.post("/v1/chat/completions", json={"model": "auto", "messages": [msg]}).status_code == 400 and up.calls == []


def test_leakbench_markers_never_contain_one_another():
    from endorouter.leakbench.runner import _marked

    m = {_marked({"id": i, "messages": [{"role": "user", "content": "x"}]})[1] for i in ("p", "public", "p")}
    assert len(m) == 3 and not any(a != b and a in b for a in m for b in m)


def test_leakbench_markers_never_look_like_secrets():
    from endorouter.leakbench.runner import _marked

    for i in range(200):
        body, _ = _marked({"id": str(i), "messages": [{"role": "user", "content": "What is TCP?"}]})
        assert scan_request(body) == []
