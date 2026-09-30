"""Dispatch and server invariants under failure: outages, redirects, 5xx, audit failure, untrusted headers, streaming."""

from __future__ import annotations

import json

import httpx
import pytest
from starlette.testclient import TestClient

from sovereign_router.audit import AuditLog
from sovereign_router.config import parse_config
from sovereign_router.router import Router
from sovereign_router.server import create_app


def make_cfg(tmp_path, extra_local=False):
    targets = {"local": {"url": "http://local.test/v1", "model": "lm", "location": "local"}}
    if extra_local:
        targets["local2"] = {"url": "http://local2.test/v1", "model": "lm2", "location": "local"}
    targets["cloud"] = {"url": "https://cloud.test/v1", "model": "cm", "location": "cloud", "api_key_env": "CLOUD_KEY"}
    return parse_config({"version": 1, "audit_log": str(tmp_path / "audit.jsonl"), "targets": targets,
                         "provenance": {"public_sources": ["docs/public/**"], "private_sources": ["clients/**"]}})


class Upstream:
    """A mock transport recording which hosts were contacted, with per-host behaviour."""

    def __init__(self, behaviour=None):
        self.calls: list[str] = []
        self.behaviour = behaviour or {}

    def __call__(self, request: httpx.Request) -> httpx.Response:
        host = request.url.host
        self.calls.append(host)
        b = self.behaviour.get(host, "ok")
        if b == "down":
            raise httpx.ConnectError("down", request=request)
        if b == "503":
            return httpx.Response(503, json={"error": "busy"})
        if b == "redirect":
            return httpx.Response(302, headers={"location": "https://evil.test/v1/chat/completions"})
        if b == "stream":
            return httpx.Response(200, headers={"content-type": "text/event-stream"},
                                  content=b"data: {\"choices\":[{\"delta\":{\"content\":\"hi\"}}]}\n\ndata: [DONE]\n\n")
        return httpx.Response(200, json={"choices": [{"message": {"role": "assistant", "content": f"from {host}"}}]})


def app_for(tmp_path, upstream, **kw):
    cfg = make_cfg(tmp_path, **kw)
    client = httpx.AsyncClient(transport=httpx.MockTransport(upstream), follow_redirects=False, trust_env=False)
    return create_app(cfg, Router(cfg, client=client)), cfg


BODY = {"model": "auto", "messages": [{"role": "user", "content": "hello"}]}


def test_unlabelled_request_goes_local_and_never_touches_cloud(tmp_path):
    up = Upstream()
    app, _ = app_for(tmp_path, up)
    r = TestClient(app).post("/v1/chat/completions", json=BODY)
    assert r.status_code == 200 and r.headers["x-sovereign-location"] == "local"
    assert up.calls == ["local.test"]


def test_public_source_from_trusted_client_may_reach_cloud_by_preference(tmp_path):
    up = Upstream()
    app, _ = app_for(tmp_path, up)
    r = TestClient(app, client=("127.0.0.1", 5000)).post("/v1/chat/completions", json={**BODY, "model": "cloud"},
                                                          headers={"x-sovereign-sources": "docs/public/a.md"})
    assert r.status_code == 200 and up.calls == ["cloud.test"]


def test_untrusted_client_cannot_declare_public(tmp_path):
    up = Upstream()
    app, _ = app_for(tmp_path, up)
    r = TestClient(app, client=("10.0.0.9", 5000)).post("/v1/chat/completions", json={**BODY, "model": "cloud"},
                                                         headers={"x-sovereign-label": "public"})
    assert r.status_code == 403 and up.calls == []


def test_local_outage_fails_closed_and_never_falls_back_to_cloud(tmp_path):
    up = Upstream({"local.test": "down"})
    app, _ = app_for(tmp_path, up)
    r = TestClient(app).post("/v1/chat/completions", json=BODY)
    assert r.status_code == 502 and "cloud.test" not in up.calls


def test_fallback_stays_inside_the_permitted_set(tmp_path):
    up = Upstream({"local.test": "503"})
    app, _ = app_for(tmp_path, up, extra_local=True)
    r = TestClient(app).post("/v1/chat/completions", json=BODY)
    assert r.status_code == 200 and up.calls == ["local.test", "local2.test"]


def test_redirects_are_never_followed(tmp_path):
    up = Upstream({"local.test": "redirect"})
    app, _ = app_for(tmp_path, up)
    r = TestClient(app).post("/v1/chat/completions", json=BODY)
    assert r.status_code == 502 and "evil.test" not in up.calls


def test_audit_failure_blocks_dispatch(tmp_path):
    up = Upstream()
    cfg = make_cfg(tmp_path)
    router = Router(cfg, client=httpx.AsyncClient(transport=httpx.MockTransport(up)),
                    audit=AuditLog(str(tmp_path / "no-such-dir" / "audit.jsonl")))
    r = TestClient(create_app(cfg, router)).post("/v1/chat/completions", json=BODY)
    assert r.status_code == 503 and up.calls == []


def test_audit_records_decision_before_dispatch_and_holds_no_content(tmp_path):
    up = Upstream()
    app, cfg = app_for(tmp_path, up)
    secret_body = {"model": "auto", "messages": [{"role": "user", "content": "my key AKIAIOSFODNN7EXAMPLE"}]}
    TestClient(app).post("/v1/chat/completions", json=secret_body)
    lines = [json.loads(x) for x in open(cfg.audit_log)]
    assert [x["event"] for x in lines] == ["decision", "dispatched"]
    assert lines[0]["label"] == "private" and "detector:aws_access_key" in lines[0]["reasons"]
    assert "AKIA" not in open(cfg.audit_log).read()


def test_streaming_passes_through_from_one_target(tmp_path):
    up = Upstream({"local.test": "stream"})
    app, _ = app_for(tmp_path, up)
    r = TestClient(app).post("/v1/chat/completions", json={**BODY, "stream": True})
    assert r.status_code == 200 and b"[DONE]" in r.content and up.calls == ["local.test"]


def test_unsupported_fields_and_images_are_rejected(tmp_path):
    app, _ = app_for(tmp_path, Upstream())
    c = TestClient(app)
    assert c.post("/v1/chat/completions", json={**BODY, "surprise": 1}).status_code == 400
    img = {"model": "auto", "messages": [{"role": "user", "content": [{"type": "image_url", "image_url": {"url": "x"}}]}]}
    assert c.post("/v1/chat/completions", json=img).status_code == 400


@pytest.mark.parametrize("header", ["x-sovereign-sources"])
def test_private_source_overrides_requested_cloud(tmp_path, header):
    up = Upstream()
    app, _ = app_for(tmp_path, up)
    r = TestClient(app).post("/v1/chat/completions", json={**BODY, "model": "cloud"}, headers={header: "clients/acme/brief.md"})
    assert r.status_code == 403 and up.calls == []
