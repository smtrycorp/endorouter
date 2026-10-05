"""Review round 10 (pre-launch): one representation for scan and send, honest post-send audit failure, verification
that is never cached, process titles that lie, a listener that cannot be seen, and a classifier failure that shows in the audit log."""

from __future__ import annotations

import asyncio
import json
import sys

import httpx
import pytest

from endorouter import discover
from endorouter.audit import AuditError
from endorouter.classifier import classify
from endorouter.config import ConfigError, parse_config
from endorouter.labels import Label
from endorouter.router import Refused, Router, SentUnrecorded, UpstreamFailed
from endorouter.validate import InvalidRequest
from tests.test_discover import installed
from tests.test_review_1 import _balanced
from tests.test_router import make_cfg


def _router(cfg, hosts):
    def up(req):
        hosts.append((req.url.host, req.content))
        return httpx.Response(200, json={"choices": [{"message": {"content": "ok"}}]})
    return Router(cfg, client=httpx.AsyncClient(transport=httpx.MockTransport(up), trust_env=False))


def test_a_tuple_is_scanned_as_the_list_it_is_sent_as(tmp_path):
    hosts = []
    body = {"model": "cloud/cm", "messages": [{"role": "user", "content": "hi"}],
            "tools": [{"type": "function", "function": {"name": "f", "parameters": {"k": ("AKIAIOSFODNN7EXAMPLE",)}}}]}
    with pytest.raises(Refused):
        asyncio.run(_router(make_cfg(tmp_path), hosts).route(body, declared=Label.PUBLIC))
    assert not any(h == "cloud.test" for h, _ in hosts)


def test_a_numeric_key_is_scanned_as_the_string_it_is_sent_as(tmp_path):
    hosts = []
    body = {"model": "cloud/cm", "messages": [{"role": "user", "content": "hi"}],
            "metadata": {4111111111111111: "card"}}
    with pytest.raises((Refused, InvalidRequest)):
        asyncio.run(_router(make_cfg(tmp_path), hosts).route(body, declared=Label.PUBLIC))
    assert not any(h == "cloud.test" for h, _ in hosts)


def test_a_body_that_is_not_plain_json_is_refused_before_anything_else(tmp_path):
    hosts = []
    for bad in ({"messages": [{"role": "user", "content": object()}]},
                {"messages": [{"role": "user", "content": "hi"}], "temperature": float("nan")}):
        with pytest.raises(InvalidRequest):
            asyncio.run(_router(make_cfg(tmp_path), hosts).route(bad))
    assert hosts == []


def test_an_audit_failure_after_sending_says_sent_not_refused(tmp_path, monkeypatch):
    hosts = []
    router = _router(make_cfg(tmp_path), hosts)
    real = router.audit.write

    def write(rec):
        if rec.get("event") == "dispatched":
            raise AuditError("disk full")
        return real(rec)

    monkeypatch.setattr(router.audit, "write", write)
    with pytest.raises(SentUnrecorded):
        asyncio.run(router.route({"model": "auto", "messages": [{"role": "user", "content": "hi"}]}))
    assert hosts and hosts[0][0] == "local.test"


def test_the_decision_record_names_who_supplied_the_label(tmp_path):
    hosts = []
    cfg = make_cfg(tmp_path)
    asyncio.run(_router(cfg, hosts).route({"model": "auto", "messages": [{"role": "user", "content": "hi"}]},
                                          declared=Label.PUBLIC, peer="127.0.0.1", trusted=True))
    rec = next(json.loads(line) for line in open(cfg.audit_log) if '"decision"' in line)
    assert rec["peer"] == "127.0.0.1" and rec["trusted"] is True and rec["declared"] == "public"


def test_an_ollama_model_that_turns_remote_is_refused_on_the_next_send(tmp_path, monkeypatch):
    cfg = parse_config({"version": 1, "audit_log": str(tmp_path / "a.jsonl"), "targets": {
        "ollama": {"url": "http://local.test:11434/v1", "model": "m", "location": "local", "verify_program": "ollama"}}})
    ollama = installed(tmp_path, monkeypatch)
    monkeypatch.setattr(discover, "_port_owners", lambda url: [ollama])
    state = {"remote": False}
    sent = []

    def up(req):
        if req.url.path == "/api/show":
            return httpx.Response(200, json={"remote_host": "https://ollama.com"} if state["remote"] else {})
        sent.append(req.url.path)
        return httpx.Response(200, json={"choices": [{"message": {"content": "ok"}}]})

    router = Router(cfg, client=httpx.AsyncClient(transport=httpx.MockTransport(up), trust_env=False))
    body = {"model": "auto", "messages": [{"role": "user", "content": "hi"}]}
    asyncio.run(router.route(body))
    state["remote"] = True
    with pytest.raises(UpstreamFailed):
        asyncio.run(router.route(body))
    assert len(sent) == 1 and "hosted remotely" in open(cfg.audit_log).read()


def test_two_sends_mean_two_ownership_checks(tmp_path, monkeypatch):
    cfg = parse_config({"version": 1, "audit_log": str(tmp_path / "a.jsonl"), "targets": {
        "llama": {"url": "http://local.test:8080/v1", "model": "m", "location": "local", "verify_program": "llama-server"}}})
    checks = []
    llama = installed(tmp_path, monkeypatch, "llama-server")
    monkeypatch.setattr(discover, "_port_owners", lambda url: checks.append(url) or [llama])
    router = _router(cfg, [])
    body = {"model": "auto", "messages": [{"role": "user", "content": "hi"}]}
    asyncio.run(router.route(body))
    asyncio.run(router.route(body))
    assert len(checks) == 2


def test_a_broken_classifier_is_recorded_not_silent(tmp_path):
    def down(req):
        raise httpx.ConnectError("refused", request=req)

    kinds = []
    client = httpx.AsyncClient(transport=httpx.MockTransport(down), trust_env=False)
    body = {"messages": [{"role": "user", "content": "hi"}]}
    assert asyncio.run(classify(_balanced(tmp_path), body, client, on_failure=kinds.append)) is None
    assert kinds == ["unreachable:ConnectError"]


@pytest.mark.parametrize("targets,match", [
    ({"a": {"url": "https://c/v1", "model": "*", "location": "cloud"}}, "local target is required"),
    ({"a": {"url": "http://127.0.0.1/v1", "model": "*", "location": "local"}}, "must name its model"),
])
def test_config_invariants_hold_for_every_construction(targets, match):
    with pytest.raises(ConfigError, match=match):
        parse_config({"version": 1, "targets": targets})


@pytest.mark.parametrize("section", ["provenance", "classifier"])
@pytest.mark.parametrize("value", [None, False, [], 0, ""])
def test_a_falsey_section_is_an_error_not_a_default(section, value):
    with pytest.raises(ConfigError):
        parse_config({"version": 1, "targets": {"l": {"url": "http://127.0.0.1/v1", "model": "m", "location": "local"}},
                      section: value})


# server
from starlette.testclient import TestClient  # noqa: E402

from endorouter.server import MAX_BODY, create_app  # noqa: E402

BODY = {"model": "auto", "messages": [{"role": "user", "content": "hi"}]}


def _app(tmp_path, hosts):
    cfg = make_cfg(tmp_path)
    return create_app(cfg, _router(cfg, hosts)), cfg


@pytest.mark.parametrize("host", ["evil.example", "evil.example:8000", "192.168.1.5:8000"])
def test_a_request_addressed_to_another_host_name_is_refused(tmp_path, host):
    hosts = []
    app, _ = _app(tmp_path, hosts)
    r = TestClient(app, base_url="http://127.0.0.1").post("/v1/chat/completions", json=BODY, headers={"host": host})
    assert r.status_code == 421 and hosts == []


@pytest.mark.parametrize("host", ["localhost:4000", "127.0.0.1:4000", "[::1]:4000", "localhost"])
def test_loopback_host_names_are_served(tmp_path, host):
    app, _ = _app(tmp_path, [])
    r = TestClient(app, base_url="http://127.0.0.1").post("/v1/chat/completions", json=BODY, headers={"host": host})
    assert r.status_code == 200


def test_a_body_over_the_cap_is_refused_unread(tmp_path):
    hosts = []
    app, _ = _app(tmp_path, hosts)
    big = {"model": "auto", "messages": [{"role": "user", "content": "x" * (MAX_BODY + 1)}]}
    r = TestClient(app, base_url="http://127.0.0.1").post("/v1/chat/completions", json=big)
    assert r.status_code == 413 and hosts == []


def test_a_private_piece_of_a_comma_joined_source_tightens(tmp_path):
    hosts = []
    app, _ = _app(tmp_path, hosts)
    r = TestClient(app, base_url="http://127.0.0.1", client=("127.0.0.1", 1)).post(
        "/v1/chat/completions", json={**BODY, "model": "cloud/cm"},
        headers={"x-endorouter-source": "docs/public/a.md,clients/acme/brief.md"})
    assert r.status_code == 403 and not any(h == "cloud.test" for h, _ in hosts)


def test_an_audit_failure_does_not_leak_its_cause_to_the_caller(tmp_path, monkeypatch):
    hosts = []
    app, cfg = _app(tmp_path, hosts)
    from endorouter import router as router_mod
    monkeypatch.setattr(router_mod.AuditLog, "write", lambda self, rec: (_ for _ in ()).throw(
        AuditError(f"[Errno 28] No space left on device: '{cfg.audit_log}'")))
    r = TestClient(app, base_url="http://127.0.0.1").post("/v1/chat/completions", json=BODY)
    assert r.status_code == 503 and cfg.audit_log not in r.text and hosts == []


def test_sent_but_unrecorded_is_a_502_that_says_so(tmp_path, monkeypatch):
    hosts = []
    cfg = make_cfg(tmp_path)
    router = _router(cfg, hosts)
    real = router.audit.write
    monkeypatch.setattr(router.audit, "write",
                        lambda rec: (_ for _ in ()).throw(AuditError("x")) if rec.get("event") == "dispatched" else real(rec))
    r = TestClient(create_app(cfg, router), base_url="http://127.0.0.1").post("/v1/chat/completions", json=BODY)
    assert r.status_code == 502 and "sent, but not recorded" in r.text


# cli
def test_serve_refuses_a_network_address():
    from endorouter import cli

    with pytest.raises(SystemExit, match="this machine only"):
        cli.main(["serve", "--host", "0.0.0.0"])


@pytest.mark.skipif(sys.platform == "win32", reason="Windows has no owner-only file mode; the log takes its folder's access list")
def test_doctor_creates_an_owner_only_audit_log(tmp_path, monkeypatch):
    import stat

    import yaml

    from endorouter import cli

    log = tmp_path / "audit.jsonl"
    conf = tmp_path / "c.yaml"
    conf.write_text(yaml.safe_dump({"version": 1, "audit_log": str(log), "targets": {
        "l": {"url": "http://127.0.0.1:9/v1", "model": "m", "location": "local"}}}))
    cli.main(["doctor", "-c", str(conf)])
    assert stat.S_IMODE(log.stat().st_mode) == 0o600


def test_serve_reports_a_bad_config_without_a_traceback(tmp_path):
    from endorouter import cli

    conf = tmp_path / "c.yaml"
    conf.write_text("version: 1\ntargets: {}\n")
    with pytest.raises(SystemExit, match="config error"):
        cli.main(["serve", "-c", str(conf)])


# detectors
@pytest.mark.parametrize("unit", [" ", "\t", " -", "\n ", " :"])
def test_whitespace_runs_scan_in_linear_time(unit):
    import time

    from endorouter.detectors import scan_text

    list(scan_text("warm", "x"))
    text = unit * (64000 // len(unit))
    t0 = time.perf_counter()
    list(scan_text(text, "x"))
    # the quadratic pattern took ~0.7 s at 16 k spaces, so ~12 s here; linear scanning takes milliseconds
    assert time.perf_counter() - t0 < 1.0


def test_yaml_credentials_are_still_found_after_the_pattern_change():
    from endorouter.detectors import scan_text

    for line in ["  api_token: 'Zt8Qw3Er6Ty9Ui2Op5As1Df4'", "- api_token: \"Zt8Qw3Er6Ty9Ui2Op5As1Df4\"",
                 "\t-\tapi_token: 'Zt8Qw3Er6Ty9Ui2Op5As1Df4'"]:
        assert list(scan_text(line, "x")), line
