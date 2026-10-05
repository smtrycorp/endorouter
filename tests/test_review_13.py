"""Windows-branch review (two reviewers, 2026-10-04): a torn audit tail, writers in separate processes, and the
/api/show probe as a recorded send."""

from __future__ import annotations

import asyncio
import json
import multiprocessing

import httpx
import pytest

from endorouter import discover
from endorouter.audit import AuditError, AuditLog
from endorouter.config import parse_config
from endorouter.router import Router
from tests.test_discover import installed


def test_a_torn_record_is_closed_off_before_the_next_one(tmp_path):
    path = tmp_path / "a.jsonl"
    path.write_bytes(b'{"event":"attempt","request_id":"a')  # a writer died here
    AuditLog(str(path)).write({"event": "attempt", "request_id": "b"})
    lines = path.read_text().splitlines()
    assert lines[0] == '{"event":"attempt","request_id":"a'
    assert json.loads(lines[1])["event"] == "audit_repaired"
    assert json.loads(lines[2]) == {"event": "attempt", "request_id": "b", "ts": json.loads(lines[2])["ts"]}
    assert len(lines) == 3


def test_a_clean_tail_gets_no_repair_record(tmp_path):
    log = AuditLog(str(tmp_path / "a.jsonl"))
    log.write({"event": "a"})
    log.write({"event": "b"})
    assert [json.loads(x)["event"] for x in (tmp_path / "a.jsonl").read_text().splitlines()] == ["a", "b"]


def _write_many(path, tag):
    log = AuditLog(path)
    for i in range(200):
        log.write({"event": tag, "i": i, "pad": "x" * 300})


def test_writers_in_separate_processes_never_interleave(tmp_path):
    path = str(tmp_path / "a.jsonl")
    ctx = multiprocessing.get_context("spawn")
    procs = [ctx.Process(target=_write_many, args=(path, f"w{n}")) for n in range(4)]
    for p in procs:
        p.start()
    for p in procs:
        p.join(120)
    assert all(p.exitcode == 0 for p in procs)
    records = [json.loads(line) for line in open(path)]
    assert len(records) == 800
    assert all(r["pad"] == "x" * 300 for r in records)
    assert sorted(r["event"] for r in records) == sorted(f"w{n}" for n in range(4) for _ in range(200))


def _ollama_router(tmp_path, monkeypatch, up):
    cfg = parse_config({"version": 1, "audit_log": str(tmp_path / "a.jsonl"), "targets": {
        "ollama": {"url": "http://local.test:11434/v1", "model": "m", "location": "local", "verify_program": "ollama"}}})
    ollama = installed(tmp_path, monkeypatch)
    monkeypatch.setattr(discover, "_port_owners", lambda url: [ollama])
    return cfg, Router(cfg, client=httpx.AsyncClient(transport=httpx.MockTransport(up), trust_env=False))


def test_the_model_locality_probe_is_on_disk_before_it_is_sent(tmp_path, monkeypatch):
    seen = []

    def up(req):
        if req.url.path == "/api/show":
            seen.append([json.loads(x)["event"] for x in open(tmp_path / "a.jsonl")])
            return httpx.Response(200, json={})
        return httpx.Response(200, json={"choices": [{"message": {"content": "ok"}}]})

    cfg, router = _ollama_router(tmp_path, monkeypatch, up)
    asyncio.run(router.route({"model": "auto", "messages": [{"role": "user", "content": "hi"}]}))
    assert seen == [["decision", "probe"]]
    events = [json.loads(x) for x in open(cfg.audit_log)]
    assert [e["event"] for e in events] == ["decision", "probe", "attempt", "dispatched"]
    assert events[1]["target"] == "ollama" and events[1]["model"] == "m"


def test_a_probe_that_cannot_be_recorded_is_not_sent(tmp_path, monkeypatch):
    posts = []

    def up(req):
        posts.append(req.url.path)
        return httpx.Response(200, json={})

    cfg, router = _ollama_router(tmp_path, monkeypatch, up)
    real = router.audit.write

    def failing(record):
        if record["event"] == "probe":
            raise AuditError("disk full")
        real(record)

    monkeypatch.setattr(router.audit, "write", failing)
    with pytest.raises(AuditError):
        asyncio.run(router.route({"model": "auto", "messages": [{"role": "user", "content": "hi"}]}))
    assert posts == []
