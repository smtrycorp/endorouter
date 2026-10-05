"""Windows-branch review (two reviewers, 2026-10-04): a torn audit tail and writers in separate processes."""

from __future__ import annotations

import json
import multiprocessing

from endorouter.audit import AuditLog


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
