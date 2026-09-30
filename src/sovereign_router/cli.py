"""Command line: init, doctor, explain, serve, leakbench."""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from pathlib import Path
from urllib.parse import urlparse

from .config import ConfigError, load_config
from .detectors import scan_request
from .labels import Label
from .policy import decide

LOOPBACK = {"127.0.0.1", "localhost", "::1"}
DEFAULT_CONFIG = "sovereign-router.yaml"


def _cfg(path: str):
    if path == DEFAULT_CONFIG and not Path(path).exists():
        return _auto()[2]  # no config file: use what discovery finds, as `serve` does
    try:
        return load_config(path)
    except ConfigError as e:
        sys.exit(f"config error: {e}")


def cmd_doctor(a) -> int:
    cfg = _cfg(a.config)
    ok = True
    print(f"config: {a.config}  mode={cfg.mode}  targets={len(cfg.targets)}  audit_log={cfg.audit_log}")
    for t in cfg.targets:
        host = urlparse(t.url).hostname or ""
        notes = []
        if t.is_local and host not in LOOPBACK:
            notes.append("declared local but not on this machine: make sure you control that host")
        if t.is_local:
            notes.append("localhost is not proof of local inference: some local servers can proxy cloud models (see README)")
        if not t.is_local and host in LOOPBACK:
            notes.append("declared cloud but loopback: fine for a local gateway, otherwise check the location")
        if t.api_key_env and not os.environ.get(t.api_key_env):
            notes.append(f"{t.api_key_env} is not set")
            ok = ok and t.is_local
        print(f"  [{t.location:5}] {t.name}: {t.url} model={t.model}"
              + (f" (verified: {t.verify_program})" if t.verify_program else ""))
        for n in notes:
            print(f"          note: {n}")
    for problem in _reverify(cfg):
        print(f"  problem: {problem}")
        ok = False
    try:
        with open(cfg.audit_log, "a"):
            pass
        print("audit log: writable")
    except OSError as e:
        print(f"audit log: NOT writable ({e}); every request would be refused")
        ok = False
    return 0 if ok else 1


def cmd_explain(a) -> int:
    cfg = _cfg(a.config)
    text = Path(a.file).read_text() if a.file else sys.stdin.read()
    try:
        body = json.loads(text)
        if not isinstance(body, dict) or "messages" not in body:
            raise ValueError
    except ValueError:
        body = {"model": "auto", "messages": [{"role": "user", "content": text}]}
    findings = scan_request(body, extra=[(f"sources[{i}]", s) for i, s in enumerate(a.source)])
    d = decide(cfg, requested_model=body.get("model"), sources=a.source, declared=Label.parse(a.label), findings=findings,
               capability=a.capability)
    print(json.dumps({**d.as_record(), "findings": [f"{f.rule} @ {f.where}" for f in findings],
                      "note": "deterministic policy only; the optional local classifier is not consulted by explain"}, indent=2))
    return 0 if d.selected else 3


def _auto(trust: tuple[str, ...] = ()):
    from .config import parse_config
    from .discover import auto_config

    try:
        raw, notes = auto_config(trust=trust)
    except RuntimeError as e:
        sys.exit(str(e))
    return raw, notes, parse_config(raw)


def _reverify(cfg) -> list[str]:
    """Targets discovery verified must still be served by the same program: if the port changed hands (the local
    server quit and a proxy started there), that target is not used. Returns one problem per failed target."""
    from .discover import verified_program

    problems = []
    for t in cfg.targets:
        if t.is_local and t.verify_program and verified_program(t.url) != t.verify_program:
            problems.append(f"{t.name}: {t.url} is no longer served by {t.verify_program}; refusing to use it "
                            f"(run `sovereign-router init --force` to re-detect)")
    return problems


def cmd_init(a) -> int:
    import yaml

    if Path(a.config).exists() and not a.force:
        sys.exit(f"{a.config} already exists (use --force to replace it)")
    raw, notes, _ = _auto(tuple(a.trust))
    for n in notes:
        print(n)
    Path(a.config).write_text("# written by `sovereign-router init`: everything below was found, not asked for\n"
                              + yaml.safe_dump(raw, sort_keys=False))
    print(f"wrote {a.config}; strict mode: nothing leaves this machine unless a trusted client labels it public")
    return 0


def cmd_serve(a) -> int:
    import uvicorn

    from .server import create_app

    if a.config == DEFAULT_CONFIG and not Path(a.config).exists():
        # zero-question start: discover the local server and any cloud keys, protect standard secret files, strict mode
        _, notes, cfg = _auto()
        for n in notes:
            print(n)
        print(f"strict mode, audit log {cfg.audit_log}; serving on http://{a.host}:{a.port}/v1")
    else:
        cfg = load_config(a.config) if Path(a.config).exists() else _cfg(a.config)
    problems = _reverify(cfg)
    if problems:
        sys.exit("\n".join(problems))
    # proxy headers off: X-Forwarded-For must never let a caller borrow a trusted client's address. Behind a reverse
    # proxy the proxy itself is the peer; list it in trusted_clients only if every caller behind it is trusted.
    uvicorn.run(create_app(cfg), host=a.host, port=a.port, log_level="warning", proxy_headers=False,
                forwarded_allow_ips="")
    return 0


def cmd_leakbench(a) -> int:
    from .leakbench.runner import run

    report = asyncio.run(run(a.base_url, a.cases, sink_port=a.sink_port, sources_header=not a.no_provenance,
                         model=a.model, extra_body=json.loads(a.extra_body) if a.extra_body else None))
    print(json.dumps(report, indent=2))
    if not report["valid"]:
        print("INVALID RUN: " + "; ".join(report["problems"]), file=sys.stderr)
        return 5
    return 0 if report["leaks"] == 0 else 4


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="sovereign-router", description=__doc__)
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name in ("init", "doctor", "explain", "serve"):
        p = sub.add_parser(name)
        p.add_argument("-c", "--config", default=DEFAULT_CONFIG)
        if name == "init":
            p.add_argument("--force", action="store_true", help="replace an existing config")
            p.add_argument("--trust", action="append", default=[], metavar="NAME",
                           help="declare a discovered server local although it could not be verified (e.g. jan)")
        if name == "explain":
            p.add_argument("-f", "--file", help="a prompt or a JSON request body (default: stdin, so prompts stay out of shell history)")
            p.add_argument("--source", action="append", default=[], help="a source identifier (repeatable)")
            p.add_argument("--label", choices=["public", "private"])
            p.add_argument("--capability")
        if name == "serve":
            p.add_argument("--host", default="127.0.0.1")
            p.add_argument("--port", type=int, default=8787)
    lb = sub.add_parser("leakbench", help="run the leak suite against any OpenAI-compatible gateway")
    lb.add_argument("--base-url", required=True, help="the gateway under test, e.g. http://127.0.0.1:8787/v1")
    lb.add_argument("--cases", default=None, help="cases JSONL (default: the bundled suite)")
    lb.add_argument("--sink-port", type=int, default=8799, help="port of the recording fake cloud the gateway must point at")
    lb.add_argument("--no-provenance", action="store_true", help="send no x-sovereign-* headers (for gateways without them)")
    lb.add_argument("--model", help="model name to request for every case (default: each case's own, usually 'auto')")
    lb.add_argument("--extra-body", help="JSON merged into every request body; '{id}' becomes the case id (e.g. a session id)")
    a = ap.parse_args(argv)
    return {"init": cmd_init, "doctor": cmd_doctor, "explain": cmd_explain, "serve": cmd_serve,
            "leakbench": cmd_leakbench}[a.cmd](a)


if __name__ == "__main__":
    sys.exit(main())
