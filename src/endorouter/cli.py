"""Command line: init, doctor, explain, serve, leakbench."""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from pathlib import Path
from urllib.parse import urlparse

from .audit import OPEN_FLAGS
from .config import ConfigError, load_config
from .detectors import scan_request
from .labels import Label
from .policy import decide

LOOPBACK = {"127.0.0.1", "localhost", "::1"}
DEFAULT_CONFIG = "endorouter.yaml"


def _cfg(path: str):
    if path == DEFAULT_CONFIG and not Path(path).exists():
        return _auto()[2]  # no config file: use what discovery finds, as `serve` does
    try:
        return load_config(path)
    except ConfigError as e:
        sys.exit(f"config error: {e}")


def cmd_doctor(args) -> int:
    cfg = _cfg(args.config)
    ok = True
    print(f"config: {args.config}  mode={cfg.mode}  targets={len(cfg.targets)}  audit_log={cfg.audit_log}")
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
        # created the way the router creates it (owner-only), so doctor never leaves a world-readable log behind
        os.close(os.open(cfg.audit_log, OPEN_FLAGS, 0o600))
        print("audit log: writable")
        if sys.platform == "win32":
            # Windows ignores the mode: the file takes its folder's access list, and the default folder,
            # %LOCALAPPDATA%, is private to the user
            print("audit log: access follows its folder on Windows; keep it in a folder only you can read")
        elif os.stat(cfg.audit_log).st_mode & 0o077:
            # the mode applies only when the file is created: an older log may still be readable by others
            print(f"audit log: readable by other users; run `chmod 600 {cfg.audit_log}`")
            ok = False
    except OSError as e:
        print(f"audit log: NOT writable ({e}); every request would be refused")
        ok = False
    return 0 if ok else 1


def cmd_explain(args) -> int:
    cfg = _cfg(args.config)
    text = Path(args.file).read_text() if args.file else sys.stdin.read()
    try:
        body = json.loads(text)
        if not isinstance(body, dict) or "messages" not in body:
            raise ValueError
    except ValueError:
        body = {"model": "auto", "messages": [{"role": "user", "content": text}]}
    findings = scan_request(body, extra=[(f"sources[{i}]", s) for i, s in enumerate(args.source)])
    d = decide(cfg, requested_model=body.get("model"), sources=args.source, declared=Label.parse(args.label), findings=findings,
               capability=args.capability)
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
    from .discover import verify_target

    problems = []
    for t in cfg.targets:
        reason = verify_target(t) if t.is_local else None
        if reason:
            problems.append(f"{t.name}: {t.url}: {reason}; refusing to use it (run `endorouter init --force` to re-detect)")
    return problems


def cmd_init(args) -> int:
    import yaml

    if Path(args.config).exists() and not args.force:
        sys.exit(f"{args.config} already exists (use --force to replace it)")
    raw, notes, _ = _auto(tuple(args.trust))
    for n in notes:
        print(n)
    Path(args.config).write_text("# written by `endorouter init`: everything below was found, not asked for\n"
                              + yaml.safe_dump(raw, sort_keys=False))
    print(f"wrote {args.config}; strict mode: nothing leaves this machine unless a trusted client labels it public")
    return 0


def cmd_serve(args) -> int:
    import uvicorn

    from .server import create_app

    if args.host not in LOOPBACK:
        # the router trusts callers by address and has no authentication of its own: on a network address, anyone
        # who can reach the port could ask for anything. Loopback only; a remote machine reaches it through SSH.
        sys.exit(f"--host {args.host}: EndoRouter listens on this machine only (127.0.0.1, localhost or ::1)")
    if args.config == DEFAULT_CONFIG and not Path(args.config).exists():
        # zero-question start: discover the local server and any cloud keys, protect standard secret files, strict mode
        _, notes, cfg = _auto()
        for n in notes:
            print(n)
        print(f"strict mode, audit log {cfg.audit_log}; serving on http://{args.host}:{args.port}/v1")
    else:
        cfg = _cfg(args.config)
    problems = _reverify(cfg)
    if problems:
        sys.exit("\n".join(problems))
    # proxy headers off: X-Forwarded-For must never let a caller borrow a trusted client's address. Behind a reverse
    # proxy the proxy itself is the peer; list it in trusted_clients only if every caller behind it is trusted.
    uvicorn.run(create_app(cfg), host=args.host, port=args.port, log_level="warning", proxy_headers=False,
                forwarded_allow_ips="")
    return 0


def cmd_leakbench(args) -> int:
    from .leakbench.runner import run

    report = asyncio.run(run(args.base_url, args.cases, sink_port=args.sink_port, sources_header=not args.no_provenance,
                         model=args.model, extra_body=json.loads(args.extra_body) if args.extra_body else None))
    print(json.dumps(report, indent=2))
    if not report["valid"]:
        print("INVALID RUN: " + "; ".join(report["problems"]), file=sys.stderr)
        return 5
    return 0 if report["leaks"] == 0 else 4


SUPPORTED_PLATFORMS = ("darwin", "linux", "win32")


def main(argv: list[str] | None = None) -> int:
    # the audit lock is chosen by platform at import, and only these three have one; refusing here beats an
    # ImportError three modules deep
    if sys.platform not in SUPPORTED_PLATFORMS:
        print(f"endorouter runs on macOS, Linux and Windows; this is {sys.platform}.", file=sys.stderr)
        return 2
    ap = argparse.ArgumentParser(prog="endorouter", description=__doc__)
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
    lb.add_argument("--no-provenance", action="store_true", help="send no x-endorouter-* headers (for gateways without them)")
    lb.add_argument("--model", help="model name to request for every case (default: each case's own, usually 'auto')")
    lb.add_argument("--extra-body", help="JSON merged into every request body; '{id}' becomes the case id (e.g. a session id)")
    args = ap.parse_args(argv)
    return {"init": cmd_init, "doctor": cmd_doctor, "explain": cmd_explain, "serve": cmd_serve,
            "leakbench": cmd_leakbench}[args.cmd](args)


if __name__ == "__main__":
    sys.exit(main())
