"""OpenAI-compatible HTTP surface: POST /v1/chat/completions, GET /v1/models, GET /healthz.

Provenance travels in headers:
  x-endorouter-source: one source identifier per header (file path, URL, collection id); repeat it for several
  x-endorouter-label:  public | private
  x-endorouter-capability: a capability the chosen target must declare (e.g. "reasoning")
Headers that could LOOSEN routing (sources, a public label) are honoured only from provenance.trusted_clients.
A private label is honoured from anyone: tightening is always safe.

Only requests addressed to this machine by a loopback name, and carrying no browser Origin, are served: a web page can
reach neither through DNS rebinding nor by a cross-site POST, and every caller on this machine looks like 127.0.0.1. v0.1 accepts text chat only; unknown request fields and non-text content parts are rejected rather
than silently dropped.
"""

from __future__ import annotations

import asyncio
import json
import sys

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response, StreamingResponse
from starlette.routing import Route

from . import __version__
from .audit import AuditError
from .config import Config
from .detectors import _nonstarter_run, _table
from .labels import Label
from .policy import source_label
from .router import Refused, Router, SentUnrecorded, UpstreamFailed, iter_stream
from .validate import InvalidRequest
from .validate import validate as _validate

MAX_BODY = 4 * 1024 * 1024  # bytes; read no further, so a huge body cannot exhaust memory before it is refused
LOOPBACK_HOSTS = {"localhost", "127.0.0.1", "::1"}
# a source is a path or URL; matching cost grows with its segments, so an oversized one is treated as private unread
MAX_SOURCE_CHARS, MAX_SOURCES = 1024, 64


def _error(status: int, message: str, **extra) -> JSONResponse:
    return JSONResponse({"error": {"message": message, "type": "endorouter", **extra}}, status_code=status)


def _host(header: str) -> str:
    """The host name in a Host header, without the port: 'localhost:8000' -> localhost, '[::1]:8000' -> ::1."""
    if header.startswith("["):
        return header[1:].split("]", 1)[0]
    return header.rsplit(":", 1)[0] if header.count(":") == 1 else header


async def _read_body(request: Request) -> bytes | None:
    """The body, or None when it is larger than MAX_BODY."""
    declared = request.headers.get("content-length", "")
    # length first: int() refuses strings over 4300 digits, and anything over 9 digits is too large anyway
    if declared.isdigit() and (len(declared) > 9 or int(declared) > MAX_BODY):
        return None
    chunks, size = [], 0
    async for chunk in request.stream():
        size += len(chunk)
        if size > MAX_BODY:
            return None
        chunks.append(chunk)
    return b"".join(chunks)


def create_app(cfg: Config, router: Router | None = None) -> Starlette:
    r = router or Router(cfg)
    _table()  # build the detector normalisation tables now, not on the first request
    _nonstarter_run()

    async def chat(request: Request):
        # application/json cannot be sent cross-site without a CORS preflight, which this server never answers
        if request.headers.get("content-type", "").split(";")[0].strip().lower() != "application/json":
            return _error(415, "content-type must be application/json")
        raw = await _read_body(request)
        if raw is None:
            return _error(413, f"request body over {MAX_BODY // (1024 * 1024)} MB")
        try:
            body = await asyncio.to_thread(json.loads, raw)  # parsing megabytes off the event loop
        except (ValueError, RecursionError):  # bad JSON or UTF-8, a number too long to convert, or absurd nesting
            return _error(400, "invalid JSON")
        problem = await asyncio.to_thread(_validate, body)
        if problem:
            return _error(400, problem)
        peer = request.client.host if request.client else ""
        trusted = peer in cfg.provenance.trusted_clients
        # every value of a repeated header counts: a later "private" can never be dropped in favour of an earlier "public"
        try:
            label = Label.parse_all(request.headers.getlist("x-endorouter-label"))
        except ValueError as e:
            return _error(400, f"x-endorouter-label: {e}")
        supplied = label
        if not trusted and label is not Label.PRIVATE:
            label = None  # an untrusted caller cannot declare anything public
        # One source per header value, since paths and URLs can contain commas. Header bytes are read as UTF-8:
        # the HTTP layer hands them over as Latin-1, which would turn 'café/' into text no private pattern matches.
        try:
            values = [v.encode("latin-1").decode("utf-8").strip() for v in request.headers.getlist("x-endorouter-source")]
        except UnicodeError:
            return _error(400, "x-endorouter-source must be UTF-8")
        values = [v for v in values if v]
        # A proxy may join repeated headers with commas, so each comma-separated piece is checked too. Counted
        # before duplicates are dropped, and refused when over the limit: matching cost grows with them.
        pieces = [p.strip() for v in values for p in v.split(",") if p.strip()]
        if len(pieces) > MAX_SOURCES or any(len(v) > MAX_SOURCE_CHARS for v in values):
            return _error(400, f"x-endorouter-source: at most {MAX_SOURCES} sources of {MAX_SOURCE_CHARS} characters")
        # A private piece is passed on as a source, whoever sent it: it can only tighten, and the record then says
        # which source made the request private instead of rewriting what the caller declared. An untrusted
        # caller's other sources are dropped, since they could only lift a label.
        private = [p for p in dict.fromkeys(pieces + values) if source_label(p, cfg)[0] is Label.PRIVATE]
        raw_sources = list(dict.fromkeys((values if trusted else []) + private))
        caps = request.headers.getlist("x-endorouter-capability")
        if len(caps) > 1:
            return _error(400, "x-endorouter-capability may be sent once")
        capability = caps[0].strip() if caps and caps[0].strip() else None
        try:
            routed = await r.route(body, sources=raw_sources, declared=label, capability=capability, peer=peer,
                                   trusted=trusted, supplied=supplied)
        except InvalidRequest as e:
            return _error(400, str(e))
        except AuditError as e:
            # the cause (a path, an OS error) stays on this machine; the caller learns only that nothing was sent
            print(f"endorouter: audit log unwritable, request refused: {e}", file=sys.stderr)
            return _error(503, "the audit log could not be written, so nothing was sent")
        except SentUnrecorded as e:
            print(f"endorouter: request {e.request_id}: {e}", file=sys.stderr)
            if not e.target:
                # only a model probe left, carrying the model's name: no prompt did, and the caller is told exactly that
                return _error(503, f"the audit log could not be written; no prompt was sent, but a model probe to "
                                   f"{e.probed} was", request_id=e.request_id, probed=e.probed)
            return _error(502, "sent, but not recorded: the audit log failed after the request left; the response "
                               "was discarded", request_id=e.request_id, target=e.target)
        except Refused as e:
            return _error(403, e.decision.error or "refused", request_id=e.request_id, label=e.decision.label.name.lower(),
                          reasons=list(e.decision.reasons))
        except UpstreamFailed as e:
            return _error(502, "every permitted target failed; nothing was sent anywhere else", request_id=e.request_id,
                          attempts=e.attempts)
        headers = {
            "x-endorouter-request-id": routed.request_id,
            "x-endorouter-target": routed.target.name,
            "x-endorouter-location": routed.target.location,
            "x-endorouter-label": routed.decision.label.name.lower(),
        }
        up = routed.response
        if body.get("stream"):
            headers["content-type"] = up.headers.get("content-type", "text/event-stream")
            return StreamingResponse(iter_stream(up), status_code=up.status_code, headers=headers)
        content = await up.aread()
        await up.aclose()
        headers["content-type"] = up.headers.get("content-type", "application/json")
        return Response(content, status_code=up.status_code, headers=headers)

    async def models(_request: Request):
        data = [{"id": "auto", "object": "model", "owned_by": "endorouter"}]
        # a pass-through target is requested as "<name>/<model>", so it is listed that way, never as a bare name
        data += [{"id": f"{t.name}/*" if t.model == "*" else t.name, "object": "model", "owned_by": t.location}
                 for t in cfg.targets]
        return JSONResponse({"object": "list", "data": data})

    async def health(_request: Request):
        return JSONResponse({"ok": True, "version": __version__, "mode": cfg.mode})

    app = Starlette(routes=[
        Route("/v1/chat/completions", chat, methods=["POST"]),
        Route("/v1/models", models, methods=["GET"]),
        Route("/healthz", health, methods=["GET"]),
    ])
    return _local_only(app)


def _local_only(app):
    """Every route, not just chat: the target list and mode are this machine's business. A browser always sends
    Origin on a cross-site request and on any POST; local clients (SDKs, curl, editors) do not."""
    async def guard(scope, receive, send):
        if scope["type"] == "http":
            headers = {k.decode("latin-1").lower(): v.decode("latin-1") for k, v in scope.get("headers") or []}
            if _host(headers.get("host", "")).lower() not in LOOPBACK_HOSTS:
                return await _error(421, "this router answers only requests addressed to localhost, 127.0.0.1 or "
                                         "[::1]")(scope, receive, send)
            if "origin" in headers:
                return await _error(403, "requests from web pages are refused")(scope, receive, send)
        await app(scope, receive, send)
    return guard
