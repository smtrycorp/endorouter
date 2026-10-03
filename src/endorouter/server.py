"""OpenAI-compatible HTTP surface: POST /v1/chat/completions, GET /v1/models, GET /healthz.

Provenance travels in headers:
  x-endorouter-source: one source identifier per header (file path, URL, collection id); repeat it for several
  x-endorouter-label:  public | private
  x-endorouter-capability: a capability the chosen target must declare (e.g. "reasoning")
Headers that could LOOSEN routing (sources, a public label) are honoured only from provenance.trusted_clients.
A private label is honoured from anyone: tightening is always safe.

Only requests addressed to this machine by a loopback name are served, so a web page cannot reach the router through
DNS rebinding. v0.1 accepts text chat only; unknown request fields and non-text content parts are rejected rather
than silently dropped.
"""

from __future__ import annotations

import json
import sys

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response, StreamingResponse
from starlette.routing import Route

from . import __version__
from .audit import AuditError
from .config import Config
from .detectors import _table
from .labels import Label
from .policy import source_label
from .router import Refused, Router, SentUnrecorded, UpstreamFailed, iter_stream
from .validate import InvalidRequest
from .validate import validate as _validate

MAX_BODY = 4 * 1024 * 1024  # bytes; read no further, so a huge body cannot exhaust memory before it is refused
LOOPBACK_HOSTS = {"localhost", "127.0.0.1", "::1"}


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
    if declared.isdigit() and int(declared) > MAX_BODY:
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
    _table()  # build the detector normalisation table now, not on the first request

    async def chat(request: Request):
        if _host(request.headers.get("host", "")).lower() not in LOOPBACK_HOSTS:
            return _error(421, "this router answers only requests addressed to localhost, 127.0.0.1 or [::1]")
        raw = await _read_body(request)
        if raw is None:
            return _error(413, f"request body over {MAX_BODY // (1024 * 1024)} MB")
        try:
            body = json.loads(raw)
        except (json.JSONDecodeError, UnicodeDecodeError):
            return _error(400, "invalid JSON")
        problem = _validate(body)
        if problem:
            return _error(400, problem)
        peer = request.client.host if request.client else ""
        trusted = peer in cfg.provenance.trusted_clients
        # every value of a repeated header counts: a later "private" can never be dropped in favour of an earlier "public"
        try:
            label = Label.parse_all(request.headers.getlist("x-endorouter-label"))
        except ValueError as e:
            return _error(400, f"x-endorouter-label: {e}")
        if not trusted and label is not Label.PRIVATE:
            label = None  # an untrusted caller cannot declare anything public
        # One source per header value, since paths and URLs can contain commas. A proxy may still join repeated
        # headers with commas, so every comma-separated piece is also checked against the private patterns: a
        # piece that is private tightens the request, whoever sent it, which is always safe.
        raw_sources = [v.strip() for v in request.headers.getlist("x-endorouter-source") if v.strip()]
        pieces = {p.strip() for v in raw_sources for p in v.split(",") if p.strip()} | set(raw_sources)
        if any(source_label(s, cfg)[0] is Label.PRIVATE for s in pieces):
            label = Label.PRIVATE
        if not trusted:
            raw_sources = []  # an untrusted caller's sources could only lift a label, so they are not used
        caps = request.headers.getlist("x-endorouter-capability")
        if len(caps) > 1:
            return _error(400, "x-endorouter-capability may be sent once")
        capability = caps[0].strip() if caps and caps[0].strip() else None
        try:
            routed = await r.route(body, sources=raw_sources, declared=label, capability=capability, peer=peer,
                                   trusted=trusted)
        except InvalidRequest as e:
            return _error(400, str(e))
        except AuditError as e:
            # the cause (a path, an OS error) stays on this machine; the caller learns only that nothing was sent
            print(f"endorouter: audit log unwritable, request refused: {e}", file=sys.stderr)
            return _error(503, "the audit log could not be written, so nothing was sent")
        except SentUnrecorded as e:
            print(f"endorouter: request {e.request_id} was sent to {e.target} but could not be recorded", file=sys.stderr)
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

    return Starlette(routes=[
        Route("/v1/chat/completions", chat, methods=["POST"]),
        Route("/v1/models", models, methods=["GET"]),
        Route("/healthz", health, methods=["GET"]),
    ])
