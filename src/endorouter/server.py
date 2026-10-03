"""OpenAI-compatible HTTP surface: POST /v1/chat/completions, GET /v1/models, GET /healthz.

Provenance travels in headers:
  x-sovereign-sources: comma-separated source identifiers (file paths, URLs, collection ids)
  x-sovereign-label:   public | private
  x-sovereign-capability: a capability the chosen target must declare (e.g. "reasoning")
Headers that could LOOSEN routing (sources, a public label) are honoured only from provenance.trusted_clients.
A private label is honoured from anyone: tightening is always safe.

v0.1 accepts text chat only; unknown request fields and non-text content parts are rejected rather than silently dropped.
"""

from __future__ import annotations

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
from .router import Refused, Router, UpstreamFailed, iter_stream
from .validate import InvalidRequest, validate as _validate


def _error(status: int, message: str, **extra) -> JSONResponse:
    return JSONResponse({"error": {"message": message, "type": "endorouter", **extra}}, status_code=status)

def create_app(cfg: Config, router: Router | None = None) -> Starlette:
    r = router or Router(cfg)
    _table()  # build the detector normalisation table now, not on the first request

    async def chat(request: Request):
        try:
            body = await request.json()
        except Exception:  # noqa: BLE001
            return _error(400, "invalid JSON")
        problem = _validate(body)
        if problem:
            return _error(400, problem)
        peer = request.client.host if request.client else ""
        trusted = peer in cfg.provenance.trusted_clients
        # every value of a repeated header counts: a later "private" can never be dropped in favour of an earlier "public"
        try:
            label = Label.parse_all(request.headers.getlist("x-sovereign-label"))
        except ValueError as e:
            return _error(400, f"x-sovereign-label: {e}")
        if not trusted and label is not Label.PRIVATE:
            label = None  # an untrusted caller cannot declare anything public
        raw_sources = [s.strip() for v in request.headers.getlist("x-sovereign-sources") for s in v.split(",") if s.strip()]
        if raw_sources and not trusted:
            # an untrusted caller's sources could only lift a label, so they are ignored; but a source it says is
            # private still tightens, which is always safe
            label = Label.PRIVATE if any(source_label(s, cfg)[0] is Label.PRIVATE for s in raw_sources) else label
            raw_sources = []
        caps = request.headers.getlist("x-sovereign-capability")
        if len(caps) > 1:
            return _error(400, "x-sovereign-capability may be sent once")
        capability = caps[0].strip() if caps and caps[0].strip() else None
        try:
            routed = await r.route(body, sources=raw_sources, declared=label, capability=capability)
        except InvalidRequest as e:
            return _error(400, str(e))
        except AuditError as e:
            return _error(503, str(e))
        except Refused as e:
            return _error(403, e.decision.error or "refused", request_id=e.request_id, label=e.decision.label.name.lower(),
                          reasons=list(e.decision.reasons))
        except UpstreamFailed as e:
            return _error(502, "every permitted target failed; nothing was sent anywhere else", request_id=e.request_id,
                          attempts=e.attempts)
        headers = {
            "x-sovereign-request-id": routed.request_id,
            "x-sovereign-target": routed.target.name,
            "x-sovereign-location": routed.target.location,
            "x-sovereign-label": routed.decision.label.name.lower(),
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
