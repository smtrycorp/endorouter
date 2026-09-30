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
from .labels import Label
from .router import Refused, Router, UpstreamFailed, iter_stream

SUPPORTED_FIELDS = {
    "model", "messages", "stream", "stream_options", "temperature", "top_p", "max_tokens", "max_completion_tokens",
    "stop", "n", "presence_penalty", "frequency_penalty", "seed", "tools", "tool_choice", "parallel_tool_calls",
    "response_format", "user", "logprobs", "top_logprobs", "logit_bias",
}


def _error(status: int, message: str, **extra) -> JSONResponse:
    return JSONResponse({"error": {"message": message, "type": "sovereign_router", **extra}}, status_code=status)


def _validate(body) -> str | None:
    if not isinstance(body, dict):
        return "request body must be a JSON object"
    extra = set(body) - SUPPORTED_FIELDS
    if extra:
        return f"unsupported field(s) {sorted(extra)} (sovereign-router v0.1 supports text chat completions)"
    msgs = body.get("messages")
    if not isinstance(msgs, list) or not msgs:
        return "messages must be a non-empty list"
    for i, m in enumerate(msgs):
        c = m.get("content") if isinstance(m, dict) else None
        if isinstance(c, list):
            for p in c:
                if not (isinstance(p, dict) and p.get("type") == "text"):
                    return f"messages[{i}]: only text content parts are supported in v0.1"
    return None


def create_app(cfg: Config, router: Router | None = None) -> Starlette:
    r = router or Router(cfg)

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
        label = Label.parse(request.headers.get("x-sovereign-label"))
        if not trusted and label is not Label.PRIVATE:
            label = None  # an untrusted caller cannot declare anything public
        sources = [s for s in (request.headers.get("x-sovereign-sources") or "").split(",") if s.strip()] if trusted else []
        capability = request.headers.get("x-sovereign-capability") or None
        try:
            routed = await r.route(body, sources=sources, declared=label, capability=capability)
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
        data = [{"id": "auto", "object": "model", "owned_by": "sovereign-router"}]
        data += [{"id": t.name, "object": "model", "owned_by": t.location} for t in cfg.targets]
        return JSONResponse({"object": "list", "data": data})

    async def health(_request: Request):
        return JSONResponse({"ok": True, "version": __version__, "mode": cfg.mode})

    return Starlette(routes=[
        Route("/v1/chat/completions", chat, methods=["POST"]),
        Route("/v1/models", models, methods=["GET"]),
        Route("/healthz", health, methods=["GET"]),
    ])
