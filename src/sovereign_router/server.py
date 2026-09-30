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

SUPPORTED_FIELDS = {
    "model", "messages", "stream", "stream_options", "temperature", "top_p", "max_tokens", "max_completion_tokens",
    "stop", "n", "presence_penalty", "frequency_penalty", "seed", "tools", "tool_choice", "parallel_tool_calls",
    "response_format", "user", "logprobs", "top_logprobs", "logit_bias",
}


def _error(status: int, message: str, **extra) -> JSONResponse:
    return JSONResponse({"error": {"message": message, "type": "sovereign_router", **extra}}, status_code=status)


ROLES = {"system", "developer", "user", "assistant", "tool"}
MESSAGE_FIELDS = {"role", "content", "name", "tool_calls", "tool_call_id", "refusal"}


def _validate(body) -> str | None:
    """Strict shape check: anything this version does not understand is refused, never forwarded unexamined."""
    if not isinstance(body, dict):
        return "request body must be a JSON object"
    extra = set(body) - SUPPORTED_FIELDS
    if extra:
        return f"unsupported field(s) {sorted(extra)} (sovereign-router v0.1 supports text chat completions)"
    if not isinstance(body.get("model", "auto"), str):
        return "model must be a string"
    msgs = body.get("messages")
    if not isinstance(msgs, list) or not msgs:
        return "messages must be a non-empty list"
    for i, m in enumerate(msgs):
        if not isinstance(m, dict) or m.get("role") not in ROLES:
            return f"messages[{i}]: must be an object with a role in {sorted(ROLES)}"
        if set(m) - MESSAGE_FIELDS:
            return f"messages[{i}]: unsupported field(s) {sorted(set(m) - MESSAGE_FIELDS)}"
        problem = _check_tool_calls(m.get("tool_calls"), f"messages[{i}]")
        if problem:
            return problem
        for k in ("name", "tool_call_id", "refusal"):
            if m.get(k) is not None and not isinstance(m.get(k), str):
                return f"messages[{i}].{k} must be a string"
        c = m.get("content")
        if isinstance(c, list):
            for p in c:
                if not (isinstance(p, dict) and p.get("type") == "text" and isinstance(p.get("text"), str) and set(p) <= {"type", "text"}):
                    return f"messages[{i}]: only text content parts are supported in v0.1"
        elif c is not None and not isinstance(c, str):
            return f"messages[{i}]: content must be a string, null or a list of text parts"
    for i, t in enumerate(body.get("tools") or []):
        f = t.get("function") if isinstance(t, dict) else None
        if not (isinstance(t, dict) and set(t) <= {"type", "function"} and t.get("type") == "function"
                and isinstance(f, dict) and isinstance(f.get("name"), str)
                and set(f) <= {"name", "description", "parameters", "strict"}):
            return f"tools[{i}]: only function tools with name, description, parameters and strict are supported"
    rf = body.get("response_format")
    if rf is not None and not (isinstance(rf, dict) and rf.get("type") in ("text", "json_object", "json_schema")
                               and set(rf) <= {"type", "json_schema"}):
        return "response_format: type must be text, json_object or json_schema"
    return None


def _check_tool_calls(calls, where: str) -> str | None:
    """Every tool call is a function call whose arguments are a string; any other shape could carry non-text payloads
    (an image, a file) that the upstream would receive before rejecting it."""
    if calls is None:
        return None
    if not isinstance(calls, list):
        return f"{where}.tool_calls must be a list"
    for j, tc in enumerate(calls):
        f = tc.get("function") if isinstance(tc, dict) else None
        if not (isinstance(tc, dict) and set(tc) <= {"id", "type", "function"} and tc.get("type") == "function"
                and isinstance(tc.get("id", ""), str) and isinstance(f, dict) and set(f) <= {"name", "arguments"}
                and isinstance(f.get("name"), str) and isinstance(f.get("arguments", ""), str)):
            return f"{where}.tool_calls[{j}]: only function calls with a name and string arguments are supported"
    return None


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
