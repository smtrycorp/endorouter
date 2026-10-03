"""leakbench: does private data reach a cloud? Portable: works against any OpenAI-compatible gateway.

Setup for the gateway under test: point its CLOUD destination at http://127.0.0.1:<sink-port>/v1 and its LOCAL destination
at http://127.0.0.1:<sink-port + 1>/v1. leakbench starts both as fake OpenAI servers. The cloud one records every request.

Each case is sent exactly as written, nothing added, one at a time, and the sinks keep listening a second after the
last. Cases are told apart by their own content: every case must contain a string of 8 or more characters that no other
case contains (the suite is refused otherwise). A private case LEAKED if any string of its own that no public case
also contains (message text, tool calls, tool definitions, schema keys, refusals: any field) arrived at the cloud sink
inside a single received string, whenever it arrived. So a gateway that forwards a whole conversation, a part of it,
or a part of it late, quoted inside other text, is caught; one that rewrites the text beyond recognition is not. A
case REACHED a sink only if its own content arrived there; a request carrying no case's content makes the run invalid.
It was OVER-RESTRICTED if its truth is public and it never reached the cloud (a cost, not a leak; strict routers accept
it by design). The result is measured at the sink, never taken from the gateway's own report.

A case that reached neither sink counts as REFUSED only when the gateway answered with a deliberate refusal status (400, 403,
451): that is safe for private data and over-restriction for public data. Anything else that reached no sink (connection
error, 404, 5xx) means the case was never routed, and the whole run is INVALID, because a gateway that answers nothing
trivially leaks nothing.

Two more checks keep a broken setup from passing. First, a benign CALIBRATION request must reach a sink before any case
counts, so a gateway that answers every request with "unknown model" or "missing API key" is invalid, not safe. Second,
every successful answer must come from one of the recording sinks: an answer from anywhere else means the gateway has a
destination leakbench cannot see, so the run is invalid.

Limit: a refusal is the gateway's own claim. leakbench cannot rule out that a refusing gateway also sent the request
somewhere it does not observe, so reports count refusals separately and mark them unverified.
"""

from __future__ import annotations

import asyncio
import json
import re
import time
from collections import defaultdict
from importlib import resources
from pathlib import Path

import httpx
import uvicorn
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route


def _fake_openai(name: str, seen: list[str]) -> Starlette:
    async def chat(request: Request):
        raw = (await request.body()).decode("utf-8", "replace")
        seen.append(raw)
        return JSONResponse({"id": f"{name}-1", "object": "chat.completion", "created": int(time.time()), "model": name,
                             "choices": [{"index": 0, "finish_reason": "stop",
                                          "message": {"role": "assistant", "content": f"ok from {name}"}}],
                             "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}})

    return Starlette(routes=[Route("/v1/chat/completions", chat, methods=["POST"])])


async def _serve(app: Starlette, port: int) -> uvicorn.Server:
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error", lifespan="off"))
    asyncio.get_running_loop().create_task(server.serve())
    for _ in range(100):
        if server.started:
            return server
        await asyncio.sleep(0.02)
    raise RuntimeError(f"fake server on {port} did not start")


def load_cases(path: str | None) -> list[dict]:
    text = Path(path).read_text() if path else resources.files("endorouter.leakbench").joinpath("cases.jsonl").read_text()
    return [json.loads(line) for line in text.splitlines() if line.strip()]


REFUSAL_STATUSES = {400, 403, 451}


CASE_METADATA = {"id", "category", "truth", "sources", "label", "model", "messages"}


def _body(case: dict, model: str | None = None) -> dict:
    """The request exactly as the case defines it. Nothing is added: any tag in the text could change what a
    detector or a classifier decides (a random-letter tag once made a classifier call a public question private,
    and a prefix stopped JSON in a message being read as JSON), so cases are told apart by their own content."""
    # every request field a case carries is kept (stop, response_format, tools, ...); only benchmark metadata is not sent
    fields = {k: json.loads(json.dumps(v)) for k, v in case.items() if k not in CASE_METADATA}
    return {**fields, "model": model or case.get("model", "auto"), "messages": json.loads(json.dumps(case["messages"]))}


CALIBRATION = {"id": "calibration", "category": "calibration", "truth": "public",
               "messages": [{"role": "user", "content": "What is the capital of France?"}]}

EVIDENCE_MIN = 8  # shorter strings ("hello", "auto") are too common to say which case they came from; reported as unmeasured
TOKEN_MIN = 12  # a word this long (a key, an id) is evidence on its own, so a credential cut out of its sentence is seen
# request fields that say how to answer, never what: not evidence, and a gateway may add them to any request
CONTROL_FIELDS = frozenset({"model", "stream", "stream_options", "n", "temperature", "top_p", "max_tokens",
                            "max_completion_tokens", "presence_penalty", "frequency_penalty", "seed", "logprobs",
                            "top_logprobs", "parallel_tool_calls", "tool_choice"})
# keys whose values are API syntax (roles, types, ids, identifiers), never what a case says
SYNTAX_KEYS = frozenset({"role", "type", "id", "tool_call_id", "name", "$schema", "format"})


def _payload(body) -> list[str]:
    """What a request says, as strings: message text and text parts, refusals, tool-call arguments, and everything in
    the other fields (tool definitions, schemas, stop sequences, metadata), schema property names and long numbers
    included. Never the API's own syntax: field names, roles, types, ids or names, which any request carries and a
    gateway may add. Cases and what sinks receive are read by this same function, so a string counted as unique to
    a case is looked for in exactly the kind of place it was found."""
    if not isinstance(body, dict):
        return []
    out: list[str] = []
    stack: list[tuple[object, bool]] = []  # (value, its keys are schema property names)
    for m in body.get("messages") or []:
        if isinstance(m, dict):
            stack += [(m.get(k), False) for k in ("content", "refusal") if m.get(k) is not None]
            for call in m.get("tool_calls") or []:
                if isinstance(call, dict) and isinstance(call.get("function"), dict):
                    stack.append((call["function"].get("arguments"), False))
    stack += [(v, False) for k, v in body.items() if k not in CONTROL_FIELDS and k != "messages"]
    while stack:
        v, props = stack.pop()
        if isinstance(v, str):
            out.append(v)
        elif isinstance(v, bool) or v is None:
            continue
        elif isinstance(v, (int, float)):
            if len(str(v)) >= EVIDENCE_MIN:
                out.append(str(v))
        elif isinstance(v, dict):
            for k, x in v.items():
                if props and isinstance(k, str):
                    out.append(k)  # a schema's property name is content: it can be a secret
                if k not in SYNTAX_KEYS:
                    stack.append((x, k == "properties"))
        elif isinstance(v, list):
            stack += [(x, False) for x in v]
    return out


_TOKEN = re.compile(r"[^\s\"'`,;:()\[\]{}<>]+")


def _case_evidence(body: dict) -> tuple[set[str], set[str]]:
    """A case's evidence (strings and long tokens of EVIDENCE_MIN+ characters), and the short strings that are too
    short to be measured."""
    strings = {s.strip() for s in _payload(body)}
    tokens = {tok.strip(".!?") for s in strings for tok in _TOKEN.findall(s)}
    evidence = {s for s in strings if len(s) >= EVIDENCE_MIN} | {x for x in tokens if len(x) >= TOKEN_MIN}
    return evidence, {s for s in strings if 0 < len(s) < EVIDENCE_MIN}


def validate_suite(cases: list[dict]) -> None:
    """Refuse a suite that would silently change the experiment: a repeated id (one body would replace another), a
    truth other than "private" or "public" (it would be scored as public), or a case with no messages."""
    seen = {CALIBRATION["id"]}
    for i, c in enumerate(cases):
        cid = c.get("id")
        if not isinstance(cid, str) or not cid or cid in seen:
            raise ValueError(f"case {i}: id {cid!r} is missing, repeated, or reserved")
        seen.add(cid)
        if c.get("truth") not in ("private", "public"):
            raise ValueError(f"case {cid!r}: truth must be \"private\" or \"public\", not {c.get('truth')!r}")
        if not isinstance(c.get("messages"), list) or not c["messages"]:
            raise ValueError(f"case {cid!r}: messages must be a non-empty list")


def _evidence(bodies: dict[str, dict], truths: dict[str, str]
              ) -> tuple[dict[str, set[str]], dict[str, set[str]], dict[str, set[str]]]:
    """Per case: the strings that identify it (found in no other case's payload), the strings whose arrival at the
    cloud is a leak (private cases; found in no public case's payload, so possibly shared with another private
    case, which then leaked too), and the strings too short to measure. Raises ValueError for a case with nothing
    of its own: it could not be told apart from the others, so no result about it would mean anything."""
    measured = {cid: _case_evidence(b) for cid, b in bodies.items()}
    payloads = {cid: [s for s in _payload(b)] for cid, b in bodies.items()}
    public_text = [s for cid, ss in payloads.items() if truths[cid] == "public" for s in ss]
    ident, leak, unmeasured = {}, {}, {}
    for cid, (mine, short) in measured.items():
        others = [s for other, ss in payloads.items() if other != cid for s in ss]
        ident[cid] = {s for s in mine if not any(s in o for o in others)}
        if not ident[cid]:
            raise ValueError(f"case {cid!r} has no text of its own ({EVIDENCE_MIN}+ characters found in no other "
                             "case), so leakbench cannot tell where it went; give it some")
        if truths[cid] == "private":
            leak[cid] = {s for s in mine if not any(s in o for o in public_text)}
            unmeasured[cid] = short
    return ident, leak, unmeasured


def _received(raw: str) -> list[str]:
    """What a sink was sent, read as a case is (see _payload); a body that is not JSON is one string."""
    try:
        return _payload(json.loads(raw))
    except (ValueError, RecursionError):
        return [raw]


def _contains(evidence: set[str], got: list[str]) -> bool:
    """Is any piece of evidence inside one of the received strings? One string at a time: text from two messages is
    never joined, or a case's string could be assembled from pieces another case sent separately."""
    return any(e in g for e in evidence for g in got)


def _answered_by(text: str) -> str:
    if "ok from fake-cloud" in text:
        return "cloud"
    if "ok from fake-local" in text:
        return "local"
    return "unobserved"


async def run(base_url: str, cases_path: str | None = None, *, sink_port: int = 8799, sources_header: bool = True,
              model: str | None = None, extra_body: dict | None = None, settle_s: float = 1.0) -> dict:
    cases = load_cases(cases_path)
    validate_suite(cases)
    bodies = {c["id"]: _body(c, model) for c in [CALIBRATION, *cases]}
    ident, leak_evidence, unmeasured = _evidence(bodies, {c["id"]: c["truth"] for c in [CALIBRATION, *cases]})
    cloud_seen: list[str] = []
    local_seen: list[str] = []
    cloud = await _serve(_fake_openai("fake-cloud", cloud_seen), sink_port)
    local = await _serve(_fake_openai("fake-local", local_seen), sink_port + 1)
    rows: list[dict] = []
    try:
        async with httpx.AsyncClient(timeout=60, trust_env=False) as client:
            for c in [CALIBRATION, *cases]:
                body = json.loads(json.dumps(bodies[c["id"]]))
                if extra_body:
                    body.update(json.loads(json.dumps(extra_body).replace("{id}", c["id"])))
                headers: list[tuple[str, str]] = []
                if sources_header:  # one header per source, since a path or URL can contain a comma
                    headers += [("x-endorouter-source", s) for s in c.get("sources", [])]
                    if c.get("label"):
                        headers.append(("x-endorouter-label", c["label"]))
                text = ""
                try:
                    r = await client.post(f"{base_url.rstrip('/')}/chat/completions", json=body, headers=headers)
                    status, text = r.status_code, r.text
                except httpx.HTTPError as e:
                    status = f"error:{type(e).__name__}"
                row = {"id": c["id"], "category": c["category"], "truth": c["truth"], "status": status,
                       "answered_by": _answered_by(text) if status == 200 else None}
                if status in REFUSAL_STATUSES:
                    row["refusal"] = text[:200]  # so a reader can check each refusal is a policy decision
                if unmeasured.get(c["id"]):  # strings too short to tell apart: a leak of only these is not seen
                    row["unmeasured"] = sorted(unmeasured[c["id"]])
                rows.append(row)
        # the sinks keep listening a little after the last case: a gateway that sends late is caught, not missed
        await asyncio.sleep(settle_s)
    finally:
        cloud.should_exit = True
        local.should_exit = True
        await asyncio.sleep(0.1)

    # Every request a sink received, as the cases whose content it carries: a case's own strings show it ran there;
    # a private case's leak evidence at the cloud is a leak, whenever it arrived and whatever else came with it.
    cloud_got = [_received(raw) for raw in cloud_seen]
    local_got = [_received(raw) for raw in local_seen]

    def at(got: list[list[str]], cid: str) -> bool:
        return any(_contains(ident[cid], g) for g in got)

    def leaked(cid: str) -> bool:
        return any(_contains(leak_evidence[cid], g) for g in cloud_got)

    def anyone(g: list[str]) -> bool:  # a request carrying no case's content cannot be attributed
        return any(_contains(ident[c], g) for c in ident) or any(_contains(ev, g) for ev in leak_evidence.values())

    calib = rows.pop(0)
    calib_ok = at(cloud_got, calib["id"]) or at(local_got, calib["id"])
    stray = sum(1 for g in cloud_got + local_got if not anyone(g))
    by_cat: dict[str, dict] = defaultdict(lambda: {"cases": 0, "leaked": 0, "over_restricted": 0})
    leaks, over, private_n, public_n = [], [], 0, 0
    for row in rows:
        # where the case demonstrably went is shown only by content unique to it; a private case's leak is shown by
        # any of its private strings at the cloud, which may be shared with another private case
        reached_cloud = leaked(row["id"]) if row["truth"] == "private" else at(cloud_got, row["id"])
        if at(cloud_got, row["id"]):
            row["reached"] = "cloud"
        elif at(local_got, row["id"]):
            row["reached"] = "local"
        elif row["status"] in REFUSAL_STATUSES:
            row["reached"] = "refused"
        else:
            row["reached"] = "none"
        cat = by_cat[row["category"]]
        cat["cases"] += 1
        if row["truth"] == "private":
            private_n += 1
            if reached_cloud:
                leaks.append(row["id"])
                cat["leaked"] += 1
        else:
            public_n += 1
            if not reached_cloud:
                over.append(row["id"])
                cat["over_restricted"] += 1
    # Never routed (gateway down, wrong URL, server error): the run is INVALID rather than a pass.
    unrouted = [r["id"] for r in rows if r["reached"] == "none"]
    unobserved = [r["id"] for r in rows if r["answered_by"] == "unobserved"]
    problems = []
    if not calib_ok:
        problems.append(f"calibration request did not reach a sink (status {calib['status']}): the gateway is not "
                        "operational or not wired to the sinks, so its refusals mean nothing")
    if unrouted:
        problems.append(f"{len(unrouted)} case(s) reached no sink and were not refused")
    if stray:
        problems.append(f"{stray} request(s) reached a sink carrying no case's content: they cannot be attributed, "
                        "so a leak could hide among them")
    if unobserved:
        problems.append(f"{len(unobserved)} answer(s) came from a destination leakbench does not observe")
    return {
        "valid": not problems,
        "problems": problems,
        "unrouted_ids": unrouted,
        "unobserved_ids": unobserved,
        "gateway": base_url,
        "cases": len(rows),
        "private_cases": private_n,
        "leaks": len(leaks),
        "leak_rate": f"{len(leaks)}/{private_n}",
        "refused": sum(1 for r in rows if r["reached"] == "refused"),
        # a refusal is the gateway's own statement that it sent nothing; leakbench sees its sinks, not the gateway's
        # other egress, so refusals are reported as unverified and never folded into a claim of zero leaks
        "refusals_verified": False,
        "public_cases": public_n,
        "over_restricted": f"{len(over)}/{public_n}",
        "leaked_ids": leaks,
        # private cases with strings too short to measure: a leak of only those strings would not be counted
        "unmeasured_ids": sorted(cid for cid, ss in unmeasured.items() if ss),
        "by_category": dict(sorted(by_cat.items())),
        "rows": rows,
    }
