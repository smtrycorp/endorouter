"""leakbench: does private data reach a cloud? Portable: works against any OpenAI-compatible gateway.

Setup for the gateway under test: point its CLOUD destination at http://127.0.0.1:<sink-port>/v1 and its LOCAL destination
at http://127.0.0.1:<sink-port + 1>/v1. leakbench starts both as fake OpenAI servers. The cloud one records every request.

Cases are sent one at a time, and each sink records which case was in flight when a request arrived. A private case
LEAKED if the cloud sink received anything while it was in flight, or anything carrying its marker (every message of a
case carries the case's unique marker, so a gateway that sends only part of a conversation, or sends it late, is still
caught). A request reaching a sink while no case is in flight cannot be attributed, and makes the run invalid. It was OVER-RESTRICTED if its truth is public and it never reached the cloud
(a cost, not a leak; strict routers accept it by design). The result is measured at the sink, never taken from the
gateway's own report.

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
import secrets
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


def _fake_openai(name: str, seen: list[tuple[str | None, str]], in_flight: dict) -> Starlette:
    async def chat(request: Request):
        raw = (await request.body()).decode("utf-8", "replace")
        seen.append((in_flight.get("case"), raw))
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


def _marked(case: dict, model: str | None = None) -> tuple[dict, str]:
    # random and fixed-length, so no marker can contain another (lbk-p inside lbk-public was a false leak); lowercase
    # letters only, so the marker itself never looks like a secret to any detector (a random hex marker did)
    marker = "lbk" + "".join(secrets.choice("abcdefghijklmnopqrstuvwxyz") for _ in range(24))
    msgs = json.loads(json.dumps(case["messages"]))
    # One marker, after everything the case says, so it never sits between two pieces a detector reads as one (a key
    # split across messages must stay joinable). It goes at the end of the last message's text, or, when that
    # message has none (a tool call), in a message of its own. Parts sent without it are found by their content.
    last = msgs[-1] if msgs else {}
    parts = [p for p in last.get("content") or [] if isinstance(p, dict) and isinstance(p.get("text"), str)] \
        if isinstance(last.get("content"), list) else []
    if isinstance(last.get("content"), str):
        last["content"] = f"{last['content']}\n[{marker}]"
    elif parts:
        parts[-1]["text"] = f"{parts[-1]['text']}\n[{marker}]"
    else:
        msgs.append({"role": "user", "content": f"[{marker}]"})
    # every request field a case carries is kept (stop, response_format, tools, ...); only benchmark metadata is not sent
    fields = {k: json.loads(json.dumps(v)) for k, v in case.items() if k not in CASE_METADATA}
    return {**fields, "model": model or case.get("model", "auto"), "messages": msgs}, marker


CALIBRATION = {"id": "calibration", "category": "calibration", "truth": "public",
               "messages": [{"role": "user", "content": "What is the capital of France?"}]}


FINGERPRINT_MIN = 12  # shorter strings ("hello", "auto") are too common to say which case they came from


def _content(body: dict) -> list[str]:
    """The strings a case says, where a secret can sit: message text and text parts, tool-call arguments, tool
    results. Not roles, types, ids or keys, which every case shares and which would name every case at once."""
    out = []
    for m in body.get("messages") or []:
        if not isinstance(m, dict):
            continue
        c = m.get("content")
        if isinstance(c, str):
            out.append(c)
        elif isinstance(c, list):
            out += [p["text"] for p in c if isinstance(p, dict) and isinstance(p.get("text"), str)]
        for call in m.get("tool_calls") or []:
            args = (call.get("function") or {}).get("arguments") if isinstance(call, dict) else None
            if isinstance(args, str):
                out.append(args)
    return out


def _case_strings(bodies: dict[str, dict], markers: set[str]) -> dict[str, set[str]]:
    """Per case, every content string it sent, marker removed; empty strings say nothing and are dropped."""
    return {cid: {s for s in (_unmarked(x, markers) for x in _content(body)) if s.strip()}
            for cid, body in bodies.items()}


def _unmarked(s: str, markers: set[str]) -> str:
    if "[lbk" in s:
        for m in markers:
            s = s.replace(f"\n[{m}]", "").replace(f"[{m}]", "")
    return s


def _fingerprints(strings: dict[str, set[str]]) -> dict[str, set[str]]:
    """Per case, the strings that name it when found inside a longer text: long enough to be specific, and neither
    equal to nor contained in anything another case sent (so a shared or overlapping system prompt names no one)."""
    prints = {}
    for cid, mine in strings.items():
        others = [s for other, ss in strings.items() if other != cid for s in ss]
        prints[cid] = {s for s in mine if len(s) >= FINGERPRINT_MIN and not any(s in o for o in others)}
    return prints


def _received(raw: str) -> list[str]:
    """What a sink was sent, as decoded strings: every string value in its JSON, so escaping cannot hide one."""
    try:
        body = json.loads(raw)
    except (ValueError, RecursionError):
        return [raw]
    out, stack = [], [body]
    while stack:
        v = stack.pop()
        if isinstance(v, str):
            out.append(v)
        elif isinstance(v, dict):
            stack.extend(v.values())
        elif isinstance(v, list):
            stack.extend(v)
    return out


def _answered_by(text: str) -> str:
    if "ok from fake-cloud" in text:
        return "cloud"
    if "ok from fake-local" in text:
        return "local"
    return "unobserved"


async def run(base_url: str, cases_path: str | None = None, *, sink_port: int = 8799, sources_header: bool = True,
              model: str | None = None, extra_body: dict | None = None, settle_s: float = 1.0) -> dict:
    cases = load_cases(cases_path)
    sent_bodies: dict[str, dict] = {}
    cloud_seen: list[tuple[str | None, str]] = []
    local_seen: list[tuple[str | None, str]] = []
    in_flight: dict = {"case": None}
    cloud = await _serve(_fake_openai("fake-cloud", cloud_seen, in_flight), sink_port)
    local = await _serve(_fake_openai("fake-local", local_seen, in_flight), sink_port + 1)
    rows: list[dict] = []
    try:
        async with httpx.AsyncClient(timeout=60, trust_env=False) as client:
            for c in [CALIBRATION, *cases]:
                body, marker = _marked(c, model)
                sent_bodies[c["id"]] = body
                if extra_body:
                    body.update(json.loads(json.dumps(extra_body).replace("{id}", c["id"])))
                headers: list[tuple[str, str]] = []
                if sources_header:  # one header per source, since a path or URL can contain a comma
                    headers += [("x-endorouter-source", s) for s in c.get("sources", [])]
                    if c.get("label"):
                        headers.append(("x-endorouter-label", c["label"]))
                text = ""
                in_flight["case"] = c["id"]
                try:
                    r = await client.post(f"{base_url.rstrip('/')}/chat/completions", json=body, headers=headers)
                    status, text = r.status_code, r.text
                except httpx.HTTPError as e:
                    status = f"error:{type(e).__name__}"
                finally:
                    in_flight["case"] = None
                row = {"id": c["id"], "category": c["category"], "truth": c["truth"], "marker": marker, "status": status,
                       "answered_by": _answered_by(text) if status == 200 else None}
                if status in REFUSAL_STATUSES:
                    row["refusal"] = text[:200]  # so a reader can check each refusal is a policy decision
                rows.append(row)
        # the sinks keep listening a little after the last case: a gateway that sends late is caught, not missed
        await asyncio.sleep(settle_s)
    finally:
        cloud.should_exit = True
        local.should_exit = True
        await asyncio.sleep(0.1)

    # A request belongs to every case whose marker it carries, and to every case whose own content it carries (so a
    # part of a conversation sent without the marker, such as a tool call, is still credited to its case). Only a
    # request with neither falls back to the case in flight, so a late send of one case is never credited to the next.
    # Then every exact string in the request that belongs to other cases, and is not explained by a case already
    # credited, is credited to all of its owners: an honest gateway sends one case's content only while that case
    # is in flight, so a string of another case's (however short, however shared) is a leak of that case's.
    markers = {r["marker"]: r["id"] for r in rows}
    strings = _case_strings(sent_bodies, set(markers))
    prints = _fingerprints(strings)
    owner_of: dict[str, set[str]] = defaultdict(set)
    for cid, ss in strings.items():
        for s in ss:
            owner_of[s].add(cid)

    def owners(case: str | None, raw: str) -> set[str]:
        got = _received(raw)
        text = "\n".join(got)
        found = {cid for m, cid in markers.items() if m in text}
        found |= {cid for cid, ss in prints.items() if any(s in text for s in ss)}
        if not found and case:
            found = {case}
        for s in got:
            who = owner_of.get(_unmarked(s, set(markers)))
            if who and not (who & found):
                found |= who
        return found

    cloud_ids = [owners(c, raw) for c, raw in cloud_seen]
    local_ids = [owners(c, raw) for c, raw in local_seen]

    def reached(ids: list[set[str]], row: dict) -> bool:
        return any(row["id"] in s for s in ids)

    calib = rows.pop(0)
    calib_ok = reached(cloud_ids, calib) or reached(local_ids, calib)
    stray = sum(1 for s in cloud_ids + local_ids if not s)
    by_cat: dict[str, dict] = defaultdict(lambda: {"cases": 0, "leaked": 0, "over_restricted": 0})
    leaks, over, private_n, public_n = [], [], 0, 0
    for row in rows:
        reached_cloud = reached(cloud_ids, row)
        if reached_cloud:
            row["reached"] = "cloud"
        elif reached(local_ids, row):
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
        problems.append(f"{stray} request(s) reached a sink while no case was in flight: they cannot be attributed, "
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
        "by_category": dict(sorted(by_cat.items())),
        "rows": rows,
    }
