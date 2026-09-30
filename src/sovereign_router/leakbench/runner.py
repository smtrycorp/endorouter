"""leakbench: does private data reach a cloud? Portable: works against any OpenAI-compatible gateway.

Setup for the gateway under test: point its CLOUD destination at http://127.0.0.1:<sink-port>/v1 and its LOCAL destination
at http://127.0.0.1:<sink-port + 1>/v1. leakbench starts both as fake OpenAI servers. The cloud one records every request.

Each case carries a unique marker. After sending every case through the gateway, a case LEAKED if its marker reached the
cloud sink and its ground truth is private. It was OVER-RESTRICTED if its truth is public and it never reached the cloud
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
    text = Path(path).read_text() if path else resources.files("sovereign_router.leakbench").joinpath("cases.jsonl").read_text()
    return [json.loads(line) for line in text.splitlines() if line.strip()]


REFUSAL_STATUSES = {400, 403, 451}


CASE_METADATA = {"id", "category", "truth", "sources", "label", "model", "messages"}


def _marked(case: dict, model: str | None = None) -> tuple[dict, str]:
    # random and fixed-length, so no marker can contain another (lbk-p inside lbk-public was a false leak); lowercase
    # letters only, so the marker itself never looks like a secret to any detector (a random hex marker did)
    marker = "lbk" + "".join(secrets.choice("abcdefghijklmnopqrstuvwxyz") for _ in range(24))
    msgs = json.loads(json.dumps(case["messages"]))
    for m in reversed(msgs):
        if m.get("role") == "user" and isinstance(m.get("content"), str):
            m["content"] = f"{m['content']}\n[{marker}]"
            break
    # every request field a case carries is kept (stop, response_format, tools, ...); only benchmark metadata is not sent
    fields = {k: json.loads(json.dumps(v)) for k, v in case.items() if k not in CASE_METADATA}
    return {**fields, "model": model or case.get("model", "auto"), "messages": msgs}, marker


CALIBRATION = {"id": "calibration", "category": "calibration", "truth": "public",
               "messages": [{"role": "user", "content": "What is the capital of France?"}]}


def _answered_by(text: str) -> str:
    if "ok from fake-cloud" in text:
        return "cloud"
    if "ok from fake-local" in text:
        return "local"
    return "unobserved"


async def run(base_url: str, cases_path: str | None = None, *, sink_port: int = 8799, sources_header: bool = True,
              model: str | None = None, extra_body: dict | None = None) -> dict:
    cases = load_cases(cases_path)
    cloud_seen: list[str] = []
    local_seen: list[str] = []
    cloud = await _serve(_fake_openai("fake-cloud", cloud_seen), sink_port)
    local = await _serve(_fake_openai("fake-local", local_seen), sink_port + 1)
    rows: list[dict] = []
    try:
        async with httpx.AsyncClient(timeout=60, trust_env=False) as client:
            for c in [CALIBRATION, *cases]:
                body, marker = _marked(c, model)
                if extra_body:
                    body.update(json.loads(json.dumps(extra_body).replace("{id}", c["id"])))
                headers = {}
                if sources_header and c.get("sources"):
                    headers["x-sovereign-sources"] = ",".join(c["sources"])
                if sources_header and c.get("label"):
                    headers["x-sovereign-label"] = c["label"]
                text = ""
                try:
                    r = await client.post(f"{base_url.rstrip('/')}/chat/completions", json=body, headers=headers)
                    status, text = r.status_code, r.text
                except httpx.HTTPError as e:
                    status = f"error:{type(e).__name__}"
                row = {"id": c["id"], "category": c["category"], "truth": c["truth"], "marker": marker, "status": status,
                       "answered_by": _answered_by(text) if status == 200 else None}
                if status in REFUSAL_STATUSES:
                    row["refusal"] = text[:200]  # so a reader can check each refusal is a policy decision
                rows.append(row)
    finally:
        cloud.should_exit = True
        local.should_exit = True
        await asyncio.sleep(0.1)

    cloud_blob, local_blob = "\n".join(cloud_seen), "\n".join(local_seen)
    calib = rows.pop(0)
    calib_ok = calib["marker"] in cloud_blob or calib["marker"] in local_blob
    by_cat: dict[str, dict] = defaultdict(lambda: {"cases": 0, "leaked": 0, "over_restricted": 0})
    leaks, over, private_n, public_n = [], [], 0, 0
    for row in rows:
        reached_cloud = row["marker"] in cloud_blob
        if reached_cloud:
            row["reached"] = "cloud"
        elif row["marker"] in local_blob:
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
