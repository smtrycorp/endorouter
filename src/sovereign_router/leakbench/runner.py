"""leakbench: does private data reach a cloud? Portable: works against any OpenAI-compatible gateway.

Setup for the gateway under test: point its CLOUD destination at http://127.0.0.1:<sink-port>/v1 and its LOCAL destination
at http://127.0.0.1:<sink-port + 1>/v1. leakbench starts both as fake OpenAI servers. The cloud one records every request.

Each case carries a unique marker. After sending every case through the gateway, a case LEAKED if its marker reached the
cloud sink and its ground truth is private. It was OVER-RESTRICTED if its truth is public and it never reached the cloud
(a cost, not a leak; strict routers accept it by design). The result is measured at the sink, never taken from the
gateway's own report.
"""

from __future__ import annotations

import asyncio
import json
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


def _marked(case: dict) -> tuple[dict, str]:
    marker = f"lbk-{case['id']}"
    msgs = json.loads(json.dumps(case["messages"]))
    for m in reversed(msgs):
        if m.get("role") == "user" and isinstance(m.get("content"), str):
            m["content"] = f"{m['content']}\n[{marker}]"
            break
    return {"model": case.get("model", "auto"), "messages": msgs, **({"tools": case["tools"]} if case.get("tools") else {})}, marker


async def run(base_url: str, cases_path: str | None = None, *, sink_port: int = 8799, sources_header: bool = True) -> dict:
    cases = load_cases(cases_path)
    cloud_seen: list[str] = []
    local_seen: list[str] = []
    cloud = await _serve(_fake_openai("fake-cloud", cloud_seen), sink_port)
    local = await _serve(_fake_openai("fake-local", local_seen), sink_port + 1)
    rows = []
    try:
        async with httpx.AsyncClient(timeout=60, trust_env=False) as client:
            for c in cases:
                body, marker = _marked(c)
                headers = {}
                if sources_header and c.get("sources"):
                    headers["x-sovereign-sources"] = ",".join(c["sources"])
                if sources_header and c.get("label"):
                    headers["x-sovereign-label"] = c["label"]
                try:
                    r = await client.post(f"{base_url.rstrip('/')}/chat/completions", json=body, headers=headers)
                    status = r.status_code
                except httpx.HTTPError as e:
                    status = f"error:{type(e).__name__}"
                rows.append({"id": c["id"], "category": c["category"], "truth": c["truth"], "marker": marker, "status": status})
    finally:
        cloud.should_exit = True
        local.should_exit = True
        await asyncio.sleep(0.1)

    cloud_blob, local_blob = "\n".join(cloud_seen), "\n".join(local_seen)
    by_cat: dict[str, dict] = defaultdict(lambda: {"cases": 0, "leaked": 0, "over_restricted": 0})
    leaks, over, private_n, public_n = [], [], 0, 0
    for row in rows:
        reached_cloud = row["marker"] in cloud_blob
        row["reached"] = "cloud" if reached_cloud else ("local" if row["marker"] in local_blob else "none")
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
    # A case that reached neither destination was never routed (gateway down, wrong URL, refused). A gateway that answers
    # nothing trivially "leaks nothing", so any unrouted case makes the whole run INVALID rather than a pass.
    unrouted = [r["id"] for r in rows if r["reached"] == "none"]
    return {
        "valid": not unrouted,
        "unrouted_ids": unrouted,
        "gateway": base_url,
        "cases": len(rows),
        "private_cases": private_n,
        "leaks": len(leaks),
        "leak_rate": f"{len(leaks)}/{private_n}",
        "public_cases": public_n,
        "over_restricted": f"{len(over)}/{public_n}",
        "leaked_ids": leaks,
        "by_category": dict(sorted(by_cat.items())),
        "rows": rows,
    }
