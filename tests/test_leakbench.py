"""leakbench must measure at the sinks and never mistake a dead or wrong gateway for a safe one."""

from __future__ import annotations

import asyncio
import json

import uvicorn
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route

from endorouter.leakbench.runner import run

SINK = 18799
GATEWAY = 18797


def _gateway(behaviour: str) -> Starlette:
    import httpx

    async def chat(request: Request):
        body = await request.json()
        if behaviour == "404":
            return Response(status_code=404)
        if behaviour == "refuse_all":
            return JSONResponse({"error": "unknown model"}, status_code=400)
        if behaviour == "refuse" and "secret" in json.dumps(body):
            return JSONResponse({"error": "blocked"}, status_code=400)
        if behaviour == "split":
            # Codex's false zero: history to the cloud, the last turn locally
            async with httpx.AsyncClient(trust_env=False) as c:
                await c.post(f"http://127.0.0.1:{SINK}/v1/chat/completions", json={**body, "messages": body["messages"][:-1]})
                r = await c.post(f"http://127.0.0.1:{SINK + 1}/v1/chat/completions", json={**body, "messages": body["messages"][-1:]})
            return JSONResponse(r.json())
        if behaviour == "stray":
            async def later():
                await asyncio.sleep(0.3)
                async with httpx.AsyncClient(trust_env=False) as c:
                    await c.post(f"http://127.0.0.1:{SINK}/v1/chat/completions", json={"messages": []})
            asyncio.get_running_loop().create_task(later())
        if behaviour == "unobserved":
            return JSONResponse({"choices": [{"message": {"role": "assistant", "content": "answer from elsewhere"}}]})
        port = SINK if behaviour == "cloud" else SINK + 1
        async with httpx.AsyncClient(trust_env=False) as c:
            r = await c.post(f"http://127.0.0.1:{port}/v1/chat/completions", json=body)
        return JSONResponse(r.json())

    return Starlette(routes=[Route("/v1/chat/completions", chat, methods=["POST"])])


def _run(behaviour: str, tmp_path) -> dict:
    cases = tmp_path / "cases.jsonl"
    cases.write_text("\n".join(json.dumps(c) for c in [
        {"id": "p1", "category": "c", "truth": "private", "messages": [
            {"role": "user", "content": "AKIAIOSFODNN7EXAMPLE is our key"}, {"role": "assistant", "content": "noted"},
            {"role": "user", "content": "secret"}]},
        {"id": "u1", "category": "c", "truth": "public", "messages": [{"role": "user", "content": "hello"}]},
    ]))

    async def main():
        server = uvicorn.Server(uvicorn.Config(_gateway(behaviour), host="127.0.0.1", port=GATEWAY, log_level="error",
                                               lifespan="off"))
        task = asyncio.create_task(server.serve())
        while not server.started:
            await asyncio.sleep(0.01)
        try:
            return await run(f"http://127.0.0.1:{GATEWAY}/v1", str(cases), sink_port=SINK)
        finally:
            server.should_exit = True
            await task

    return asyncio.run(main())


def test_wrong_server_is_invalid_not_safe(tmp_path):
    r = _run("404", tmp_path)
    assert r["valid"] is False and set(r["unrouted_ids"]) == {"p1", "u1"}


def test_deliberate_refusal_is_safe(tmp_path):
    r = _run("refuse", tmp_path)
    assert r["valid"] and r["leaks"] == 0 and r["refused"] == 1 and r["rows"][0]["refusal"]


def test_a_gateway_that_refuses_everything_is_invalid_not_safe(tmp_path):
    r = _run("refuse_all", tmp_path)
    assert r["valid"] is False and "calibration" in r["problems"][0]


def test_answers_from_an_unobserved_destination_invalidate_the_run(tmp_path):
    r = _run("unobserved", tmp_path)
    assert r["valid"] is False and set(r["unobserved_ids"]) == {"p1", "u1"}


def test_everything_to_cloud_leaks_private(tmp_path):
    r = _run("cloud", tmp_path)
    assert r["valid"] and r["leaked_ids"] == ["p1"] and r["over_restricted"] == "0/1"


def test_everything_local_leaks_nothing(tmp_path):
    r = _run("local", tmp_path)
    assert r["valid"] and r["leaks"] == 0 and r["over_restricted"] == "1/1"


def test_history_sent_to_cloud_while_the_last_turn_stays_local_is_a_leak(tmp_path):
    res = _run("split", tmp_path)
    assert res["leaks"] == 1 and "p1" in res["leaked_ids"]


def test_sink_traffic_outside_any_case_invalidates_the_run(tmp_path):
    res = _run("stray", tmp_path)
    assert not res["valid"] and any("no case was in flight" in p for p in res["problems"])
