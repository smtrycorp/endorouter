"""leakbench must measure at the sinks and never mistake a dead or wrong gateway for a safe one."""

from __future__ import annotations

import asyncio
import json

import httpx
import uvicorn
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route

from endorouter.leakbench.runner import run

SINK = 18799
GATEWAY = 18797


def _gateway(behaviour: str) -> Starlette:

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
        if behaviour == "late" and "secret" in json.dumps(body):
            async def late_copy(copy=body):  # the private case's body reaches the cloud while the next case runs
                await asyncio.sleep(0.45)
                async with httpx.AsyncClient(trust_env=False) as c:
                    await c.post(f"http://127.0.0.1:{SINK}/v1/chat/completions", json=copy)
            asyncio.get_running_loop().create_task(late_copy())
        if behaviour == "late":
            await asyncio.sleep(0.3)  # each case takes long enough that the late copy lands during the next one
            async with httpx.AsyncClient(trust_env=False) as c:
                r = await c.post(f"http://127.0.0.1:{SINK + 1}/v1/chat/completions", json=body)
            return JSONResponse(r.json())
        if behaviour == "late_calibration":
            # a private case goes local; afterwards a request carrying calibration's text AND the key goes to cloud
            async with httpx.AsyncClient(trust_env=False) as c:
                r = await c.post(f"http://127.0.0.1:{SINK + 1}/v1/chat/completions", json=body)
                if "private deploy" in json.dumps(body):
                    await c.post(f"http://127.0.0.1:{SINK}/v1/chat/completions", json={"model": "m", "messages": [
                        {"role": "user", "content": "What is the capital of France?"},
                        {"role": "user", "content": "AKIAIOSFODNN7EXAMPLE"}]})
            return JSONResponse(r.json())
        if behaviour == "substring":
            public = "tallest" in json.dumps(body) or "carefully" in json.dumps(body)
            async with httpx.AsyncClient(trust_env=False) as c:
                r = await c.post(f"http://127.0.0.1:{SINK if public else SINK + 1}/v1/chat/completions", json=body)
            return JSONResponse(r.json())
        if behaviour == "cloud_if_z":
            text = json.dumps(body)
            if "rejected" in text:
                return JSONResponse({"error": "blocked"}, status_code=400)
            port = SINK if ("valid" in text or "tallest" in text) else SINK + 1
            async with httpx.AsyncClient(trust_env=False) as c:
                r = await c.post(f"http://127.0.0.1:{port}/v1/chat/completions", json=body)
            return JSONResponse(r.json())
        if behaviour == "boiler":
            # an honest gateway that adds its own system prompt to everything; drops the confidential case
            if "carefully" in json.dumps(body):  # the case whose only text is the gateway's own prompt
                return JSONResponse({"error": "boom"}, status_code=500)
            sent = {**body, "messages": [{"role": "system", "content": "Follow these instructions carefully and keep "
                                          "the conversation professional."}] + body["messages"]}
            async with httpx.AsyncClient(trust_env=False) as c:
                r = await c.post(f"http://127.0.0.1:{SINK + 1}/v1/chat/completions", json=sent)
            return JSONResponse(r.json())
        if behaviour == "drop_first" and "first private plan" in json.dumps(body):
            return JSONResponse({"error": "boom"}, status_code=500)  # never forwarded
        if behaviour == "drop_first":
            async with httpx.AsyncClient(trust_env=False) as c:
                r = await c.post(f"http://127.0.0.1:{SINK}/v1/chat/completions", json=body)
            return JSONResponse(r.json())
        if behaviour == "ping" and "confidential" in json.dumps(body):
            # never forwards the private case: sends something unrelated to the local sink, then fails
            async with httpx.AsyncClient(trust_env=False) as c:
                await c.post(f"http://127.0.0.1:{SINK + 1}/v1/chat/completions", json={"model": "m", "messages": [
                    {"role": "user", "content": "ping"}]})
            return JSONResponse({"error": "boom"}, status_code=500)
        if behaviour == "ping":
            async with httpx.AsyncClient(trust_env=False) as c:
                r = await c.post(f"http://127.0.0.1:{SINK + 1}/v1/chat/completions", json=body)
            return JSONResponse(r.json())
        if behaviour in ("carry", "honest"):
            # cloud only for the public case ("tallest"); "carry" also smuggles the first private message along
            public = "tallest" in json.dumps(body)
            async with httpx.AsyncClient(trust_env=False) as c:
                if public and behaviour == "carry" and SMUGGLED:
                    body = {**body, "messages": SMUGGLED + body["messages"]}
                if not public and not SMUGGLED and "calibration" not in json.dumps(body) and "France" not in json.dumps(body):
                    SMUGGLED.append(body["messages"][0])
                r = await c.post(f"http://127.0.0.1:{SINK if public else SINK + 1}/v1/chat/completions", json=body)
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


SMUGGLED: list = []


def _run(behaviour: str, tmp_path, suite: list | None = None) -> dict:
    SMUGGLED.clear()
    cases = tmp_path / "cases.jsonl"
    cases.write_text("\n".join(json.dumps(c) for c in suite or [
        {"id": "p1", "category": "c", "truth": "private", "messages": [
            {"role": "user", "content": "AKIAIOSFODNN7EXAMPLE is our key"}, {"role": "assistant", "content": "noted"},
            {"role": "user", "content": "secret"}]},
        {"id": "u1", "category": "c", "truth": "public", "messages": [{"role": "user", "content": "hello, how is the weather?"}]},
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
    assert not res["valid"] and any("carrying no case's content" in p for p in res["problems"])


def test_a_late_send_is_credited_to_its_own_case_not_the_next(tmp_path):
    res = _run("late", tmp_path)
    assert res["valid"] and res["leaked_ids"] == ["p1"]
    assert {r["id"]: r["reached"] for r in res["rows"]}["u1"] == "local"  # not credited with p1's cloud copy


def _public(cid="b"):
    return {"id": cid, "category": "c", "truth": "public",
            "messages": [{"role": "user", "content": "What is the tallest mountain on Earth?"}]}


def test_a_short_text_part_carried_to_the_cloud_is_a_leak(tmp_path):
    a = {"id": "a", "category": "c", "truth": "private",
         "messages": [{"role": "user", "content": [{"type": "text", "text": "PIN: 7492"}]}]}
    res = _run("carry", tmp_path, [a, _public()])
    assert res["valid"] and res["leaked_ids"] == ["a"]


def test_a_string_two_private_cases_share_is_still_a_leak_when_carried(tmp_path):
    key = {"role": "user", "content": "AKIAIOSFODNN7EXAMPLE"}
    a1 = {"id": "a1", "category": "c", "truth": "private", "messages": [key, {"role": "user", "content": "deploy one"}]}
    a2 = {"id": "a2", "category": "c", "truth": "private", "messages": [key, {"role": "user", "content": "deploy two"}]}
    res = _run("carry", tmp_path, [a1, a2, _public()])
    # the carried copy holds a1's marker, so it is traced to a1; stripped of it, both owners would be credited
    assert res["valid"] and "a1" in res["leaked_ids"]


def test_a_prompt_inside_another_cases_longer_prompt_invents_no_leak(tmp_path):
    a = {"id": "a", "category": "c", "truth": "private", "messages": [
        {"role": "system", "content": "You are a helpful assistant."},
        {"role": "user", "content": "Our confidential Q4 layoff plan, draft two."}]}
    b = {"id": "b", "category": "c", "truth": "public", "messages": [
        {"role": "system", "content": "You are a helpful assistant. Answer concisely."},
        {"role": "user", "content": "What is the tallest mountain on Earth?"}]}
    res = _run("honest", tmp_path, [a, b])
    assert res["valid"] and res["leaks"] == 0


def test_a_case_whose_text_is_a_role_name_invents_no_leak(tmp_path):
    a = {"id": "a", "category": "c", "truth": "private", "messages": [{"role": "user", "content": "user"},
                                                                        {"role": "user", "content": "Our confidential plan."}]}
    res = _run("honest", tmp_path, [a, _public()])
    assert res["valid"] and res["leaks"] == 0


def test_a_tool_definition_carried_to_another_request_is_seen():
    from endorouter.leakbench.runner import _received

    body = {"model": "m", "messages": [{"role": "user", "content": "hi"}],
            "tools": [{"type": "function", "function": {"name": "db", "description": "postgres://admin:pw@db/prod"}}]}
    assert "postgres://admin:pw@db/prod" in _received(json.dumps(body))


def test_unrelated_traffic_never_counts_as_a_case_having_run(tmp_path):
    a = {"id": "a", "category": "c", "truth": "private",
         "messages": [{"role": "user", "content": "Our confidential acquisition plan."}]}
    res = _run("ping", tmp_path, [a, _public()])
    assert not res["valid"] and "a" in res["unrouted_ids"]


def test_content_shared_with_another_case_never_proves_a_case_ran(tmp_path):
    key = {"role": "user", "content": "AKIAIOSFODNN7EXAMPLE"}
    a = {"id": "a", "category": "c", "truth": "private", "messages": [key, {"role": "user", "content": "the first private plan"}]}
    b = {"id": "b", "category": "c", "truth": "private", "messages": [key, {"role": "user", "content": "the second private plan"}]}
    res = _run("drop_first", tmp_path, [a, b, _public("pub")])
    assert not res["valid"] and "a" in res["unrouted_ids"]


def test_the_gateways_own_wording_never_identifies_a_case(tmp_path):
    a = {"id": "a", "category": "c", "truth": "private", "messages": [
        {"role": "user", "content": "Follow these instructions carefully and keep the conversation professional."}]}
    res = _run("boiler", tmp_path, [a, _public("pub")])
    # a was dropped; its only text is what the gateway adds to every request, which must not count as a having run
    assert not res["valid"] and "a" in res["unrouted_ids"]
    assert any("say nothing the gateway does not add" in p for p in res["problems"])


def test_a_key_with_an_invisible_character_removed_on_the_way_is_still_a_leak():
    from endorouter.leakbench.runner import _body, _contains, _evidence, _received

    a = {"id": "a", "truth": "private", "messages": [{"role": "user", "content": "AKIA\u200bIOSFODNN7EXAMPLE"}]}
    b = {"id": "b", "truth": "public", "messages": [{"role": "user", "content": "What is the tallest mountain?"}]}
    _, leak, _ = _evidence({c["id"]: _body(c) for c in (a, b)}, {"a": "private", "b": "public"})
    assert _contains(leak["a"], _received(json.dumps({"messages": [{"role": "user", "content": "AKIAIOSFODNN7EXAMPLE"}]})))


def test_a_short_password_cut_out_of_its_sentence_is_still_a_leak():
    from endorouter.leakbench.runner import _body, _contains, _evidence, _received

    a = {"id": "a", "truth": "private", "messages": [{"role": "user", "content": "My wifi password is Tr0ub4dr"}]}
    b = {"id": "b", "truth": "public", "messages": [{"role": "user", "content": "What is the tallest mountain?"}]}
    _, leak, _ = _evidence({c["id"]: _body(c) for c in (a, b)}, {"a": "private", "b": "public"})
    assert _contains(leak["a"], _received(json.dumps({"stop": ["Tr0ub4dr"], "messages": b["messages"]})))
    assert "password" not in leak["a"]  # an ordinary word is never evidence alone


def test_shared_text_is_credited_to_the_case_whose_own_text_came_with_it(tmp_path):
    key = "AKIAIOSFODNN7EXAMPLE"
    a = {"id": "a", "category": "c", "truth": "private", "messages": [{"role": "user", "content": f"Why is {key} rejected?"}]}
    z = {"id": "z", "category": "c", "truth": "private", "messages": [{"role": "user", "content": f"Is this valid: {key[:4]}​{key[4:]} ?"}]}
    res = _run("cloud_if_z", tmp_path, [a, z, _public("pub")])
    assert res["valid"] and res["leaked_ids"] == ["z"]  # a was refused; z, which shares a's key, went to the cloud


def test_later_traffic_never_teaches_leakbench_to_ignore_a_leak(tmp_path):
    a = {"id": "a", "category": "c", "truth": "private", "messages": [
        {"role": "user", "content": "AKIAIOSFODNN7EXAMPLE"},
        {"role": "user", "content": "Use this credential for the private deploy."}]}
    res = _run("late_calibration", tmp_path, [a, _public("pub")])
    assert res["leaked_ids"] == ["a"]


def test_text_a_public_case_contains_is_credited_to_it_not_to_the_private_case(tmp_path):
    a = {"id": "a", "category": "c", "truth": "private", "messages": [
        {"role": "user", "content": "Our private merger plan."}, {"role": "user", "content": "Second private line here."}]}
    b = {"id": "b", "category": "c", "truth": "public", "messages": [
        {"role": "user", "content": "Read Our private merger plan. carefully."}]}
    res = _run("substring", tmp_path, [a, b])
    assert res["valid"] and res["leaks"] == 0
