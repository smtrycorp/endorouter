"""The router: scan, classify, decide, audit, dispatch. Used by the HTTP server and usable directly as a library.

Dispatch rules:
  - only targets in the decision's permitted set are ever contacted, in preference order;
  - a failed attempt (connection error, timeout, HTTP 5xx or 429) moves to the next permitted target, never outside the set;
  - streaming is committed to one target before the first byte is returned; there is no mid-stream switch;
  - the HTTP client follows no redirects and ignores proxy environment variables, so traffic goes only where configured.
"""

from __future__ import annotations

import asyncio
import json
import os
import time
import uuid
from dataclasses import dataclass
from typing import AsyncIterator, Sequence

import httpx

from . import POLICY_VERSION
from .audit import AuditError, AuditLog
from .classifier import classify
from .config import Config, Target
from .detectors import Finding, scan_request
from .discover import ollama_show_url, remote_from_show, verify_target
from .labels import Label
from .policy import Decision, decide, permitted_targets
from .validate import InvalidRequest, validate

RETRYABLE = {429, 500, 502, 503, 504}


class Refused(Exception):
    def __init__(self, decision: Decision, request_id: str):
        super().__init__(decision.error or "refused")
        self.decision = decision
        self.request_id = request_id


def _plain_json(body) -> dict:
    """The request as the JSON that will be sent, validated; raises InvalidRequest. One representation from here on:
    validating, scanning and sending the same value closes the gap a tuple or a numeric dict key opened, where the
    scan saw one shape and the wire another, and it is a private copy the caller cannot change mid-flight."""
    try:
        body = json.loads(json.dumps(body, allow_nan=False))
    except (TypeError, ValueError, RecursionError) as e:
        raise InvalidRequest("the request must be plain JSON: strings, numbers, booleans, lists and objects") from e
    problem = validate(body)
    if problem:  # the same refusal a library caller gets as an HTTP caller
        raise InvalidRequest(problem)
    return body


class SentUnrecorded(Exception):
    """The request reached a target, but the record of that could not be written. Distinct from a refusal: the prompt
    has left, and the caller must not be told otherwise."""

    def __init__(self, request_id: str, target: str):
        super().__init__(f"sent to {target}, but the audit log could not record it")
        self.request_id = request_id
        self.target = target


class UpstreamFailed(Exception):
    def __init__(self, request_id: str, attempts: list[dict]):
        super().__init__("every permitted target failed")
        self.request_id = request_id
        self.attempts = attempts


@dataclass
class Routed:
    request_id: str
    decision: Decision
    target: Target
    response: httpx.Response  # open when streaming; caller closes


def make_client() -> httpx.AsyncClient:
    return httpx.AsyncClient(follow_redirects=False, trust_env=False)


class Router:
    def __init__(self, cfg: Config, client: httpx.AsyncClient | None = None, audit: AuditLog | None = None):
        if client is not None and client.trust_env:
            # trust_env lets HTTP_PROXY / HTTPS_PROXY send even "local" traffic through an outside proxy
            raise ValueError("an injected httpx client must be created with trust_env=False")
        self.cfg = cfg
        self.client = client or make_client()
        self.audit = audit or AuditLog(cfg.audit_log)

    async def plan(
        self,
        body: dict,
        *,
        sources: Sequence[str] = (),
        declared: Label | None = None,
        capability: str | None = None,
        request_id: str | None = None,
        sent: list[str] | None = None,
    ) -> tuple[Decision, list[Finding]]:
        """The decision for a request. The local classifier, when enabled, receives the text here; its name is added
        to sent just before the text leaves, so an audit failure after that is never reported as "nothing was sent",
        and a classifier that never received it is never reported as a recipient."""
        # scanning is CPU work; in a thread, a large request cannot stall every other request in flight
        findings = await asyncio.to_thread(scan_request, body, [(f"sources[{i}]", s) for i, s in enumerate(sources)])
        verdict = None
        if self.cfg.classifier.enabled:
            ct = self.cfg.target(self.cfg.classifier.target or "")
            # the classifier receives the prompt text too: its port is re-verified like any other send, and an
            # unverified port means no verdict (which never grants anything)
            if ct is not None and (not (ct.verify_program or ct.ollama_api)
                                   or await self._still_verified(ct, request_id or "")):
                def dispatching() -> None:
                    # written only when the text is about to leave, and before it does
                    self.audit.write({"event": "classifier_dispatch", "request_id": request_id, "target": ct.name})
                    if sent is not None:
                        sent.append(ct.name)

                verdict = await classify(
                    self.cfg, body, self.client,
                    on_failure=lambda kind: self.audit.write(
                        {"event": "classifier_failed", "request_id": request_id, "kind": kind}),
                    on_send=dispatching)
        d = decide(
            self.cfg,
            requested_model=body.get("model"),
            sources=sources,
            declared=declared,
            findings=findings,
            classifier_verdict=verdict,
            capability=capability,
        )
        return d, findings

    async def route(
        self,
        body: dict,
        *,
        sources: Sequence[str] = (),
        declared: Label | None = None,
        capability: str | None = None,
        peer: str | None = None,
        trusted: bool | None = None,
        supplied: Label | None = None,
    ) -> Routed:
        """Route one chat request. Raises InvalidRequest, AuditError (nothing was sent), Refused, UpstreamFailed, or
        SentUnrecorded (sent, but not recorded). peer and trusted say who supplied any label, for the audit log."""
        request_id = uuid.uuid4().hex[:16]
        body = await asyncio.to_thread(_plain_json, body)  # megabytes of work, off the event loop
        sources = tuple(str(s) for s in sources)
        given = supplied if supplied is not None else declared  # Label.PUBLIC is 0: never test labels for truth
        sent: list[str] = []  # every target that may hold the prompt, the local classifier included
        try:
            decision, _ = await self.plan(body, sources=sources, declared=declared, capability=capability,
                                          request_id=request_id, sent=sent)
            # flushed before any target is sent the request; an AuditError here, with nothing sent, is a refusal
            self.audit.write({"event": "decision", "request_id": request_id, "mode": self.cfg.mode,
                              "policy_version": POLICY_VERSION, "peer": peer, "trusted": trusted,
                              # what the caller sent, and whether policy used it: an untrusted caller's "public" is
                              # recorded, never applied
                              "declared": None if given is None else given.name.lower(),
                              "declared_applied": declared is not None,
                              "sources": len(sources), **decision.as_record()})
            if decision.selected is None:
                raise Refused(decision, request_id)
            return await self._dispatch(body, decision, request_id, sent)
        except AuditError:
            if not sent:
                raise
            raise SentUnrecorded(request_id, ", ".join(sent)) from None

    async def _dispatch(self, body: dict, decision: Decision, request_id: str, sent: list[str]) -> Routed:
        attempts: list[dict] = []
        stream = bool(body.get("stream"))
        for target in permitted_targets(self.cfg, decision):
            if (target.verify_program or target.ollama_api) and not await self._still_verified(target, request_id):
                attempts.append({"target": target.name, "error": "port_not_verified"})
                continue
            t0 = time.monotonic()
            requested = str(body.get("model") or "")
            model = requested.split("/", 1)[1] if target.model == "*" and "/" in requested else target.model
            if model == "*":  # never send the wildcard itself upstream
                attempts.append({"target": target.name, "error": "no_model"})
                continue
            upstream = {**body, "model": model}
            headers = {"content-type": "application/json"}
            if target.api_key_env:
                key = os.environ.get(target.api_key_env, "")
                if key:
                    headers["authorization"] = f"Bearer {key}"
            # the actual destination is on disk before each send, including fallbacks
            self.audit.write({"event": "attempt", "request_id": request_id, "target": target.name, "location": target.location})
            sent.append(target.name)  # a send that fails partway may still have delivered the prompt
            try:
                req = self.client.build_request("POST", f"{target.url}/chat/completions", json=upstream, headers=headers,
                                                timeout=target.timeout_s)
                # explicit per call: an injected client configured to follow redirects must not carry a body elsewhere
                resp = await self.client.send(req, stream=stream, follow_redirects=False)
            except httpx.HTTPError as e:
                attempts.append({"target": target.name, "error": type(e).__name__, "ms": int((time.monotonic() - t0) * 1000)})
                continue
            if resp.status_code in RETRYABLE or 300 <= resp.status_code < 400:
                attempts.append({"target": target.name, "status": resp.status_code, "ms": int((time.monotonic() - t0) * 1000)})
                await resp.aclose()
                continue
            try:
                self.audit.write({"event": "dispatched", "request_id": request_id, "target": target.name,
                                  "location": target.location, "status": resp.status_code, "attempts": attempts,
                                  "ms": int((time.monotonic() - t0) * 1000)})
            except AuditError:
                await resp.aclose()
                raise
            return Routed(request_id, decision, target, resp)
        self.audit.write({"event": "failed", "request_id": request_id, "attempts": attempts})
        raise UpstreamFailed(request_id, attempts)

    async def _ollama_model_remote(self, target: Target) -> str | None:
        """Ollama can start serving a hosted model under a name that was local at setup; ask it again each time."""
        if "cloud" in target.model.lower():
            return f"model {target.model} is hosted remotely"
        try:
            r = await self.client.post(ollama_show_url(target.url), json={"model": target.model})
            info = r.json()
        except (httpx.HTTPError, ValueError):
            return "could not confirm the model runs on this machine"
        return f"model {target.model} is hosted remotely" if remote_from_show(r.status_code, info) else None

    async def _still_verified(self, target: Target, request_id: str) -> bool:
        """Checked before every send, never cached: a port that changes hands, or an Ollama model that is now hosted
        remotely, is refused on the next request. The process table is read in a worker thread so other requests continue."""
        reason = await asyncio.to_thread(verify_target, target)
        if reason is None and (target.ollama_api or target.verify_program == "ollama"):
            reason = await self._ollama_model_remote(target)
        if reason is None:
            return True
        self.audit.write({"event": "target_unverified", "request_id": request_id, "target": target.name, "reason": reason})
        return False

    async def aclose(self) -> None:
        await self.client.aclose()


async def iter_stream(resp: httpx.Response) -> AsyncIterator[bytes]:
    try:
        if resp.is_stream_consumed:  # a transport that pre-read the body (tests, some proxies): pass it through whole
            yield resp.content
        else:
            async for chunk in resp.aiter_raw():
                yield chunk
    finally:
        await resp.aclose()
