"""The router: scan, classify, decide, audit, dispatch. Used by the HTTP server and usable directly as a library.

Dispatch rules:
  - only targets in the decision's permitted set are ever contacted, in preference order;
  - a failed attempt (connection error, timeout, HTTP 5xx or 429) moves to the next permitted target, never outside the set;
  - streaming is committed to one target before the first byte is returned; there is no mid-stream switch;
  - the HTTP client follows no redirects and ignores proxy environment variables, so traffic goes only where configured.
"""

from __future__ import annotations

import copy
import os
import time
import uuid
from dataclasses import dataclass
from typing import AsyncIterator, Sequence

import httpx

from . import POLICY_VERSION
from .audit import AuditLog
from .classifier import classify
from .config import Config, Target
from .detectors import Finding, scan_request
from .labels import Label
from .policy import Decision, decide, permitted_targets
from .validate import InvalidRequest, validate

RETRYABLE = {429, 500, 502, 503, 504}


class Refused(Exception):
    def __init__(self, decision: Decision, request_id: str):
        super().__init__(decision.error or "refused")
        self.decision = decision
        self.request_id = request_id


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
        # targets discovery verified are re-checked before every send (cached for a second): a port that changed
        # hands is skipped, and used again only once the verified program is back on it
        self._verified_at: dict[str, float] = {}
        self.audit = audit or AuditLog(cfg.audit_log)

    async def plan(
        self,
        body: dict,
        *,
        sources: Sequence[str] = (),
        declared: Label | None = None,
        capability: str | None = None,
        request_id: str | None = None,
    ) -> tuple[Decision, list[Finding]]:
        findings = scan_request(body, extra=[(f"sources[{i}]", s) for i, s in enumerate(sources)])
        verdict = None
        if self.cfg.classifier.enabled:
            ct = self.cfg.target(self.cfg.classifier.target or "")
            # the classifier receives the prompt text too: its port is re-verified like any other send, and an
            # unverified port means no verdict (which never grants anything)
            if ct is not None and (not ct.verify_program or self._still_verified(ct, request_id or "")):
                self.audit.write({"event": "classifier_dispatch", "request_id": request_id, "target": ct.name})
                verdict = await classify(self.cfg, body, self.client)
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
    ) -> Routed:
        request_id = uuid.uuid4().hex[:16]
        problem = validate(body)
        if problem:  # the same refusal a library caller gets as an HTTP caller
            raise InvalidRequest(problem)
        # inspect and send one private snapshot: a caller that mutates its own objects mid-flight cannot change
        # what is sent after it was inspected
        body = copy.deepcopy(body)
        sources = tuple(str(s) for s in sources)
        decision, _ = await self.plan(body, sources=sources, declared=declared, capability=capability, request_id=request_id)
        # written and flushed before anything leaves; raises AuditError (the caller refuses) if the log is unwritable
        self.audit.write({"event": "decision", "request_id": request_id, "mode": self.cfg.mode,
                          "policy_version": POLICY_VERSION, **decision.as_record()})
        if decision.selected is None:
            raise Refused(decision, request_id)
        attempts: list[dict] = []
        stream = bool(body.get("stream"))
        for target in permitted_targets(self.cfg, decision):
            if target.verify_program and not self._still_verified(target, request_id):
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
            try:
                req = self.client.build_request("POST", f"{target.url}/chat/completions", json=upstream, headers=headers,
                                                timeout=target.timeout_s)
                # explicit per call: an injected client configured to follow redirects must not carry a body elsewhere
                resp = await self.client.send(req, stream=stream, follow_redirects=False)
            except httpx.HTTPError as e:
                attempts.append({"target": target.name, "error": type(e).__name__, "ms": int((time.monotonic() - t0) * 1000)})
                self._verified_at.pop(target.name, None)  # after a failure, look again next time
                continue
            if resp.status_code in RETRYABLE or 300 <= resp.status_code < 400:
                attempts.append({"target": target.name, "status": resp.status_code, "ms": int((time.monotonic() - t0) * 1000)})
                await resp.aclose()
                continue
            self.audit.write({"event": "dispatched", "request_id": request_id, "target": target.name,
                              "location": target.location, "status": resp.status_code, "attempts": attempts,
                              "ms": int((time.monotonic() - t0) * 1000)})
            return Routed(request_id, decision, target, resp)
        self.audit.write({"event": "failed", "request_id": request_id, "attempts": attempts})
        raise UpstreamFailed(request_id, attempts)

    def _still_verified(self, target: Target, request_id: str) -> bool:
        from .discover import verified_program

        now = time.monotonic()
        if now - self._verified_at.get(target.name, -10.0) < 1.0:
            return True
        if verified_program(target.url) == target.verify_program:
            self._verified_at[target.name] = now
            return True
        self._verified_at.pop(target.name, None)
        self.audit.write({"event": "target_unverified", "request_id": request_id, "target": target.name,
                          "reason": f"port not served by {target.verify_program} right now"})
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
