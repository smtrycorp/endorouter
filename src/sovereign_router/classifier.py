"""Optional local classifier. It runs on a LOCAL target only (config enforces this), sees the same text the detectors
saw, and answers one line: PRIVATE or PUBLIC. Its verdict can make a request more private; in balanced mode a PUBLIC
verdict may clear an UNKNOWN request that has no structural findings. Any failure, timeout or unparseable answer returns
None, and None never grants anything."""

from __future__ import annotations

import re

import httpx

from .config import Config
from .detectors import texts_in_request
from .labels import Label

PROMPT = (
    "You decide whether text may be sent to a third-party cloud AI service.\n"
    "PRIVATE = anything confidential to a person or an organisation: unpublished plans, strategy, finances, customer or "
    "employee details, internal code or systems, credentials, legal or medical matters, anything shared in confidence.\n"
    "PUBLIC = general knowledge, public documentation, open-source code, or text written to be published.\n"
    "If unsure, answer PRIVATE.\nAnswer with exactly one word: PRIVATE or PUBLIC.\n\nTEXT:\n{text}\n\nANSWER:"
)
_VERDICT = re.compile(r"^\W*(PRIVATE|PUBLIC)\W*$")  # the whole answer is one verdict word, or it grants nothing
MAX_CHARS = 12000


async def classify(cfg: Config, body: dict, client: httpx.AsyncClient) -> Label | None:
    if not cfg.classifier.enabled:
        return None
    t = cfg.target(cfg.classifier.target or "")
    if t is None or not t.is_local:  # defence in depth; config validation already requires this
        return None
    text = "\n".join(s for _, s in texts_in_request(body))
    if len(text) > MAX_CHARS:
        # never clear text the classifier did not read: a long request gets no verdict (strict treatment)
        return None
    try:
        r = await client.post(
            f"{t.url}/chat/completions",
            json={"model": t.model, "messages": [{"role": "user", "content": PROMPT.format(text=text)}], "max_tokens": 8, "temperature": 0},
            timeout=cfg.classifier.timeout_s,
            follow_redirects=False,
        )
        r.raise_for_status()
        answer = r.json()["choices"][0]["message"]["content"] or ""
    except Exception:  # noqa: BLE001
        return None
    m = _VERDICT.match(answer.strip().upper())
    if not m:
        return None
    return Label.PRIVATE if m.group(1) == "PRIVATE" else Label.PUBLIC
