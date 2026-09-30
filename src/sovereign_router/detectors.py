"""Structural detectors. Each recognises a FORMAT (with a checksum or structural validation where one exists), not a
list of sensitive words. A match makes content private. The absence of a match proves nothing and never clears anything.

Every detector sees every piece of text in the request: all messages of every role, tool definitions, tool-call
arguments and tool results. Text is normalised first so a secret split by zero-width characters is still seen.
"""

from __future__ import annotations

import base64
import json
import re
import unicodedata
from dataclasses import dataclass
from typing import Iterable, Iterator


@dataclass(frozen=True)
class Finding:
    rule: str
    where: str  # e.g. "messages[3].content", "tools[0].function.parameters"


_ZERO_WIDTH = re.compile(r"[\u200b-\u200f\u2060\ufeff]")


def normalise(text: str) -> str:
    return _ZERO_WIDTH.sub("", unicodedata.normalize("NFKC", text))


def _luhn(digits: str) -> bool:
    total, alt = 0, False
    for ch in reversed(digits):
        d = ord(ch) - 48
        if alt:
            d *= 2
            if d > 9:
                d -= 9
        total += d
        alt = not alt
    return total % 10 == 0


def _jwt(token: str) -> bool:
    parts = token.split(".")
    if len(parts) != 3:
        return False
    try:
        head = json.loads(base64.urlsafe_b64decode(parts[0] + "=" * (-len(parts[0]) % 4)))
    except Exception:  # noqa: BLE001
        return False
    return isinstance(head, dict) and "alg" in head


# (rule id, pattern, optional validator). Prefixes are the issuers' documented token formats. Every repetition is
# bounded so a match attempt costs constant time and a large input scans in linear time (no quadratic backtracking).
_RULES: list[tuple[str, re.Pattern, object]] = [
    ("private_key", re.compile(r"-----BEGIN (?:[A-Z0-9 ]{1,64} )?PRIVATE KEY-----"), None),
    ("aws_access_key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), None),
    ("github_token", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{60,255})\b"), None),
    ("openai_key", re.compile(r"\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_\-]{20,256}\b"), None),
    ("anthropic_key", re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{20,256}\b"), None),
    ("stripe_key", re.compile(r"\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,256}\b"), None),
    ("slack_token", re.compile(r"\bxox[abposr]-[A-Za-z0-9-]{10,256}\b"), None),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"), None),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_\-]{8,4096}\.[A-Za-z0-9_\-]{8,8192}\.[A-Za-z0-9_\-]{8,4096}\b"), _jwt),
    ("credential_url", re.compile(r"\b[a-z][a-z0-9+.\-]{1,15}://[^\s:/@]{1,256}:[^\s@/]{1,256}@[^\s/]{1,256}"), None),
    ("payment_card", re.compile(r"\b(?:\d[ -]?){13,19}\b"), lambda m: _luhn(re.sub(r"\D", "", m)) and 13 <= len(re.sub(r"\D", "", m)) <= 19),
    ("us_ssn", re.compile(r"\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b"), None),
    ("email_address", re.compile(r"\b[A-Za-z0-9._%+\-]{1,64}@[A-Za-z0-9.\-]{1,253}\.[A-Za-z]{2,24}\b"), None),
    # not inside a hyphen-joined token (e.g. the digit runs of a Slack token), where a phone number never sits
    ("phone_number", re.compile(r"(?<![\w\-])\+?\d{1,3}[ .\-]?\(?\d{2,4}\)?[ .\-]?\d{3,4}[ .\-]?\d{3,4}(?![\w\-])"), None),
]


def scan_text(text: str, where: str) -> Iterator[Finding]:
    t = normalise(text)
    for rule, pat, check in _RULES:
        for m in pat.finditer(t):
            if check is None or check(m.group(0)):
                yield Finding(rule, where)
                break


def _walk(obj, where: str) -> Iterator[tuple[str, str]]:
    if isinstance(obj, str):
        yield where, obj
        # tool-call arguments and similar fields are JSON inside a string: scan the decoded form too, so a secret
        # written with JSON escapes (\u0041KIA...) is seen the way the model will read it
        if obj[:1] in "{[" and len(obj) < 1_000_000:
            try:
                decoded = json.loads(obj)
            except ValueError:
                decoded = None
            if isinstance(decoded, (dict, list)):
                yield from _walk(decoded, f"{where}<json>")
    elif isinstance(obj, dict):
        for k, v in obj.items():
            if isinstance(k, str):
                yield f"{where}.<key>", k
            yield from _walk(v, f"{where}.{k}")
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            yield from _walk(v, f"{where}[{i}]")


def texts_in_request(body: dict) -> Iterator[tuple[str, str]]:
    """Every string the upstream model would receive: every field of the body except the model name, which the router
    replaces. That covers messages of every role, content parts, tool calls and results, tools, stop sequences,
    response_format schemas and the user field, including dict keys and JSON carried inside strings."""
    for k, v in body.items():
        if k == "model":
            continue
        yield from _walk(v, k)


def scan_request(body: dict, extra: Iterable[tuple[str, str]] = ()) -> list[Finding]:
    found: list[Finding] = []
    for where, text in list(texts_in_request(body)) + list(extra):
        found.extend(scan_text(text, where))
    return found
