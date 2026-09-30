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


# (rule id, pattern, optional validator). Prefixes are the issuers' documented token formats.
_RULES: list[tuple[str, re.Pattern, object]] = [
    ("private_key", re.compile(r"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----"), None),
    ("aws_access_key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), None),
    ("github_token", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{60,255})\b"), None),
    ("openai_key", re.compile(r"\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_\-]{20,}\b"), None),
    ("anthropic_key", re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{20,}\b"), None),
    ("stripe_key", re.compile(r"\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}\b"), None),
    ("slack_token", re.compile(r"\bxox[abposr]-[A-Za-z0-9-]{10,}\b"), None),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"), None),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\b"), _jwt),
    ("credential_url", re.compile(r"\b[a-z][a-z0-9+.\-]{1,15}://[^\s:/@]+:[^\s@/]+@[^\s/]+"), None),
    ("payment_card", re.compile(r"\b(?:\d[ -]?){13,19}\b"), lambda m: _luhn(re.sub(r"\D", "", m)) and 13 <= len(re.sub(r"\D", "", m)) <= 19),
    ("us_ssn", re.compile(r"\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b"), None),
    ("email_address", re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"), None),
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
    elif isinstance(obj, dict):
        for k, v in obj.items():
            yield from _walk(v, f"{where}.{k}")
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            yield from _walk(v, f"{where}[{i}]")


def texts_in_request(body: dict) -> Iterator[tuple[str, str]]:
    """Every string the upstream model would see: messages (all roles, content parts, tool calls, tool results) and tools."""
    for i, msg in enumerate(body.get("messages") or []):
        yield from _walk(msg, f"messages[{i}]")
    for i, tool in enumerate(body.get("tools") or body.get("functions") or []):
        yield from _walk(tool, f"tools[{i}]")


def scan_request(body: dict, extra: Iterable[tuple[str, str]] = ()) -> list[Finding]:
    found: list[Finding] = []
    for where, text in list(texts_in_request(body)) + list(extra):
        found.extend(scan_text(text, where))
    return found
