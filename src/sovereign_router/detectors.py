"""Structural detectors. Each recognises a FORMAT (with a checksum or structural validation where one exists), not a
list of sensitive words. A match makes content private. The absence of a match proves nothing and never clears anything.

Every detector sees every piece of text in the request: all messages of every role, tool definitions, tool-call
arguments and tool results. Text is normalised first so a secret split by zero-width characters is still seen.
"""

from __future__ import annotations

import base64
import json
import math
import re
import unicodedata
from dataclasses import dataclass
from typing import Iterable, Iterator


@dataclass(frozen=True)
class Finding:
    rule: str
    where: str  # e.g. "messages[3].content", "tools[0].function.parameters"


# Latin look-alikes that NFKC leaves alone (Cyrillic and Greek). Mapped for scanning only; the request is never changed.
_CONFUSABLES = {
    "А": "A", "В": "B", "Е": "E", "К": "K", "М": "M", "Н": "H", "О": "O", "Р": "P", "С": "C", "Т": "T", "Х": "X",
    "Ѕ": "S", "І": "I", "Ј": "J", "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "ѕ": "s",
    "і": "i", "ј": "j", "Α": "A", "Β": "B", "Ε": "E", "Ζ": "Z", "Η": "H", "Ι": "I", "Κ": "K", "Μ": "M", "Ν": "N",
    "Ο": "O", "Ρ": "P", "Τ": "T", "Υ": "Y", "Χ": "X", "ο": "o", "ν": "v",
}
_TABLE: dict[int, str | None] | None = None
# Unicode Default_Ignorable_Code_Point ranges (DerivedCoreProperties.txt) beyond category Cf: characters that render as
# nothing, such as the combining grapheme joiner U+034F, Hangul fillers and variation selectors
_DEFAULT_IGNORABLE = [
    (0x00AD, 0x00AD), (0x034F, 0x034F), (0x061C, 0x061C), (0x115F, 0x1160), (0x17B4, 0x17B5), (0x180B, 0x180F),
    (0x200B, 0x200F), (0x202A, 0x202E), (0x2060, 0x206F), (0x3164, 0x3164), (0xFE00, 0xFE0F), (0xFEFF, 0xFEFF),
    (0xFFA0, 0xFFA0), (0xFFF0, 0xFFF8), (0x1BCA0, 0x1BCA3), (0x1D173, 0x1D17A), (0xE0000, 0xE0FFF),
]


def _table() -> dict[int, str | None]:
    """Every invisible format character (Unicode category Cf: zero-width, soft hyphen, invisible separators, bidi
    controls, tag characters) is deleted and every listed confusable is mapped. Built once, applied in linear time."""
    global _TABLE
    if _TABLE is None:
        t: dict[int, str | None] = {cp: None for cp in range(0x110000) if unicodedata.category(chr(cp)) == "Cf"}
        for lo, hi in _DEFAULT_IGNORABLE:
            t.update({cp: None for cp in range(lo, hi + 1)})
        t.update({ord(k): v for k, v in _CONFUSABLES.items()})
        _TABLE = t
    return _TABLE


def normalise(text: str) -> str:
    return unicodedata.normalize("NFKC", text).translate(_table())


# Runs of base64 alphabet, any length (one class, greedy, anchored by the look-behind: linear time). There is no cap
# on how many runs are decoded, so padding a prompt with decoys cannot push a real secret past the scanner.
_B64 = re.compile(r"(?<![A-Za-z0-9+/_\-])[A-Za-z0-9+/_\-]{16,}={0,2}")


def _decoded_base64(text: str) -> Iterator[str]:
    """One level deep, kept only when the decoded bytes are mostly printable text. Total work is linear in the input.
    Enough to see a base64-wrapped key; not a general decoder (binary containers such as zip are not opened)."""
    for m in _B64.finditer(text):
        tok = m.group(0)
        try:
            raw = base64.b64decode(tok.replace("-", "+").replace("_", "/") + "=" * (-len(tok) % 4), validate=True)
        except (ValueError, base64.binascii.Error):
            continue
        if raw and sum(32 <= b < 127 or b in (9, 10, 13) for b in raw) >= 0.9 * len(raw):
            yield raw.decode("ascii", "ignore")


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


def _card(d: str) -> bool:
    """Luhn plus a real issuer prefix and length, so a 13-digit millisecond timestamp is not a card."""
    n = len(d)
    if not 13 <= n <= 19 or not _luhn(d):
        return False
    p2, p3, p4 = int(d[:2]), int(d[:3]), int(d[:4])
    return (
        (d[0] == "4" and n in (13, 16, 19))                                  # Visa
        or ((51 <= p2 <= 55 or 2221 <= p4 <= 2720) and n == 16)              # Mastercard
        or (p2 in (34, 37) and n == 15)                                      # American Express
        or ((p4 == 6011 or p2 == 65 or 644 <= p3 <= 649) and 16 <= n <= 19)  # Discover
        or (3528 <= p4 <= 3589 and 16 <= n <= 19)                            # JCB
        or ((300 <= p3 <= 305 or p2 in (36, 38, 39)) and 14 <= n <= 19)      # Diners Club
        or (p2 == 62 and 16 <= n <= 19)                                      # UnionPay
    )


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
    # A distinctive issuer prefix standing alone, too short to be a whole key, is still credential material: a key
    # split across messages ("first half: AKIAIOSF", "second half: ...") never appears whole in any one string.
    ("secret_fragment", re.compile(
        r"\b(?:(?:AKIA|ASIA)[0-9A-Z]{4,15}|gh[pousr]_[A-Za-z0-9]{4,35}|github_pat_[A-Za-z0-9_]{4,59}"
        r"|sk-(?:proj|ant|svcacct|admin)-[A-Za-z0-9_\-]{4,19}|(?:sk|rk)_live_[A-Za-z0-9]{4,15}|xox[abposr]-\d{4,9}"
        r"|AIza[0-9A-Za-z_\-]{8,34})\b"), None),
    ("private_key_boundary", re.compile(r"-----END (?:[A-Z0-9 ]{1,64} )?PRIVATE KEY-----"), None),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_\-]{8,4096}\.[A-Za-z0-9_\-]{8,8192}\.[A-Za-z0-9_\-]{8,4096}\b"), _jwt),
    ("credential_url", re.compile(r"\b[a-z][a-z0-9+.\-]{1,15}://[^\s:/@]{1,256}:[^\s@/]{1,256}@[^\s/]{1,256}", re.IGNORECASE), None),
    ("payment_card", re.compile(r"\b(?:\d[ -]?){13,19}\b"), lambda m: _card(re.sub(r"\D", "", m))),
    ("us_ssn", re.compile(r"\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b"), None),
    ("email_address", re.compile(r"\b[A-Za-z0-9._%+\-]{1,64}@[A-Za-z0-9.\-]{1,253}\.[A-Za-z]{2,24}\b"), None),
    # not inside a hyphen-joined token (e.g. the digit runs of a Slack token), where a phone number never sits
    # and never a bare digit run without a leading +: timestamps and ids look exactly like that
    ("phone_number", re.compile(r"(?<![\w\-])\+?\d{1,3}[ \t.\-]?\(?\d{2,4}\)?[ \t.\-]?\d{3,4}[ \t.\-]?\d{3,4}(?![\w\-])"),
     lambda m: m.startswith("+") or bool(re.search(r"[ \t.\-()]", m))),
]


def _scan_normalised(t: str, where: str) -> Iterator[Finding]:
    for rule, pat, check in _RULES:
        for m in pat.finditer(t):
            if check is None or check(m.group(0)):
                yield Finding(rule, where)
                break


# ---- vendor-agnostic secret shape ---------------------------------------------------------------------------------
# No vendor prefixes and no words: a token is secret-shaped when it is long, mixes character classes the way random
# generators do, switches between classes often, has near-maximal character entropy, and is not made of word-like
# lowercase runs (identifiers). Bare hex is ambiguous with digests, so it counts only where credentials are placed
# (NAME=value, Bearer) or with a vendor-style prefix glued on. Measured 2026-09-30 on 660 synthetic keys from made-up
# vendors (81% overall, 97%+ for base62/base64 shapes, ~45% for bare hex) and 16.8 MB of public source, docs and
# lockfiles (4.2 false alarms per MB). This rule catches keys from vendors nobody has written a pattern for.
_SHAPE_TOKEN = re.compile(r"(?<![A-Za-z0-9+/_=.\-])[A-Za-z0-9+/_=.\-]{20,512}(?![A-Za-z0-9+/_=.\-])")
_UUID = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
_DIGEST = re.compile(r"^(?:sha(?:1|224|256|384|512)|md5|blake2[bs]?|blake3|sha3-(?:256|512))[-:=]", re.IGNORECASE)
_WORD_PREFIX = re.compile(r"^(?:[A-Za-z]{1,12}[-_.])+")
_CRED_PLACE = re.compile(r"(?:^|[\s;])(?:export\s+)?[A-Z][A-Z0-9_]{2,63}\s*[=:]\s*[\"']?$|Bearer\s+$")


def _secret_shaped(tok: str, before: str) -> bool:
    if _UUID.match(tok) or _DIGEST.match(tok) or tok.count("/") >= 2:
        return False
    if tok.count(".") >= 2 and not any(c.isdigit() for c in tok):
        return False
    core = re.sub(r"[._\-/+=]", "", tok)
    n = len(core)
    if n < 20:
        return False
    tail = _WORD_PREFIX.sub("", tok)
    if re.fullmatch(r"[0-9a-fA-F]+", re.sub(r"[._\-/+=]", "", tail)):
        glued = tail != tok and "_" in tok[: len(tok) - len(tail)]
        return len(tail) >= 32 and (glued or bool(_CRED_PLACE.search(before)))
    digits = sum(c.isdigit() for c in core) / n
    if digits == 0 or digits >= 0.9:
        return False
    if sum(len(r) for r in re.findall(r"[a-z]{4,}", tok)) / n > 0.35:
        return False
    kinds = [("d" if c.isdigit() else "u" if c.isupper() else "l") for c in core]
    switch = sum(a != b for a, b in zip(kinds, kinds[1:])) / (n - 1)
    counts: dict[str, int] = {}
    for c in core:
        counts[c] = counts.get(c, 0) + 1
    entropy = -sum(v / n * math.log2(v / n) for v in counts.values())
    return len(set(kinds)) >= 2 and switch >= 0.3 and entropy >= 0.75 * math.log2(min(n, 62))


def _shape_findings(t: str, where: str) -> Iterator[Finding]:
    for m in _SHAPE_TOKEN.finditer(t):
        if _secret_shaped(m.group(0), t[max(0, m.start() - 80):m.start()]):
            yield Finding("secret_shape", where)
            return


# a run of single characters separated by single spaces or hyphens ("A K I A I O S F ..."): a secret typed out letter
# by letter; bounded and linear
_SPACED = re.compile(r"(?<![A-Za-z0-9_\-])(?:[A-Za-z0-9_\-] ){7,4096}[A-Za-z0-9_\-](?![A-Za-z0-9_\-])")
# a JSON string literal holding escapes, anywhere in prose ("Tool returned: {\"k\": \"\\u0041KIA...\"}"), decoded
_JSON_STR = re.compile(r'"(?:[^"\\\n]|\\.){0,8192}"')


def scan_text(text: str, where: str) -> Iterator[Finding]:
    t = normalise(text)
    seen = set()
    for f in _scan_normalised(t, where):
        seen.add(f.rule)
        yield f
    if not seen:  # a known format already makes it private; the generic shape rule covers everything else
        for f in _shape_findings(t, where):
            seen.add(f.rule)
            yield f
    if "\\" in t:
        for m in _JSON_STR.finditer(t):
            if "\\" not in m.group(0):
                continue
            try:
                decoded = json.loads(m.group(0))
            except ValueError:
                continue
            for f in _scan_normalised(normalise(decoded), f"{where}<json-string>"):
                if f.rule not in seen:
                    seen.add(f.rule)
                    yield f
    for m in _SPACED.finditer(t):
        for f in _scan_normalised(m.group(0).replace(" ", ""), f"{where}<spaced>"):
            if f.rule not in seen:
                seen.add(f.rule)
                yield f
    for decoded in _decoded_base64(t):
        for f in _scan_normalised(normalise(decoded), f"{where}<base64>"):
            if f.rule not in seen:
                seen.add(f.rule)
                yield f


class _Undecodable(str):
    """A JSON string nested too deeply to decode: it cannot be inspected, so it is treated as a finding."""


MAX_DEPTH = 64


def _walk(obj, where: str) -> Iterator[tuple[str, str]]:
    """Iterative, so no input can exhaust the stack. Structure deeper than MAX_DEPTH cannot be inspected and is reported
    as undecodable, which the scanner treats as a finding (fail closed)."""
    stack = [(obj, where, 0)]
    while stack:
        o, w, depth = stack.pop()
        if depth > MAX_DEPTH:
            yield w, _Undecodable("")
            continue
        if isinstance(o, str):
            yield w, o
            # tool-call arguments and similar fields are JSON inside a string: scan the decoded form too, so a
            # secret written with JSON escapes (\u0041KIA...) is seen the way the model will read it
            if o.lstrip()[:1] in ("{", "["):
                try:
                    decoded = json.loads(o)
                except ValueError:
                    decoded = None
                except RecursionError:
                    yield f"{w}<json>", _Undecodable("")
                    continue
                if isinstance(decoded, (dict, list)):
                    stack.append((decoded, f"{w}<json>", depth + 1))
        elif isinstance(o, bool) or o is None:
            continue
        elif isinstance(o, int):
            yield w, str(o)
        elif isinstance(o, float):
            yield w, repr(o)
            if o.is_integer() and abs(o) < 1e30:  # 4.000000000000512e18 is also the 19-digit integer the model may read
                yield w, str(int(o))
        elif isinstance(o, dict):
            # children pushed in reverse so they come off the stack in document order (the classifier reads this text)
            for k, v in reversed(list(o.items())):
                stack.append((v, f"{w}.{k}", depth + 1))
                if isinstance(k, str):
                    stack.append((k, f"{w}.<key>", depth + 1))
        elif isinstance(o, list):
            for i, v in reversed(list(enumerate(o))):
                stack.append((v, f"{w}[{i}]", depth + 1))


def texts_in_request(body: dict) -> Iterator[tuple[str, str]]:
    """The forwarded text, for readers such as the classifier (undecodable markers left out)."""
    return ((w, t) for w, t in _texts(body) if not isinstance(t, _Undecodable))


def _texts(body: dict) -> Iterator[tuple[str, str]]:
    """Every string the upstream model would receive: every field of the body, the model name included. That covers messages of every role, content parts, tool calls and results, tools, stop sequences,
    response_format schemas and the user field, including dict keys and JSON carried inside strings."""
    for k, v in body.items():
        yield from _walk(v, k)  # includes "model": a pass-through target forwards the client's model name upstream


_JOIN_RULES = {"private_key", "aws_access_key", "github_token", "openai_key", "anthropic_key", "stripe_key",
               "slack_token", "google_api_key", "jwt", "payment_card"}


def _joined_texts(body: dict) -> Iterator[tuple[str, str]]:
    """Message texts joined with nothing between them: all messages, and the user's messages alone, so a key split
    across messages or content parts ("AKIA" then "IOSFODNN7EXAMPLE") is whole again. Only precise format rules are
    run on the joins; they cost one more linear pass."""
    parts, user = [], []
    for m in body.get("messages") or []:
        if not isinstance(m, dict):
            continue
        c = m.get("content")
        texts = [c] if isinstance(c, str) else [p.get("text") for p in c if isinstance(p, dict) and isinstance(p.get("text"), str)] if isinstance(c, list) else []
        parts.extend(texts)
        if m.get("role") == "user":
            user.extend(texts)
    if len(parts) > 1:
        yield "messages<joined>", "".join(t.strip() for t in parts)
    if len(user) > 1:
        yield "messages<user-joined>", "".join(t.strip() for t in user)


def scan_request(body: dict, extra: Iterable[tuple[str, str]] = ()) -> list[Finding]:
    found: list[Finding] = []
    for where, text in _joined_texts(body):
        t = normalise(text)
        found.extend(f for f in _scan_normalised(t, where) if f.rule in _JOIN_RULES)
    for where, text in list(_texts(body)) + list(extra):
        if isinstance(text, _Undecodable):
            found.append(Finding("undecodable_nested_json", where))
            continue
        found.extend(scan_text(text, where))
    return found
