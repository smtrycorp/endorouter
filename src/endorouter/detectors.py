"""Structural detectors. Each recognises a FORMAT (with a checksum or structural validation where one exists), not a
list of sensitive words. A match makes content private. The absence of a match proves nothing and never clears anything.

Every detector sees every piece of text in the request: all messages of every role, tool definitions, tool-call
arguments and tool results. Text is normalised first so a secret split by zero-width characters is still seen.
"""

from __future__ import annotations

import base64
import functools
import itertools
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


@functools.cache
def _nonstarter_run() -> re.Pattern:
    """30 characters in a row that each normalise to something starting with a mark (nonzero combining class), built
    once. Judged on the normalised form, not the character itself: U+0F73 has class 0 but becomes two marks, so
    counting only marks as written let a run of it through to a quadratic sort."""
    cps = [cp for cp in range(0x110000)
           if (d := unicodedata.normalize("NFKD", chr(cp))) and unicodedata.combining(d[0])]
    ranges, start = [], cps[0]
    for prev, cp in zip(cps, cps[1:] + [None], strict=True):
        if cp != prev + 1 if cp is not None else True:
            ranges.append(f"{re.escape(chr(start))}-{re.escape(chr(prev))}" if prev > start else re.escape(chr(start)))
            start = cp
    return re.compile(f"[{''.join(ranges)}]{{30}}")


def normalise(text: str) -> str:
    # Normalisation sorts each run of combining marks, which takes time quadratic in the run's length. As in
    # Unicode's stream-safe text format (UAX #15), a combining grapheme joiner after every 30 marks bounds each run;
    # it is a default-ignorable character, so the table below removes it again. No real text stacks 30 marks.
    text = _nonstarter_run().sub(lambda m: m.group(0) + "\u034f", text)
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


def _card_in_groups(m: str) -> bool:
    """Any run of whole digit groups 13 to 19 digits long that is a valid card: '4242424242424242 12/28' holds a card
    even though all 18 digits together do not."""
    groups = [g for g in re.split(r"[ -]", m) if g]
    if len(groups) == 1:
        d = groups[0]
        return any(_card(d[i:i + n]) for n in range(13, 20) for i in (0, len(d) - n) if 0 <= i and i + n <= len(d))
    for i in range(len(groups)):
        for j in range(i + 1, len(groups) + 1):
            d = "".join(groups[i:j])
            if len(d) > 19:
                break
            if len(d) >= 13 and _card(d):
                return True
    return False


def _jwt(token: str) -> bool:
    parts = token.split(".")
    if len(parts) != 3:
        return False
    try:
        head = json.loads(base64.urlsafe_b64decode(parts[0] + "=" * (-len(parts[0]) % 4)))
    except (ValueError, RecursionError):  # bad base64, bad UTF-8, bad JSON (all ValueError), or absurdly deep JSON
        return False
    return isinstance(head, dict) and "alg" in head


# (rule id, pattern, optional validator). Prefixes are the issuers' documented token formats. Repetitions are bounded,
# or cannot overlap, so a large input scans in linear time; tests/test_review_10.py holds the adversarial inputs.
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
    ("credential_url", re.compile(r"\b[a-z][a-z0-9+.\-]{1,15}://[^\s:/@]{0,256}:[^\s@/]{1,256}@[^\s/]{1,256}", re.IGNORECASE), None),  # redis://:password@host too
    ("payment_card", re.compile(r"\b(?:\d[ -]?){13,40}\b"), lambda m: _card_in_groups(m)),
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
# (NAME=value, Bearer) or with a vendor-style prefix glued on. This rule catches keys from vendors nobody has written a
# pattern for; bench/shape_eval.py measures how often, and how often it fires on public code.
_SHAPE_TOKEN = re.compile(r"(?<![A-Za-z0-9+/_=.\-])[A-Za-z0-9+/_=.\-]{20,512}(?![A-Za-z0-9+/_=.\-])")
_UUID = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
_DIGEST = re.compile(r"^(?:sha(?:1|224|256|384|512)|md5|blake2[bs]?|blake3|sha3-(?:256|512))[-:=]", re.IGNORECASE)
_WORD_PREFIX = re.compile(r"^(?:[A-Za-z]{1,12}[-_.])+")
_CRED_PLACE = re.compile(r"(?:^|[\s;])(?:export\s+)?[A-Z][A-Z0-9_]{2,63}\s*[=:]\s*[\"']?$|Bearer\s+$")


def _secret_shaped(tok: str, before: str) -> bool:
    # tokens with '/' are scored like any other (base64 keys and webhook URLs have them); paths are left alone by the
    # word-like rule below
    if _UUID.match(tok) or _DIGEST.match(tok):
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
    switch = sum(a != b for a, b in zip(kinds, kinds[1:], strict=False)) / (n - 1)
    counts: dict[str, int] = {}
    for c in core:
        counts[c] = counts.get(c, 0) + 1
    entropy = -sum(v / n * math.log2(v / n) for v in counts.values())
    return len(set(kinds)) >= 2 and switch >= 0.3 and entropy >= 0.75 * math.log2(min(n, 62))


# a value assigned to an UPPER_SNAKE name (NAME=value, NAME: value): generated passwords and Django-style keys carry
# punctuation that splits them into short tokens, so the whole value is scored, punctuation as its own class
_CRED_VALUE = [
    # NAME=value, NAME: value, "NAME=value" (env lists), with or without quotes around the name
    re.compile(r"(?:^|[\s;,{\[])(?:export\s+)?[\"']?[A-Z][A-Z0-9_]{2,63}[\"']?\s*[=:]\s*([\"']?)([^\s'\"]{16,256})\1(?=\s|$|[;,}\]\"'])"),
    # a quoted JSON pair, any case: "db_password": "..."
    re.compile(r"[\"'][A-Za-z_][A-Za-z0-9_.\-]{1,63}[\"']\s*:\s*([\"'])([^\s'\"]{16,256})\1"),
    # a YAML key with a quoted value, any case: password: "..."
    # indentation, then an optional list dash: two runs that can never both match the same space, so a line of
    # spaces is read once rather than split every possible way (that split was quadratic)
    re.compile(r"(?m)^[ \t]*(?:-[ \t]*)?[A-Za-z_][A-Za-z0-9_.\-]{1,63}[ \t]*:[ \t]*([\"'])([^\s'\"]{16,256})\1[ \t]*$"),
]


_CODE_EXPR = re.compile(r"[A-Za-z_][\w.]*(?:\(.*\))?,?")  # an identifier, attribute or call: code, not a secret
_SECRET_PUNCT = set("!@#$%^&*~?<>|")  # password punctuation; not base64's + / =, not code's brackets


def _punct_secret(v: str) -> bool:
    if "://" in v or sum(len(r) for r in re.findall(r"[a-z]{4,}", v)) / len(v) > 0.35:
        return False  # URLs are the credential_url rule's; word-like values are settings, not secrets
    if _CODE_EXPR.fullmatch(v) or _DIGEST.match(v) or sum(c in _SECRET_PUNCT for c in v) < 2:
        return False
    kinds = {("d" if c.isdigit() else "u" if c.isupper() else "l" if c.islower() else "p") for c in v}
    if "p" not in kinds or len(kinds) < 3:
        return False
    counts: dict[str, int] = {}
    for c in v:
        counts[c] = counts.get(c, 0) + 1
    entropy = -sum(n / len(v) * math.log2(n / len(v)) for n in counts.values())
    return entropy >= 0.8 * math.log2(min(len(v), 94))


def _shape_findings(t: str, where: str) -> Iterator[Finding]:
    for m in _SHAPE_TOKEN.finditer(t):
        if _secret_shaped(m.group(0), t[max(0, m.start() - 80):m.start()]):
            yield Finding("secret_shape", where)
            return
    for rx in _CRED_VALUE:
        for m in rx.finditer(t):
            if _punct_secret(m.group(2)):
                yield Finding("secret_shape", where)
                return


# a run of single characters separated by single spaces ("A K I A I O S F ...", "e y J . ..."): a secret typed out
# letter by letter, credential punctuation kept; bounded and linear
_SPACED = re.compile(r"(?<![A-Za-z0-9_.\-])(?:[A-Za-z0-9_.\-] ){7,4096}[A-Za-z0-9_.\-](?![A-Za-z0-9_.\-])")
# a JSON string literal holding escapes, anywhere in prose ("Tool returned: {\"k\": \"\\u0041KIA...\"}"), decoded
_PLAIN_RUN = re.compile(r'[^"\\]*')


def _string_literals(line: str, start: int) -> Iterator[str]:
    """The double-quoted literals of one line, left to right, from start. One forward pass: when a literal never
    closes, no later quote can open one that does (an escaped quote stays escaped whichever quote the reading starts
    from, since the backslashes before it are the same), so the scan stops instead of retrying from each quote. A
    regex retrying from every quote took quadratic time on a line of escaped quotes."""
    i = start
    while (q := line.find('"', i)) >= 0:
        j = q + 1
        while True:
            j = _PLAIN_RUN.match(line, j).end()
            if j >= len(line):
                return
            if line[j] == '"':
                break
            j += 2  # a backslash and the character it escapes
        yield line[q : j + 1]
        i = j + 1


def _json_literals(t: str) -> Iterator[str]:
    """String literals paired both ways: from the start of each line, and from just after its first quote. A stray
    '"' earlier on the line shifts the pairing by one; the second pass has the other parity. Two linear passes."""
    for line in t.split("\n"):
        if '"' not in line or "\\" not in line:
            continue
        yield from _string_literals(line, 0)
        yield from _string_literals(line, line.find('"') + 1)


def _decoded_findings(t: str, where: str) -> Iterator[Finding]:
    """Decoded text (base64, JSON escapes, spaced-out letters) gets the format rules AND the shape rule, one level deep."""
    found = False
    for f in _scan_normalised(t, where):
        found = True
        yield f
    if not found:
        yield from _shape_findings(t, where)


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
        for lit in _json_literals(t):
            if "\\" not in lit:
                continue
            try:
                decoded = json.loads(lit)
            except ValueError:
                continue
            for f in _decoded_findings(normalise(decoded), f"{where}<json-string>"):
                if f.rule not in seen:
                    seen.add(f.rule)
                    yield f
    for m in _SPACED.finditer(t):
        for f in _decoded_findings(m.group(0).replace(" ", ""), f"{where}<spaced>"):
            if f.rule not in seen:
                seen.add(f.rule)
                yield f
    for decoded in _decoded_base64(t):
        for f in _decoded_findings(normalise(decoded), f"{where}<base64>"):
            if f.rule not in seen:
                seen.add(f.rule)
                yield f


class _Undecodable(str):
    """A JSON string nested too deeply to decode: it cannot be inspected, so it is treated as a finding."""


MAX_DEPTH = 64


class _Loc:
    """Where a string sits in the request. Each location holds only its own step and a link to its parent, so the
    path text is never copied for every value under a long or deep key (that copying made memory grow with the
    square of the input); the text is built only when a finding is reported."""

    __slots__ = ("parent", "step", "in_json")

    def __init__(self, parent: "_Loc | None", step: str, in_json: bool = False):
        self.parent, self.step, self.in_json = parent, step, in_json

    def child(self, step: str, into_json: bool = False) -> "_Loc":
        return _Loc(self, step, self.in_json or into_json)

    def __str__(self) -> str:
        steps, loc = [], self
        while loc is not None:
            steps.append(loc.step if len(loc.step) <= 34 else loc.step[:33] + "…")
            loc = loc.parent
        return "".join(reversed(steps))


def _children(o, w: _Loc) -> Iterator[tuple[object, _Loc]]:
    """A container's contents in document order, made one at a time: a dict's key, then its value."""
    if isinstance(o, dict):
        for k, v in o.items():
            if isinstance(k, str):
                yield k, w.child(".<key>")
            yield v, w.child(f".{k}")
    else:
        for i, v in enumerate(o):
            yield v, w.child(f"[{i}]")


def _walk(obj, where: _Loc) -> Iterator[tuple[_Loc, str]]:
    """Every string in obj, in document order (the classifier reads this text). Iterative, so no input can exhaust
    the stack, and lazy: the stack holds one iterator per level of nesting, never a container's every element, so
    memory follows depth, not size. Structure deeper than MAX_DEPTH cannot be inspected and is reported as
    undecodable, which the scanner treats as a finding (fail closed)."""
    stack: list[tuple[Iterator[tuple[object, _Loc]], int]] = [(iter([(obj, where)]), 0)]
    while stack:
        it, depth = stack[-1]
        nxt = next(it, None)
        if nxt is None:
            stack.pop()
            continue
        o, w = nxt
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
                    yield w.child("<json>", into_json=True), _Undecodable("")
                    continue
                if isinstance(decoded, (dict, list)):
                    stack.append((iter([(decoded, w.child("<json>", into_json=True))]), depth + 1))
        elif isinstance(o, bool) or o is None:
            continue
        elif isinstance(o, int):
            yield w, str(o)
        elif isinstance(o, float):
            yield w, repr(o)
            if o.is_integer() and abs(o) < 1e30:  # 4.000000000000512e18 is also the 19-digit integer the model may read
                yield w, str(int(o))
        elif isinstance(o, (dict, list)):
            stack.append((_children(o, w), depth + 1))


def texts_in_request(body: dict) -> Iterator[tuple[str, str]]:
    """The forwarded text, for readers such as the classifier (undecodable markers left out)."""
    return ((str(w), t) for w, t in _texts(body) if not isinstance(t, _Undecodable))


def _texts(body: dict) -> Iterator[tuple[_Loc, str]]:
    """Every string the upstream model would receive: every field of the body, the model name included. That covers messages of every role, content parts, tool calls and results, tools, stop sequences,
    response_format schemas and the user field, including dict keys and JSON carried inside strings."""
    for k, v in body.items():
        yield from _walk(v, _Loc(None, k))  # includes "model": a pass-through target forwards the client's model name


# Key formats for joined text, without word boundaries: at a join seam a key half sits against its neighbour
# ("assistantAKIA", "EXAMPLEok"), so \b cannot be required there. Cards are left out: digits from unrelated fields
# would join into false cards.
_JOIN_RULES = [
    ("aws_access_key", re.compile(r"(?:AKIA|ASIA)[0-9A-Z]{16}")),
    ("github_token", re.compile(r"gh[pousr]_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{60}")),
    ("anthropic_key", re.compile(r"sk-ant-[A-Za-z0-9_\-]{20}")),
    ("openai_key", re.compile(r"sk-(?:proj|svcacct|admin)-[A-Za-z0-9_\-]{20}")),
    ("stripe_key", re.compile(r"(?:sk|rk)_live_[A-Za-z0-9]{16}")),
    ("slack_token", re.compile(r"xox[abposr]-\d{6,}-[A-Za-z0-9-]{6}")),
    ("google_api_key", re.compile(r"AIza[0-9A-Za-z_\-]{35}")),
    ("private_key", re.compile(r"-----BEGIN (?:[A-Z0-9 ]{1,64} )?PRIVATE KEY-----")),
]
# the API's own structural fields, which sit between content in document order
_STRUCTURAL = (".<key>", ".role", ".id", ".type", ".name", ".tool_call_id")


def _joined_texts(body: dict) -> Iterator[tuple[str, str]]:
    """Joins with nothing between strings, in document order: the content strings alone (structural fields skipped);
    every value (so a key split across a tool's name and its arguments is whole); and the keys and values of JSON
    carried inside strings (a key half in a JSON key, the other in its value). One more linear pass each."""
    content: list[str] = []
    everything: list[str] = []
    with_keys: list[str] = []
    decoded_json: list[str] = []
    for where, t in _texts(body):
        if isinstance(t, _Undecodable):
            continue
        with_keys.append(t.strip())  # keys and values everywhere: {"parameters": {"AKIA": "IOSFODNN7EXAMPLE"}}
        if where.in_json:
            decoded_json.append(t.strip())  # keys and values of JSON inside strings: {"AKIA": "IOSFODNN7EXAMPLE"}
        if where.step == ".<key>":
            continue
        everything.append(t.strip())
        if not (where.parent is None and where.step == "model") and where.step not in _STRUCTURAL:
            content.append(t.strip())
    for label, parts in (("request<joined>", content), ("request<joined-all>", everything),
                         ("request<joined-keys>", with_keys), ("json<joined>", decoded_json)):
        if len(parts) > 1:
            yield label, "".join(parts)


MIN_SCANNED = 6  # the shortest format any rule matches (an email such as a@b.co) has 6 characters
MAX_FINDINGS_PER_RULE = 16  # the decision needs which rules fired; a request of a million card numbers need not keep a million


def scan_request(body: dict, extra: Iterable[tuple[str, str]] = ()) -> list[Finding]:
    found: list[Finding] = []
    count: dict[str, int] = {}

    def add(rule: str, where) -> None:
        if count.get(rule, 0) < MAX_FINDINGS_PER_RULE:
            count[rule] = count.get(rule, 0) + 1
            found.append(Finding(rule, str(where)))

    for where, text in _joined_texts(body):
        t = normalise(text)
        for rule, pat in _JOIN_RULES:
            if pat.search(t):
                add(rule, where)
    # one string at a time, never all of them held at once
    for where, text in itertools.chain(_texts(body), extra):
        if isinstance(text, _Undecodable):
            add("undecodable_nested_json", where)
            continue
        if len(text.strip()) < MIN_SCANNED:
            continue  # too short to hold any format a rule knows; pieces of a split secret are caught in the joins above
        for f in scan_text(text, str(where) if isinstance(where, str) else ""):
            add(f.rule, where)
    return found
