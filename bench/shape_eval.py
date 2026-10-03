"""Measure the vendor-agnostic secret-shape rule, reproducibly.

Detection: synthetic keys from made-up vendors, generated from a fixed seed in the shapes real keys take (base62,
base64, base64url, bare hex), each with and without a vendor-style prefix, each placed the way keys appear (alone in
prose, NAME=value, Bearer, a JSON field). Only the secret_shape rule is counted, since vendor patterns cannot know
these vendors. Assigned values (Django keys, generated passwords, AWS secrets) count any detector, since that is how
they are caught in practice.

False alarms: every .py, .txt, .md, .json, .toml and .cfg file in this interpreter's standard library: public code
and docs that hold no secrets. Every secret_shape finding there is a false alarm. The corpus is pinned by the Python
version printed with the result.

    python bench/shape_eval.py [--seed 7] [--keys 600]
"""

from __future__ import annotations

import argparse
import json
import random
import string
import sys
import sysconfig
import time
from collections import Counter
from pathlib import Path

from endorouter.detectors import scan_text

ALPHABETS = {
    "base62": string.ascii_letters + string.digits,
    "base64": string.ascii_letters + string.digits + "+/",
    "base64url": string.ascii_letters + string.digits + "-_",
    "hex": "0123456789abcdef",
}
PLACES = ["use {k} for staging", "export ACME_TOKEN={k}", "Authorization: Bearer {k}", '{{"apiKey": "{k}"}}']


def _key(rng: random.Random, shape: str) -> str:
    body = "".join(rng.choice(ALPHABETS[shape]) for _ in range(rng.randint(24, 48)))
    if rng.random() < 0.5:
        vendor = "".join(rng.choice(string.ascii_lowercase) for _ in range(rng.randint(2, 5)))
        body = f"{vendor}_{rng.choice(['sk', 'live', 'key', 'pat'])}_{body}"
    return body


def detection(seed: int, n: int) -> dict:
    rng = random.Random(seed)
    found, total = Counter(), Counter()
    for i in range(n):
        shape = list(ALPHABETS)[i % len(ALPHABETS)]
        text = rng.choice(PLACES).format(k=_key(rng, shape))
        total[shape] += 1
        found[shape] += any(f.rule == "secret_shape" for f in scan_text(text, "x"))
    return {s: f"{found[s]}/{total[s]} ({100 * found[s] / total[s]:.0f}%)" for s in ALPHABETS} | {
        "all": f"{sum(found.values())}/{n} ({100 * sum(found.values()) / n:.0f}%)"}


ASSIGNED = {
    # Django's own SECRET_KEY alphabet and length; NAME = 'value' as settings.py writes it
    "django_key": ("SECRET_KEY = '{k}'", string.ascii_lowercase + string.digits + "!@#$%^&*(-_=+)", 50, 50),
    # generated passwords, letters, digits and punctuation, in a .env line
    "password_20": ("DB_PASSWORD={k}", string.ascii_letters + string.digits + "!#%&*+-.:;<=>?@^_~", 20, 20),
    # AWS secret access keys: 40 base64 characters, slashes included
    "aws_secret_40": ("aws_secret_access_key = {k}", string.ascii_letters + string.digits + "+/", 40, 40),
}


def assigned(seed: int, n: int) -> dict:
    """Values assigned to an upper- or lower-case credential name, scored whole (any detector counts)."""
    rng = random.Random(seed + 1)
    out = {}
    for name, (place, alphabet, lo, hi) in ASSIGNED.items():
        hits = 0
        for _ in range(n):
            k = "".join(rng.choice(alphabet) for _ in range(rng.randint(lo, hi)))
            hits += bool(list(scan_text(place.format(k=k), "x")))
        out[name] = f"{hits}/{n} ({100 * hits / n:.0f}%)"
    return out


def false_alarms() -> dict:
    root = Path(sysconfig.get_paths()["stdlib"])
    files = [p for p in sorted(root.rglob("*")) if p.suffix in {".py", ".txt", ".md", ".json", ".toml", ".cfg"}
             and "site-packages" not in p.parts and p.is_file()]
    size, alarms, t0 = 0, 0, time.perf_counter()
    for p in files:
        text = p.read_text("utf-8", "replace")
        size += len(text.encode())
        alarms += sum(1 for f in scan_text(text, str(p)) if f.rule == "secret_shape")
    mb = size / 1e6
    secs = time.perf_counter() - t0
    return {"corpus": f"Python {sys.version.split()[0]} standard library, {len(files)} files, {mb:.1f} MB",
            "false_alarms": alarms, "per_MB": round(alarms / mb, 2), "scan_seconds_per_MB": round(secs / mb, 2)}


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--keys", type=int, default=600)
    args = ap.parse_args()
    print(json.dumps({"seed": args.seed, "detection": detection(args.seed, args.keys),
                      "assigned": assigned(args.seed, 200), "false_alarms": false_alarms()}, indent=2))
