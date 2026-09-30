"""Zero-question setup. Everything here is a universal convention, the same for every user, so nothing needs editing
per install: the ports local model servers listen on, the environment variables cloud keys live in, and the file
names that hold secrets. A user who wants more (public sources, balanced mode) edits the written config later."""

from __future__ import annotations

import os
from pathlib import Path

import httpx

# default OpenAI-compatible ports of common local servers, in the order they are tried
LOCAL_SERVERS = [
    ("ollama", "http://127.0.0.1:11434/v1"),
    ("lmstudio", "http://127.0.0.1:1234/v1"),
    ("llamacpp", "http://127.0.0.1:8080/v1"),
    ("vllm", "http://127.0.0.1:8000/v1"),
    ("jan", "http://127.0.0.1:1337/v1"),
]

# OpenAI-compatible endpoints of cloud providers, keyed by the environment variable their SDKs already read.
# Added only when that variable is set. The client names the model per request as "<provider>/<model>".
CLOUD_PROVIDERS = [
    ("openai", "OPENAI_API_KEY", "https://api.openai.com/v1"),
    ("anthropic", "ANTHROPIC_API_KEY", "https://api.anthropic.com/v1"),
    ("gemini", "GEMINI_API_KEY", "https://generativelanguage.googleapis.com/v1beta/openai"),
    ("mistral", "MISTRAL_API_KEY", "https://api.mistral.ai/v1"),
    ("groq", "GROQ_API_KEY", "https://api.groq.com/openai/v1"),
    ("openrouter", "OPENROUTER_API_KEY", "https://openrouter.ai/api/v1"),
]

# files that hold secrets by convention on every system
SECRET_FILES = [
    ".env*", "**/.env*", "**/*.pem", "**/*.key", "**/*.p12", "**/*.pfx", "**/id_rsa*", "**/id_ed25519*", "**/id_ecdsa*",
    "**/.aws/credentials", "**/.netrc", "**/.npmrc", "**/.pypirc", "**/.docker/config.json", "**/.kube/config",
]


def default_audit_log() -> str:
    base = Path(os.environ.get("XDG_STATE_HOME") or Path.home() / ".local" / "state") / "sovereign-router"
    base.mkdir(parents=True, exist_ok=True)
    return str(base / "audit.jsonl")


def find_local(timeout: float = 1.0) -> list[tuple[str, str, str]]:
    """(name, url, first model id) for every local server that answers /models."""
    found = []
    with httpx.Client(timeout=timeout, trust_env=False, follow_redirects=False) as c:
        for name, url in LOCAL_SERVERS:
            try:
                r = c.get(f"{url}/models")
                models = [m.get("id") for m in r.json().get("data", []) if isinstance(m, dict) and m.get("id")]
            except Exception:  # noqa: BLE001
                continue
            if r.status_code == 200 and models:
                found.append((name, url, models[0]))
    return found


def find_cloud() -> list[tuple[str, str, str]]:
    return [(name, env, url) for name, env, url in CLOUD_PROVIDERS if os.environ.get(env)]


def auto_config(timeout: float = 1.0) -> tuple[dict, list[str]]:
    """A config dict for parse_config, plus a plain-language summary of what was found."""
    local = find_local(timeout)
    notes = []
    if not local:
        raise RuntimeError("no local model server found on the usual ports (Ollama 11434, LM Studio 1234, "
                           "llama.cpp 8080, vLLM 8000, Jan 1337). Start one, or write a config: see example.yaml")
    targets: dict = {}
    for name, url, model in local:
        targets[name] = {"url": url, "model": model, "location": "local"}
        notes.append(f"local: {name} at {url}, model {model}")
    for name, env, url in find_cloud():
        targets[name] = {"url": url, "model": "*", "location": "cloud", "api_key_env": env}
        notes.append(f"cloud: {name} ({env} is set); request models as '{name}/<model>', only for public work")
    if not any(t["location"] == "cloud" for t in targets.values()):
        notes.append("no cloud key found in the environment: everything stays local")
    raw = {"version": 1, "mode": "strict", "audit_log": default_audit_log(), "targets": targets,
           "provenance": {"public_sources": [], "private_sources": SECRET_FILES}}
    return raw, notes
