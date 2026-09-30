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

# files that hold secrets by convention on every system ("**/" also matches the top level: see policy._glob)
SECRET_FILES = [
    ".env*", "**/.env*", "**/*.pem", "**/*.key", "**/*.p12", "**/*.pfx", "**/id_rsa*", "**/id_ed25519*", "**/id_ecdsa*",
    "**/.aws/credentials", "**/.netrc", "**/.npmrc", "**/.pypirc", "**/.docker/config.json", "**/.kube/config",
]


def default_audit_log() -> str:
    base = Path(os.environ.get("XDG_STATE_HOME") or Path.home() / ".local" / "state") / "sovereign-router"
    base.mkdir(parents=True, exist_ok=True)
    return str(base / "audit.jsonl")


# Programs known to run inference on this machine. A server is trusted as local only when the process that owns its
# port is one of these; anything else (a gateway, a proxy, an app that can call hosted models) could forward prompts
# to a cloud, so it is reported but never trusted without an explicit `init --trust <name>`.
LOCAL_INFERENCE_PROGRAMS = {"ollama", "llama-server", "llamafile", "vllm", "mlx_lm", "koboldcpp", "lms"}
LOCAL_INFERENCE_APPS = {"LM Studio.app"}  # an app bundle, matched as a whole path component


def _program(cmdline: str) -> str | None:
    """The local-inference program a command line runs, matched exactly: the executable's name, the module after
    'python -m', or the script a Python interpreter runs. A substring anywhere in the line is never enough (a proxy
    run from ~/vllm-tests/ must not count as vLLM)."""
    import shlex

    # an app bundle's executable path can contain spaces and ps prints it unquoted: check the bundle first
    if cmdline.startswith("/") and ".app/" in cmdline:
        bundle = Path(cmdline.split(".app/", 1)[0] + ".app").name
        if bundle in LOCAL_INFERENCE_APPS:
            return "lm studio"
    try:
        argv = shlex.split(cmdline)
    except ValueError:
        argv = cmdline.split()
    if not argv:
        return None
    exe = Path(argv[0])
    if any(part in LOCAL_INFERENCE_APPS for part in exe.parts):
        return "lm studio"
    name = exe.name.lower()
    if name in LOCAL_INFERENCE_PROGRAMS:
        return name
    if name.startswith("python"):
        if "-m" in argv[1:]:
            i = argv.index("-m")
            mod = argv[i + 1].split(".")[0].lower() if i + 1 < len(argv) else ""
            return mod if mod in LOCAL_INFERENCE_PROGRAMS else None
        script = next((a for a in argv[1:] if not a.startswith("-")), "")
        base = Path(script).name.lower()
        return base if base in LOCAL_INFERENCE_PROGRAMS else None
    return None


def _port_owner(url: str) -> str | None:
    """The full command line of the process listening on the url's port, or None if it cannot be determined."""
    import shutil
    import subprocess
    from urllib.parse import urlsplit

    port = urlsplit(url).port
    if not port or not shutil.which("lsof") or not shutil.which("ps"):
        return None
    try:
        pids = subprocess.run(["lsof", "-nP", f"-iTCP:{port}", "-sTCP:LISTEN", "-t"], capture_output=True, text=True,
                              timeout=5).stdout.split()
        if not pids:
            return None
        return subprocess.run(["ps", "-o", "command=", "-p", pids[0]], capture_output=True, text=True, timeout=5).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return None


def _ollama_remote(c: httpx.Client, url: str, model: str) -> bool:
    """Ollama can serve hosted 'cloud' models behind a local port; those report a remote host, or carry 'cloud' in
    their tag. Treated as remote when in doubt."""
    if "cloud" in model.split(":")[-1] or model.endswith("-cloud"):
        return True
    try:
        info = c.post(url.rsplit("/v1", 1)[0] + "/api/show", json={"model": model}).json()
    except Exception:  # noqa: BLE001
        return True
    return bool(info.get("remote_host") or info.get("remote_model")) or not isinstance(info, dict)


def find_local(timeout: float = 1.0) -> tuple[list[tuple[str, str, str]], list[str]]:
    """Verified local servers as (name, url, model), plus notes on servers found but not trusted."""
    found, notes = [], []
    with httpx.Client(timeout=timeout, trust_env=False, follow_redirects=False) as c:
        for name, url in LOCAL_SERVERS:
            try:
                r = c.get(f"{url}/models")
                models = [m.get("id") for m in r.json().get("data", []) if isinstance(m, dict) and m.get("id")]
            except Exception:  # noqa: BLE001
                continue
            if r.status_code != 200 or not models:
                continue
            owner = _port_owner(url) or ""
            program = _program(owner)
            if program is None:
                notes.append(f"found a server at {url} but could not verify it runs models on this machine "
                             f"(served by {Path(owner.split()[0]).name if owner else 'an unknown program'}); not used. If you know it is local: "
                             f"sovereign-router init --trust {name}")
                continue
            if program == "ollama":
                local_models = [m for m in models if not _ollama_remote(c, url, m)]
                if not local_models:
                    notes.append(f"{name}: every model is hosted remotely; not used")
                    continue
                models = local_models
            found.append((name, url, models[0]))
    return found, notes


def find_cloud() -> list[tuple[str, str, str]]:
    return [(name, env, url) for name, env, url in CLOUD_PROVIDERS if os.environ.get(env)]


def auto_config(timeout: float = 1.0, trust: tuple[str, ...] = ()) -> tuple[dict, list[str]]:
    """A config dict for parse_config, plus a plain-language summary of what was found. `trust` names servers the
    user explicitly declares local (the only way an unverifiable server is used)."""
    local, notes = find_local(timeout)
    for name in trust:
        url = dict(LOCAL_SERVERS).get(name)
        if url and not any(n == name for n, _, _ in local):
            try:
                with httpx.Client(timeout=timeout, trust_env=False, follow_redirects=False) as c:
                    model = c.get(f"{url}/models").json()["data"][0]["id"]
            except Exception:  # noqa: BLE001
                raise RuntimeError(f"--trust {name}: nothing answering at {url}") from None
            local.append((name, url, model))
            notes = [n for n in notes if f"--trust {name}" not in n]
            notes.append(f"{name}: trusted as local because you said so (--trust)")
    if not local:
        raise RuntimeError("no verified local model server found on the usual ports (Ollama 11434, LM Studio 1234, "
                           "llama.cpp 8080, vLLM 8000, Jan 1337)." + ("\n" + "\n".join(notes) if notes else
                           " Start one, or write a config: see example.yaml"))
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
