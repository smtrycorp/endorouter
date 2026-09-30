"""Zero-question setup. Everything here is a universal convention, the same for every user, so nothing needs editing
per install: the ports local model servers listen on, the environment variables cloud keys live in, and the file
names that hold secrets. A user who wants more (public sources, balanced mode) edits the written config later."""

from __future__ import annotations

import os
import re
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

    # the executable path (ps comm) comes first when known; an app bundle is judged from it alone, never from the
    # arguments (node '/Users/me/LM Studio.app/proxy.js' is node)
    exe_path, sep, rest = cmdline.partition("\0")
    if sep:
        cmdline = rest
    else:
        m = re.match(r"^(/(?:[^/]+/)*?[^/]+\.app/Contents/MacOS/[^/]+?)(?:\s+-|$)", cmdline)
        exe_path = m.group(1) if m else ""
    if exe_path.startswith("/") and ".app/" in exe_path:
        bundle = Path(exe_path.split(".app/", 1)[0] + ".app").name
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
        # interpreter options come first; the first non-option is the script, or '-m <module>' names a module.
        # A '-m' after the script belongs to the script (python proxy.py -m vllm is not vLLM).
        i = 1
        while i < len(argv):
            a = argv[i]
            if a == "-m":
                mod = argv[i + 1].split(".")[0].lower() if i + 1 < len(argv) else ""
                return mod if mod in LOCAL_INFERENCE_PROGRAMS else None
            if a == "-c" or not a.startswith("-"):
                break
            i += 2 if a in ("-X", "-W", "-Q") else 1
        if i < len(argv) and not argv[i].startswith("-"):
            base = Path(argv[i]).name.lower()
            return base if base in LOCAL_INFERENCE_PROGRAMS else None
        return None
    return None


def _port_owners(url: str) -> list[str] | None:
    """The command line of every process listening on the url's port, or None if that cannot be determined."""
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
        owners = []
        for pid in dict.fromkeys(pids):
            exe = subprocess.run(["ps", "-o", "comm=", "-p", pid], capture_output=True, text=True, timeout=5).stdout.strip()
            cmd = subprocess.run(["ps", "-o", "command=", "-p", pid], capture_output=True, text=True, timeout=5).stdout.strip()
            owners.append(f"{exe}\0{cmd}" if exe else cmd)  # executable path, then the full command line
        return owners
    except (OSError, subprocess.SubprocessError):
        return None


def verified_program(url: str) -> str | None:
    """The local-inference program behind a port, when EVERY process listening on it is that same program."""
    owners = _port_owners(url)
    if not owners:
        return None
    programs = {_program(o) for o in owners}
    return programs.pop() if len(programs) == 1 and None not in programs else None


def _port_owner(url: str) -> str | None:  # kept for the notes printed to the user
    owners = _port_owners(url)
    return owners[0] if owners else None


def _ollama_remote(c: httpx.Client, url: str, model: str) -> bool:
    """Ollama can serve hosted 'cloud' models behind a local port; those report a remote host, or carry 'cloud' in
    their tag. Anything but a clean answer counts as remote."""
    if "cloud" in model.lower():
        return True
    try:
        r = c.post(url.rsplit("/v1", 1)[0] + "/api/show", json={"model": model})
        info = r.json()
    except Exception:  # noqa: BLE001
        return True
    if r.status_code != 200 or not isinstance(info, dict):
        return True
    caps = info.get("capabilities")
    if isinstance(caps, list) and "completion" not in caps:
        return True  # an embedding-only model cannot serve chat: not usable, so treated like one we will not pick
    return bool(info.get("remote_host") or info.get("remote_model"))


def _local_models(c: httpx.Client, url: str, models: list[str], ollama_api: bool) -> list[str]:
    """Models that run here: never one whose name says cloud, and for an Ollama API never one it reports as remote."""
    keep = [m for m in models if "cloud" not in m.lower()]
    return [m for m in keep if not _ollama_remote(c, url, m)] if ollama_api else keep


def _speaks_ollama(c: httpx.Client, url: str) -> bool:
    try:
        return c.get(url.rsplit("/v1", 1)[0] + "/api/version").status_code == 200
    except Exception:  # noqa: BLE001
        return False


def find_local(timeout: float = 1.0) -> tuple[list[tuple[str, str, str, str | None]], list[str]]:
    """Verified local servers as (name, url, model, program), plus notes on servers found but not trusted."""
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
            program = verified_program(url)
            if program is None:
                owners = _port_owners(url) or []
                shown = "; ".join(o.split("\0")[-1][:160] for o in owners) or "a program this user cannot see"
                notes.append(f"found a server at {url} but could not verify it runs models on this machine. It is "
                             f"served by: {shown}. Not used. Only if that program runs models here, trust it with "
                             f"`sovereign-router init --trust {name}=<model>` naming the local model to use")
                continue
            models = _local_models(c, url, models, ollama_api=program == "ollama" or _speaks_ollama(c, url))
            if not models:
                notes.append(f"{name}: every model it lists is hosted remotely; not used")
                continue
            found.append((name, url, models[0], program))
    return found, notes


def find_cloud() -> list[tuple[str, str, str]]:
    return [(name, env, url) for name, env, url in CLOUD_PROVIDERS if os.environ.get(env)]


def auto_config(timeout: float = 1.0, trust: tuple[str, ...] = ()) -> tuple[dict, list[str]]:
    """A config dict for parse_config, plus a plain-language summary of what was found. `trust` names servers the
    user explicitly declares local (the only way an unverifiable server is used)."""
    local, notes = find_local(timeout)
    known = dict(LOCAL_SERVERS)
    for spec in trust:
        name, _, pinned = spec.partition("=")
        if name not in known:
            raise RuntimeError(f"--trust {name}: unknown server name (one of {', '.join(known)})")
        url = known[name]
        if any(n == name for n, _, _, _ in local):
            continue
        try:
            with httpx.Client(timeout=timeout, trust_env=False, follow_redirects=False) as c:
                listed = [m.get("id") for m in c.get(f"{url}/models").json()["data"] if isinstance(m, dict) and m.get("id")]
                ollama_api = _speaks_ollama(c, url)
                usable = _local_models(c, url, listed, ollama_api=ollama_api)
        except Exception:  # noqa: BLE001
            raise RuntimeError(f"--trust {name}: nothing answering at {url}") from None
        if pinned:
            # your word covers this model on this server; a model named 'cloud', or one Ollama reports as hosted, is refused
            if pinned not in listed:
                raise RuntimeError(f"--trust {name}={pinned}: the server does not list that model")
            if pinned not in usable:
                raise RuntimeError(f"--trust {name}={pinned}: that model is hosted remotely")
            model = pinned
        elif ollama_api and usable:
            model = usable[0]  # an Ollama API reports which of its models are hosted, so the first local one is safe
        else:
            raise RuntimeError(f"--trust {name}: name the local model to use, e.g. --trust {name}=<model>. "
                               f"This server lists: {', '.join(listed[:8])}. A gateway can list hosted models too, "
                               f"so the router will not pick one for you")
        local.append((name, url, model, None))
        notes = [n for n in notes if f"--trust {name}" not in n]
        notes.append(f"{name}: trusted as local because you said so (--trust); model {model}")
    if not local:
        raise RuntimeError("no verified local model server found on the usual ports (Ollama 11434, LM Studio 1234, "
                           "llama.cpp 8080, vLLM 8000, Jan 1337)." + ("\n" + "\n".join(notes) if notes else
                           " Start one, or write a config: see example.yaml"))
    targets: dict = {}
    for name, url, model, program in local:
        targets[name] = {"url": url, "model": model, "location": "local"}
        if program:  # re-checked at every start: if another program takes the port later, this target is refused
            targets[name]["verify_program"] = program
        notes.append(f"local: {name} at {url}, model {model}")
    for name, env, url in find_cloud():
        targets[name] = {"url": url, "model": "*", "location": "cloud", "api_key_env": env}
        notes.append(f"cloud: {name} ({env} is set); request models as '{name}/<model>', only for public work")
    if not any(t["location"] == "cloud" for t in targets.values()):
        notes.append("no cloud key found in the environment: everything stays local")
    raw = {"version": 1, "mode": "strict", "audit_log": default_audit_log(), "targets": targets,
           "provenance": {"public_sources": [], "private_sources": SECRET_FILES}}
    return raw, notes
