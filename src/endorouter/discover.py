"""Zero-question setup. Everything here is a universal convention, the same for every user, so nothing needs editing
per install: the ports local model servers listen on, the environment variables cloud keys live in, and the file
names that hold secrets. A user who wants more (public sources, balanced mode) edits the written config later."""

from __future__ import annotations

import ctypes
import json
import os
import shlex
import subprocess
import sys
from collections import namedtuple
from pathlib import Path, PurePosixPath, PureWindowsPath
from urllib.parse import urlsplit

import httpx
import psutil

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

# files that hold secrets by convention on every system ("**/" also matches the top level: see policy._glob);
# _netrc is the Windows spelling
SECRET_FILES = [
    ".env*", "**/.env*", "**/*.pem", "**/*.key", "**/*.p12", "**/*.pfx", "**/id_rsa*", "**/id_ed25519*", "**/id_ecdsa*",
    "**/.aws/credentials", "**/.netrc", "**/_netrc", "**/.npmrc", "**/.pypirc", "**/.docker/config.json", "**/.kube/config",
]


def default_audit_log() -> str:
    """The audit log in the user's state directory: XDG on Unix, %LOCALAPPDATA% on Windows. Both are private to the
    user by default, which matters on Windows, where the file's own mode is not applied (see cli.cmd_doctor)."""
    if sys.platform == "win32":
        state = Path(os.environ.get("LOCALAPPDATA") or Path.home() / "AppData" / "Local")
    else:
        state = Path(os.environ.get("XDG_STATE_HOME") or Path.home() / ".local" / "state")
    base = state / "endorouter"
    base.mkdir(parents=True, exist_ok=True)
    return str(base / "audit.jsonl")


# Where each local-inference program's installer puts its executable, per platform. A port is trusted only when every
# process holding it runs an executable from one of these places, as the kernel reports the path (resolved, so
# Homebrew's /opt/homebrew/bin/ollama symlink is seen as its Cellar target). A known name anywhere else, such as a
# download folder or /tmp, proves nothing: anyone can put a file of that name there. A Python program (vLLM, mlx_lm,
# KoboldCpp) cannot be verified either: 'python -m vllm' names a module, not the code that answers. Both are used
# only with `init --trust <name>=<model>`. Ollama: install.sh puts the Linux binary in <prefix>/bin and the macOS
# server inside Ollama.app; the Windows installer uses %LOCALAPPDATA%\Programs\Ollama. llama.cpp: Homebrew and
# winget. LM Studio and Jan serve their port from helper processes inside the app, so any executable inside counts.
INSTALLS = {
    "linux": {
        "ollama": ("/usr/local/bin", "/usr/bin", "/bin", "/home/linuxbrew/.linuxbrew/Cellar/ollama"),
        "llama-server": ("/usr/local/bin", "/usr/bin", "/home/linuxbrew/.linuxbrew/Cellar/llama.cpp"),
    },
    "darwin": {
        "ollama": ("/Applications/Ollama.app", "/usr/local/bin", "/opt/homebrew/Cellar/ollama", "/usr/local/Cellar/ollama"),
        "llama-server": ("/usr/local/bin", "/opt/homebrew/Cellar/llama.cpp", "/usr/local/Cellar/llama.cpp"),
        "lm studio": ("/Applications/LM Studio.app",),
        "jan": ("/Applications/Jan.app",),
    },
    "win32": {
        "ollama": (r"%LOCALAPPDATA%\Programs\Ollama",),
        "llama-server": (r"%LOCALAPPDATA%\Microsoft\WinGet\Packages",),
        "lm studio": (r"%LOCALAPPDATA%\Programs\LM Studio",),
        "jan": (r"%LOCALAPPDATA%\Programs\Jan",),
    },
}
APPS = {"lm studio", "jan"}  # matched by folder alone; the others by the executable's name as well

# process paths are in the syntax of the machine the process runs on; tests set these to judge another platform
_HostPath = PureWindowsPath if sys.platform == "win32" else PurePosixPath
_INSTALLS = INSTALLS.get(sys.platform, {})


def _basename(path: str) -> str:
    """The lower-cased file name, less the '.exe' every Windows program carries. Only there: on Unix a file called
    ollama.exe is not ollama."""
    name = _HostPath(path).name.lower()
    return name.removesuffix(".exe") if _HostPath is PureWindowsPath else name


def _installed(exe: str) -> str | None:
    """The program an executable belongs to by its name and its place: inside one of the folders its installer uses."""
    path = _HostPath(exe)
    for program, folders in _INSTALLS.items():
        if program in APPS or _basename(exe) == program:
            if any(_HostPath(os.path.expandvars(f)) in path.parents for f in folders):
                return program
    return None


def _program(exe: str) -> str | None:
    """The local-inference program an executable is, or None: a known name in its install location that, on Unix, no
    other user can write. Windows has no mode bits to read: the install folders are under the user's own profile, and
    their access lists are not checked."""
    program = _installed(exe)
    if program is None:
        return None
    if sys.platform != "win32":
        try:
            if os.stat(exe).st_mode & 0o022:
                return None
        except OSError:
            return None
    return program


Owner = namedtuple("Owner", "exe cmdline")  # exe as the kernel reports it; the command line is shown, never judged


def _listens_on(conn, port: int) -> bool:
    return conn.status == psutil.CONN_LISTEN and bool(conn.laddr) and conn.laddr.port == port


_PROC = "/proc"


def _linux_holders(port: int) -> set[int] | None:
    """Every readable process holding a LISTEN socket on the port, from /proc, or None when a socket on it belongs to
    another user. /proc/net/tcp and tcp6 list each listening socket once, with the uid that created it. The holders
    are found in every process's descriptor table, so a listener two processes share is seen with both. A table this
    user cannot read (another user's process, or one that made itself non-dumpable, as ssh-agent does) is skipped:
    such a process can hold this user's socket only if a process of this user handed it over. psutil's table is not
    used because it keeps one pid per socket, which hides a shared listener."""
    me = os.getuid()
    sockets = set()
    for table in ("tcp", "tcp6"):
        try:
            rows = Path(_PROC, "net", table).read_text().splitlines()[1:]
        except FileNotFoundError:  # IPv6 disabled
            continue
        for row in rows:
            fields = row.split()
            if len(fields) < 10:
                return None
            if fields[3] != "0A" or int(fields[1].rsplit(":", 1)[1], 16) != port:  # 0A is LISTEN
                continue
            if int(fields[7]) != me:
                return None
            sockets.add(f"socket:[{fields[9]}]")
    if not sockets:
        return set()
    pids = set()
    for entry in os.listdir(_PROC):
        if not entry.isdigit():
            continue
        try:
            fds = os.listdir(f"{_PROC}/{entry}/fd")
        except OSError:  # unreadable, or exited meanwhile
            continue
        for fd in fds:
            try:
                if os.readlink(f"{_PROC}/{entry}/fd/{fd}") in sockets:
                    pids.add(int(entry))
            except OSError:  # closed meanwhile
                continue
    return pids


def _linux_exe(pid: int) -> str | None:
    try:
        return os.readlink(f"{_PROC}/{pid}/exe")
    except OSError:
        return None


def _linux_cmdline(pid: int) -> str | None:
    try:
        argv = Path(_PROC, str(pid), "cmdline").read_bytes().split(b"\0")
    except OSError:
        return None
    return shlex.join(a.decode(errors="replace") for a in argv if a) or None


_NETSTAT = ["/usr/sbin/netstat", "-anv", "-p", "tcp"]


def _darwin_holders(port: int) -> set[int] | None:
    """Every process holding a LISTEN socket on the port, or None when the kernel's list cannot be read. That list
    (netstat -v reads it through sysctl, which needs no privilege, where psutil's system-wide table does) names one
    holder per socket, of any user. A socket two processes share is listed with one of them, so each process is also
    asked for its own sockets. One that refuses (another user's, or setuid) is skipped: it can hold this user's socket
    only if a process of this user handed it over. A zombie holds no descriptors."""
    out = subprocess.run(_NETSTAT, capture_output=True, text=True, check=True, timeout=10).stdout
    pids = set()
    for line in out.splitlines():
        fields = line.split()
        if len(fields) < 6 or not fields[0].startswith("tcp") or fields[5] != "LISTEN":
            continue
        if int(fields[3].rsplit(".", 1)[1]) != port:
            continue
        # the line ends "process:pid" and eight counters; a layout this parse does not fit gives no verdict
        head, *counters = line.rsplit(None, 8)
        _, colon, pid = head.rpartition(":")
        if len(counters) != 8 or not colon:
            return None
        pids.add(int(pid))
    for p in psutil.process_iter():
        try:
            if any(_listens_on(c, port) for c in p.net_connections(kind="tcp")):
                pids.add(p.pid)
        except psutil.Error:
            continue
    return pids


def _darwin_exe(pid: int) -> str | None:
    buf = ctypes.create_string_buffer(4096)  # PROC_PIDPATHINFO_MAXSIZE
    n = _libproc.proc_pidpath(pid, buf, 4096)
    return os.fsdecode(buf.raw[:n]) if n > 0 else None


def _windows_holders(port: int) -> set[int] | None:
    """Every process holding a LISTEN socket on the port, or None when that set may be incomplete. psutil reads
    GetExtendedTcpTable: every socket of every user, each with the pid that created it. A handle duplicated into a
    second process is not listed, so a listener a verified program shares with another program needs that program's
    cooperation, the same limit as on Unix. A row the table could not attribute to a process gives no verdict."""
    pids = {c.pid for c in psutil.net_connections(kind="tcp") if _listens_on(c, port)}
    return None if None in pids or 0 in pids else pids


def _windows_exe(pid: int) -> str | None:
    """The image path from the kernel: OpenProcess with the least right that allows the query, then
    QueryFullProcessImageNameW. psutil's exe() is not used because it falls back to argv[0] when the kernel refuses."""
    from ctypes import wintypes

    k32 = ctypes.windll.kernel32
    k32.OpenProcess.restype = wintypes.HANDLE
    k32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    k32.QueryFullProcessImageNameW.restype = wintypes.BOOL
    k32.QueryFullProcessImageNameW.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD)]
    k32.CloseHandle.argtypes = [wintypes.HANDLE]
    handle = k32.OpenProcess(0x1000, False, pid)  # PROCESS_QUERY_LIMITED_INFORMATION
    if not handle:
        return None
    try:
        size = wintypes.DWORD(32768)
        buf = ctypes.create_unicode_buffer(size.value)
        if not k32.QueryFullProcessImageNameW(handle, 0, buf, ctypes.byref(size)):
            return None
        return buf.value or None
    finally:
        k32.CloseHandle(handle)


def _psutil_cmdline(pid: int) -> str | None:
    try:
        return shlex.join(psutil.Process(pid).cmdline()) or None
    except psutil.Error:
        return None


if sys.platform == "linux":
    _holders, _kernel_exe, _cmdline = _linux_holders, _linux_exe, _linux_cmdline
elif sys.platform == "darwin":
    _libproc = ctypes.CDLL("/usr/lib/libproc.dylib")
    _holders, _kernel_exe, _cmdline = _darwin_holders, _darwin_exe, _psutil_cmdline
else:
    _holders, _kernel_exe, _cmdline = _windows_holders, _windows_exe, _psutil_cmdline


def _port_owners(url: str) -> list[Owner] | None:
    """Every process listening on the url's port, with the executable the kernel reports for it, or None when any of
    them is unknown: a partial list of a port's owners is exactly the one that would leave out a forwarding process."""
    port = urlsplit(url).port
    if not port:
        return None
    try:
        pids = _holders(port)
        if not pids:
            return None
        owners = []
        for pid in pids:
            exe = _kernel_exe(pid)
            if not exe:
                return None
            owners.append(Owner(exe, _cmdline(pid) or exe))
        return owners
    except (OSError, ValueError, psutil.Error, subprocess.SubprocessError):
        # a process table that cannot be read leaves the port's owners unknown; the caller reports that, not a traceback
        return None


def verified_program(url: str) -> str | None:
    """The local-inference program behind a port, when EVERY process listening on it is that same program."""
    owners = _port_owners(url)
    if not owners:
        return None
    programs = {_program(o.exe) for o in owners}
    return programs.pop() if len(programs) == 1 and None not in programs else None


def _why_unverified(owners: list[Owner]) -> str:
    names = {_basename(o.exe) for o in owners}
    if names & set(_INSTALLS):
        return "a program with a known name is running from outside its install location"
    if any(n.startswith("python") for n in names):
        return "a Python program (vLLM, KoboldCpp, mlx_lm) cannot be verified by its name"
    return "it is not a known local-inference program"


def verify_target(target) -> str | None:
    """Why a discovered target must not be used right now, or None when its port is still owned by the program
    discovery verified. Runs before every send; the router adds the model-locality check for Ollama."""
    if not target.verify_program:
        return None
    found = verified_program(target.url)
    if found != target.verify_program:
        return f"no longer served by {target.verify_program}"
    return None


def ollama_show_url(url: str) -> str:
    return url.rsplit("/v1", 1)[0] + "/api/show"


def remote_from_show(status: int, info: object) -> bool:
    """Judge an Ollama /api/show answer: hosted models report a remote host. Anything but a clean answer counts as
    remote, and an embedding-only model counts too, since it cannot serve chat."""
    if status != 200 or not isinstance(info, dict):
        return True
    caps = info.get("capabilities")
    if isinstance(caps, list) and "completion" not in caps:
        return True
    return bool(info.get("remote_host") or info.get("remote_model"))


def _ollama_remote(c: httpx.Client, url: str, model: str) -> bool:
    """Ollama can serve hosted 'cloud' models behind a local port; those report a remote host, or carry 'cloud' in
    their tag."""
    if "cloud" in model.lower():
        return True
    try:
        r = c.post(ollama_show_url(url), json={"model": model})
        info = r.json()
    except (httpx.HTTPError, json.JSONDecodeError):
        return True
    return remote_from_show(r.status_code, info)


def _local_models(c: httpx.Client, url: str, models: list[str], ollama_api: bool) -> list[str]:
    """Models that run here: never one whose name says cloud, and for an Ollama API never one it reports as remote."""
    keep = [m for m in models if "cloud" not in m.lower()]
    return [m for m in keep if not _ollama_remote(c, url, m)] if ollama_api else keep


def _speaks_ollama(c: httpx.Client, url: str) -> bool:
    try:
        return c.get(url.rsplit("/v1", 1)[0] + "/api/version").status_code == 200
    except httpx.HTTPError:
        return False


def find_local(timeout: float = 1.0) -> tuple[list[tuple[str, str, str, str | None, bool]], list[str]]:
    """Verified local servers as (name, url, model, program, speaks the Ollama API), plus notes on servers found but
    not trusted."""
    found, notes = [], []
    with httpx.Client(timeout=timeout, trust_env=False, follow_redirects=False) as c:
        for name, url in LOCAL_SERVERS:
            try:
                r = c.get(f"{url}/models")
                models = [m.get("id") for m in r.json().get("data", []) if isinstance(m, dict) and m.get("id")]
            except (httpx.HTTPError, json.JSONDecodeError, AttributeError, TypeError):
                continue  # nothing there, or something that does not speak the models API
            if r.status_code != 200 or not models:
                continue
            program = verified_program(url)
            if program is None:
                owners = _port_owners(url)
                if owners:
                    why = f"{_why_unverified(owners)}. It is served by: " + "; ".join(o.cmdline[:160] for o in owners)
                else:
                    why = ("it is served by a program this user cannot see (on Linux, a service running as another "
                           "user, such as the ollama service, is invisible to this check)")
                notes.append(f"found a server at {url} but could not verify it runs models on this machine: {why}. "
                             f"Not used. Only if that program runs models here, trust it with "
                             f"`endorouter init --trust {name}=<model>` naming the local model to use")
                continue
            ollama_api = program == "ollama" or _speaks_ollama(c, url)
            models = _local_models(c, url, models, ollama_api=ollama_api)
            if not models:
                notes.append(f"{name}: every model it lists is hosted remotely; not used")
                continue
            found.append((name, url, models[0], program, ollama_api))
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
        verified = next((entry for entry in local if entry[0] == name), None)
        if verified is not None:
            if pinned:  # already verified: honour the model the user named, after the same checks
                with httpx.Client(timeout=timeout, trust_env=False, follow_redirects=False) as c:
                    listed = [m.get("id") for m in c.get(f"{url}/models").json()["data"] if isinstance(m, dict) and m.get("id")]
                    usable = _local_models(c, url, listed, ollama_api=_speaks_ollama(c, url))
                if pinned not in usable:
                    raise RuntimeError(f"--trust {name}={pinned}: not listed, or hosted remotely")
                local[local.index(verified)] = (name, url, pinned, verified[3], verified[4])
            continue
        try:
            with httpx.Client(timeout=timeout, trust_env=False, follow_redirects=False) as c:
                listed = [m.get("id") for m in c.get(f"{url}/models").json()["data"] if isinstance(m, dict) and m.get("id")]
                ollama_api = _speaks_ollama(c, url)
                usable = _local_models(c, url, listed, ollama_api=ollama_api)
        except (httpx.HTTPError, json.JSONDecodeError, KeyError, AttributeError, TypeError):
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
        local.append((name, url, model, None, ollama_api))
        notes = [n for n in notes if f"--trust {name}" not in n]
        notes.append(f"{name}: trusted as local because you said so (--trust); model {model}")
    if not local:
        raise RuntimeError("no verified local model server found on the usual ports (Ollama 11434, LM Studio 1234, "
                           "llama.cpp 8080, vLLM 8000, Jan 1337)." + ("\n" + "\n".join(notes) if notes else
                           " Start one, or write a config: see example.yaml"))
    targets: dict = {}
    for name, url, model, program, ollama_api in local:
        targets[name] = {"url": url, "model": model, "location": "local"}
        if program:  # re-checked before every send: if another program takes the port, this target is refused
            targets[name]["verify_program"] = program
        if ollama_api:  # before every send, Ollama is asked again whether this model runs here
            targets[name]["ollama_api"] = True
        notes.append(f"local: {name} at {url}, model {model}")
    for name, env, url in find_cloud():
        targets[name] = {"url": url, "model": "*", "location": "cloud", "api_key_env": env}
        notes.append(f"cloud: {name} ({env} is set); request models as '{name}/<model>', only for public work")
    if not any(t["location"] == "cloud" for t in targets.values()):
        notes.append("no cloud key found in the environment: everything stays local")
    raw = {"version": 1, "mode": "strict", "audit_log": default_audit_log(), "targets": targets,
           "provenance": {"public_sources": [], "private_sources": SECRET_FILES}}
    return raw, notes
