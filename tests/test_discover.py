"""Zero-question setup: discovery finds local servers and env keys, and verifies which program owns a port through the
process table on every platform; pass-through cloud targets route by '<target>/<model>'."""

from __future__ import annotations

import shlex
import socket
import subprocess
import sys
from collections import namedtuple
from pathlib import PurePosixPath, PureWindowsPath

import httpx
import psutil
import pytest
from starlette.testclient import TestClient

from endorouter import Label, decide, discover
from endorouter.config import parse_config
from endorouter.router import Router
from endorouter.server import create_app


def test_auto_config_finds_local_and_env_keys(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path))
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    monkeypatch.setattr(discover, "find_local", lambda timeout=1.0: ([("ollama", "http://127.0.0.1:11434/v1", "qwen3:8b", "ollama", True)], []))
    for _, env, _ in discover.CLOUD_PROVIDERS:
        monkeypatch.delenv(env, raising=False)
    monkeypatch.setenv("OPENAI_API_KEY", "x")
    raw, notes = discover.auto_config()
    cfg = parse_config(raw)
    assert cfg.mode == "strict" and cfg.target("ollama").is_local and cfg.target("openai").model == "*"
    assert "**/.env*" in cfg.provenance.private_sources and cfg.provenance.public_sources == ()
    assert cfg.target("ollama").verify_program == "ollama"


def test_no_local_server_is_a_clear_error(monkeypatch):
    monkeypatch.setattr(discover, "find_local", lambda timeout=1.0: ([], []))
    with pytest.raises(RuntimeError, match="no verified local model server"):
        discover.auto_config()


def _cfg(tmp_path):
    return parse_config({"version": 1, "audit_log": str(tmp_path / "a.jsonl"), "targets": {
        "local": {"url": "http://local.test/v1", "model": "m", "location": "local"},
        "openai": {"url": "https://cloud.test/v1", "model": "*", "location": "cloud", "api_key_env": "K"}}})


def test_auto_never_selects_a_pass_through_target(tmp_path):
    assert decide(_cfg(tmp_path), declared=Label.PUBLIC).permitted == ("local",)


def test_pass_through_needs_public_and_sends_the_named_model(tmp_path):
    sent = []

    def up(req):
        sent.append((req.url.host, req.content))
        return httpx.Response(200, json={"choices": [{"message": {"content": "ok"}}]})

    cfg = _cfg(tmp_path)
    app = create_app(cfg, Router(cfg, client=httpx.AsyncClient(transport=httpx.MockTransport(up), trust_env=False)))
    c = TestClient(app, base_url="http://127.0.0.1", client=("127.0.0.1", 5000))
    body = {"model": "openai/gpt-5", "messages": [{"role": "user", "content": "hi"}]}
    assert c.post("/v1/chat/completions", json=body).status_code == 403 and sent == []  # unknown: refused
    r = c.post("/v1/chat/completions", json=body, headers={"x-endorouter-label": "public"})
    assert r.status_code == 200 and sent[0][0] == "cloud.test" and b'"model":"gpt-5"' in sent[0][1].replace(b" ", b"")


def test_the_audit_log_defaults_to_the_users_state_folder_on_windows(monkeypatch, tmp_path):
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    assert discover.default_audit_log() == str(tmp_path / "endorouter" / "audit.jsonl")


# stand-ins for what psutil reports: a TCP listener, and a process whose executable, command line and sockets are
# given, or are an exception when the user is not allowed to read them
_Addr = namedtuple("_Addr", "ip port")


class Conn:
    def __init__(self, port, pid, status=psutil.CONN_LISTEN):
        self.laddr, self.pid, self.status = _Addr("127.0.0.1", port), pid, status


class FakeProcess:
    """Stands in for psutil.Process: pid -> (exe, argv[, conns]); an exception in any slot is raised when read."""

    def __init__(self, table):
        self.table = table

    def __call__(self, pid):
        return _Proc(pid, *self.table[pid])

    def iter(self):
        return [self(pid) for pid in self.table]


class _Proc:
    def __init__(self, pid, exe, argv, conns=()):
        self.pid, self._exe, self._argv, self._conns = pid, exe, argv, conns

    def exe(self):
        return _given(self._exe)

    def cmdline(self):
        return _given(self._argv)

    def net_connections(self, kind):
        return _given(self._conns)


def _given(v):
    if isinstance(v, BaseException):
        raise v
    return v


def _owner(exe, argv):
    """The owner line _port_owners builds: executable, NUL, shell-quoted command line."""
    return f"{exe}\0{shlex.join(argv)}"


def test_a_port_owned_by_one_known_program_on_v4_and_v6_is_verified(monkeypatch):
    monkeypatch.setattr(discover.psutil, "net_connections", lambda kind: [Conn(11434, 4242), Conn(11434, 4242), Conn(80, 7)])
    monkeypatch.setattr(discover.psutil, "Process", FakeProcess({4242: ("/usr/local/bin/ollama", ["/usr/local/bin/ollama", "serve"])}))
    assert discover.verified_program("http://127.0.0.1:11434/v1") == "ollama"


def test_on_macos_each_process_answers_for_its_own_sockets_and_other_users_go_unseen(monkeypatch):
    def denied(kind):
        raise psutil.AccessDenied(1)

    procs = FakeProcess({1: ("/usr/libexec/logd", psutil.AccessDenied(1), psutil.AccessDenied(1)),
                         4242: ("/usr/local/bin/ollama", ["/usr/local/bin/ollama", "serve"], [Conn(11434, None)])})
    monkeypatch.setattr(discover.psutil, "net_connections", denied)
    monkeypatch.setattr(discover.psutil, "process_iter", procs.iter)
    monkeypatch.setattr(discover.psutil, "Process", procs)
    assert discover.verified_program("http://127.0.0.1:11434/v1") == "ollama"


def test_a_process_whose_command_line_is_withheld_gives_no_verdict(monkeypatch):
    monkeypatch.setattr(discover.psutil, "net_connections", lambda kind: [Conn(11434, 4242)])
    monkeypatch.setattr(discover.psutil, "Process", FakeProcess({4242: ("/usr/local/bin/ollama", [])}))
    assert discover._port_owners("http://127.0.0.1:11434/v1") is None


def test_a_port_nobody_listens_on_gives_no_verdict(monkeypatch):
    monkeypatch.setattr(discover.psutil, "net_connections", lambda kind: [Conn(11434, 4242, status=psutil.CONN_ESTABLISHED)])
    assert discover._port_owners("http://127.0.0.1:11434/v1") is None


OLLAMA_EXE = r"C:\Users\me\AppData\Local\Programs\Ollama\ollama.exe"
PYTHON_EXE = r"C:\Python312\python.exe"


@pytest.mark.parametrize("exe,argv,expected", [
    (OLLAMA_EXE, [OLLAMA_EXE, "serve"], "ollama"),
    (r"C:\Tools\OLLAMA.EXE", [r"C:\Tools\OLLAMA.EXE", "serve"], "ollama"),             # the file system ignores case
    (r"C:\Program Files\KoboldCpp\koboldcpp.exe", [r"C:\Program Files\KoboldCpp\koboldcpp.exe"], "koboldcpp"),
    (PYTHON_EXE, [PYTHON_EXE, "-m", "koboldcpp"], "koboldcpp"),
    (PYTHON_EXE, [PYTHON_EXE, r"C:\Python312\Scripts\vllm.exe", "serve"], "vllm"),   # a pip launcher runs the script by that name
    (PYTHON_EXE, [PYTHON_EXE, r"C:\Users\me\bin\ollama.exe", "serve"], None),        # Python wearing a native server's name
    (r"C:\Users\me\ollama-proxy\node.exe", [r"C:\Users\me\ollama-proxy\node.exe", "server.js"], None),  # the folder is not the program
    (r"C:\Tools\ollama.exe.exe", [r"C:\Tools\ollama.exe.exe"], None),
    (r"C:\Users\me\AppData\Local\Programs\LM Studio\LM Studio.exe", [r"C:\Users\me\AppData\Local\Programs\LM Studio\LM Studio.exe"], None),  # not known on Windows: see README
    (r"C:\Tools\ollama.bat", [r"C:\Tools\ollama.bat"], None),
])
def test_windows_programs_are_matched_by_name_without_their_exe_suffix(monkeypatch, exe, argv, expected):
    monkeypatch.setattr(discover, "_HostPath", PureWindowsPath)
    assert discover._program(_owner(exe, argv)) == expected


def test_the_exe_suffix_is_only_dropped_on_windows(monkeypatch):
    monkeypatch.setattr(discover, "_HostPath", PurePosixPath)
    assert discover._program(_owner("/usr/local/bin/ollama.exe", ["/usr/local/bin/ollama.exe", "serve"])) is None


LISTENER = "import socket, sys, time\ns = socket.socket(); s.bind(('127.0.0.1', 0)); s.listen(1)\n" \
           "print(s.getsockname()[1], flush=True); time.sleep(60)"


def test_a_real_listener_is_found_through_the_process_table_and_judged_by_its_executable():
    """The one test that reads the live process table: the stand-in is a Python process, so it is found, read, and
    rightly not trusted."""
    child = subprocess.Popen([sys.executable, "-c", LISTENER], stdout=subprocess.PIPE, text=True)
    try:
        port = int(child.stdout.readline())
        with socket.create_connection(("127.0.0.1", port), timeout=5):
            pass  # it is listening
        url = f"http://127.0.0.1:{port}/v1"
        owners = discover._port_owners(url)
        assert owners is not None and len(owners) == 1
        exe, _, cmd = owners[0].partition("\0")
        assert discover._basename(exe).startswith("python") and "s.listen(1)" in cmd
        assert discover.verified_program(url) is None
    finally:
        child.kill()
        child.wait()
