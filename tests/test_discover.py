"""Zero-question setup: discovery finds local servers and env keys, and verifies which program owns a port through the
process table on every platform; pass-through cloud targets route by '<target>/<model>'."""

from __future__ import annotations

import os
import socket
import subprocess
import sys
from collections import namedtuple
from pathlib import Path, PurePosixPath, PureWindowsPath

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


# stand-ins for what psutil reports: a TCP listener, and a process whose sockets are given, or are an exception when
# the user is not allowed to read them
_Addr = namedtuple("_Addr", "ip port")


class Conn:
    def __init__(self, port, pid, status=psutil.CONN_LISTEN):
        self.laddr, self.pid, self.status = _Addr("127.0.0.1", port), pid, status


class FakeProcess:
    """Stands in for psutil.process_iter: pid -> (exe, argv, conns); an exception in a slot is raised when read."""

    def __init__(self, table):
        self.table = table

    def iter(self):
        return [_Proc(pid, *row) for pid, row in self.table.items()]


class _Proc:
    def __init__(self, pid, exe, argv, conns=()):
        self.pid, self._conns = pid, conns

    def net_connections(self, kind):
        if isinstance(self._conns, BaseException):
            raise self._conns
        return self._conns


# A program is verified by the executable the kernel reports for each process on the port: a known name, inside the
# folder its installer uses, that other users cannot write. The tests below declare a folder under tmp_path as that
# install location and put a real file there.
def installed(tmp_path, monkeypatch, program="ollama", name=None) -> discover.Owner:
    folder = tmp_path / "bin"
    folder.mkdir(exist_ok=True)
    exe = folder / (name or program)
    exe.write_text("")
    exe.chmod(0o755)
    monkeypatch.setattr(discover, "_INSTALLS", {**discover._INSTALLS, program: (str(folder),)})
    return discover.Owner(str(exe), f"{exe} serve")


def table(monkeypatch, holders, exes: dict):
    """A stand-in for the platform's process table: the pids holding the port, and each pid's kernel executable."""
    monkeypatch.setattr(discover, "_holders", lambda port: holders)
    monkeypatch.setattr(discover, "_kernel_exe", exes.get)
    monkeypatch.setattr(discover, "_cmdline", lambda pid: None)


URL = "http://127.0.0.1:11434/v1"
LOCALAPPDATA = r"C:\Users\me\AppData\Local"
WINDOWS_INSTALLS = {p: tuple(f.replace("%LOCALAPPDATA%", LOCALAPPDATA) for f in fs) for p, fs in discover.INSTALLS["win32"].items()}


@pytest.mark.parametrize("exe,expected", [
    ("/Applications/Ollama.app/Contents/Resources/ollama", "ollama"),
    ("/usr/local/bin/ollama", "ollama"),
    ("/opt/homebrew/bin/llama-server", "llama-server"),
    ("/Applications/LM Studio.app/Contents/MacOS/LM Studio", "lm studio"),
    ("/Applications/LM Studio.app/Contents/Frameworks/LM Studio Helper.app/Contents/MacOS/LM Studio Helper", "lm studio"),
    ("/Applications/LM Studio.app/Contents/Frameworks/LM Studio Helper (GPU).app/Contents/MacOS/LM Studio Helper (GPU)", "lm studio"),
    ("/Applications/Jan.app/Contents/MacOS/Jan", "jan"),
    ("/tmp/ollama", None),
    ("/Users/me/Downloads/ollama", None),
    ("/Users/me/LM Studio.app/Contents/MacOS/LM Studio", None),
    ("/usr/local/bin/ollama.exe", None),      # on Unix the suffix is part of the name
    ("/usr/local/bin/python3", None),
    ("/opt/homebrew/bin/ollama-proxy", None),
    ("/usr/local/bin/attacker/ollama", None),  # a direct child of the folder, not anything beneath it
    ("/opt/homebrew/Cellar/ollama/0.12.3/bin/ollama", None),  # a Cellar binary counts only as the bin/ link's target
    ("/Applications/LM Studio.app/Contents/Resources/python3", None),  # an app's folder does not bless any file in it
    ("/Applications/LM Studio.app/Contents/MacOS/python3", None),
    ("/Applications/Jan.app/proxy", None),
])
def test_a_macos_executable_is_known_by_name_and_install_folder(monkeypatch, exe, expected):
    monkeypatch.setattr(discover, "_HostPath", PurePosixPath)
    monkeypatch.setattr(discover, "_INSTALLS", discover.INSTALLS["darwin"])
    assert discover._installed(exe) == expected


@pytest.mark.parametrize("exe,expected", [
    (LOCALAPPDATA + r"\Programs\Ollama\ollama.exe", "ollama"),
    (r"C:\Users\ME\APPDATA\Local\Programs\Ollama\OLLAMA.EXE", "ollama"),  # the file system ignores case
    (LOCALAPPDATA + r"\Microsoft\WinGet\Packages\ggml.llamacpp_Microsoft.Winget.Source_8wekyb3d8bbwe\llama-server.exe", "llama-server"),
    (LOCALAPPDATA + r"\Programs\LM Studio\LM Studio.exe", "lm studio"),
    (LOCALAPPDATA + r"\Programs\LM Studio\resources\helper.exe", None),  # not the app's own name
    (LOCALAPPDATA + r"\Programs\LM Studio\resources\LM Studio.exe", None),  # not a direct child of the install folder
    (LOCALAPPDATA + r"\Programs\Jan\Jan.exe", "jan"),
    (LOCALAPPDATA + r"\Programs\Ollama\attacker\ollama.exe", None),
    (LOCALAPPDATA + r"\Microsoft\WinGet\Packages\unrelated.proxy_Microsoft.Winget.Source_8wekyb3d8bbwe\llama-server.exe", None),
    (LOCALAPPDATA + r"\Microsoft\WinGet\Packages\llama-server.exe", None),
    (LOCALAPPDATA + r"\Temp\ollama.exe", None),
    (r"C:\Users\me\Downloads\ollama.exe", None),
    (r"C:\Program Files\KoboldCpp\koboldcpp.exe", None),                 # a portable download has no install folder
    (LOCALAPPDATA + r"\Programs\Ollama\ollama.exe.exe", None),
    (LOCALAPPDATA + r"\Programs\Ollama\ollama.bat", None),
    (r"\\?\C:\Users\me\AppData\Local\Programs\Ollama\ollama.exe", None),  # an unusual path form is not matched
    (r"C:\Python312\python.exe", None),
])
def test_a_windows_executable_is_known_by_name_and_install_folder(monkeypatch, exe, expected):
    monkeypatch.setattr(discover, "_HostPath", PureWindowsPath)
    monkeypatch.setattr(discover, "_INSTALLS", WINDOWS_INSTALLS)
    assert discover._installed(exe) == expected


def test_an_unset_localappdata_matches_nothing_on_windows(monkeypatch):
    monkeypatch.setattr(discover, "_HostPath", PureWindowsPath)
    monkeypatch.setattr(discover, "_INSTALLS", discover.INSTALLS["win32"])
    monkeypatch.delenv("LOCALAPPDATA", raising=False)
    assert discover._installed(LOCALAPPDATA + r"\Programs\Ollama\ollama.exe") is None


def test_one_installed_program_on_every_listener_is_verified(tmp_path, monkeypatch):
    ollama = installed(tmp_path, monkeypatch)
    table(monkeypatch, {4242, 4243}, {4242: ollama.exe, 4243: ollama.exe})
    assert discover.verified_program(URL) == "ollama"


def test_a_known_name_outside_its_install_folder_is_not_verified(tmp_path, monkeypatch):
    installed(tmp_path, monkeypatch)
    stray = tmp_path / "ollama"
    stray.write_text("")
    stray.chmod(0o755)
    table(monkeypatch, {4242}, {4242: str(stray)})
    assert discover.verified_program(URL) is None


@pytest.mark.skipif(sys.platform == "win32", reason="Windows has no mode bits")
@pytest.mark.parametrize("mode", [0o775, 0o757])
def test_an_executable_other_users_can_write_is_not_verified(tmp_path, monkeypatch, mode):
    ollama = installed(tmp_path, monkeypatch)
    Path(ollama.exe).chmod(mode)
    table(monkeypatch, {4242}, {4242: ollama.exe})
    assert discover.verified_program(URL) is None


@pytest.mark.skipif(sys.platform == "win32", reason="a running image cannot be deleted on Windows, and no mode bits are read")
def test_an_installed_executable_that_was_deleted_is_not_verified(tmp_path, monkeypatch):
    ollama = installed(tmp_path, monkeypatch)
    Path(ollama.exe).unlink()
    table(monkeypatch, {4242}, {4242: ollama.exe})
    assert discover.verified_program(URL) is None


def test_two_programs_on_one_port_give_no_verdict(tmp_path, monkeypatch):
    ollama = installed(tmp_path, monkeypatch)
    table(monkeypatch, {100, 200}, {100: sys.executable, 200: ollama.exe})
    assert discover.verified_program(URL) is None


def test_a_holder_whose_executable_the_kernel_withholds_gives_no_verdict(tmp_path, monkeypatch):
    ollama = installed(tmp_path, monkeypatch)
    table(monkeypatch, {100, 200}, {200: ollama.exe})
    assert discover.verified_program(URL) is None


def test_the_command_line_never_decides(tmp_path, monkeypatch):
    """A process titles itself as it likes: argv is shown to the user, and the kernel's executable is judged."""
    installed(tmp_path, monkeypatch)
    monkeypatch.setattr(discover, "_holders", lambda port: {100})
    monkeypatch.setattr(discover, "_kernel_exe", lambda pid: sys.executable)
    monkeypatch.setattr(discover, "_cmdline", lambda pid: "/usr/local/bin/ollama serve")
    assert discover.verified_program(URL) is None
    assert discover._port_owners(URL)[0].cmdline == "/usr/local/bin/ollama serve"


@pytest.mark.parametrize("failure", [OSError("proc table gone"), psutil.AccessDenied(1), ValueError("bad row")])
def test_an_enumeration_error_is_unverified_not_an_exception(monkeypatch, failure):
    def broken(port):
        raise failure

    monkeypatch.setattr(discover, "_holders", broken)
    cfg = parse_config({"version": 1, "targets": {
        "ollama": {"url": URL, "model": "m", "location": "local", "verify_program": "ollama"}}})
    assert discover.verify_target(cfg.target("ollama")) == "no longer served by ollama"


def test_a_python_program_is_reported_as_unverifiable_with_the_trust_command(monkeypatch):
    class R:
        status_code = 200

        def json(self):
            return {"data": [{"id": "qwen3"}]}

    class C:
        def __init__(self, **kw):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *a):
            pass

        def get(self, url):
            return R()

    monkeypatch.setattr(discover.httpx, "Client", C)
    monkeypatch.setattr(discover, "_port_owners", lambda url: [discover.Owner("/usr/bin/python3", "/usr/bin/python3 -m vllm.entrypoints.openai.api_server")])
    found, notes = discover.find_local()
    assert found == []
    assert all("Python program" in n and "--trust" in n and "=<model>" in n for n in notes)


def test_a_known_name_in_the_wrong_place_is_reported_as_such(monkeypatch):
    monkeypatch.setattr(discover, "_INSTALLS", discover.INSTALLS["darwin"])
    note = discover._why_unverified([discover.Owner("/tmp/ollama", "/tmp/ollama serve")])
    assert "outside its install location" in note


# Linux: /proc/net/tcp lists each listening socket with its creator's uid; the holders are found in every readable
# process's descriptor table. A fake /proc tree stands in for the kernel's.
def proc_tree(tmp_path, port, sockets, procs, sockets6=()):
    """sockets: (inode, uid) per LISTEN row of /proc/net/tcp, sockets6 the same for tcp6; procs: pid -> (exe, [inodes
    held])."""
    proc = tmp_path / "proc"
    (proc / "net").mkdir(parents=True)
    header = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode"
    for table, listening, local in (("tcp", sockets, "0100007F"), ("tcp6", sockets6, "00000000000000000000000001000000")):
        rows = [header]
        for inode, uid in listening:
            rows.append(f"   0: {local}:{port:04X} {'0' * len(local)}:0000 0A 00000000:00000000 00:00000000 00000000  {uid}        0 {inode} 1 0 100 0 0 10 0")
        rows.append(f"   1: {local}:{port:04X} {local}:B3C2 01 00000000:00000000 00:00000000 00000000  {os.getuid()}        0 999 1 0 20 4 -1")
        (proc / "net" / table).write_text("\n".join(rows) + "\n")
    for pid, (exe, held) in procs.items():
        fd = proc / str(pid) / "fd"
        fd.mkdir(parents=True)
        os.symlink(exe, proc / str(pid) / "exe")
        (proc / str(pid) / "cmdline").write_bytes(f"{exe}\0serve\0".encode())
        for i, inode in enumerate(held):
            os.symlink(f"socket:[{inode}]", fd / str(3 + i))
    return proc


linux_only_logic = pytest.mark.skipif(sys.platform == "win32", reason="symlinks need a privilege on Windows")


@linux_only_logic
def test_linux_a_listener_held_by_one_installed_program_is_verified(tmp_path, monkeypatch):
    ollama = installed(tmp_path, monkeypatch)
    monkeypatch.setattr(discover, "_PROC", str(proc_tree(tmp_path, 11434, [(777, os.getuid())], {200: (ollama.exe, [777])})))
    monkeypatch.setattr(discover, "_holders", discover._linux_holders)
    monkeypatch.setattr(discover, "_kernel_exe", discover._linux_exe)
    monkeypatch.setattr(discover, "_cmdline", discover._linux_cmdline)
    assert discover.verified_program(URL) == "ollama"
    assert discover._port_owners(URL)[0].cmdline == f"{ollama.exe} serve"


@linux_only_logic
def test_linux_a_listener_two_processes_share_is_seen_with_both(tmp_path, monkeypatch):
    """psutil's table keeps one pid per socket, so a proxy that hands its listener to a real ollama was invisible."""
    ollama = installed(tmp_path, monkeypatch)
    proc = proc_tree(tmp_path, 11434, [(777, os.getuid())], {100: (sys.executable, [777]), 200: (ollama.exe, [777])})
    monkeypatch.setattr(discover, "_PROC", str(proc))
    assert discover._linux_holders(11434) == {100, 200}
    monkeypatch.setattr(discover, "_holders", discover._linux_holders)
    monkeypatch.setattr(discover, "_kernel_exe", discover._linux_exe)
    assert discover.verified_program(URL) is None


@linux_only_logic
def test_linux_a_socket_of_another_user_gives_no_verdict(tmp_path, monkeypatch):
    ollama = installed(tmp_path, monkeypatch)
    proc = proc_tree(tmp_path, 11434, [(777, os.getuid()), (778, os.getuid() + 1)], {200: (ollama.exe, [777])})
    monkeypatch.setattr(discover, "_PROC", str(proc))
    assert discover._linux_holders(11434) is None


@linux_only_logic
def test_linux_an_unreadable_process_that_holds_no_listener_does_not_matter(tmp_path, monkeypatch):
    """ssh-agent, another user's shell: a descriptor table this user cannot read costs the verdict only when a socket
    on the port is left with no holder found (test_review_14)."""
    if os.geteuid() == 0:
        pytest.skip("root reads everything")
    ollama = installed(tmp_path, monkeypatch)
    proc = proc_tree(tmp_path, 11434, [(777, os.getuid())], {100: (sys.executable, []), 200: (ollama.exe, [777])})
    (proc / "100" / "fd").chmod(0)
    monkeypatch.setattr(discover, "_PROC", str(proc))
    try:
        assert discover._linux_holders(11434) == {200}
    finally:
        (proc / "100" / "fd").chmod(0o755)


@linux_only_logic
def test_linux_a_port_nobody_listens_on_has_no_holders(tmp_path, monkeypatch):
    monkeypatch.setattr(discover, "_PROC", str(proc_tree(tmp_path, 11434, [(777, os.getuid())], {})))
    assert discover._linux_holders(8080) == set()
    assert discover._linux_holders(11434) is None  # a socket nobody readable holds: owners unknown, not absent


# macOS: the kernel's socket list (netstat -v) names one holder per socket, of any user; each readable process is
# then asked for its own sockets, so a shared listener is seen with every holder this user can read.
NETSTAT = """Active Internet connections (including servers)
Proto Recv-Q Send-Q  Local Address                                 Foreign Address                               (state)          rxbytes      txbytes  rhiwat  shiwat          process:pid    state  options           gencnt    flags   flags1 usecnt rtncnt fltrs
tcp4       0      0  127.0.0.1.11434        127.0.0.1.52011        ESTABLISHED         9638         3711  131072  131376           ollama:4242   00102 00000008 000000000251db68 00000080 04000900      2      0 000000
tcp4       0      0  127.0.0.1.11434        *.*                    LISTEN                 0            0  131072  131072           ollama:4242   00000 00000006 000000000246b336 00000000 00000800      1      0 000000
tcp6       0      0  ::1.11434              *.*                    LISTEN                 0            0  131072  131072 Google Chrome He:1411   00000 00000006 000000000245e65a 00000000 00000800      1      0 000000
tcp4       0      0  127.0.0.1.1234         *.*                    LISTEN                 0            0  131072  131072        LM Studio:77     00000 00000006 000000000245e65b 00000000 00000800      1      0 000000
"""


class _Run:
    def __init__(self, stdout, stderr=""):
        self.stdout, self.stderr, self.returncode = stdout, stderr, 0


def macos_table(monkeypatch, netstat, procs: FakeProcess, stderr=""):
    monkeypatch.setattr(discover.subprocess, "run", lambda *a, **kw: _Run(netstat, stderr))
    monkeypatch.setattr(discover.psutil, "process_iter", procs.iter)


def test_macos_every_listener_in_the_kernels_list_counts_whoever_owns_it(monkeypatch):
    """ollama on IPv4 and another user's process on IPv6 of the same port: both are holders."""
    macos_table(monkeypatch, NETSTAT, FakeProcess({4242: ("x", [], [Conn(11434, 4242)]), 1411: ("x", [], psutil.AccessDenied(1411))}))
    assert discover._darwin_holders(11434) == {4242, 1411}
    assert discover._darwin_holders(1234) == {77}
    assert discover._darwin_holders(8080) == set()


def test_macos_a_shared_listener_is_seen_with_every_readable_holder(monkeypatch):
    macos_table(monkeypatch, NETSTAT, FakeProcess({4242: ("x", [], [Conn(11434, 4242)]), 100: ("x", [], [Conn(11434, 100)]),
                                                   1411: ("x", [], psutil.AccessDenied(1411)), 5: ("x", [], psutil.ZombieProcess(5))}))
    assert discover._darwin_holders(11434) == {4242, 1411, 100}


def test_macos_a_netstat_layout_this_parse_does_not_fit_gives_no_verdict(monkeypatch):
    short = NETSTAT.replace("      1      0 000000\n", "\n")
    macos_table(monkeypatch, short, FakeProcess({}))
    assert discover._darwin_holders(11434) is None
    macos_table(monkeypatch, NETSTAT.replace("ollama:4242   00000", "ollama 00000"), FakeProcess({}))
    assert discover._darwin_holders(11434) is None
    macos_table(monkeypatch, NETSTAT.replace("ollama:4242   00000", "ollama:x   00000"), FakeProcess({}))
    with pytest.raises(ValueError):
        discover._darwin_holders(11434)  # _port_owners turns this into no verdict


# Windows: GetExtendedTcpTable, one row per socket with the pid that created it, for every user
def test_windows_every_listening_row_names_its_process_or_there_is_no_verdict(monkeypatch):
    monkeypatch.setattr(discover.psutil, "net_connections", lambda kind: [Conn(11434, 4242), Conn(11434, 4242), Conn(80, 7), Conn(11434, 9, status=psutil.CONN_ESTABLISHED)])
    assert discover._windows_holders(11434) == {4242}
    monkeypatch.setattr(discover.psutil, "net_connections", lambda kind: [Conn(11434, 4242), Conn(11434, 0)])
    assert discover._windows_holders(11434) is None
    monkeypatch.setattr(discover.psutil, "net_connections", lambda kind: [Conn(11434, None)])
    assert discover._windows_holders(11434) is None


LISTENER = "import socket, sys, time\ns = socket.socket(); s.bind(('127.0.0.1', 0)); s.listen(1)\n" \
           "print(s.getsockname()[1], flush=True); time.sleep(60)"


def test_a_real_listener_is_found_through_the_process_table_and_judged_by_its_executable():
    """The one test that reads the live process table: the stand-in is a Python process, so it is found, its
    executable read from the kernel, and rightly not trusted."""
    child = subprocess.Popen([sys.executable, "-c", LISTENER], stdout=subprocess.PIPE, text=True)
    try:
        port = int(child.stdout.readline())
        with socket.create_connection(("127.0.0.1", port), timeout=5):
            pass  # it is listening
        url = f"http://127.0.0.1:{port}/v1"
        owners = discover._port_owners(url)
        assert owners is not None and len(owners) == 1
        assert discover._basename(owners[0].exe).startswith("python") and "s.listen(1)" in owners[0].cmdline
        assert Path(owners[0].exe).is_file()
        assert discover.verified_program(url) is None
    finally:
        child.kill()
        child.wait()
