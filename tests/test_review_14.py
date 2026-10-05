"""Windows-branch review, round 2 (two reviewers, 2026-10-04): every listening socket needs a holder that was found, the
macOS socket table must be recognised before readable processes add to it, an executable's place is judged by its
canonical path and by who can write along it, a malformed table or URL gives no verdict, the model probe follows no
redirect and is reported when it left, and the audit repair judges the last line, not the last byte."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from endorouter import discover
from endorouter.audit import AuditLog
from endorouter.config import ConfigError, Target, parse_config
from tests.test_discover import (
    NETSTAT,
    URL,
    Conn,
    FakeProcess,
    installed,
    linux_only_logic,
    macos_table,
    proc_tree,
    table,
)

unix_only = pytest.mark.skipif(sys.platform == "win32", reason="no mode bits on Windows, and symlinks need a privilege")
windows_only = pytest.mark.skipif(sys.platform != "win32", reason="junctions and 8.3 names are Windows")
TARGET = {"version": 1, "targets": {"ollama": {"url": URL, "model": "m", "location": "local", "verify_program": "ollama"}}}


def linux_proc(monkeypatch, proc):
    monkeypatch.setattr(discover, "_PROC", str(proc))
    monkeypatch.setattr(discover, "_holders", discover._linux_holders)
    monkeypatch.setattr(discover, "_kernel_exe", discover._linux_exe)
    monkeypatch.setattr(discover, "_cmdline", discover._linux_cmdline)


def unreadable(folder: Path):
    if os.geteuid() == 0:
        pytest.skip("root reads everything")
    mode = folder.stat().st_mode
    folder.chmod(0)
    return lambda: folder.chmod(mode)


@linux_only_logic
def test_linux_a_second_socket_on_the_port_whose_holder_cannot_be_read_gives_no_verdict(tmp_path, monkeypatch):
    """SO_REUSEPORT: a process of this user binds its own listener beside ollama's and is handed half the connections.
    It hides its descriptor table (PR_SET_DUMPABLE=0), so its socket is listed but nobody is found holding it."""
    ollama = installed(tmp_path, monkeypatch)
    me = os.getuid()
    proc = proc_tree(tmp_path, 11434, [(777, me), (888, me)], {200: (ollama.exe, [777]), 100: (sys.executable, [888])})
    restore = unreadable(proc / "100" / "fd")
    try:
        linux_proc(monkeypatch, proc)
        assert discover._linux_holders(11434) is None
        assert discover.verified_program(URL) is None
    finally:
        restore()


@linux_only_logic
def test_linux_an_ipv4_socket_nobody_was_found_holding_is_not_covered_by_the_ipv6_one(tmp_path, monkeypatch):
    """A proxy on 127.0.0.1:11434 with an unreadable table, ollama on [::1]:11434: separate sockets, and the
    configured IPv4 destination is the proxy."""
    ollama = installed(tmp_path, monkeypatch)
    me = os.getuid()
    proc = proc_tree(tmp_path, 11434, [(888, me)], {200: (ollama.exe, [777]), 100: (sys.executable, [888])}, sockets6=[(777, me)])
    restore = unreadable(proc / "100" / "fd")
    try:
        linux_proc(monkeypatch, proc)
        assert discover._linux_holders(11434) is None
        assert discover.verified_program(URL) is None
    finally:
        restore()


@linux_only_logic
def test_linux_a_listening_row_without_an_inode_gives_no_verdict(tmp_path, monkeypatch):
    ollama = installed(tmp_path, monkeypatch)
    proc = proc_tree(tmp_path, 11434, [(777, os.getuid()), (0, os.getuid())], {200: (ollama.exe, [777])})
    linux_proc(monkeypatch, proc)
    assert discover._linux_holders(11434) is None
    assert discover.verified_program(URL) is None


@linux_only_logic
def test_linux_a_row_without_the_address_separator_gives_no_verdict(tmp_path, monkeypatch):
    ollama = installed(tmp_path, monkeypatch)
    proc = proc_tree(tmp_path, 11434, [(777, os.getuid())], {200: (ollama.exe, [777])})
    tcp = proc / "net" / "tcp"
    tcp.write_text(tcp.read_text().replace("0100007F:2CAA 00000000", "0100007F2CAA 00000000", 1))
    linux_proc(monkeypatch, proc)
    assert discover._linux_holders(11434) is None
    cfg = parse_config(TARGET)
    assert discover.verify_target(cfg.target("ollama")) == "no longer served by ollama"


def macos_proc(monkeypatch, exe):
    monkeypatch.setattr(discover, "_holders", discover._darwin_holders)
    monkeypatch.setattr(discover, "_kernel_exe", lambda pid: exe)
    monkeypatch.setattr(discover, "_cmdline", lambda pid: None)


def test_macos_a_denied_socket_table_is_not_stood_in_for_by_readable_processes(tmp_path, monkeypatch):
    """What netstat returned in a sandbox: exit 0, nothing on stdout, the refused sysctl on stderr. The one readable
    ollama process is not the whole port."""
    ollama = installed(tmp_path, monkeypatch)
    macos_table(monkeypatch, "", FakeProcess({4242: ("x", [], [Conn(11434, 4242)])}),
                stderr="netstat: sysctl: net.inet.tcp.pcblist_n: Operation not permitted\n")
    assert discover._darwin_holders(11434) is None
    macos_proc(monkeypatch, ollama.exe)
    assert discover.verify_target(parse_config(TARGET).target("ollama")) == "no longer served by ollama"


@pytest.mark.parametrize("output,stderr", [
    ("", ""),
    ("Active Internet connections (including servers)\n", ""),
    (NETSTAT.replace("Proto Recv-Q Send-Q  Local", "Proto Recv-Q  Local"), ""),  # a column fewer: state is elsewhere
    (NETSTAT.replace("          process:pid    state", "    state"), ""),  # a netstat that names no process
    (NETSTAT, "netstat: something went wrong\n"),
])
def test_macos_a_table_not_in_the_expected_layout_gives_no_verdict(monkeypatch, output, stderr):
    macos_table(monkeypatch, output, FakeProcess({4242: ("x", [], [Conn(11434, 4242)])}), stderr=stderr)
    assert discover._darwin_holders(11434) is None


def test_macos_a_local_address_without_a_port_separator_gives_no_verdict(monkeypatch):
    macos_table(monkeypatch, NETSTAT.replace("127.0.0.1.11434        *.*                    LISTEN",
                                             "localhost              *.*                    LISTEN"), FakeProcess({}))
    assert discover._darwin_holders(11434) is None


@unix_only
def test_a_homebrew_binary_counts_only_as_the_target_of_its_bin_link(tmp_path, monkeypatch):
    """/opt/homebrew/bin/ollama -> ../Cellar/ollama/<version>/bin/ollama: the kernel reports the Cellar path, and it is
    verified because the link in the install folder leads to it. A Cellar folder of another name is not."""
    installed(tmp_path, monkeypatch)
    cellar = tmp_path / "Cellar" / "ollama" / "0.12.3" / "bin"
    cellar.mkdir(parents=True)
    (cellar / "ollama").write_text("")
    (tmp_path / "bin" / "ollama").unlink()
    os.symlink(cellar / "ollama", tmp_path / "bin" / "ollama")
    table(monkeypatch, {4242}, {4242: str(cellar / "ollama")})
    assert discover.verified_program(URL) == "ollama"
    evil = tmp_path / "Cellar" / "ollama" / "evil" / "bin"
    evil.mkdir(parents=True)
    (evil / "ollama").write_text("")
    table(monkeypatch, {4242}, {4242: str(evil / "ollama")})
    assert discover.verified_program(URL) is None


@unix_only
def test_a_path_is_judged_canonical_not_as_spelled(tmp_path, monkeypatch):
    ollama = installed(tmp_path, monkeypatch)
    attacker = tmp_path / "attacker"
    attacker.mkdir()
    (attacker / "ollama").write_text("")
    table(monkeypatch, {4242}, {4242: str(tmp_path / "bin" / ".." / "attacker" / "ollama")})
    assert discover.verified_program(URL) is None
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    os.symlink(ollama.exe, elsewhere / "ollama")
    table(monkeypatch, {4242}, {4242: str(elsewhere / "ollama")})
    assert discover.verified_program(URL) == "ollama"  # a link into the install folder leads to the installed file


def stat_as(monkeypatch, path: Path, **fields):
    """The real stat, except that path reports the given st_ fields: ownership cannot be arranged without root."""
    real = os.stat

    def fake(p):
        st = real(p)
        if Path(p) != path:
            return st
        values = {k: getattr(st, k) for k in ("st_mode", "st_ino", "st_dev", "st_nlink", "st_uid", "st_gid", "st_size", "st_atime", "st_mtime", "st_ctime")}
        values.update(fields)
        return os.stat_result(tuple(values.values()))

    monkeypatch.setattr(discover, "_stat", fake)


@unix_only
def test_an_executable_owned_by_another_user_is_not_verified(tmp_path, monkeypatch):
    ollama = installed(tmp_path, monkeypatch)
    table(monkeypatch, {4242}, {4242: ollama.exe})
    stat_as(monkeypatch, Path(ollama.exe), st_uid=os.getuid() + 1)
    assert discover.verified_program(URL) is None
    stat_as(monkeypatch, Path(ollama.exe), st_uid=0)
    assert discover.verified_program(URL) == "ollama"


@unix_only
@pytest.mark.parametrize("mode", [0o775, 0o757])
def test_a_folder_above_the_executable_that_others_can_write_is_not_verified(tmp_path, monkeypatch, mode):
    ollama = installed(tmp_path, monkeypatch)
    table(monkeypatch, {4242}, {4242: ollama.exe})
    (tmp_path / "bin").chmod(mode)
    assert discover.verified_program(URL) is None
    (tmp_path / "bin").chmod(0o755)
    assert discover.verified_program(URL) == "ollama"


@unix_only
def test_a_sticky_world_writable_folder_above_is_allowed(tmp_path, monkeypatch):
    """/tmp: anyone may add an entry, but only an entry's owner may remove or rename it, so nothing below can be
    replaced from there."""
    (tmp_path / "sticky").mkdir()
    ollama = installed(tmp_path / "sticky", monkeypatch)
    table(monkeypatch, {4242}, {4242: ollama.exe})
    (tmp_path / "sticky").chmod(0o1777)
    assert discover.verified_program(URL) == "ollama"
    (tmp_path / "sticky").chmod(0o777)
    assert discover.verified_program(URL) is None


@unix_only
def test_on_macos_only_the_admin_group_may_write_the_folders_above(tmp_path, monkeypatch):
    """/Applications and Homebrew's folders are root:admin or <user>:admin and group-writable on every Mac; admin's
    members may run anything as root with sudo, so the group adds no one."""
    ollama = installed(tmp_path, monkeypatch)
    table(monkeypatch, {4242}, {4242: ollama.exe})
    stat_as(monkeypatch, tmp_path / "bin", st_gid=discover.ADMIN_GID, st_mode=0o40775)
    monkeypatch.setattr(sys, "platform", "darwin")
    assert discover.verified_program(URL) == "ollama"
    monkeypatch.setattr(sys, "platform", "linux")
    assert discover.verified_program(URL) is None


@windows_only
def test_windows_a_junction_is_judged_by_the_folder_it_leads_to(tmp_path, monkeypatch):
    ollama = installed(tmp_path, monkeypatch, name="ollama.exe")
    subprocess.run(["cmd", "/c", "mklink", "/J", str(tmp_path / "J"), str(tmp_path / "bin")], check=True, capture_output=True)
    table(monkeypatch, {4242}, {4242: str(tmp_path / "J" / "ollama.exe")})
    assert discover.verified_program(URL) == "ollama"
    stray = tmp_path / "stray"
    stray.mkdir()
    (stray / "ollama.exe").write_text("")
    subprocess.run(["cmd", "/c", "mklink", "/J", str(tmp_path / "bin" / "K"), str(stray)], check=True, capture_output=True)
    table(monkeypatch, {4242}, {4242: str(tmp_path / "bin" / "K" / "ollama.exe")})
    assert discover.verified_program(URL) is None  # spelled under the install folder, kept elsewhere
    assert Path(ollama.exe).is_file()


@windows_only
def test_windows_a_short_name_is_judged_by_its_long_form(tmp_path, monkeypatch):
    import ctypes
    from ctypes import wintypes

    ollama = installed(tmp_path, monkeypatch, name="ollama.exe")
    k32 = ctypes.windll.kernel32
    k32.GetShortPathNameW.argtypes = [wintypes.LPCWSTR, wintypes.LPWSTR, wintypes.DWORD]
    buf = ctypes.create_unicode_buffer(1024)
    if not k32.GetShortPathNameW(ollama.exe, buf, 1024) or buf.value.lower() == ollama.exe.lower():
        pytest.skip("this volume keeps no 8.3 names")
    table(monkeypatch, {4242}, {4242: buf.value})
    assert discover.verified_program(URL) == "ollama"


@pytest.mark.parametrize("url", ["http://127.0.0.1:bad/v1", "http://127.0.0.1:70000/v1", "http://[::1/v1", "http:///v1", "ftp://127.0.0.1:1/v1"])
def test_a_target_url_whose_host_or_port_does_not_parse_is_a_config_error(url):
    with pytest.raises(ConfigError):
        parse_config({"version": 1, "targets": {"t": {"url": url, "model": "m", "location": "local"}}})


def test_verify_target_never_raises():
    t = Target(name="t", url="http://127.0.0.1:bad/v1", model="m", location="local", verify_program="ollama")
    assert discover.verify_target(t) == "no longer served by ollama"


def test_a_repair_interrupted_after_its_newline_still_gets_the_marker(tmp_path):
    """The torn line then ends in a newline, which the last byte alone would call clean."""
    path = tmp_path / "a.jsonl"
    path.write_bytes(b'{"event"\n')
    AuditLog(str(path)).write({"event": "next"})
    lines = path.read_text().splitlines()
    assert lines[0] == '{"event"'
    assert json.loads(lines[1])["event"] == "audit_repaired"
    assert json.loads(lines[2])["event"] == "next" and len(lines) == 3


def test_every_interruption_point_of_a_repair_leaves_the_next_record_whole(tmp_path):
    path = tmp_path / "a.jsonl"
    torn = b'{"event":"attempt","request_id":"a'
    path.write_bytes(torn)
    log = AuditLog(str(path))
    log.write({"event": "b"})
    repair_and_record = path.read_bytes()[len(torn):]
    for cut in range(1, len(repair_and_record)):
        path.write_bytes(torn + repair_and_record[:cut])
        log.write({"event": "c"})
        lines = path.read_bytes().split(b"\n")
        assert lines[-1] == b"" and b"" not in lines[:-1], cut
        assert json.loads(lines[-2])["event"] == "c", cut
        repairs = [x for x in lines[1:-2] if x.startswith(b'{"event":"audit_repaired"') and x.endswith(b"}")]
        assert repairs and lines[0] == torn, cut
