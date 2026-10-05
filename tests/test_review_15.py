"""Windows-branch review, round 3 (Astra, 2026-10-05): the links on the way to an installed executable are judged like
the executable, only Electron's helper names count as an app, a macOS socket row is read whole or not at all, the
audit tail is read whole and judged only where the last line is known to start, and a URL the HTTP client cannot
represent is a configuration error."""

from __future__ import annotations

import asyncio
import json
import os
import sys
from pathlib import Path, PurePosixPath, PureWindowsPath

import httpx
import psutil
import pytest
from starlette.testclient import TestClient

from endorouter import audit, discover
from endorouter.audit import TAIL, AuditLog
from endorouter.config import Config, ConfigError, Target, parse_config
from endorouter.router import Router, UpstreamFailed
from endorouter.server import create_app
from tests.test_discover import (
    LOCALAPPDATA,
    NETSTAT,
    URL,
    WINDOWS_INSTALLS,
    Conn,
    FakeProcess,
    installed,
    macos_table,
    table,
)
from tests.test_review_14 import stat_as, unix_only


def owned_by(monkeypatch, uid: int, *paths: Path):
    """The real stat and lstat, except that these paths report the uid: ownership cannot be arranged without root."""
    real_stat, real_lstat = os.stat, os.lstat

    def as_uid(call):
        def fake(p):
            st = call(p)
            if Path(p) not in paths:
                return st
            values = list(st)
            values[4] = uid  # st_uid's place in the tuple
            return os.stat_result(values)
        return fake

    monkeypatch.setattr(discover, "_stat", as_uid(real_stat))
    monkeypatch.setattr(discover, "_lstat", as_uid(real_lstat))


@unix_only
def test_every_link_on_the_way_to_an_installed_file_must_be_as_protected_as_the_file(tmp_path, monkeypatch):
    """/opt/homebrew/bin/ollama -> /tmp/route/ollama -> ~/Downloads/ollama, with the route folder and its link owned by
    another user: the destination passes every check of its own, but that user chose it."""
    installed(tmp_path, monkeypatch)
    (tmp_path / "bin" / "ollama").unlink()
    route, downloads = tmp_path / "route", tmp_path / "Downloads"
    route.mkdir()
    downloads.mkdir()
    (downloads / "ollama").write_text("")
    (downloads / "ollama").chmod(0o755)
    os.symlink(downloads / "ollama", route / "ollama")
    os.symlink(route / "ollama", tmp_path / "bin" / "ollama")
    table(monkeypatch, {4242}, {4242: str(downloads / "ollama")})
    assert discover.verified_program(URL) == "ollama"
    for theirs in ([route, route / "ollama"], [route / "ollama"], [route], [tmp_path / "bin" / "ollama"]):
        owned_by(monkeypatch, os.getuid() + 1, *theirs)
        assert discover.verified_program(URL) is None, theirs


@unix_only
def test_a_folder_on_the_way_that_others_can_write_is_not_trusted_even_when_the_destination_is(tmp_path, monkeypatch):
    """The link sits in a folder that is not above the destination, so only the chain's own check can see it."""
    installed(tmp_path, monkeypatch)
    (tmp_path / "bin" / "ollama").unlink()
    hop, dest = tmp_path / "hop", tmp_path / "dest"
    hop.mkdir()
    dest.mkdir()
    (dest / "ollama").write_text("")
    (dest / "ollama").chmod(0o755)
    os.symlink(dest / "ollama", hop / "ollama")
    os.symlink(hop / "ollama", tmp_path / "bin" / "ollama")
    table(monkeypatch, {4242}, {4242: str(dest / "ollama")})
    assert discover.verified_program(URL) == "ollama"
    hop.chmod(0o777)  # anyone may now point the link elsewhere
    assert discover.verified_program(URL) is None
    hop.chmod(0o1777)  # sticky: only the link's owner may, as in /tmp
    assert discover.verified_program(URL) == "ollama"


@unix_only
def test_on_macos_the_admin_group_may_write_a_folder_above_but_not_the_executable(tmp_path, monkeypatch):
    """A file with the group bit set for admin is written by any admin account's process, elevated or not."""
    ollama = installed(tmp_path, monkeypatch)
    table(monkeypatch, {4242}, {4242: ollama.exe})
    monkeypatch.setattr(sys, "platform", "darwin")
    stat_as(monkeypatch, Path(ollama.exe), st_gid=discover.ADMIN_GID, st_mode=0o100775)
    assert discover.verified_program(URL) is None
    stat_as(monkeypatch, Path(ollama.exe), st_gid=discover.ADMIN_GID, st_mode=0o100755)
    assert discover.verified_program(URL) == "ollama"


HELPERS = "/Applications/LM Studio.app/Contents/Frameworks/{0}.app/Contents/MacOS/{0}"


@pytest.mark.parametrize("name,expected", [
    ("LM Studio Helper", "lm studio"),
    ("LM Studio Helper (Renderer)", "lm studio"),
    ("LM Studio Helper (GPU)", "lm studio"),
    ("LM Studio Helper (Plugin)", "lm studio"),
    ("LM Studio Helpermalware", None),
    ("LM Studio Helper (Malware)", None),
    ("LM Studio Helper.bak", None),
    ("LM Studio Helper (GPU) ", None),
])
def test_only_electrons_own_helper_names_count_as_the_app(monkeypatch, name, expected):
    monkeypatch.setattr(discover, "_HostPath", PurePosixPath)
    monkeypatch.setattr(discover, "_INSTALLS", discover.INSTALLS["darwin"])
    assert discover._installed(HELPERS.format(name)) == expected


def test_a_windows_helper_name_with_anything_after_helper_is_not_the_app(monkeypatch):
    monkeypatch.setattr(discover, "_HostPath", PureWindowsPath)
    monkeypatch.setattr(discover, "_INSTALLS", WINDOWS_INSTALLS)
    assert discover._installed(LOCALAPPDATA + r"\Programs\Jan\Jan Helpermalware.exe") is None
    assert discover._installed(LOCALAPPDATA + r"\Programs\Jan\Jan Helper.exe") == "jan"


OLLAMA_ROW = "tcp4       0      0  127.0.0.1.11434        *.*                    LISTEN                 0            0  131072  131072           ollama:4242   00000 00000006 000000000246b336 00000000 00000800      1      0 000000\n"
# Astra's row: the name is "x:4242 ", the pid 1411, and the last counter is missing, so counting eight trailing tokens
# takes ":1411" for a counter and 4242 for the pid
ASTRA_ROW = "tcp6 0 0 ::1.11434 *.* LISTEN 0 0 131072 131072 x:4242 :1411 00000 00000006 000000000245e65a 00000000 00000800 1 0\n"


def with_row(row: str) -> str:
    return NETSTAT.replace(OLLAMA_ROW, OLLAMA_ROW + row)


@pytest.mark.parametrize("row", [
    ASTRA_ROW,
    ASTRA_ROW.replace(" 1 0\n", " 1 0 000000\n").replace("x:4242 :1411", "x:4242 1411"),  # no colon before the pid
    ASTRA_ROW.replace("x:4242 :1411", ":1411 00000"),  # an empty name
    OLLAMA_ROW.replace("      1      0 000000\n", "      1      0\n"),  # a counter short
    OLLAMA_ROW.replace("ollama:4242   00000", "ollama:4242   0000g"),  # a counter that is not a number
    OLLAMA_ROW.replace("*.*                    LISTEN", "LISTEN"),  # the state column shifted left
    OLLAMA_ROW.replace("*.*                    LISTEN", "*.*   extra   LISTEN"),  # and right
    OLLAMA_ROW.replace("LISTEN                 0            0", "LISTEN                 0"),  # a middle counter short
    "tcp4       0      0  127.0.0.1.11434\n",
])
def test_macos_a_row_on_the_port_the_parse_cannot_read_whole_gives_no_verdict(monkeypatch, row):
    """Every row on the port must be in the layout the header promised; one that is not is no verdict for the whole
    port, never a skipped row, since the readable processes would then stand in for it."""
    macos_table(monkeypatch, with_row(row), FakeProcess({4242: ("x", [], [Conn(11434, 4242)]), 1411: ("x", [], psutil.AccessDenied(1411))}))
    assert discover._darwin_holders(11434) is None
    macos_table(monkeypatch, with_row(ASTRA_ROW.replace(" 1 0\n", " 1 0 000000\n")), FakeProcess({}))
    assert discover._darwin_holders(11434) == {4242, 1411}, "the same row with its eighth counter names both pids"


def test_macos_a_malformed_row_on_another_port_does_not_cost_the_verdict(monkeypatch):
    macos_table(monkeypatch, with_row(ASTRA_ROW.replace("::1.11434", "::1.9999")), FakeProcess({}))
    assert discover._darwin_holders(11434) == {4242, 1411}


def test_a_short_read_of_the_tail_does_not_pass_a_torn_line_as_clean(tmp_path, monkeypatch):
    """os.read may return fewer bytes than asked. Three at a time here: the first read ends at the newline after the
    whole record, and judging that alone merged the torn line with the next record."""
    path = tmp_path / "a.jsonl"
    path.write_bytes(b'{}\n{"event"')
    real = os.read
    monkeypatch.setattr(audit.os, "read", lambda fd, n: real(fd, min(n, 3)))
    AuditLog(str(path)).write({"event": "next"})
    lines = path.read_bytes().split(b"\n")
    assert lines[:2] == [b"{}", b'{"event"']
    assert json.loads(lines[2])["event"] == "audit_repaired"
    assert json.loads(lines[3])["event"] == "next" and lines[4:] == [b""]


def test_the_last_line_is_judged_only_where_its_start_is_in_the_window(tmp_path):
    """Astra's payload: a last line that is not a record, whose tail-window suffix is one, followed by a blank line.
    The blank line satisfied the old check for a newline somewhere in the window."""
    path = tmp_path / "a.jsonl"
    payload = b"not-json:" + b'{"x":"' + b"x" * (TAIL - 10) + b'"}\n\n'
    path.write_bytes(payload)
    AuditLog(str(path)).write({"event": "next"})
    lines = path.read_bytes().split(b"\n")
    assert lines[0] == payload[:-2] and lines[1] == b""
    assert json.loads(lines[2])["event"] == "audit_repaired"
    assert json.loads(lines[3])["event"] == "next" and lines[4:] == [b""]


def test_a_record_longer_than_the_window_gets_the_repair_and_a_whole_file_in_the_window_does_not(tmp_path):
    path = tmp_path / "a.jsonl"
    path.write_bytes(json.dumps({"pad": "x" * TAIL}).encode() + b"\n")
    AuditLog(str(path)).write({"event": "next"})
    assert [json.loads(x)["event"] for x in path.read_bytes().split(b"\n")[1:3]] == ["audit_repaired", "next"]
    path.write_bytes(json.dumps({"pad": "x" * (TAIL - 100)}).encode() + b"\n")
    AuditLog(str(path)).write({"event": "next"})
    assert [json.loads(x).get("event") for x in path.read_bytes().split(b"\n")[:2]] == [None, "next"]


BAD_URLS = ["http://127.0.0.1:11434/v1\n", "http://127.0.0.1:11434/v\x001", "http://[v1.fe80::a]:11434/v1"]


@pytest.mark.parametrize("url", BAD_URLS)
def test_a_url_the_http_client_cannot_represent_is_a_config_error(url):
    """urlsplit took these; httpx raised InvalidURL at dispatch, which was a 500 with nothing sent."""
    with pytest.raises(ConfigError):
        parse_config({"version": 1, "targets": {"t": {"url": url, "model": "m", "location": "local"}}})


@pytest.mark.parametrize("url", BAD_URLS)
def test_a_target_url_the_client_refuses_at_dispatch_is_a_failed_target_not_a_crash(tmp_path, url):
    """A Config built in code is not parsed, so dispatch still meets such a URL: the target fails like one that is down,
    and the HTTP caller is told every permitted target failed."""
    cfg = Config(targets=(Target(name="t", url=url, model="m", location="local"),), audit_log=str(tmp_path / "a.jsonl"))
    client = httpx.AsyncClient(transport=httpx.MockTransport(lambda req: httpx.Response(200, json={})), trust_env=False)
    router = Router(cfg, client=client)
    body = {"model": "auto", "messages": [{"role": "user", "content": "hi"}]}
    with pytest.raises(UpstreamFailed) as e:
        asyncio.run(router.route(body))
    assert e.value.attempts == [{"target": "t", "error": "InvalidURL", "ms": e.value.attempts[0]["ms"]}]
    c = TestClient(create_app(cfg, router), base_url="http://127.0.0.1", client=("127.0.0.1", 5000))
    r = c.post("/v1/chat/completions", json=body)
    assert r.status_code == 502 and r.json()["error"]["attempts"][0]["error"] == "InvalidURL"


def test_macos_an_unbound_socket_row_is_not_a_malformed_one(monkeypatch):
    """netstat -a lists CLOSED sockets with the wildcard port; they hold no port and cost nothing."""
    closed = "tcp4 0 0 *.* *.* CLOSED 0 0 131072 131072 unrelated:99 00000 00000000 000000000245e65a 00000000 00000000 1 0 000000\n"
    macos_table(monkeypatch, with_row(closed), FakeProcess({4242: ("x", [], [Conn(11434, 4242)])}))
    assert discover._darwin_holders(11434) == {4242, 1411}  # the table's two listeners, the CLOSED row ignored


@pytest.mark.skipif(sys.platform == "win32", reason="the component walk runs on Unix; Windows uses realpath")
@pytest.mark.skipif(not os.path.isfile("/usr/bin/true"), reason="needs a regular file at a fixed path")
@pytest.mark.parametrize("path", ["/usr/bin/true/../false", "/usr/bin/true/", "/usr/bin/true/."])
def test_a_path_through_a_file_leads_nowhere(path):
    assert discover._leads_to(path) is None


@pytest.mark.skipif(sys.platform == "win32", reason="the component walk runs on Unix; Windows uses realpath")
def test_a_link_that_cannot_be_read_leads_nowhere(tmp_path, monkeypatch):
    target = tmp_path / "ollama"
    target.write_text("")
    link = tmp_path / "entry"
    link.symlink_to(target)
    assert discover._leads_to(str(link)) == os.path.realpath(target), "the walk must reach readlink at all"
    real = os.readlink

    def gone(p, *a, **k):
        if str(p) == str(link):
            raise FileNotFoundError(p)
        return real(p, *a, **k)

    monkeypatch.setattr(os, "readlink", gone)
    assert discover._leads_to(str(link)) is None
