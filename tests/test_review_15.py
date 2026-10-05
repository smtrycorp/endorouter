"""Windows-branch review, round 3 (Astra, 2026-10-05): the links on the way to an installed executable are judged like
the executable, only Electron's helper names count as an app, a macOS socket row is read whole or not at all, the
audit tail is read whole and judged only where the last line is known to start, and a URL the HTTP client cannot
represent is a configuration error."""

from __future__ import annotations

import os
import sys
from pathlib import Path, PurePosixPath, PureWindowsPath

import psutil
import pytest

from endorouter import discover
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
