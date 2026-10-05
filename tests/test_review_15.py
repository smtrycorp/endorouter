"""Windows-branch review, round 3 (Astra, 2026-10-05): the links on the way to an installed executable are judged like
the executable, only Electron's helper names count as an app, a macOS socket row is read whole or not at all, the
audit tail is read whole and judged only where the last line is known to start, and a URL the HTTP client cannot
represent is a configuration error."""

from __future__ import annotations

import os
import sys
from pathlib import Path

from endorouter import discover
from tests.test_discover import URL, installed, table
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
