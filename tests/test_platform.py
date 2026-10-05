"""On an unsupported platform the command refuses up front instead of failing on an import."""

from __future__ import annotations

import sys

import psutil  # noqa: F401  imported before any test fakes sys.platform, which psutil reads to pick its backend
import pytest

from endorouter import cli


def test_unsupported_platform_is_refused_with_a_plain_message(monkeypatch, capsys):
    monkeypatch.setattr(sys, "platform", "cygwin")
    assert cli.main(["serve"]) == 2
    err = capsys.readouterr().err
    assert "macOS, Linux and Windows" in err and "cygwin" in err


@pytest.mark.parametrize("platform", ["linux", "darwin", "win32"])
def test_supported_platform_reaches_the_parser(monkeypatch, capsys, platform):
    monkeypatch.setattr(sys, "platform", platform)
    try:
        cli.main([])
    except SystemExit as exc:
        assert exc.code == 2  # argparse: a subcommand is required
    assert "macOS, Linux and Windows" not in capsys.readouterr().err


def test_doctor_on_windows_points_at_the_folder_not_at_chmod(monkeypatch, capsys, tmp_path):
    import yaml

    conf = tmp_path / "c.yaml"
    conf.write_text(yaml.safe_dump({"version": 1, "audit_log": str(tmp_path / "audit.jsonl"), "targets": {
        "l": {"url": "http://127.0.0.1:9/v1", "model": "m", "location": "local"}}}))
    monkeypatch.setattr(sys, "platform", "win32")
    cli.main(["doctor", "-c", str(conf)])
    out = capsys.readouterr().out
    assert "audit log: writable" in out and "folder" in out and "chmod" not in out
