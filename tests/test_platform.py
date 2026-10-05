"""On an unsupported platform the command refuses up front instead of failing on an import."""

from __future__ import annotations

import sys

from endorouter import cli


def test_unsupported_platform_is_refused_with_a_plain_message(monkeypatch, capsys):
    monkeypatch.setattr(sys, "platform", "win32")
    assert cli.main(["serve"]) == 2
    err = capsys.readouterr().err
    assert "macOS and Linux" in err and "win32" in err


def test_supported_platform_reaches_the_parser(monkeypatch, capsys):
    monkeypatch.setattr(sys, "platform", "linux")
    try:
        cli.main([])
    except SystemExit as exc:
        assert exc.code == 2  # argparse: a subcommand is required
    assert "macOS and Linux" not in capsys.readouterr().err
