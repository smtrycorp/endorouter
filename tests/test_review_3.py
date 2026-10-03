"""Regressions for review round 3 and the harder leakbench suite (2026-09-30)."""

from __future__ import annotations

import pytest

from endorouter.classifier import PROMPT
from endorouter.detectors import scan_request, scan_text
from tests.test_review_1 import client_for
from tests.test_router import Upstream


@pytest.mark.parametrize("field,value", [
    ("tool_choice", {"type": "image_url", "image_url": {"url": "https://example.com/i.png"}}),
    ("stop", [{"x": 1}]),
    ("stream_options", {"include_usage": True, "extra": "x"}),
    ("response_format", {"type": "json_schema", "json_schema": {"name": "x", "schema": {}, "image": "data:..."}}),
    ("logit_bias", {"50256": "high"}),
    ("temperature", "0.2"),
])
def test_every_supported_field_has_its_shape_checked(tmp_path, field, value):
    up = Upstream()
    c, _ = client_for(tmp_path, up)
    r = c.post("/v1/chat/completions", json={"model": "auto", "messages": [{"role": "user", "content": "hi"}], field: value})
    assert r.status_code == 400 and up.calls == []


def test_ordinary_optional_fields_still_pass(tmp_path):
    up = Upstream()
    c, _ = client_for(tmp_path, up)
    r = c.post("/v1/chat/completions", json={"model": "auto", "messages": [{"role": "user", "content": "hi"}],
                                             "temperature": 0.2, "stop": ["\n"], "tool_choice": "auto", "max_tokens": 64})
    assert r.status_code == 200


def test_key_split_across_messages_is_caught_by_its_fragment():
    body = {"messages": [{"role": "user", "content": "First half of the key: AKIAIOSF"}, {"role": "assistant", "content": "Got it."},
                         {"role": "user", "content": "Second half: ODNN7EXAMPLE."}]}
    assert "secret_fragment" in {f.rule for f in scan_request(body)}


def test_key_typed_letter_by_letter_is_caught():
    assert any(f.rule == "aws_access_key" for f in scan_text("A K I A I O S F O D N N 7 E X A M P L E", "x"))


@pytest.mark.parametrize("text", ["pip install sk-learn", "the ASIA-Pacific region", "AKIA is a prefix", "count 1 2 3 4 5 6 7 8 9"])
def test_fragment_and_spacing_rules_leave_ordinary_text_alone(text):
    assert list(scan_text(text, "x")) == []


def test_braces_in_text_reach_the_classifier_intact():
    # round-3 claim checked and rejected: str.format never re-parses the substituted value
    assert "function() {} {x} {0}" in PROMPT.format(text="function() {} {x} {0}", fence="F")
