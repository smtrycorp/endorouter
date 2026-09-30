"""Invariants of the policy, the detectors and the config. Each test names the guarantee it pins."""

from __future__ import annotations

import pytest

from sovereign_router import ConfigError, Label, decide
from sovereign_router.config import parse_config
from sovereign_router.detectors import scan_request, scan_text


def cfg(mode="strict", classifier=False, **prov):
    raw = {
        "version": 1,
        "mode": mode,
        "targets": {
            "local": {"url": "http://127.0.0.1:11434/v1", "model": "m", "location": "local", "capabilities": ["chat"]},
            "cloud": {"url": "https://api.example.com/v1", "model": "c", "location": "cloud", "capabilities": ["chat", "reasoning"]},
        },
        "provenance": {"public_sources": ["docs/public/**"], "private_sources": ["**/.env*", ".env*", "clients/**"], **prov},
    }
    if classifier:
        raw["classifier"] = {"enabled": True, "target": "local"}
    return parse_config(raw)


# ── invariant 1: private or unknown never selects an external target (strict) ──────────────────────────────


def test_no_provenance_is_unknown_and_local_only():
    d = decide(cfg())
    assert d.label is Label.UNKNOWN and d.permitted == ("local",) and d.selected == "local"


def test_declared_public_may_use_cloud():
    d = decide(cfg(), declared=Label.PUBLIC)
    assert d.label is Label.PUBLIC and "cloud" in d.permitted


def test_explicitly_requesting_cloud_for_unknown_is_refused():
    d = decide(cfg(), requested_model="cloud")
    assert d.selected is None and "not permitted" in d.error


# ── invariant 2: labels combine to the most restrictive ─────────────────────────────────────────────────────


@pytest.mark.parametrize("sources,expected", [
    (["docs/public/a.md"], Label.PUBLIC),
    (["docs/public/a.md", "clients/acme/x.md"], Label.PRIVATE),
    (["docs/public/a.md", "notes/todo.md"], Label.UNKNOWN),
    (["docs/public/.env"], Label.PRIVATE),  # private wins over public for the same source
])
def test_sources_combine_most_restrictive(sources, expected):
    assert decide(cfg(), sources=sources).label is expected


def test_public_label_cannot_lift_a_private_source():
    d = decide(cfg(), sources=["clients/acme/brief.md"], declared=Label.PUBLIC)
    assert d.label is Label.PRIVATE and d.permitted == ("local",)


def test_findings_make_public_private():
    findings = scan_request({"messages": [{"role": "user", "content": "key AKIAIOSFODNN7EXAMPLE"}]})
    d = decide(cfg(), declared=Label.PUBLIC, findings=findings)
    assert d.label is Label.PRIVATE and "detector:aws_access_key" in d.reasons


# ── invariant 3: the classifier tightens, never loosens (and only balanced mode lets it clear UNKNOWN) ──────


def test_classifier_public_does_not_clear_in_strict_mode():
    assert decide(cfg(), classifier_verdict=Label.PUBLIC).permitted == ("local",)


def test_classifier_can_clear_unknown_only_in_balanced_mode_and_it_is_recorded():
    d = decide(cfg("balanced", classifier=True), classifier_verdict=Label.PUBLIC)
    assert "cloud" in d.permitted and d.cleared_by_classifier and "cleared_by_classifier" in d.reasons


def test_classifier_cannot_clear_findings_or_private_sources():
    findings = scan_request({"messages": [{"role": "user", "content": "4242 4242 4242 4242"}]})
    c = cfg("balanced", classifier=True)
    assert decide(c, findings=findings, classifier_verdict=Label.PUBLIC).permitted == ("local",)
    assert decide(c, sources=["clients/a.md"], classifier_verdict=Label.PUBLIC).permitted == ("local",)


def test_classifier_failure_grants_nothing():
    assert decide(cfg("balanced", classifier=True), classifier_verdict=None).permitted == ("local",)


def test_classifier_private_tightens_public():
    d = decide(cfg(), declared=Label.PUBLIC, classifier_verdict=Label.PRIVATE)
    assert d.label is Label.PRIVATE and d.permitted == ("local",)


# ── detectors see everything, recognise formats, and resist trivial evasion ─────────────────────────────────


def test_detectors_see_history_tool_calls_tool_results_and_tools():
    body = {
        "messages": [
            {"role": "user", "content": "old: ghp_a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"},
            {"role": "assistant", "content": None, "tool_calls": [{"id": "1", "type": "function",
             "function": {"name": "f", "arguments": "{\"k\": \"sk_live_51HxAbCdEfGhIjKlMnOp\"}"}}]},
            {"role": "tool", "tool_call_id": "1", "content": "xoxb-2231-9981-AbCdEfGhIjKl"},
            {"role": "user", "content": "anything"},
        ],
        "tools": [{"type": "function", "function": {"name": "t", "description": "uses AKIAIOSFODNN7EXAMPLE"}}],
    }
    rules = {f.rule for f in scan_request(body)}
    assert {"github_token", "stripe_key", "slack_token", "aws_access_key"} <= rules


def test_zero_width_split_secret_is_found():
    assert any(f.rule == "aws_access_key" for f in scan_text("AKIA​IOSFODNN7EXAMPLE", "x"))


def test_card_needs_luhn():
    assert any(f.rule == "payment_card" for f in scan_text("4242 4242 4242 4242", "x"))
    assert not any(f.rule == "payment_card" for f in scan_text("4242 4242 4242 4241", "x"))


def test_plain_prose_has_no_findings():
    assert scan_text("How do I reverse a list in Python? Summarise Moby-Dick.", "x") == [] or \
        list(scan_text("How do I reverse a list in Python? Summarise Moby-Dick.", "x")) == []


# ── config: typos are errors; a local target is mandatory; the classifier must be local ─────────────────────


def test_unknown_field_is_an_error():
    with pytest.raises(ConfigError, match="unknown field"):
        parse_config({"version": 1, "targets": {"l": {"url": "http://127.0.0.1/v1", "model": "m", "location": "local"}}, "mdoe": "x"})


def test_local_target_required():
    with pytest.raises(ConfigError, match="local target"):
        parse_config({"version": 1, "targets": {"c": {"url": "https://x/v1", "model": "m", "location": "cloud"}}})


def test_classifier_must_be_local_and_balanced_needs_it():
    raw = {"version": 1, "mode": "balanced", "targets": {
        "l": {"url": "http://127.0.0.1/v1", "model": "m", "location": "local"},
        "c": {"url": "https://x/v1", "model": "m", "location": "cloud"}}}
    with pytest.raises(ConfigError, match="balanced"):
        parse_config(raw)
    with pytest.raises(ConfigError, match="classifier.target"):
        parse_config({**raw, "classifier": {"enabled": True, "target": "c"}})


def test_capability_filters_targets():
    d = decide(cfg(), declared=Label.PUBLIC, capability="reasoning")
    assert d.permitted == ("cloud",)
    d = decide(cfg(), capability="reasoning")  # unknown + capability only a cloud target has: refuse, never leak
    assert d.selected is None


def test_phone_rule_ignores_digit_runs_inside_tokens():
    rules = {f.rule for f in scan_text("xoxb-1234567890123-1234567890123-AbCdEfGhIjKlMnOpQrStUvWx", "x")}
    assert "slack_token" in rules and "phone_number" not in rules
    assert any(f.rule == "phone_number" for f in scan_text("call me on +1 415 555 0132 tomorrow", "x"))


def test_every_forwarded_field_is_scanned_including_keys_and_json_in_strings():
    body = {
        "model": "auto",
        "messages": [{"role": "user", "content": "hi"}],
        "stop": ["AKIAIOSFODNN7EXAMPLE"],
        "response_format": {"type": "json_schema", "json_schema": {"name": "x", "schema": {"properties": {
            "ghp_a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8": {"type": "string"}}}}},
    }
    rules = {f.rule for f in scan_request(body)}
    assert {"aws_access_key", "github_token"} <= rules


def test_json_escaped_secret_in_tool_arguments_is_found():
    args = '{"k": "\\u0041KIAIOSFODNN7EXAMPLE"}'
    body = {"messages": [{"role": "assistant", "content": None, "tool_calls": [
        {"id": "1", "type": "function", "function": {"name": "f", "arguments": args}}]}]}
    assert any(f.rule == "aws_access_key" for f in scan_request(body))


def test_large_adversarial_input_scans_in_linear_time():
    import time

    t0 = time.monotonic()
    for text in ("xoxb-" + "a-" * 100_000, "a:" * 100_000, "a@" * 100_000, "-----BEGIN " * 20_000):
        list(scan_text(text, "x"))
    assert time.monotonic() - t0 < 3  # was 36 s for the first input alone before quantifiers were bounded
