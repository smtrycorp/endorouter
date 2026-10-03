"""The vendor-agnostic secret-shape rule: keys from vendors no pattern names are found; ordinary technical text is not."""

from __future__ import annotations

import pytest

from endorouter.detectors import scan_text


def rules(t):
    return {f.rule for f in scan_text(t, "x")}


@pytest.mark.parametrize("text", [
    "export NIMBUS_KEY=nmb_sk_R7tY3wB6zq4f9KxP2mQ8vL1n",
    "Authorization: Bearer 7Hq2Lr9Xw4Pz8Kv1Nm6Bt3Yc5Df0Gs",
    '{"apiKey": "lmn.Zt8Qw3Er6Ty9Ui2Op5As1Df4Gh7"}',
    "use Tx9pL2mQ8vK4nR7wZ3yB6cD1 for staging",
    "SERVICE_TOKEN=9c1e4a7b2d5f8e0c3b6a9d2f5e8c1b4a",   # bare hex where a credential is placed
    "zq_live_9c1e4a7b2d5f8e0c3b6a9d2f5e8c1b4a",          # vendor-style prefix glued to hex
])
def test_unknown_vendor_keys_are_found(text):
    assert "secret_shape" in rules(text)


@pytest.mark.parametrize("text", [
    "commit 9c1e4a7b2d5f8e0c3b6a9d2f5e8c1b4a7d0e3f6a fixed it",           # git SHA in prose
    '"integrity": "sha512-4U2JKLMWlDu0CotYyUkWakDxr8AIav3QtIUXXnHtAr+uTkt9m"',  # lockfile digest
    "id 1234abcd-12ab-34cd-56ef-1234567890ab",                           # UUID
    "class TwelveLabsMarengo3AudioRequest(BaseModel):",                 # identifier
    "pi = 3.14159265358979311599796346854418516159",                    # number
    "see src/endorouter/leakbench/runner.py",                     # path
    "model Qwen3-235B-A22B-Instruct-2507 is large",                     # model name
])
def test_ordinary_technical_text_is_left_alone(text):
    assert "secret_shape" not in rules(text)
