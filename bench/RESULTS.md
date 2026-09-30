# leakbench results, 2026-09-30

29 cases: 24 private, 5 public. Every result is measured at the recording sinks.

## Summary

| Gateway | Private cases that reached the cloud | Public cases kept off the cloud |
|---|---|---|
| sovereign-router 0.1, strict, with provenance headers | 0 of 24 | 3 of 5 |
| sovereign-router 0.1, strict, no provenance headers | 0 of 24 | 5 of 5 |
| sovereign-router 0.1, balanced, local 30B classifier | 0 of 24 | 0 of 5 |
| LiteLLM 1.103.1, content filter on every request | 13 of 24 | 0 of 5 |
| Pass-through control (cloud declared local) | 24 of 24 | 0 of 5 |

All five runs are valid. In each, the calibration request reached a sink, every case reached a sink or was refused, and every answer came from a recording sink. All 11 LiteLLM refusals were its content filter reporting a matched pattern, and the reports keep each refusal message.

## By category

Each cell shows private cases leaked, or public cases kept off the cloud, out of the category total.

| Category | Cases | sovereign-router | sovereign-router, no provenance | LiteLLM | Control |
|---|---|---|---|---|---|
| secret_latest | 4 | 0 | 0 | 0 | 4 |
| secret_format | 3 | 0 | 0 | 3 | 3 |
| secret_split | 1 | 0 | 0 | 1 | 1 |
| secret_in_history | 1 | 0 | 0 | 0 | 1 |
| secret_in_tool_call | 1 | 0 | 0 | 0 | 1 |
| secret_in_tool_result | 1 | 0 | 0 | 0 | 1 |
| personal_data | 4 | 0 | 0 | 0 | 4 |
| private_source | 2 | 0 | 0 | 2 | 2 |
| mixed_sources | 1 | 0 | 0 | 1 | 1 |
| declared_private | 1 | 0 | 0 | 1 | 1 |
| unlabeled_confidential | 5 | 0 | 0 | 5 | 5 |
| public_labeled (kept off cloud) | 2 | 0 | 2 | 0 | 0 |
| public_unlabeled (kept off cloud) | 3 | 3 | 3 | 0 | 0 |

## Reading this fairly

- **The trade is the design.** sovereign-router leaks nothing because unlabelled work stays local. The cost is that unlabelled public work stays local too: 3 of 5 public cases with provenance, 5 of 5 without. LiteLLM sends every public case to the cloud and leaks what its patterns miss.
- **LiteLLM scans the whole conversation.** It caught a recognised key in history, in tool arguments and in tool results. Its misses were key formats it has no pattern for, a key split with a zero-width space, and confidential prose.
- **The provenance cases are structural, not a detector contest.** LiteLLM has no way to receive a source path or a private declaration. Those 4 of its 13 leaks show that gap.
- **Five cases are confidential prose with no secret format in them.** No pattern list can catch these. Only a default-local policy or a classifier can.
- **This is our own suite.** It is small and it was written by the authors of one of the gateways under test. The cases are in `src/sovereign_router/leakbench/cases.jsonl`, and we welcome cases that make any gateway look worse, including ours.

## Balanced mode

In balanced mode, unlabelled work may go to the cloud when no detector fires and a local model classifies it as public. For this run the classifier was a 30B open-weight model, quantised to 4 bits, running on the same laptop (an M2 Max with 64 GB). Its verdicts, taken from the audit log:

| Classifier verdict | Requests |
|---|---|
| Private, so kept local | 22 |
| Public, so cleared for the cloud | 4 (the 3 unlabelled public questions and the calibration request) |
| No usable verdict | 0 |

It classified all 5 confidential prose cases as private. That removes the over-restriction cost of strict mode on this suite.

The cost is latency. The run averaged about 9.5 seconds per request on that machine, because every unlabelled request waits for the classifier. The confidential cases here are also fairly plain. A harder suite, with subtle confidential text and public text that mentions confidentiality, is the next thing to build before claiming more.

## How LiteLLM was configured

LiteLLM's documentation describes a `sensitive_data_routing` guardrail that reroutes sensitive requests to an on-premise model. That guardrail type was not in 1.103.1, the latest release on PyPI when we tested. We used its built-in `litellm_content_filter` instead, with the following settings:

- every data-relevant prebuilt pattern;
- the keywords from the routing documentation;
- `on_sensitive_data: route`, pointed at the on-premise model;
- a session id on every request.

In this release that filter blocked on detection with HTTP 400 and did not reroute. leakbench counts a block as safe, so this choice favours LiteLLM on leak rate. The full config is in `litellm-leakbench.yaml`.

## Reproduce

```
python -m venv bench/.litellm-venv
bench/.litellm-venv/bin/pip install "litellm[proxy]==1.103.1"
bench/.litellm-venv/bin/litellm --config bench/litellm-leakbench.yaml --host 127.0.0.1 --port 8796
sovereign-router leakbench --base-url http://127.0.0.1:8796/v1 --no-provenance --model cloud-model --extra-body '{"metadata":{"session_id":"lb-{id}"}}'

sovereign-router serve -c bench/leakbench-strict.yaml --port 8797
sovereign-router leakbench --base-url http://127.0.0.1:8797/v1
sovereign-router leakbench --base-url http://127.0.0.1:8797/v1 --no-provenance

python bench/local_shim.py 8801     # or point the classifier target at any OpenAI-compatible local server
sovereign-router serve -c bench/leakbench-balanced.yaml --port 8795
sovereign-router leakbench --base-url http://127.0.0.1:8795/v1

sovereign-router serve -c bench/leakbench-passthrough.yaml --port 8798
sovereign-router leakbench --base-url http://127.0.0.1:8798/v1
```

Raw outputs are the `result-*.json` files in this directory.
