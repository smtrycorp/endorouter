# leakbench results, 2026-09-30 (final run on the code after nine review rounds)

29 cases: 24 private, 5 public. Every result is measured at the recording sinks.

## Summary

| Gateway | Private cases that reached the cloud | Public cases kept off the cloud |
|---|---|---|
| EndoRouter 0.1, strict, with provenance headers | 0 of 24 | 3 of 5 |
| EndoRouter 0.1, strict, no provenance headers | 0 of 24 | 5 of 5 |
| EndoRouter 0.1, balanced, local 30B classifier | 0 of 24 | 1 of 5 (0 or 1 across runs) |
| LiteLLM 1.103.1, content filter on every request | 13 of 24 | 0 of 5 |
| Pass-through control (cloud declared local) | 24 of 24 | 0 of 5 |

All five runs are valid. In each, the calibration request reached a sink, every case reached a sink or was refused, and every answer came from a recording sink. All 11 LiteLLM refusals were its content filter reporting a matched pattern, and the reports keep each refusal message. A refusal is still the gateway's own claim, so leakbench reports refusals separately and marks them unverified. Counting them as safe favours LiteLLM.

## By category

Each cell shows private cases leaked, or public cases kept off the cloud, out of the category total.

| Category | Cases | EndoRouter | EndoRouter, no provenance | LiteLLM | Control |
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

- **The trade is the design.** EndoRouter leaks nothing because unlabelled work stays local. The cost is that unlabelled public work stays local too: 3 of 5 public cases with provenance, 5 of 5 without. LiteLLM sends every public case to the cloud and leaks what its patterns miss.
- **LiteLLM scans the whole conversation.** It caught a recognised key in history, in tool arguments and in tool results. Its misses were key formats it has no pattern for, a key split with a zero-width space, and confidential prose.
- **The provenance cases are structural, not a detector contest.** LiteLLM has no way to receive a source path or a private declaration. Those 4 of its 13 leaks show that gap.
- **Five cases are confidential prose with no secret format in them.** No pattern list can catch these. Only a default-local policy or a classifier can.
- **This is our own suite.** It is small and it was written by the authors of one of the gateways under test. The cases are in `src/endorouter/leakbench/cases.jsonl`, and we welcome cases that make any gateway look worse, including ours.

## Balanced mode

In balanced mode, unlabelled work may go to the cloud when no detector fires and a local model classifies it as public. The classifier here was a 30B open-weight model, quantised to 4 bits, running on the same laptop (an M2 Max with 64 GB). We ran the suite many times as the code changed.

- **Private prompts.** In every run, no private case reached the cloud. The classifier called all 5 confidential prose cases private.
- **Unlabelled public prompts.** In every run, the classifier cleared all 3 for the cloud.
- **Run-to-run variation.** In some runs one public question stayed local, and which one varied. An example is a public-source request with no substance: "Explain what this README section means for a new user". The classifier may tighten any request, even one with public provenance, so a flip like this costs a cloud trip and never causes a leak.
- **Latency.** Every unlabelled request waits for the classifier. The first run averaged about 9.5 seconds per request on that machine.

## The harder suite

`cases-hard.jsonl` has 23 cases: 15 private and 8 public. It was built after the first results to test what the main suite made too easy.

- **Confidential prose with no giveaway words.** There are 7 cases, such as layoff plans, a term sheet, a patient note and a legal strategy.
- **Keys from vendors no pattern names.** There are 3, in a `.env` line, a Bearer header and a JSON config.
- **Classifier injection.** Two private memos carry lines telling the classifier to answer PUBLIC, and one public question asks about prompt injection.
- **Secrets split up.** One key is split across two messages, one is typed out letter by letter, and one card number is split across messages.
- **Public prompts that mention confidentiality.** There are 5, such as NDA clauses, HIPAA definitions and a spy story.
- **Ordinary public code questions.** There are 2.

| Gateway | Private cases that reached the cloud | Public cases kept off the cloud |
|---|---|---|
| EndoRouter, strict | 0 of 15 | 8 of 8 |
| EndoRouter, balanced, local 30B classifier | 0 of 15 | 0 of 8 |
| LiteLLM 1.103.1, content filter | 15 of 15 | 1 of 8 (a keyword block on the NDA question) |

**The first balanced run on this suite leaked 1 of 10.** It was the key split across two messages. No single string held a whole key, so no detector fired, and the classifier called the conversation public. We added two detector rules. The first flags a distinctive issuer prefix standing on its own, such as `AKIAIOSF`. The second rejoins text typed out letter by letter. The rerun above leaked none.

The three unknown-vendor keys are caught by a rule with no vendor list, described in the README. While adding it we found that leakbench's own random hex markers looked like secrets to that rule, which made 6 public cases look private. Markers are now random lowercase letters, and a test checks that no marker trips a detector.

The suite is still small, and it was written by the same authors as the router.

## How LiteLLM was configured

LiteLLM's documentation describes a `sensitive_data_routing` guardrail that reroutes sensitive requests to an on-premise model. That guardrail type was not in 1.103.1, the latest release on PyPI when we tested. We used its built-in `litellm_content_filter` instead, with the following settings:

- every data-relevant prebuilt pattern;
- the keywords from the routing documentation;
- `on_sensitive_data: route`, pointed at the on-premise model;
- a session id on every request.

In this release that filter blocked on detection with HTTP 400 and did not reroute. leakbench counts a block as safe, so this choice favours LiteLLM on leak rate. The full config is in `litellm-leakbench.yaml`.

## Reproduce

`bench/run_all.sh` runs every configuration on the main suite, and `bench/run_hard.sh` runs the harder suite. Step by step:

```
python -m venv bench/.litellm-venv
bench/.litellm-venv/bin/pip install "litellm[proxy]==1.103.1"
bench/.litellm-venv/bin/litellm --config bench/litellm-leakbench.yaml --host 127.0.0.1 --port 8796
endorouter leakbench --base-url http://127.0.0.1:8796/v1 --no-provenance --model cloud-model --extra-body '{"metadata":{"session_id":"lb-{id}"}}'

endorouter serve -c bench/leakbench-strict.yaml --port 8797
endorouter leakbench --base-url http://127.0.0.1:8797/v1
endorouter leakbench --base-url http://127.0.0.1:8797/v1 --no-provenance

python bench/local_shim.py 8801     # or point the classifier target at any OpenAI-compatible local server
endorouter serve -c bench/leakbench-balanced.yaml --port 8795
endorouter leakbench --base-url http://127.0.0.1:8795/v1

endorouter serve -c bench/leakbench-passthrough.yaml --port 8798
endorouter leakbench --base-url http://127.0.0.1:8798/v1
```

Raw outputs are the `result-*.json` files in this directory.
