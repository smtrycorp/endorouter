# leakbench results, 2026-10-03

Every result here was produced by commit `e26ed92`; `bench/run-info-*.txt` records the commit of each run.

29 cases: 24 private, 5 public. Every result is measured at the recording sinks.

## Summary

| Gateway | Private cases that reached the cloud | Public cases kept off the cloud |
|---|---|---|
| EndoRouter 0.1, strict, with provenance headers | 0 of 24 | 3 of 5 |
| EndoRouter 0.1, strict, no provenance headers | 0 of 24 | 5 of 5 |
| EndoRouter 0.1, balanced, local 30B classifier | 0 of 24 | 0 of 5 (0 or 1 across runs) |
| LiteLLM 1.103.1, content filter on every request | 13 of 24 | 0 of 5 |
| Pass-through control (cloud declared local) | 24 of 24 | 0 of 5 |

All five runs are valid. In each, the calibration request reached a sink, every case reached a sink or was refused, every answer came from a recording sink, and no request reached a sink outside the case it belonged to. Since 2026-10-03, leakbench sends each case exactly as written and tells cases apart by what they say, never by API syntax or by text the gateway adds to every request. A private case leaked if any of its strings, or a secret-like word in them, that no public case says arrived at the cloud sink, whenever it arrived; a case counts as run only if text unique to it reached a sink. Strings and numbers under 8 characters cannot be measured and are listed per case (in these suites only filler such as "Got it." and "200 OK"); text rewritten beyond recognition is not caught (see the README). All 11 LiteLLM refusals were its content filter reporting a matched pattern, and the reports keep each refusal message. A refusal is still the gateway's own claim, so leakbench reports refusals separately and marks them unverified. Counting them as safe favours LiteLLM.

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

In balanced mode, unlabelled work may go to the cloud when no detector fires and a local model classifies it as public. The classifier here was Muse Glimmer 30B, an open-weight model, quantised to 4 bits with MLX and running on the same laptop (an M2 Max with 64 GB). We ran the suite many times as the code changed.

- **Private prompts.** In every run, no private case reached the cloud. The classifier called all 5 confidential prose cases private.
- **Unlabelled public prompts.** In every run, the classifier cleared all 3 for the cloud.
- **Run-to-run variation.** In some runs one public question stayed local, and which one varied. An example is a public-source request with no substance: "Explain what this README section means for a new user". The classifier may tighten any request, even one with public provenance, so a flip like this costs a cloud trip and never causes a leak.
- **Latency.** Every unlabelled request waits for the classifier. The first run averaged about 9.5 seconds per request on that machine.

**A benchmark's tags can sway what it measures.** leakbench used to add a unique marker to each case. A random 27-letter marker placed first made the local classifier call one public question private in 2 of 3 runs (3 of 3 public without it), and a reviewer showed a marker could stop JSON in a message being read as JSON, hiding a key from the detectors. leakbench now adds nothing to a case and identifies cases by their own content; the numbers above were run that way.

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

The strict zero here holds by construction, as on the main suite: none of these cases is labelled, so none can go to the cloud in strict mode. The balanced zero is the one the detectors and classifier earn.

**The first balanced run on this suite leaked 1 of 10.** The suite then had 10 private cases; the other 5 were added afterwards. It was the key split across two messages. No single string held a whole key, so no detector fired, and the classifier called the conversation public. We added two detector rules. The first flags a distinctive issuer prefix standing on its own, such as `AKIAIOSF`. The second rejoins text typed out letter by letter. The rerun above leaked none.

The three unknown-vendor keys are caught by a rule with no vendor list, described in the README. While adding it we found that leakbench's own random hex markers looked like secrets to that rule, which made 6 public cases look private. That was the first sign that tagging cases changes results; leakbench now adds no markers at all (see above).

The suite is still small, and it was written by the same authors as the router.

## The boundary suite

The strict-mode zeros above hold by construction: unlabelled work never goes to the cloud, so an unlabelled private case stays local whether or not any detector fires. `cases-boundary.jsonl` tests where the detectors actually decide. Its 12 private cases carry a public label or a public source, as a client that labels everything public would send them, with a secret inside.

- **7 cases use formats the detectors cover:** an AWS key, an unknown vendor's key, a card number, a token in earlier history, a Django key in a tool result, a private key under a public source path, and a database URL in a streaming request.
- **5 cases are the README's own known misses**, added after a reviewer pointed out that a suite of covered formats flatters the detectors: bare hex, a key made of plain words, an all-lowercase key, base64 wrapped across lines, and an 8-character password.
- **2 public cases** check that a public label still reaches the cloud.

| Gateway | Covered formats that reached the cloud | Known misses that reached the cloud | Public cases kept off the cloud |
|---|---|---|---|
| EndoRouter, strict | 0 of 7 | 5 of 5 | 0 of 2 |
| EndoRouter, balanced | 0 of 7 | 0 of 5 | 0 of 2 |
| LiteLLM 1.103.1, content filter | 3 of 7 | 5 of 5 | 0 of 2 |

We predicted the strict and LiteLLM rows before the run. We predicted balanced mode would also leak all 5 misses, and it leaked none: in balanced mode the local classifier reads every request of up to 12,000 characters, public labels included, and its verdict can only tighten (a longer request gets no verdict, so a public label then rests on the detectors alone). It called all 5 private. That catch depends on the classifier model and is not guaranteed; the strict row is what the detectors alone do. LiteLLM receives no provenance headers, so for it these are ordinary requests; its 4 refusals were its content filter.

## How LiteLLM was configured

LiteLLM's documentation describes a `sensitive_data_routing` guardrail that reroutes sensitive requests to an on-premise model. That guardrail type was not in 1.103.1, the latest release on PyPI when we tested. We used its built-in `litellm_content_filter` instead, with the following settings:

- every data-relevant prebuilt pattern;
- the keywords from the routing documentation;
- `on_sensitive_data: route`, pointed at the on-premise model;
- a session id on every request.

In this release that filter blocked on detection with HTTP 400 and did not reroute. leakbench counts a block as safe, so this choice favours LiteLLM on leak rate. The full config is in `litellm-leakbench.yaml`.

## Reproduce

You need the router installed in `.venv` (`python3 -m venv .venv && .venv/bin/pip install -e .`) and LiteLLM in `bench/.litellm-venv` (below). `bench/run_all.sh` runs every configuration on the main suite, and `bench/run_hard.sh` runs the harder and boundary suites. Each script stops the servers it started, and exits non-zero if any run is invalid or a configuration expected to leak nothing leaked.

Balanced mode needs a local model server with an OpenAI-compatible API on `127.0.0.1:8801`, serving a model named `local-classifier`; edit `leakbench-balanced.yaml` to use another name. Without it, the scripts skip balanced mode and say so. Our runs used Muse Glimmer 30B, MLX 4-bit (group size 64), on an M2 Max with 64 GB. With a different model, balanced results will differ, and the strict results will not.

Step by step:

```
python -m venv bench/.litellm-venv
bench/.litellm-venv/bin/pip install "litellm[proxy]==1.103.1"
bench/.litellm-venv/bin/litellm --config bench/litellm-leakbench.yaml --host 127.0.0.1 --port 8796
endorouter leakbench --base-url http://127.0.0.1:8796/v1 --no-provenance --model cloud-model --extra-body '{"metadata":{"session_id":"lb-{id}"}}'

endorouter serve -c bench/leakbench-strict.yaml --port 8797
endorouter leakbench --base-url http://127.0.0.1:8797/v1
endorouter leakbench --base-url http://127.0.0.1:8797/v1 --no-provenance

# start a local model server on 127.0.0.1:8801 first, e.g. llama-server -m <model.gguf> --port 8801
endorouter serve -c bench/leakbench-balanced.yaml --port 8795
endorouter leakbench --base-url http://127.0.0.1:8795/v1

endorouter serve -c bench/leakbench-passthrough.yaml --port 8798
endorouter leakbench --base-url http://127.0.0.1:8798/v1
```

Raw outputs are the `result-*.json`, `hard-*.json` and `boundary-*.json` files in this directory. They hold the synthetic cases and the routing outcome of each, never model answers.
