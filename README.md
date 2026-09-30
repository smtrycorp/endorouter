# sovereign-router

A model router that decides **where a prompt is allowed to go** before it decides which model is best.

Most routers send everything to the cloud and try to catch the sensitive requests on the way out. That fails open: anything the detectors do not recognise, such as a strategy memo, a patient note, or proprietary code, leaves the building. sovereign-router fails closed. Work stays on your local model unless its provenance says it is public, and every decision is written to an audit log before a single byte is sent.

```
client ──▶ sovereign-router ──▶ scan ─▶ label ─▶ decide ─▶ audit ─▶ dispatch
                                                               │
                             private or unknown ──────────────┴──▶ local model only
                             public (by provenance) ─────────────▶ local or cloud, by preference
```

It speaks the OpenAI chat completions API, so any client that lets you set a base URL can use it.

## Quickstart

```
pip install .    # from a clone; not yet on PyPI
sovereign-router doctor -c sovereign-router.yaml
sovereign-router serve -c sovereign-router.yaml
```

Then point your client at `http://127.0.0.1:8787/v1`. Start from the bundled `example.yaml`: one local target (Ollama, LM Studio, llama.cpp, mlx-lm or any OpenAI-compatible server) and, optionally, one cloud target.

To see a decision without sending anything:

```
sovereign-router explain -c sovereign-router.yaml --source clients/acme/brief.md < prompt.txt
```

## How a request is labelled

Every request gets one label: `public`, `unknown` or `private`. Labels only ever combine toward the most restrictive.

| Signal | Effect |
|---|---|
| No provenance | `unknown`, which stays local in strict mode |
| A source matching `public_sources`, sent by a trusted client | may become `public` |
| A source matching `private_sources` | `private` |
| A structural detector finding anywhere in the request | `private` |
| The optional local classifier | can tighten; in balanced mode it may also clear `unknown`, and the audit log says so |

Clients pass provenance with two headers:

```
x-sovereign-sources: docs/public/intro.md,https://example.com/post
x-sovereign-label: public
```

Only clients listed in `trusted_clients` can declare anything public. Any client can declare `private`.

**Detectors check formats, not word lists.** They cover private keys, cloud and SaaS tokens, JWTs with a decodable header, credentials in URLs, Luhn-valid card numbers, US social security numbers, email addresses and phone numbers. They scan every message, including history, tool calls, tool results and tool definitions. Before matching, the text is normalised and zero-width characters are stripped.

## Guarantees

These are enforced in code and pinned by tests.

- A private or unknown request never selects a cloud target in strict mode. Asking for a cloud model by name is refused, not honoured.
- If the local model is down, the request fails. It never falls back to the cloud.
- Fallback only moves between targets that were already permitted.
- The audit record is flushed before dispatch. If the log cannot be written, the request is refused.
- The audit log holds decisions and reasons, never prompt content.
- The HTTP client follows no redirects and ignores proxy environment variables.
- Unknown request fields and non-text content are rejected rather than passed through unexamined.
- A typo in the config is an error, never a silent default.

## The trust boundary

A router can only enforce what it is told, so this section matters more than the rest.

- **Localhost is not proof of local inference.** Some local servers can proxy requests to a hosted model. If a target you declare `local` forwards to a cloud, this router cannot know. `sovereign-router doctor` reminds you of this for every local target.
- **Provenance is only as good as the client that sends it.** Configure `trusted_clients` narrowly.
- **Detectors catch formats, not meaning.** That is why the default is local. In balanced mode, unlabelled work can reach the cloud if the local classifier calls it public, and that is a judgement call you opt into.

## leakbench

leakbench measures whether private data reaches a cloud through any OpenAI-compatible gateway, not just this one. It starts two recording fake servers, one standing in for the cloud and one for the local model. It sends marked cases through the gateway and checks which server each marker reached. The result is measured at the sink, never taken from the gateway's own report.

```
sovereign-router leakbench --base-url http://127.0.0.1:8787/v1
```

Point the gateway's cloud destination at port 8799 and its local destination at 8800. A case that reaches neither is either a deliberate refusal (HTTP 400, 403 or 451), which counts as safe, or a routing failure, which makes the whole run invalid. A gateway that answers nothing must never score as one that leaks nothing.

Results from 2026-09-30 are in [bench/RESULTS.md](bench/RESULTS.md), with the commands to reproduce them.

## Status

Version 0.1, pre-release. Text chat completions, with and without streaming. Not yet supported: images, audio, embeddings and the Responses API. Requests that use them are refused rather than passed through.

Licence: Apache-2.0. Contact: hello@smtry.ai.
