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
sovereign-router serve
```

Then point your client at `http://127.0.0.1:8787/v1`. There are no questions and no config file. On start the router does three things:

- **It finds your local model and checks that it really is local.** It looks at the ports Ollama, LM Studio, llama.cpp, vLLM and Jan use by default. A server is trusted only if the program behind the port is known to run models on this machine. It also skips any Ollama model that is hosted remotely. Anything it cannot verify, such as a gateway or proxy, is reported with the full command line of the program on that port, and not used. If you know that program runs models here, trust it yourself and name the model: `sovereign-router init --trust vllm=Qwen/Qwen3-8B`. Only a server that speaks the Ollama API can be trusted by name alone, because it reports which of its models are hosted. Verified servers are re-checked before every send, with the result cached for one second. A port served by a different program is skipped until the verified program is back on it.
- **It adds cloud providers only if their key is already set.** Examples are `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `GEMINI_API_KEY`, `MISTRAL_API_KEY`, `GROQ_API_KEY` and `OPENROUTER_API_KEY`. A client asks for a cloud model as `openai/gpt-5`, and gets it only for work labelled public.
- **It protects standard secret files.** Examples are `.env`, `*.pem`, SSH keys, `.aws/credentials` and `.netrc`. It runs in strict mode, so anything unlabelled stays local.

To see or change what it found, write it to a file:

```
sovereign-router init        # writes sovereign-router.yaml; nothing is asked, everything is detected
sovereign-router doctor
```

To see a decision without sending anything:

```
sovereign-router explain --source clients/acme/brief.md < prompt.txt
```

## How a request is labelled

Every request gets one label: `public`, `unknown` or `private`. Labels only ever combine toward the most restrictive.

| Signal | Effect |
|---|---|
| No provenance | `unknown`, which stays local in strict mode |
| A source matching `public_sources`, sent by a trusted client | may become `public` |
| A source matching `private_sources` | `private` |
| Any path | normalised first, so `docs/public/../x` is matched as `x`; a path that climbs above its root, such as `../x`, is `unknown` |
| A structural detector finding anywhere in the request | `private` |
| The optional local classifier | can tighten; in balanced mode it may also clear `unknown`, and the audit log says so |

Clients pass provenance with two headers:

```
x-sovereign-sources: docs/public/intro.md,https://example.com/post
x-sovereign-label: public
```

Only clients listed in `trusted_clients` can declare anything public. Any client can declare `private`.

**Detectors check formats, not word lists.** One rule needs no vendor list at all. It flags any token shaped like a machine-generated secret: long, random, mixing character classes, and not made of word-like runs. It catches keys from vendors nobody has written a pattern for. On synthetic keys from made-up vendors it found 97% of base62 and base64 shapes, but only about 45% of bare hex, which looks the same as a file hash. On 16.8 MB of public code, docs and lockfiles it raised 4.2 false alarms per megabyte. Precise format rules sit alongside it for private keys, cloud and SaaS tokens, JWTs with a decodable header, credentials in URLs, card numbers with a valid issuer prefix, length and Luhn checksum, US social security numbers, email addresses and phone numbers. They scan every field that is forwarded upstream: all messages including history, tool calls, tool results, tool definitions, stop sequences and response schemas. That includes dict keys, numbers, and JSON carried inside strings. Before matching, text is NFKC-normalised, every invisible and default-ignorable character is removed, and common Cyrillic and Greek look-alike letters are mapped to Latin. Base64 runs are decoded one level and scanned too, with no cap on how many. Structure nested too deeply to inspect counts as a finding. Every pattern is bounded, so scanning takes linear time: about a second per megabyte on a laptop.

Where a value is assigned to an upper-case name, such as `DB_PASSWORD=...` or `SECRET_KEY = '...'`, the whole value is scored, punctuation included. That covers generated passwords and Django-style keys, which punctuation would otherwise split into short pieces. It caught all of 200 Django-style keys and 170 of 200 twenty-character passwords, with no false alarms on the public corpus. Known misses of the shape rule: bare hex, which looks like a file hash; short keys; and keys with a plain word inside, such as AWS's documentation example that ends in `EXAMPLEKEY`. Realistic 40-character AWS-style secrets with slashes were found 294 times in 300.

What detectors cannot see: secrets split across messages, encrypted or compressed data, other encodings, and anything that is sensitive because of what it means rather than how it looks. That is the reason unlabelled work stays local by default.

## Guarantees

These are enforced in code and pinned by tests.

- A private or unknown request never selects a cloud target in strict mode. Asking for a cloud model by name is refused, not honoured.
- If the local model is down, a private or unknown request fails. It never falls back to the cloud. A public request may fall back to any permitted target.
- Fallback only moves between targets that were already permitted.
- The decision is flushed to the audit log before anything is sent, and so is each attempt, naming its target, before that attempt. That includes the local classifier. If the log cannot be written, nothing is sent. Records are file-locked, so separate processes never interleave them.
- The audit log holds decisions and reasons, never prompt content.
- The HTTP client follows no redirects and ignores proxy environment variables. As a library, the router refuses an injected client that trusts the environment, and it inspects and sends its own copy of the request.
- Unknown request fields and non-text content are rejected rather than passed through unexamined. That covers nested tool calls, tools and response formats.
- A typo in the config is an error, never a silent default.

## The trust boundary

A router can only enforce what it is told, so this section matters more than the rest.

- **Localhost is not proof of local inference.** Some local servers can proxy requests to a hosted model. Discovery trusts only known local-inference programs, and it checks Ollama models for remote hosting. A target you declare `local` yourself, in a config file or with `--trust`, is taken at your word. `sovereign-router doctor` reminds you of this for every local target.
- **Provenance is only as good as the client that sends it.** Configure `trusted_clients` narrowly. The router ignores `X-Forwarded-For`, so no caller can borrow a trusted address. Behind a reverse proxy, the proxy is the peer, so list it in `trusted_clients` only if every caller behind it is trusted.
- **A static public label moves the decision to the model picker.** Many clients can only send fixed headers. If you set `x-sovereign-label: public` on every request, every request counts as public, and only the detectors stand between a pasted secret and the cloud model you chose. Label per request where you can, or route by source paths with `public_sources`.
- **Detectors catch formats, not meaning.** That is why the default is local. In balanced mode, unlabelled work can reach the cloud if the local classifier calls it public, and that is a judgement call you opt into.

## leakbench

leakbench measures whether private data reaches a cloud through any OpenAI-compatible gateway, not just this one. It starts two recording fake servers, one standing in for the cloud and one for the local model. It sends marked cases through the gateway and checks which server each marker reached. The result is measured at the sink, never taken from the gateway's own report.

```
sovereign-router leakbench --base-url http://127.0.0.1:8787/v1
```

Point the gateway's cloud destination at port 8799 and its local destination at 8800. A gateway that answers nothing must never score as one that leaks nothing, so three checks make a run invalid:

- A benign calibration request does not reach a sink. This means the gateway is down, misconfigured or missing credentials.
- A case reaches no sink and was not refused with HTTP 400, 403 or 451.
- A successful answer did not come from one of the recording sinks. This means the gateway has a destination leakbench cannot see.

Each refusal's response text is kept in the report, so a reader can check it was a policy decision. A refusal is still the gateway's own claim, because leakbench cannot see egress outside its sinks. Reports therefore count refusals separately and mark them unverified.

Results from 2026-09-30 are in [bench/RESULTS.md](bench/RESULTS.md), with the commands to reproduce them.

## Status

Version 0.1, pre-release. Text chat completions, with and without streaming. Not yet supported: images, audio, embeddings and the Responses API. Requests that use them are refused rather than passed through.

Licence: Apache-2.0. Contact: hello@smtry.ai.
