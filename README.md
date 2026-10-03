# EndoRouter

A model router that decides **where a prompt is allowed to go** before it decides which model is best.

Most routers send everything to the cloud and try to catch the sensitive requests on the way out. That fails open: anything the detectors do not recognise, such as a strategy memo, a patient note, or proprietary code, leaves the building. EndoRouter fails closed. Work stays on your local model unless its provenance says it is public, and every decision is written to an audit log before a single byte is sent.

```
client ──▶ endorouter ──▶ scan ─▶ label ─▶ decide ─▶ audit ─▶ dispatch
                                                               │
                             private or unknown ──────────────┴──▶ local model only
                             public (by provenance) ─────────────▶ local or cloud, by preference
```

It speaks the OpenAI chat completions API for text chat, so a client that lets you set a base URL can use it. To send anything to the cloud, the client must also label work as public, per request, with the headers described below. A client that cannot send headers still works, but everything it sends stays local.

## Quickstart

You need Python 3.10 or newer on macOS or Linux, `lsof` (installed by default on macOS), and a local model server that is already running, such as Ollama.

```
pip install .    # from a clone; not yet on PyPI
endorouter serve
```

Then point your client at `http://127.0.0.1:8787/v1` and ask for the model `auto`:

```
curl http://127.0.0.1:8787/v1/chat/completions -H 'content-type: application/json' \
  -d '{"model": "auto", "messages": [{"role": "user", "content": "hello"}]}'
```

There are no questions and no config file. On start the router does three things:

- **It finds your local model and checks that it really is local.** It looks at the ports Ollama, LM Studio, llama.cpp, vLLM and Jan use by default. A server is trusted only if the program behind the port is known to run models on this machine. It also skips any Ollama model that is hosted remotely. Anything it cannot verify, such as a gateway or proxy, is reported with the full command line of the program on that port, and not used. If you know that program runs models here, trust it yourself and name the model: `endorouter init --trust vllm=Qwen/Qwen3-8B`. Only a server that speaks the Ollama API can be trusted by name alone, because it reports which of its models are hosted. Verified servers are re-checked before every send, with no caching: the program on the port, and for Ollama whether the model is still local. A port served by a different program, or an Ollama model that is now hosted remotely, is skipped until the check passes again.
- **It adds cloud providers only if their key is already set.** Examples are `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `GEMINI_API_KEY`, `MISTRAL_API_KEY`, `GROQ_API_KEY` and `OPENROUTER_API_KEY`. A client asks for a cloud model as `openai/gpt-5`, and gets it only for work labelled public.
- **It protects standard secret files.** Examples are `.env`, `*.pem`, SSH keys, `.aws/credentials` and `.netrc`. It runs in strict mode, so anything unlabelled stays local.

On Linux, Ollama usually runs as a system service under its own user, and discovery cannot see which program owns a port another user runs. Trust it once by name, and the router writes that into its config: `endorouter init --trust ollama`, then `endorouter serve`. A target trusted this way is taken at your word: the router cannot check which program owns its port, though it still asks Ollama before every send whether the model runs on this machine.

To see or change what it found, write it to a file:

```
endorouter init        # writes endorouter.yaml; nothing is asked, everything is detected
endorouter doctor
```

To see a decision without sending anything:

```
endorouter explain --source clients/acme/brief.md < prompt.txt
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

Clients pass provenance with headers. Send one `x-endorouter-source` header per source, since a path or URL can contain a comma:

```
x-endorouter-source: docs/public/intro.md
x-endorouter-source: https://example.com/post
x-endorouter-label: public
```

If a proxy joins repeated headers with commas, each comma-separated piece is still checked against `private_sources`, so a private piece keeps the request private.

Only clients listed in `trusted_clients` can declare anything public. Any client can declare `private`.

**Detectors check formats, not word lists.** One rule needs no vendor list at all. It flags any token shaped like a machine-generated secret: long, random, mixing character classes, and not made of word-like runs. It catches keys from vendors nobody has written a pattern for. On 600 synthetic keys from made-up vendors it found 95 to 97% of base62, base64 and base64url shapes, but only 53% of bare hex, which looks the same as a file hash. On the Python 3.14 standard library (38.8 MB of code and docs) it raised 0.62 false alarms per megabyte; expect more on lockfiles and minified bundles, which were not in that corpus. `python bench/shape_eval.py` reproduces these numbers from a fixed seed. Precise format rules sit alongside it for private keys, cloud and SaaS tokens, JWTs with a decodable header, credentials in URLs, card numbers with a valid issuer prefix, length and Luhn checksum, US social security numbers, email addresses and phone numbers. They scan every field that is forwarded upstream: all messages including history, tool calls, tool results, tool definitions, stop sequences and response schemas. That includes dict keys, numbers, and JSON carried inside strings. Before matching, text is NFKC-normalised, every invisible and default-ignorable character is removed, and common Cyrillic and Greek look-alike letters are mapped to Latin. Base64 runs are decoded one level and scanned too, with no cap on how many. Structure nested too deeply to inspect counts as a finding. Scanning time grows in proportion to the input, including for inputs built to make regular expressions backtrack, and tests hold those inputs. On the standard-library corpus it took 0.28 seconds per megabyte on an M2 Max. Request bodies over 4 MB are refused: unread when the size is declared, and read no further than 4 MB when it is not.

Where a value is assigned to an upper-case name, such as `DB_PASSWORD=...` or `SECRET_KEY = '...'`, the whole value is scored, punctuation included. That covers generated passwords and Django-style keys, which punctuation would otherwise split into short pieces. From the same script: 90% of 200 Django-style keys, 82% of 200 twenty-character passwords, and 98% of 200 forty-character AWS-style secrets. Known misses of the shape rule: bare hex, which looks like a file hash; short keys; all-lowercase keys with long runs of letters, which read as words (most of the Django misses); and keys made of plain words, such as `BlueHorseBatteryStaple77`.

What detectors cannot see: secrets split across messages in ways they do not rejoin (they rejoin a key whose issuer prefix stands alone, and text typed out letter by letter, but not arbitrary pieces), encrypted or compressed data, other encodings, and anything that is sensitive because of what it means rather than how it looks. That is the reason unlabelled work stays local by default.

## Guarantees

These are enforced in code and pinned by tests.

- A private or unknown request never selects a cloud target in strict mode. Asking for a cloud model by name is refused, not honoured.
- If the local model is down, a private or unknown request fails. It never falls back to the cloud. A public request may fall back to any permitted target.
- Fallback only moves between targets that were already permitted.
- The decision is flushed to the audit log before anything is sent, and so is each attempt, naming its target, before that attempt. That includes the local classifier. If the log cannot be written before the first send, nothing is sent. Once any target has received the request, including one that then failed and was fallen back from, an audit failure is reported as 502 "sent, but not recorded", naming every target that received it, and the response is discarded. Records are file-locked, so separate processes never interleave them.
- The decision record names the caller's address and whether it was trusted, so every public label can be traced to the address that supplied it. Every process on this machine shares 127.0.0.1, so that address says which trusted client sent it only when you trust a single one. A classifier that fails is recorded as `classifier_failed` with the kind of failure.
- The audit log holds decisions and reasons, never prompt content.
- The HTTP client follows no redirects and ignores proxy environment variables. As a library, the router refuses an injected client that trusts the environment. It converts each request to plain JSON once, then validates, scans and sends exactly that, so a tuple or a numeric key cannot be scanned in one shape and sent in another.
- It listens on loopback only. On every route it answers only requests addressed to `localhost`, `127.0.0.1` or `[::1]` and carrying no browser `Origin` header, and chat requests must be sent as `application/json`. A web page therefore cannot reach it, by DNS rebinding or by a cross-site form or fetch.
- Unknown request fields and non-text content are rejected rather than passed through unexamined. That covers nested tool calls, tools and response formats.
- A typo in the config is an error, never a silent default.

## The trust boundary

A router can only enforce what it is told, so this section matters more than the rest.

- **Localhost is not proof of local inference.** Some local servers can proxy requests to a hosted model. Discovery trusts only known local-inference programs, and it checks Ollama models for remote hosting. A target you declare `local` yourself, in a config file or with `--trust`, is taken at your word. `endorouter doctor` reminds you of this for every local target.
- **Provenance is only as good as the client that sends it.** Configure `trusted_clients` narrowly. The router ignores `X-Forwarded-For`, so no caller can borrow a trusted address. Do not put a shared reverse proxy in front of it: the proxy becomes the peer, and if it is trusted, everyone behind it can label work public.
- **A static public label moves the decision to the model picker.** Many clients can only send fixed headers. If you set `x-endorouter-label: public` on every request, every request counts as public, and only the detectors stand between a pasted secret and the cloud model you chose. Label per request where you can, or route by source paths with `public_sources`.
- **Detectors catch formats, not meaning.** That is why the default is local. In balanced mode, unlabelled work can reach the cloud if the local classifier calls it public, and that is a judgement call you opt into.

## leakbench

leakbench measures whether private data reaches a cloud through any OpenAI-compatible gateway, not just this one. It starts two recording fake servers, one standing in for the cloud and one for the local model. It sends cases through the gateway one at a time, and each server records which case was in flight when a request arrived. Every text message of a case also carries the case's marker, and a request is credited to the cases whose markers it carries before it is credited to the case in flight. A gateway that sends only part of a conversation is caught; so is one that sends late, as long as it sends before the sinks stop listening, one second after the last case by default. The result is measured at the sink, never taken from the gateway's own report.

```
endorouter leakbench --base-url http://127.0.0.1:8787/v1
```

Point the gateway's cloud destination at port 8799 and its local destination at 8800. A gateway that answers nothing must never score as one that leaks nothing, so four checks make a run invalid:

- A benign calibration request does not reach a sink. This means the gateway is down, misconfigured or missing credentials.
- A case reaches no sink and was not refused with HTTP 400, 403 or 451.
- A successful answer did not come from one of the recording sinks. This means the gateway has a destination leakbench cannot see.
- A request reached a sink while no case was in flight, so it cannot be attributed.

Each refusal's response text is kept in the report, so a reader can check it was a policy decision. A refusal is still the gateway's own claim, because leakbench cannot see egress outside its sinks. Reports therefore count refusals separately and mark them unverified.

Results are in [bench/RESULTS.md](bench/RESULTS.md), with the commands to reproduce them. Read the strict-mode zero for what it is: unlabelled work never goes to the cloud, so every unlabelled private case stays local whether or not a detector fires. That zero holds by construction. The detectors are tested where they matter, in the boundary suite, which sends secrets under a public label.

## Status

Version 0.1, pre-release. macOS and Linux. Text chat completions, with and without streaming. Not yet supported: images, audio, embeddings and the Responses API. Requests that use them are refused rather than passed through. Known gap: base64 wrapped across lines (as in PEM or MIME bodies) is not reassembled before decoding.

Licence: [Apache-2.0](LICENSE), copyright 2026 J. I. Ashley Consulting LLC. Security reports: see [SECURITY.md](SECURITY.md). Contact: hello@smtry.ai.
