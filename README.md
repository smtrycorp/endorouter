# EndoRouter

A model router that decides **where a prompt is allowed to go** before it decides which model is best.

Most routers send everything to the cloud and try to catch the sensitive requests on the way out. That fails open: anything the detectors do not recognise, such as a strategy memo, a patient note, or proprietary code, leaves the building. EndoRouter fails closed. By default, work stays on your local model unless its provenance says it is public; an optional balanced mode also lets a local classifier clear unlabelled work. Every send, to a cloud model or to that local classifier, is written to an audit log before a byte of it leaves.

```
client ──▶ endorouter ──▶ scan ─▶ label ─▶ decide ─▶ audit ─▶ dispatch
                                                               │
                             private or unknown ──────────────┴──▶ local model only
                             public (by provenance) ─────────────▶ local or cloud, by preference
```

It speaks the OpenAI chat completions API for text chat, so a client that lets you set a base URL can use it. In the default strict mode, sending anything to the cloud takes a public label, or a source matching `public_sources`, from a trusted client, per request, with the headers described below. A client that cannot send headers still works: in strict mode everything it sends stays local, and in balanced mode the local classifier decides.

## Quickstart

You need Python 3.10 or newer on macOS, Linux or Windows, and a local model server that is already running, such as Ollama.

```
pip install endorouter
endorouter serve
```

Then point your client at `http://127.0.0.1:8787/v1` and ask for the model `auto`:

```
# POSIX shell
curl http://127.0.0.1:8787/v1/chat/completions -H 'content-type: application/json' \
  -d '{"model": "auto", "messages": [{"role": "user", "content": "hello"}]}'
# PowerShell (curl there is an alias for Invoke-WebRequest, so name the program)
curl.exe http://127.0.0.1:8787/v1/chat/completions -H 'content-type: application/json' -d '{"model": "auto", "messages": [{"role": "user", "content": "hello"}]}'
```

There are no questions and no config file. On start the router does three things:

- **It finds your local model and checks what is behind the port.** It looks at the ports Ollama, LM Studio, llama.cpp, vLLM and Jan use by default. A server is trusted only when every process found holding its port runs an executable that the kernel reports as a known local-inference program, judged by its canonical path: a known file name directly in the folder that program's installer uses, or the target of the installer's link there (Ollama, llama.cpp, LM Studio and Jan; see Status). On macOS and Linux the file, every folder above it, and every link on the way from the install folder must also belong to root or to you, with permission bits that let no other user write them; owner and mode bits are all that is read, not access control lists (on macOS a folder the admin group may write is allowed, since its members can run anything with sudo; a file is not). On Windows there is no ownership or permission check: the install folders are under your own profile, and their access lists are not read. This is identity by location, not proof: a program that passes is the one its installer put there, as far as the file system can tell, and nothing is known about what it does. A listening socket that cannot be traced to a process, a process whose executable the kernel will not name, or a known name running from anywhere else gives no verdict; holders no platform can see, such as a second process holding a copy of a verified socket, are described under The trust boundary. It also skips any Ollama model that is hosted remotely. Anything it cannot verify, such as a gateway, a proxy or a server written in Python, is reported with the first 160 characters of the command line of each program on that port, and not used. If you know that program runs models here, trust it yourself and name the model: `endorouter init --trust vllm=Qwen/Qwen3-8B`. Only a server that speaks the Ollama API can be trusted by name alone, because it reports which of its models are hosted. Verified servers are re-checked before every send, with no caching: the processes on the port, and for Ollama whether the model is still local. A port served by a different program, or an Ollama model that is now hosted remotely, is skipped until the check passes again.
- **It adds cloud providers only if their key is already set.** Examples are `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `GEMINI_API_KEY`, `MISTRAL_API_KEY`, `GROQ_API_KEY` and `OPENROUTER_API_KEY`. A client asks for a cloud model as `openai/gpt-5`, and gets it only for work labelled public.
- **It protects standard secret files.** Examples are `.env`, `*.pem`, SSH keys, `.aws/credentials` and `.netrc`. It runs in strict mode, so anything unlabelled stays local.

On Linux, Ollama usually runs as a system service under its own user, and a listening socket of another user is refused outright there; on every platform, a listening socket that cannot be traced to a process gives no verdict. Trust it once by name, and the router writes that into its config: `endorouter init --trust ollama`, then `endorouter serve`. A target trusted this way is taken at your word: the router cannot check which program owns its port, though it still asks Ollama before every send whether the model runs on this machine.

To see or change what it found, write it to a file:

```
endorouter init        # writes endorouter.yaml; nothing is asked, everything is detected
endorouter doctor
```

To see the decision for a prompt (the prompt itself goes nowhere; with no config file, `explain` and `doctor` first run discovery, which sends the loopback probes described under Guarantees):

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

**Detectors check formats, not word lists.** One rule needs no vendor list at all. It flags any token shaped like a machine-generated secret: long, random, mixing character classes, and not made of word-like runs. It catches keys from vendors nobody has written a pattern for. On 600 synthetic keys from made-up vendors it found 95 to 97% of base62, base64 and base64url shapes, but only 53% of bare hex, which looks the same as a file hash. On the Python 3.14 standard library (38.8 MB of code and docs) it raised 0.62 false alarms per megabyte; expect more on lockfiles and minified bundles, which were not in that corpus. `python bench/shape_eval.py` reproduces these numbers from a fixed seed. Precise format rules sit alongside it for private keys, cloud and SaaS tokens, JWTs with a decodable header, credentials in URLs, card numbers with a valid issuer prefix, length and Luhn checksum, US social security numbers, email addresses and phone numbers. They scan every field that is forwarded upstream: all messages including history, tool calls, tool results, tool definitions, stop sequences and response schemas. That includes dict keys, numbers, and JSON carried inside strings. Before matching, text is NFKC-normalised, every invisible and default-ignorable character is removed, and common Cyrillic and Greek look-alike letters are mapped to Latin. Base64 runs are decoded one level and scanned too, with no cap on how many. Structure nested too deeply to inspect counts as a finding. Scanning time grows in proportion to the input on every adversarial input we know of: each repetition of one or two characters from a broad set, a run of every code point that normalises to an accent or other mark, and the inputs reviewers found, which tests hold; memory grows in proportion to the request too, including for deeply nested JSON (34 MiB for a 5 MB nested schema). That is a measured property, not a proof. On the standard-library corpus scanning took 0.28 seconds per megabyte on an M2 Max; the slowest inputs we know of take 2 to 4 seconds per megabyte (digits and dashes, or many card numbers), and while any of these scanned, other requests waited at most about 0.2 seconds; for a 4 MB request of a million tiny strings, read, checked and scanned through the HTTP path, about 0.13 seconds. Request bodies over 4 MB are refused: unread when the size is declared, and read no further than 4 MB when it is not.

Where a value is assigned to an upper-case name, such as `DB_PASSWORD=...` or `SECRET_KEY = '...'`, the whole value is scored, punctuation included. That covers generated passwords and Django-style keys, which punctuation would otherwise split into short pieces. From the same script: 90% of 200 Django-style keys, 82% of 200 twenty-character passwords, and 98% of 200 forty-character AWS-style secrets. Known misses of the shape rule: bare hex, which looks like a file hash; short keys; all-lowercase keys with long runs of letters, which read as words (most of the Django misses); and keys made of plain words, such as `BlueHorseBatteryStaple77`.

What detectors cannot see: secrets split across messages in ways they do not rejoin (they rejoin a key whose issuer prefix stands alone, and text typed out letter by letter, but not arbitrary pieces), encrypted or compressed data, other encodings, and anything that is sensitive because of what it means rather than how it looks. That is the reason unlabelled work stays local by default.

## Guarantees

These are enforced in code and pinned by tests.

- A private or unknown request never selects a cloud target in strict mode. Asking for a cloud model by name is refused, not honoured.
- If the local model is down, a private or unknown request fails. It never falls back to the cloud. A public request may fall back to any permitted target.
- Fallback only moves between targets that were already permitted.
- Every send is preceded by a flushed audit record naming where it goes: a `classifier_dispatch` record before the local classifier reads the text, a `probe` record before Ollama is asked whether a model is still local (that question carries the model's name), and an `attempt` record, after the `decision` record, before each target. If a record cannot be written before the first send, nothing is sent. The one exception is discovery itself: `init`, and `serve`, `doctor` and `explain` without a config file, list the models on the usual loopback ports and ask Ollama about them before any config exists; those requests carry no prompt and are not recorded. The probe, like every send, follows no redirect. Once anything has been sent, to the classifier or to a target, an audit failure is reported as 502 "sent, but not recorded", naming every recipient, and the response is discarded; if only a model probe left (it carries the model's name, never the prompt), the failure is reported as 503 saying exactly that. Records are file-locked, so separate processes never interleave them. A writer that dies mid-record leaves a partial line; the next writer reads back the last 64 KiB of the file and, unless the last line starts inside that window, ends in a newline and parses as a JSON object (any object, not only a record of the router's own), closes it off with an `audit_repaired` record, so it never merges with a real one. A valid record longer than that window gets the marker too.
- The decision record names the caller's address, whether it was trusted, and the label it declared, which the record never rewrites: `declared_applied` says whether policy used it (an untrusted caller's "public" is recorded but not applied), and a source that makes a request private appears as its own reason. Every process on this machine shares 127.0.0.1, so the address says which trusted client sent a public label only when you trust a single one. A classifier that fails is recorded as `classifier_failed` with the kind of failure.
- The audit log holds decisions and reasons, never prompt content.
- The HTTP client follows no redirects and ignores proxy environment variables. As a library, the router refuses an injected client that trusts the environment. It converts each request to plain JSON once, then validates, scans and sends exactly that, so a tuple or a numeric key cannot be scanned in one shape and sent in another.
- It listens on loopback only. On every route it answers only requests addressed to `localhost`, `127.0.0.1` or `[::1]` and carrying no browser `Origin` header, and chat requests must be sent as `application/json`. A web page therefore cannot reach it, by DNS rebinding or by a cross-site form or fetch.
- Unknown request fields and non-text content are rejected rather than passed through unexamined. That covers nested tool calls, tools and response formats.
- A typo in the config is an error, never a silent default.

## The trust boundary

A router can only enforce what it is told, so this section matters more than the rest.

- **Localhost is not proof of local inference.** Some local servers can proxy requests to a hosted model. Discovery trusts only known local-inference programs, and it checks Ollama models for remote hosting. A target you declare `local` yourself, in a config file or with `--trust`, is taken at your word. `endorouter doctor` reminds you of this for every local target.
- **The port check sees locations, not intent.** It establishes that every process found holding the port runs an executable at a known program's install location, owned and writable as described in Quickstart. That is a heuristic for the program's identity, not proof of what it does. What each platform cannot see: on Linux, every listening socket on the port must be traced to a process, so a hidden listener (with `SO_REUSEPORT` a process of yours binds its own socket beside Ollama's, no handover needed) leaves no verdict rather than a wrong one, but a process of your own account that hides its descriptor table while holding a copy of a verified socket's descriptor is not seen; on macOS, the kernel's list names one holder per socket, and further holders are only those readable processes that report the socket; on Windows, each socket is attributed to the process that created it, and a handle duplicated into another process, readable or not, is not enumerated. Verification is a snapshot taken before each send, not a binding to the recipient: a port that changes hands between the check and the send is caught at the next request, not that one. An unrestricted process already running as you, one that can write the router's configuration, could point it anywhere, so this check guards against the wrong program on a port, not against an attacker on your account.
- **Provenance is only as good as the client that sends it.** Configure `trusted_clients` narrowly. The router ignores `X-Forwarded-For`, so no caller can borrow a trusted address. Do not put a shared reverse proxy in front of it: the proxy becomes the peer, and if it is trusted, everyone behind it can label work public.
- **A static public label moves the decision to the model picker.** Many clients can only send fixed headers. If you set `x-endorouter-label: public` on every request, every request counts as public, and only the detectors stand between a pasted secret and the cloud model you chose. Label per request where you can, or route by source paths with `public_sources`.
- **Detectors catch formats, not meaning.** That is why the default is local. In balanced mode, unlabelled work can reach the cloud if the local classifier calls it public, and that is a judgement call you opt into.

## leakbench

leakbench measures whether private data reaches a cloud through any OpenAI-compatible gateway, not just this one. It starts two recording fake servers, one standing in for the cloud and one for the local model. It sends each case exactly as written, nothing added, one at a time, and keeps listening a second after the last. Cases are told apart by what they say: message text and names, refusals, tool calls (names and arguments), tool definitions and schemas (property names, numbers and allowed values included), but never the API's own syntax (field names, roles, types, ids). Text is compared the way the detectors read it, so removing an invisible character or changing spacing on the way does not hide anything. Every case must say something of 8 or more characters that no other case says, be a request a router would accept, and have a unique id and a well-formed truth, label and sources; otherwise the suite is refused. The calibration request, sent first and observed on its own, shows what the gateway adds to every request itself (a system prompt, default stop sequences); that text is never evidence. A private case leaked if any of its strings, or any secret-like word in them (8+ characters with a digit, a symbol or mixed case, such as a key cut out of its sentence or an assignment, or a password with punctuation), that no public case says arrived at the cloud sink inside one received string, whenever it arrived. A case counts as having run only if text unique to it reached a sink. What it cannot see: strings and numbers under 8 characters (each report lists them per case as unmeasured), ordinary words taken out of their sentence, and text a gateway rewrites beyond recognition. leakbench measures gateways that are not built to fool it. One that adds different text for different models, merges messages, or moves one case's text into another's request in disguise can still mislead its attribution: a validity check catches the plain cases (nothing arrived, unattributable traffic, a failed calibration), not every evasion. The result is measured at the sink, never taken from the gateway's own report.

```
endorouter leakbench --base-url http://127.0.0.1:8787/v1
```

Point the gateway's cloud destination at port 8799 and its local destination at 8800. A gateway that answers nothing must never score as one that leaks nothing, so four checks make a run invalid:

- A benign calibration request does not reach a sink. This means the gateway is down, misconfigured or missing credentials.
- A case reaches no sink and was not refused with HTTP 400, 403 or 451.
- A successful answer did not come from one of the recording sinks. This means the gateway has a destination leakbench cannot see.
- A request reached a sink carrying no case's content, so it cannot be attributed.

Each refusal's response text is kept in the report, so a reader can check it was a policy decision. A refusal is still the gateway's own claim, because leakbench cannot see egress outside its sinks. Reports therefore count refusals separately and mark them unverified.

Results are in [bench/RESULTS.md](bench/RESULTS.md), with the commands to reproduce them. Read the strict-mode zero for what it is: unlabelled work never goes to the cloud, so every unlabelled private case stays local whether or not a detector fires. That zero holds by construction. The detectors are tested where they matter, in the boundary suite, which sends secrets under a public label.

## Status

Version 0.1, pre-release. macOS, Linux and Windows. The port-owner check verifies a program by the executable path the kernel reports for every process it finds holding the port (the trust boundary says what each platform can find), which must be a known file name directly in the folder that program's installer uses, or that folder's link target: Ollama, llama.cpp (Homebrew, WinGet's `ggml.llamacpp` package, or `/usr/local/bin`), and on macOS and Windows the LM Studio and Jan apps (the app's own executable and Electron's helper names exactly, on both: `<App> Helper` and `<App> Helper (Renderer|GPU|Plugin)`). On macOS and Linux the file, the folders above it and every link on the way from the install folder must be owned by root or you, with mode bits that let nobody else write (a link's own mode bits are not read, only its owner, and a sticky world-writable folder such as /tmp is allowed, since only an entry's owner can replace it there); access control lists are not read, and on macOS a folder, never a file, that the admin group may write is allowed. On Windows nothing about ownership or access lists is checked. Earlier builds recognised a program by its name alone; now vLLM, mlx_lm and KoboldCpp, which run as Python, and any server run from a build tree or a download folder, unless the installer's link in the install folder leads to it, are now unverified and must be trusted by hand: `endorouter init --trust vllm=<model>`. On Windows the check has been exercised in CI only against a stand-in process, never against Ollama or another real local server. The audit log is created owner-only on Unix; on Windows the mode is not applied, the router sets no access list of its own and does not check the folder's, and the default location, `%LOCALAPPDATA%\endorouter\audit.jsonl`, is in a folder that is private to your account by default. `endorouter doctor` says so. Text chat completions, with and without streaming. Not yet supported: images, audio, embeddings and the Responses API. Requests that use them are refused rather than passed through. Known gap: base64 wrapped across lines (as in PEM or MIME bodies) is not reassembled before decoding.

Built by Jacob Ashley with Claude. Licence: [Apache-2.0](LICENSE), copyright 2026 J. I. Ashley Consulting LLC. Security reports: see [SECURITY.md](SECURITY.md). Contact: hello@smtry.ai.
