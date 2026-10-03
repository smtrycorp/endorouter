"""Request shape validation, shared by the HTTP server and Router.route, so a library caller gets the same refusals.

Anything this version does not understand is refused rather than forwarded unexamined. Container types are checked
before they are iterated, so a malformed body is a 400, never a crash.
"""

from __future__ import annotations


class InvalidRequest(ValueError):
    pass


SUPPORTED_FIELDS = {
    "model", "messages", "stream", "stream_options", "temperature", "top_p", "max_tokens", "max_completion_tokens",
    "stop", "n", "presence_penalty", "frequency_penalty", "seed", "tools", "tool_choice", "parallel_tool_calls",
    "response_format", "user", "logprobs", "top_logprobs", "logit_bias",
}


ROLES = {"system", "developer", "user", "assistant", "tool"}
MESSAGE_FIELDS = {"role", "content", "name", "tool_calls", "tool_call_id", "refusal"}


def validate(body) -> str | None:
    """Strict shape check: anything this version does not understand is refused, never forwarded unexamined."""
    if not isinstance(body, dict):
        return "request body must be a JSON object"
    extra = set(body) - SUPPORTED_FIELDS
    if extra:
        return f"unsupported field(s) {sorted(extra)} (endorouter v0.1 supports text chat completions)"
    if not isinstance(body.get("model", "auto"), str):
        return "model must be a string"
    msgs = body.get("messages")
    if not isinstance(msgs, list) or not msgs:
        return "messages must be a non-empty list"
    for i, m in enumerate(msgs):
        if not isinstance(m, dict) or not isinstance(m.get("role"), str) or m.get("role") not in ROLES:
            return f"messages[{i}]: must be an object with a role in {sorted(ROLES)}"
        if set(m) - MESSAGE_FIELDS:
            return f"messages[{i}]: unsupported field(s) {sorted(set(m) - MESSAGE_FIELDS)}"
        problem = _check_tool_calls(m.get("tool_calls"), f"messages[{i}]")
        if problem:
            return problem
        for k in ("name", "tool_call_id", "refusal"):
            if m.get(k) is not None and not isinstance(m.get(k), str):
                return f"messages[{i}].{k} must be a string"
        c = m.get("content")
        if isinstance(c, list):
            for p in c:
                if not (isinstance(p, dict) and p.get("type") == "text" and isinstance(p.get("text"), str) and set(p) <= {"type", "text"}):
                    return f"messages[{i}]: only text content parts are supported in v0.1"
        elif c is not None and not isinstance(c, str):
            return f"messages[{i}]: content must be a string, null or a list of text parts"
    tools = body.get("tools")
    if tools is not None and not isinstance(tools, list):
        return "tools must be a list"
    for i, t in enumerate(tools or []):
        f = t.get("function") if isinstance(t, dict) else None
        if not (isinstance(t, dict) and set(t) <= {"type", "function"} and t.get("type") == "function"
                and isinstance(f, dict) and isinstance(f.get("name"), str)
                and set(f) <= {"name", "description", "parameters", "strict"}
                and isinstance(f.get("description", ""), str) and isinstance(f.get("parameters", {}), dict)
                and isinstance(f.get("strict", False), bool)):
            return f"tools[{i}]: only function tools with a string name and description, object parameters and boolean strict"
    rf = body.get("response_format")
    if rf is not None:
        js = rf.get("json_schema") if isinstance(rf, dict) else None
        if not (isinstance(rf, dict) and rf.get("type") in ("text", "json_object", "json_schema") and set(rf) <= {"type", "json_schema"}
                and (js is None or (isinstance(js, dict) and set(js) <= {"name", "description", "schema", "strict"}
                                    and isinstance(js.get("name", ""), str) and isinstance(js.get("description", ""), str)
                                    and isinstance(js.get("schema", {}), dict) and isinstance(js.get("strict", False), bool)))):
            return "response_format: type must be text, json_object or json_schema with name, description, schema and strict"
    return _check_scalars(body)


def _is_num(v) -> bool:
    return isinstance(v, (int, float)) and not isinstance(v, bool)


def _check_scalars(body: dict) -> str | None:
    """Every other supported field has one plain shape; anything else is refused rather than forwarded."""
    checks = {
        "stream": lambda v: isinstance(v, bool),
        "stream_options": lambda v: isinstance(v, dict) and set(v) <= {"include_usage"} and isinstance(v.get("include_usage", False), bool),
        "temperature": _is_num, "top_p": _is_num, "presence_penalty": _is_num, "frequency_penalty": _is_num,
        "max_tokens": lambda v: isinstance(v, int) and not isinstance(v, bool),
        "max_completion_tokens": lambda v: isinstance(v, int) and not isinstance(v, bool),
        "n": lambda v: isinstance(v, int) and not isinstance(v, bool),
        "seed": lambda v: isinstance(v, int) and not isinstance(v, bool),
        "top_logprobs": lambda v: isinstance(v, int) and not isinstance(v, bool),
        "logprobs": lambda v: isinstance(v, bool),
        "parallel_tool_calls": lambda v: isinstance(v, bool),
        "user": lambda v: isinstance(v, str),
        "stop": lambda v: isinstance(v, str) or (isinstance(v, list) and all(isinstance(x, str) for x in v)),
        "logit_bias": lambda v: isinstance(v, dict) and all(isinstance(k, str) and _is_num(x) for k, x in v.items()),
        "tool_choice": lambda v: v in ("none", "auto", "required") or (
            isinstance(v, dict) and set(v) <= {"type", "function"} and v.get("type") == "function"
            and isinstance(v.get("function"), dict) and set(v["function"]) <= {"name"} and isinstance(v["function"].get("name"), str)),
    }
    for k, ok in checks.items():
        if k in body and body[k] is not None and not ok(body[k]):
            return f"{k}: unsupported value shape"
    return None


def _check_tool_calls(calls, where: str) -> str | None:
    """Every tool call is a function call whose arguments are a string; any other shape could carry non-text payloads
    (an image, a file) that the upstream would receive before rejecting it."""
    if calls is None:
        return None
    if not isinstance(calls, list):
        return f"{where}.tool_calls must be a list"
    for j, tc in enumerate(calls):
        f = tc.get("function") if isinstance(tc, dict) else None
        if not (isinstance(tc, dict) and set(tc) <= {"id", "type", "function"} and tc.get("type") == "function"
                and isinstance(tc.get("id", ""), str) and isinstance(f, dict) and set(f) <= {"name", "arguments"}
                and isinstance(f.get("name"), str) and isinstance(f.get("arguments", ""), str)):
            return f"{where}.tool_calls[{j}]: only function calls with a name and string arguments are supported"
    return None


