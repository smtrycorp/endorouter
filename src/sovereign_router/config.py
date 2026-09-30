"""Strict configuration. Unknown fields are errors: a typo must never silently widen where data can go."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

MODES = ("strict", "balanced")
LOCATIONS = ("local", "cloud")


class ConfigError(ValueError):
    pass


@dataclass(frozen=True)
class Target:
    name: str
    url: str  # base URL of an OpenAI-compatible API, e.g. http://127.0.0.1:11434/v1
    model: str  # model name sent upstream; "*" = pass-through, the client asks for "<target>/<model>"
    location: str  # "local" or "cloud", declared by the operator (localhost is not proof: see README)
    capabilities: tuple[str, ...] = ("chat",)
    api_key_env: str | None = None  # name of an environment variable holding the key; never the key itself
    timeout_s: float = 120.0

    @property
    def is_local(self) -> bool:
        return self.location == "local"


@dataclass(frozen=True)
class Provenance:
    public_sources: tuple[str, ...] = ()  # glob patterns for sources approved to leave the machine
    private_sources: tuple[str, ...] = ()  # glob patterns that are always private (wins over public)
    trusted_clients: tuple[str, ...] = ("127.0.0.1", "::1")  # peers whose provenance headers are honoured


@dataclass(frozen=True)
class Classifier:
    enabled: bool = False
    target: str | None = None  # must name a LOCAL target
    timeout_s: float = 30.0


@dataclass(frozen=True)
class Config:
    targets: tuple[Target, ...]  # in preference order
    mode: str = "strict"
    audit_log: str = "sovereign-router.log.jsonl"
    provenance: Provenance = field(default_factory=Provenance)
    classifier: Classifier = field(default_factory=Classifier)

    def target(self, name: str) -> Target | None:
        return next((t for t in self.targets if t.name == name), None)

    @property
    def local_targets(self) -> tuple[Target, ...]:
        return tuple(t for t in self.targets if t.is_local)


def _only(d: dict, allowed: set[str], where: str) -> None:
    extra = set(d) - allowed
    if extra:
        raise ConfigError(f"{where}: unknown field(s) {sorted(extra)}; allowed: {sorted(allowed)}")


def _bool(v: Any, where: str, default: bool) -> bool:
    if v is None:
        return default
    if not isinstance(v, bool):  # "false" or a typo must never become True
        raise ConfigError(f"{where} must be true or false, not {v!r}")
    return v


def _seconds(v: Any, where: str, default: float) -> float:
    if v is None:
        return default
    if isinstance(v, bool) or not isinstance(v, (int, float)) or not 0 < v <= 3600:
        raise ConfigError(f"{where} must be a number of seconds between 0 and 3600, not {v!r}")
    return float(v)


def _opt_str(v: Any, where: str) -> str | None:
    if v is None:
        return None
    if not isinstance(v, str) or not v:
        raise ConfigError(f"{where} must be a non-empty string")
    return v


def _strs(v: Any, where: str) -> tuple[str, ...]:
    if v is None:
        return ()
    if not isinstance(v, list) or not all(isinstance(x, str) for x in v):
        raise ConfigError(f"{where}: expected a list of strings")
    return tuple(v)


def parse_config(raw: dict) -> Config:
    if not isinstance(raw, dict):
        raise ConfigError("config must be a mapping")
    _only(raw, {"version", "mode", "audit_log", "targets", "provenance", "classifier"}, "config")
    if raw.get("version") != 1:
        raise ConfigError("config: version must be 1")
    mode = raw.get("mode", "strict")
    if mode not in MODES:
        raise ConfigError(f"config: mode must be one of {MODES}")
    traw = raw.get("targets")
    if not isinstance(traw, dict) or not traw:
        raise ConfigError("config: at least one target is required")
    targets = []
    for name, t in traw.items():
        if not isinstance(t, dict):
            raise ConfigError(f"targets.{name}: expected a mapping")
        _only(t, {"url", "model", "location", "capabilities", "api_key_env", "timeout_s"}, f"targets.{name}")
        for k in ("url", "model", "location"):
            if not isinstance(t.get(k), str) or not t[k]:
                raise ConfigError(f"targets.{name}.{k} is required")
        if t["location"] not in LOCATIONS:
            raise ConfigError(f"targets.{name}.location must be 'local' or 'cloud'")
        if not t["url"].startswith(("http://", "https://")):
            raise ConfigError(f"targets.{name}.url must be http(s)")
        targets.append(
            Target(
                name=name,
                url=t["url"].rstrip("/"),
                model=t["model"],
                location=t["location"],
                capabilities=_strs(t.get("capabilities", ["chat"]), f"targets.{name}.capabilities") or ("chat",),
                api_key_env=_opt_str(t.get("api_key_env"), f"targets.{name}.api_key_env"),
                timeout_s=_seconds(t.get("timeout_s"), f"targets.{name}.timeout_s", 120.0),
            )
        )
    if not any(t.is_local for t in targets):
        raise ConfigError("config: at least one local target is required (private and unknown work has nowhere else to go)")
    praw = raw.get("provenance") or {}
    _only(praw, {"public_sources", "private_sources", "trusted_clients"}, "provenance")
    prov = Provenance(
        public_sources=_strs(praw.get("public_sources"), "provenance.public_sources"),
        private_sources=_strs(praw.get("private_sources"), "provenance.private_sources"),
        trusted_clients=_strs(praw.get("trusted_clients", ["127.0.0.1", "::1"]), "provenance.trusted_clients"),
    )
    craw = raw.get("classifier") or {}
    _only(craw, {"enabled", "target", "timeout_s"}, "classifier")
    clf = Classifier(enabled=_bool(craw.get("enabled"), "classifier.enabled", False),
                     target=_opt_str(craw.get("target"), "classifier.target"),
                     timeout_s=_seconds(craw.get("timeout_s"), "classifier.timeout_s", 30.0))
    cfg = Config(targets=tuple(targets), mode=mode, audit_log=str(raw.get("audit_log", "sovereign-router.log.jsonl")), provenance=prov, classifier=clf)
    if clf.enabled:
        ct = cfg.target(clf.target or "")
        if ct is None or not ct.is_local:
            raise ConfigError("classifier.target must name a local target (the classifier reads private text)")
    if mode == "balanced" and not clf.enabled:
        raise ConfigError("mode 'balanced' needs the local classifier enabled: nothing else may clear unlabelled text")
    return cfg


def load_config(path: str | Path) -> Config:
    p = Path(path)
    try:
        raw = yaml.safe_load(p.read_text())
    except OSError as e:
        raise ConfigError(f"cannot read {p}: {e}") from e
    return parse_config(raw)
