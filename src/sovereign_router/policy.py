"""The policy: a pure function from (request, provenance, findings, classifier verdict, config) to a decision.

No network, no clock, no randomness. Everything the router guarantees is decided here, so it is unit-tested here.

The label of a request is the MOST restrictive of:
  - each declared source, matched against provenance.private_sources (private) and provenance.public_sources (public);
    a source matching neither is unknown; private wins over public;
  - an explicit label from a trusted caller (public or private);
  - structural findings anywhere in the request (private);
  - the local classifier, which may only make things MORE private.
With no sources and no label the request is UNKNOWN.

Where it may go:
  - PUBLIC           -> any target
  - UNKNOWN, strict  -> local targets only
  - UNKNOWN, balanced-> any target ONLY if there are no findings AND the local classifier returned "public";
                        the decision records reason "cleared_by_classifier" so it is never mistaken for a declared label
  - PRIVATE          -> local targets only
"""

from __future__ import annotations

from dataclasses import dataclass, field
from fnmatch import fnmatchcase
from typing import Sequence

from .config import Config, Target
from .detectors import Finding
from .labels import Label


@dataclass(frozen=True)
class Decision:
    label: Label
    permitted: tuple[str, ...]  # target names allowed, in preference order
    selected: str | None  # first permitted target that satisfies the request; None = refuse
    reasons: tuple[str, ...]  # rule ids that produced the label and the choice
    cleared_by_classifier: bool = False
    error: str | None = None  # why nothing was selected

    def as_record(self) -> dict:
        return {
            "label": self.label.name.lower(),
            "permitted": list(self.permitted),
            "selected": self.selected,
            "reasons": list(self.reasons),
            "cleared_by_classifier": self.cleared_by_classifier,
            "error": self.error,
        }


def source_label(source: str, cfg: Config) -> tuple[Label, str]:
    s = source.strip()
    if any(fnmatchcase(s, g) for g in cfg.provenance.private_sources):
        return Label.PRIVATE, "source_private"
    if any(fnmatchcase(s, g) for g in cfg.provenance.public_sources):
        return Label.PUBLIC, "source_public"
    return Label.UNKNOWN, "source_unknown"


def decide(
    cfg: Config,
    *,
    requested_model: str | None = "auto",
    sources: Sequence[str] = (),
    declared: Label | None = None,
    findings: Sequence[Finding] = (),
    classifier_verdict: Label | None = None,
    capability: str | None = None,
) -> Decision:
    reasons: list[str] = []
    labels: list[Label] = []

    for s in sources:
        lab, why = source_label(s, cfg)
        labels.append(lab)
        reasons.append(why)
    if declared is not None:
        labels.append(declared)
        reasons.append(f"declared_{declared.name.lower()}")
    if findings:
        labels.append(Label.PRIVATE)
        reasons.extend(sorted({f"detector:{f.rule}" for f in findings}))
    if classifier_verdict is Label.PRIVATE:
        labels.append(Label.PRIVATE)
        reasons.append("classifier_private")

    # A request with no provenance at all is unknown. With sources, the label is the most restrictive source; an explicit
    # public label can never lift an unknown or private source (combine = max).
    if not sources and declared is None:
        labels.append(Label.UNKNOWN)
        reasons.append("no_provenance")
    label = Label.combine(*labels)

    cleared = False
    if label is Label.PUBLIC:
        allowed = list(cfg.targets)
    elif label is Label.UNKNOWN and cfg.mode == "balanced" and not findings and classifier_verdict is Label.PUBLIC:
        allowed = list(cfg.targets)
        cleared = True
        reasons.append("cleared_by_classifier")
    else:
        allowed = list(cfg.local_targets)
        reasons.append("local_only")

    if capability:
        allowed = [t for t in allowed if capability in t.capabilities]
        reasons.append(f"capability:{capability}")

    permitted = tuple(t.name for t in allowed)
    model = (requested_model or "auto").strip()
    if model not in ("", "auto"):
        t = cfg.target(model)
        if t is None:
            return Decision(label, permitted, None, tuple(reasons), cleared, f"unknown target '{model}'")
        if t.name not in permitted:
            return Decision(label, permitted, None, tuple(reasons + ["requested_target_not_permitted"]), cleared,
                            f"target '{model}' is not permitted for a {label.name.lower()} request")
        return Decision(label, (t.name,), t.name, tuple(reasons + ["requested_target"]), cleared)
    if not permitted:
        return Decision(label, permitted, None, tuple(reasons), cleared, "no permitted target satisfies this request")
    return Decision(label, permitted, permitted[0], tuple(reasons), cleared)


def permitted_targets(cfg: Config, decision: Decision) -> list[Target]:
    return [t for n in decision.permitted if (t := cfg.target(n)) is not None]
