"""Sensitivity labels. The order is the whole point: combining labels always keeps the most restrictive."""

from __future__ import annotations

from enum import IntEnum


class Label(IntEnum):
    PUBLIC = 0  # approved to leave the machine
    UNKNOWN = 1  # nobody said; treated as private in strict mode
    PRIVATE = 2  # must stay on a local target

    @classmethod
    def combine(cls, *labels: "Label") -> "Label":
        return max(labels, default=cls.UNKNOWN)

    @classmethod
    def parse_all(cls, values: "list[str]") -> "Label | None":
        """Every value of every header, comma-separated or repeated. One unrecognised token is an error (ValueError),
        never silently ignored; valid tokens combine to the most restrictive."""
        found: list[Label] = []
        for raw in values:
            for tok in raw.split(","):
                if not tok.strip():
                    continue
                lab = cls.parse(tok)
                if lab is None:
                    raise ValueError(f"unrecognised label {tok.strip()[:32]!r}")
                found.append(lab)
        return cls.combine(*found) if found else None

    @classmethod
    def parse(cls, value: str | None) -> "Label | None":
        if not value:
            return None
        v = value.strip().lower()
        return {"public": cls.PUBLIC, "private": cls.PRIVATE, "unknown": cls.UNKNOWN}.get(v)
