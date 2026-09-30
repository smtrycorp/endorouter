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
    def parse(cls, value: str | None) -> "Label | None":
        if not value:
            return None
        v = value.strip().lower()
        return {"public": cls.PUBLIC, "private": cls.PRIVATE, "unknown": cls.UNKNOWN}.get(v)
