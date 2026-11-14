"""Immutable snapshot of the authenticated caller."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class Identity:
    """Who is calling: ``sub``, e-mail, name and token groups.

    ``name`` falls back to ``sub`` and ``email`` to ``""`` when the token has none.
    """

    sub: str
    email: str
    name: str
    groups: tuple[str, ...]
