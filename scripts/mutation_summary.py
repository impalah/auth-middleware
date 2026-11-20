#!/usr/bin/env python3
"""Summarise a ``mutmut`` run: mutation score per module, optional threshold.

Usage:
    python scripts/mutation_summary.py [--min 85] [--survivors]

Reads ``mutmut results --all true`` (run ``make mutation`` first). The score of a
module is killed / (killed + survived); ``timeout`` and ``suspicious`` count as killed
(the mutant changed behaviour), ``no tests`` and ``not checked`` are reported apart and
count as survived. Exits 1 when a module is below ``--min``.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from collections import defaultdict

_LINE = re.compile(r"^\s*(?P<name>\S+?)__mutmut_(?P<n>\d+):\s*(?P<status>.+?)\s*$")
_KILLED = {"killed", "timeout", "suspicious", "segfault"}


def module_of(name: str) -> str:
    """Drop the trailing function/method part of a mutant name."""
    return name.rsplit(".", 1)[0]


def parse(text: str) -> dict[str, dict[str, int]]:
    """Count mutant statuses per module from ``mutmut results --all true`` output."""
    counts: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    for line in text.splitlines():
        match = _LINE.match(line)
        if match is None:
            continue
        module = module_of(match.group("name"))
        status = match.group("status")
        bucket = "killed" if status in _KILLED else status
        counts[module][bucket] += 1
    return counts


def score(counts: dict[str, int]) -> float:
    """Killed / (killed + everything that was not)."""
    total = sum(counts.values())
    return 100.0 * counts.get("killed", 0) / total if total else 100.0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--min", type=float, default=None, help="fail below this score")
    parser.add_argument("--survivors", action="store_true", help="list the survivors")
    args = parser.parse_args(argv)

    out = subprocess.run(
        ["uv", "run", "--with", "mutmut", "mutmut", "results", "--all", "true"],  # noqa: S607
        capture_output=True,
        text=True,
        check=False,
    ).stdout
    counts = parse(out)
    if not counts:
        print("no mutmut results: run `make mutation` first", file=sys.stderr)
        return 2
    failed = False
    print(f"{'module':58} {'score':>6} {'killed':>7} {'survived':>9} {'other':>6}")
    for module in sorted(counts):
        c = counts[module]
        other = sum(v for k, v in c.items() if k not in ("killed", "survived"))
        s = score(c)
        killed, survived = c.get("killed", 0), c.get("survived", 0)
        print(f"{module:58} {s:5.1f}% {killed:7} {survived:9} {other:6}")
        failed = failed or (args.min is not None and s < args.min)
    if args.survivors:
        for line in out.splitlines():
            if line.rstrip().endswith("survived"):
                print(line.strip())
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
