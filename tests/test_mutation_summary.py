from __future__ import annotations

import importlib.util
from pathlib import Path

spec = importlib.util.spec_from_file_location(
    "mutation_summary", Path(__file__).parents[1] / "scripts/mutation_summary.py"
)
summary = importlib.util.module_from_spec(spec)
spec.loader.exec_module(summary)  # type: ignore[union-attr]

OUT = """
    pkg.mod.x_a__mutmut_1: killed
    pkg.mod.x_a__mutmut_2: survived
    pkg.mod.xǁKlassǁm__mutmut_3: timeout
    pkg.mod.x_a__mutmut_4: no tests
    pkg.other.x_b__mutmut_1: killed
    garbage line
"""


def test_parse_groups_by_module_and_counts_timeouts_as_killed():
    counts = summary.parse(OUT)
    assert counts["pkg.mod"] == {"killed": 2, "survived": 1, "no tests": 1}
    assert counts["pkg.other"] == {"killed": 1}


def test_score():
    assert summary.score({"killed": 3, "survived": 1}) == 75.0
    assert summary.score({"killed": 1, "no tests": 1}) == 50.0
    assert summary.score({}) == 100.0
