"""Condition-agnostic exploration policy shared by the runner and the analysis.

The protocol knows nothing about what either condition discloses: a session
follows at most FOLLOW_BUDGET references, chosen strictly in first-observation
order among references it has not requested yet. Depth differences between
conditions therefore emerge from content alone, never from per-playbook
target lists.
"""

FOLLOW_BUDGET = 3


def next_follow(disclosure_order: list[str], requested: set[str]) -> str | None:
    """First observed reference not yet requested, or None."""
    for ref in disclosure_order:
        if ref not in requested:
            return ref
    return None
