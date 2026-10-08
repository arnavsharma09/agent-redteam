"""Novelty deduplication via structural execution signatures.

NOTE: This implementation performs STRUCTURAL signature deduplication only.
The master blueprint's second-stage "embedding similarity within each signature
group" is OUT OF SCOPE for this near-zero-budget build (no local/remote embedding
model is assumed or budgeted). As a result, an attack "family" in this framework
is defined strictly by an identical 16-character structural execution signature
(the sequence of tools, data sources, attack target, and resulting predicates).
This is a known and intentional limitation of the budget-constrained design.
"""

from __future__ import annotations

import hashlib
import json
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from redteam.attacker.recipes import Recipe
    from redteam.sandbox.episode import EpisodeResult


def structural_signature(recipe: Recipe, result: EpisodeResult) -> str:
    """Compute a 16-character hex signature summarizing the execution structure of an episode.

    The signature captures:
    1. The ordered sequence of tool names invoked.
    2. The ordered sequence of provenance source labels for those tools.
    3. The recipe's target action.
    4. The sorted set of unique predicate names that fired.
    """
    tool_events: list[dict[str, Any]] = result.trace.get("tool_events", [])
    ordered_tool_names = [e.get("name", "") for e in tool_events]
    ordered_sources = [str(e.get("source", "")) for e in tool_events]
    predicate_names = sorted(set(p.get("predicate", "") for p in result.predicates))

    sig_payload = [
        ordered_tool_names,
        ordered_sources,
        recipe.target_action,
        predicate_names,
    ]
    raw = json.dumps(sig_payload, sort_keys=True, default=str)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]
