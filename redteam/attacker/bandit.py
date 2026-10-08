"""UCB1 multi-armed bandit for adaptive recipe exploration/exploitation."""

from __future__ import annotations

import math
from typing import Sequence


class UCB1Bandit:
    """UCB1 bandit over a discrete set of arms (recipes)."""

    def __init__(self, arm_ids: Sequence[str], c: float = 1.4142) -> None:
        self.arm_ids: list[str] = list(arm_ids)
        self.c: float = c
        self.pulls: dict[str, int] = {a: 0 for a in self.arm_ids}
        self.total_reward: dict[str, float] = {a: 0.0 for a in self.arm_ids}
        self.total_pulls: int = 0

    def select_arm(self) -> str:
        """Select next arm. Untried arms in arm_ids order, then argmax UCB1 score."""
        # 1. Round-robin through untried arms in order
        for arm_id in self.arm_ids:
            if self.pulls[arm_id] == 0:
                return arm_id

        # 2. Argmax of UCB1: mean_reward[a] + c * sqrt(2 * ln(total_pulls) / counts[a])
        best_arm = self.arm_ids[0]
        best_score = -float("inf")
        ln_total = math.log(self.total_pulls)

        for arm_id in self.arm_ids:
            n_a = self.pulls[arm_id]
            mean_r = self.total_reward[arm_id] / n_a
            score = mean_r + self.c * math.sqrt(2.0 * ln_total / n_a)
            if score > best_score:
                best_score = score
                best_arm = arm_id

        return best_arm

    def update(self, arm_id: str, reward: float) -> None:
        """Record reward observation for arm_id."""
        if arm_id not in self.pulls:
            raise KeyError(f"Unknown arm_id: {arm_id}")
        self.pulls[arm_id] += 1
        self.total_reward[arm_id] += float(reward)
        self.total_pulls += 1

    def stats(self) -> dict[str, dict[str, float | int]]:
        """Return pulls, mean_reward, and total_reward per arm."""
        return {
            a: {
                "pulls": self.pulls[a],
                "mean_reward": (self.total_reward[a] / self.pulls[a]) if self.pulls[a] > 0 else 0.0,
                "total_reward": self.total_reward[a],
            }
            for a in self.arm_ids
        }

    def best_arms(self, k: int = 10) -> list[tuple[str, float]]:
        """Return up to k arms with pulls >= 1 sorted descending by mean_reward."""
        tested = [
            (a, self.total_reward[a] / self.pulls[a])
            for a in self.arm_ids
            if self.pulls[a] >= 1
        ]
        tested.sort(key=lambda item: item[1], reverse=True)
        return tested[:k]
