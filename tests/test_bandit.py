"""Tests for redteam.attacker.bandit."""

import pytest

from redteam.attacker.bandit import UCB1Bandit


class TestUCB1Bandit:
    def test_all_arms_tried_once_before_any_tried_twice(self) -> None:
        """Bandit must try all arms in sequence order before repeating any arm."""
        arms = ["arm_1", "arm_2", "arm_3", "arm_4", "arm_5"]
        bandit = UCB1Bandit(arms)

        selected_initial = []
        for _ in range(len(arms)):
            arm = bandit.select_arm()
            selected_initial.append(arm)
            bandit.update(arm, 0.5)

        assert selected_initial == arms, f"Initial pulls must match arms order: {selected_initial}"

    def test_exploitation_prefers_high_reward_arm(self) -> None:
        """Arm with 1.0 reward must receive >= 70% of total pulls over 200 pulls."""
        arms = ["A", "B", "C"]
        bandit = UCB1Bandit(arms, c=1.4142)

        # Reward map: A=1.0, B=0.0, C=0.0
        rewards = {"A": 1.0, "B": 0.0, "C": 0.0}

        for _ in range(200):
            arm = bandit.select_arm()
            bandit.update(arm, rewards[arm])

        stats = bandit.stats()
        pulls_a = stats["A"]["pulls"]
        assert pulls_a >= 140, f"Arm A should have >= 70% pulls (got {pulls_a}/200 = {pulls_a/200:.2%})"

        best = bandit.best_arms(k=2)
        assert best[0][0] == "A"
        assert best[0][1] == 1.0

    def test_stats_and_best_arms_correctness(self) -> None:
        """Verify stats dictionary and best_arms ranking."""
        bandit = UCB1Bandit(["x", "y", "z"])
        bandit.update("x", 1.0)
        bandit.update("x", 0.5)
        bandit.update("y", 0.2)

        stats = bandit.stats()
        assert stats["x"]["pulls"] == 2
        assert stats["x"]["total_reward"] == 1.5
        assert stats["x"]["mean_reward"] == 0.75
        assert stats["y"]["pulls"] == 1
        assert stats["y"]["mean_reward"] == 0.2
        assert stats["z"]["pulls"] == 0
        assert stats["z"]["mean_reward"] == 0.0

        best = bandit.best_arms(k=2)
        assert len(best) == 2
        assert best[0] == ("x", 0.75)
        assert best[1] == ("y", 0.2)
