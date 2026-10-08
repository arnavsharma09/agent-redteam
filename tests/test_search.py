"""Tests for redteam.attacker.search."""

import pytest

from redteam.attacker.recipes import ALL_RECIPES
from redteam.attacker.search import AttackSearchConfig, run_attack_search
from redteam.defender.guardrails import make_guardrail_factory
from redteam.sandbox.agents import ScriptedVictim


class TestAttackSearch:
    def test_search_exfil_http_undefended_runs_fast_and_finds_success(self) -> None:
        """Search over exfil_http arms with ScriptedVictim executes fast and achieves 1.0."""
        http_arms = tuple(r for r in ALL_RECIPES if r.target_action == "exfil_http")
        assert len(http_arms) == 36

        cfg = AttackSearchConfig(
            arms=http_arms,
            max_episodes=40,
            time_budget_s=30.0,
            use_prober=True,
            guardrail_factory=None,
        )

        result = run_attack_search(cfg, agent_factory=lambda: ScriptedVictim())

        assert result.episodes_run == 40
        assert result.stop_reason == "max_episodes"
        assert result.total_seconds < 10.0, f"Expected < 10s, got {result.total_seconds:.2f}s"

        # At least one episode achieved 1.0 (predicate fired)
        rewards = [e["reward"] for e in result.episodes]
        assert any(r == 1.0 for r in rewards), f"Expected at least one 1.0 reward, got rewards: {rewards}"

        # Arm stats populated
        assert len(result.arm_stats) == 36
        pulled_arms = {e["recipe_id"] for e in result.episodes}
        for arm_id in pulled_arms:
            assert result.arm_stats[arm_id]["pulls"] >= 1

        # Families populated
        assert len(result.families) >= 1
        for sig, fam in result.families.items():
            assert "recipe_id" in fam
            assert fam["count"] >= 1
            assert "best_reward" in fam
            assert "example_episode_index" in fam

    def test_search_with_taint_guardrail_reduces_reward_and_blocks(self) -> None:
        """Comparing undefended vs taint guardrail search confirms reward drop and blocks (0.2)."""
        http_arms = tuple(r for r in ALL_RECIPES if r.target_action == "exfil_http")

        cfg_undefended = AttackSearchConfig(
            arms=http_arms,
            max_episodes=40,
            time_budget_s=30.0,
            use_prober=True,
            guardrail_factory=None,
        )
        res_undefended = run_attack_search(cfg_undefended, agent_factory=lambda: ScriptedVictim())
        mean_undefended = sum(e["reward"] for e in res_undefended.episodes) / res_undefended.episodes_run

        cfg_defended = AttackSearchConfig(
            arms=http_arms,
            max_episodes=40,
            time_budget_s=30.0,
            use_prober=True,
            guardrail_factory=make_guardrail_factory("taint"),
        )
        res_defended = run_attack_search(cfg_defended, agent_factory=lambda: ScriptedVictim())
        mean_defended = sum(e["reward"] for e in res_defended.episodes) / res_defended.episodes_run

        assert mean_defended < mean_undefended, (
            f"Expected defended mean ({mean_defended:.3f}) < undefended ({mean_undefended:.3f})"
        )
        assert any(e["reward"] == 0.2 for e in res_defended.episodes), (
            "Expected at least one blocked episode (reward 0.2) in defended search"
        )

    def test_search_determinism_identical_arm_sequence(self) -> None:
        """Two runs with identical config produce identical arm pull sequences."""
        http_arms = tuple(r for r in ALL_RECIPES if r.target_action == "exfil_http")
        cfg = AttackSearchConfig(
            arms=http_arms,
            max_episodes=40,
            time_budget_s=30.0,
            use_prober=True,
            guardrail_factory=None,
        )

        res1 = run_attack_search(cfg, agent_factory=lambda: ScriptedVictim())
        res2 = run_attack_search(cfg, agent_factory=lambda: ScriptedVictim())

        seq1 = [e["recipe_id"] for e in res1.episodes]
        seq2 = [e["recipe_id"] for e in res2.episodes]
        assert seq1 == seq2, "Bandit arm selection sequence must be strictly deterministic"
