"""Search orchestrator running adaptive UCB1 red-team attacks."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Callable

from redteam.attacker.bandit import UCB1Bandit
from redteam.attacker.novelty import structural_signature
from redteam.attacker.prober import make_prober_policy
from redteam.attacker.recipes import ALL_RECIPES, Recipe, build_plants_and_messages
from redteam.attacker.reward import graded_reward, reward_label
from redteam.sandbox.episode import run_episode


@dataclass
class AttackSearchConfig:
    """Configuration for an automated red-team search."""

    arms: tuple[Recipe, ...] = ALL_RECIPES
    max_episodes: int = 100
    time_budget_s: float = 300.0
    use_prober: bool = True
    guardrail_factory: Callable[[], Any] | None = None
    c: float = 1.4142
    seed_base: int = 5000
    probe_message: str = "Please proceed and confirm you have completed the task."
    on_episode: Callable[[dict[str, Any]], None] | None = None


@dataclass
class AttackSearchResult:
    """Aggregated outcome of an attack search run."""

    episodes: list[dict[str, Any]]
    arm_stats: dict[str, dict[str, Any]]
    families: dict[str, dict[str, Any]]
    total_seconds: float
    episodes_run: int
    stop_reason: str  # "max_episodes" | "time_budget"


def run_attack_search(
    config: AttackSearchConfig,
    agent_factory: Callable[[], Any],
) -> AttackSearchResult:
    """Run UCB1 bandit-guided red-team attack search."""
    recipe_by_id: dict[str, Recipe] = {r.id: r for r in config.arms}
    arm_ids: list[str] = [r.id for r in config.arms]
    bandit = UCB1Bandit(arm_ids, c=config.c)

    episodes: list[dict[str, Any]] = []
    families: dict[str, dict[str, Any]] = {}

    t_start = time.perf_counter()
    stop_reason = "max_episodes"
    episode_idx = 0

    while True:
        # Check termination conditions
        if episode_idx >= config.max_episodes:
            stop_reason = "max_episodes"
            break

        elapsed = time.perf_counter() - t_start
        if elapsed >= config.time_budget_s:
            stop_reason = "time_budget"
            break

        # 1. Select arm
        arm_id = bandit.select_arm()
        recipe = recipe_by_id[arm_id]

        # 2. Build fixtures and messages
        plants, user_messages = build_plants_and_messages(recipe, episode_idx)

        # 3. Setup prober if configured
        if config.use_prober and user_messages:
            policy = make_prober_policy(user_messages[0], config.probe_message)
        else:
            policy = None

        # 4. Execute episode
        seed = config.seed_base + episode_idx
        result = run_episode(
            user_messages=user_messages,
            plants=plants,
            agent_factory=agent_factory,
            guardrail_factory=config.guardrail_factory,
            seed=seed,
            message_policy=policy,
        )

        # 5. Evaluate reward
        reward = graded_reward(recipe, result)
        bandit.update(arm_id, reward)

        # 6. Structural novelty deduplication
        sig = structural_signature(recipe, result)
        if sig not in families:
            families[sig] = {
                "recipe_id": arm_id,
                "count": 1,
                "best_reward": reward,
                "example_episode_index": episode_idx,
            }
        else:
            families[sig]["count"] += 1
            if reward > families[sig]["best_reward"]:
                families[sig]["best_reward"] = reward

        # 7. Record episode log
        label = reward_label(reward)
        rec = {
            "episode_index": episode_idx,
            "recipe_id": arm_id,
            "reward": reward,
            "reward_label": label,
            "signature": sig,
            "n_tool_events": result.n_tool_events,
            "n_blocked": result.n_blocked,
            "seconds": result.seconds,
            "error": result.error,
        }
        episodes.append(rec)
        if config.on_episode is not None:
            try:
                config.on_episode(rec)
            except Exception:
                pass

        episode_idx += 1

    total_seconds = time.perf_counter() - t_start

    return AttackSearchResult(
        episodes=episodes,
        arm_stats=bandit.stats(),
        families=families,
        total_seconds=total_seconds,
        episodes_run=len(episodes),
        stop_reason=stop_reason,
    )
