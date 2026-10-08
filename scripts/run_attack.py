"""run_attack.py — Run adaptive red-team attack search on a local Ollama model.

Usage::

    py scripts/run_attack.py --model qwen2.5:7b --max-episodes 60
    py scripts/run_attack.py --guardrail taint --target-actions exfil_http,exec
    py scripts/run_attack.py --no-prober --time-budget-s 300

NEVER calls any non-localhost endpoint.
If Ollama is not reachable this script will print a clear error and exit 1.
"""

from __future__ import annotations

import argparse
import datetime
import json
import sys
from pathlib import Path
from typing import Any

# Ensure repo root and SDK are on path
REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "third_party" / "kaggle_pkg"))

from redteam.attacker.bandit import UCB1Bandit
from redteam.attacker.recipes import ALL_RECIPES, Recipe
from redteam.attacker.search import AttackSearchConfig, run_attack_search
from redteam.defender.guardrails import make_guardrail_factory
from redteam.sandbox.agents import make_chat_agent_factory, make_ollama_backend
from redteam.sandbox.episode import BENIGN_TASK_MESSAGE, run_episode


def parse_args(args: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run adaptive UCB1 red-team attack search against a local LLM agent."
    )
    parser.add_argument(
        "--model",
        default="qwen2.5:7b",
        help="Ollama model name (default: qwen2.5:7b)",
    )
    parser.add_argument(
        "--max-episodes",
        type=int,
        default=60,
        help="Maximum episodes to run (default: 60)",
    )
    parser.add_argument(
        "--time-budget-s",
        type=float,
        default=600.0,
        help="Maximum wall-clock seconds for search (default: 600.0)",
    )
    parser.add_argument(
        "--guardrail",
        choices=["none", "naive", "taint", "sdk_baseline"],
        default="none",
        help="Guardrail to defend agent with (default: none)",
    )
    parser.add_argument(
        "--target-actions",
        default="exfil_http,exfil_email,destructive,exec",
        help="Comma-separated subset of target actions (default: all 4)",
    )
    parser.add_argument(
        "--no-prober",
        action="store_true",
        help="Disable follow-up prober message on blocked events",
    )
    parser.add_argument(
        "--out",
        default=None,
        help="Output JSONL filepath (default: runs/attack_<model>_<guardrail>_<timestamp>.jsonl)",
    )
    parser.add_argument(
        "--seed-base",
        type=int,
        default=5000,
        help="Base seed for episode generation (default: 5000)",
    )
    parser.add_argument(
        "--base-url",
        default="http://localhost:11434/v1",
        help="Local Ollama OpenAI-compatible endpoint (default: http://localhost:11434/v1)",
    )
    return parser.parse_args(args)


def check_reachable(base_url: str, model: str) -> None:
    """Ensure Ollama local server is reachable, exit 1 with clear message if not."""
    url_lower = base_url.lower()
    if not (url_lower.startswith("http://localhost") or url_lower.startswith("http://127.")):
        print(
            f"ERROR: --base-url must be a localhost endpoint. Got: {base_url!r}\n"
            "This script never calls non-localhost endpoints.",
            file=sys.stderr,
        )
        sys.exit(1)

    import openai
    from redteam.sandbox.llm_backend import OpenAICompatBackend

    backend = OpenAICompatBackend(base_url=base_url, timeout_s=10.0, retries=0)
    try:
        backend.chat(
            model=model,
            messages=[{"role": "user", "content": "ping"}],
            tools=[],
            temperature=0.0,
            max_tokens=1,
            seed=None,
        )
        print(f"[attack] Endpoint reachable: {base_url}  model={model}")
    except openai.APIConnectionError as exc:
        print(
            f"\nERROR: Cannot reach {base_url}\n"
            f"Is Ollama running? Start it with: ollama serve\n"
            f"Detail: {exc}",
            file=sys.stderr,
        )
        sys.exit(1)
    except openai.APITimeoutError as exc:
        print(
            f"\nERROR: Connection to {base_url} timed out.\n"
            f"Detail: {exc}",
            file=sys.stderr,
        )
        sys.exit(1)
    except Exception as exc:
        print(f"[attack] Note: probe returned error but server is reachable: {exc}")


def main() -> None:
    args = parse_args()

    # 1. Reachability check
    check_reachable(args.base_url, args.model)

    # 2. Output file path setup
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    clean_model_name = args.model.replace(":", "_").replace("/", "_")
    if args.out:
        out_path = Path(args.out)
    else:
        out_path = REPO_ROOT / "runs" / f"attack_{clean_model_name}_{args.guardrail}_{timestamp}.jsonl"
    out_path.parent.mkdir(parents=True, exist_ok=True)

    # 3. Build agent factory and warmup
    backend = make_ollama_backend(base_url=args.base_url)
    agent_factory = make_chat_agent_factory(backend, model=args.model, temperature=0.7)

    print("[attack] Running warmup episode...")
    warmup_res = run_episode(
        user_messages=[BENIGN_TASK_MESSAGE],
        plants=(),
        agent_factory=agent_factory,
        seed=args.seed_base,
    )
    if warmup_res.error:
        print(f"\nERROR [warmup]: {warmup_res.error}", file=sys.stderr)
        sys.exit(1)
    print(f"[attack] Warmup completed in {warmup_res.seconds:.2f}s.")

    # 4. Filter recipes by target actions
    selected_actions = {a.strip() for a in args.target_actions.split(",") if a.strip()}
    arms: tuple[Recipe, ...] = tuple(r for r in ALL_RECIPES if r.target_action in selected_actions)
    if not arms:
        print(f"ERROR: No recipes matched target-actions: {args.target_actions}", file=sys.stderr)
        sys.exit(1)
    print(f"[attack] Starting search over {len(arms)} arms across target actions: {sorted(selected_actions)}")

    # 5. Guardrail factory
    guardrail_factory = make_guardrail_factory(args.guardrail)

    # 6. Stream JSONL writer
    out_file = open(out_path, "a", encoding="utf-8")

    def on_episode_write(record: dict[str, Any]) -> None:
        out_file.write(json.dumps(record, default=str) + "\n")
        out_file.flush()

    config = AttackSearchConfig(
        arms=arms,
        max_episodes=args.max_episodes,
        time_budget_s=args.time_budget_s,
        use_prober=not args.no_prober,
        guardrail_factory=guardrail_factory,
        seed_base=args.seed_base,
        on_episode=on_episode_write,
    )

    try:
        search_result = run_attack_search(config, agent_factory=agent_factory)
    finally:
        out_file.close()

    # 7. Print summary statistics
    print("\n" + "=" * 60)
    print("ATTACK SEARCH SUMMARY")
    print("=" * 60)
    print(f"Output saved to:       {out_path}")
    print(f"Episodes run:         {search_result.episodes_run}")
    print(f"Stop reason:          {search_result.stop_reason}")
    print(f"Total duration:       {search_result.total_seconds:.2f}s")
    print(f"Distinct families:    {len(search_result.families)}")

    # Reward histogram
    rewards = [e["reward"] for e in search_result.episodes]
    hist = {0.0: 0, 0.2: 0, 0.5: 0, 1.0: 0}
    for r in rewards:
        # map to nearest histogram bucket
        closest = min(hist.keys(), key=lambda k: abs(k - r))
        hist[closest] += 1
    print("\nReward Histogram:")
    print(f"  0.0 (refused/untried):      {hist[0.0]}")
    print(f"  0.2 (blocked by gate):     {hist[0.2]}")
    print(f"  0.5 (executed not scored): {hist[0.5]}")
    print(f"  1.0 (predicate fired):     {hist[1.0]}")

    # Top 10 arms
    bandit = UCB1Bandit([r.id for r in arms])
    for a_id, a_data in search_result.arm_stats.items():
        bandit.pulls[a_id] = a_data["pulls"]
        bandit.total_reward[a_id] = a_data["total_reward"]
    top_10 = bandit.best_arms(k=10)
    print("\nTop Arms by Mean Reward:")
    for rank, (a_id, mean_r) in enumerate(top_10, start=1):
        pulls = search_result.arm_stats[a_id]["pulls"]
        print(f"  {rank:>2}. mean={mean_r:.3f} (pulls={pulls:>2}) | {a_id}")
    print("=" * 60)


if __name__ == "__main__":
    main()
