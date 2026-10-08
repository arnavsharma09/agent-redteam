"""Measure benign-task completion with local LLM agent across guardrails.

Runs T_brief, T_email, and T_post across configured guardrails (default: none, naive, taint)
on clean fixtures with no plants, evaluating deterministic completion rates and Wilson 95% CIs.
"""

from __future__ import annotations

import argparse
from collections import Counter
import datetime
import json
from pathlib import Path
import sys
from typing import Any

# Ensure repo root and SDK are on sys.path
_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))
_SDK_PATH = _REPO_ROOT / "third_party" / "kaggle_pkg"
if _SDK_PATH.exists() and str(_SDK_PATH) not in sys.path:
    sys.path.insert(0, str(_SDK_PATH))

from redteam.benign.checks import (
    TASKS,
    TASK_BRIEF,
    TASK_EMAIL,
    TASK_MESSAGES,
    TASK_POST,
    check_task_success,
)
from redteam.defender.guardrails import make_guardrail_factory
from redteam.replay.stats import wilson_interval
from redteam.sandbox.agents import make_chat_agent_factory, make_ollama_backend
from redteam.sandbox.episode import BENIGN_TASK_MESSAGE, run_episode


def parse_args(args: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Measure benign-task completion across guardrails using a local LLM agent."
    )
    parser.add_argument(
        "--model",
        default="qwen2.5:7b",
        help="Ollama model name (default: qwen2.5:7b)",
    )
    parser.add_argument(
        "--runs",
        type=int,
        default=20,
        help="Number of runs per task per guardrail (default: 20)",
    )
    parser.add_argument(
        "--guardrails",
        default="none,naive,taint",
        help="Comma-separated guardrails to evaluate (default: none,naive,taint)",
    )
    parser.add_argument(
        "--tasks",
        default="T_brief,T_email,T_post",
        help="Comma-separated subset of tasks to evaluate (default: T_brief,T_email,T_post)",
    )
    parser.add_argument(
        "--seed-base",
        type=int,
        default=7000,
        help="Base seed for episodes (default: 7000)",
    )
    parser.add_argument(
        "--out",
        default=None,
        help="Output JSONL filepath (default: runs/benign_<model>_<timestamp>.jsonl)",
    )
    parser.add_argument(
        "--base-url",
        default="http://localhost:11434/v1",
        help="Local Ollama OpenAI-compatible endpoint (default: http://localhost:11434/v1)",
    )
    return parser.parse_args(args)


def check_reachable(base_url: str, model: str) -> None:
    """Ensure Ollama local server is reachable, exit 1 if not."""
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
        print(f"[benign-eval] Endpoint reachable: {base_url}  model={model}")
    except openai.APIConnectionError as exc:
        print(
            f"\nERROR: Cannot reach {base_url}\n"
            f"Is Ollama running? Start it with:  ollama serve\n"
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
        print(f"[benign-eval] Note: probe returned error but server is reachable: {exc}")


def _extract_block_reasons(result: Any) -> list[str]:
    """Extract reasons for non-ALLOW decisions from guardrail_log or trace."""
    reasons: list[str] = []
    if getattr(result, "guardrail_log", None):
        for entry in result.guardrail_log:
            verdict = str(entry.get("verdict", "")).upper()
            if verdict not in ("ALLOW", ""):
                r = entry.get("reason")
                if r:
                    reasons.append(str(r))
    else:
        # Fall back to error messages on blocked tool events in trace
        for ev in result.trace.get("tool_events", []):
            if not ev.get("ok") and ev.get("error"):
                reasons.append(str(ev["error"]))
    return reasons


def main(argv: list[str] | None = None) -> None:
    args = parse_args(argv)

    # 1. Validate tasks and guardrails
    guardrail_names = [g.strip() for g in args.guardrails.split(",") if g.strip()]
    tasks = [t.strip() for t in args.tasks.split(",") if t.strip()]
    invalid_tasks = [t for t in tasks if t not in TASKS]
    if invalid_tasks or not tasks:
        print(
            f"ERROR: Invalid task(s): {invalid_tasks}. Allowed tasks: {list(TASKS)}",
            file=sys.stderr,
        )
        sys.exit(1)

    # 2. Reachability check
    check_reachable(args.base_url, args.model)

    # 3. Output file setup
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    clean_model_name = args.model.replace(":", "_").replace("/", "_")
    if args.out:
        out_path = Path(args.out)
    else:
        out_path = _REPO_ROOT / "runs" / f"benign_{clean_model_name}_{timestamp}.jsonl"
    out_path.parent.mkdir(parents=True, exist_ok=True)

    # 4. Backend and Warmup
    backend = make_ollama_backend(base_url=args.base_url)
    warmup_agent_factory = make_chat_agent_factory(backend, model=args.model, temperature=0.7)

    print("[benign-eval] Running throwaway warmup episode...")
    warmup_res = run_episode(
        user_messages=[BENIGN_TASK_MESSAGE],
        plants=(),
        agent_factory=warmup_agent_factory,
        seed=args.seed_base,
    )
    if warmup_res.error:
        print(f"\nERROR [warmup]: backend error encountered:\n{warmup_res.error}", file=sys.stderr)
        sys.exit(1)
    print(f"[benign-eval] Warmup completed in {warmup_res.seconds:.2f}s.")

    total_episodes = len(tasks) * len(guardrail_names) * args.runs
    print(
        f"[benign-eval] Starting evaluation: {len(tasks)} tasks x {len(guardrail_names)} guardrails x "
        f"{args.runs} runs = {total_episodes} episodes total."
    )
    print(f"[benign-eval] Streaming JSONL to: {out_path}")

    # Track results for reporting
    records: list[dict[str, Any]] = []

    out_file = open(out_path, "a", encoding="utf-8")
    try:
        episode_count = 0
        for task in tasks:
            user_msg = TASK_MESSAGES[task]
            for guardrail_name in guardrail_names:
                for i in range(args.runs):
                    episode_count += 1
                    seed = args.seed_base + i
                    sample_seed = seed
                    guardrail_factory = make_guardrail_factory(guardrail_name)
                    agent_factory = make_chat_agent_factory(
                        backend,
                        model=args.model,
                        temperature=0.7,
                        sample_seed=sample_seed,
                    )

                    result = run_episode(
                        user_messages=[user_msg],
                        plants=(),
                        agent_factory=agent_factory,
                        guardrail_factory=guardrail_factory,
                        seed=seed,
                    )

                    # Abort on backend error
                    if result.error:
                        print(
                            f"\nERROR: episode {episode_count} (task={task}, guardrail={guardrail_name}, "
                            f"run={i}) failed with backend error:\n{result.error}",
                            file=sys.stderr,
                        )
                        sys.exit(1)

                    success = check_task_success(task, result)
                    tool_events = result.trace.get("tool_events", [])
                    tool_sequence = [str(ev.get("name")) for ev in tool_events if ev.get("name")]
                    block_reasons = _extract_block_reasons(result)

                    row: dict[str, Any] = {
                        "task": task,
                        "guardrail": guardrail_name,
                        "run": i,
                        "seed": seed,
                        "success": bool(success),
                        "n_tool_events": result.n_tool_events,
                        "n_blocked": result.n_blocked,
                        "fired": result.fired,
                        "tool_sequence": tool_sequence,
                        "block_reasons": block_reasons,
                        "seconds": round(result.seconds, 3),
                        "error": result.error,
                    }
                    records.append(row)
                    out_file.write(json.dumps(row, ensure_ascii=False) + "\n")
                    out_file.flush()
    finally:
        out_file.close()

    # 4. End-of-run reporting
    print("\n" + "=" * 70)
    print("BENIGN TASK COMPLETION EVALUATION")
    print("=" * 70)

    # Table 1: Success rates & Wilson 95% CIs
    header1 = f"{'Task':<10} | {'Guardrail':<10} | {'Success':<9} | {'Rate':<8} | {'Wilson 95% CI':<18}"
    print(header1)
    print("-" * len(header1))

    for task in tasks:
        for guardrail_name in guardrail_names:
            matching = [r for r in records if r["task"] == task and r["guardrail"] == guardrail_name]
            k = sum(1 for r in matching if r["success"])
            n = len(matching)
            rate_str = f"{(k / n * 100):.1f}%" if n > 0 else "0.0%"
            lo, hi = wilson_interval(k, n) if n > 0 else (0.0, 0.0)
            ci_str = f"[{lo:.3f}, {hi:.3f}]"
            print(f"{task:<10} | {guardrail_name:<10} | {f'{k}/{n}':<9} | {rate_str:<8} | {ci_str:<18}")

    # Table 2: Total blocks and top 3 reasons
    print("\n" + "=" * 70)
    print("GUARDRAIL BLOCKS & TOP REASONS")
    print("=" * 70)
    header2 = f"{'Task':<10} | {'Guardrail':<10} | {'Total Blocks':<12} | {'Top 3 Block Reasons'}"
    print(header2)
    print("-" * len(header2))

    for task in tasks:
        for guardrail_name in guardrail_names:
            matching = [r for r in records if r["task"] == task and r["guardrail"] == guardrail_name]
            total_blocks = sum(r["n_blocked"] for r in matching)
            all_reasons: list[str] = []
            for r in matching:
                all_reasons.extend(r["block_reasons"])
            if all_reasons:
                reason_counts = Counter(all_reasons).most_common(3)
                top_reasons_str = ", ".join(f"{reason} ({count})" for reason, count in reason_counts)
            else:
                top_reasons_str = "none"
            print(f"{task:<10} | {guardrail_name:<10} | {total_blocks:<12} | {top_reasons_str}")

    # Mean seconds overall
    if records:
        mean_sec = sum(r["seconds"] for r in records) / len(records)
        print(f"\nMean seconds per episode overall: {mean_sec:.2f}s")
    print("=" * 70 + "\n")


if __name__ == "__main__":
    main()
