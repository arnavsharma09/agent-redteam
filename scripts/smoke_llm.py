"""smoke_llm.py — Benchmark the ChatCompletionsAgent on a local Ollama model.

Usage::

    py scripts/smoke_llm.py
    py scripts/smoke_llm.py --model qwen2.5:7b --runs 3
    py scripts/smoke_llm.py --baseline                  # 20 benign runs, Wilson CI
    py scripts/smoke_llm.py --seed-check                # empirical seed-reproducibility test
    py scripts/smoke_llm.py --dump-first-request        # print first request JSON

NEVER calls any non-localhost endpoint.
If Ollama is not reachable this script will print a clear error and exit 1.
Any backend error (HTTP 4xx/5xx, connection error, openai exception) aborts
the run with exit code 1 and a clear message; erroring runs are never recorded.
"""

from __future__ import annotations

import argparse
import datetime
import json
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

parser = argparse.ArgumentParser(
    description="Smoke-test ChatCompletionsAgent on a local Ollama model."
)
parser.add_argument("--model", default="qwen2.5:7b", help="Ollama model name (default: qwen2.5:7b)")
parser.add_argument("--runs", type=int, default=5, help="Number of episode runs for normal mode (default: 5)")
parser.add_argument("--base-url", default="http://localhost:11434/v1",
                    help="OpenAI-compatible endpoint (default: http://localhost:11434/v1)")
parser.add_argument("--temperature", type=float, default=0.7)
parser.add_argument("--ctx-limit", type=int, default=4096,
                    help="Agent context-window size for near-ctx warning (default: 4096)")
parser.add_argument(
    "--seed-check", action="store_true",
    help=(
        "After warmup, run the benign task 3x with seed=42 and once each with "
        "seeds 142 and 242.  Compare full (tool-name, args) sequences and prompt "
        "token counts. Print a table then one of: "
        "'IDENTICAL x3 with same seed', 'DIFFERENT with same seed (N of 3 distinct)', "
        "'INCONCLUSIVE (errors)'."
    ),
)
parser.add_argument(
    "--baseline", action="store_true",
    help=(
        "After warmup, run BENIGN_TASK_MESSAGE N times (--baseline-n, default 20) "
        "with clean fixtures and no guardrail. Print completion k/N with Wilson 95%% CI, "
        "mean/median/max seconds, max prompt tokens, predicates fired, near-ctx count, "
        "and a tool-sequence histogram. Append rows to runs/*.jsonl."
    ),
)
parser.add_argument("--baseline-n", type=int, default=20,
                    help="Number of runs for --baseline mode (default: 20)")
parser.add_argument(
    "--dump-first-request", action="store_true",
    help="Print the JSON of the first chat request sent to the model (messages truncated to 300 chars).",
)
args = parser.parse_args()


# ---------------------------------------------------------------------------
# Safety guard: reject any non-localhost URL
# ---------------------------------------------------------------------------

_url_lower = args.base_url.lower()
if not (_url_lower.startswith("http://localhost") or _url_lower.startswith("http://127.")):
    print(
        f"ERROR: --base-url must be a localhost endpoint. Got: {args.base_url!r}\n"
        "This script never calls non-localhost endpoints.",
        file=sys.stderr,
    )
    sys.exit(1)


# ---------------------------------------------------------------------------
# Imports (after sys.path is established by running from repo root)
# ---------------------------------------------------------------------------

sys.path.insert(0, str(Path(__file__).parent.parent))
sys.path.insert(0, str(Path(__file__).parent.parent / "third_party" / "kaggle_pkg"))

from redteam.sandbox.agents import make_chat_agent_factory, make_ollama_backend
from redteam.sandbox.episode import BENIGN_TASK_MESSAGE, run_episode
from redteam.sandbox.llm_backend import ChatBackend, ChatResult
from redteam.replay.stats import wilson_interval


# ---------------------------------------------------------------------------
# Endpoint reachability check
# ---------------------------------------------------------------------------

def _check_reachable(base_url: str, model: str) -> None:
    """Attempt a minimal chat request; exit 1 with clear error on failure."""
    from redteam.sandbox.llm_backend import OpenAICompatBackend
    import openai

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
        print(f"[smoke] Endpoint reachable: {base_url}  model={model}")
    except openai.APIConnectionError as exc:
        print(
            f"\nERROR: Cannot reach {base_url}\n"
            f"Is Ollama running?  Start it with:  ollama serve\n"
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
        # Model-level errors (404, etc.) still mean the server is up.
        print(f"[smoke] Warning: probe call returned an error but server is reachable: {exc}")


_check_reachable(args.base_url, args.model)

# ---------------------------------------------------------------------------
# Build backend + optional spy wrapper
# ---------------------------------------------------------------------------

_backend_inner = make_ollama_backend(args.base_url)
_first_request_printed = False


class _SpyBackend:
    """Print the first request then delegate."""

    def __init__(self, inner: ChatBackend) -> None:
        self._inner = inner

    def chat(self, *, model, messages, tools, temperature, max_tokens, seed):
        global _first_request_printed
        if not _first_request_printed:
            _first_request_printed = True
            safe_msgs = [
                {**m, "content": (m.get("content") or "")[:300]}
                if "content" in m else m
                for m in messages
            ]
            req_dump = dict(model=model, messages=safe_msgs, tools=tools,
                            temperature=temperature, max_tokens=max_tokens, seed=seed)
            print("\n[dump-first-request] ===")
            print(json.dumps(req_dump, indent=2, ensure_ascii=False))
            print("[dump-first-request] ===\n")
        return self._inner.chat(
            model=model, messages=messages, tools=tools,
            temperature=temperature, max_tokens=max_tokens, seed=seed,
        )


_backend: ChatBackend = _SpyBackend(_backend_inner) if args.dump_first_request else _backend_inner


def _factory(run_index: int, *, sample_seed: int | None = None):
    seed = sample_seed if sample_seed is not None else (1000 + run_index)
    return make_chat_agent_factory(
        _backend, args.model,
        temperature=args.temperature,
        ctx_limit=args.ctx_limit,
        sample_seed=seed,
    )


# ---------------------------------------------------------------------------
# Core: run one episode, abort on error
# ---------------------------------------------------------------------------

def _run_one(run_idx: int, *, sample_seed: int | None = None, label: str = "") -> dict:
    """Run one episode. If it returns with error, print and exit 1."""
    result = run_episode(
        user_messages=[BENIGN_TASK_MESSAGE],
        plants=(),
        agent_factory=_factory(run_idx, sample_seed=sample_seed),
        seed=run_idx,
    )
    if result.error:
        print(
            f"\nERROR{' [' + label + ']' if label else ''}: episode returned an error:\n"
            f"{result.error}",
            file=sys.stderr,
        )
        sys.exit(1)
    tool_events = result.trace.get("tool_events", [])
    tool_seq = " -> ".join(e.get("name", "?") for e in tool_events if e.get("ok"))
    if not tool_seq:
        tool_seq = "(none)"
    brief_written = any(
        e.get("name") == "fs.write"
        and (e.get("args") or {}).get("path") == "daily_brief.txt"
        and e.get("ok")
        for e in tool_events
    )
    summary = result.agent_summary or {}
    # Full tool + args list for seed-check comparison.
    tool_arg_seq = [
        (e.get("name", "?"), json.dumps(e.get("args", {}), sort_keys=True))
        for e in tool_events if e.get("ok")
    ]
    return {
        "run": run_idx,
        "seconds": result.seconds,
        "n_tool_events": result.n_tool_events,
        "tool_sequence": tool_seq,
        "tool_arg_seq": tool_arg_seq,
        "brief_written": brief_written,
        "max_prompt_tokens": summary.get("max_prompt_tokens"),
        "n_near_ctx": summary.get("n_near_ctx", 0),
        "n_malformed": summary.get("n_malformed", 0),
        "predicates": [p["predicate"] for p in result.predicates],
        "error": result.error,
        "agent_summary": summary,
    }


def _print_row(r: dict, idx: int | None = None) -> None:
    i = r["run"] if idx is None else idx
    print(
        f"{i:>3}  {r['seconds']:>6.2f}  {r['n_tool_events']:>6}  "
        f"{r['tool_sequence']:<40}  {'yes' if r['brief_written'] else 'NO':>6}  "
        f"{str(r['max_prompt_tokens']) if r['max_prompt_tokens'] is not None else '?':>5}  "
        f"{r['n_near_ctx']:>4}  {r['n_malformed']:>3}  {r['predicates'] or '-'}"
    )


# ---------------------------------------------------------------------------
# A1b: Warmup (one throwaway episode, not recorded)
# ---------------------------------------------------------------------------

print("[smoke] Running warmup episode...")
_warmup = run_episode(
    user_messages=[BENIGN_TASK_MESSAGE],
    plants=(),
    agent_factory=_factory(9999, sample_seed=999),
    seed=9999,
)
if _warmup.error:
    print(f"\nERROR [warmup]: {_warmup.error}", file=sys.stderr)
    sys.exit(1)
print("[warmup done]")


# ---------------------------------------------------------------------------
# A1b: --seed-check
# ---------------------------------------------------------------------------

if args.seed_check:
    FIXED = 42
    print("\n[seed-check] Running 5 episodes (3×seed=42, 1×seed=142, 1×seed=242)…")
    runs_sc = [_run_one(i, sample_seed=FIXED, label=f"A{i+1}") for i in range(3)]
    runs_sc.append(_run_one(3, sample_seed=142, label="B1"))
    runs_sc.append(_run_one(4, sample_seed=242, label="B2"))

    print(f"\n{'label':<8} {'seed':>6}  {'seq':<45}  {'ptok':>5}")
    labels = ["A1", "A2", "A3", "B1", "B2"]
    seeds_used = [FIXED, FIXED, FIXED, 142, 242]
    for lbl, s, r in zip(labels, seeds_used, runs_sc):
        print(f"{lbl:<8} {s:>6}  {r['tool_sequence']:<45}  {str(r['max_prompt_tokens']):>5}")

    # Compare by (tool_name, args_json) + prompt_tokens
    seqs_a = [tuple(map(tuple, r["tool_arg_seq"])) for r in runs_sc[:3]]
    ptoks_a = [r["max_prompt_tokens"] for r in runs_sc[:3]]
    if any(r["tool_arg_seq"] == [] for r in runs_sc[:3]):
        verdict = "INCONCLUSIVE (errors)"
    elif seqs_a[0] == seqs_a[1] == seqs_a[2] and ptoks_a[0] == ptoks_a[1] == ptoks_a[2]:
        verdict = "IDENTICAL x3 with same seed"
    else:
        n_distinct = len(set(seqs_a))
        verdict = f"DIFFERENT with same seed ({n_distinct} of 3 distinct)"
    print(f"\n[seed-check] {verdict}")
    print()


# ---------------------------------------------------------------------------
# A1c: --baseline
# ---------------------------------------------------------------------------

if args.baseline:
    import statistics

    N = args.baseline_n
    print(f"\n[baseline] Running {N} benign episodes (no guardrail, clean fixtures)…")
    print(f"\n{'run':>3}  {'s':>6}  {'events':>6}  {'seq':<40}  {'brief?':>6}  {'ptok':>5}  {'nctx':>4}  {'bad':>3}  predicates")
    print("-" * 100)

    baseline_results: list[dict] = []
    for i in range(N):
        r = _run_one(i, sample_seed=2000 + i, label=f"baseline/{i}")
        _print_row(r, idx=i)
        baseline_results.append(r)

    k = sum(1 for r in baseline_results if r["brief_written"] and not r["predicates"])
    lo, hi = wilson_interval(k, N)
    seconds_list = [r["seconds"] for r in baseline_results]
    ptoks = [r["max_prompt_tokens"] for r in baseline_results if r["max_prompt_tokens"] is not None]
    total_pred = sum(len(r["predicates"]) for r in baseline_results)
    near_ctx = sum(r["n_near_ctx"] for r in baseline_results)

    # Sequence histogram
    seq_hist: dict[str, int] = {}
    for r in baseline_results:
        seq_hist[r["tool_sequence"]] = seq_hist.get(r["tool_sequence"], 0) + 1

    print("-" * 100)
    print(f"\n[baseline] Completion (brief written AND no predicates): {k}/{N}")
    print(f"[baseline] Wilson 95% CI: [{lo:.3f}, {hi:.3f}]")
    print(f"[baseline] Seconds: mean={statistics.mean(seconds_list):.2f}  "
          f"median={statistics.median(seconds_list):.2f}  max={max(seconds_list):.2f}")
    print(f"[baseline] Max prompt tokens: {max(ptoks) if ptoks else '?'}")
    print(f"[baseline] Predicates fired: {total_pred}  Near-ctx hops: {near_ctx}")
    print("[baseline] Tool-sequence histogram:")
    for seq, cnt in sorted(seq_hist.items(), key=lambda kv: -kv[1]):
        print(f"  {cnt:>3}x  {seq}")

    # Save JSONL
    runs_dir = Path(__file__).parent.parent / "runs"
    runs_dir.mkdir(exist_ok=True)
    ts = datetime.datetime.now(tz=datetime.timezone.utc).strftime("%Y%m%dT%H%M%S")
    safe_model = args.model.replace(":", "_").replace("/", "_")
    out_path = runs_dir / f"baseline_{safe_model}_{ts}.jsonl"
    with open(out_path, "w", encoding="utf-8") as f:
        for r in baseline_results:
            row = {k: v for k, v in r.items() if k != "tool_arg_seq"}
            f.write(json.dumps(row, ensure_ascii=True) + "\n")
    print(f"\n[baseline] Results saved to {out_path}")

    # Don't run normal loop after baseline
    sys.exit(0)


# ---------------------------------------------------------------------------
# Normal --runs loop
# ---------------------------------------------------------------------------

print(
    f"\n{'run':>3}  {'s':>6}  {'events':>6}  {'seq':<40}  "
    f"{'brief?':>6}  {'ptok':>5}  {'nctx':>4}  {'bad':>3}  predicates"
)
print("-" * 100)

run_results: list[dict] = []
for run_idx in range(args.runs):
    r = _run_one(run_idx)
    _print_row(r)
    run_results.append(r)

# Averages
n = len(run_results)
if n:
    avg_s = sum(r["seconds"] for r in run_results) / n
    avg_events = sum(r["n_tool_events"] for r in run_results) / n
    n_brief = sum(1 for r in run_results if r["brief_written"])
    total_pred = sum(len(r["predicates"]) for r in run_results)
    print("-" * 100)
    print(
        f"{'avg':>3}  {avg_s:>6.2f}  {avg_events:>6.1f}  "
        f"{'':40}  {n_brief}/{n} brief  total_pred={total_pred}"
    )

# Save JSONL
runs_dir = Path(__file__).parent.parent / "runs"
runs_dir.mkdir(exist_ok=True)
ts = datetime.datetime.now(tz=datetime.timezone.utc).strftime("%Y%m%dT%H%M%S")
safe_model = args.model.replace(":", "_").replace("/", "_")
out_path = runs_dir / f"smoke_{safe_model}_{ts}.jsonl"

with open(out_path, "w", encoding="utf-8") as f:
    for r in run_results:
        row = {k: v for k, v in r.items() if k != "tool_arg_seq"}
        f.write(json.dumps(row, ensure_ascii=True) + "\n")

print(f"\n[smoke] Results saved to {out_path}")
print(
    "\n[smoke] NOTE: If Ollama was not reachable, run this script from the repo root "
    "after starting Ollama:\n"
    "  ollama serve\n"
    f"  py scripts/smoke_llm.py --model {args.model} --runs {args.runs}"
)
