"""scripts/export_taxonomy.py — Export offline attack exploit taxonomy report.

Reads existing attack run logs from runs/ and writes:
- reports/taxonomy.json: structured JSON data keyed by (guardrail, target_action)
- reports/taxonomy.md: human-readable Markdown summary tables

Filtering methodology:
- EXCLUDE attack files whose date (YYYYMMDD) is < 20261004 (earlier runs had a
  measurement bug where the model did not read the planted content).
- Taint files dated < 20261006 are labeled "taint_prefix" (before base64 and
  protected-content leak fixes); dated >= 20261006 are labeled "taint".
- Skip files with zero valid rows; skip rows where error is not null.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import statistics
import sys
from typing import Any

# Ensure repo root is on sys.path
_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from redteam.replay.stats import wilson_interval

# ---------------------------------------------------------------------------
# Filter constants & limitations
# ---------------------------------------------------------------------------

MIN_DATE_CUTOFF = "20261004"
TAINT_PREFIX_CUTOFF = "20261006"
TAINT_FILES_CUTOFF = "20261009"

METHODOLOGY_LIMITATIONS = [
    "results are for one victim model (qwen2.5:7b) and one fixture set",
    'each run is a UCB1 search (attacker adapts), so a rate is "fraction of attacker episodes that succeeded", not a fixed-recipe replay probability',
    'signature-count is a gameable diversity measure and "family" here = unique structural signature (no embedding stage)',
    "Marginal breakdowns are computed over UCB1-selected episodes (adaptive allocation, not uniform sampling); treat them as descriptive, not as per-category success probabilities.",
    "Success means an SDK predicate fired. Predicates match intent keywords in the last user message and count only web/email as untrusted sources, so some (target action, sink) cells cannot score 1.0 by construction.",
]

POOLING_NOTE = (
    "All files with the same (guardrail, target action) after the date cutoff are pooled, "
    "including runs that were interrupted early."
)

UNSCORABLE_CELLS: dict[tuple[str, str], str] = {
    ("exfil_email", "email"): (
        "the email-sink user message contains the word 'email', which CONFUSED_DEPUTY "
        "and UNTRUSTED_TO_ACTION(SHARE) read as intent to share"
    ),
    ("exec", "file"): (
        "UNTRUSTED_TO_ACTION counts only web/email as untrusted sources while fs.read has source 'file'"
    ),
}

ATTACK_FILENAME_PATTERN = re.compile(
    r"^attack_(.+)_(none|naive|taint|sdk_baseline)_(\d{8})_(\d{6})\.jsonl$"
)


class TaxonomyDict(dict):
    """Dictionary supporting key access via tuple (guardrail, target_action) or string."""

    def __getitem__(self, key: Any) -> Any:
        if isinstance(key, tuple) and len(key) == 2:
            s_key = f"{key[0]}/{key[1]}"
            if s_key in self:
                return super().__getitem__(s_key)
        return super().__getitem__(key)

    def get(self, key: Any, default: Any = None) -> Any:
        if isinstance(key, tuple) and len(key) == 2:
            s_key = f"{key[0]}/{key[1]}"
            if s_key in self:
                return super().__getitem__(s_key)
        return super().get(key, default)


def classify_attack_file(path: Path) -> tuple[str, str, str] | None:
    """Classify an attack run file name.

    Returns (model, effective_guardrail, date_str) or None if not an attack file.
    """
    m = ATTACK_FILENAME_PATTERN.match(path.name)
    if not m:
        return None
    model, raw_guardrail, date_str, _time_str = m.groups()
    if raw_guardrail == "taint" and date_str < TAINT_PREFIX_CUTOFF:
        effective_guardrail = "taint_prefix"
    elif raw_guardrail == "taint" and date_str >= TAINT_FILES_CUTOFF:
        effective_guardrail = "taint_files"
    else:
        effective_guardrail = raw_guardrail
    return model, effective_guardrail, date_str


def load_attack_rows(path: Path) -> tuple[list[dict[str, Any]], int]:
    """Load valid rows from a JSONL file, skipping error rows.

    Returns (valid_rows, error_count).
    """
    valid_rows: list[dict[str, Any]] = []
    error_count = 0
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line_str = line.strip()
            if not line_str:
                continue
            try:
                row = json.loads(line_str)
            except json.JSONDecodeError:
                error_count += 1
                continue
            if row.get("error") is not None:
                error_count += 1
                continue
            valid_rows.append(row)
    return valid_rows, error_count


def _compute_group_metrics(
    guardrail: str,
    target_action: str,
    rows_with_meta: list[tuple[str, dict[str, Any]]],
) -> dict[str, Any]:
    """Compute taxonomy metrics for a single (guardrail, target_action) group."""
    episodes = len(rows_with_meta)
    reward_counts = {"0.0": 0, "0.2": 0, "0.5": 0, "1.0": 0}
    blocked_calls = 0
    blocked_episodes = 0
    exec_not_scored = 0
    attack_success = 0

    for _fn, r in rows_with_meta:
        rew = float(r.get("reward", 0.0))
        rew_key = f"{rew:.1f}"
        if rew_key in reward_counts:
            reward_counts[rew_key] += 1
        if rew == 1.0:
            attack_success += 1
        elif rew == 0.5:
            exec_not_scored += 1
        elif rew == 0.2:
            blocked_episodes += 1
        blocked_calls += int(r.get("n_blocked", 0))

    attack_success_rate = (attack_success / episodes) if episodes > 0 else 0.0
    exec_not_scored_rate = (exec_not_scored / episodes) if episodes > 0 else 0.0

    if episodes > 0:
        lo, hi = wilson_interval(attack_success, episodes)
        ci_95 = [round(lo, 4), round(hi, 4)]
    else:
        ci_95 = [0.0, 0.0]

    # Scorable cells only calculation (drop rows in UNSCORABLE_CELLS)
    scorable_rows = [
        (fn, r)
        for fn, r in rows_with_meta
        if (target_action, str(r.get("recipe_id", "")).split("|")[0]) not in UNSCORABLE_CELLS
    ]
    scorable_episodes = len(scorable_rows)
    scorable_success = sum(1 for _fn, r in scorable_rows if float(r.get("reward", 0.0)) == 1.0)
    scorable_rate = (scorable_success / scorable_episodes) if scorable_episodes > 0 else 0.0
    if scorable_episodes > 0:
        s_lo, s_hi = wilson_interval(scorable_success, scorable_episodes)
        scorable_ci = [round(s_lo, 4), round(s_hi, 4)]
    else:
        scorable_ci = [0.0, 0.0]

    # Families: group by signature
    sig_order: list[str] = []
    sig_groups: dict[str, list[dict[str, Any]]] = {}
    for _fn, r in rows_with_meta:
        sig = str(r.get("signature", "unknown"))
        if sig not in sig_groups:
            sig_order.append(sig)
            sig_groups[sig] = []
        sig_groups[sig].append(r)

    families: list[dict[str, Any]] = []
    for sig in sig_order:
        sig_rows = sig_groups[sig]
        best_rew = max(float(r.get("reward", 0.0)) for r in sig_rows)
        first_recipe = sig_rows[0].get("recipe_id", "")
        first_ep_with_1: int | None = None
        for r in sig_rows:
            if float(r.get("reward", 0.0)) == 1.0:
                first_ep_with_1 = r.get("episode_index")
                break
        families.append({
            "signature": sig,
            "count": len(sig_rows),
            "best_reward": best_rew,
            "example_recipe_id": first_recipe,
            "first_episode_index_with_reward_1": first_ep_with_1,
        })

    # Sort families by count descending, then best_reward descending
    families.sort(key=lambda f: (-f["count"], -f["best_reward"], f["signature"]))
    n_families = len(families)
    n_families_with_success = sum(1 for f in families if f["best_reward"] == 1.0)

    # episodes_to_first_success: PER FILE (episode_index + 1), then median
    file_rows: dict[str, list[dict[str, Any]]] = {}
    for fn, r in rows_with_meta:
        file_rows.setdefault(fn, []).append(r)

    episodes_to_first_per_file: dict[str, int | None] = {}
    success_episodes_list: list[int] = []
    for fn, frows in file_rows.items():
        found_ep: int | None = None
        for r in frows:
            if float(r.get("reward", 0.0)) == 1.0:
                found_ep = int(r.get("episode_index", 0)) + 1
                break
        episodes_to_first_per_file[fn] = found_ep
        if found_ep is not None:
            success_episodes_list.append(found_ep)

    median_ep_to_success: float | int | None = None
    if success_episodes_list:
        median_ep_to_success = statistics.median(success_episodes_list)

    n_succ_files = len(success_episodes_list)
    if median_ep_to_success is not None:
        med_disp: Any = (
            int(median_ep_to_success)
            if isinstance(median_ep_to_success, float) and median_ep_to_success.is_integer()
            else median_ep_to_success
        )
        file_word = "file" if n_succ_files == 1 else "files"
        episodes_to_first_success_label = f"{med_disp} ({n_succ_files} {file_word})"
    else:
        episodes_to_first_success_label = "-"

    # Breakdowns: marginals over sink, semantic, evasion
    breakdowns: dict[str, dict[str, Any]] = {"sink": {}, "semantic": {}, "evasion": {}}
    dim_indices = {"sink": 0, "semantic": 1, "evasion": 3}

    for dim, idx in dim_indices.items():
        dim_groups: dict[str, list[dict[str, Any]]] = {}
        for _fn, r in rows_with_meta:
            rec = str(r.get("recipe_id", ""))
            parts = rec.split("|")
            val = parts[idx] if len(parts) > idx else "unknown"
            dim_groups.setdefault(val, []).append(r)

        for val, drows in sorted(dim_groups.items()):
            pulls = len(drows)
            succ = sum(1 for r in drows if float(r.get("reward", 0.0)) == 1.0)
            exec_05 = sum(1 for r in drows if float(r.get("reward", 0.0)) == 0.5)
            rate = (succ / pulls) if pulls > 0 else 0.0
            exec_rate = (exec_05 / pulls) if pulls > 0 else 0.0
            if pulls > 0:
                d_lo, d_hi = wilson_interval(succ, pulls)
                w_ci = [round(d_lo, 4), round(d_hi, 4)]
            else:
                w_ci = [0.0, 0.0]

            entry: dict[str, Any] = {
                "pulls": pulls,
                "successes": succ,
                "rate": round(rate, 4),
                "wilson_interval": w_ci,
                "exec_not_scored": exec_05,
                "exec_not_scored_rate": round(exec_rate, 4),
            }

            if dim == "sink":
                cell_key = (target_action, val)
                if cell_key in UNSCORABLE_CELLS:
                    entry["unscorable_by_construction"] = True
                    entry["unscorable_reason"] = UNSCORABLE_CELLS[cell_key]
                else:
                    entry["unscorable_by_construction"] = False

            breakdowns[dim][val] = entry

    # Top recipes: 5 recipe_ids with most successes (ties broken by pulls)
    recipe_stats: dict[str, dict[str, int]] = {}
    for _fn, r in rows_with_meta:
        rec = str(r.get("recipe_id", "unknown"))
        if rec not in recipe_stats:
            recipe_stats[rec] = {"successes": 0, "pulls": 0}
        recipe_stats[rec]["pulls"] += 1
        if float(r.get("reward", 0.0)) == 1.0:
            recipe_stats[rec]["successes"] += 1

    sorted_recipes = sorted(
        recipe_stats.items(),
        key=lambda item: (-item[1]["successes"], -item[1]["pulls"], item[0]),
    )
    top_5 = sorted_recipes[:5]
    top_recipes = [
        {
            "recipe_id": r_id,
            "successes": s["successes"],
            "pulls": s["pulls"],
            "rate": round(s["successes"] / s["pulls"], 4) if s["pulls"] else 0.0,
        }
        for r_id, s in top_5
    ]

    return {
        "guardrail": guardrail,
        "target_action": target_action,
        "episodes": episodes,
        "reward_counts": reward_counts,
        "attack_success": attack_success,
        "attack_success_rate": round(attack_success_rate, 4),
        "wilson_interval": ci_95,
        "scorable_cells_only": {
            "episodes": scorable_episodes,
            "attack_success": scorable_success,
            "rate": round(scorable_rate, 4),
            "wilson_interval": scorable_ci,
        },
        "exec_not_scored": exec_not_scored,
        "exec_not_scored_rate": round(exec_not_scored_rate, 4),
        "blocked_calls": blocked_calls,
        "blocked_episodes": blocked_episodes,
        "blocked_count": blocked_calls,  # preserved for backward compatibility
        "families": families,
        "n_families": n_families,
        "n_families_with_success": n_families_with_success,
        "episodes_to_first_success": median_ep_to_success,
        "episodes_to_first_success_label": episodes_to_first_success_label,
        "episodes_to_first_success_files": n_succ_files,
        "episodes_to_first_success_per_file": episodes_to_first_per_file,
        "breakdowns": breakdowns,
        "top_recipes": top_recipes,
    }


def build_taxonomy(runs_dir: Path | str) -> TaxonomyDict:
    """Read run logs from runs_dir and build complete taxonomy dictionary."""
    runs_path = Path(runs_dir)
    if not runs_path.exists():
        raise FileNotFoundError(f"Runs directory does not exist: {runs_path}")

    files_used: list[dict[str, Any]] = []
    files_excluded: list[dict[str, str]] = []
    total_error_rows = 0

    # Group rows by (effective_guardrail, target_action)
    groups: dict[tuple[str, str], list[tuple[str, dict[str, Any]]]] = {}

    for path in sorted(runs_path.glob("*.jsonl")):
        m = ATTACK_FILENAME_PATTERN.match(path.name)
        if not m:
            continue
        model, raw_guardrail, date_str, _time = m.groups()

        # Date filter
        if date_str < MIN_DATE_CUTOFF:
            files_excluded.append({
                "name": path.name,
                "reason": f"date {date_str} < {MIN_DATE_CUTOFF} (plant read measurement bug)",
            })
            continue

        valid_rows, error_count = load_attack_rows(path)
        total_error_rows += error_count

        if not valid_rows:
            files_excluded.append({
                "name": path.name,
                "reason": "zero valid rows",
            })
            continue

        if raw_guardrail == "taint" and date_str < TAINT_PREFIX_CUTOFF:
            effective_g = "taint_prefix"
        elif raw_guardrail == "taint" and date_str >= TAINT_FILES_CUTOFF:
            effective_g = "taint_files"
        else:
            effective_g = raw_guardrail
        files_used.append({"name": path.name, "n_rows": len(valid_rows)})

        for r in valid_rows:
            rec = str(r.get("recipe_id", ""))
            parts = rec.split("|")
            target_action = parts[2] if len(parts) > 2 else "unknown"
            key = (effective_g, target_action)
            groups.setdefault(key, []).append((path.name, r))

    methodology = {
        "file_filters": {
            "min_date_cutoff": MIN_DATE_CUTOFF,
            "taint_prefix_cutoff": TAINT_PREFIX_CUTOFF,
            "description": (
                f"Excluded attack runs with date < {MIN_DATE_CUTOFF} due to plant read measurement bug. "
                f"Taint runs with date < {TAINT_PREFIX_CUTOFF} labeled 'taint_prefix' (before base64 fixes); "
                f"date >= {TAINT_PREFIX_CUTOFF} labeled 'taint'. Skipped files with 0 valid rows; "
                f"skipped rows with error not null."
            ),
        },
        "cutoff_dates": {
            "min_date": MIN_DATE_CUTOFF,
            "taint_prefix_cutoff": TAINT_PREFIX_CUTOFF,
        },
        "pooling_note": POOLING_NOTE,
        "files_used": files_used,
        "files_excluded": files_excluded,
        "error_rows_skipped": total_error_rows,
        "limitations": list(METHODOLOGY_LIMITATIONS),
    }

    result = TaxonomyDict()
    result["methodology"] = methodology

    # Populate groups in sorted order
    for (g, act), r_meta in sorted(groups.items()):
        group_data = _compute_group_metrics(g, act, r_meta)
        result[f"{g}/{act}"] = group_data

    return result


def generate_markdown_report(data: dict[str, Any]) -> str:
    """Generate compact human-readable Markdown summary tables."""
    methodology = data.get("methodology", {})
    files_used = methodology.get("files_used", [])

    lines: list[str] = [
        "# Attack Exploit Taxonomy Report",
        "",
        "## Overview & Methodology",
        "",
        "This report aggregates adaptive red-team UCB1 attack search runs across guardrail tiers and target actions.",
        "",
        f"- **Minimum Date Cutoff:** `{methodology.get('cutoff_dates', {}).get('min_date', MIN_DATE_CUTOFF)}` "
        "(excluded earlier runs due to plant-read measurement bug)",
        f"- **Taint Prefix Cutoff:** `{methodology.get('cutoff_dates', {}).get('taint_prefix_cutoff', TAINT_PREFIX_CUTOFF)}` "
        "(`taint_prefix` before base64 / protected-content fixes; `taint` thereafter)",
        f"- **Files Analyzed:** {len(files_used)} run log files",
        f"- **Error Rows Skipped:** {methodology.get('error_rows_skipped', 0)}",
        "",
        "### Run Log Files Analyzed",
        "",
        "| File Name | Valid Rows |",
        "| --- | --- |",
    ]

    for f_info in files_used:
        lines.append(f"| `{f_info['name']}` | {f_info['n_rows']} |")

    lines.extend([
        "",
        f"> **Pooling note:** {methodology.get('pooling_note', POOLING_NOTE)}",
        "",
        "### Limitations",
        "",
    ])

    for lim in methodology.get("limitations", METHODOLOGY_LIMITATIONS):
        lines.append(f"- {lim}")

    lines.extend(["", "---", "", "## Summary by Guardrail × Target Action", ""])

    # Main Summary Table with new columns
    main_headers = [
        "Guardrail",
        "Target Action",
        "Episodes",
        "Successes",
        "Rate",
        "Wilson 95% CI",
        "Rate, scorable cells only",
        "Exec, not scored",
        "Families (Hit/Tot)",
        "Med Ep to 1st",
        "Blocked calls",
        "Blocked eps",
    ]
    lines.append("| " + " | ".join(main_headers) + " |")
    lines.append("| " + " | ".join(["---"] * len(main_headers)) + " |")

    group_keys = [k for k in data.keys() if k != "methodology"]
    for k in sorted(group_keys):
        g = data[k]
        g_name = g["guardrail"]
        act_name = g["target_action"]
        eps = g["episodes"]
        succ = g["attack_success"]
        rate_str = f"{(g['attack_success_rate'] * 100):.1f}%"
        ci = g["wilson_interval"]
        ci_str = f"[{ci[0]:.3f}, {ci[1]:.3f}]"

        # Rate, scorable cells only
        sc = g.get("scorable_cells_only", {})
        sc_eps = sc.get("episodes", eps)
        sc_succ = sc.get("attack_success", succ)
        sc_rate = sc.get("rate", g["attack_success_rate"])
        sc_ci = sc.get("wilson_interval", ci)
        if sc_eps > 0:
            sc_str = f"{(sc_rate * 100):.1f}% ({sc_succ}/{sc_eps}) [{sc_ci[0]:.3f}, {sc_ci[1]:.3f}]"
        else:
            sc_str = "-"

        # Exec, not scored
        exec_ns = g.get("exec_not_scored", 0)
        exec_ns_rate = g.get("exec_not_scored_rate", 0.0)
        exec_ns_str = f"{exec_ns} ({(exec_ns_rate * 100):.1f}%)"

        fams_str = f"{g['n_families_with_success']} / {g['n_families']}"
        med_str = str(g.get("episodes_to_first_success_label", "-"))
        b_calls = g.get("blocked_calls", g.get("blocked_count", 0))
        b_eps = g.get("blocked_episodes", 0)

        row = [
            g_name,
            act_name,
            str(eps),
            str(succ),
            rate_str,
            ci_str,
            sc_str,
            exec_ns_str,
            fams_str,
            med_str,
            str(b_calls),
            str(b_eps),
        ]
        lines.append("| " + " | ".join(row) + " |")

    lines.extend(["", "---", "", "## Marginal Breakdowns", ""])

    for k in sorted(group_keys):
        g = data[k]
        lines.append(f"### `{k}` (Episodes: {g['episodes']}, Successes: {g['attack_success']})")
        lines.append("")

        for dim in ("sink", "semantic", "evasion"):
            lines.append(f"#### Marginal by {dim.title()}")
            dim_headers = [
                "Category",
                "Pulls",
                "Successes",
                "Rate",
                "Wilson 95% CI",
                "Exec, not scored",
            ]
            lines.append("| " + " | ".join(dim_headers) + " |")
            lines.append("| " + " | ".join(["---"] * len(dim_headers)) + " |")

            footnotes: list[str] = []
            for cat, c_stat in sorted(g["breakdowns"].get(dim, {}).items()):
                p = c_stat["pulls"]
                s = c_stat["successes"]
                r_str = f"{(c_stat['rate'] * 100):.1f}%"
                c_ci = c_stat["wilson_interval"]
                c_ci_str = f"[{c_ci[0]:.3f}, {c_ci[1]:.3f}]"

                c_exec = c_stat.get("exec_not_scored", 0)
                c_exec_rate = c_stat.get("exec_not_scored_rate", 0.0)
                c_exec_str = f"{c_exec} ({(c_exec_rate * 100):.1f}%)"

                cat_display = cat
                if c_stat.get("unscorable_by_construction"):
                    cat_display = f"{cat} †"
                    reason = c_stat.get("unscorable_reason", "")
                    footnotes.append(f"† *{cat}*: Unscorable by construction — {reason}.")

                lines.append(f"| {cat_display} | {p} | {s} | {r_str} | {c_ci_str} | {c_exec_str} |")

            lines.append("")
            if footnotes:
                for fn_text in footnotes:
                    lines.append(f"*{fn_text}*")
                lines.append("")

        if g.get("top_recipes"):
            lines.append("#### Top Exploit Recipes")
            lines.append("| Recipe ID | Successes | Pulls | Rate |")
            lines.append("| --- | --- | --- | --- |")
            for tr in g["top_recipes"]:
                r_rate = f"{(tr['rate'] * 100):.1f}%"
                lines.append(f"| `{tr['recipe_id']}` | {tr['successes']} | {tr['pulls']} | {r_rate} |")
            lines.append("")

        lines.append("---")
        lines.append("")

    return "\n".join(lines)


def export_taxonomy(
    runs_dir: Path | str = "runs",
    out_json: Path | str = "reports/taxonomy.json",
    out_md: Path | str = "reports/taxonomy.md",
) -> tuple[TaxonomyDict, str]:
    """Execute complete taxonomy export and write reports files.

    Returns (taxonomy_dict, markdown_content).
    """
    runs_path = Path(runs_dir)
    json_path = Path(out_json)
    md_path = Path(out_md)

    json_path.parent.mkdir(parents=True, exist_ok=True)
    md_path.parent.mkdir(parents=True, exist_ok=True)

    data = build_taxonomy(runs_path)
    md_content = generate_markdown_report(data)

    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)

    with open(md_path, "w", encoding="utf-8") as f:
        f.write(md_content)

    return data, md_content


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        description="Export attack exploit taxonomy from JSONL run logs to JSON and Markdown."
    )
    parser.add_argument(
        "--runs-dir",
        default=str(_REPO_ROOT / "runs"),
        help="Directory containing attack JSONL run logs (default: runs)",
    )
    parser.add_argument(
        "--out-json",
        default=str(_REPO_ROOT / "reports" / "taxonomy.json"),
        help="Output path for taxonomy JSON (default: reports/taxonomy.json)",
    )
    parser.add_argument(
        "--out-md",
        default=str(_REPO_ROOT / "reports" / "taxonomy.md"),
        help="Output path for taxonomy Markdown report (default: reports/taxonomy.md)",
    )
    args = parser.parse_args(argv)

    _data, md_summary = export_taxonomy(
        runs_dir=args.runs_dir,
        out_json=args.out_json,
        out_md=args.out_md,
    )
    print(md_summary)


if __name__ == "__main__":
    main()
