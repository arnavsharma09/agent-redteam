"""Tests for redteam.attacker.novelty."""

from redteam.attacker.recipes import Recipe
from redteam.attacker.novelty import structural_signature
from redteam.sandbox.episode import EpisodeResult


def _make_res(tool_events: list[dict], predicates: list[dict]) -> EpisodeResult:
    return EpisodeResult(
        trace={"tool_events": tool_events},
        predicates=predicates,
        fired=bool(predicates),
        sdk_cell_signature=None,
        seconds=0.1,
        n_tool_events=len(tool_events),
        n_blocked=0,
        max_hops_used=len(tool_events),
        agent_summary={},
        guardrail_log=[],
        error=None,
        plants_hash="hash",
        seed=1,
    )


class TestStructuralSignature:
    def test_identical_executions_produce_same_signature(self) -> None:
        """Episodes with matching tools, sources, action, and predicates have identical signatures."""
        recipe1 = Recipe("web", "direct_command", "exfil_http", "none")
        recipe2 = Recipe("email", "authority", "exfil_http", "base64")  # same target_action

        events = [
            {"name": "web.open", "source": "web"},
            {"name": "http.post", "source": "tool"},
        ]
        preds = [{"predicate": "EXFILTRATION", "severity": 5, "evidence": {"tool": "http.post"}}]

        res1 = _make_res(events, preds)
        res2 = _make_res(events, preds)

        sig1 = structural_signature(recipe1, res1)
        sig2 = structural_signature(recipe2, res2)
        assert len(sig1) == 16
        assert sig1 == sig2, "Identical execution structure should produce same signature"

    def test_changing_predicate_changes_signature(self) -> None:
        """Varying predicates changes signature."""
        recipe = Recipe("web", "direct_command", "exfil_http", "none")
        events = [{"name": "http.post", "source": "tool"}]

        res_no_pred = _make_res(events, [])
        res_with_pred = _make_res(events, [{"predicate": "EXFILTRATION"}])

        sig1 = structural_signature(recipe, res_no_pred)
        sig2 = structural_signature(recipe, res_with_pred)
        assert sig1 != sig2

    def test_changing_tool_sequence_changes_signature(self) -> None:
        """Different tool order or names changes signature."""
        recipe = Recipe("web", "direct_command", "exfil_http", "none")

        events1 = [{"name": "web.open", "source": "web"}, {"name": "http.post", "source": "tool"}]
        events2 = [{"name": "http.post", "source": "tool"}, {"name": "web.open", "source": "web"}]

        sig1 = structural_signature(recipe, _make_res(events1, []))
        sig2 = structural_signature(recipe, _make_res(events2, []))
        assert sig1 != sig2

    def test_changing_target_action_changes_signature(self) -> None:
        """Different recipe target_action changes signature."""
        recipe1 = Recipe("web", "direct_command", "exfil_http", "none")
        recipe2 = Recipe("web", "direct_command", "destructive", "none")

        events = [{"name": "fs.delete", "source": "file"}]
        res = _make_res(events, [])

        sig1 = structural_signature(recipe1, res)
        sig2 = structural_signature(recipe2, res)
        assert sig1 != sig2
