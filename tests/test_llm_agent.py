"""Tests for ChatCompletionsAgent and CassetteBackend.

All tests use a FakeBackend — NO network, NO Ollama required.
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
from typing import Any

import pytest

from aicomp_sdk.agents.tool_specs import build_openai_tool_name_maps
from aicomp_sdk.agents.types import (
    AssistantMessageEvent,
    FinalResponseDecision,
    InstructionEvent,
    ToolCall,
    ToolCallDecision,
    ToolRequestEvent,
    ToolResultEvent,
    UserMessageEvent,
)
from aicomp_sdk.core.runtime_history import RuntimeHistory

from redteam.sandbox.episode import BENIGN_TASK_MESSAGE, run_episode
from redteam.sandbox.fixture_builder import EmailPlant
from redteam.sandbox.llm_agent import ChatCompletionsAgent, CallRecord
from redteam.sandbox.llm_backend import (
    CassetteBackend,
    CassetteMiss,
    ChatResult,
    ChatUsage,
)


# ---------------------------------------------------------------------------
# FakeBackend
# ---------------------------------------------------------------------------


class FakeBackend:
    """Scripted ChatResult sequence for offline testing."""

    def __init__(self, responses: list[dict[str, Any]]) -> None:
        """
        Each entry may have keys:
        - ``tool_name``: canonical name (will appear as the *openai* name in the call)
        - ``tool_args``: dict of arguments (serialised to JSON string)
        - ``content``: optional str for assistant content
        - ``usage``: optional {prompt_tokens, completion_tokens}
        - ``latency_s``: float (default 0.01)
        - ``finish_reason``: str (default "tool_calls" or "stop")
        """
        self._responses = list(responses)
        self._index = 0
        self.calls: list[dict[str, Any]] = []

    def chat(
        self,
        *,
        model: str,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]],
        temperature: float,
        max_tokens: int,
        seed: int | None,
    ) -> ChatResult:
        # --- STRICT FORMAT ASSERTION ---
        # Every tool must be {"type": "function", "function": {name, description, parameters}}
        # No "strict" key permitted (flat Responses-API shape would have it).
        for i, t in enumerate(tools):
            assert set(t.keys()) == {"type", "function"}, (
                f"tools[{i}] must have exactly keys {{type, function}}, got {set(t.keys())}"
            )
            assert t["type"] == "function", f"tools[{i}]['type'] must be 'function'"
            fn = t["function"]
            assert "name" in fn, f"tools[{i}]['function'] missing 'name'"
            assert "description" in fn, f"tools[{i}]['function'] missing 'description'"
            assert "parameters" in fn, f"tools[{i}]['function'] missing 'parameters'"
            assert "strict" not in t, f"tools[{i}] must not have 'strict' at top level"
            assert "strict" not in fn, f"tools[{i}]['function'] must not have 'strict'"
        # --- END ASSERTION ---

        if self._index >= len(self._responses):
            raise IndexError("FakeBackend: no more scripted responses")
        spec = self._responses[self._index]
        self._index += 1
        self.calls.append(
            dict(model=model, messages=messages, tools=tools,
                 temperature=temperature, max_tokens=max_tokens, seed=seed)
        )

        # Build the message dict.
        tool_name: str | None = spec.get("tool_name")
        msg: dict[str, Any] = {"role": "assistant", "content": spec.get("content", "")}
        if tool_name is not None:
            # Find the openai name from the tools list (nested format only).
            openai_name = tool_name  # default if not found
            for t in tools:
                if t.get("function", {}).get("name") == tool_name:
                    openai_name = t["function"]["name"]
                    break
            args = spec.get("tool_args", {})
            msg["tool_calls"] = [
                {
                    "id": f"fake_tc_{self._index:04d}",
                    "type": "function",
                    "function": {
                        "name": openai_name,
                        "arguments": json.dumps(args),
                    },
                }
            ]
            msg["content"] = spec.get("content", None)

        usage_spec = spec.get("usage")
        usage = ChatUsage(**usage_spec) if usage_spec else None
        finish = spec.get("finish_reason", "tool_calls" if tool_name else "stop")

        return ChatResult(
            message=msg,
            usage=usage,
            latency_s=spec.get("latency_s", 0.01),
            finish_reason=finish,
            raw_model=model,
        )


def _make_agent(responses: list[dict[str, Any]], **kw: Any) -> ChatCompletionsAgent:
    return ChatCompletionsAgent(backend=FakeBackend(responses), model="fake", **kw)


def _get_real_agent_tool_specs():
    """Return (specs, canonical_to_openai, openai_to_canonical) from the public SDK path.

    Uses ToolSuite(fixtures_dir).specs -> to_agent_tool_specs, exactly the same
    path SandboxEnv.__init__ uses.  No hardcoded fallback.
    """
    from pathlib import Path

    from aicomp_sdk.agents.tool_specs import build_openai_tool_name_maps, to_agent_tool_specs
    from aicomp_sdk.core.tools.suite import ToolSuite
    from redteam.sandbox.fixture_builder import EpisodeWorkspace

    with EpisodeWorkspace(()) as ws:
        suite = ToolSuite(Path(ws.fixtures_dir))
        specs = to_agent_tool_specs(tuple(suite.specs.values()))

    assert len(specs) == 10, (
        f"Expected exactly 10 tools from SDK; got {len(specs)}: {[s.name for s in specs]}"
    )
    c2o, o2c = build_openai_tool_name_maps(specs)
    return specs, c2o, o2c



# ---------------------------------------------------------------------------
# Tool format: nested shape, no strict, name regex, no collisions
# ---------------------------------------------------------------------------


class TestChatCompletionsToolFormat:
    """Verify that the agent emits the correct nested tool shape."""

    def _capture_tools_sent(self):
        """Build tools from the real SDK path (ToolSuite -> to_agent_tool_specs)."""
        from redteam.sandbox.llm_agent import _to_chat_completions_tool

        specs, c2o, o2c = _get_real_agent_tool_specs()
        assert len(specs) == 10, f"Expected exactly 10 tools from ToolSuite; got {len(specs)}"
        tools_sent = [_to_chat_completions_tool(spec, c2o[spec.name]) for spec in specs]
        assert len(tools_sent) == 10, f"Expected exactly 10 tools sent; got {len(tools_sent)}"
        return tools_sent, c2o, o2c

    def test_tool_shape_is_nested_not_flat(self) -> None:
        """Each tool has exactly {type, function}; no strict key; function has name/description/parameters."""
        tools, _, _ = self._capture_tools_sent()
        assert len(tools) == 10, f"Expected exactly 10 tools; got {len(tools)}"
        for t in tools:
            assert set(t.keys()) == {"type", "function"}, (
                f"Expected only 'type' and 'function'; got keys: {set(t.keys())}"
            )
            assert t["type"] == "function"
            fn = t["function"]
            assert "name" in fn
            assert "description" in fn
            assert "parameters" in fn
            assert "strict" not in t, "'strict' must not be at top level"
            assert "strict" not in fn, "'strict' must not be inside function"

    def test_all_openai_names_match_safe_regex(self) -> None:
        """All sanitized tool names must match ^[A-Za-z0-9_-]+$."""
        import re
        tools, _, _ = self._capture_tools_sent()
        pattern = re.compile(r"^[A-Za-z0-9_-]+$")
        for t in tools:
            name = t["function"]["name"]
            assert pattern.match(name), (
                f"Tool name {name!r} does not match ^[A-Za-z0-9_-]+$"
            )

    def test_no_name_collisions_in_mapping(self) -> None:
        """Each openai name maps back to exactly one canonical name (no collisions)."""
        _, c2o, o2c = self._capture_tools_sent()
        assert len(o2c) == len(c2o), (
            f"Collision detected: {len(c2o)} canonical → {len(o2c)} openai names"
        )
        for openai_name, canonical in o2c.items():
            assert c2o[canonical] == openai_name, (
                f"Round-trip failed: {canonical!r} → {c2o[canonical]!r} != {openai_name!r}"
            )

    def test_fakebackend_rejects_flat_shape(self) -> None:
        """FakeBackend raises AssertionError when given the flat Responses-API shape."""
        from aicomp_sdk.agents.tool_specs import to_openai_function_tool
        from aicomp_sdk.agents.types import AgentToolSpec

        spec = AgentToolSpec(
            name="fs.read", description="Read a file",
            parameters_json_schema={"type": "object", "properties": {}},
        )
        flat_tool = to_openai_function_tool(spec, name_override="fs_read")
        backend = FakeBackend([{"content": "ok"}])
        import pytest as _pytest
        with _pytest.raises(AssertionError):
            backend.chat(
                model="fake",
                messages=[{"role": "user", "content": "hi"}],
                tools=[flat_tool],
                temperature=0.0, max_tokens=10, seed=None,
            )


# ---------------------------------------------------------------------------
# a. History → messages: tool_call/tool pairing with consistent IDs
# ---------------------------------------------------------------------------


class TestHistoryToMessages:
    def _build_history_with_tool_roundtrip(self) -> RuntimeHistory:
        """Instruction + user + tool-request + tool-result history."""
        call = ToolCall(call_id="call_000001", tool_name="fs.read", arguments={"path": "note.txt"})
        result_ev = ToolResultEvent(
            result=type("R", (), {
                "call_id": "call_000001",
                "tool_name": "fs.read",
                "output_text": "note content",
                "is_error": False,
            })()  # type: ignore[arg-type]
        )
        # Use ToolResult directly
        from aicomp_sdk.agents.types import ToolResult
        h = (
            RuntimeHistory()
            .with_instruction("You are a helpful agent.")
            .with_user_message("Read note.txt for me.")
            .with_tool_request(call)
            .with_tool_result(
                ToolResult(
                    call_id="call_000001",
                    tool_name="fs.read",
                    output_text="note content",
                )
            )
        )
        return h

    def test_system_message_from_instructions(self) -> None:
        """InstructionEvents become a single system message."""
        agent = _make_agent([{"content": "done"}])
        h = RuntimeHistory().with_instruction("Instr A").with_instruction("Instr B").with_user_message("Hi")
        msgs = agent._build_messages(h, {})
        assert msgs[0]["role"] == "system"
        assert "Instr A" in msgs[0]["content"]
        assert "Instr B" in msgs[0]["content"]

    def test_tool_call_followed_by_tool_message(self) -> None:
        """Assistant tool_calls message is immediately followed by role=tool with same ID."""
        agent = _make_agent([{"content": "done"}])
        h = self._build_history_with_tool_roundtrip()
        msgs = agent._build_messages(h, {"fs.read": "fs_read"})

        # Find assistant message with tool_calls.
        asst_msgs = [m for m in msgs if m.get("role") == "assistant" and m.get("tool_calls")]
        assert asst_msgs, "No assistant tool_calls message found"
        tc_id = asst_msgs[0]["tool_calls"][0]["id"]
        assert tc_id == "call_000001"

        # The NEXT message must be role=tool with matching tool_call_id.
        asst_idx = msgs.index(asst_msgs[0])
        assert asst_idx + 1 < len(msgs), "No message after assistant tool_calls"
        tool_msg = msgs[asst_idx + 1]
        assert tool_msg["role"] == "tool"
        assert tool_msg["tool_call_id"] == tc_id, (
            f"tool_call_id mismatch: {tool_msg['tool_call_id']!r} != {tc_id!r}"
        )
        assert "note content" in tool_msg["content"]

    def test_name_mapping_in_tool_call_message(self) -> None:
        """Canonical fs.read → openai fs_read in the assistant tool_calls message."""
        agent = _make_agent([{"content": "done"}])
        h = self._build_history_with_tool_roundtrip()
        msgs = agent._build_messages(h, {"fs.read": "fs_read"})
        asst = [m for m in msgs if m.get("role") == "assistant" and m.get("tool_calls")][0]
        assert asst["tool_calls"][0]["function"]["name"] == "fs_read"


# ---------------------------------------------------------------------------
# b. Name mapping both directions
# ---------------------------------------------------------------------------


class TestNameMapping:
    def _make_spec(self, name: str):
        from aicomp_sdk.agents.types import AgentToolSpec
        return AgentToolSpec(name=name, description="", parameters_json_schema={"type": "object", "properties": {}})

    def test_canonical_to_openai_dotted_names(self) -> None:
        """Dotted names like fs.read, http.post, email.send are mapped to safe names."""
        from aicomp_sdk.agents.tool_specs import build_openai_tool_name_maps
        specs = [self._make_spec(n) for n in ["fs.read", "http.post", "email.send"]]
        c2o, o2c = build_openai_tool_name_maps(specs)
        for canon in ["fs.read", "http.post", "email.send"]:
            openai_name = c2o[canon]
            assert "." not in openai_name, f"Dot in openai name for {canon}: {openai_name!r}"
            assert o2c[openai_name] == canon

    def test_round_trip_fs_read(self) -> None:
        specs = [self._make_spec("fs.read")]
        c2o, o2c = build_openai_tool_name_maps(specs)
        assert o2c[c2o["fs.read"]] == "fs.read"

    def test_round_trip_http_post(self) -> None:
        specs = [self._make_spec("http.post")]
        c2o, o2c = build_openai_tool_name_maps(specs)
        assert o2c[c2o["http.post"]] == "http.post"

    def test_round_trip_email_send(self) -> None:
        specs = [self._make_spec("email.send")]
        c2o, o2c = build_openai_tool_name_maps(specs)
        assert o2c[c2o["email.send"]] == "email.send"


# ---------------------------------------------------------------------------
# c. Multiple parallel tool_calls: first used, extra counted
# ---------------------------------------------------------------------------


class TestParallelToolCalls:
    def test_extra_calls_dropped_counted(self) -> None:
        """When the model returns 3 tool calls, first is used, 2 are counted as dropped."""
        agent = _make_agent([])
        # Build a synthetic ChatResult with 3 tool_calls.
        msg = {
            "role": "assistant",
            "content": None,
            "tool_calls": [
                {"id": "tc1", "type": "function",
                 "function": {"name": "fs_read", "arguments": '{"path":"a.txt"}'}},
                {"id": "tc2", "type": "function",
                 "function": {"name": "fs_read", "arguments": '{"path":"b.txt"}'}},
                {"id": "tc3", "type": "function",
                 "function": {"name": "fs_write", "arguments": '{"path":"c.txt","content":"x"}'}},
            ],
        }
        result = ChatResult(message=msg, usage=None, latency_s=0.01,
                            finish_reason="tool_calls", raw_model="fake")
        openai_to_canonical = {"fs_read": "fs.read", "fs_write": "fs.write"}
        decision = agent._parse_result(result, openai_to_canonical)
        assert isinstance(decision, ToolCallDecision)
        assert decision.call.tool_name == "fs.read"
        assert decision.call.arguments == {"path": "a.txt"}
        assert agent.call_records[-1].extra_calls_dropped == 2


# ---------------------------------------------------------------------------
# d. Invalid JSON arguments → FinalResponseDecision + malformed counted
# ---------------------------------------------------------------------------


class TestInvalidJson:
    def test_invalid_json_args_gives_final_and_counts_malformed(self) -> None:
        agent = _make_agent([])
        msg = {
            "role": "assistant",
            "content": "fallback",
            "tool_calls": [
                {"id": "tc1", "type": "function",
                 "function": {"name": "fs_read", "arguments": "not-valid-json{"}},
            ],
        }
        result = ChatResult(message=msg, usage=None, latency_s=0.01,
                            finish_reason="tool_calls", raw_model="fake")
        decision = agent._parse_result(result, {"fs_read": "fs.read"})
        assert isinstance(decision, FinalResponseDecision)
        assert agent.call_records[-1].malformed is True


# ---------------------------------------------------------------------------
# e. Unknown tool name → FinalResponseDecision + malformed
# ---------------------------------------------------------------------------


class TestUnknownToolName:
    def test_unknown_tool_name_gives_final_and_malformed(self) -> None:
        agent = _make_agent([])
        msg = {
            "role": "assistant",
            "content": "hmm",
            "tool_calls": [
                {"id": "tc1", "type": "function",
                 "function": {"name": "nonexistent_tool", "arguments": '{"x":1}'}},
            ],
        }
        result = ChatResult(message=msg, usage=None, latency_s=0.01,
                            finish_reason="tool_calls", raw_model="fake")
        # No mapping for nonexistent_tool.
        decision = agent._parse_result(result, {"fs_read": "fs.read"})
        assert isinstance(decision, FinalResponseDecision)
        assert agent.call_records[-1].malformed is True


# ---------------------------------------------------------------------------
# f. No tool_calls → FinalResponseDecision
# ---------------------------------------------------------------------------


class TestNoToolCalls:
    def test_no_tool_calls_gives_final(self) -> None:
        agent = _make_agent([{"content": "I'm done."}])
        h = RuntimeHistory().with_user_message("Are you done?")
        from aicomp_sdk.agents.types import AgentToolSpec
        tools = [AgentToolSpec(name="fs.read", description="", parameters_json_schema={"type": "object", "properties": {}})]
        decision = agent.next_action(history=h, tools=tools)
        assert isinstance(decision, FinalResponseDecision)
        assert decision.text == "I'm done."


# ---------------------------------------------------------------------------
# g. Near-ctx flag
# ---------------------------------------------------------------------------


class TestNearCtx:
    def test_near_ctx_set_when_prompt_tokens_high(self) -> None:
        """near_ctx=True when prompt_tokens >= ctx_warn_frac * ctx_limit."""
        agent = _make_agent([], ctx_limit=100, ctx_warn_frac=0.9)
        msg = {"role": "assistant", "content": "done"}
        result = ChatResult(
            message=msg,
            usage=ChatUsage(prompt_tokens=95, completion_tokens=10),
            latency_s=0.01, finish_reason="stop", raw_model="fake",
        )
        agent._parse_result(result, {})
        assert agent.call_records[-1].near_ctx is True

    def test_near_ctx_false_when_prompt_tokens_low(self) -> None:
        agent = _make_agent([], ctx_limit=100, ctx_warn_frac=0.9)
        msg = {"role": "assistant", "content": "done"}
        result = ChatResult(
            message=msg,
            usage=ChatUsage(prompt_tokens=50, completion_tokens=5),
            latency_s=0.01, finish_reason="stop", raw_model="fake",
        )
        agent._parse_result(result, {})
        assert agent.call_records[-1].near_ctx is False

    def test_near_ctx_false_when_usage_none(self) -> None:
        agent = _make_agent([], ctx_limit=100, ctx_warn_frac=0.9)
        msg = {"role": "assistant", "content": "done"}
        result = ChatResult(message=msg, usage=None, latency_s=0.01,
                            finish_reason="stop", raw_model="fake")
        agent._parse_result(result, {})
        assert agent.call_records[-1].near_ctx is False


# ---------------------------------------------------------------------------
# h. Seed progression: sample_seed + i; no seed when None
# ---------------------------------------------------------------------------


class TestSeedProgression:
    def test_seed_increments_per_call(self) -> None:
        """Each call uses sample_seed + call_index."""
        responses = [{"content": "a"}, {"content": "b"}, {"content": "c"}]
        backend = FakeBackend(responses)
        agent = ChatCompletionsAgent(backend=backend, model="fake", sample_seed=1000)
        h = RuntimeHistory().with_user_message("hi")
        from aicomp_sdk.agents.types import AgentToolSpec
        tools = [AgentToolSpec(name="fs.read", description="", parameters_json_schema={"type": "object", "properties": {}})]
        for _ in range(3):
            agent.next_action(history=h, tools=tools)
        seeds = [c["seed"] for c in backend.calls]
        assert seeds == [1000, 1001, 1002]

    def test_no_seed_when_sample_seed_none(self) -> None:
        """When sample_seed=None, seed kwarg is None."""
        responses = [{"content": "a"}]
        backend = FakeBackend(responses)
        agent = ChatCompletionsAgent(backend=backend, model="fake", sample_seed=None)
        h = RuntimeHistory().with_user_message("hi")
        from aicomp_sdk.agents.types import AgentToolSpec
        tools = [AgentToolSpec(name="fs.read", description="", parameters_json_schema={"type": "object", "properties": {}})]
        agent.next_action(history=h, tools=tools)
        assert backend.calls[0]["seed"] is None


# ---------------------------------------------------------------------------
# i. reset_state clears records
# ---------------------------------------------------------------------------


class TestResetState:
    def test_reset_clears_call_records(self) -> None:
        agent = _make_agent([{"content": "a"}, {"content": "b"}])
        h = RuntimeHistory().with_user_message("hi")
        from aicomp_sdk.agents.types import AgentToolSpec
        tools = [AgentToolSpec(name="fs.read", description="", parameters_json_schema={"type": "object", "properties": {}})]
        agent.next_action(history=h, tools=tools)
        assert len(agent.call_records) == 1
        agent.reset_state()
        assert len(agent.call_records) == 0
        assert agent._call_index == 0


# ---------------------------------------------------------------------------
# j. CassetteBackend record → replay roundtrip; CassetteMiss in replay mode
# ---------------------------------------------------------------------------


class TestCassetteBackend:
    def _make_inner(self) -> FakeBackend:
        return FakeBackend([
            {"content": "recorded response", "usage": {"prompt_tokens": 10, "completion_tokens": 5}}
        ])

    def test_record_then_replay(self, tmp_path: Path) -> None:
        cassette_path = tmp_path / "cassette.jsonl"
        inner = self._make_inner()

        # Record.
        backend = CassetteBackend(inner, cassette_path, mode="record")
        r1 = backend.chat(
            model="fake", messages=[{"role": "user", "content": "hi"}],
            tools=[], temperature=0.0, max_tokens=100, seed=42,
        )
        assert backend.misses == 1
        assert cassette_path.exists()

        # Replay.
        backend2 = CassetteBackend(FakeBackend([]), cassette_path, mode="replay")
        r2 = backend2.chat(
            model="fake", messages=[{"role": "user", "content": "hi"}],
            tools=[], temperature=0.0, max_tokens=100, seed=42,
        )
        assert backend2.hits == 1
        assert r2.message == r1.message
        assert r2.usage is not None
        assert r2.usage.prompt_tokens == 10

    def test_replay_miss_raises(self, tmp_path: Path) -> None:
        cassette_path = tmp_path / "empty.jsonl"
        cassette_path.write_text("")  # empty file
        backend = CassetteBackend(FakeBackend([]), cassette_path, mode="replay")
        with pytest.raises(CassetteMiss):
            backend.chat(
                model="fake", messages=[{"role": "user", "content": "unseen"}],
                tools=[], temperature=0.0, max_tokens=100, seed=1,
            )
        assert backend.misses == 1

    def test_auto_mode_uses_cache_on_second_call(self, tmp_path: Path) -> None:
        cassette_path = tmp_path / "auto.jsonl"
        inner = FakeBackend([{"content": "first"}, {"content": "second"}])
        backend = CassetteBackend(inner, cassette_path, mode="auto")
        kwargs = dict(model="fake", messages=[{"role": "user", "content": "q"}],
                      tools=[], temperature=0.0, max_tokens=50, seed=7)
        r1 = backend.chat(**kwargs)
        r2 = backend.chat(**kwargs)  # same kwargs → cache hit
        assert backend.misses == 1
        assert backend.hits == 1
        assert r1.message["content"] == r2.message["content"]


# ---------------------------------------------------------------------------
# k. run_episode with FakeBackend: benign task, no predicate, daily_brief written
# ---------------------------------------------------------------------------


class TestRunEpisodeFakeBackend:
    """Integration test using FakeBackend instead of a real LLM.

    The scripted sequence mimics:
      email.list (not a real SDK tool, so we use email.read)
      -> email.read(email_0)
      -> fs.write(daily_brief.txt, ...)
      -> FinalResponseDecision("Done.")

    The BENIGN_TASK_MESSAGE user message contains "inbox" and "save" —
    which means predicates allow write intent (user_allows_share=False,
    write allowed since "save" is in msg).
    """

    def _make_fake_backend_sequence(self) -> FakeBackend:
        return FakeBackend([
            # Turn 1: read email_0
            {
                "tool_name": "email_read",  # openai name (will be passed back, mapped by agent)
                "tool_args": {"id": "email_0"},
                "usage": {"prompt_tokens": 100, "completion_tokens": 20},
            },
            # Turn 2: write daily_brief.txt
            {
                "tool_name": "fs_write",
                "tool_args": {"path": "daily_brief.txt", "content": "Today's brief: all good."},
                "usage": {"prompt_tokens": 200, "completion_tokens": 20},
            },
            # Turn 3: final response
            {
                "content": "Done. I saved the brief.",
                "usage": {"prompt_tokens": 250, "completion_tokens": 10},
            },
        ])

    def test_benign_task_no_predicate_fires_and_file_written(self) -> None:
        """FakeBackend-driven benign episode: no predicate fires, file written."""
        from redteam.sandbox.agents import make_chat_agent_factory

        backend = self._make_fake_backend_sequence()
        factory = make_chat_agent_factory(backend, model="fake", sample_seed=0)

        result = run_episode(
            user_messages=[BENIGN_TASK_MESSAGE],
            plants=(),
            agent_factory=factory,
            seed=0,
        )
        assert result.error is None, f"Episode error: {result.error}"

        # No predicate should fire for a benign task.
        assert not result.fired, (
            f"Unexpected predicates for benign episode: {result.predicates}"
        )

        # Verify fs.write(daily_brief.txt) appears in trace.
        write_events = [
            e for e in result.trace.get("tool_events", [])
            if e.get("name") == "fs.write"
            and (e.get("args") or {}).get("path") == "daily_brief.txt"
            and e.get("ok") is True
        ]
        assert write_events, (
            f"fs.write(daily_brief.txt) not found in trace. "
            f"Tool events: {[(e.get('name'), e.get('args')) for e in result.trace.get('tool_events', [])]}"
        )

        # agent_summary should be populated.
        assert result.agent_summary is not None
        assert result.agent_summary["n_calls"] >= 1
