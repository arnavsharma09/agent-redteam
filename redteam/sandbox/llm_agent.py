"""ChatCompletionsAgent: AgentProtocol implementation backed by any ChatBackend.

Uses the OpenAI chat/completions API format (NOT the Responses API).
Designed for use with local Ollama models or any compatible endpoint.

NOTE ON SEED PROGRESSION
------------------------
``sample_seed`` is combined with a per-call counter: ``seed = sample_seed + i``.
This means each call within a single episode gets a distinct seed, giving
varied behaviour across hops.  If you want strict reproducibility *between*
two full episode runs, use the same ``sample_seed`` for both.

If ``sample_seed`` is *None* no seed is sent to the backend.  Do NOT pass a
fixed ``sample_seed`` with ``temperature > 0`` and expect N independent replays
to differ: the same (seed, prompt) pair will produce the same completion from
models that honour the seed parameter.

UNVERIFIED: Whether the Ollama OpenAI-compatible endpoint honours the ``seed``
parameter is not confirmed.  The parameter is sent if ``sample_seed`` is set;
Ollama may silently ignore it.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any

from aicomp_sdk.agents.tool_specs import build_openai_tool_name_maps
from aicomp_sdk.agents.types import (
    AGENT_STATE_VERSION,
    AgentStateSnapshot,
    AgentStateVersionError,
    AgentToolSpec,
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

from redteam.sandbox.llm_backend import ChatBackend, ChatResult


# ---------------------------------------------------------------------------
# Per-call record
# ---------------------------------------------------------------------------


@dataclass
class CallRecord:
    """Metrics captured for a single call to the backend."""

    latency_s: float
    prompt_tokens: int | None
    completion_tokens: int | None
    finish_reason: str | None
    near_ctx: bool  # prompt_tokens >= ctx_warn_frac * ctx_limit
    malformed: bool  # tool call with unparseable JSON or unknown name
    extra_calls_dropped: int  # parallel tool calls beyond the first that were discarded


# ---------------------------------------------------------------------------
# ChatCompletionsAgent
# ---------------------------------------------------------------------------


class ChatCompletionsAgent:
    """AgentProtocol implementation that uses the chat/completions endpoint.

    Parameters
    ----------
    backend:
        Any :class:`~redteam.sandbox.llm_backend.ChatBackend`.
    model:
        Model name passed to the backend (e.g. ``"qwen2.5:7b"``).
    temperature:
        Sampling temperature.  Default 0.7.
    max_tokens:
        Maximum tokens to generate per call.  Default 512.
    sample_seed:
        Base seed for the sequence ``seed_i = sample_seed + i``.  When
        ``None``, no seed is sent (see module docstring for guidance).
    system_suffix:
        Extra text appended to the system message after instruction events.
    ctx_limit:
        Approximate context-window size in tokens used only for the
        ``near_ctx`` warning flag.  Default 4096 (Ollama default).
    ctx_warn_frac:
        Fraction of ``ctx_limit`` at which ``near_ctx`` is set.
        Default 0.9 → warn at ≥ 3686 prompt tokens for a 4096-token context.
    """

    def __init__(
        self,
        *,
        backend: ChatBackend,
        model: str,
        temperature: float = 0.7,
        max_tokens: int = 512,
        sample_seed: int | None = None,
        system_suffix: str = "",
        ctx_limit: int = 4096,
        ctx_warn_frac: float = 0.9,
    ) -> None:
        self._backend = backend
        self._model = model
        self._temperature = temperature
        self._max_tokens = max_tokens
        self._sample_seed = sample_seed
        self._system_suffix = system_suffix
        self._ctx_limit = ctx_limit
        self._ctx_warn_frac = ctx_warn_frac
        self._call_index: int = 0
        self.call_records: list[CallRecord] = []

    # ------------------------------------------------------------------
    # AgentProtocol
    # ------------------------------------------------------------------

    def next_action(
        self,
        *,
        history: RuntimeHistory,
        tools: Sequence[AgentToolSpec],
    ) -> ToolCallDecision | FinalResponseDecision:
        canonical_to_openai, openai_to_canonical = build_openai_tool_name_maps(tools)

        messages = self._build_messages(history, canonical_to_openai)
        openai_tools = [
            _to_chat_completions_tool(spec, canonical_to_openai.get(spec.name, spec.name))
            for spec in tools
        ]

        seed: int | None = (
            self._sample_seed + self._call_index
            if self._sample_seed is not None
            else None
        )
        self._call_index += 1

        result: ChatResult = self._backend.chat(
            model=self._model,
            messages=messages,
            tools=openai_tools,
            temperature=self._temperature,
            max_tokens=self._max_tokens,
            seed=seed,
        )

        return self._parse_result(result, openai_to_canonical)

    def reset_state(self) -> None:
        """Clear all per-episode call records and counters."""
        self._call_index = 0
        self.call_records = []

    def snapshot_state(self) -> AgentStateSnapshot:
        return {
            "version": AGENT_STATE_VERSION,
            "backend": "chat_completions",
            "data": {"call_index": self._call_index},
        }

    def restore_state(self, snapshot: AgentStateSnapshot) -> None:
        if snapshot["version"] != AGENT_STATE_VERSION:
            raise AgentStateVersionError(
                f"Unsupported agent snapshot version: {snapshot['version']}"
            )
        if snapshot["backend"] != "chat_completions":
            raise AgentStateVersionError(
                f"Unsupported agent snapshot backend: {snapshot['backend']}"
            )
        self._call_index = int(snapshot["data"].get("call_index", 0))

    # ------------------------------------------------------------------
    # Summary
    # ------------------------------------------------------------------

    def summary(self) -> dict[str, Any]:
        """Return a diagnostic summary of all calls made since last reset_state."""
        records = self.call_records
        n = len(records)
        if n == 0:
            return {
                "n_calls": 0,
                "total_latency_s": 0.0,
                "max_prompt_tokens": None,
                "n_near_ctx": 0,
                "n_malformed": 0,
                "n_dropped": 0,
                "usage_available": False,
            }

        usage_records = [r for r in records if r.prompt_tokens is not None]
        return {
            "n_calls": n,
            "total_latency_s": sum(r.latency_s for r in records),
            "max_prompt_tokens": (
                max(r.prompt_tokens for r in usage_records)
                if usage_records else None
            ),
            "n_near_ctx": sum(1 for r in records if r.near_ctx),
            "n_malformed": sum(1 for r in records if r.malformed),
            "n_dropped": sum(r.extra_calls_dropped for r in records),
            # True only when ALL records have usage; warns if any are missing.
            "usage_available": len(usage_records) == n,
        }

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _build_messages(
        self,
        history: RuntimeHistory,
        canonical_to_openai: dict[str, str],
    ) -> list[dict[str, Any]]:
        """Convert RuntimeHistory into a chat/completions message list.

        System message
        --------------
        InstructionEvents are joined with double newlines and placed as a
        single ``role="system"`` message.  ``system_suffix`` is appended.

        Conversation messages
        ---------------------
        The chat/completions API requires that every assistant message that
        contains ``tool_calls`` is immediately followed by one ``role="tool"``
        message per tool call (matching ``tool_call_id``).

        We iterate the canonical events in order:
        - ``UserMessageEvent`` → ``{"role":"user","content":text}``
        - ``AssistantMessageEvent`` → ``{"role":"assistant","content":text}``
        - ``ToolRequestEvent`` → accumulated into ``pending_tool_calls`` list;
          an assistant message is emitted once we move past it.
        - ``ToolResultEvent`` → emitted as ``{"role":"tool",...}`` using the
          stored ``call_id``.
        """
        messages: list[dict[str, Any]] = []

        # System message from instruction events + suffix.
        parts = [ev.text for ev in history.instructions if ev.text.strip()]
        if self._system_suffix.strip():
            parts.append(self._system_suffix.strip())
        if parts:
            messages.append({"role": "system", "content": "\n\n".join(parts)})

        # Accumulate pending tool calls so we can emit them as one assistant message.
        pending_tool_calls: list[tuple[str, str, dict[str, Any]]] = []
        # (call_id, openai_name, arguments)

        for event in history.events:
            if isinstance(event, UserMessageEvent):
                # Flush any pending tool calls first (shouldn't happen in well-formed
                # history, but be defensive).
                if pending_tool_calls:
                    messages.append(_make_assistant_tool_calls_message(pending_tool_calls))
                    pending_tool_calls = []
                messages.append({"role": "user", "content": event.text})

            elif isinstance(event, AssistantMessageEvent):
                if pending_tool_calls:
                    messages.append(_make_assistant_tool_calls_message(pending_tool_calls))
                    pending_tool_calls = []
                messages.append({"role": "assistant", "content": event.text})

            elif isinstance(event, ToolRequestEvent):
                call = event.call
                openai_name = canonical_to_openai.get(call.tool_name, call.tool_name)
                pending_tool_calls.append(
                    (call.call_id, openai_name, dict(call.arguments))
                )

            elif isinstance(event, ToolResultEvent):
                # Emit the assistant message with tool_calls if not yet emitted.
                if pending_tool_calls:
                    messages.append(_make_assistant_tool_calls_message(pending_tool_calls))
                    pending_tool_calls = []
                result = event.result
                messages.append(
                    {
                        "role": "tool",
                        "tool_call_id": result.call_id,
                        "content": result.output_text,
                    }
                )

        # Flush any remaining pending tool calls.
        if pending_tool_calls:
            messages.append(_make_assistant_tool_calls_message(pending_tool_calls))

        return messages

    def _parse_result(
        self,
        result: ChatResult,
        openai_to_canonical: dict[str, str],
    ) -> ToolCallDecision | FinalResponseDecision:
        """Parse a ChatResult into an AgentDecision and record metrics."""
        msg = result.message
        tool_calls_raw: list[dict[str, Any]] = msg.get("tool_calls") or []
        content: str = msg.get("content") or ""

        malformed = False
        extra_calls_dropped = max(0, len(tool_calls_raw) - 1)

        decision: ToolCallDecision | FinalResponseDecision

        if tool_calls_raw:
            first = tool_calls_raw[0]
            openai_name: str = first.get("function", {}).get("name", "")
            raw_args: str = first.get("function", {}).get("arguments", "{}")
            call_id = f"call_{self._call_index:06d}"

            # Map name back to canonical.
            canonical_name = openai_to_canonical.get(openai_name)
            if canonical_name is None:
                # Unknown tool name → treat as final response.
                malformed = True
                decision = FinalResponseDecision(text=content)
            else:
                # Parse arguments JSON.
                try:
                    arguments = json.loads(raw_args)
                    if not isinstance(arguments, dict):
                        raise ValueError("arguments must be a JSON object")
                except Exception:
                    malformed = True
                    decision = FinalResponseDecision(text=content)
                else:
                    decision = ToolCallDecision(
                        call=ToolCall(
                            call_id=call_id,
                            tool_name=canonical_name,
                            arguments=arguments,
                        ),
                        assistant_message=content or None,
                    )
        else:
            # No tool calls → final response.
            decision = FinalResponseDecision(text=content)

        # Compute near-ctx flag.
        prompt_tokens: int | None = (
            result.usage.prompt_tokens if result.usage is not None else None
        )
        near_ctx = (
            prompt_tokens is not None
            and prompt_tokens >= self._ctx_warn_frac * self._ctx_limit
        )

        self.call_records.append(
            CallRecord(
                latency_s=result.latency_s,
                prompt_tokens=prompt_tokens,
                completion_tokens=(
                    result.usage.completion_tokens if result.usage is not None else None
                ),
                finish_reason=result.finish_reason,
                near_ctx=near_ctx,
                malformed=malformed,
                extra_calls_dropped=extra_calls_dropped,
            )
        )
        return decision


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------


def _make_assistant_tool_calls_message(
    pending: list[tuple[str, str, dict[str, Any]]],
) -> dict[str, Any]:
    """Build an assistant message dict with ``tool_calls`` from pending calls."""
    return {
        "role": "assistant",
        "content": None,
        "tool_calls": [
            {
                "id": call_id,
                "type": "function",
                "function": {
                    "name": openai_name,
                    "arguments": json.dumps(args, sort_keys=True),
                },
            }
            for call_id, openai_name, args in pending
        ],
    }


# ---------------------------------------------------------------------------
# Tool format builder for chat/completions (NOT Responses API)
# ---------------------------------------------------------------------------


def _to_chat_completions_tool(spec: AgentToolSpec, openai_name: str) -> dict[str, Any]:
    """Build the nested tool dict required by chat/completions endpoints.

    The OpenAI chat/completions (and Ollama) endpoint expects::

        {
            "type": "function",
            "function": {
                "name": "<sanitized_name>",
                "description": "<description>",
                "parameters": { ... JSON Schema ... }
            }
        }

    This differs from the Responses-API "flat" shape emitted by
    ``to_openai_function_tool`` which includes ``"name"`` and ``"strict"`` at
    the top level.  The ``"strict"`` key is intentionally omitted here because
    Ollama may reject it.
    """
    return {
        "type": "function",
        "function": {
            "name": openai_name,
            "description": spec.description,
            "parameters": dict(spec.parameters_json_schema),
        },
    }
