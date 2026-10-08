"""Agent re-exports and factories for agent-redteam.

``ScriptedVictim`` is a re-export of the SDK's ``VulnerableDeterministicAgent``
(a deterministic, no-LLM reference victim agent that naively follows injected
instructions from tool outputs).

``ChatCompletionsAgent`` is the LLM-backed victim agent; use
``make_chat_agent_factory`` to create a zero-arg factory compatible with
``run_episode``.

TODO (next task): Add LLM attacker agent.
"""

from __future__ import annotations

from typing import Any, Callable

from aicomp_sdk.agents.deterministic_agent import (
    VulnerableDeterministicAgent as ScriptedVictim,
)

from redteam.sandbox.llm_agent import ChatCompletionsAgent

__all__ = [
    "ScriptedVictim",
    "ChatCompletionsAgent",
    "make_chat_agent_factory",
    "make_ollama_backend",
]


def make_ollama_backend(base_url: str = "http://localhost:11434/v1") -> "Any":
    """Return an :class:`~redteam.sandbox.llm_backend.OpenAICompatBackend` for Ollama.

    Parameters
    ----------
    base_url:
        Ollama OpenAI-compatible endpoint.  Default: ``http://localhost:11434/v1``.
    """
    from redteam.sandbox.llm_backend import OpenAICompatBackend  # noqa: PLC0415

    return OpenAICompatBackend(base_url=base_url)


def make_chat_agent_factory(
    backend: "Any",
    model: str,
    **kw: Any,
) -> Callable[[], ChatCompletionsAgent]:
    """Return a zero-arg factory that creates a fresh :class:`ChatCompletionsAgent`.

    Compatible with ``run_episode``'s ``agent_factory`` parameter.

    Parameters
    ----------
    backend:
        A :class:`~redteam.sandbox.llm_backend.ChatBackend` instance.
    model:
        Model name, e.g. ``"qwen2.5:7b"``.
    **kw:
        Extra keyword arguments forwarded to :class:`ChatCompletionsAgent`
        (e.g. ``temperature``, ``max_tokens``, ``sample_seed``).
    """

    def _factory() -> ChatCompletionsAgent:
        return ChatCompletionsAgent(backend=backend, model=model, **kw)

    return _factory
