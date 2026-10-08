"""LLM backend abstractions for agent-redteam.

Provides:
- :class:`ChatUsage` / :class:`ChatResult` – typed result containers.
- :class:`ChatBackend` – Protocol that all backends implement.
- :class:`OpenAICompatBackend` – thin wrapper around ``openai.chat.completions``
  compatible with any OpenAI-compatible endpoint (e.g. Ollama at
  ``http://localhost:11434/v1``).
- :class:`CassetteBackend` – record/replay wrapper for deterministic offline
  testing.  Keys by SHA-256 over canonical JSON of the request parameters.
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol, runtime_checkable

import openai


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass
class ChatUsage:
    """Token-usage counters returned by the model."""

    prompt_tokens: int
    completion_tokens: int


@dataclass
class ChatResult:
    """Normalised result of one chat-completions call.

    ``message`` is the raw OpenAI-style assistant message dict
    (keys: ``role``, ``content``, optionally ``tool_calls``).
    ``usage`` may be ``None`` when the backend does not report usage.
    """

    message: dict[str, Any]
    usage: ChatUsage | None
    latency_s: float
    finish_reason: str | None
    raw_model: str | None


# ---------------------------------------------------------------------------
# Protocol
# ---------------------------------------------------------------------------


@runtime_checkable
class ChatBackend(Protocol):
    """Minimal interface every backend must satisfy."""

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
        """Send one chat-completions request and return a normalised result."""
        ...


# ---------------------------------------------------------------------------
# OpenAICompatBackend
# ---------------------------------------------------------------------------


class OpenAICompatBackend:
    """Chat-completions backend pointing at any OpenAI-compatible endpoint.

    Parameters
    ----------
    base_url:
        Base URL, e.g. ``"http://localhost:11434/v1"`` for Ollama.
    api_key:
        API key string.  Defaults to ``"ollama"`` (Ollama ignores the value).
    timeout_s:
        Per-request timeout in seconds.  Default 180.
    retries:
        Number of *additional* attempts on connection / timeout errors only
        (not on model-level errors such as 4xx/5xx).  Default 2.
    """

    def __init__(
        self,
        base_url: str,
        api_key: str = "ollama",
        timeout_s: float = 180.0,
        retries: int = 2,
    ) -> None:
        self._client = openai.OpenAI(
            base_url=base_url,
            api_key=api_key,
            # Disable the SDK's built-in retries; we handle retries ourselves
            # so we can apply them only to connection/timeout errors.
            max_retries=0,
            timeout=timeout_s,
        )
        self._retries = retries

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
        kwargs: dict[str, Any] = dict(
            model=model,
            messages=messages,
            temperature=temperature,
            max_tokens=max_tokens,
        )
        if tools:
            kwargs["tools"] = tools
        if seed is not None:
            kwargs["seed"] = seed

        last_exc: Exception | None = None
        for attempt in range(self._retries + 1):
            if attempt > 0:
                time.sleep(0.5 * attempt)  # short backoff: 0.5s, 1.0s, …
            try:
                t0 = time.perf_counter()
                resp = self._client.chat.completions.create(**kwargs)
                latency_s = time.perf_counter() - t0
                break
            except (openai.APIConnectionError, openai.APITimeoutError) as exc:
                last_exc = exc
                continue
        else:
            raise last_exc  # type: ignore[misc]

        choice = resp.choices[0]
        msg = choice.message

        # Convert to plain dict (the SDK returns a Pydantic model).
        message_dict: dict[str, Any] = {"role": msg.role, "content": msg.content}
        if msg.tool_calls:
            message_dict["tool_calls"] = [
                {
                    "id": tc.id,
                    "type": tc.type,
                    "function": {
                        "name": tc.function.name,
                        "arguments": tc.function.arguments,
                    },
                }
                for tc in msg.tool_calls
            ]

        usage: ChatUsage | None = None
        if resp.usage is not None:
            usage = ChatUsage(
                prompt_tokens=resp.usage.prompt_tokens,
                completion_tokens=resp.usage.completion_tokens,
            )

        return ChatResult(
            message=message_dict,
            usage=usage,
            latency_s=latency_s,
            finish_reason=choice.finish_reason,
            raw_model=resp.model,
        )


# ---------------------------------------------------------------------------
# CassetteMiss
# ---------------------------------------------------------------------------


class CassetteMiss(LookupError):
    """Raised by :class:`CassetteBackend` in replay mode when a key is absent."""


# ---------------------------------------------------------------------------
# CassetteBackend
# ---------------------------------------------------------------------------


def _cassette_key(
    *,
    model: str,
    temperature: float,
    seed: int | None,
    max_tokens: int,
    messages: list[dict[str, Any]],
    tools: list[dict[str, Any]],
) -> str:
    """Return the SHA-256 hex digest that keys a cassette entry."""
    canonical = json.dumps(
        {
            "model": model,
            "temperature": temperature,
            "seed": seed,
            "max_tokens": max_tokens,
            "messages": messages,
            "tools": tools,
        },
        sort_keys=True,
        ensure_ascii=True,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class CassetteBackend:
    """Record / replay wrapper around any :class:`ChatBackend`.

    Modes
    -----
    ``"record"``:
        Always call *inner*; append every response to the JSONL file.
    ``"replay"``:
        Load the cassette at construction; never call *inner*.
        A cache miss raises :class:`CassetteMiss`.
    ``"auto"``:
        Replay on hit; call *inner* and append on miss.

    The cassette is a JSONL file where each line is a JSON object with keys
    ``key`` (SHA-256 hex) and ``result`` (the serialised :class:`ChatResult`).
    ``usage`` is stored so cost accounting survives caching.
    """

    def __init__(
        self,
        inner: ChatBackend,
        path: str | Path,
        mode: str = "auto",
    ) -> None:
        if mode not in ("record", "replay", "auto"):
            raise ValueError(f"mode must be 'record', 'replay', or 'auto'; got {mode!r}")
        self._inner = inner
        self._path = Path(path)
        self._mode = mode
        self._store: dict[str, ChatResult] = {}
        self.hits = 0
        self.misses = 0

        if mode in ("replay", "auto") and self._path.exists():
            self._load()

    def _load(self) -> None:
        with open(self._path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                    key = entry["key"]
                    r = entry["result"]
                    usage = None
                    if r.get("usage") is not None:
                        usage = ChatUsage(**r["usage"])
                    self._store[key] = ChatResult(
                        message=r["message"],
                        usage=usage,
                        latency_s=r["latency_s"],
                        finish_reason=r.get("finish_reason"),
                        raw_model=r.get("raw_model"),
                    )
                except Exception:
                    pass  # skip malformed lines

    def _append(self, key: str, result: ChatResult) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        entry = {
            "key": key,
            "result": {
                "message": result.message,
                "usage": (
                    {"prompt_tokens": result.usage.prompt_tokens,
                     "completion_tokens": result.usage.completion_tokens}
                    if result.usage is not None else None
                ),
                "latency_s": result.latency_s,
                "finish_reason": result.finish_reason,
                "raw_model": result.raw_model,
            },
        }
        with open(self._path, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=True) + "\n")

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
        key = _cassette_key(
            model=model,
            temperature=temperature,
            seed=seed,
            max_tokens=max_tokens,
            messages=messages,
            tools=tools,
        )

        if self._mode == "replay":
            if key in self._store:
                self.hits += 1
                return self._store[key]
            self.misses += 1
            raise CassetteMiss(f"No cassette entry for key {key[:12]}…")

        if self._mode in ("auto", "record"):
            if self._mode == "auto" and key in self._store:
                self.hits += 1
                return self._store[key]

            # Call inner backend and record.
            self.misses += 1
            result = self._inner.chat(
                model=model,
                messages=messages,
                tools=tools,
                temperature=temperature,
                max_tokens=max_tokens,
                seed=seed,
            )
            self._store[key] = result
            self._append(key, result)
            return result

        raise RuntimeError(f"Unreachable mode: {self._mode!r}")
