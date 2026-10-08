"""Fixture builder for agent-redteam sandbox episodes.

Provides frozen dataclasses for individual planted items (EmailPlant, WebPlant,
FilePlant), a ``build_fixtures`` function that copies the clean baseline fixtures
into a target directory and merges any Plants on top, and an ``EpisodeWorkspace``
context manager that owns the temporary directory lifecycle.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

# Root of the clean baseline fixtures (shipped with redteam package).
_CLEAN_FIXTURES_DIR: Path = Path(__file__).parent / "fixtures_clean"

# Hard limit on plant content to guard against accidental huge injections.
_MAX_PLANT_CONTENT_CHARS: int = 10_000


# ---------------------------------------------------------------------------
# Frozen plant dataclasses
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class EmailPlant:
    """A single email to append to the inbox in mail_seed.json."""

    id: str
    sender: str
    subject: str
    body: str


@dataclass(frozen=True)
class WebPlant:
    """A single web page to append to the corpus in web_corpus.json."""

    id: str
    title: str
    url: str
    content: str


@dataclass(frozen=True)
class FilePlant:
    """A file to write into file_seed/."""

    path: str  # Relative path inside file_seed/ — no "..", no absolute, no drive letters.
    content: str


# A Plant set is a tuple of any mix of the three plant types.
Plant = EmailPlant | WebPlant | FilePlant


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------


def _validate_file_path(path: str) -> None:
    """Raise ValueError for unsafe file paths."""
    if not path:
        raise ValueError("FilePlant path must not be empty.")
    # Reject absolute paths (Windows drive letters and Unix /)
    if os.path.isabs(path):
        raise ValueError(f"FilePlant path must be relative, got: {path!r}")
    # Reject Windows drive letters like C:
    if re.match(r"^[A-Za-z]:", path):
        raise ValueError(f"FilePlant path contains a drive letter: {path!r}")
    # Reject path traversal
    normalized = os.path.normpath(path)
    if normalized.startswith(".."):
        raise ValueError(f"FilePlant path escapes the sandbox root: {path!r}")


def _validate_plant_content(content: str, label: str) -> None:
    """Raise ValueError if content exceeds the per-plant cap."""
    if len(content) > _MAX_PLANT_CONTENT_CHARS:
        raise ValueError(
            f"{label} content exceeds {_MAX_PLANT_CONTENT_CHARS} chars "
            f"(got {len(content)})."
        )


# ---------------------------------------------------------------------------
# Core build function
# ---------------------------------------------------------------------------


def build_fixtures(
    plants: tuple[Plant, ...],
    dest_dir: str | os.PathLike[str],
) -> None:
    """Copy the clean baseline fixtures into *dest_dir* and apply *plants*.

    Steps
    -----
    1. Copy ``fixtures_clean/`` into ``dest_dir`` (overwriting dest if it exists).
    2. For each :class:`EmailPlant`, append the email to ``mail_seed.json``.
       Raises :exc:`ValueError` on duplicate email ``id``.
    3. For each :class:`WebPlant`, append the page to ``web_corpus.json``.
       Raises :exc:`ValueError` on duplicate page ``id``.
    4. For each :class:`FilePlant`, write the file into ``file_seed/``.
       Overwriting an existing file is **allowed**; duplicate ids within the
       same call (for emails/pages) raise :exc:`ValueError`.

    Validation
    ----------
    - ``FilePlant.path`` must be relative, contain no ``..``, and have no
      drive letter — otherwise :exc:`ValueError` is raised.
    - Each plant's content must not exceed :data:`_MAX_PLANT_CONTENT_CHARS`.
    """
    dest = Path(dest_dir)
    dest.mkdir(parents=True, exist_ok=True)

    # 1. Copy clean baseline.
    shutil.copytree(
        _CLEAN_FIXTURES_DIR,
        dest,
        dirs_exist_ok=True,
    )

    # Separate plants by type.
    email_plants = [p for p in plants if isinstance(p, EmailPlant)]
    web_plants = [p for p in plants if isinstance(p, WebPlant)]
    file_plants = [p for p in plants if isinstance(p, FilePlant)]

    # 2. Merge email plants.
    if email_plants:
        mail_path = dest / "mail_seed.json"
        with open(mail_path, encoding="utf-8") as f:
            mail_data: dict[str, Any] = json.load(f)
        inbox: list[dict[str, Any]] = mail_data.setdefault("inbox", [])
        existing_ids = {e["id"] for e in inbox}
        for ep in email_plants:
            _validate_plant_content(ep.body, f"EmailPlant(id={ep.id!r})")
            if ep.id in existing_ids:
                raise ValueError(f"Duplicate email id in plants: {ep.id!r}")
            existing_ids.add(ep.id)
            inbox.append(
                {"id": ep.id, "from": ep.sender, "subject": ep.subject, "body": ep.body}
            )
        with open(mail_path, "w", encoding="utf-8") as f:
            json.dump(mail_data, f, indent=2)

    # 3. Merge web plants.
    if web_plants:
        web_path = dest / "web_corpus.json"
        with open(web_path, encoding="utf-8") as f:
            web_data: dict[str, Any] = json.load(f)
        pages: list[dict[str, Any]] = web_data.setdefault("pages", [])
        existing_ids = {p["id"] for p in pages}
        for wp in web_plants:
            _validate_plant_content(wp.content, f"WebPlant(id={wp.id!r})")
            if wp.id in existing_ids:
                raise ValueError(f"Duplicate web page id in plants: {wp.id!r}")
            existing_ids.add(wp.id)
            pages.append(
                {"id": wp.id, "title": wp.title, "url": wp.url, "content": wp.content}
            )
        with open(web_path, "w", encoding="utf-8") as f:
            json.dump(web_data, f, indent=2)

    # 4. Write file plants.
    file_seed_dir = dest / "file_seed"
    file_seed_dir.mkdir(exist_ok=True)
    for fp in file_plants:
        _validate_file_path(fp.path)
        _validate_plant_content(fp.content, f"FilePlant(path={fp.path!r})")
        target = file_seed_dir / fp.path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(fp.content, encoding="utf-8")


# ---------------------------------------------------------------------------
# plants_hash
# ---------------------------------------------------------------------------


def plants_hash(plants: tuple[Plant, ...]) -> str:
    """Return a stable SHA-256 hex digest of the canonical JSON of *plants*.

    The hash is deterministic: same plants in the same order → same hash.
    Can be used as a cache key to avoid re-building identical fixture sets.
    """
    serializable: list[dict[str, Any]] = []
    for p in plants:
        if isinstance(p, EmailPlant):
            serializable.append(
                {"type": "email", "id": p.id, "sender": p.sender, "subject": p.subject, "body": p.body}
            )
        elif isinstance(p, WebPlant):
            serializable.append(
                {"type": "web", "id": p.id, "title": p.title, "url": p.url, "content": p.content}
            )
        elif isinstance(p, FilePlant):
            serializable.append({"type": "file", "path": p.path, "content": p.content})
        else:
            raise TypeError(f"Unknown plant type: {type(p)}")
    canonical = json.dumps(serializable, sort_keys=True, ensure_ascii=True)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# EpisodeWorkspace context manager
# ---------------------------------------------------------------------------


class EpisodeWorkspace:
    """Context manager that owns a temporary fixtures directory for one episode.

    Usage::

        plants = (EmailPlant(id="msg1", sender="x@y.invalid", subject="Hi", body="Hello"),)
        with EpisodeWorkspace(plants) as ws:
            env = SandboxEnv(seed=123, fixtures_dir=ws.fixtures_dir, agent=my_agent)
            env.interact("Do something")

    On exit the temporary directory is removed explicitly (does not rely on GC).
    """

    def __init__(self, plants: tuple[Plant, ...] = ()) -> None:
        self._plants = plants
        self._tmpdir: tempfile.TemporaryDirectory[str] | None = None
        self.fixtures_dir: str = ""

    def __enter__(self) -> "EpisodeWorkspace":
        self._tmpdir = tempfile.TemporaryDirectory(prefix="redteam_ep_")
        self.fixtures_dir = self._tmpdir.name
        build_fixtures(self._plants, self.fixtures_dir)
        return self

    def __exit__(self, exc_type: object, exc_val: object, exc_tb: object) -> None:
        if self._tmpdir is not None:
            self._tmpdir.cleanup()
            self._tmpdir = None
            self.fixtures_dir = ""
