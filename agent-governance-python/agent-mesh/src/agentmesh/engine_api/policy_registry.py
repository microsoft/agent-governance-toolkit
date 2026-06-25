# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Filesystem-backed policy registry for the Engine API reference adapter.

This is the real backend for the policy read routes (``GET /api/v1/policies`` and
``GET /api/v1/policies/{id}``) and the single write route (``POST /api/v1/policy/save``). It
scans a policy directory, derives a :class:`~agentmesh.engine_api.models.PolicySummary` /
:class:`~agentmesh.engine_api.models.PolicyDetail` per file, and re-scans on demand.

It deliberately does **not** reuse the module-global state in
``agentmesh.server.policy_server`` (which only tracks counts) and does not modify it. Policy
metadata is extracted with a tolerant raw parse (``yaml.safe_load`` / ``json.loads``) so a
single malformed file never breaks the listing - it simply lists with the id as the name and
a zero rule count.

``save`` persists the policy file and then calls :meth:`PolicyRegistry.reload`. That re-scan
is the intended reload side effect of saving (contract section 8.1); the standalone
``POST /api/v1/policy/reload`` route is excluded by the spec and is not exposed.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import logging
import os
import tempfile
import threading
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

import yaml

from agentmesh.engine_api.models import PolicyDetail, PolicySummary

logger = logging.getLogger(__name__)

#: Glob suffix -> contract ``format`` value.
_YAML_SUFFIXES = {".yaml", ".yml"}
_JSON_SUFFIXES = {".json"}


@dataclass(frozen=True)
class _PolicyRecord:
    """Internal per-file policy record."""

    id: str
    name: str
    format: str
    source: str
    description: str | None
    content: str
    rules_count: int
    last_modified: datetime

    def to_summary(self) -> PolicySummary:
        return PolicySummary(
            id=self.id,
            name=self.name,
            format=self.format,  # type: ignore[arg-type]
            source=self.source,
            description=self.description,
        )

    def to_detail(self) -> PolicyDetail:
        return PolicyDetail(
            id=self.id,
            name=self.name,
            format=self.format,  # type: ignore[arg-type]
            source=self.source,
            description=self.description,
            content=self.content,
            rules_count=self.rules_count,
            last_modified=self.last_modified,
        )


def _format_for_suffix(suffix: str) -> str | None:
    lowered = suffix.lower()
    if lowered in _YAML_SUFFIXES:
        return "yaml"
    if lowered in _JSON_SUFFIXES:
        return "json"
    return None


def _extract_meta(text: str, fmt: str) -> tuple[str | None, str | None, int]:
    """Tolerantly extract ``(name, description, rules_count)`` from policy content."""
    try:
        data = yaml.safe_load(text) if fmt == "yaml" else json.loads(text)
    except (yaml.YAMLError, json.JSONDecodeError, ValueError):
        return None, None, 0
    if not isinstance(data, dict):
        return None, None, 0
    name = data.get("name")
    description = data.get("description")
    rules = data.get("rules", [])
    rules_count = len(rules) if isinstance(rules, list) else 0
    return (
        name if isinstance(name, str) else None,
        description if isinstance(description, str) else None,
        rules_count,
    )


class PolicyRegistry:
    """Scans a policy directory and serves policy summaries/details.

    Args:
        policy_dir: Directory containing ``*.yaml`` / ``*.yml`` / ``*.json`` policy files.
            The directory need not exist; an absent directory yields an empty registry.
    """

    def __init__(self, policy_dir: str | Path) -> None:
        self._policy_dir = Path(policy_dir)
        self._records: dict[str, _PolicyRecord] = {}
        # Re-entrant so ``save`` can hold the lock across its own ``reload`` call. Serializes
        # the read-modify-write in ``save`` against concurrent ``load``/``reload`` scans.
        self._lock = threading.RLock()
        self.load()

    @property
    def policy_dir(self) -> Path:
        return self._policy_dir

    def load(self) -> None:
        """Scan the policy directory and rebuild the in-memory record map."""
        with self._lock:
            records: dict[str, _PolicyRecord] = {}
            if not self._policy_dir.exists():
                logger.warning("Policy directory %s does not exist", self._policy_dir)
                self._records = records
                return

            for path in sorted(self._policy_dir.iterdir()):
                if not path.is_file():
                    continue
                fmt = _format_for_suffix(path.suffix)
                if fmt is None:
                    continue
                try:
                    content = path.read_text(encoding="utf-8")
                except OSError as exc:
                    logger.warning("Could not read policy %s: %s", path.name, exc)
                    continue

                policy_id = path.stem
                if policy_id in records:
                    logger.warning(
                        "Duplicate policy id '%s' across formats: '%s' shadows '%s'. "
                        "Keep one file per id to avoid ambiguity.",
                        policy_id,
                        path.name,
                        records[policy_id].source,
                    )
                name, description, rules_count = _extract_meta(content, fmt)
                last_modified = datetime.fromtimestamp(path.stat().st_mtime, tz=UTC)
                records[policy_id] = _PolicyRecord(
                    id=policy_id,
                    name=name or policy_id,
                    format=fmt,
                    source=path.name,
                    description=description,
                    content=content,
                    rules_count=rules_count,
                    last_modified=last_modified,
                )

            self._records = records
            logger.info("Loaded %d policies from %s", len(records), self._policy_dir)

    def reload(self) -> None:
        """Re-scan the policy directory. Alias of :meth:`load`."""
        self.load()

    def list_summaries(self) -> list[PolicySummary]:
        """Return all policy summaries, ordered by id."""
        return [self._records[pid].to_summary() for pid in sorted(self._records)]

    def get_detail(self, policy_id: str) -> PolicyDetail | None:
        """Return the :class:`PolicyDetail` for ``policy_id`` or ``None`` if unknown."""
        record = self._records.get(policy_id)
        return record.to_detail() if record is not None else None

    def save(self, policy_id: str, content: str, fmt: str) -> str:
        """Persist a policy file, re-scan, and return an opaque version token.

        Args:
            policy_id: Validated policy identifier (becomes the filename stem).
            content: Raw policy content to write.
            fmt: ``"yaml"`` or ``"json"`` - selects the file extension.

        Returns:
            An opaque version token (a content hash) for optimistic concurrency.
        """
        suffix = ".yaml" if fmt == "yaml" else ".json"
        with self._lock:
            self._policy_dir.mkdir(parents=True, exist_ok=True)
            target = self._policy_dir / f"{policy_id}{suffix}"
            # Defense in depth: the HTTP layer validates ``policy_id`` against a strict
            # pattern, but guard the primitive too so a future caller cannot escape the
            # policy directory via separators or ``..`` segments.
            if target.resolve().parent != self._policy_dir.resolve():
                raise ValueError(
                    f"Invalid policy id '{policy_id}': resolves outside the policy directory"
                )
            # One file per id: drop any sibling stored in another recognized format so saving
            # ``alpha`` as JSON does not leave a stale ``alpha.yaml`` that silently shadows it
            # on the next reload (sorted ``iterdir`` order is otherwise the only tiebreaker).
            for other_suffix in (*_YAML_SUFFIXES, *_JSON_SUFFIXES):
                sibling = self._policy_dir / f"{policy_id}{other_suffix}"
                if sibling != target and sibling.exists():
                    with contextlib.suppress(OSError):
                        sibling.unlink()
            # Atomic write: write to a temp file in the same directory, then ``os.replace``,
            # so a crash or signal mid-write can never leave a partially written policy file.
            # The temp name carries a ``.tmp`` suffix so a concurrent reload scan skips it.
            fd, tmp_path = tempfile.mkstemp(
                dir=self._policy_dir, prefix=f".{policy_id}.", suffix=f"{suffix}.tmp"
            )
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as handle:
                    handle.write(content)
                os.replace(tmp_path, target)
            except BaseException:
                with contextlib.suppress(OSError):
                    os.unlink(tmp_path)
                raise
            self.reload()
            return hashlib.sha256(content.encode("utf-8")).hexdigest()[:16]
