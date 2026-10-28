# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Sandbox state management — checkpoint / restore via ``docker commit``."""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from agent_sandbox.docker_provider.provider import DockerSandboxProvider

logger = logging.getLogger(__name__)

# One path component of a Docker image repository name (distribution
# reference grammar): lowercase alphanumerics, joined by ``.``, ``_``,
# ``__`` or runs of ``-``.
_REPO_COMPONENT_RE = re.compile(r"^[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*$")
# Docker's limit on the length of a whole repository name.
_REPO_NAME_MAX = 255

@dataclass
class SandboxCheckpoint:
    """Metadata for a saved sandbox checkpoint image."""

    agent_id: str
    name: str
    image_tag: str
    created_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )


class SandboxStateManager:
    """Manages checkpoint images for a ``DockerSandboxProvider``.

    This is an internal helper — callers should use the provider's
    ``save_state`` / ``restore_state`` / ``list_checkpoints`` /
    ``delete_checkpoint`` methods directly.
    """

    def __init__(self, provider: DockerSandboxProvider) -> None:
        self._provider = provider

    @staticmethod
    def _repo_name(agent_id: str) -> str:
        """Return the image repository that holds *agent_id*'s checkpoints.

        ``agent_id`` may contain uppercase letters and leading, trailing or
        repeated separators, which a repository name cannot, so
        ``docker commit`` would reject ``agent-sandbox-<agent_id>``. Such an
        id gets the repository ``agent-sandbox/id<escaped>``, where
        ``<escaped>`` keeps lowercase letters and digits, keeps a single
        ``-`` or ``.`` that sits between two kept characters, and writes
        every other character as ``_`` and its code point in two lowercase
        hex digits (``A`` -> ``_41``, ``_`` -> ``_5f``). ``_`` appears only
        as the start of an escape and every escape has the same width, so
        the id can be read back from the name and two ids never share a
        repository; ``Agent`` and ``agent`` stay apart, which lowercasing
        would not do. The ``id`` prefix keeps the component starting with
        an alphanumeric when the id starts with an escaped character.

        Ids that already form a valid name keep ``agent-sandbox-<agent_id>``,
        so existing checkpoints are unaffected, and as such a name contains
        no ``/`` it never collides with one under ``agent-sandbox/``.

        Raises ``ValueError`` if the escaped name would exceed Docker's
        255-character repository limit (a long id with many uppercase
        letters), or if *agent_id* contains a character outside ASCII,
        which ``create_session`` does not accept.
        """
        repo = f"agent-sandbox-{agent_id}"
        if _REPO_COMPONENT_RE.match(repo):
            return repo
        if not agent_id.isascii():
            raise ValueError(f"agent_id {agent_id!r} contains non-ASCII characters")

        def kept(char: str) -> bool:
            return char.isascii() and (char.islower() or char.isdigit())

        escaped = []
        for index, char in enumerate(agent_id):
            if kept(char):
                escaped.append(char)
            elif (
                char in "-."
                and index > 0
                and kept(agent_id[index - 1])
                and index + 1 < len(agent_id)
                and kept(agent_id[index + 1])
            ):
                escaped.append(char)
            else:
                escaped.append(f"_{ord(char):02x}")
        repo = "agent-sandbox/id" + "".join(escaped)
        if len(repo) > _REPO_NAME_MAX:
            raise ValueError(
                f"agent_id {agent_id!r} cannot be checkpointed: its image "
                f"repository name would be {len(repo)} characters, over "
                f"Docker's limit of {_REPO_NAME_MAX}"
            )
        return repo

    def save(
        self,
        agent_id: str,
        session_id: str,
        name: str,
    ) -> SandboxCheckpoint:
        """Snapshot the session's running container via ``docker commit``."""
        key = (agent_id, session_id)
        container = self._provider._containers.get(key)
        if container is None:
            raise RuntimeError(
                f"No active container for agent '{agent_id}', "
                f"session '{session_id}'"
            )

        repo = self._repo_name(agent_id)
        now = datetime.now(timezone.utc).isoformat()
        container.commit(
            repository=repo,
            tag=name,
            message=f"Checkpoint '{name}' for agent '{agent_id}' at {now}",
            conf={
                "Labels": {
                    "agent-sandbox.checkpoint": name,
                    "agent-sandbox.agent-id": agent_id,
                    "agent-sandbox.created-at": now,
                },
            },
        )
        logger.info("Saved checkpoint '%s' for agent '%s'", name, agent_id)
        return SandboxCheckpoint(
            agent_id=agent_id,
            name=name,
            image_tag=f"{repo}:{name}",
            created_at=now,
        )

    def restore(
        self,
        agent_id: str,
        session_id: str,
        name: str,
        config: Any | None = None,
    ) -> None:
        """Restore a checkpoint — destroy current container, recreate from image."""
        from agent_sandbox.sandbox_provider import SandboxConfig

        repo = self._repo_name(agent_id)
        image_tag = f"{repo}:{name}"

        # Verify the checkpoint image exists
        try:
            self._provider._client.images.get(image_tag)
        except Exception as exc:
            raise RuntimeError(
                f"Checkpoint image '{image_tag}' not found for agent "
                f"'{agent_id}'"
            ) from exc

        # Hold the provider's state lock across the entire destroy +
        # recreate sequence so a concurrent restore (or a concurrent
        # session create) cannot interleave with this one. The
        # explicit ``image`` argument to ``_create_container`` removes
        # the previous global ``self._provider._image`` mutation,
        # which let two concurrent restores swap images out from under
        # each other. Even with that mutation gone, the destroy +
        # recreate window must be serialised — otherwise an
        # interleaved create_session for the same key could win the
        # ``_containers[(agent_id, session_id)]`` slot.
        cfg = config or SandboxConfig()
        with self._provider._state_lock:
            # Preserve the policy evaluator across restore —
            # destroy_session pops it from _evaluators, so we save
            # and restore it. Also captured under the lock so the
            # snapshot matches the destroyed session.
            evaluator = self._provider._evaluators.get(
                (agent_id, session_id)
            )

            # Tear down the current container
            self._provider.destroy_session(agent_id, session_id)

            # Recreate container from the checkpoint image, passing
            # the image explicitly instead of mutating the provider's
            # base image attribute.
            container = self._provider._create_container(
                agent_id, session_id, cfg, image=image_tag
            )
            self._provider._containers[(agent_id, session_id)] = container

            # Re-attach the policy evaluator to the restored session
            if evaluator is not None:
                self._provider._evaluators[
                    (agent_id, session_id)
                ] = evaluator

        logger.info(
            "Restored checkpoint '%s' for agent '%s'", name, agent_id
        )

    def list_checkpoints(self, agent_id: str) -> list[SandboxCheckpoint]:
        """List all checkpoint images for the agent."""
        repo = self._repo_name(agent_id)
        try:
            images = self._provider._client.images.list(name=repo)
        except Exception:
            return []

        checkpoints: list[SandboxCheckpoint] = []
        for img in images:
            labels = img.labels or {}
            for tag in img.tags:
                if ":" in tag:
                    _, cp_name = tag.rsplit(":", 1)
                else:
                    cp_name = tag
                checkpoints.append(
                    SandboxCheckpoint(
                        agent_id=agent_id,
                        name=cp_name,
                        image_tag=tag,
                        created_at=labels.get(
                            "agent-sandbox.created-at", ""
                        ),
                    )
                )
        return checkpoints

    def delete_checkpoint(self, agent_id: str, name: str) -> None:
        """Remove a checkpoint image."""
        repo = self._repo_name(agent_id)
        image_tag = f"{repo}:{name}"
        try:
            self._provider._client.images.remove(
                image=image_tag, force=True
            )
            logger.info(
                "Deleted checkpoint '%s' for agent '%s'", name, agent_id
            )
        except Exception as exc:
            raise RuntimeError(
                f"Failed to delete checkpoint '{image_tag}': {exc}"
            ) from exc
