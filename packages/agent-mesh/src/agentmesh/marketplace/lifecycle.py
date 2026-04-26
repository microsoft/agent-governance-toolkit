# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Plugin Lifecycle Management
===========================

Tracks plugin state through its lifecycle: published → active → deprecated
→ end-of-life (EOL) → archived. Handles deprecation notices, EOL
enforcement, and certificate/signing key renewal.

Integrates with :class:`agentmesh.marketplace.registry.PluginRegistry`
and :class:`agentmesh.marketplace.signing.PluginSigner`.

Usage::

    from agentmesh.marketplace.lifecycle import PluginLifecycleManager

    manager = PluginLifecycleManager(registry)
    manager.deprecate("old-plugin", "2.0.0",
        reason="Replaced by new-plugin",
        successor="new-plugin",
        eol_date="2026-09-01",
    )
    status = manager.get_status("old-plugin", "2.0.0")
    assert status.phase == LifecyclePhase.DEPRECATED
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from typing import Any

logger = logging.getLogger(__name__)


class LifecyclePhase(str, Enum):
    """Plugin lifecycle phases."""

    PUBLISHED = "published"
    ACTIVE = "active"
    DEPRECATED = "deprecated"
    EOL = "end_of_life"
    ARCHIVED = "archived"


@dataclass
class DeprecationNotice:
    """Deprecation metadata for a plugin version."""

    reason: str
    deprecated_at: str = field(
        default_factory=lambda: datetime.now(UTC).isoformat()
    )
    eol_date: str = ""
    successor_plugin: str = ""
    successor_version: str = ""
    migration_guide_url: str = ""


@dataclass
class CertRenewalRecord:
    """Record of a signing certificate renewal."""

    old_key_fingerprint: str
    new_key_fingerprint: str
    renewed_at: str = field(
        default_factory=lambda: datetime.now(UTC).isoformat()
    )
    reason: str = ""


@dataclass
class PluginLifecycleStatus:
    """Current lifecycle status of a plugin version."""

    plugin_name: str
    version: str
    phase: LifecyclePhase
    deprecation: DeprecationNotice | None = None
    cert_renewals: list[CertRenewalRecord] = field(default_factory=list)
    phase_history: list[dict[str, str]] = field(default_factory=list)

    @property
    def is_usable(self) -> bool:
        """Plugin can still be installed and used."""
        return self.phase in (
            LifecyclePhase.PUBLISHED,
            LifecyclePhase.ACTIVE,
            LifecyclePhase.DEPRECATED,
        )

    @property
    def is_deprecated(self) -> bool:
        return self.phase == LifecyclePhase.DEPRECATED

    @property
    def is_eol(self) -> bool:
        return self.phase in (LifecyclePhase.EOL, LifecyclePhase.ARCHIVED)

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "plugin_name": self.plugin_name,
            "version": self.version,
            "phase": self.phase.value,
            "is_usable": self.is_usable,
        }
        if self.deprecation:
            result["deprecation"] = {
                "reason": self.deprecation.reason,
                "deprecated_at": self.deprecation.deprecated_at,
                "eol_date": self.deprecation.eol_date,
                "successor_plugin": self.deprecation.successor_plugin,
                "migration_guide_url": self.deprecation.migration_guide_url,
            }
        if self.cert_renewals:
            result["cert_renewals"] = [
                {
                    "old_key": r.old_key_fingerprint,
                    "new_key": r.new_key_fingerprint,
                    "renewed_at": r.renewed_at,
                    "reason": r.reason,
                }
                for r in self.cert_renewals
            ]
        return result


class PluginLifecycleManager:
    """Manage plugin lifecycle transitions and enforcement.

    Args:
        store: Backing store for lifecycle state. Defaults to in-memory dict.
    """

    def __init__(self, store: dict[str, PluginLifecycleStatus] | None = None) -> None:
        self._store: dict[str, PluginLifecycleStatus] = store or {}

    @staticmethod
    def _key(name: str, version: str) -> str:
        return f"{name}@{version}"

    def publish(self, name: str, version: str) -> PluginLifecycleStatus:
        """Register a newly published plugin version."""
        key = self._key(name, version)
        status = PluginLifecycleStatus(
            plugin_name=name,
            version=version,
            phase=LifecyclePhase.PUBLISHED,
            phase_history=[
                {"phase": "published", "at": datetime.now(UTC).isoformat()}
            ],
        )
        self._store[key] = status
        logger.info("Published %s", key)
        return status

    def activate(self, name: str, version: str) -> PluginLifecycleStatus:
        """Mark a plugin version as actively maintained."""
        status = self._get_or_create(name, version)
        status.phase = LifecyclePhase.ACTIVE
        status.phase_history.append(
            {"phase": "active", "at": datetime.now(UTC).isoformat()}
        )
        logger.info("Activated %s@%s", name, version)
        return status

    def deprecate(
        self,
        name: str,
        version: str,
        *,
        reason: str,
        successor: str = "",
        successor_version: str = "",
        eol_date: str = "",
        migration_guide_url: str = "",
    ) -> PluginLifecycleStatus:
        """Mark a plugin version as deprecated.

        Args:
            name: Plugin name.
            version: Plugin version.
            reason: Human-readable deprecation reason.
            successor: Name of the replacement plugin (if any).
            successor_version: Recommended successor version.
            eol_date: ISO-8601 date when the plugin reaches end-of-life.
            migration_guide_url: URL to migration documentation.
        """
        status = self._get_or_create(name, version)
        status.phase = LifecyclePhase.DEPRECATED
        status.deprecation = DeprecationNotice(
            reason=reason,
            successor_plugin=successor,
            successor_version=successor_version,
            eol_date=eol_date,
            migration_guide_url=migration_guide_url,
        )
        status.phase_history.append(
            {"phase": "deprecated", "at": datetime.now(UTC).isoformat()}
        )
        logger.info("Deprecated %s@%s: %s", name, version, reason)
        return status

    def end_of_life(self, name: str, version: str) -> PluginLifecycleStatus:
        """Mark a plugin version as end-of-life (no longer installable)."""
        status = self._get_or_create(name, version)
        status.phase = LifecyclePhase.EOL
        status.phase_history.append(
            {"phase": "end_of_life", "at": datetime.now(UTC).isoformat()}
        )
        logger.info("EOL %s@%s", name, version)
        return status

    def archive(self, name: str, version: str) -> PluginLifecycleStatus:
        """Archive a plugin version (fully retired)."""
        status = self._get_or_create(name, version)
        status.phase = LifecyclePhase.ARCHIVED
        status.phase_history.append(
            {"phase": "archived", "at": datetime.now(UTC).isoformat()}
        )
        logger.info("Archived %s@%s", name, version)
        return status

    def record_cert_renewal(
        self,
        name: str,
        version: str,
        *,
        old_key_fingerprint: str,
        new_key_fingerprint: str,
        reason: str = "scheduled rotation",
    ) -> CertRenewalRecord:
        """Record a signing certificate/key renewal for a plugin."""
        status = self._get_or_create(name, version)
        record = CertRenewalRecord(
            old_key_fingerprint=old_key_fingerprint,
            new_key_fingerprint=new_key_fingerprint,
            reason=reason,
        )
        status.cert_renewals.append(record)
        logger.info(
            "Cert renewal for %s@%s: %s → %s",
            name,
            version,
            old_key_fingerprint[:8],
            new_key_fingerprint[:8],
        )
        return record

    def get_status(self, name: str, version: str) -> PluginLifecycleStatus | None:
        """Get the lifecycle status of a plugin version."""
        return self._store.get(self._key(name, version))

    def check_install_allowed(self, name: str, version: str) -> tuple[bool, str]:
        """Check if a plugin version is allowed to be installed.

        Returns:
            Tuple of (allowed, reason). Deprecated plugins are allowed
            but return a warning reason. EOL/archived plugins are blocked.
        """
        status = self.get_status(name, version)
        if status is None:
            return True, ""

        if status.phase == LifecyclePhase.DEPRECATED:
            dep = status.deprecation
            msg = f"WARNING: {name}@{version} is deprecated"
            if dep:
                msg += f": {dep.reason}"
                if dep.successor_plugin:
                    msg += f". Use {dep.successor_plugin} instead."
                if dep.eol_date:
                    msg += f" EOL: {dep.eol_date}."
            return True, msg

        if status.phase in (LifecyclePhase.EOL, LifecyclePhase.ARCHIVED):
            return False, f"{name}@{version} has reached end-of-life and cannot be installed"

        return True, ""

    def enforce_eol_dates(self) -> list[PluginLifecycleStatus]:
        """Scan deprecated plugins and auto-transition those past EOL date.

        Returns:
            List of plugins that were transitioned to EOL.
        """
        now = datetime.now(UTC).isoformat()
        transitioned = []
        for status in self._store.values():
            if (
                status.phase == LifecyclePhase.DEPRECATED
                and status.deprecation
                and status.deprecation.eol_date
                and status.deprecation.eol_date <= now
            ):
                status.phase = LifecyclePhase.EOL
                status.phase_history.append(
                    {"phase": "end_of_life", "at": now, "auto": "eol_date_reached"}
                )
                transitioned.append(status)
                logger.info(
                    "Auto-EOL %s@%s (eol_date %s reached)",
                    status.plugin_name,
                    status.version,
                    status.deprecation.eol_date,
                )
        return transitioned

    def list_deprecated(self) -> list[PluginLifecycleStatus]:
        """List all deprecated plugin versions."""
        return [
            s for s in self._store.values()
            if s.phase == LifecyclePhase.DEPRECATED
        ]

    def list_eol(self) -> list[PluginLifecycleStatus]:
        """List all end-of-life plugin versions."""
        return [
            s for s in self._store.values()
            if s.phase in (LifecyclePhase.EOL, LifecyclePhase.ARCHIVED)
        ]

    def _get_or_create(self, name: str, version: str) -> PluginLifecycleStatus:
        key = self._key(name, version)
        if key not in self._store:
            self._store[key] = PluginLifecycleStatus(
                plugin_name=name,
                version=version,
                phase=LifecyclePhase.PUBLISHED,
                phase_history=[
                    {"phase": "published", "at": datetime.now(UTC).isoformat()}
                ],
            )
        return self._store[key]
