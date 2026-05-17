# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Plugin Installer

Download, verify, install, and uninstall AgentMesh plugins with dependency
resolution and install-time restricted-import scanning.

Security contract
-----------------
* **Install time** — :meth:`PluginInstaller.install` calls
  :meth:`PluginInstaller.scan_source_files` on every ``*.py`` file that
  lands in the plugin directory and raises :class:`~agent_marketplace.manifest.MarketplaceError`
  if any file imports a module from :data:`RESTRICTED_MODULES`.
* **Runtime** — full subprocess isolation with import blocking is provided
  by ``agentmesh.marketplace.sandbox.PluginSandbox``.

:func:`check_sandbox` is a **policy predicate** — it returns ``True``/``False``
for a single module name but does *not* block any import by itself.
"""

from __future__ import annotations

import ast
import hashlib
import hmac
import logging
import os
import shutil
import tempfile
import urllib.request
import zipfile
from pathlib import Path
from types import MappingProxyType
from typing import Any, Mapping, Optional

import yaml
from packaging.requirements import InvalidRequirement, Requirement

from agent_marketplace.manifest import (
    MANIFEST_FILENAME,
    MarketplaceError,
    PluginManifest,
    load_manifest,
)
from agent_marketplace.registry import PluginRegistry
from agent_marketplace.signing import verify_signature

logger = logging.getLogger(__name__)

# Modules that plugins are NOT allowed to import
RESTRICTED_MODULES = frozenset(
    {
        "subprocess",
        "os",
        "shutil",
        "ctypes",
        "importlib",
    }
)

# Name of the stored artifact archive inside each installed plugin directory.
# Kept after unpacking so _verify_on_disk() can re-check the SHA-256 hash.
ARTIFACT_FILENAME = ".artifact.zip"


class PluginInstaller:
    """Install, uninstall, and manage AgentMesh plugins.

    Args:
        plugins_dir: Directory where plugins are installed.
        registry: Plugin registry to resolve names/versions.
        trusted_keys: Optional mapping of author → Ed25519 public key for
            signature verification.

    Example:
        >>> installer = PluginInstaller(Path("./plugins"), registry)
        >>> installer.install("my-plugin", "1.0.0")
    """

    def __init__(
        self,
        plugins_dir: Path,
        registry: PluginRegistry,
        trusted_keys: Optional[Mapping[str, Any]] = None,
    ) -> None:
        self._plugins_dir = plugins_dir
        self._registry = registry
        # Freeze trusted keys at construction time to prevent runtime mutation.
        self._trusted_keys: MappingProxyType[str, Any] = MappingProxyType(
            dict(trusted_keys) if trusted_keys else {}
        )
        self._plugins_dir.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------
    # Install / Uninstall
    # ------------------------------------------------------------------

    def install(
        self,
        name: str,
        version: Optional[str] = None,
        *,
        verify: bool = True,
        _seen: Optional[set[str]] = None,
    ) -> Path:
        """Install a plugin from the registry.

        Steps:
            1. Resolve manifest from registry.
            2. Verify Ed25519 signature when ``verify=True`` (the signature
               covers all manifest fields including ``artifact_sha256``, so
               it cryptographically binds the manifest to the artifact).
            3. Resolve and install dependencies (recursively).
            4. Download the plugin artifact archive from ``manifest.artifact_url``
               (if set), verify its SHA-256 digest against
               ``manifest.artifact_sha256``, and unpack it under
               ``plugins_dir/<name>/``.  The archive is also kept as
               ``plugins_dir/<name>/.artifact.zip`` for on-load re-verification.
               If ``artifact_url`` is not set, no code is placed on disk; only
               the manifest is written (manifest-registration mode).
            5. Write the manifest atomically to
               ``plugins_dir/<name>/agent-plugin.yaml``.

        Args:
            name: Plugin name.
            version: Desired version (``None`` for latest).
            verify: Whether to verify the Ed25519 signature and artifact hash.

        Returns:
            Path to the installed plugin directory.

        Raises:
            MarketplaceError: On resolution, verification, download, or
                dependency errors.
        """
        manifest = self._registry.get_plugin(name, version)

        # Signature verification — fail closed when verify=True
        if verify:
            if not manifest.signature:
                raise MarketplaceError(
                    f"Plugin {name}@{manifest.version} has no signature; "
                    "install with verify=False to bypass (not recommended)"
                )
            if manifest.author not in self._trusted_keys:
                raise MarketplaceError(
                    f"Plugin {name}@{manifest.version} signed by untrusted "
                    f"author '{manifest.author}'"
                )
            public_key = self._trusted_keys[manifest.author]
            verify_signature(manifest, public_key)
            logger.info("Signature verified for %s@%s", name, manifest.version)

        # Dependency resolution
        if _seen is None:
            _seen = set()
        self._resolve_dependencies(manifest, verify=verify, _seen=_seen)

        # Install to plugins directory
        dest = self._plugins_dir / name
        dest.mkdir(parents=True, exist_ok=True)

        # Artifact download + verification (when manifest declares an artifact)
        if manifest.artifact_url:
            self._fetch_artifact(manifest, dest, verify=verify)

        manifest_file = dest / MANIFEST_FILENAME

        data = manifest.model_dump(mode="json")
        _atomic_write_yaml(manifest_file, data)

        # Scan any bundled Python source files for restricted imports.
        violations = self.scan_source_files(dest)
        if violations:
            try:
                shutil.rmtree(dest)
            except OSError:
                pass
            raise MarketplaceError(
                f"Plugin {name}@{manifest.version} imports restricted modules: "
                + "; ".join(violations)
            )

        logger.info("Installed plugin %s@%s to %s", name, manifest.version, dest)
        return dest

    def uninstall(self, name: str) -> None:
        """Remove an installed plugin.

        Args:
            name: Plugin name.

        Raises:
            MarketplaceError: If the plugin is not installed.
        """
        dest = self._plugins_dir / name
        if not dest.exists():
            raise MarketplaceError(f"Plugin not installed: {name}")
        shutil.rmtree(dest)
        logger.info("Uninstalled plugin %s", name)

    def list_installed(self, *, verify: bool = True) -> list[PluginManifest]:
        """Return manifests for all installed plugins.

        On-disk manifests are re-verified against ``self._trusted_keys`` so a
        tampered or unsigned file written after the original install is not
        silently surfaced as an installed plugin.

        Args:
            verify: When ``True`` (default), each manifest must carry a valid
                Ed25519 signature from a trusted author; otherwise it is
                skipped with a warning. Pass ``False`` to mirror an
                ``install(verify=False)`` workflow.

        Returns:
            List of installed plugin manifests that passed verification.
        """
        results: list[PluginManifest] = []
        if not self._plugins_dir.exists():
            return results
        for child in sorted(self._plugins_dir.iterdir()):
            manifest_path = child / MANIFEST_FILENAME
            if not manifest_path.exists():
                continue
            try:
                manifest = load_manifest(manifest_path)
            except MarketplaceError:
                logger.warning("Skipping invalid plugin at %s", child)
                continue
            if verify and not self._verify_on_disk(manifest, child):
                continue
            results.append(manifest)
        return results

    def _fetch_artifact(
        self,
        manifest: PluginManifest,
        dest: Path,
        *,
        verify: bool = True,
    ) -> None:
        """Download, verify, and unpack the plugin artifact archive.

        The archive is saved as ``dest/.artifact.zip`` after a successful
        integrity check so that ``_verify_on_disk`` can re-verify the hash on
        subsequent ``list_installed()`` calls.

        Args:
            manifest: Plugin manifest carrying ``artifact_url`` and optionally
                ``artifact_sha256``.
            dest: Destination directory (``plugins_dir/<name>``).
            verify: When ``True``, ``artifact_sha256`` must be present and
                the download must match it exactly.

        Raises:
            MarketplaceError: If ``verify=True`` and no ``artifact_sha256`` is
                supplied, if the downloaded file fails the hash check, or if
                the archive cannot be unpacked.
        """
        artifact_url = manifest.artifact_url
        if not artifact_url:
            return

        # Restrict downloads to http/https to prevent file:// or other
        # local-path schemes from exposing files on the host system.
        try:
            from urllib.parse import urlparse
            scheme = urlparse(artifact_url).scheme.lower()
        except Exception as exc:
            raise MarketplaceError(
                f"Plugin {manifest.name}@{manifest.version}: invalid artifact_url: {exc}"
            ) from exc
        if scheme not in ("http", "https"):
            raise MarketplaceError(
                f"Plugin {manifest.name}@{manifest.version}: artifact_url must use "
                f"http or https (got {scheme!r})"
            )

        if verify and not manifest.artifact_sha256:
            raise MarketplaceError(
                f"Plugin {manifest.name}@{manifest.version} declares artifact_url "
                "but no artifact_sha256; cannot verify artifact integrity. "
                "Set artifact_sha256 in the manifest or install with verify=False."
            )

        # `dest` is always a directory here: install() calls dest.mkdir() before
        # invoking _fetch_artifact(), so mkstemp will not raise FileNotFoundError.
        artifact_path = dest / ARTIFACT_FILENAME
        fd, tmp_path = tempfile.mkstemp(
            prefix=".artifact.", suffix=".tmp", dir=str(dest)
        )
        try:
            with os.fdopen(fd, "wb") as f:
                # S310 suppressed: scheme is validated above (http/https only).
                with urllib.request.urlopen(artifact_url) as resp:  # noqa: S310
                    while True:
                        chunk = resp.read(65536)
                        if not chunk:
                            break
                        f.write(chunk)
                f.flush()
                os.fsync(f.fileno())

            if verify and manifest.artifact_sha256:
                _verify_file_sha256(tmp_path, manifest.artifact_sha256)
                logger.info(
                    "Artifact SHA-256 verified for %s@%s",
                    manifest.name,
                    manifest.version,
                )

            # Unpack the archive into the plugin directory.
            # Guard against zip-slip: reject any member whose resolved path
            # escapes the destination directory.
            try:
                with zipfile.ZipFile(tmp_path) as zf:
                    dest_resolved = dest.resolve()
                    for member in zf.infolist():
                        member_path = (dest / member.filename).resolve()
                        try:
                            member_path.relative_to(dest_resolved)
                        except ValueError:
                            raise MarketplaceError(
                                f"Artifact for {manifest.name}@{manifest.version} "
                                f"contains unsafe path: {member.filename!r}"
                            )
                        zf.extract(member, dest)
            except zipfile.BadZipFile as exc:
                raise MarketplaceError(
                    f"Artifact for {manifest.name}@{manifest.version} is not a valid "
                    f"zip archive: {exc}"
                ) from exc

            # Keep the zip for on-disk re-verification
            os.replace(tmp_path, artifact_path)
            logger.info(
                "Artifact for %s@%s downloaded and unpacked to %s",
                manifest.name,
                manifest.version,
                dest,
            )
        except Exception:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            raise

    def _verify_on_disk(self, manifest: PluginManifest, location: Path) -> bool:
        """Re-verify an on-disk manifest's signature and artifact hash."""
        if not manifest.signature:
            logger.warning(
                "Skipping plugin %s at %s: no signature on disk",
                manifest.name, location,
            )
            return False
        if manifest.author not in self._trusted_keys:
            logger.warning(
                "Skipping plugin %s at %s: untrusted author %r",
                manifest.name, location, manifest.author,
            )
            return False
        try:
            verify_signature(manifest, self._trusted_keys[manifest.author])
        except MarketplaceError as exc:
            logger.warning(
                "Skipping plugin %s at %s: signature verification failed (%s)",
                manifest.name, location, exc,
            )
            return False

        # Re-verify the artifact hash when the manifest declares one.
        # The manifest signature already covers artifact_sha256, so a valid
        # signature guarantees the hash itself has not been tampered with.
        if manifest.artifact_sha256:
            artifact_path = location / ARTIFACT_FILENAME
            if not artifact_path.exists():
                logger.warning(
                    "Skipping plugin %s at %s: .artifact.zip missing "
                    "(expected artifact_sha256 %s)",
                    manifest.name, location, manifest.artifact_sha256,
                )
                return False
            try:
                _verify_file_sha256(str(artifact_path), manifest.artifact_sha256)
            except MarketplaceError as exc:
                logger.warning(
                    "Skipping plugin %s at %s: artifact hash verification failed (%s)",
                    manifest.name, location, exc,
                )
                return False

        return True

    # ------------------------------------------------------------------
    # Dependency resolution
    # ------------------------------------------------------------------

    def _resolve_dependencies(
        self,
        manifest: PluginManifest,
        *,
        verify: bool = True,
        _seen: set[str],
    ) -> None:
        """Recursively resolve and install plugin dependencies.

        Args:
            manifest: The manifest whose dependencies should be resolved.
            verify: Whether to verify signatures on dependencies.
            _seen: Set of already-visited plugin names (cycle detection).

        Raises:
            MarketplaceError: On circular dependencies or missing plugins.
        """
        if manifest.name in _seen:
            raise MarketplaceError(f"Circular dependency detected: {manifest.name}")
        _seen.add(manifest.name)

        for dep_spec in manifest.dependencies:
            dep_name, dep_version = _parse_dependency(dep_spec)
            dest = self._plugins_dir / dep_name
            if dest.exists():
                continue  # already installed
            self.install(dep_name, dep_version, verify=verify, _seen=_seen)

    # ------------------------------------------------------------------
    # Sandboxing
    # ------------------------------------------------------------------

    @staticmethod
    def check_sandbox(module_name: str) -> bool:
        """Return whether *module_name* is permitted under the sandbox policy.

        This is a **policy predicate** — it answers "is this module on the
        restricted list?" but does *not* block any import by itself.
        Install-time enforcement is performed by :meth:`scan_source_files`,
        which :meth:`install` calls automatically.  Full runtime enforcement
        (including dynamic imports) requires
        ``agentmesh.marketplace.sandbox.PluginSandbox``.

        Args:
            module_name: Fully-qualified module name (e.g. ``"os.path"``).

        Returns:
            ``True`` if the module is **allowed**, ``False`` if it is
            **restricted**.
        """
        top_level = module_name.split(".")[0]
        return top_level not in RESTRICTED_MODULES

    @staticmethod
    def scan_source_files(plugin_dir: Path) -> list[str]:
        """Scan Python source files in *plugin_dir* for restricted imports.

        Parses every ``*.py`` file under *plugin_dir* with :mod:`ast` and
        reports any ``import X`` or ``from X import ...`` statements that
        reference a top-level module in :data:`RESTRICTED_MODULES`.

        .. note::

            Dynamic import calls such as ``__import__("subprocess")`` or
            ``importlib.import_module("os")`` are **not** detected by this
            scan.  For full runtime enforcement use
            ``agentmesh.marketplace.sandbox.PluginSandbox``.

        Args:
            plugin_dir: Directory containing the installed plugin files.

        Returns:
            List of human-readable violation strings (one per offending
            import statement).  An empty list means no restricted imports
            were found.
        """
        violations: list[str] = []
        for py_file in sorted(plugin_dir.rglob("*.py")):
            try:
                source = py_file.read_text(encoding="utf-8")
            except OSError as exc:
                logger.warning("Could not read %s for sandbox scan: %s", py_file, exc)
                continue
            try:
                tree = ast.parse(source, filename=str(py_file))
            except SyntaxError as exc:
                logger.warning("Could not parse %s for sandbox scan: %s", py_file, exc)
                continue
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        top = alias.name.split(".")[0]
                        if top in RESTRICTED_MODULES:
                            violations.append(
                                f"{py_file}: imports '{alias.name}'"
                            )
                elif isinstance(node, ast.ImportFrom):
                    if node.module:
                        top = node.module.split(".")[0]
                        if top in RESTRICTED_MODULES:
                            violations.append(
                                f"{py_file}: imports from '{node.module}'"
                            )
        return violations


def _verify_file_sha256(path: str, expected_hex: str) -> None:
    """Verify the SHA-256 digest of a file against an expected hex string.

    Uses ``hmac.compare_digest`` for a timing-safe comparison to avoid
    leaking information about a partial match.

    Args:
        path: Path to the file to hash.
        expected_hex: Expected lowercase hex SHA-256 digest.

    Raises:
        MarketplaceError: If the computed digest does not match.
    """
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(65536)
            if not chunk:
                break
            h.update(chunk)
    actual = h.hexdigest()
    if not hmac.compare_digest(actual.lower(), expected_hex.lower()):
        raise MarketplaceError(
            f"Artifact SHA-256 mismatch: expected {expected_hex!r}, got {actual!r}"
        )


def _atomic_write_yaml(path: Path, data: Any) -> None:
    """Write YAML to ``path`` atomically via tempfile + ``os.replace``.

    A torn write or crash leaves either the previous file intact or no file,
    never a half-written manifest visible to readers.
    """
    parent = path.parent
    fd, tmp_path = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=str(parent)
    )
    try:
        with os.fdopen(fd, "w") as f:
            yaml.dump(data, f, default_flow_style=False, sort_keys=True)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_path, path)
    except Exception:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise


def _parse_dependency(dep_spec: str) -> tuple[str, Optional[str]]:
    """Parse a PEP 508 dependency specifier like ``plugin-name>=1.0.0``.

    Returns a ``(name, version_or_none)`` tuple. ``version`` is the pinned
    string from an ``==X`` specifier when one is present; otherwise ``None``
    so the registry resolves the latest matching version. Compound
    specifiers (``>=1.0,<2.0``), inequality (``!=``), and compatible-release
    (``~=``) all return ``None`` instead of being mis-parsed as a literal
    version string.

    Raises:
        MarketplaceError: If ``dep_spec`` is not a valid PEP 508 requirement.
    """
    try:
        req = Requirement(dep_spec)
    except InvalidRequirement as exc:
        raise MarketplaceError(f"Invalid dependency specifier {dep_spec!r}: {exc}") from exc
    for spec in req.specifier:
        if spec.operator == "==":
            return req.name, spec.version
    return req.name, None

