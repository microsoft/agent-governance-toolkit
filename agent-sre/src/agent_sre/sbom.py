# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Software Bill of Materials (SBOM) generation for agent artifacts.

Supports SPDX 2.3 and CycloneDX 1.5 output formats.
"""

from __future__ import annotations

import hashlib
import json
import re
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


@dataclass
class SBOMPackage:
    """A single package entry in the SBOM."""

    name: str
    version: str
    supplier: str = ""
    license_id: str = "MIT"
    spdx_id: str = ""

    def __post_init__(self) -> None:
        if not self.spdx_id:
            safe = re.sub(r"[^a-zA-Z0-9._-]", "-", self.name)
            self.spdx_id = f"SPDXRef-Package-{safe}-{self.version}"


@dataclass
class SBOMRelationship:
    """A dependency relationship between two SBOM packages."""

    parent_spdx_id: str
    child_spdx_id: str
    relationship_type: str = "DEPENDS_ON"


class AgentSBOM:
    """Generate Software Bill of Materials for agent artifacts in SPDX format."""

    def __init__(self, agent_id: str, version: str) -> None:
        self.agent_id = agent_id
        self.version = version
        self.packages: list[SBOMPackage] = []
        self.relationships: list[SBOMRelationship] = []
        self._document_spdx_id = "SPDXRef-DOCUMENT"
        self._root_spdx_id = f"SPDXRef-RootPackage-{agent_id}"
        self._created = datetime.now(timezone.utc).isoformat()

    def add_package(
        self,
        name: str,
        version: str,
        supplier: str = "",
        license_id: str = "MIT",
    ) -> SBOMPackage:
        """Add a package to the SBOM and return it."""
        pkg = SBOMPackage(
            name=name, version=version, supplier=supplier, license_id=license_id
        )
        self.packages.append(pkg)
        return pkg

    def add_dependency(self, parent: str, child: str) -> None:
        """Record a dependency relationship between two SPDX IDs."""
        self.relationships.append(
            SBOMRelationship(parent_spdx_id=parent, child_spdx_id=child)
        )

    # ------------------------------------------------------------------
    # Factory helpers
    # ------------------------------------------------------------------

    @classmethod
    def from_requirements(
        cls, agent_id: str, version: str, requirements_path: str
    ) -> AgentSBOM:
        """Parse requirements.txt and generate SBOM."""
        sbom = cls(agent_id, version)
        path = Path(requirements_path)
        if not path.exists():
            raise FileNotFoundError(f"Requirements file not found: {requirements_path}")

        for raw_line in path.read_text(encoding="utf-8").splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#") or line.startswith("-"):
                continue

            # Handle version specifiers: name==1.0, name>=1.0, name~=1.0, etc.
            match = re.match(r"^([A-Za-z0-9_][A-Za-z0-9._-]*)\s*([><=!~]+.+)?", line)
            if not match:
                continue

            pkg_name = match.group(1)
            version_spec = (match.group(2) or "").strip()
            # Extract bare version from ==X.Y.Z, otherwise keep the spec string
            ver_match = re.match(r"==\s*(.+)", version_spec)
            pkg_version = ver_match.group(1) if ver_match else version_spec or "0.0.0"

            pkg = sbom.add_package(pkg_name, pkg_version)
            sbom.add_dependency(sbom._root_spdx_id, pkg.spdx_id)

        return sbom

    @classmethod
    def from_pyproject(cls, agent_id: str, pyproject_path: str) -> AgentSBOM:
        """Parse pyproject.toml and generate SBOM.

        Reads the ``[project]`` table for *version* and *dependencies*.
        Only the stdlib ``tomllib`` / ``tomli`` parser is used — no heavy
        third-party dependency is required.
        """
        path = Path(pyproject_path)
        if not path.exists():
            raise FileNotFoundError(f"pyproject.toml not found: {pyproject_path}")

        try:
            import tomllib  # Python 3.11+
        except ModuleNotFoundError:
            import tomli as tomllib  # type: ignore[no-redef]

        data = tomllib.loads(path.read_text(encoding="utf-8"))
        project = data.get("project", {})
        version = project.get("version", "0.0.0")

        sbom = cls(agent_id, version)

        for dep in project.get("dependencies", []):
            match = re.match(r"^([A-Za-z0-9_][A-Za-z0-9._-]*)\s*([><=!~]+.+)?", dep)
            if not match:
                continue
            pkg_name = match.group(1)
            version_spec = (match.group(2) or "").strip()
            ver_match = re.match(r"==\s*(.+)", version_spec)
            pkg_version = ver_match.group(1) if ver_match else version_spec or "0.0.0"

            pkg = sbom.add_package(pkg_name, pkg_version)
            sbom.add_dependency(sbom._root_spdx_id, pkg.spdx_id)

        return sbom

    # ------------------------------------------------------------------
    # Export formats
    # ------------------------------------------------------------------

    def to_spdx(self) -> dict[str, Any]:
        """Export as SPDX 2.3 JSON."""
        doc_namespace = (
            f"https://spdx.org/spdxdocs/{self.agent_id}-{self.version}-"
            f"{uuid.uuid4()}"
        )

        spdx_packages: list[dict[str, Any]] = [
            {
                "SPDXID": self._root_spdx_id,
                "name": self.agent_id,
                "versionInfo": self.version,
                "downloadLocation": "NOASSERTION",
                "supplier": "Organization: Microsoft",
                "licenseConcluded": "MIT",
                "licenseDeclared": "MIT",
                "copyrightText": "Copyright (c) Microsoft Corporation.",
            }
        ]

        for pkg in self.packages:
            spdx_packages.append(
                {
                    "SPDXID": pkg.spdx_id,
                    "name": pkg.name,
                    "versionInfo": pkg.version,
                    "downloadLocation": "NOASSERTION",
                    "supplier": f"Organization: {pkg.supplier}" if pkg.supplier else "NOASSERTION",
                    "licenseConcluded": pkg.license_id,
                    "licenseDeclared": pkg.license_id,
                    "copyrightText": "NOASSERTION",
                }
            )

        spdx_relationships: list[dict[str, str]] = [
            {
                "spdxElementId": self._document_spdx_id,
                "relationshipType": "DESCRIBES",
                "relatedSpdxElement": self._root_spdx_id,
            }
        ]
        for rel in self.relationships:
            spdx_relationships.append(
                {
                    "spdxElementId": rel.parent_spdx_id,
                    "relationshipType": rel.relationship_type,
                    "relatedSpdxElement": rel.child_spdx_id,
                }
            )

        return {
            "spdxVersion": "SPDX-2.3",
            "dataLicense": "CC0-1.0",
            "SPDXID": self._document_spdx_id,
            "name": f"{self.agent_id}-sbom",
            "documentNamespace": doc_namespace,
            "creationInfo": {
                "created": self._created,
                "creators": ["Tool: agent-sre"],
            },
            "packages": spdx_packages,
            "relationships": spdx_relationships,
        }

    def to_cyclonedx(self) -> dict[str, Any]:
        """Export as CycloneDX 1.5 JSON."""
        components: list[dict[str, Any]] = []
        dep_map: dict[str, list[str]] = {}

        for pkg in self.packages:
            bom_ref = f"{pkg.name}@{pkg.version}"
            components.append(
                {
                    "type": "library",
                    "bom-ref": bom_ref,
                    "name": pkg.name,
                    "version": pkg.version,
                    "supplier": {"name": pkg.supplier} if pkg.supplier else {},
                    "licenses": [{"license": {"id": pkg.license_id}}],
                }
            )

        for rel in self.relationships:
            dep_map.setdefault(rel.parent_spdx_id, []).append(rel.child_spdx_id)

        dependencies: list[dict[str, Any]] = []
        for parent, children in dep_map.items():
            dependencies.append({"ref": parent, "dependsOn": children})

        return {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "version": 1,
            "metadata": {
                "timestamp": self._created,
                "component": {
                    "type": "application",
                    "bom-ref": self.agent_id,
                    "name": self.agent_id,
                    "version": self.version,
                },
                "tools": [{"name": "agent-sre", "vendor": "Microsoft"}],
            },
            "components": components,
            "dependencies": dependencies,
        }

    def save(self, path: str, format: str = "spdx") -> None:
        """Persist the SBOM to disk as JSON.

        Args:
            path: Destination file path.
            format: ``"spdx"`` (default) or ``"cyclonedx"``.
        """
        doc = self.to_cyclonedx() if format == "cyclonedx" else self.to_spdx()

        dest = Path(path)
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")

    # ------------------------------------------------------------------
    # Utility
    # ------------------------------------------------------------------

    @staticmethod
    def hash_file(file_path: str) -> str:
        """Return the SHA-256 hex digest of a file."""
        sha = hashlib.sha256()
        with open(file_path, "rb") as fh:
            for chunk in iter(lambda: fh.read(8192), b""):
                sha.update(chunk)
        return sha.hexdigest()
