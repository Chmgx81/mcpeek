"""
SBOM (Software Bill of Materials) Generator — produces CycloneDX and SPDX format SBOMs
from scanned packages and dependencies.
"""

from __future__ import annotations

import json
import hashlib
from datetime import datetime
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Optional


class SBOMFormat(str, Enum):
    CYCLONEDX = "cyclonedx"
    SPDX = "spdx"


class LicenseCategory(str, Enum):
    PERMISSIVE = "permissive"      # MIT, Apache-2.0, BSD, ISC
    WEAK_COPYLEFT = "weak_copyleft"  # LGPL, MPL, EPL
    STRONG_COPYLEFT = "strong_copyleft"  # GPL, AGPL
    PROPRIETARY = "proprietary"
    UNKNOWN = "unknown"


# License classification mapping
LICENSE_CATEGORIES: dict[str, LicenseCategory] = {
    # Permissive
    "MIT": LicenseCategory.PERMISSIVE,
    "Apache-2.0": LicenseCategory.PERMISSIVE,
    "Apache 2.0": LicenseCategory.PERMISSIVE,
    "BSD-2-Clause": LicenseCategory.PERMISSIVE,
    "BSD-3-Clause": LicenseCategory.PERMISSIVE,
    "ISC": LicenseCategory.PERMISSIVE,
    "0BSD": LicenseCategory.PERMISSIVE,
    "CC0-1.0": LicenseCategory.PERMISSIVE,
    "Unlicense": LicenseCategory.PERMISSIVE,
    "WTFPL": LicenseCategory.PERMISSIVE,
    # Weak Copyleft
    "LGPL-2.1": LicenseCategory.WEAK_COPYLEFT,
    "LGPL-3.0": LicenseCategory.WEAK_COPYLEFT,
    "MPL-2.0": LicenseCategory.WEAK_COPYLEFT,
    "EPL-1.0": LicenseCategory.WEAK_COPYLEFT,
    "EPL-2.0": LicenseCategory.WEAK_COPYLEFT,
    "CDDL-1.0": LicenseCategory.WEAK_COPYLEFT,
    # Strong Copyleft
    "GPL-2.0": LicenseCategory.STRONG_COPYLEFT,
    "GPL-3.0": LicenseCategory.STRONG_COPYLEFT,
    "AGPL-3.0": LicenseCategory.STRONG_COPYLEFT,
    "GPL-2.0-only": LicenseCategory.STRONG_COPYLEFT,
    "GPL-3.0-only": LicenseCategory.STRONG_COPYLEFT,
    "AGPL-3.0-only": LicenseCategory.STRONG_COPYLEFT,
}


@dataclass
class SBOMComponent:
    """Single component in SBOM."""
    name: str
    version: str
    purl: str  # Package URL
    license: str = ""
    license_category: LicenseCategory = LicenseCategory.UNKNOWN
    author: str = ""
    description: str = ""
    hashes: dict[str, str] = field(default_factory=dict)
    external_references: list[str] = field(default_factory=list)
    properties: dict[str, str] = field(default_factory=dict)


@dataclass
class SBOM:
    """Software Bill of Materials."""
    format: SBOMFormat
    name: str
    version: str = "1.0.0"
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")
    components: list[SBOMComponent] = field(default_factory=list)
    dependencies: dict[str, list[str]] = field(default_factory=dict)
    metadata: dict = field(default_factory=dict)

    @property
    def total_components(self) -> int:
        return len(self.components)

    @property
    def license_summary(self) -> dict[LicenseCategory, int]:
        summary: dict[LicenseCategory, int] = {}
        for comp in self.components:
            cat = comp.license_category
            summary[cat] = summary.get(cat, 0) + 1
        return summary

    @property
    def has_copyleft(self) -> bool:
        """Check if any component has strong copyleft license."""
        return any(
            comp.license_category == LicenseCategory.STRONG_COPYLEFT
            for comp in self.components
        )

    @property
    def has_weak_copyleft(self) -> bool:
        """Check if any component has weak copyleft license."""
        return any(
            comp.license_category == LicenseCategory.WEAK_COPYLEFT
            for comp in self.components
        )

    def to_cyclonedx(self) -> dict:
        """Export as CycloneDX 1.5 JSON format."""
        bom = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "version": 1,
            "serialNumber": f"urn:uuid:{hashlib.md5(f'{self.name}{self.created_at}'.encode()).hexdigest()}",
            "metadata": {
                "timestamp": self.created_at,
                "tools": [{"vendor": "MCPeek", "name": "mcpeek", "version": "0.1.0"}],
                "component": {
                    "type": "application",
                    "name": self.name,
                    "version": self.version,
                },
            },
            "components": [],
            "dependencies": [],
        }

        for comp in self.components:
            component = {
                "type": "library",
                "name": comp.name,
                "version": comp.version,
                "purl": comp.purl,
            }
            if comp.license:
                component["licenses"] = [{"license": {"id": comp.license}}]
            if comp.author:
                component["author"] = comp.author
            if comp.description:
                component["description"] = comp.description
            if comp.hashes:
                component["hashes"] = [
                    {"alg": alg.upper(), "content": h}
                    for alg, h in comp.hashes.items()
                ]
            bom["components"].append(component)

        for pkg, deps in self.dependencies.items():
            bom["dependencies"].append({
                "ref": f"pkg:npm/{pkg}" if "/" not in pkg else f"pkg:pypi/{pkg}",
                "dependsOn": deps,
            })

        return bom

    def to_spdx(self) -> dict:
        """Export as SPDX 2.3 JSON format."""
        spdx_id = hashlib.md5(f"{self.name}{self.created_at}".encode()).hexdigest()

        document = {
            "spdxVersion": "SPDX-2.3",
            "dataLicense": "CC0-1.0",
            "SPDXID": f"SPDXRef-DOCUMENT",
            "name": self.name,
            "documentNamespace": f"https://mcpeek.dev/sbom/{spdx_id}",
            "creationInfo": {
                "created": self.created_at,
                "creators": ["Tool: MCPeek-0.1.0"],
                "licenseListVersion": "3.21",
            },
            "documentDescribes": [f"SPDXRef-Package-{self.name}"],
            "packages": [],
            "relationships": [],
        }

        # Root package
        document["packages"].append({
            "SPDXID": f"SPDXRef-Package-{self.name}",
            "name": self.name,
            "versionInfo": self.version,
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": False,
        })

        for comp in self.components:
            pkg = {
                "SPDXID": f"SPDXRef-Package-{comp.name}",
                "name": comp.name,
                "versionInfo": comp.version,
                "downloadLocation": comp.external_references[0] if comp.external_references else "NOASSERTION",
                "filesAnalyzed": False,
            }
            if comp.license:
                pkg["licenseConcluded"] = comp.license
                pkg["licenseDeclared"] = comp.license
            else:
                pkg["licenseConcluded"] = "NOASSERTION"
                pkg["licenseDeclared"] = "NOASSERTION"
            if comp.author:
                pkg["originator"] = f"Person: {comp.author}"
            document["packages"].append(pkg)

            # Add dependency relationship
            document["relationships"].append({
                "spdxElementId": f"SPDXRef-Package-{self.name}",
                "relationshipType": "DEPENDS_ON",
                "relatedSpdxElement": f"SPDXRef-Package-{comp.name}",
            })

        return document


def classify_license(license_id: str) -> LicenseCategory:
    """Classify a license ID into a category."""
    if not license_id:
        return LicenseCategory.UNKNOWN

    # Try exact match
    if license_id in LICENSE_CATEGORIES:
        return LICENSE_CATEGORIES[license_id]

    # Try partial match
    license_upper = license_id.upper()
    for key, category in LICENSE_CATEGORIES.items():
        if key.upper() in license_upper:
            return category

    return LicenseCategory.UNKNOWN


def generate_sbom(
    name: str,
    dependencies: dict[str, str],
    format: SBOMFormat = SBOMFormat.CYCLONEDX,
    version: str = "1.0.0",
) -> SBOM:
    """
    Generate SBOM from dependency list.

    Args:
        name: Package/project name
        dependencies: Dict of {package_name: version}
        format: Output format (CycloneDX or SPDX)
        version: Package version

    Returns:
        SBOM object ready for export
    """
    sbom = SBOM(format=format, name=name, version=version)

    for pkg_name, pkg_version in dependencies.items():
        # Generate PURL
        if "/" in pkg_name or "@" in pkg_name:
            # npm scoped package
            purl = f"pkg:npm/{pkg_name}@{pkg_version}"
        elif pkg_name.replace("-", "").replace("_", "").isalnum():
            # PyPI package
            purl = f"pkg:pypi/{pkg_name}@{pkg_version}"
        else:
            purl = f"pkg:generic/{pkg_name}@{pkg_version}"

        comp = SBOMComponent(
            name=pkg_name,
            version=pkg_version,
            purl=purl,
            properties={"ecosystem": "npm" if "npm" in purl else "pypi"},
        )
        sbom.components.append(comp)

    return sbom


def check_license_compatibility(
    sbom: SBOM,
    allowed_categories: Optional[list[LicenseCategory]] = None,
) -> list[dict]:
    """
    Check license compatibility across SBOM components.

    Args:
        sbom: SBOM to check
        allowed_categories: List of allowed license categories (default: permissive only)

    Returns:
        List of license issues found
    """
    if allowed_categories is None:
        allowed_categories = [LicenseCategory.PERMISSIVE]

    issues = []
    for comp in sbom.components:
        cat = classify_license(comp.license)
        comp.license_category = cat

        if cat == LicenseCategory.STRONG_COPYLEFT:
            issues.append({
                "severity": "high",
                "package": comp.name,
                "license": comp.license,
                "category": cat.value,
                "message": f"Strong copyleft license '{comp.license}' may require source code disclosure",
            })
        elif cat == LicenseCategory.WEAK_COPYLEFT:
            issues.append({
                "severity": "medium",
                "package": comp.name,
                "license": comp.license,
                "category": cat.value,
                "message": f"Weak copyleft license '{comp.license}' has modification disclosure requirements",
            })
        elif cat == LicenseCategory.UNKNOWN and comp.license:
            issues.append({
                "severity": "low",
                "package": comp.name,
                "license": comp.license,
                "category": cat.value,
                "message": f"Unknown license '{comp.license}' — manual review recommended",
            })

    return issues
