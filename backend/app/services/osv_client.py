"""OSV (Open Source Vulnerabilities) API client.

Queries the free OSV API for known vulnerabilities in dependencies.
Supports npm, PyPI, Go, Maven, crates.io, and more.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import Optional

import httpx

from ..schemas import FindingCreate

logger = logging.getLogger(__name__)

OSV_API_BASE = "https://api.osv.dev/v1"


@dataclass
class OSVVulnerability:
    vuln_id: str
    summary: str
    severity: str
    aliases: list[str]
    affected_package: str
    affected_versions: str
    fixed_version: Optional[str]
    reference_url: Optional[str]


def _classify_severity(severity_data: dict | list | None) -> str:
    """Convert OSV severity to our severity scale."""
    if not severity_data:
        return "medium"

    if isinstance(severity_data, list):
        for s in severity_data:
            score_str = s.get("score", "")
            s_type = s.get("type", "")
            if s_type == "CVSS_V3" and score_str:
                try:
                    # Try to parse as float directly
                    score = float(score_str)
                    if score >= 9.0:
                        return "critical"
                    elif score >= 7.0:
                        return "high"
                    elif score >= 4.0:
                        return "medium"
                    else:
                        return "low"
                except ValueError:
                    # Parse CVSS vector string
                    # Check for high-impact indicators in the vector
                    if "C:H" in score_str and "I:H" in score_str:
                        return "critical"
                    elif "C:H" in score_str or "I:H" in score_str or "A:H" in score_str:
                        return "high"
                    # Try to extract numeric parts
                    for part in score_str.split("/"):
                        if "/" not in part and part.replace(".", "").isdigit():
                            try:
                                score = float(part)
                                if score >= 9.0:
                                    return "critical"
                                elif score >= 7.0:
                                    return "high"
                                elif score >= 4.0:
                                    return "medium"
                                else:
                                    return "low"
                            except ValueError:
                                continue

    if isinstance(severity_data, dict):
        score = severity_data.get("score")
        if score is not None:
            try:
                score_val = float(score)
                if score_val >= 9.0:
                    return "critical"
                elif score_val >= 7.0:
                    return "high"
                elif score_val >= 4.0:
                    return "medium"
                else:
                    return "low"
            except (ValueError, TypeError):
                pass

    return "medium"


def _extract_fixed_version(affected_ranges: list[dict]) -> str | None:
    """Extract the fixed version from OSV affected ranges."""
    for affected in affected_ranges:
        events = affected.get("events", [])
        for event in events:
            if "fixed" in event:
                return event["fixed"]
    return None


def _extract_affected_versions(affected_ranges: list[dict]) -> str:
    """Extract affected version ranges."""
    ranges = []
    for affected in affected_ranges:
        events = affected.get("events", [])
        introduced = None
        fixed = None
        for event in events:
            if "introduced" in event:
                introduced = event["introduced"]
            if "fixed" in event:
                fixed = event["fixed"]
        if introduced and fixed:
            ranges.append(f">={introduced}, <{fixed}")
        elif introduced:
            ranges.append(f">={introduced}")
        elif fixed:
            ranges.append(f"<{fixed}")
    return ", ".join(ranges) if ranges else "unknown"


async def query_osv(package_name: str, version: str, ecosystem: str = "npm") -> list[OSVVulnerability]:
    """Query OSV API for vulnerabilities affecting a specific package version.

    Args:
        package_name: Name of the package
        version: Version to check
        ecosystem: Package ecosystem (npm, PyPI, Go, Maven, crates.io, etc.)

    Returns:
        List of OSVVulnerability objects
    """
    vulnerabilities = []

    try:
        async with httpx.AsyncClient(timeout=10) as client:
            # Use the batch endpoint for efficiency
            payload = {
                "version": version,
                "package": {
                    "name": package_name,
                    "ecosystem": ecosystem,
                }
            }

            resp = await client.post(f"{OSV_API_BASE}/query", json=payload)

            if resp.status_code == 200:
                data = resp.json()
                vulns = data.get("vulns", [])

                for vuln in vulns:
                    vuln_id = vuln.get("id", "unknown")
                    summary = vuln.get("summary", "No summary")
                    severity = _classify_severity(vuln.get("severity"))
                    aliases = vuln.get("aliases", [])

                    # Get affected versions
                    affected = vuln.get("affected", [])
                    affected_versions = "unknown"
                    fixed_version = None

                    for aff in affected:
                        pkg = aff.get("package", {})
                        if pkg.get("name", "").lower() == package_name.lower():
                            ranges = aff.get("ranges", [])
                            affected_versions = _extract_affected_versions(ranges)
                            fixed_version = _extract_fixed_version(ranges)
                            break

                    # Get reference URL
                    ref_url = None
                    references = vuln.get("references", [])
                    for ref in references:
                        if ref.get("type") == "WEB":
                            ref_url = ref.get("url")
                            break
                    if not ref_url and references:
                        ref_url = references[0].get("url")

                    vuln_obj = OSVVulnerability(
                        vuln_id=vuln_id,
                        summary=summary,
                        severity=severity,
                        aliases=aliases,
                        affected_package=package_name,
                        affected_versions=affected_versions,
                        fixed_version=fixed_version,
                        reference_url=ref_url,
                    )
                    vulnerabilities.append(vuln_obj)

            elif resp.status_code == 400:
                logger.warning("OSV API returned 400 for %s@%s", package_name, version)
            else:
                logger.warning("OSV API returned %d for %s@%s", resp.status_code, package_name, version)

    except httpx.TimeoutException:
        logger.warning("OSV API timeout for %s@%s", package_name, version)
    except Exception as e:
        logger.warning("OSV API error for %s@%s: %s", package_name, version, e)

    return vulnerabilities


def osv_to_finding(vuln: OSVVulnerability) -> FindingCreate:
    """Convert an OSVVulnerability to a FindingCreate."""
    cwe_ids = []
    # Try to extract CWE from summary
    cwe_match = re.findall(r"CWE-\d+", vuln.summary)
    if cwe_match:
        cwe_ids = cwe_match

    description = f"{vuln.summary}"
    if vuln.affected_versions and vuln.affected_versions != "unknown":
        description += f"\n\nAffected versions: {vuln.affected_versions}"
    if vuln.fixed_version:
        description += f"\nFixed in: {vuln.fixed_version}"

    references = []
    if vuln.reference_url:
        references.append(vuln.reference_url)
    for alias in vuln.aliases:
        if alias.startswith("CVE-"):
            references.append(f"https://nvd.nist.gov/vuln/detail/{alias}")

    return FindingCreate(
        category="dependency",
        severity=vuln.severity,
        title=f"{vuln.affected_package}: {vuln.vuln_id} — {vuln.summary[:80]}",
        description=description,
        evidence=f"Package: {vuln.affected_package}\nVulnerability: {vuln.vuln_id}\nAliases: {', '.join(vuln.aliases)}",
        remediation=f"Update {vuln.affected_package} to version {vuln.fixed_version} or later."
                   if vuln.fixed_version
                   else f"Check {vuln.affected_package} for patches or mitigations.",
        cwe=", ".join(cwe_ids) if cwe_ids else None,
        references=references,
        source="osv",
    )


async def scan_dependencies_with_osv(
    dependencies: dict[str, str],
    ecosystem: str = "npm",
) -> list[FindingCreate]:
    """Scan a list of dependencies against the OSV database.

    Args:
        dependencies: Dict of {package_name: version}
        ecosystem: Package ecosystem

    Returns:
        List of findings for vulnerable dependencies
    """
    findings = []

    for pkg_name, pkg_version in dependencies.items():
        # Clean version string (remove ^, ~, >=, etc.)
        clean_version = re.sub(r"[^0-9a-zA-Z.\-]", "", pkg_version.split(",")[0].split(" ")[0])

        if not clean_version or not re.match(r"^\d+\.", clean_version):
            # Skip if version can't be parsed (e.g., "latest", "workspace:*")
            continue

        vulns = await query_osv(pkg_name, clean_version, ecosystem)

        for vuln in vulns:
            findings.append(osv_to_finding(vuln))

    return findings
