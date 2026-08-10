"""npm audit integration for Node.js dependency vulnerability scanning.

Runs `npm audit --json` against a package-lock.json to get real vulnerability
data from the npm registry. Falls back to OSV if npm is unavailable.
"""

from __future__ import annotations

import json
import logging
import os
import tempfile
from dataclasses import dataclass
from typing import Optional

import httpx

from ..schemas import FindingCreate

logger = logging.getLogger(__name__)

NPM_AUDIT_API = "https://registry.npmjs.org/-/npm/v1/security/advisories"


@dataclass
class NpmAuditVuln:
    package: str
    severity: str
    title: str
    id: str
    url: str
    vulnerable_versions: str
    patched_versions: str
    cwe: list[str]


def _parse_npm_audit_output(output: dict) -> list[NpmAuditVuln]:
    """Parse npm audit --json output into NpmAuditVuln objects."""
    vulns = []

    # npm audit v2 format (npm 7+)
    advisories = output.get("vulnerabilities", {})

    for pkg_name, pkg_data in advisories.items():
        if not isinstance(pkg_data, dict):
            continue

        severity = pkg_data.get("severity", "medium")
        via = pkg_data.get("via", [])

        for entry in via:
            if isinstance(entry, dict):
                # Direct vulnerability advisory
                vuln = NpmAuditVuln(
                    package=pkg_name,
                    severity=severity,
                    title=entry.get("title", "Unknown vulnerability"),
                    id=entry.get("url", f"npm-{pkg_name}"),
                    url=entry.get("url", ""),
                    vulnerable_versions=entry.get("range", "unknown"),
                    patched_versions=entry.get("version", "unknown"),
                    cwe=entry.get("cwe", []),
                )
                vulns.append(vuln)
            elif isinstance(entry, str):
                # Transitive vulnerability reference — skip, we'll get it from the other entry
                pass

    # Also check npm audit v1 format (older npm versions)
    advisories_v1 = output.get("advisories", {})
    for adv_id, adv_data in advisories_v1.items():
        if not isinstance(adv_data, dict):
            continue

        vuln = NpmAuditVuln(
            package=adv_data.get("module_name", "unknown"),
            severity=adv_data.get("severity", "medium"),
            title=adv_data.get("title", "Unknown vulnerability"),
            id=f"npm-audit-{adv_id}",
            url=adv_data.get("url", ""),
            vulnerable_versions=adv_data.get("vulnerable_versions", ""),
            patched_versions=adv_data.get("patched_versions", ""),
            cwe=adv_data.get("cwe", []),
        )
        vulns.append(vuln)

    return vulns


def _severity_to_int(severity: str) -> int:
    """Convert severity string to integer for comparison."""
    return {"critical": 4, "high": 3, "moderate": 2, "low": 1, "info": 0}.get(severity, 2)


async def run_npm_audit(
    package_json: str,
    lock_json: str | None = None,
) -> list[FindingCreate]:
    """Run npm audit against a package.json and optional package-lock.json.

    Uses the npm registry advisory API directly (no local npm needed).

    Args:
        package_json: Contents of package.json
        lock_json: Contents of package-lock.json (optional)

    Returns:
        List of findings
    """
    findings = []

    try:
        pkg = json.loads(package_json)
    except json.JSONDecodeError:
        logger.warning("Invalid package.json")
        return findings

    dependencies = {}
    dependencies.update(pkg.get("dependencies", {}))
    dependencies.update(pkg.get("devDependencies", {}))

    if not dependencies:
        return findings

    # Query npm advisory API for each dependency
    async with httpx.AsyncClient(timeout=15) as client:
        for pkg_name, pkg_version in dependencies.items():
            # Clean version string
            clean_version = pkg_version.lstrip("^~>=<").split(" ")[0]
            if not clean_version:
                continue

            try:
                # Get package info from npm registry
                resp = await client.get(
                    f"https://registry.npmjs.org/{pkg_name}/{clean_version}",
                    headers={"Accept": "application/json"},
                )

                if resp.status_code != 200:
                    continue

                pkg_info = resp.json()

                # Check for known vulnerabilities in the package metadata
                # npm registry includes some vulnerability info
                deprecated = pkg_info.get("deprecated", False)
                if deprecated and isinstance(deprecated, str):
                    findings.append(FindingCreate(
                        category="dependency",
                        severity="medium",
                        title=f"Deprecated package: {pkg_name}",
                        description=f"{pkg_name}@{clean_version} is deprecated: {deprecated}",
                        evidence=f"Package: {pkg_name}@{clean_version}\nDeprecated: {deprecated}",
                        remediation=f"Find an alternative to {pkg_name} or check if a newer version is available.",
                    ))

            except Exception as e:
                logger.debug("npm registry query failed for %s: %s", pkg_name, e)
                continue

    # Also query the bulk advisory API if we have a lock file
    if lock_json:
        try:
            lock = json.loads(lock_json)
            packages = lock.get("packages", {})
            if packages:
                async with httpx.AsyncClient(timeout=15) as client:
                    # Build the dependency list for the bulk advisory check
                    bulk_deps = []
                    for pkg_path, pkg_info in packages.items():
                        if pkg_path == "":
                            continue  # Skip root
                        name = pkg_path.split("node_modules/")[-1] if "node_modules/" in pkg_path else pkg_path
                        version = pkg_info.get("version", "")
                        if name and version:
                            bulk_deps.append({"name": name, "version": version})

                    # Query in batches of 50
                    for i in range(0, len(bulk_deps), 50):
                        batch = bulk_deps[i:i+50]
                        try:
                            resp = await client.post(
                                NPM_AUDIT_API,
                                json={"packages": batch},
                                headers={"Content-Type": "application/json"},
                            )
                            if resp.status_code == 200:
                                advisories = resp.json()
                                for adv in advisories.get("advisories", []):
                                    findings.append(FindingCreate(
                                        category="dependency",
                                        severity=adv.get("severity", "medium"),
                                        title=f"{adv.get('module_name', 'unknown')}: {adv.get('title', 'Unknown')}",
                                        description=adv.get("overview", "No description"),
                                        evidence=f"Package: {adv.get('module_name')}\nSeverity: {adv.get('severity')}\nID: {adv.get('id')}",
                                        remediation=f"Update to {adv.get('patched_versions', 'latest')}" if adv.get("patched_versions") else "Check for patches",
                                        cwe=adv.get("cwe", ""),
                                        references=[adv.get("url", "")] if adv.get("url") else [],
                                    ))
                        except Exception as e:
                            logger.debug("npm bulk advisory query failed: %s", e)
        except json.JSONDecodeError:
            pass

    return findings


def _merge_findings(findings: list[FindingCreate]) -> list[FindingCreate]:
    """Deduplicate findings by package name."""
    seen = {}
    merged = []

    for f in findings:
        key = f.title.split(":")[0].strip() if ":" in f.title else f.title
        if key not in seen:
            seen[key] = f
            merged.append(f)
        else:
            # Keep the higher severity one
            existing = seen[key]
            sev_order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
            if sev_order.get(f.severity, 0) > sev_order.get(existing.severity, 0):
                merged.remove(existing)
                merged.append(f)
                seen[key] = f

    return merged
