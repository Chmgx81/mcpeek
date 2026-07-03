
import httpx

from ..schemas import FindingCreate

# Common package names for typosquatting comparison
TOP_PACKAGES = {
    "npm": {
        "lodash", "react", "axios", "express", "moment", "chalk", "commander",
        "webpack", "babel", "eslint", "prettier", "typescript", "jest", "mocha",
        "vue", "angular", "next", "gatsby", "redux", "moment", "underscore",
        "request", "debug", "glob", "minimatch", "semver", "yargs", "inquirer",
    },
    "pypi": {
        "requests", "flask", "django", "numpy", "pandas", "scipy", "matplotlib",
        "tensorflow", "torch", "pillow", "beautifulsoup4", "selenium", "scrapy",
        "fastapi", "uvicorn", "pydantic", "sqlalchemy", "celery", "redis",
        "boto3", "cryptography", "paramiko", "pytest", "black", "ruff",
    },
}

DANGEROUS_NPM_SCRIPTS = {
    "postinstall", "preinstall", "postuninstall", "preuninstall",
    "prepare", "publish", "prepublish", "install",
}

EXECUTION_PATTERNS = [
    "eval(", "Function(", "child_process", "execSync", "spawn(",
    "exec(", "require('child_process')", 'require("child_process")',
    "curl ", "wget ", "powershell", "cmd.exe", "/bin/sh", "/bin/bash",
]


async def scan_package(target: str, target_type: str, deep: bool = True, timeout: int = 120) -> tuple[list[FindingCreate], dict]:
    findings: list[FindingCreate] = []
    metadata: dict = {"files_analyzed": 0, "urls_checked": 0, "deps_analyzed": 0}

    is_npm = target_type == "npm_package"
    registry_url = f"https://registry.npmjs.org/{target}" if is_npm else f"https://pypi.org/pypi/{target}/json"

    try:
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
            resp = await client.get(registry_url)
            resp.raise_for_status()
            data = resp.json()
            metadata["files_analyzed"] = 1
    except httpx.HTTPStatusError as e:
        if e.response.status_code == 404:
            findings.append(
                FindingCreate(
                    category="package",
                    severity="info",
                    title=f"Package not found: {target}",
                    description=f"The package '{target}' was not found in the {'npm' if is_npm else 'PyPI'} registry.",
                    remediation="Verify the package name is correct.",
                )
            )
        return findings, metadata
    except Exception:
        return findings, metadata

    if is_npm:
        findings.extend(_analyze_npm_package(target, data, metadata))
    else:
        findings.extend(_analyze_pypi_package(target, data, metadata))

    findings.extend(_check_typosquatting(target, "npm" if is_npm else "pypi"))

    return findings, metadata


def _analyze_npm_package(name: str, data: dict, metadata: dict) -> list[FindingCreate]:
    findings: list[FindingCreate] = []
    latest_version = data.get("dist-tags", {}).get("latest", "")
    pkg_data = data.get("versions", {}).get(latest_version, {}) or {}

    # Check scripts
    scripts = pkg_data.get("scripts", {})
    if isinstance(scripts, dict):
        for script_name, script_cmd in scripts.items():
            if script_name.lower() in DANGEROUS_NPM_SCRIPTS and isinstance(script_cmd, str):
                for pattern in EXECUTION_PATTERNS:
                    if pattern.lower() in script_cmd.lower():
                        findings.append(
                            FindingCreate(
                                category="supply_chain",
                                severity="high",
                                title=f"Dangerous {script_name} script in {name}",
                                description=f"The '{script_name}' script contains execution patterns: {script_cmd[:150]}",
                                evidence=f"Package: {name}@{latest_version}\nScript: {script_name} = {script_cmd}",
                                remediation="Review this script for malicious behavior. Consider using --ignore-scripts during install.",
                                cwe="CWE-506",
                            )
                        )
                        break

    # Check maintainers
    maintainers = data.get("maintainers", [])
    if len(maintainers) == 0:
        findings.append(
            FindingCreate(
                category="supply_chain",
                severity="medium",
                title=f"No maintainers listed for {name}",
                description="This package has no listed maintainers, which is unusual and may indicate an abandoned or malicious package.",
                evidence=f"Package: {name}@{latest_version}\nMaintainers: 0",
                remediation="Verify the package is actively maintained by a trusted publisher.",
            )
        )
    elif len(maintainers) == 1:
        findings.append(
            FindingCreate(
                category="supply_chain",
                severity="low",
                title=f"Single maintainer for {name}",
                description="This package has only one maintainer, which increases the risk if that account is compromised.",
                evidence=f"Package: {name}@{latest_version}\nMaintainers: {len(maintainers)}",
                remediation="Consider whether the bus factor is acceptable for your risk tolerance.",
            )
        )

    # Check dependencies
    deps = pkg_data.get("dependencies", {})
    metadata["deps_analyzed"] = len(deps)

    if len(deps) > 50:
        findings.append(
            FindingCreate(
                category="supply_chain",
                severity="low",
                title=f"High dependency count: {len(deps)}",
                description=f"The package has {len(deps)} direct dependencies, increasing the supply chain attack surface.",
                evidence=f"Package: {name}@{latest_version}\nDependencies: {len(deps)}",
                remediation="Audit the dependency tree for unnecessary packages.",
            )
        )

    # Check for suspicious binary/native dependencies
    binary_deps = [d for d in deps if any(kw in d.lower() for kw in ["native", "binding", "addon", "ffi"])]
    if binary_deps:
        findings.append(
            FindingCreate(
                category="supply_chain",
                severity="medium",
                title=f"Native binary dependencies in {name}",
                description=f"The package depends on native binary modules: {', '.join(binary_deps[:5])}",
                evidence=f"Binary deps: {binary_deps[:5]}",
                remediation="Native modules run compiled code that cannot be statically audited as easily. Verify their necessity.",
                cwe="CWE-506",
            )
        )

    return findings


def _analyze_pypi_package(name: str, data: dict, metadata: dict) -> list[FindingCreate]:
    findings: list[FindingCreate] = []
    info = data.get("info", {})

    # Check author/maintainer
    author = info.get("author") or info.get("author_email") or ""
    maintainer = info.get("maintainer") or info.get("maintainer_email") or ""
    if not author and not maintainer:
        findings.append(
            FindingCreate(
                category="supply_chain",
                severity="medium",
                title=f"No author information for {name}",
                description="This package has no author or maintainer information, which is unusual for a legitimate package.",
                evidence=f"Package: {name}\nAuthor: (none)\nMaintainer: (none)",
                remediation="Verify the package is from a trusted source.",
            )
        )

    # Check for suspicious classifiers
    classifiers = info.get("classifiers", [])
    if not classifiers:
        findings.append(
            FindingCreate(
                category="supply_chain",
                severity="low",
                title=f"No PyPI classifiers for {name}",
                description="The package lacks standard PyPI classifiers, which may indicate it's not following packaging best practices.",
                evidence=f"Package: {name}\nClassifiers: 0",
                remediation="Check the package documentation and source repository.",
            )
        )

    # Check dependencies
    requires = info.get("requires_dist", []) or []
    metadata["deps_analyzed"] = len(requires)

    if len(requires) > 30:
        findings.append(
            FindingCreate(
                category="supply_chain",
                severity="low",
                title=f"High dependency count: {len(requires)}",
                description=f"The package has {len(requires)} dependencies.",
                evidence=f"Package: {name}\nDependencies: {len(requires)}",
                remediation="Audit the dependency tree.",
            )
        )

    # Check project URLs
    project_urls = info.get("project_urls") or {}
    if not project_urls:
        findings.append(
            FindingCreate(
                category="supply_chain",
                severity="low",
                title=f"No project URLs for {name}",
                description="The package has no linked project URLs (homepage, repository, etc.).",
                remediation="Verify the package source repository exists and is trustworthy.",
            )
        )

    return findings


def _check_typosquatting(name: str, ecosystem: str) -> list[FindingCreate]:
    findings: list[FindingCreate] = []
    top = TOP_PACKAGES.get(ecosystem, set())

    for known in top:
        # Simple similarity: check if name is a close variant
        if name == known:
            continue

        # Substring containment with slight modification
        if len(name) > 3 and len(known) > 3:
            # Check if one contains the other with small additions
            if known in name and len(name) - len(known) <= 3:
                findings.append(
                    FindingCreate(
                        category="supply_chain",
                        severity="high",
                        title=f"Possible typosquatting of '{known}'",
                        description=f"The package name '{name}' is very similar to the popular package '{known}'. This may be a typosquatting attempt.",
                        evidence=f"Similar package: {known}\nThis package: {name}\nEcosystem: {ecosystem}",
                        remediation="Verify this is the intended package. Check the author, download count, and repository.",
                        cwe="CWE-506",
                    )
                )
                break

            # Check Levenshtein-like: swap adjacent characters
            for i in range(len(known) - 1):
                variant = known[:i] + known[i + 1] + known[i] + known[i + 2:]
                if name == variant:
                    findings.append(
                        FindingCreate(
                            category="supply_chain",
                            severity="high",
                            title=f"Possible typosquatting of '{known}'",
                            description=f"The package name '{name}' appears to be '{known}' with swapped characters. This is a common typosquatting technique.",
                            evidence=f"Similar package: {known}\nThis package: {name}",
                            remediation="Use the original package name. Verify the publisher.",
                            cwe="CWE-506",
                        )
                    )
                    break

    return findings
