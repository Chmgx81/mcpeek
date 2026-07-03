from difflib import SequenceMatcher


from app.schemas.scan import FindingCreate

# ── Common package names used for typosquatting comparison ──

COMMON_PACKAGES = [
    "react", "express", "lodash", "axios", "chalk", "commander", "body-parser",
    "morgan", "cors", "dotenv", "mongoose", "passport", "bcrypt", "jsonwebtoken",
    "socket.io", "request", "async", "bluebird", "moment", "underscore",
    "colors", "glob", "rimraf", "mkdirp", "yargs", "minimist", "debug",
    "js-yaml", "node-fetch", "uuid", "validate", "joi", "yup", "zod",
    "fastify", "koa", "hapi", "next", "nuxt", "gatsby", "webpack",
    "babel", "typescript", "eslint", "prettier", "postcss", "tailwindcss",
    "django", "flask", "fastapi", "requests", "numpy", "pandas", "scipy",
    "matplotlib", "scikit-learn", "torch", "tensorflow", "pillow", "sqlalchemy",
    "alembic", "celery", "redis", "pytest", "pydantic", "click", "rich",
    "httpx", "aiohttp", "asyncio", "uvicorn", "gunicorn", "starlette",
    "typer", "pydantic-settings", "python-dotenv", "setuptools", "wheel",
]

TOP_PACKAGES: set[str] = set()


def _build_top_packages():
    """Cache the common package set once."""
    global TOP_PACKAGES
    if not TOP_PACKAGES:
        TOP_PACKAGES.update(COMMON_PACKAGES)
        # Add scoped npm package bases
        for pkg in list(COMMON_PACKAGES):
            TOP_PACKAGES.add(f"@{pkg}")

_build_top_packages()


# ── Helper functions ──


def _levenshtein_ratio(a: str, b: str) -> float:
    return SequenceMatcher(None, a, b).ratio()


def check_typosquatting(name: str) -> list[FindingCreate]:
    """Check a package name for typosquatting against known packages."""
    findings: list[FindingCreate] = []
    for known in COMMON_PACKAGES:
        if name == known:
            continue
        ratio = _levenshtein_ratio(name.lower(), known.lower())
        if ratio > 0.8 and ratio < 1.0:
            findings.append(
                FindingCreate(
                    category="supply_chain",
                    severity="high",
                    title=f"Possible typosquatting: '{name}' looks like '{known}'",
                    description=f"Package name '{name}' has a similarity ratio of {ratio:.0%} with the well-known package '{known}'. This may be a typosquatting attack.",
                    evidence=f"Suspicious: {name}\nLegitimate: {known}\nSimilarity: {ratio:.0%}",
                    remediation="Double-check the package name. Install the well-known package if you mistyped. Verify the maintainer's identity.",
                    cwe="CWE-1104",
                )
            )
    return findings


def check_maintainers(name: str, latest_version: str, maintainers: list, data: dict) -> list[FindingCreate]:
    """Check maintainer count and recency."""
    findings: list[FindingCreate] = []

    if not maintainers:
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

    return findings


def check_dependency_count(name: str, deps: dict, threshold: int = 50) -> list[FindingCreate]:
    """Flag packages with excessive dependencies."""
    if len(deps) > threshold:
        return [
            FindingCreate(
                category="supply_chain",
                severity="low",
                title=f"High dependency count: {len(deps)}",
                description=f"The package has {len(deps)} direct dependencies, increasing the supply chain attack surface.",
                evidence=f"Package: {name}\nDependencies: {len(deps)}",
                remediation="Audit the dependency tree for unnecessary packages.",
            )
        ]
    return []


def check_binary_dependencies(name: str, deps: dict) -> list[FindingCreate]:
    """Flag native/binary dependencies that can't be statically audited."""
    binary_deps = [d for d in deps if any(kw in d.lower() for kw in ["native", "binding", "addon", "ffi"])]
    if binary_deps:
        return [
            FindingCreate(
                category="supply_chain",
                severity="medium",
                title=f"Native binary dependencies in {name}",
                description=f"The package depends on native binary modules: {', '.join(binary_deps[:5])}",
                evidence=f"Binary deps: {binary_deps[:5]}",
                remediation="Native modules run compiled code that cannot be statically audited as easily. Verify their necessity.",
                cwe="CWE-506",
            )
        ]
    return []


def check_metadata_anomalies(name: str, info: dict) -> list[FindingCreate]:
    """Check PyPI package info for red flags (no author, no repo, etc.)."""
    findings: list[FindingCreate] = []
    author = (info.get("author") or info.get("author_email") or "").strip()
    maintainer = (info.get("maintainer") or info.get("maintainer_email") or "").strip()
    if not author and not maintainer:
        findings.append(
            FindingCreate(
                category="supply_chain",
                severity="medium",
                title=f"No author or maintainer for {name}",
                description="This PyPI package has no listed author or maintainer, which is suspicious.",
                evidence=f"Package: {name}",
                remediation="Verify the package source. Consider reaching out to the PyPI maintainers.",
            )
        )

    home_page = info.get("home_page") or info.get("project_urls", {}).get("Homepage", "")
    if not home_page:
        findings.append(
            FindingCreate(
                category="supply_chain",
                severity="low",
                title=f"No homepage for {name}",
                description="This package has no homepage URL, which reduces traceability.",
                evidence=f"Package: {name}",
                remediation="Ensure the package links to a legitimate repository or project site.",
            )
        )
    return findings
