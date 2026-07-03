"""External dependency scanner — extracts and analyzes URLs, domains, and external references."""

from __future__ import annotations

import re
from urllib.parse import urlparse

from ..schemas.scan import FindingCreate

# ── Extraction patterns ──

URL_RE = re.compile(r'https?://[^\s<>"\')\]{}]+')
DOMAIN_RE = re.compile(r'(?<![a-z0-9.-])([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.(?:com|net|org|io|dev|sh|py|js|ts|co|ai|xyz|top|ru|cn|de|fr|uk|ca|au|in|br|nl|se|no|fi|dk|pl|cz|sk|hu|ro|bg|hr|si|lt|lv|ee|ie|pt|es|it|gr|tr|ua|kz|uz|jp|kr|tw|hk|sg|my|th|vn|ph|id|au|nz))', re.IGNORECASE)
API_ENDPOINT_RE = re.compile(r'(?:GET|POST|PUT|DELETE|PATCH)\s+(/\S+)', re.IGNORECASE)
API_URL_RE = re.compile(r'https?://[^/\s]+/api(?:/[^\s<>"\')\]]+)?')
INSTALL_SCRIPT_RE = re.compile(r'https?://[^\s<>"\']+(?:install|setup|bootstrap)\.(?:sh|bash|zsh|ps1|bat|cmd)')
RAW_SCRIPT_RE = re.compile(r'(?:curl|wget)\s+(?:-[a-zA-Z]+\s+)*https?://[^\s<>"\']+')
DOC_LINK_RE = re.compile(r'https?://(?:docs|documentation|wiki|readthedocs|gitbook)\.[^\s<>"\')\]]+', re.IGNORECASE)
NPM_REGISTRY_RE = re.compile(r'https?://(?:registry\.npmjs\.org|unpkg\.com|jsdelivr\.net|cdn\.skypack\.dev|esm\.run)/[^\s<>"\']+', re.IGNORECASE)
PYPI_REGISTRY_RE = re.compile(r'https?://(?:pypi\.org|files\.pythonhosted\.org)/[^\s<>"\']+', re.IGNORECASE)
DOCKER_REGISTRY_RE = re.compile(r'https?://(?:hub\.docker\.com|ghcr\.io|gcr\.io|ecr\.[a-z0-9-]+\.amazonaws\.com|registry\.?docker\.io)/[^\s<>"\']+', re.IGNORECASE)

# ── Known legitimate domains (not suspicious) ──

TRUSTED_DOMAINS = frozenset({
    'github.com', 'gitlab.com', 'bitbucket.org',
    'npmjs.com', 'pypi.org', 'crates.io',
    'hub.docker.com', 'ghcr.io',
    'docs.python.org', 'developer.mozilla.org',
    'www.npmjs.com', 'registry.npmjs.org',
    'raw.githubusercontent.com', 'gist.github.com',
    'example.com', 'localhost',
})

# ── Suspicious TLDs (common in phishing/malware) ──

SUSPICIOUS_TLDS = frozenset({
    'xyz', 'top', 'club', 'buzz', 'work', 'click', 'link',
    'loan', 'racing', 'date', 'faith', 'review', 'stream',
    'download', 'cricket', 'science', 'party', 'gdn',
})

# ── Known typosquatting targets for AI/ML ecosystems ──

TYPOSQUAT_MAP: dict[str, list[str]] = {
    'openai': ['openai-api', 'openai-sdk', 'openai-python'],
    'anthropic': ['anthropic-api', 'anthropic-sdk'],
    'langchain': ['langchain-core', 'langchain-api'],
    'llamaindex': ['llama-index', 'llamaindex'],
    'huggingface': ['hugging-face', 'huggingface-api'],
    'mcp': ['mcp-server', 'mcp-sdk', 'modelcontextprotocol'],
    'react': ['react-dom', 'react-router'],
    'next': ['nextjs', 'next-server'],
    'vue': ['vuejs', 'vue-cli'],
}

# ── Package registry shorthand patterns ──

NPM_INSTALL_RE = re.compile(r'npm\s+(?:install|i|add)\s+(@?[a-z0-9_-]+(?:@[a-z0-9._-]+)?)')
PIP_INSTALL_RE = re.compile(r'pip\s+(?:install)\s+(-[a-zA-Z]+\s+)*([a-zA-Z0-9_-]+(?:[=><]+[a-zA-Z0-9._-]+)?)')
CURL_BASH_RE = re.compile(r'curl\s+(?:-[a-zA-Z]+\s+)*https?://[^\s]+[^|]*\|\s*(?:sudo\s+)?(?:ba)?sh')


def _extract_domains(text: str) -> list[str]:
    """Extract unique domain names from text."""
    domains: set[str] = set()
    for match in URL_RE.finditer(text):
        try:
            parsed = urlparse(match.group())
            if parsed.hostname:
                domains.add(parsed.hostname.lower())
        except Exception:
            pass
    # Also grab bare domains
    for match in DOMAIN_RE.finditer(text):
        domains.add(match.group().lower())
    return sorted(domains)


def _extract_urls(text: str) -> list[dict[str, str]]:
    """Extract URLs with their context."""
    results: list[dict[str, str]] = []
    seen: set[str] = set()
    for match in URL_RE.finditer(text):
        url = match.group().rstrip('.,;:!?')
        if url in seen:
            continue
        seen.add(url)
        # Grab surrounding context
        start = max(0, match.start() - 60)
        end = min(len(text), match.end() + 60)
        ctx = text[start:end].replace('\n', ' ').strip()
        results.append({'url': url, 'context': ctx})
    return results


def _classify_url(url: str) -> str:
    """Classify a URL into a category."""
    url_lower = url.lower()
    if INSTALL_SCRIPT_RE.search(url_lower) or CURL_BASH_RE.search(url_lower):
        return 'install_script'
    if RAW_SCRIPT_RE.search(url_lower):
        return 'remote_script'
    if NPM_REGISTRY_RE.search(url_lower):
        return 'npm_registry'
    if PYPI_REGISTRY_RE.search(url_lower):
        return 'pypi_registry'
    if DOCKER_REGISTRY_RE.search(url_lower):
        return 'docker_registry'
    if DOC_LINK_RE.search(url_lower):
        return 'documentation'
    if API_URL_RE.search(url_lower):
        return 'api_endpoint'
    return 'external_resource'


def _is_suspicious_domain(domain: str) -> list[str]:
    """Check if a domain looks suspicious. Returns list of reasons."""
    reasons: list[str] = []
    parts = domain.split('.')
    tld = parts[-1] if parts else ''

    # Suspicious TLD
    if tld in SUSPICIOUS_TLDS:
        reasons.append(f'suspicious TLD (.{tld})')

    # Typosquatting check — only flag if domain closely mimics an official project
    for canonical, variants in TYPOSQUAT_MAP.items():
        # Only match if the domain IS the canonical or a variant prefix (e.g. "openai-api.com")
        # Don't flag "awesome-mcp.io" as typosquatting of "mcp" — that's the tool's own domain
        for variant in variants:
            if domain == variant or domain.startswith(variant + '.'):
                # Looks like it could be impersonating the official project
                reasons.append(f'possible typosquatting of "{canonical}"')
                break

    # Unofficial docs domains — only flag if domain impersonates a known project's docs
    known_official_projects = {
        'openai': ['openai.com', 'platform.openai.com'],
        'anthropic': ['anthropic.com', 'docs.anthropic.com'],
        'langchain': ['langchain.com', 'docs.langchain.com', 'python.langchain.com'],
        'microsoft': ['microsoft.com', 'docs.microsoft.com', 'learn.microsoft.com'],
        'google': ['google.com', 'ai.google.dev', 'cloud.google.com'],
        'meta': ['meta.com', 'llama.meta.com'],
    }
    for project, official_domains in known_official_projects.items():
        if project in domain and not any(d in domain for d in official_domains):
            if 'docs' in domain or 'documentation' in domain:
                reasons.append(f'unofficial docs domain for {project}')

    # IP address in URL (should be domain)
    if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', domain):
        reasons.append('raw IP address instead of domain')

    return reasons


def check_external_dependencies(
    content: str,
    source: str = 'content',
) -> list[FindingCreate]:
    """Scan for and analyze external dependencies in content.

    Extracts URLs, domains, API endpoints, install scripts, and docs.
    Flags suspicious patterns and untrusted external resources.
    """
    findings: list[FindingCreate] = []

    # ── Extract all external references ──
    urls = _extract_urls(content)
    domains = _extract_domains(content)

    # ── Install scripts (Critical) ──
    for match in CURL_BASH_RE.finditer(content):
        findings.append(
            FindingCreate(
                category='external_dependency',
                severity='critical',
                title='Remote script execution',
                description='Content contains a curl pipe to shell command, which executes arbitrary remote code.',
                evidence=f'Pattern: {match.group()[:200]}',
                remediation='Pin to specific versions, download and verify checksums before executing. Avoid piping remote scripts directly to shell.',
                cwe='CWE-94',
            )
        )
        break  # one finding per category

    for url_info in urls:
        cat = _classify_url(url_info['url'])

        if cat == 'install_script':
            findings.append(
                FindingCreate(
                    category='external_dependency',
                    severity='critical',
                    title='Remote install script reference',
                    description='Tool references a remote install/setup script that can change after verification.',
                    evidence=f'URL: {url_info["url"]}\nContext: {url_info["context"][:200]}',
                    remediation='Pin versions and validate external content regularly. Use checksums or signatures.',
                    cwe='CWE-494',
                )
            )
        elif cat == 'remote_script':
            findings.append(
                FindingCreate(
                    category='external_dependency',
                    severity='high',
                    title='Remote script download',
                    description='Content downloads a remote script for execution, which can be modified after initial review.',
                    evidence=f'URL: {url_info["url"]}\nContext: {url_info["context"][:200]}',
                    remediation='Pin versions, verify checksums, and mirror scripts locally where possible.',
                    cwe='CWE-494',
                )
            )
        elif cat == 'api_endpoint':
            findings.append(
                FindingCreate(
                    category='external_dependency',
                    severity='medium',
                    title='External API endpoint reference',
                    description='Tool references an external API endpoint that could change, be deprecated, or leak data.',
                    evidence=f'URL: {url_info["url"]}\nContext: {url_info["context"][:200]}',
                    remediation='Document API dependencies, pin to specific versions, and monitor for breaking changes.',
                    cwe='CWE-406',
                )
            )
        elif cat in ('npm_registry', 'pypi_registry', 'docker_registry'):
            severity = 'high' if cat == 'docker_registry' else 'medium'
            findings.append(
                FindingCreate(
                    category='external_dependency',
                    severity=severity,
                    title=f'Package registry reference ({cat.split("_")[0]})',
                    description=f'Tool references a package on {cat.split("_")[0]} registry. Packages can be updated or replaced (dependency confusion).',
                    evidence=f'URL: {url_info["url"]}',
                    remediation='Pin exact versions, use lockfiles, verify package integrity with checksums or signatures.',
                    cwe='CWE-829',
                )
            )
        elif cat == 'documentation':
            # Only flag if it's NOT a known official docs domain
            parsed = urlparse(url_info['url'])
            hostname = (parsed.hostname or '').lower()
            if hostname and not any(trusted in hostname for trusted in TRUSTED_DOMAINS):
                findings.append(
                    FindingCreate(
                        category='external_dependency',
                        severity='medium',
                        title='Unofficial documentation link',
                        description='Documentation link points to a non-official domain. Could be misleading or compromised.',
                        evidence=f'URL: {url_info["url"]}\nDomain: {hostname}',
                        remediation='Use official documentation sources. Verify documentation URLs against project homepage.',
                        cwe='CWE-200',
                    )
                )

    # ── Domain analysis ──
    for domain in domains:
        if any(trusted in domain for trusted in TRUSTED_DOMAINS):
            continue
        reasons = _is_suspicious_domain(domain)
        if reasons:
            severity = 'high' if any('typosquat' in r or 'unofficial' in r for r in reasons) else 'medium'
            findings.append(
                FindingCreate(
                    category='external_dependency',
                    severity=severity,
                    title='Suspicious domain detected',
                    description=f'Domain "{domain}" has suspicious characteristics: {"; ".join(reasons)}.',
                    evidence=f'Domain: {domain}',
                    remediation='Verify domain ownership. Use official package sources. Check domain registration date if available.',
                    cwe='CWE-200',
                )
            )

    # ── Unpinned external references (High) ──
    # Check for npm/pip install without version pinning
    for match in NPM_INSTALL_RE.finditer(content):
        pkg = match.group(1)
        if '@' not in pkg:  # no version specified
            findings.append(
                FindingCreate(
                    category='external_dependency',
                    severity='high',
                    title=f'Unpinned npm package: {pkg}',
                    description=f'Package "{pkg}" is installed without a pinned version. Supply chain attacks can inject malicious code via version updates.',
                    evidence=f'Command: {match.group()}',
                    remediation=f'Pin to specific version: {pkg}@x.y.z, or use a lockfile.',
                    cwe='CWE-829',
                )
            )

    for match in PIP_INSTALL_RE.finditer(content):
        pkg = match.group(2)
        if pkg and '==' not in pkg and '>=' not in pkg and '<=' not in pkg and not pkg.startswith('-') and not pkg.endswith('.txt') and not pkg.endswith('.in'):
            findings.append(
                FindingCreate(
                    category='external_dependency',
                    severity='high',
                    title=f'Unpinned pip package: {pkg}',
                    description=f'Package "{pkg}" is installed without a pinned version. Supply chain attacks can inject malicious code via version updates.',
                    evidence=f'Command: {match.group()}',
                    remediation=f'Pin to specific version: {pkg}==x.y.z, or use a requirements lockfile.',
                    cwe='CWE-829',
                )
            )

    # ── External dependency risk summary (High)
    # One aggregated finding when ANY external resources are found
    if urls:
        external_count = len(urls)
        findings.append(
            FindingCreate(
                category='external_dependency',
                severity='high',
                title='External Dependency Risk',
                description=f'Tool references {external_count} external resource(s) that can change after initial verification. External URLs, APIs, and packages are mutable and can be compromised.',
                evidence=f'External resources found: {external_count}\n' + '\n'.join(
                    f'- {u["url"]}' for u in urls[:10]
                ),
                remediation='Pin versions and validate external content regularly. Use checksums, signatures, or lockfiles for all external dependencies.',
                cwe='CWE-829',
            )
        )

    return findings
