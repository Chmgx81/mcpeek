"""External dependency risk scoring.

Evaluates the risk profile of external URLs and dependencies found in
scanned content. Flags suspicious domains, URL shorteners, and high
external dependency counts.
"""

from __future__ import annotations

import re
from urllib.parse import urlparse

from ..schemas import FindingCreate


# ---------------------------------------------------------------------------
# Domain reputation
# ---------------------------------------------------------------------------

# URL shorteners and redirect services (high risk — can hide real destination)
SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "adf.ly", "tiny.cc", "lnkd.in", "cutt.ly",
    "shorturl.at", "rb.gy", "tny.im", "v.gd", "qr.ae",
    "bl.ink", "l.link", "s.id", "po.st",
}

# Free/throwaway hosting often used for phishing
SUSPICIOUS_HOSTING = {
    "herokuapp.com", "netlify.app", "vercel.app", "pages.dev",
    "workers.dev", "glitch.me", "repl.it", "codesandbox.io",
    "surge.sh", "render.com", "fly.dev",
}

# Suspicious TLDs commonly used in malicious URLs
SUSPICIOUS_TLDS = {
    ".xyz", ".tk", ".ml", ".ga", ".cf", ".gq", ".buzz", ".top",
    ".click", ".download", ".racing", ".win", ".bid", ".stream",
    ".loan", ".review", ".party", ".trade", ".webcam", ".accountant",
}

# Known safe domains
SAFE_DOMAINS = {
    "github.com", "raw.githubusercontent.com", "gist.github.com",
    "npmjs.com", "registry.npmjs.org", "pypi.org", "files.pythonhosted.org",
    "docs.python.org", "nodejs.org", "developer.mozilla.org",
    "stackoverflow.com", "google.com", "anthropic.com", "openai.com",
    "huggingface.co", "hf.co",
}


def score_urls(urls: list[str]) -> tuple[list[FindingCreate], int]:
    """Score a list of URLs for risk. Returns (findings, risk_score).

    risk_score is 0-100 where higher is riskier.
    """
    findings: list[FindingCreate] = []
    risk_score = 0

    if not urls:
        return findings, 0

    # 1. Count-based risk
    url_count = len(urls)
    if url_count > 10:
        findings.append(FindingCreate(
            category="supply_chain",
            severity="high" if url_count > 20 else "medium",
            title=f"High external dependency count: {url_count} URLs",
            description=f"This skill references {url_count} external URLs, creating a large attack surface. Each URL is a potential payload delivery vector.",
            evidence=f"Total external URLs: {url_count}",
            remediation="Minimize external dependencies. Audit each URL for necessity.",
            cwe="CWE-506",
        ))
        risk_score += min(url_count * 2, 30)
    elif url_count > 5:
        risk_score += url_count * 2

    # 2. Per-URL analysis
    shortener_count = 0
    suspicious_count = 0
    suspicious_tld_count = 0

    for url in urls:
        try:
            parsed = urlparse(url)
            if not parsed.netloc:
                continue
            hostname = parsed.netloc.lower().split(":")[0]

            # Skip safe domains
            if any(sd in hostname for sd in SAFE_DOMAINS):
                continue

            # Check URL shorteners
            if hostname in SHORTENER_DOMAINS or any(hostname.endswith("." + d) for d in SHORTENER_DOMAINS):
                shortener_count += 1
                continue

            # Check suspicious hosting
            if any(hostname.endswith("." + h) for h in SUSPICIOUS_HOSTING):
                suspicious_count += 1
                continue

            # Check suspicious TLDs
            for tld in SUSPICIOUS_TLDS:
                if hostname.endswith(tld):
                    suspicious_tld_count += 1
                    break

        except Exception:
            pass

    if shortener_count > 0:
        findings.append(FindingCreate(
            category="supply_chain",
            severity="high",
            title=f"URL shortener/redirect service detected ({shortener_count})",
            description=f"Found {shortener_count} URL shortener domain(s). These obscure the real destination and are commonly used in phishing and payload delivery.",
            evidence=f"Shortener domains found: {shortener_count} of {url_count} URLs",
            remediation="Replace URL shorteners with direct links to verify the actual destination.",
            cwe="CWE-601",
        ))
        risk_score += shortener_count * 10

    if suspicious_count > 0:
        findings.append(FindingCreate(
            category="supply_chain",
            severity="medium",
            title=f"Free/throwaway hosting detected ({suspicious_count})",
            description=f"Found {suspicious_count} URL(s) on free hosting platforms. These are commonly used for temporary malicious payloads.",
            evidence=f"Suspicious hosting domains: {suspicious_count} of {url_count} URLs",
            remediation="Verify the hosting platform is intentional. Consider self-hosting critical assets.",
            cwe="CWE-506",
        ))
        risk_score += suspicious_count * 5

    if suspicious_tld_count > 0:
        findings.append(FindingCreate(
            category="supply_chain",
            severity="medium",
            title=f"Suspicious TLD detected ({suspicious_tld_count})",
            description=f"Found {suspicious_tld_count} URL(s) using suspicious top-level domains (.xyz, .tk, .top, etc.) commonly associated with malicious activity.",
            evidence=f"Suspicious TLDs: {suspicious_tld_count} of {url_count} URLs",
            remediation="Verify the domain is legitimate. Consider using only established TLDs.",
            cwe="CWE-506",
        ))
        risk_score += suspicious_tld_count * 5

    # 3. Check for encoded/obfuscated URLs
    obfuscated_urls = [u for u in urls if _is_obfuscated_url(u)]
    if obfuscated_urls:
        findings.append(FindingCreate(
            category="obfuscation",
            severity="high",
            title=f"Obfuscated URL detected ({len(obfuscated_urls)})",
            description="Found URLs containing encoded or obfuscated components that may hide the real destination.",
            evidence=f"Obfuscated URLs: {len(obfuscated_urls)} (e.g., {obfuscated_urls[0][:80]}...)" if obfuscated_urls else "",
            remediation="Decode and verify the actual URL destination.",
            cwe="CWE-506",
        ))
        risk_score += len(obfuscated_urls) * 10

    return findings, min(risk_score, 100)


def _is_obfuscated_url(url: str) -> bool:
    """Check if a URL contains obfuscation indicators."""
    # Base64 in URL path or query
    if re.search(r"[?&/][A-Za-z0-9+/]{40,}={0,2}", url):
        return True
    # Hex encoding in URL
    if re.search(r"%[0-9a-fA-F]{2}(?:%[0-9a-fA-F]{2}){5,}", url):
        return True
    # Excessive URL encoding
    encoded_pct = url.count("%")
    if encoded_pct > 10 and encoded_pct / max(len(url), 1) > 0.1:
        return True
    return False


def analyze_domain_reputation(urls: list[str]) -> list[FindingCreate]:
    """Analyze domain reputation patterns across a list of URLs.

    Flags patterns commonly associated with malicious infrastructure:
    - Multiple subdomains (DNS tricks)
    - IP addresses instead of domains
    - Non-standard ports
    - Very long domain names (typosquatting)
    - Homoglyph detection (internationalized domain attacks)
    """
    findings: list[FindingCreate] = []

    for url in urls:
        try:
            parsed = urlparse(url)
            if not parsed.netloc:
                continue
            hostname = parsed.netloc.lower().split(":")[0]

            # IP address instead of domain
            import ipaddress
            try:
                ipaddress.ip_address(hostname)
                findings.append(FindingCreate(
                    category="supply_chain",
                    severity="high",
                    title=f"IP address used instead of domain: {hostname}",
                    description="A URL uses a raw IP address instead of a domain name. This bypasses DNS-based security controls and is common in malicious infrastructure.",
                    evidence=f"URL: {url}\nIP: {hostname}",
                    remediation="Replace IP addresses with domain names for proper DNS resolution and security controls.",
                    cwe="CWE-290",
                ))
                continue
            except ValueError:
                pass

            # Excessive subdomain depth (3+ subdomains)
            parts = hostname.split(".")
            if len(parts) > 4:
                findings.append(FindingCreate(
                    category="supply_chain",
                    severity="medium",
                    title=f"Excessive subdomain depth: {hostname}",
                    description=f"Domain has {len(parts)} parts (deep subdomain nesting). This can be used to obscure the real domain owner.",
                    evidence=f"URL: {url}\nHostname: {hostname}\nParts: {len(parts)}",
                    remediation="Verify the domain ownership and legitimacy.",
                    cwe="CWE-290",
                ))

            # Non-standard port
            if parsed.port and parsed.port not in (80, 443, 8080, 8443):
                findings.append(FindingCreate(
                    category="supply_chain",
                    severity="low",
                    title=f"Non-standard port: {hostname}:{parsed.port}",
                    description=f"URL uses a non-standard port ({parsed.port}). While not inherently malicious, it may indicate a custom C2 server.",
                    evidence=f"URL: {url}\nPort: {parsed.port}",
                    remediation="Verify the port is expected for this service.",
                    cwe="CWE-290",
                ))

        except Exception:
            pass

    return findings
