import re
from urllib.parse import urlparse

import httpx
from httpx import URL

from ..schemas import FindingCreate
from .ast_analyzer import analyze_js_patterns
from .url_safety import is_safe_public_url

SUSPICIOUS_CONTENT_TYPES = {"application/x-executable", "application/x-msdownload", "application/x-sh"}
SUSPICIOUS_EXTENSIONS = {".exe", ".bat", ".cmd", ".ps1", ".sh", ".dll", ".so", ".dylib"}

# Crypto mining detection patterns
CRYPTO_MINING_PATTERNS = [
    (r"(?i)(?:stratum\+tcp|stratum\+ssl|stratum2):", "Stratum mining protocol connection"),
    (r"(?i)(?:coinhive|coin-hive|cryptonight|monero|xmrig|xmr-stak)", "Known cryptominer reference"),
    (r"(?i)(?:minero\.php|proxy\.php|miner\.js)", "Miner proxy script"),
    (r"(?i)(?:hashrate|hash_rate|shares_difficulty|difficulty\.target)", "Mining terminology"),
    (r"(?i)(?:blob\.blob\.core\.windows\.net|paste\.bin\.com.*mining)", "Cloud-hosted miner"),
]

# JS sandbox / obfuscation patterns
JS_OBFUSCATION_PATTERNS = [
    (r"(?i)String\.fromCharCode\((?:\d+,\s*){3,}", "Heavy String.fromCharCode obfuscation"),
    (r"(?i)\\x[0-9a-f]{2}(?:\\x[0-9a-f]{2}){5,}", "Hex-encoded string sequences"),
    (r"(?i)\\u[0-9a-f]{4}(?:\\u[0-9a-f]{4}){5,}", "Unicode-encoded string sequences"),
    (r"(?i)(?:atob|btoa)\s*\([^)]*\)\s*\+\s*(?:atob|btoa)", "Nested base64 encoding/decoding"),
    (r"(?i)eval\s*\(\s*(?:atob|btoa|decodeURIComponent|unescape)", "Eval with decoder — obfuscated code execution"),
    (r"(?i)(?:_0x[a-f0-9]{4,8}\s*(?:\+\+\s*|\-\-\s*)){3,}", "Obfuscated variable name rotation (JSFuck-style)"),
    (r"(?i)Function\s*\(\s*['\"]return\s", "Function constructor — dynamic code generation"),
    (r"(?i)(?:document\.write|document\.writeln)\s*\(\s*unescape", "document.write with unescape — historical XSS pattern"),
]

# Data exfiltration patterns in fetched content
DATA_EXFIL_PATTERNS = [
    (r"(?i)(?:new\s+Image|fetch|XMLHttpRequest|axios|beacon)\s*\([^)]*(?:cookie|token|session|auth|password|secret|key|credential)", "Potential credential exfiltration"),
    (r"(?i)(?:navigator\.userAgent|screen\.width|screen\.height|location\.href|document\.cookie)", "Browser fingerprinting"),
    (r"(?i)(?:https?://[^\s'\"]+(?:/collect|/track|/log|/pixel|/beacon))", "Tracking/beacon endpoint"),
]


async def analyze_urls(urls: list[str], timeout: int = 15, max_urls: int = 30) -> tuple[list[FindingCreate], int]:
    findings: list[FindingCreate] = []
    checked = 0

    async with httpx.AsyncClient(
        timeout=min(timeout, 8),
        follow_redirects=True,
        headers={"User-Agent": "MCPeek/0.1 Security Scanner"},
    ) as client:
        for url in urls[:max_urls]:
            checked += 1
            try:
                parsed = urlparse(url)
                if parsed.scheme not in ("http", "https") or not is_safe_public_url(url):
                    continue

                resp = await client.get(url, follow_redirects=False)
                final_url = str(resp.url)

                # Check redirects
                if 300 <= resp.status_code < 400 and "location" in resp.headers:
                    final_url = str(URL(url).join(resp.headers["location"]))
                    if not is_safe_public_url(final_url):
                        findings.append(
                            FindingCreate(
                                category="external_resources",
                                severity="high",
                                title=f"Unsafe redirect blocked: {url}",
                                description="External URL redirects to a private, reserved, or otherwise blocked network target.",
                                evidence=f"Original: {url}\nRedirected to: {final_url}",
                                remediation="Remove redirects to internal or private network resources.",
                                cwe="CWE-918",
                                references=[],
                            )
                        )
                        continue
                    resp = await client.get(final_url, follow_redirects=False)

                if final_url.rstrip("/") != url.rstrip("/"):
                    final_parsed = urlparse(final_url)
                    orig_parsed = urlparse(url)
                    if final_parsed.netloc != orig_parsed.netloc:
                        findings.append(
                            FindingCreate(
                                category="external_resources",
                                severity="medium",
                                title=f"External redirect detected: {url}",
                                description=f"URL redirects to a different domain: {final_url}. This could indicate URL hijacking or tracking.",
                                evidence=f"Original: {url}\nRedirected to: {final_url}",
                                remediation="Verify the redirect target is intentional and trustworthy. Consider pinning to expected domains.",
                                references=[],
                            )
                        )

                # Check content type
                content_type = resp.headers.get("content-type", "")
                ct_base = content_type.split(";")[0].strip().lower()
                if ct_base in SUSPICIOUS_CONTENT_TYPES:
                    findings.append(
                        FindingCreate(
                            category="external_resources",
                            severity="high",
                            title=f"Executable content at {url}",
                            description=f"The URL serves executable content (Content-Type: {ct_base}). This could be a payload delivery mechanism.",
                            evidence=f"Content-Type: {content_type}\nResponse size: {len(resp.content)} bytes",
                            remediation="Review the purpose of this URL. Ensure executable content is intentional and from a trusted source.",
                            cwe="CWE-502",
                            references=[],
                        )
                    )

                # Analyze text content for threats
                if "text" in ct_base or "json" in ct_base:
                    text = resp.content[:100000].decode(resp.encoding or "utf-8", errors="replace")

                    # Base64 payloads
                    b64_matches = re.findall(r"[A-Za-z0-9+/]{40,}={0,2}", text)
                    long_b64 = [m for m in b64_matches if len(m) > 100]
                    if long_b64:
                        findings.append(
                            FindingCreate(
                                category="external_resources",
                                severity="medium",
                                title=f"Base64-encoded payload at {url}",
                                description=f"Found {len(long_b64)} base64-encoded strings (longest: {max(len(m) for m in long_b64)} chars). These may hide executable code.",
                                evidence=f"URL: {url}\nLongest payload: {len(long_b64[0])} characters\nSample: {long_b64[0][:80]}...",
                                remediation="Decode and inspect base64 payloads to verify they contain benign data.",
                                references=[],
                            )
                        )

                    # Crypto mining detection
                    for pattern, title in CRYPTO_MINING_PATTERNS:
                        if re.search(pattern, text):
                            findings.append(
                                FindingCreate(
                                    category="external_resources",
                                    severity="critical",
                                    title=f"Crypto mining detected at {url}",
                                    description=f"Content matches cryptominer pattern: {title}",
                                    evidence=f"URL: {url}\nPattern: {title}\nContent-Type: {content_type}",
                                    remediation="Remove this URL immediately. Cryptominers consume resources and may indicate compromise.",
                                    cwe="CWE-400",
                                    references=[],
                                )
                            )
                            break

                    # JS obfuscation detection
                    for pattern, title in JS_OBFUSCATION_PATTERNS:
                        if re.search(pattern, text):
                            findings.append(
                                FindingCreate(
                                    category="external_resources",
                                    severity="high",
                                    title=f"Obfuscated JavaScript at {url}",
                                    description=f"Content matches obfuscation pattern: {title}",
                                    evidence=f"URL: {url}\nPattern: {title}\nContent-Type: {content_type}",
                                    remediation="Inspect the obfuscated code. Heavy obfuscation in external resources is suspicious.",
                                    cwe="CWE-502",
                                    references=[],
                                )
                            )
                            break

                    # Data exfiltration patterns
                    for pattern, title in DATA_EXFIL_PATTERNS:
                        match = re.search(pattern, text)
                        if match:
                            findings.append(
                                FindingCreate(
                                    category="external_resources",
                                    severity="high",
                                    title=f"Data exfiltration risk at {url}",
                                    description=f"Content matches exfiltration pattern: {title}",
                                    evidence=f"URL: {url}\nMatch: {match.group()[:150]}",
                                    remediation="Review what data is being collected/sent. Ensure no sensitive data is leaked.",
                                    cwe="CWE-200",
                                    references=[],
                                )
                            )
                            break

                    # Dangerous script patterns
                    js_findings = analyze_js_patterns(text)
                    for jf in js_findings:
                        jf.evidence = f"URL: {url}\n{jf.evidence}"
                        findings.append(jf)

                # Check for suspicious script tags in HTML
                if "text/html" in ct_base:
                    html = resp.content[:100000].decode(resp.encoding or "utf-8", errors="replace")
                    scripts = re.findall(r"<script[^>]*>(.*?)</script>", html, re.DOTALL)
                    for script in scripts:
                        if re.search(r"(eval|Function\(|document\.write|innerHTML\s*=)", script):
                            findings.append(
                                FindingCreate(
                                    category="external_resources",
                                    severity="high",
                                    title=f"Suspicious script at {url}",
                                    description="HTML page contains scripts using eval/Function/document.write which can execute arbitrary code.",
                                    evidence=f"Script snippet: {script[:200]}...",
                                    remediation="Review the embedded scripts. Dynamic code execution in external resources is a security risk.",
                                    cwe="CWE-95",
                                    references=[],
                                )
                            )
                            break

            except httpx.TimeoutException:
                pass
            except httpx.RequestError:
                pass

    return findings, checked
