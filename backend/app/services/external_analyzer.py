import re
from urllib.parse import urlparse

import httpx

from ..schemas import FindingCreate
from .ast_analyzer import analyze_js_patterns
from .content_hash import compute_content_hash

SUSPICIOUS_CONTENT_TYPES = {"application/x-executable", "application/x-msdownload", "application/x-sh"}
SUSPICIOUS_EXTENSIONS = {".exe", ".bat", ".cmd", ".ps1", ".sh", ".dll", ".so", ".dylib"}


async def analyze_urls(urls: list[str], timeout: int = 15) -> list[FindingCreate]:
    findings: list[FindingCreate] = []
    checked = 0

    async with httpx.AsyncClient(
        timeout=timeout,
        follow_redirects=True,
        headers={"User-Agent": "MCPeek/0.1 Security Scanner"},
    ) as client:
        for url in urls[:30]:  # cap at 30 URLs
            checked += 1
            try:
                parsed = urlparse(url)
                if parsed.scheme not in ("http", "https"):
                    continue

                resp = await client.get(url, follow_redirects=True)
                final_url = str(resp.url)

                # Check redirects
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

                # Check for base64 payloads in text responses
                if "text" in ct_base or "json" in ct_base:
                    text = resp.content[:50000].decode(resp.encoding or "utf-8", errors="replace")
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

                    # Scan downloaded code for dangerous patterns
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
