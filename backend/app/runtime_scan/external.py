from urllib.parse import urlparse

import httpx

from app.schemas.scan import FindingCreate

SUSPICIOUS_CONTENT_TYPES = {"application/x-executable", "application/x-msdownload", "application/x-sh"}
SUSPICIOUS_EXTENSIONS = {".exe", ".bat", ".cmd", ".ps1", ".sh", ".dll", ".so", ".dylib"}


async def analyze_urls(urls: list[str], timeout: int = 15) -> tuple[list[FindingCreate], int]:
    """Check external URLs for redirects, executable content, and base64 payloads."""
    findings: list[FindingCreate] = []
    checked = 0

    async with httpx.AsyncClient(
        timeout=timeout,
        follow_redirects=True,
        headers={"User-Agent": "MCPeek/0.1 Security Scanner"},
    ) as client:
        for url in urls[:30]:  # cap at 30 URLs
            try:
                resp = await client.head(url)
                checked += 1

                # Check for base64-encoded data in URL
                if "base64" in url.lower():
                    findings.append(
                        FindingCreate(
                            category="external_resources",
                            severity="high",
                            title="Base64-encoded data in URL",
                            description="The URL contains base64-encoded content which could be an obfuscated payload.",
                            evidence=f"URL: {url[:200]}",
                            remediation="Verify the encoded content is legitimate. Base64 in URLs can hide malicious payloads.",
                            cwe="CWE-200",
                        )
                    )

                # Check for redirect to different domain
                final_url = str(resp.url)
                if final_url != url:
                    final_parsed = urlparse(final_url)
                    orig_parsed = urlparse(url)
                    if final_parsed.netloc != orig_parsed.netloc:
                        findings.append(
                            FindingCreate(
                                category="external_resources",
                                severity="medium",
                                title="External redirect detected",
                                description=f"URL redirects to a different domain: {final_url}. This could indicate URL hijacking or tracking.",
                                evidence=f"Original: {url}\nRedirected to: {final_url}",
                                remediation="Verify the final destination is trusted. Ensure redirects are expected.",
                                cwe="CWE-601",
                            )
                        )

                # Check content type for executables
                content_type = resp.headers.get("content-type", "")
                ct_base = content_type.split(";")[0].strip().lower()
                if ct_base in SUSPICIOUS_CONTENT_TYPES:
                    findings.append(
                        FindingCreate(
                            category="external_resources",
                            severity="high",
                            title="Executable content detected",
                            description=f"The URL serves executable content (Content-Type: {ct_base}). This could be a payload delivery mechanism.",
                            evidence=f"URL: {url}\nContent-Type: {ct_base}",
                            remediation="Avoid fetching executable content from external URLs during package installation.",
                            cwe="CWE-829",
                        )
                    )

                # Check URL extension for executable files
                path_lower = urlparse(url).path.lower()
                if any(path_lower.endswith(ext) for ext in SUSPICIOUS_EXTENSIONS):
                    findings.append(
                        FindingCreate(
                            category="external_resources",
                            severity="medium",
                            title="Suspicious file extension in URL",
                            description=f"The URL points to a file with an executable extension: {path_lower}",
                            evidence=f"URL: {url}",
                            remediation="Verify the file is necessary. Executable downloads from external URLs are high risk.",
                            cwe="CWE-829",
                        )
                    )

            except httpx.TimeoutException:
                pass
            except Exception:
                pass

    return findings, checked
