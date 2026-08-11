# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in MCPeek, please report it responsibly:

1. **Do NOT** open a public GitHub issue for security vulnerabilities
2. Email security findings to: [your-email@example.com]
3. Include a description of the vulnerability, steps to reproduce, and potential impact
4. Allow reasonable time for a fix before public disclosure

## What We Consider a Security Vulnerability

- Remote code execution via MCP config scanning
- SSRF bypass (accessing private IPs, DNS rebinding)
- Authentication/authorization bypass
- Data exposure (leaking scan results, API keys, database contents)
- Denial of service via crafted payloads
- Supply chain attacks on MCPeek's own dependencies

## Security Features

MCPeek includes these security measures:

- **Rate limiting**: 10 scans/min/IP (configurable)
- **SSRF protection**: Blocks private/reserved IPs, DNS rebinding defense
- **Input validation**: Size limits (500KB inline, 2MB remote)
- **No code execution**: Static analysis only — never runs scanned code
- **Content hashing**: SHA-256 tamper detection for bait-and-switch attacks
- **Agent defense**: Unicode normalization, Base64 decoding, social engineering detection
- **Session tracking**: 3-strike rule for repeated suspicious activity

## Scope

- MCPeek web application (frontend + API)
- GitHub Action
- CLI scanner
- Backend scanner engine

Out of scope:
- Third-party MCP servers being scanned (report those to their maintainers)
- Issues in dependencies (report to the dependency maintainer)

## Response Timeline

- Acknowledgment: within 48 hours
- Initial assessment: within 1 week
- Fix or mitigation: within 2 weeks for critical issues

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x | Yes |
| < 0.1 | No |
