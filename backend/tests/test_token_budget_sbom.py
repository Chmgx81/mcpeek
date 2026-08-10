"""Tests for token budget analysis and SBOM generation."""

import json
import pytest
from unittest.mock import patch, AsyncMock


class TestTokenBudget:
    def test_excessive_max_tokens(self):
        from app.services.mcp_scanner import _check_token_budget

        content = '{"max_tokens": 150000}'
        manifest = {"mcpServers": {"test": {"command": "node"}}}
        findings = _check_token_budget(content, manifest, "test")
        assert any("max_tokens" in f.title for f in findings)
        assert any(f.severity == "medium" for f in findings)

    def test_normal_max_tokens(self):
        from app.services.mcp_scanner import _check_token_budget

        content = '{"max_tokens": 4096}'
        manifest = {"mcpServers": {"test": {"command": "node", "rateLimit": 100}}}
        findings = _check_token_budget(content, manifest, "test")
        assert len(findings) == 0

    def test_excessive_max_output_tokens(self):
        from app.services.mcp_scanner import _check_token_budget

        content = '{"maxOutputTokens": 200000}'
        manifest = {"mcpServers": {"test": {"command": "node"}}}
        findings = _check_token_budget(content, manifest, "test")
        assert any("maxOutputTokens" in f.title for f in findings)

    def test_missing_rate_limit(self):
        from app.services.mcp_scanner import _check_token_budget

        content = '{}'
        manifest = {"mcpServers": {"test": {"command": "node"}}}
        findings = _check_token_budget(content, manifest, "test")
        assert any("rate limiting" in f.title.lower() for f in findings)

    def test_has_rate_limit(self):
        from app.services.mcp_scanner import _check_token_budget

        content = '{}'
        manifest = {"mcpServers": {"test": {"command": "node", "rateLimit": 100}}}
        findings = _check_token_budget(content, manifest, "test")
        assert not any("rate limiting" in f.title.lower() for f in findings)

    def test_large_context_window(self):
        from app.services.mcp_scanner import _check_token_budget

        content = '{"context_window": 2000000}'
        manifest = {"mcpServers": {"test": {"command": "node"}}}
        findings = _check_token_budget(content, manifest, "test")
        assert any("context window" in f.title.lower() for f in findings)

    def test_unbounded_loop(self):
        from app.services.mcp_scanner import _check_token_budget

        content = 'while(true) { processTask(); }'
        manifest = None
        findings = _check_token_budget(content, manifest, "test")
        assert any("unbounded" in f.title.lower() for f in findings)
        assert any(f.severity == "high" for f in findings)

    def test_bounded_loop(self):
        from app.services.mcp_scanner import _check_token_budget

        content = 'while(true) { processTask(); } maxIterations: 50'
        manifest = None
        findings = _check_token_budget(content, manifest, "test")
        assert not any("unbounded" in f.title.lower() for f in findings)

    def test_high_iteration_limit(self):
        from app.services.mcp_scanner import _check_token_budget

        content = 'maxIterations: 500'
        manifest = None
        findings = _check_token_budget(content, manifest, "test")
        assert any("iteration limit" in f.title.lower() for f in findings)


class TestSBOM:
    def test_generate_sbom(self):
        from app.services.sbom_generator import generate_sbom

        deps = {"test-pkg": "1.0.0", "other-pkg": "2.1.0"}
        sbom = generate_sbom("test-server", deps)
        assert sbom is not None
        assert len(sbom.components) > 0

    def test_sbom_components(self):
        from app.services.sbom_generator import generate_sbom

        deps = {"test-pkg": "1.0.0", "other-pkg": "2.1.0"}
        sbom = generate_sbom("test-server", deps)
        assert len(sbom.components) == 2
        assert sbom.components[0].name == "test-pkg"

    def test_sbom_with_dependencies(self):
        from app.services.sbom_generator import generate_sbom

        deps = {"express": "4.18.2", "lodash": "4.17.21"}
        sbom = generate_sbom("test-server", deps)
        assert sbom is not None
        assert sbom.name == "test-server"

    def test_license_compatibility(self):
        from app.services.sbom_generator import generate_sbom, check_license_compatibility

        deps = {"test-pkg": "1.0.0"}
        sbom = generate_sbom("test-server", deps)
        warnings = check_license_compatibility(sbom)
        assert isinstance(warnings, list)

    def test_license_compatibility_with_gpl(self):
        from app.services.sbom_generator import generate_sbom, check_license_compatibility

        deps = {"gpl-package": "1.0.0"}
        sbom = generate_sbom("test-server", deps)
        warnings = check_license_compatibility(sbom)
        assert isinstance(warnings, list)

    def test_sbom_format_cyclonedx(self):
        from app.services.sbom_generator import generate_sbom, SBOMFormat

        deps = {"test-pkg": "1.0.0"}
        sbom = generate_sbom("test-server", deps, format=SBOMFormat.CYCLONEDX)
        assert sbom.format == SBOMFormat.CYCLONEDX

    def test_sbom_format_spdx(self):
        from app.services.sbom_generator import generate_sbom, SBOMFormat

        deps = {"test-pkg": "1.0.0"}
        sbom = generate_sbom("test-server", deps, format=SBOMFormat.SPDX)
        assert sbom.format == SBOMFormat.SPDX
