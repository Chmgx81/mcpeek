"""Tests for AI-native detection module."""

import pytest

from app.schemas import FindingCreate
from app.services.ai_detector import (
    _apply_additions,
    _apply_refinements,
    _build_detection_prompt,
    _parse_json,
    _sanitize,
)


class TestSanitize:
    def test_strips_control_chars(self):
        assert _sanitize("hello\x00world") == "helloworld"

    def test_collapses_newlines(self):
        assert _sanitize("a\n\n\n\n\nb") == "a\n\nb"

    def test_truncates_long_text(self):
        result = _sanitize("x" * 2000, max_len=100)
        assert len(result) <= 115
        assert result.endswith("...[truncated]")

    def test_empty_string(self):
        assert _sanitize("") == ""

    def test_none_like(self):
        assert _sanitize("") == ""


class TestParseJson:
    def test_direct_json(self):
        assert _parse_json('{"a": 1}') == {"a": 1}

    def test_array(self):
        assert _parse_json('[{"x": 1}]') == [{"x": 1}]

    def test_code_block(self):
        text = '```json\n{"a": 1}\n```'
        assert _parse_json(text) == {"a": 1}

    def test_nested_code_block(self):
        text = 'Some text\n```json\n{"key": "value"}\n```\nMore text'
        assert _parse_json(text) == {"key": "value"}

    def test_invalid_json(self):
        assert _parse_json("not json at all") is None

    def test_empty(self):
        assert _parse_json("") is None

    def test_none(self):
        assert _parse_json(None) is None

    def test_trailing_comma(self):
        assert _parse_json('{"a": 1,}') == {"a": 1}


class TestApplyRefinements:
    def _make_finding(self, title="Test finding", severity="high"):
        return FindingCreate(
            category="test",
            severity=severity,
            title=title,
            description="desc",
        )

    def test_keep_action(self):
        findings = [self._make_finding("shell exec")]
        refinements = [{"title": "shell exec", "action": "keep", "reason": "confirmed"}]
        result = _apply_refinements(findings, refinements)
        assert len(result) == 1
        assert result[0].source == "heuristic+ai"

    def test_remove_action(self):
        findings = [self._make_finding("false positive")]
        refinements = [{"title": "false positive", "action": "remove", "reason": "FP"}]
        result = _apply_refinements(findings, refinements)
        assert len(result) == 0

    def test_downgrade_action(self):
        findings = [self._make_finding("maybe issue", severity="critical")]
        refinements = [{"title": "maybe issue", "action": "downgrade", "reason": "overrated"}]
        result = _apply_refinements(findings, refinements)
        assert len(result) == 1
        assert result[0].severity == "high"
        assert result[0].source == "heuristic+ai"

    def test_no_matching_refinement(self):
        findings = [self._make_finding("unique title")]
        refinements = [{"title": "other title", "action": "remove"}]
        result = _apply_refinements(findings, refinements)
        assert len(result) == 1
        assert result[0].source == "heuristic"

    def test_case_insensitive_match(self):
        findings = [self._make_finding("Shell Exec")]
        refinements = [{"title": "shell exec", "action": "remove"}]
        result = _apply_refinements(findings, refinements)
        assert len(result) == 0


class TestApplyAdditions:
    def test_valid_addition(self):
        additions = [{
            "category": "ai_detected",
            "severity": "high",
            "title": "Novel prompt injection",
            "description": "Context-dependent attack",
            "evidence": "...",
            "remediation": "Fix it",
            "cwe": "CWE-77",
        }]
        result = _apply_additions([], additions)
        assert len(result) == 1
        assert result[0].source == "ai_detected"
        assert result[0].title == "AI: Novel prompt injection"

    def test_invalid_addition_missing_fields(self):
        additions = [{"category": "ai_detected"}]
        result = _apply_additions([], additions)
        assert len(result) == 0

    def test_invalid_severity(self):
        additions = [{
            "category": "ai_detected",
            "severity": "invalid",
            "title": "Test",
            "description": "Test",
        }]
        result = _apply_additions([], additions)
        assert len(result) == 0

    def test_non_dict_skipped(self):
        result = _apply_additions([], ["not a dict"])
        assert len(result) == 0


class TestBuildDetectionPrompt:
    def test_includes_content(self):
        prompt = _build_detection_prompt("test content", [], "mcp_server")
        assert "test content" in prompt

    def test_includes_findings(self):
        findings = [{"severity": "high", "category": "shell", "title": "exec"}]
        prompt = _build_detection_prompt("content", findings, "mcp_server")
        assert "exec" in prompt
        assert "HIGH" in prompt

    def test_empty_findings(self):
        prompt = _build_detection_prompt("content", [], "mcp_server")
        assert "(none)" in prompt
