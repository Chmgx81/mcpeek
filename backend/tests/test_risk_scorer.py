"""Tests for risk scoring logic."""

import pytest

from app.schemas import FindingCreate
from app.services.risk_scorer import build_summary, calculate_risk


class TestCalculateRisk:
    def test_no_findings(self):
        score, level = calculate_risk([])
        assert score == 0
        assert level == "safe"

    def test_single_critical(self):
        findings = [FindingCreate(category="test", severity="critical", title="t", description="d")]
        score, level = calculate_risk(findings)
        assert score == 25
        assert level == "low"

    def test_four_criticals_max_out(self):
        findings = [
            FindingCreate(category="test", severity="critical", title=f"t{i}", description="d")
            for i in range(4)
        ]
        score, level = calculate_risk(findings)
        assert score == 100
        assert level == "critical"

    def test_five_criticals_capped_at_100(self):
        findings = [
            FindingCreate(category="test", severity="critical", title=f"t{i}", description="d")
            for i in range(5)
        ]
        score, level = calculate_risk(findings)
        assert score == 100
        assert level == "critical"

    def test_mixed_severities(self):
        findings = [
            FindingCreate(category="test", severity="critical", title="c", description="d"),
            FindingCreate(category="test", severity="high", title="h", description="d"),
            FindingCreate(category="test", severity="medium", title="m", description="d"),
            FindingCreate(category="test", severity="low", title="l", description="d"),
        ]
        score, level = calculate_risk(findings)
        # 25 + 15 + 8 + 3 = 51
        assert score == 51
        assert level == "medium"

    def test_info_findings_add_zero(self):
        findings = [
            FindingCreate(category="test", severity="info", title="i", description="d")
            for _ in range(10)
        ]
        score, level = calculate_risk(findings)
        assert score == 0
        assert level == "safe"

    def test_unknown_severity_adds_zero(self):
        findings = [FindingCreate(category="test", severity="unknown", title="u", description="d")]
        score, level = calculate_risk(findings)
        assert score == 0


class TestBuildSummary:
    def test_empty_findings(self):
        summary = build_summary([])
        assert summary == {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "trust_score": 100}

    def test_counts_by_severity(self):
        findings = [
            FindingCreate(category="test", severity="critical", title="c1", description="d"),
            FindingCreate(category="test", severity="critical", title="c2", description="d"),
            FindingCreate(category="test", severity="high", title="h1", description="d"),
            FindingCreate(category="test", severity="medium", title="m1", description="d"),
        ]
        summary = build_summary(findings)
        assert summary["critical"] == 2
        assert summary["high"] == 1
        assert summary["medium"] == 1
        assert summary["low"] == 0
        assert summary["info"] == 0
        assert summary["trust_score"] == 100

    def test_unknown_severity_not_counted(self):
        findings = [FindingCreate(category="test", severity="unknown", title="u", description="d")]
        summary = build_summary(findings)
        assert summary["critical"] == 0
        assert summary["high"] == 0
        assert summary["medium"] == 0
        assert summary["low"] == 0
        assert summary["info"] == 0
        assert summary["trust_score"] == 100
