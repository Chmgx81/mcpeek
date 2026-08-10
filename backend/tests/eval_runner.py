"""
MCPeek Evaluation Runner — benchmarks detection accuracy across all layers.

Metrics:
- Precision: TP / (TP + FP) — of all flags, how many are real?
- Recall: TP / (TP + FN) — of all real threats, how many did we catch?
- F1: harmonic mean of precision and recall
- Accuracy: (TP + TN) / Total
- False Positive Rate: FP / (FP + TN)
- Detection rate by difficulty and category
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field

from app.services.vulnerability_db import get_vulnerability_db, AttackCategory
from app.services.attack_defense import get_attack_defense, ThreatLevel
from app.services.ai_detector import _match_vulnerability_db, _run_attack_defense
from app.schemas import FindingCreate
from tests.eval_cases import TestCase, get_all_test_cases, get_true_positives, get_true_negatives, get_by_difficulty


@dataclass
class EvalResult:
    """Result of evaluating a single test case."""
    test_case: TestCase
    detected: bool
    threat_level: ThreatLevel
    findings_count: int
    categories_detected: list[str]
    latency_ms: float
    correct: bool  # TP detected or TN not detected
    false_positive: bool = False
    false_negative: bool = False


@dataclass
class EvalMetrics:
    """Aggregated evaluation metrics."""
    total: int = 0
    tp: int = 0  # True Positives (correctly detected)
    tn: int = 0  # True Negatives (correctly not flagged)
    fp: int = 0  # False Positives (falsely flagged)
    fn: int = 0  # False Negatives (missed threats)

    @property
    def precision(self) -> float:
        return self.tp / (self.tp + self.fp) if (self.tp + self.fp) > 0 else 0.0

    @property
    def recall(self) -> float:
        return self.tp / (self.tp + self.fn) if (self.tp + self.fn) > 0 else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) > 0 else 0.0

    @property
    def accuracy(self) -> float:
        return (self.tp + self.tn) / self.total if self.total > 0 else 0.0

    @property
    def false_positive_rate(self) -> float:
        return self.fp / (self.fp + self.tn) if (self.fp + self.tn) > 0 else 0.0

    @property
    def detection_rate(self) -> float:
        return self.tp / (self.tp + self.fn) if (self.tp + self.fn) > 0 else 0.0


@dataclass
class CategoryMetrics:
    """Metrics per attack category."""
    category: str
    detected: int = 0
    expected: int = 0
    false_positives: int = 0

    @property
    def recall(self) -> float:
        return self.detected / self.expected if self.expected > 0 else 0.0


@dataclass
class EvalReport:
    """Full evaluation report."""
    overall: EvalMetrics
    by_difficulty: dict[str, EvalMetrics]
    by_category: dict[str, CategoryMetrics]
    results: list[EvalResult]
    total_latency_ms: float = 0.0
    avg_latency_ms: float = 0.0

    def print_report(self) -> None:
        print("=" * 70)
        print("MCPeek EVALUATION REPORT")
        print("=" * 70)
        print()

        # Overall
        m = self.overall
        print("OVERALL METRICS")
        print("-" * 40)
        print(f"  Total test cases:  {m.total}")
        print(f"  True Positives:    {m.tp}")
        print(f"  True Negatives:    {m.tn}")
        print(f"  False Positives:   {m.fp}")
        print(f"  False Negatives:   {m.fn}")
        print()
        print(f"  Precision:         {m.precision:.1%}")
        print(f"  Recall:            {m.recall:.1%}")
        print(f"  F1 Score:          {m.f1:.1%}")
        print(f"  Accuracy:          {m.accuracy:.1%}")
        print(f"  False Positive Rate: {m.false_positive_rate:.1%}")
        print()

        # By difficulty
        print("BY DIFFICULTY")
        print("-" * 40)
        for diff in ["easy", "medium", "hard"]:
            dm = self.by_difficulty.get(diff)
            if dm:
                print(f"  {diff.upper():8s}  P={dm.precision:.0%} R={dm.recall:.0%} F1={dm.f1:.0%}  ({dm.tp+dm.tn}/{dm.total} correct)")
        print()

        # By category
        print("BY ATTACK CATEGORY")
        print("-" * 40)
        for cat, cm in sorted(self.by_category.items()):
            bar = "#" * int(cm.recall * 20)
            print(f"  {cat:25s}  {cm.detected}/{cm.expected}  {cm.recall:.0%}  {bar}")
        print()

        # Performance
        print("PERFORMANCE")
        print("-" * 40)
        print(f"  Total latency:     {self.total_latency_ms:.0f}ms")
        print(f"  Average per case:  {self.avg_latency_ms:.1f}ms")
        print()

        # Failures
        fps = [r for r in self.results if r.false_positive]
        fns = [r for r in self.results if r.false_negative]
        if fps:
            print("FALSE POSITIVES (flagged safe content)")
            print("-" * 40)
            for r in fps:
                print(f"  {r.test_case.id}: {r.test_case.description}")
                print(f"    Content: {r.test_case.content[:80]}...")
                print()
        if fns:
            print("FALSE NEGATIVES (missed real threats)")
            print("-" * 40)
            for r in fns:
                print(f"  {r.test_case.id}: {r.test_case.description}")
                print(f"    Content: {r.test_case.content[:80]}...")
                print()
        print("=" * 70)


def _is_detected(threat_level: ThreatLevel) -> bool:
    """Check if a threat level means the content was flagged."""
    return threat_level in (ThreatLevel.LOW, ThreatLevel.MEDIUM, ThreatLevel.HIGH, ThreatLevel.CRITICAL)


def evaluate_test_case(tc: TestCase) -> EvalResult:
    """Evaluate a single test case against all detection layers."""
    start = time.monotonic()

    # Layer 1: VulnDB
    vuln_findings = _match_vulnerability_db(tc.content)
    # Layer 2: Attack Defense
    defense_findings = _run_attack_defense(tc.content)
    # Combined
    all_findings = vuln_findings + defense_findings

    # Determine detection
    defense = get_attack_defense()
    report = defense.analyze(tc.content)
    detected = _is_detected(report.threat_level)

    # Categories detected
    categories = list(set(f.category for f in all_findings))

    latency = (time.monotonic() - start) * 1000

    # Determine correctness
    correct = (tc.expected_threat and detected) or (not tc.expected_threat and not detected)
    false_positive = not tc.expected_threat and detected
    false_negative = tc.expected_threat and not detected

    return EvalResult(
        test_case=tc,
        detected=detected,
        threat_level=report.threat_level,
        findings_count=len(all_findings),
        categories_detected=categories,
        latency_ms=latency,
        correct=correct,
        false_positive=false_positive,
        false_negative=false_negative,
    )


def run_evaluation(test_cases: list[TestCase] | None = None) -> EvalReport:
    """Run the full evaluation suite."""
    cases = test_cases or get_all_test_cases()
    results = []

    for tc in cases:
        result = evaluate_test_case(tc)
        results.append(result)

    # Aggregate
    overall = EvalMetrics()
    by_difficulty: dict[str, EvalMetrics] = {}
    by_category: dict[str, CategoryMetrics] = {}

    for r in results:
        overall.total += 1
        if r.correct:
            if r.test_case.expected_threat:
                overall.tp += 1
            else:
                overall.tn += 1
        else:
            if r.false_positive:
                overall.fp += 1
            elif r.false_negative:
                overall.fn += 1

        # By difficulty
        diff = r.test_case.difficulty
        if diff not in by_difficulty:
            by_difficulty[diff] = EvalMetrics()
        dm = by_difficulty[diff]
        dm.total += 1
        if r.correct:
            if r.test_case.expected_threat:
                dm.tp += 1
            else:
                dm.tn += 1
        else:
            if r.false_positive:
                dm.fp += 1
            elif r.false_negative:
                dm.fn += 1

        # By category
        if r.test_case.expected_threat:
            for cat in r.test_case.expected_categories:
                if cat not in by_category:
                    by_category[cat] = CategoryMetrics(category=cat)
                cm = by_category[cat]
                cm.expected += 1
                if cat in r.categories_detected:
                    cm.detected += 1
            if r.false_positive:
                for cat in r.categories_detected:
                    if cat not in by_category:
                        by_category[cat] = CategoryMetrics(category=cat)
                    by_category[cat].false_positives += 1

    total_latency = sum(r.latency_ms for r in results)
    avg_latency = total_latency / len(results) if results else 0

    return EvalReport(
        overall=overall,
        by_difficulty=by_difficulty,
        by_category=by_category,
        results=results,
        total_latency_ms=total_latency,
        avg_latency_ms=avg_latency,
    )


if __name__ == "__main__":
    report = run_evaluation()
    report.print_report()
