"""Trust signal analyzer — evaluate repository reputation, domain trust, and consistency."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone

from ..schemas.scan import FindingCreate

# ── Domain reputation tiers ──

TIER_1_DOMAINS = frozenset({  # Maximum trust
    'github.com', 'gitlab.com', 'bitbucket.org',
    'pypi.org', 'npmjs.com', 'crates.io',
    'hub.docker.com', 'ghcr.io', 'quay.io',
})

TIER_2_DOMAINS = frozenset({  # High trust (major cloud/docs)
    'raw.githubusercontent.com', 'gist.github.com',
    'docs.python.org', 'developer.mozilla.org',
    'registry.npmjs.org', 'files.pythonhosted.org',
    'www.npmjs.com', 'go.dev', 'crates.io',
})

TIER_3_DOMAINS = frozenset({  # Medium trust (known ecosystems)
    'deno.land', 'unpkg.com', 'jsdelivr.net',
    'cdn.jsdelivr.net', 'esm.sh', 'skypack.dev',
    'colab.research.google.com', 'replit.com',
})

SUSPICIOUS_TLDS = frozenset({
    'xyz', 'top', 'club', 'buzz', 'work', 'click', 'link',
    'loan', 'racing', 'date', 'faith', 'review', 'stream',
    'download', 'cricket', 'science', 'party', 'gdn',
    'tk', 'ml', 'ga', 'cf', 'gq',
})

# ── Data classes ──

@dataclass
class RepoMetadata:
    """Repository metadata for trust analysis."""
    name: str = ''
    full_name: str = ''
    url: str = ''
    stars: int = 0
    forks: int = 0
    open_issues: int = 0
    contributors: int = 0
    commits: int = 0
    created_at: str = ''       # ISO format
    updated_at: str = ''       # ISO format
    pushed_at: str = ''        # ISO format (last commit)
    license: str = ''
    owner_type: str = ''       # 'User', 'Organization'
    description: str = ''
    topics: list[str] = field(default_factory=list)
    external_urls: list[str] = field(default_factory=list)
    has_wiki: bool = False
    has_pages: bool = False
    default_branch: str = 'main'


@dataclass
class TrustFinding:
    """Trust analysis finding with confidence and metadata."""
    title: str
    severity: str              # critical, high, medium, low, info
    category: str              # trust_mismatch, reputation, domain_risk
    description: str
    evidence: str = ''
    remediation: str = ''
    cwe: str | None = None
    confidence: float = 0.0    # 0.0–1.0
    impact: str = 'no_impact'  # total_system_compromise, data_breach, etc.

    def to_finding_create(self) -> FindingCreate:
        return FindingCreate(
            category=self.category,
            severity=self.severity,
            title=self.title,
            description=f'{self.description}\n\nConfidence: {self.confidence:.0%}\nImpact: {self.impact}',
            evidence=self.evidence,
            remediation=self.remediation,
            cwe=self.cwe,
        )


@dataclass
class TrustAnalysisResult:
    """Complete trust analysis result."""
    trust_score: int                    # 0–100
    trust_level: str                    # critical, high, medium, low, safe
    repo_score: int = 0                 # contribution to trust from repo metrics
    domain_score: int = 0               # contribution to trust from domain analysis
    activity_score: int = 0             # contribution to trust from commit activity
    findings: list[TrustFinding] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            'trust_score': self.trust_score,
            'trust_level': self.trust_level,
            'breakdown': {
                'repo': self.repo_score,
                'domain': self.domain_score,
                'activity': self.activity_score,
            },
            'findings': [
                {
                    'title': f.title,
                    'severity': f.severity,
                    'category': f.category,
                    'description': f.description,
                    'confidence': f.confidence,
                    'impact': f.impact,
                }
                for f in self.findings
            ],
        }


# ── Domain analysis ──

def _domain_tier(domain: str) -> int:
    """Return trust tier for domain (1=highest, 4=unknown)."""
    d = domain.lower().strip('.')
    if d in TIER_1_DOMAINS:
        return 1
    if d in TIER_2_DOMAINS:
        return 2
    if d in TIER_3_DOMAINS:
        return 3
    # Check parent domains
    parts = d.split('.')
    for i in range(len(parts) - 1):
        parent = '.'.join(parts[i:])
        if parent in TIER_1_DOMAINS:
            return 2
        if parent in TIER_2_DOMAINS:
            return 3
    return 4  # unknown


def _is_suspicious_tld(domain: str) -> bool:
    parts = domain.lower().split('.')
    return bool(parts) and parts[-1] in SUSPICIOUS_TLDS


def _domain_age_days(iso_date: str) -> int | None:
    """Parse ISO date and return age in days. None if parse fails."""
    if not iso_date:
        return None
    try:
        dt = datetime.fromisoformat(iso_date.replace('Z', '+00:00'))
        now = datetime.now(timezone.utc)
        return max(0, (now - dt).days)
    except (ValueError, TypeError):
        return None


# ── Repository scoring ──

def _score_repo(meta: RepoMetadata) -> tuple[int, list[TrustFinding]]:
    """Score repository trustworthiness (0–40). Returns score and findings."""
    score = 40  # start max, deduct
    findings: list[TrustFinding] = []

    # Star-based trust
    if meta.stars >= 10000:
        pass  # full marks
    elif meta.stars >= 1000:
        score -= 2
    elif meta.stars >= 100:
        score -= 5
    elif meta.stars >= 10:
        score -= 10
    else:
        score -= 20
        findings.append(TrustFinding(
            title='Low repository stars',
            severity='medium',
            category='reputation',
            description=f'Repository has only {meta.stars} stars. Low community trust signal.',
            evidence=f'Stars: {meta.stars}, Forks: {meta.forks}',
            remediation='Verify repository legitimacy through other signals (contributor count, commit activity, license).',
            confidence=0.6,
            impact='information_disclosure',
        ))

    # Contributor trust
    if meta.contributors >= 50:
        pass
    elif meta.contributors >= 10:
        score -= 3
    elif meta.contributors >= 3:
        score -= 8
    else:
        score -= 15
        findings.append(TrustFinding(
            title='Very few contributors',
            severity='medium',
            category='reputation',
            description=f'Repository has only {meta.contributors} contributor(s). Single-maintainer projects are higher risk for supply chain attacks.',
            evidence=f'Contributors: {meta.contributors}',
            remediation='Check if the maintainer is reputable. Review commit history for signs of account takeover.',
            confidence=0.65,
            impact='privilege_escalation',
        ))

    # Forks ratio (forks > stars is suspicious — could indicate bot activity)
    if meta.stars > 0 and meta.forks > meta.stars * 2:
        score -= 8
        findings.append(TrustFinding(
            title='Unusual fork-to-star ratio',
            severity='medium',
            category='reputation',
            description=f'Repository has {meta.forks} forks but only {meta.stars} stars (ratio > 2:1). '
                        'This may indicate bot activity or suspicious forking patterns.',
            evidence=f'Stars: {meta.stars}, Forks: {meta.forks}, Ratio: {meta.forks/max(meta.stars,1):.1f}',
            remediation='Investigate fork activity. High fork counts with low stars can indicate coordinated manipulation.',
            confidence=0.55,
            impact='information_disclosure',
        ))

    # No license
    if not meta.license:
        score -= 5
        findings.append(TrustFinding(
            title='No license specified',
            severity='low',
            category='reputation',
            description='Repository has no license. This makes legal use ambiguous and may indicate a non-professional project.',
            evidence='License: None',
            remediation='Check if the project is intended for public use. Consider only using licensed packages.',
            confidence=0.7,
            impact='no_impact',
        ))

    return max(0, score), findings


def _score_activity(meta: RepoMetadata) -> tuple[int, list[TrustFinding]]:
    """Score commit activity (0–30). Returns score and findings."""
    score = 30
    findings: list[TrustFinding] = []

    # Days since last push
    push_age = _domain_age_days(meta.pushed_at)
    created_age = _domain_age_days(meta.created_at)

    if push_age is not None:
        if push_age > 365:
            score -= 15
            findings.append(TrustFinding(
                title='Abandoned repository',
                severity='high',
                category='reputation',
                description=f'Last commit was {push_age} days ago (>1 year). Abandoned repos may contain unpatched vulnerabilities.',
                evidence=f'Last push: {meta.pushed_at} ({push_age} days ago)',
                remediation='Check for maintained forks or alternatives. Unpatched dependencies are a supply chain risk.',
                confidence=0.85,
                impact='privilege_escalation',
            ))
        elif push_age > 180:
            score -= 8
            findings.append(TrustFinding(
                title='Stale repository',
                severity='medium',
                category='reputation',
                description=f'Last commit was {push_age} days ago (>6 months). Stale repos may lag behind security patches.',
                evidence=f'Last push: {meta.pushed_at} ({push_age} days ago)',
                remediation='Evaluate if active maintenance is critical for your use case.',
                confidence=0.7,
                impact='information_disclosure',
            ))
        elif push_age > 90:
            score -= 3

    # Commit count
    if meta.commits > 500:
        pass
    elif meta.commits > 100:
        score -= 3
    elif meta.commits > 20:
        score -= 8
    else:
        score -= 12
        findings.append(TrustFinding(
            title='Low commit activity',
            severity='medium',
            category='reputation',
            description=f'Repository has only {meta.commits} commits. Low development activity may indicate abandoned or immature project.',
            evidence=f'Commits: {meta.commits}',
            remediation='Check if the project is production-ready. Low commit count correlates with higher bug rates.',
            confidence=0.6,
            impact='information_disclosure',
        ))

    # Recently created (< 30 days) with high trust signals = suspicious
    if created_age is not None and created_age < 30:
        if meta.stars > 100 or meta.contributors > 10:
            score -= 10
            findings.append(TrustFinding(
                title='Recently created repo with suspicious trust signals',
                severity='high',
                category='trust_mismatch',
                description=f'Repository was created only {created_age} days ago but has {meta.stars} stars '
                            f'and {meta.contributors} contributors. This mismatch may indicate bought followers or astroturfing.',
                evidence=f'Created: {meta.created_at} ({created_age} days ago), Stars: {meta.stars}, Contributors: {meta.contributors}',
                remediation='Investigate contributor profiles for bot accounts. Verify star legitimacy.',
                confidence=0.75,
                impact='privilege_escalation',
            ))

    return max(0, score), findings


def _analyze_domains(
    meta: RepoMetadata,
    extracted_domains: list[str],
) -> tuple[int, list[TrustFinding]]:
    """Analyze domain trust (0–30). Returns score and findings."""
    score = 30
    findings: list[TrustFinding] = []

    if not extracted_domains:
        return score, findings

    suspicious_count = 0
    unknown_count = 0

    for domain in extracted_domains:
        tier = _domain_tier(domain)

        if tier >= 4:
            unknown_count += 1
            # Check for suspicious TLD
            if _is_suspicious_tld(domain):
                suspicious_count += 1
                score -= 8
                findings.append(TrustFinding(
                    title='Suspicious domain TLD',
                    severity='high',
                    category='domain_risk',
                    description=f'Domain "{domain}" uses a TLD commonly associated with phishing and malware.',
                    evidence=f'Domain: {domain}, TLD: .{domain.split(".")[-1]}',
                    remediation='Verify domain ownership. Avoid resources hosted on suspicious TLDs.',
                    cwe='CWE-200',
                    confidence=0.8,
                    impact='data_breach',
                ))
            else:
                score -= 3
                findings.append(TrustFinding(
                    title='Unknown external domain',
                    severity='medium',
                    category='domain_risk',
                    description=f'Domain "{domain}" is not in any known trust tier. Proceed with caution.',
                    evidence=f'Domain: {domain}',
                    remediation='Verify the domain is legitimate and maintained.',
                    confidence=0.5,
                    impact='information_disclosure',
                ))

    # Trust mismatch: high stars + many unknown/suspicious domains
    if meta.stars > 1000 and (suspicious_count > 0 or unknown_count > 2):
        findings.append(TrustFinding(
            title='Trust mismatch: high reputation + suspicious domains',
            severity='high',
            category='trust_mismatch',
            description=f'Repository has {meta.stars} stars but references {unknown_count} unknown domain(s) '
                        f'and {suspicious_count} suspicious domain(s). This inconsistency is a red flag.',
            evidence=f'Stars: {meta.stars}, Unknown domains: {unknown_count}, Suspicious: {suspicious_count}',
            remediation='Investigate why a high-reputation repo references untrusted external domains.',
            confidence=0.8,
            impact='data_breach',
        ))

    return max(0, score), findings


# ── Main analysis ──

def analyze_trust(
    meta: RepoMetadata,
    extracted_domains: list[str] | None = None,
) -> TrustAnalysisResult:
    """Analyze repository trust signals and compute a trust score.

    Args:
        meta: Repository metadata (stars, contributors, commits, dates, etc.)
        extracted_domains: List of external domains found in the repo content.

    Returns:
        TrustAnalysisResult with trust_score (0–100), breakdown, and findings.
    """
    all_findings: list[TrustFinding] = []

    repo_score, repo_findings = _score_repo(meta)
    all_findings.extend(repo_findings)

    activity_score, activity_findings = _score_activity(meta)
    all_findings.extend(activity_findings)

    domain_score, domain_findings = _analyze_domains(meta, extracted_domains or [])
    all_findings.extend(domain_findings)

    trust_score = min(100, repo_score + activity_score + domain_score)

    # Determine trust level
    if trust_score >= 90:
        level = 'safe'
    elif trust_score >= 70:
        level = 'low'
    elif trust_score >= 50:
        level = 'medium'
    elif trust_score >= 25:
        level = 'high'
    else:
        level = 'critical'

    # Sort findings: critical first, then by confidence
    severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
    all_findings.sort(key=lambda f: (severity_order.get(f.severity, 5), -f.confidence))

    return TrustAnalysisResult(
        trust_score=trust_score,
        trust_level=level,
        repo_score=repo_score,
        activity_score=activity_score,
        domain_score=domain_score,
        findings=all_findings,
    )
