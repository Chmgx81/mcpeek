import json
import ipaddress
import socket
from urllib.parse import urlparse

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, Request
from slowapi import Limiter
from slowapi.util import get_remote_address
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..config import settings
from ..database import get_db
from ..models import Finding, Scan
from ..schemas import (
    FindingResponse,
    ReportResponse,
    ScanListItem,
    ScanListResponse,
    ScanRequest,
    ScanResponse,
    StatsResponse,
)
from ..services.scanner import run_scan

router = APIRouter(prefix="/api/v1")
limiter = Limiter(key_func=get_remote_address)


# ---------------------------------------------------------------------------
# URL validation (SSRF protection)
# ---------------------------------------------------------------------------

_BLOCKED_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("192.0.0.0/24"),
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.18.0.0/15"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
    ipaddress.ip_network("224.0.0.0/4"),
    ipaddress.ip_network("240.0.0.0/4"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]


def _is_blocked_host(hostname: str) -> bool:
    try:
        addresses = [ipaddress.ip_address(hostname)]
    except ValueError:
        try:
            infos = socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
        except socket.gaierror:
            raise HTTPException(status_code=400, detail="Invalid URL: hostname cannot be resolved")
        addresses = [ipaddress.ip_address(info[4][0]) for info in infos]

    return any(any(ip in net for net in _BLOCKED_NETWORKS) for ip in addresses)


def _validate_target(target: str, target_type: str) -> None:
    """Validate scan target to prevent SSRF and other abuses."""
    if len(target) > settings.MAX_TARGET_LENGTH:
        raise HTTPException(status_code=400, detail="Target is too long")

    if target == "__inline_config__":
        return

    if target_type in ("mcp_server", "agent_skill") and not target.startswith(("http://", "https://")):
        if not settings.ALLOW_LOCAL_PATH_SCANS:
            raise HTTPException(status_code=400, detail="Local path scans are disabled in this environment")
        return

    if target_type in ("mcp_server", "agent_skill") and target.startswith("http"):
        parsed = urlparse(target)
        if parsed.scheme not in ("http", "https"):
            raise HTTPException(status_code=400, detail="Only http/https URLs are allowed")
        hostname = parsed.hostname
        if not hostname:
            raise HTTPException(status_code=400, detail="Invalid URL: no hostname")
        if not settings.ALLOW_PRIVATE_NETWORK_SCANS and _is_blocked_host(hostname):
            raise HTTPException(
                status_code=400,
                detail=f"Scanning private/reserved network targets is not allowed: {hostname}",
            )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _finding_dicts(findings: list[Finding]) -> list[dict]:
    return [
        {
            "id": f.id, "category": f.category, "severity": f.severity,
            "title": f.title, "description": f.description,
            "evidence": f.evidence, "remediation": f.remediation,
            "cwe": f.cwe, "owasp": f.owasp,
            "references": json.loads(f.references_json),
        }
        for f in findings
    ]


def _finding_responses(findings: list[Finding]) -> list[FindingResponse]:
    return [
        FindingResponse(
            id=f.id, category=f.category, severity=f.severity,
            title=f.title, description=f.description, evidence=f.evidence,
            remediation=f.remediation, cwe=f.cwe, owasp=f.owasp,
            references=json.loads(f.references_json),
        )
        for f in findings
    ]


def _group_by_severity(findings: list[Finding]) -> dict[str, list[FindingResponse]]:
    groups: dict[str, list[FindingResponse]] = {
        "critical": [], "high": [], "medium": [], "low": [], "info": [],
    }
    for f in findings:
        fr = FindingResponse(
            id=f.id, category=f.category, severity=f.severity,
            title=f.title, description=f.description, evidence=f.evidence,
            remediation=f.remediation, cwe=f.cwe, owasp=f.owasp,
            references=json.loads(f.references_json),
        )
        if f.severity in groups:
            groups[f.severity].append(fr)
    return groups


def _meta(scan: Scan) -> dict:
    return {
        "scan_duration_ms": scan.scan_duration_ms,
        "files_analyzed": scan.files_analyzed,
        "urls_checked": scan.urls_checked,
        "deps_analyzed": scan.deps_analyzed,
    }


# ---------------------------------------------------------------------------
# Submit scan
# ---------------------------------------------------------------------------

@router.post("/scan")
@limiter.limit(f"{settings.RATE_LIMIT_PER_MINUTE}/minute")
async def submit_scan(request: Request, scan_req: ScanRequest, background_tasks: BackgroundTasks, db: AsyncSession = Depends(get_db)):
    import uuid

    _validate_target(scan_req.target, scan_req.target_type.value)

    scan_id = str(uuid.uuid4())
    scan = Scan(
        id=scan_id,
        target=scan_req.target,
        target_type=scan_req.target_type.value,
        status="pending",
    )
    db.add(scan)
    await db.commit()

    background_tasks.add_task(_run_scan_task, scan_id, scan_req)

    return {"scan_id": scan_id, "status": "pending"}


async def _run_scan_task(scan_id: str, request: ScanRequest) -> None:
    from ..database import async_session

    async with async_session() as db:
        await run_scan(scan_id, request, db)


# ---------------------------------------------------------------------------
# Scan status
# ---------------------------------------------------------------------------

@router.get("/scan/{scan_id}", response_model=ScanResponse)
async def get_scan(scan_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    findings_result = await db.execute(
        select(Finding).where(Finding.scan_id == scan_id).order_by(Finding.severity)
    )
    findings = findings_result.scalars().all()

    return ScanResponse(
        scan_id=scan.id,
        status=scan.status,
        target=scan.target,
        target_type=scan.target_type,
        overall_risk=scan.overall_risk,
        risk_level=scan.risk_level,
        summary=json.loads(scan.summary_json),
        findings=_finding_responses(findings),
        metadata=_meta(scan),
        created_at=scan.created_at.isoformat() if scan.created_at else None,
        error_message=scan.error_message,
        content_changed=scan.content_hashes_json != "{}" and scan.rescan_of is not None,
    )


# ---------------------------------------------------------------------------
# Re-scan a previously scanned target (detect bait-and-switch)
# ---------------------------------------------------------------------------

@router.post("/scan/{scan_id}/rescan")
@limiter.limit(f"{settings.RATE_LIMIT_PER_MINUTE}/minute")
async def rescan_scan(
    request: Request,
    scan_id: str,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
):
    """Re-scan the same target as a previous scan, comparing URL content hashes."""
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    prev_scan = result.scalar_one_or_none()
    if not prev_scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if prev_scan.status not in ("completed", "failed"):
        raise HTTPException(status_code=400, detail="Previous scan is still in progress")

    from ..schemas import ScanOptions
    new_req = ScanRequest(
        target_type=prev_scan.target_type,
        target=prev_scan.target,
        options=ScanOptions(deep=True),
        rescan_of=scan_id,
    )

    import uuid
    new_id = str(uuid.uuid4())
    new_scan = Scan(
        id=new_id,
        target=prev_scan.target,
        target_type=prev_scan.target_type,
        status="pending",
        rescan_of=scan_id,
    )
    db.add(new_scan)
    await db.commit()

    background_tasks.add_task(_run_scan_task, new_id, new_req)

    return {"scan_id": new_id, "status": "pending", "rescan_of": scan_id}


# ---------------------------------------------------------------------------
# Content change comparison
# ---------------------------------------------------------------------------

@router.get("/scan/{scan_id}/changes")
async def get_content_changes(scan_id: str, db: AsyncSession = Depends(get_db)):
    """Compare this scan's URL content hashes against the scan it was based on."""
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if not scan.rescan_of:
        raise HTTPException(status_code=400, detail="This scan is not a re-scan")

    from ..services.content_hash import compare_hashes, hashes_from_json
    new_hashes = hashes_from_json(scan.content_hashes_json or "{}")

    prev_result = await db.execute(select(Scan).where(Scan.id == scan.rescan_of))
    prev_scan = prev_result.scalar_one_or_none()
    if not prev_scan:
        raise HTTPException(status_code=404, detail="Previous scan not found")

    old_hashes = hashes_from_json(prev_scan.content_hashes_json or "{}")
    changes = compare_hashes(old_hashes, new_hashes)

    return {
        "scan_id": scan_id,
        "rescan_of": scan.rescan_of,
        "changes": changes,
        "total_changes": len(changes),
        "has_changes": len(changes) > 0,
    }


# ---------------------------------------------------------------------------
# Report (original structured format)
# ---------------------------------------------------------------------------

@router.get("/report/{scan_id}", response_model=ReportResponse)
async def get_report(scan_id: str, db: AsyncSession = Depends(get_db)):
    """Return a structured report with findings grouped by severity."""
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    findings_result = await db.execute(
        select(Finding).where(Finding.scan_id == scan_id).order_by(Finding.severity)
    )
    findings = findings_result.scalars().all()

    return ReportResponse(
        scan_id=scan.id,
        target=scan.target,
        target_type=scan.target_type,
        status=scan.status,
        overall_risk=scan.overall_risk,
        risk_level=scan.risk_level,
        summary=json.loads(scan.summary_json),
        findings=_group_by_severity(findings),
        total_findings=len(findings),
        metadata=_meta(scan),
        created_at=scan.created_at.isoformat() if scan.created_at else None,
        error_message=scan.error_message,
    )


# ---------------------------------------------------------------------------
# Full report (JSON report + security summary + executive summary)
# ---------------------------------------------------------------------------

@router.get("/report/{scan_id}/full")
async def get_full_report(scan_id: str, db: AsyncSession = Depends(get_db)):
    """Full report: JSON structured report, security summary, executive summary, attack simulation."""
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    findings_result = await db.execute(
        select(Finding).where(Finding.scan_id == scan_id).order_by(Finding.severity)
    )
    findings = findings_result.scalars().all()

    from ..services.report_generator import generate_report

    report_data = generate_report(
        scan_id=scan.id,
        target=scan.target,
        target_type=scan.target_type,
        status=scan.status,
        risk_score=scan.overall_risk,
        findings=_finding_dicts(findings),
        metadata=_meta(scan),
        created_at=scan.created_at.isoformat() if scan.created_at else None,
    )

    return report_data


# ---------------------------------------------------------------------------
# Report export (plain text, markdown)
# ---------------------------------------------------------------------------

@router.get("/report/{scan_id}/export")
async def export_report(
    scan_id: str,
    fmt: str = Query("json", alias="format", pattern="^(json|text|markdown)$"),
    db: AsyncSession = Depends(get_db),
):
    """Export report as JSON, plain text, or Markdown."""
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    findings_result = await db.execute(
        select(Finding).where(Finding.scan_id == scan_id).order_by(Finding.severity)
    )
    findings = findings_result.scalars().all()
    meta = _meta(scan)

    from ..services.report_generator import (
        build_json_report,
        build_security_summary,
    )

    fdicts = _finding_dicts(findings)

    if fmt == "json":
        return build_json_report(
            scan_id=scan.id, target=scan.target, target_type=scan.target_type,
            status=scan.status, risk_score=scan.overall_risk,
            findings=fdicts, metadata=meta,
            created_at=scan.created_at.isoformat() if scan.created_at else None,
        )

    from ..services.report_generator import _compute_trust_score, _trust_label
    trust = _compute_trust_score(fdicts)

    if fmt == "markdown":
        return {"format": "markdown", "content": _to_markdown(scan, fdicts, meta, trust, trust_label=_trust_label(trust))}

    return {"format": "text", "content": build_security_summary(
        scan.target, scan.target_type, scan.overall_risk, trust,
        fdicts, meta,
    )}


# ---------------------------------------------------------------------------
# Markdown renderer
# ---------------------------------------------------------------------------

def _to_markdown(scan, findings, meta, trust, trust_label):
    from ..services.report_generator import _risk_label, _generate_attack_scenarios, _build_recommendations

    risk = scan.overall_risk
    by_sev = {"critical": [], "high": [], "medium": [], "low": [], "info": []}
    for f in findings:
        s = f.get("severity", "info")
        if s in by_sev:
            by_sev[s].append(f)

    lines = [
        "# MCPeek Security Report",
        "",
        "| Field | Value |",
        "|-------|-------|",
        f"| Target | `{scan.target}` |",
        f"| Type | {scan.target_type} |",
        f"| Risk Score | {risk}/100 ({_risk_label(risk)}) |",
        f"| Trust Score | {trust}/100 ({trust_label}) |",
        f"| Scan ID | {scan.id} |",
        f"| Files Analyzed | {meta.get('files_analyzed', 'N/A')} |",
        f"| URLs Checked | {meta.get('urls_checked', 'N/A')} |",
        f"| Dependencies | {meta.get('deps_analyzed', 'N/A')} |",
        "",
    ]

    # Findings summary
    total = len(findings)
    lines.append(f"## Findings ({total})")
    lines.append("")
    for sev in ["critical", "high", "medium", "low", "info"]:
        c = len(by_sev[sev])
        if c:
            lines.append(f"- **{sev.upper()}:** {c}")
    lines.append("")

    # Findings detail
    for sev in ["critical", "high", "medium", "low", "info"]:
        for f in by_sev[sev]:
            lines.append(f"### [{f['severity'].upper()}] {f['title']}")
            lines.append("")
            lines.append(f"{f['description']}")
            if f.get("evidence"):
                lines.append(f"\n> Evidence: `{f['evidence'][:200]}`")
            if f.get("remediation"):
                lines.append(f"\n**Remediation:** {f['remediation']}")
            lines.append("")

    # Recommendations
    recs = _build_recommendations(findings, risk, trust)
    lines.append("## Recommendations")
    lines.append("")
    for i, r in enumerate(recs, 1):
        lines.append(f"{i}. {r}")
    lines.append("")

    # Attack simulation
    attacks = _generate_attack_scenarios(findings)
    if attacks:
        lines.append("## Attack Simulation")
        lines.append("")
        for a in attacks:
            lines.append(f"### {a['finding']}")
            lines.append(f"**Severity:** {a['severity']}  ")
            lines.append(f"**Attack Vector:** {a['attack_vector']}")
            lines.append("")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Scan history + stats
# ---------------------------------------------------------------------------

@router.get("/scans", response_model=ScanListResponse)
async def list_scans(
    page: int = Query(1, ge=1),
    limit: int = Query(20, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
):
    offset = (page - 1) * limit

    total_result = await db.execute(select(func.count(Scan.id)))
    total = total_result.scalar() or 0

    result = await db.execute(
        select(Scan).order_by(Scan.created_at.desc()).offset(offset).limit(limit)
    )
    scans = result.scalars().all()

    return ScanListResponse(
        scans=[
            ScanListItem(
                scan_id=s.id, target=s.target, target_type=s.target_type,
                status=s.status, overall_risk=s.overall_risk, risk_level=s.risk_level,
                created_at=s.created_at.isoformat() if s.created_at else None,
            )
            for s in scans
        ],
        total=total, page=page, limit=limit,
    )


@router.get("/health")
async def health():
    return {"status": "ok", "service": "mcpeek"}


@router.get("/stats", response_model=StatsResponse)
async def stats(db: AsyncSession = Depends(get_db)):
    total_result = await db.execute(select(func.count(Scan.id)))
    total = total_result.scalar() or 0

    risk_result = await db.execute(
        select(Scan.risk_level, func.count(Scan.id)).group_by(Scan.risk_level)
    )
    risk_dist = {row[0]: row[1] for row in risk_result.all()}

    recent_result = await db.execute(
        select(Scan).order_by(Scan.created_at.desc()).limit(5)
    )
    recent = recent_result.scalars().all()

    return StatsResponse(
        total_scans=total,
        risk_distribution=risk_dist,
        recent_scans=[
            ScanListItem(
                scan_id=s.id, target=s.target, target_type=s.target_type,
                status=s.status, overall_risk=s.overall_risk, risk_level=s.risk_level,
                created_at=s.created_at.isoformat() if s.created_at else None,
            )
            for s in recent
        ],
    )
