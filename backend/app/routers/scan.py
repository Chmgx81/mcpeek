import json
import logging
import uuid
from datetime import datetime, timezone, timedelta
from urllib.parse import urlparse

from fastapi import APIRouter, BackgroundTasks, HTTPException, Query, Request
from slowapi import Limiter
from slowapi.util import get_remote_address

from ..config import settings
from ..database import fetch_one, fetch_all, fetch_val, execute
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
from ..services.content_hash import compare_hashes, hashes_from_json
from ..services.url_safety import is_blocked_host

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1")
limiter = Limiter(key_func=get_remote_address)


# ---------------------------------------------------------------------------
# URL validation (SSRF protection)
# ---------------------------------------------------------------------------

def _validate_target(target: str, target_type: str) -> None:
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
        if not settings.ALLOW_PRIVATE_NETWORK_SCANS and is_blocked_host(hostname):
            raise HTTPException(
                status_code=400,
                detail=f"Scanning private/reserved network targets is not allowed: {hostname}",
            )


# ---------------------------------------------------------------------------
# Submit scan
# ---------------------------------------------------------------------------

@router.post("/scan")
@limiter.limit(f"{settings.RATE_LIMIT_PER_MINUTE}/minute")
async def submit_scan(request: Request, scan_req: ScanRequest, background_tasks: BackgroundTasks):
    _validate_target(scan_req.target, scan_req.target_type.value)

    scan_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()
    inline_content = scan_req.options.inline_content if scan_req.options else None

    await execute(
        "INSERT INTO scans (id, target, target_type, status, inline_content, created_at) VALUES (?, ?, ?, 'pending', ?, ?)",
        [scan_id, scan_req.target, scan_req.target_type.value, inline_content, now],
    )

    background_tasks.add_task(_run_scan_task, scan_id, scan_req)

    return {"scan_id": scan_id, "status": "pending"}


async def _run_scan_task(scan_id: str, request: ScanRequest) -> None:
    max_retries = 2
    for attempt in range(max_retries + 1):
        try:
            await run_scan(scan_id, request)
            return
        except Exception:
            if attempt < max_retries:
                logger.warning("Scan %s attempt %d failed, retrying...", scan_id, attempt + 1)
                import asyncio
                await asyncio.sleep(2 ** attempt)
            else:
                logger.exception("Scan %s failed after %d attempts", scan_id, max_retries + 1)
                try:
                    await execute(
                        "UPDATE scans SET status = 'failed', error_message = ? WHERE id = ? AND status != 'completed'",
                        ["Scan failed after retries", scan_id],
                    )
                except Exception:
                    logger.exception("Failed to mark scan %s as failed", scan_id)


# ---------------------------------------------------------------------------
# Delete scan
# ---------------------------------------------------------------------------

@router.delete("/scan/{scan_id}")
async def delete_scan(scan_id: str):
    row = await fetch_one("SELECT id FROM scans WHERE id = ?", [scan_id])
    if not row:
        raise HTTPException(status_code=404, detail="Scan not found")

    await execute("DELETE FROM findings WHERE scan_id = ?", [scan_id])
    await execute("DELETE FROM scans WHERE id = ?", [scan_id])

    return {"deleted": True, "scan_id": scan_id}


# ---------------------------------------------------------------------------
# Get scan
# ---------------------------------------------------------------------------

def _parse_findings(rows: list[dict]) -> list[FindingResponse]:
    return [
        FindingResponse(
            id=f["id"], category=f["category"], severity=f["severity"],
            title=f["title"], description=f["description"], evidence=f["evidence"],
            remediation=f["remediation"], cwe=f.get("cwe"), owasp=f.get("owasp"),
            references=json.loads(f["references_json"]) if f.get("references_json") else [],
        )
        for f in rows
    ]


def _finding_dicts(rows: list[dict]) -> list[dict]:
    return [
        {
            "id": f["id"], "category": f["category"], "severity": f["severity"],
            "title": f["title"], "description": f["description"],
            "evidence": f["evidence"], "remediation": f["remediation"],
            "cwe": f.get("cwe"), "owasp": f.get("owasp"),
            "references": json.loads(f["references_json"]) if f.get("references_json") else [],
        }
        for f in rows
    ]


def _meta(scan: dict) -> dict:
    return {
        "scan_duration_ms": scan.get("scan_duration_ms", 0),
        "files_analyzed": scan.get("files_analyzed", 0),
        "urls_checked": scan.get("urls_checked", 0),
        "deps_analyzed": scan.get("deps_analyzed", 0),
    }


def _content_changed(scan: dict, previous_scan: dict | None) -> bool:
    if not scan.get("rescan_of") or previous_scan is None:
        return False
    old_hashes = hashes_from_json(previous_scan.get("content_hashes_json") or "{}")
    new_hashes = hashes_from_json(scan.get("content_hashes_json") or "{}")
    return bool(compare_hashes(old_hashes, new_hashes))


@router.get("/scan/{scan_id}", response_model=ScanResponse)
async def get_scan(scan_id: str):
    scan = await fetch_one("SELECT * FROM scans WHERE id = ?", [scan_id])
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    findings_rows = await fetch_all(
        """SELECT * FROM findings WHERE scan_id = ?
        ORDER BY CASE severity
            WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2
            WHEN 'low' THEN 3 WHEN 'info' THEN 4 ELSE 5 END""",
        [scan_id],
    )

    previous_scan = None
    if scan.get("rescan_of"):
        previous_scan = await fetch_one("SELECT * FROM scans WHERE id = ?", [scan["rescan_of"]])

    ai_data = {}
    if scan.get("ai_json"):
        try:
            ai_data = json.loads(scan["ai_json"])
        except (json.JSONDecodeError, TypeError):
            ai_data = {}

    return ScanResponse(
        scan_id=scan["id"],
        status=scan["status"],
        target=scan["target"],
        target_type=scan["target_type"],
        overall_risk=scan["overall_risk"],
        risk_level=scan["risk_level"],
        summary=json.loads(scan.get("summary_json") or "{}"),
        findings=_parse_findings(findings_rows),
        metadata=_meta(scan),
        created_at=scan.get("created_at"),
        error_message=scan.get("error_message"),
        content_changed=_content_changed(scan, previous_scan),
        rescan_of=scan.get("rescan_of"),
        ai_attack_scenarios=ai_data.get("ai_attack_scenarios", []),
        ai_remediation=ai_data.get("ai_remediation", []),
        ai_narrative=ai_data.get("ai_narrative", {}),
        ai_threat_intel=ai_data.get("ai_threat_intel", []),
    )


# ---------------------------------------------------------------------------
# Re-scan
# ---------------------------------------------------------------------------

@router.post("/scan/{scan_id}/rescan")
@limiter.limit(f"{settings.RATE_LIMIT_PER_MINUTE}/minute")
async def rescan_scan(request: Request, scan_id: str, background_tasks: BackgroundTasks):
    prev_scan = await fetch_one("SELECT * FROM scans WHERE id = ?", [scan_id])
    if not prev_scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if prev_scan["status"] not in ("completed", "failed"):
        raise HTTPException(status_code=400, detail="Previous scan is still in progress")

    from ..schemas import ScanOptions
    new_req = ScanRequest(
        target_type=prev_scan["target_type"],
        target=prev_scan["target"],
        options=ScanOptions(deep=True, inline_content=prev_scan.get("inline_content")),
        rescan_of=scan_id,
    )

    new_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()
    await execute(
        "INSERT INTO scans (id, target, target_type, status, rescan_of, created_at) VALUES (?, ?, ?, 'pending', ?, ?)",
        [new_id, prev_scan["target"], prev_scan["target_type"], scan_id, now],
    )

    background_tasks.add_task(_run_scan_task, new_id, new_req)

    return {"scan_id": new_id, "status": "pending", "rescan_of": scan_id}


# ---------------------------------------------------------------------------
# Content change comparison
# ---------------------------------------------------------------------------

@router.get("/scan/{scan_id}/changes")
async def get_content_changes(scan_id: str):
    scan = await fetch_one("SELECT * FROM scans WHERE id = ?", [scan_id])
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if not scan.get("rescan_of"):
        raise HTTPException(status_code=400, detail="This scan is not a re-scan")

    new_hashes = hashes_from_json(scan.get("content_hashes_json") or "{}")
    prev_scan = await fetch_one("SELECT * FROM scans WHERE id = ?", [scan["rescan_of"]])
    if not prev_scan:
        raise HTTPException(status_code=404, detail="Previous scan not found")

    old_hashes = hashes_from_json(prev_scan.get("content_hashes_json") or "{}")
    changes = compare_hashes(old_hashes, new_hashes)

    return {
        "scan_id": scan_id,
        "rescan_of": scan["rescan_of"],
        "changes": changes,
        "total_changes": len(changes),
        "has_changes": len(changes) > 0,
    }


# ---------------------------------------------------------------------------
# Report (structured)
# ---------------------------------------------------------------------------

@router.get("/report/{scan_id}", response_model=ReportResponse)
async def get_report(scan_id: str):
    scan = await fetch_one("SELECT * FROM scans WHERE id = ?", [scan_id])
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    findings_rows = await fetch_all(
        """SELECT * FROM findings WHERE scan_id = ?
        ORDER BY CASE severity
            WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2
            WHEN 'low' THEN 3 WHEN 'info' THEN 4 ELSE 5 END""",
        [scan_id],
    )

    def _group(findings: list[dict]) -> dict[str, list[FindingResponse]]:
        groups: dict[str, list[FindingResponse]] = {
            "critical": [], "high": [], "medium": [], "low": [], "info": [],
        }
        for f in findings:
            fr = FindingResponse(
                id=f["id"], category=f["category"], severity=f["severity"],
                title=f["title"], description=f["description"], evidence=f["evidence"],
                remediation=f["remediation"], cwe=f.get("cwe"), owasp=f.get("owasp"),
                references=json.loads(f["references_json"]) if f.get("references_json") else [],
            )
            if f["severity"] in groups:
                groups[f["severity"]].append(fr)
        return groups

    return ReportResponse(
        scan_id=scan["id"],
        target=scan["target"],
        target_type=scan["target_type"],
        status=scan["status"],
        overall_risk=scan["overall_risk"],
        risk_level=scan["risk_level"],
        summary=json.loads(scan.get("summary_json") or "{}"),
        findings=_group(findings_rows),
        total_findings=len(findings_rows),
        metadata=_meta(scan),
        created_at=scan.get("created_at"),
        error_message=scan.get("error_message"),
    )


# ---------------------------------------------------------------------------
# Full report
# ---------------------------------------------------------------------------

@router.get("/report/{scan_id}/full")
async def get_full_report(scan_id: str):
    scan = await fetch_one("SELECT * FROM scans WHERE id = ?", [scan_id])
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    findings_rows = await fetch_all(
        """SELECT * FROM findings WHERE scan_id = ?
        ORDER BY CASE severity
            WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2
            WHEN 'low' THEN 3 WHEN 'info' THEN 4 ELSE 5 END""",
        [scan_id],
    )

    from ..services.report_generator import generate_report

    return generate_report(
        scan_id=scan["id"],
        target=scan["target"],
        target_type=scan["target_type"],
        status=scan["status"],
        risk_score=scan["overall_risk"],
        findings=_finding_dicts(findings_rows),
        metadata=_meta(scan),
        created_at=scan.get("created_at"),
    )


# ---------------------------------------------------------------------------
# Report export
# ---------------------------------------------------------------------------

@router.get("/report/{scan_id}/export")
async def export_report(
    scan_id: str,
    fmt: str = Query("json", alias="format", pattern="^(json|text|markdown)$"),
):
    scan = await fetch_one("SELECT * FROM scans WHERE id = ?", [scan_id])
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    findings_rows = await fetch_all(
        """SELECT * FROM findings WHERE scan_id = ?
        ORDER BY CASE severity
            WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2
            WHEN 'low' THEN 3 WHEN 'info' THEN 4 ELSE 5 END""",
        [scan_id],
    )
    meta = _meta(scan)
    fdicts = _finding_dicts(findings_rows)

    from ..services.report_generator import (
        build_json_report,
        build_security_summary,
        _compute_trust_score,
        _trust_label,
    )

    if fmt == "json":
        return build_json_report(
            scan_id=scan["id"], target=scan["target"], target_type=scan["target_type"],
            status=scan["status"], risk_score=scan["overall_risk"],
            findings=fdicts, metadata=meta,
            created_at=scan.get("created_at"),
        )

    trust = _compute_trust_score(fdicts)

    if fmt == "markdown":
        return {"format": "markdown", "content": _to_markdown(scan, fdicts, meta, trust, trust_label=_trust_label(trust))}

    return {"format": "text", "content": build_security_summary(
        scan["target"], scan["target_type"], scan["overall_risk"], trust,
        fdicts, meta,
    )}


def _to_markdown(scan, findings, meta, trust, trust_label):
    from ..services.report_generator import _risk_label, _generate_attack_scenarios, _build_recommendations

    risk = scan["overall_risk"]
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
        f"| Target | `{scan['target']}` |",
        f"| Type | {scan['target_type']} |",
        f"| Risk Score | {risk}/100 ({_risk_label(risk)}) |",
        f"| Trust Score | {trust}/100 ({trust_label}) |",
        f"| Scan ID | {scan['id']} |",
        f"| Files Analyzed | {meta.get('files_analyzed', 'N/A')} |",
        f"| URLs Checked | {meta.get('urls_checked', 'N/A')} |",
        f"| Dependencies | {meta.get('deps_analyzed', 'N/A')} |",
        "",
    ]

    total = len(findings)
    lines.append(f"## Findings ({total})")
    lines.append("")
    for sev in ["critical", "high", "medium", "low", "info"]:
        c = len(by_sev[sev])
        if c:
            lines.append(f"- **{sev.upper()}:** {c}")
    lines.append("")

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

    recs = _build_recommendations(findings, risk, trust)
    lines.append("## Recommendations")
    lines.append("")
    for i, r in enumerate(recs, 1):
        lines.append(f"{i}. {r}")
    lines.append("")

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
):
    offset = (page - 1) * limit

    total = await fetch_val("SELECT COUNT(*) FROM scans")

    rows = await fetch_all(
        "SELECT * FROM scans ORDER BY created_at DESC LIMIT ? OFFSET ?",
        [limit, offset],
    )

    return ScanListResponse(
        scans=[
            ScanListItem(
                scan_id=s["id"], target=s["target"], target_type=s["target_type"],
                status=s["status"], overall_risk=s["overall_risk"], risk_level=s["risk_level"],
                created_at=s.get("created_at"),
            )
            for s in rows
        ],
        total=total or 0, page=page, limit=limit,
    )


@router.get("/stats", response_model=StatsResponse)
async def stats():
    total = await fetch_val("SELECT COUNT(*) FROM scans")

    risk_rows = await fetch_all("SELECT risk_level, COUNT(*) as cnt FROM scans GROUP BY risk_level")
    risk_dist = {row["risk_level"]: row["cnt"] for row in risk_rows}

    recent = await fetch_all("SELECT * FROM scans ORDER BY created_at DESC LIMIT 5")

    return StatsResponse(
        total_scans=total or 0,
        risk_distribution=risk_dist,
        recent_scans=[
            ScanListItem(
                scan_id=s["id"], target=s["target"], target_type=s["target_type"],
                status=s["status"], overall_risk=s["overall_risk"], risk_level=s["risk_level"],
                created_at=s.get("created_at"),
            )
            for s in recent
        ],
    )
