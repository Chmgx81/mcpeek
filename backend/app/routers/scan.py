import json
import logging
import uuid
from datetime import datetime, timezone, timedelta
from urllib.parse import urlparse

from fastapi import APIRouter, BackgroundTasks, HTTPException, Query, Request
from slowapi import Limiter
from slowapi.util import get_remote_address

from ..auth import create_workspace, require_admin, resolve_workspace
from ..config import settings
from ..database import fetch_one, fetch_all, fetch_val, execute, record_audit_event
from ..schemas import (
    AuditEvent,
    AuditEventListResponse,
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


def _request_context(request: Request) -> dict[str, str]:
    request_id = request.headers.get("x-request-id") or str(uuid.uuid4())
    forwarded_for = request.headers.get("x-forwarded-for", "").split(",")[0].strip()
    client_ip = forwarded_for or (request.client.host if request.client else "unknown")
    user_agent = (request.headers.get("user-agent") or "").strip()
    return {
        "request_id": request_id,
        "client_ip": client_ip,
        "user_agent": user_agent[:512],
    }


def _public_scan_error(request_id: str) -> str:
    return f"Scan failed. Reference request_id={request_id} when contacting support."


def _decode_details(value: str | None) -> dict[str, object]:
    if not value:
        return {}
    try:
        decoded = json.loads(value)
        return decoded if isinstance(decoded, dict) else {}
    except (json.JSONDecodeError, TypeError):
        return {}


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
    context = _request_context(request)
    workspace = await resolve_workspace(request)

    scan_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()
    inline_content = scan_req.options.inline_content if scan_req.options else None

    await execute(
        "INSERT INTO scans (id, workspace_id, target, target_type, status, inline_content, request_id, client_ip, user_agent, created_at) VALUES (?, ?, ?, ?, 'pending', ?, ?, ?, ?, ?)",
        [scan_id, workspace.workspace_id, scan_req.target, scan_req.target_type.value, inline_content, context["request_id"], context["client_ip"], context["user_agent"], now],
    )
    await record_audit_event(
        "scan_submitted",
        scan_id=scan_id,
        workspace_id=workspace.workspace_id,
        target=scan_req.target,
        request_id=context["request_id"],
        client_ip=context["client_ip"],
        user_agent=context["user_agent"],
        details={"target_type": scan_req.target_type.value},
    )
    # For Vercel Hobby plan (60s limit), run scan inline with timeout
    # Client should use inline_content for configs to avoid timeouts
    import asyncio
    try:
        await asyncio.wait_for(run_scan(scan_id, scan_req), timeout=55.0)
        return {"scan_id": scan_id, "status": "completed", "request_id": context["request_id"]}
    except asyncio.TimeoutError:
        logger.warning("Scan %s timed out inline, marking as failed (request_id=%s)", scan_id, context["request_id"])
        try:
            await execute(
                "UPDATE scans SET status = 'failed', error_message = ? WHERE id = ?",
                ["Scan timed out (Vercel 60s limit)", scan_id],
            )
        except Exception:
            pass
        await record_audit_event(
            "scan_failed",
            scan_id=scan_id,
            workspace_id=workspace.workspace_id,
            target=scan_req.target,
            request_id=context["request_id"],
            client_ip=context["client_ip"],
            user_agent=context["user_agent"],
            details={"reason": "timeout"},
        )
        return {
            "scan_id": scan_id,
            "status": "failed",
            "error": _public_scan_error(context["request_id"]),
            "request_id": context["request_id"],
        }
    except Exception as e:
        logger.exception("Scan %s failed (request_id=%s)", scan_id, context["request_id"])
        try:
            await execute(
                "UPDATE scans SET status = 'failed', error_message = ? WHERE id = ?",
                [f"{type(e).__name__}: scan failed", scan_id],
            )
        except Exception:
            pass
        await record_audit_event(
            "scan_failed",
            scan_id=scan_id,
            workspace_id=workspace.workspace_id,
            target=scan_req.target,
            request_id=context["request_id"],
            client_ip=context["client_ip"],
            user_agent=context["user_agent"],
            details={"reason": type(e).__name__},
        )
        return {
            "scan_id": scan_id,
            "status": "failed",
            "error": _public_scan_error(context["request_id"]),
            "request_id": context["request_id"],
        }


async def _run_scan_task(scan_id: str, request: ScanRequest) -> None:
    import asyncio
    scan = await fetch_one("SELECT target, request_id, client_ip, user_agent, workspace_id FROM scans WHERE id = ?", [scan_id])
    max_retries = 2
    for attempt in range(max_retries + 1):
        try:
            # Add timeout to prevent Vercel 60s limit
            await asyncio.wait_for(run_scan(scan_id, request), timeout=55.0)
            return
        except asyncio.TimeoutError:
            logger.warning("Scan %s timed out after 55s", scan_id)
            try:
                await execute(
                    "UPDATE scans SET status = 'failed', error_message = ? WHERE id = ? AND status != 'completed'",
                    ["Scan timed out", scan_id],
                )
            except Exception:
                pass
            if scan:
                await record_audit_event(
                    "scan_failed",
                    scan_id=scan_id,
                    workspace_id=scan.get("workspace_id"),
                    target=scan.get("target"),
                    request_id=scan.get("request_id"),
                    client_ip=scan.get("client_ip"),
                    user_agent=scan.get("user_agent"),
                    details={"reason": "timeout"},
                )
            return
        except Exception:
            if attempt < max_retries:
                logger.warning("Scan %s attempt %d failed, retrying...", scan_id, attempt + 1)
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
                if scan:
                    await record_audit_event(
                        "scan_failed",
                        scan_id=scan_id,
                        workspace_id=scan.get("workspace_id"),
                        target=scan.get("target"),
                        request_id=scan.get("request_id"),
                        client_ip=scan.get("client_ip"),
                        user_agent=scan.get("user_agent"),
                        details={"reason": "retries_exhausted"},
                    )


# ---------------------------------------------------------------------------
# Delete scan
# ---------------------------------------------------------------------------

@router.delete("/scan/{scan_id}")
async def delete_scan(request: Request, scan_id: str):
    row = await fetch_one("SELECT id, workspace_id FROM scans WHERE id = ?", [scan_id])
    if not row:
        raise HTTPException(status_code=404, detail="Scan not found")
    workspace = await resolve_workspace(request)
    if row.get("workspace_id") != workspace.workspace_id:
        raise HTTPException(status_code=403, detail="Forbidden")

    scan = await fetch_one("SELECT target, request_id, client_ip, user_agent, workspace_id FROM scans WHERE id = ?", [scan_id])

    await execute("DELETE FROM findings WHERE scan_id = ?", [scan_id])
    await execute("DELETE FROM scans WHERE id = ?", [scan_id])

    if scan:
        await record_audit_event(
            "scan_deleted",
            scan_id=scan_id,
            workspace_id=scan.get("workspace_id"),
            target=scan.get("target"),
            request_id=scan.get("request_id"),
            client_ip=scan.get("client_ip"),
            user_agent=scan.get("user_agent"),
        )

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
            source=f.get("source", "heuristic"),
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
            "source": f.get("source", "heuristic"),
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
async def get_scan(request: Request, scan_id: str):
    workspace = await resolve_workspace(request)
    scan = await fetch_one("SELECT * FROM scans WHERE id = ?", [scan_id])
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan.get("workspace_id") != workspace.workspace_id:
        raise HTTPException(status_code=403, detail="Forbidden")

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
        request_id=scan.get("request_id"),
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
    context = _request_context(request)
    workspace = await resolve_workspace(request)
    prev_scan = await fetch_one("SELECT * FROM scans WHERE id = ?", [scan_id])
    if not prev_scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if prev_scan.get("workspace_id") != workspace.workspace_id:
        raise HTTPException(status_code=403, detail="Forbidden")
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
        "INSERT INTO scans (id, workspace_id, target, target_type, status, rescan_of, request_id, client_ip, user_agent, created_at) VALUES (?, ?, ?, ?, 'pending', ?, ?, ?, ?, ?)",
        [new_id, workspace.workspace_id, prev_scan["target"], prev_scan["target_type"], scan_id, context["request_id"], context["client_ip"], context["user_agent"], now],
    )

    await record_audit_event(
        "scan_rescan_requested",
        scan_id=new_id,
        workspace_id=workspace.workspace_id,
        target=prev_scan["target"],
        request_id=context["request_id"],
        client_ip=context["client_ip"],
        user_agent=context["user_agent"],
        details={"rescan_of": scan_id},
    )

    background_tasks.add_task(_run_scan_task, new_id, new_req)

    return {"scan_id": new_id, "status": "pending", "rescan_of": scan_id, "request_id": context["request_id"]}


# ---------------------------------------------------------------------------
# Content change comparison
# ---------------------------------------------------------------------------

@router.get("/scan/{scan_id}/changes")
async def get_content_changes(request: Request, scan_id: str):
    workspace = await resolve_workspace(request)
    scan = await fetch_one("SELECT * FROM scans WHERE id = ?", [scan_id])
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan.get("workspace_id") != workspace.workspace_id:
        raise HTTPException(status_code=403, detail="Forbidden")
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
async def get_report(request: Request, scan_id: str):
    workspace = await resolve_workspace(request)
    scan = await fetch_one("SELECT * FROM scans WHERE id = ?", [scan_id])
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan.get("workspace_id") != workspace.workspace_id:
        raise HTTPException(status_code=403, detail="Forbidden")

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
                source=f.get("source", "heuristic"),
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
        request_id=scan.get("request_id"),
    )


# ---------------------------------------------------------------------------
# Full report
# ---------------------------------------------------------------------------

@router.get("/report/{scan_id}/full")
async def get_full_report(request: Request, scan_id: str):
    workspace = await resolve_workspace(request)
    scan = await fetch_one("SELECT * FROM scans WHERE id = ?", [scan_id])
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan.get("workspace_id") != workspace.workspace_id:
        raise HTTPException(status_code=403, detail="Forbidden")

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
    request: Request,
    scan_id: str,
    fmt: str = Query("json", alias="format", pattern="^(json|text|markdown)$"),
):
    workspace = await resolve_workspace(request)
    scan = await fetch_one("SELECT * FROM scans WHERE id = ?", [scan_id])
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan.get("workspace_id") != workspace.workspace_id:
        raise HTTPException(status_code=403, detail="Forbidden")

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
    request: Request,
    page: int = Query(1, ge=1),
    limit: int = Query(20, ge=1, le=100),
):
    workspace = await resolve_workspace(request)
    offset = (page - 1) * limit

    total = await fetch_val("SELECT COUNT(*) FROM scans WHERE workspace_id = ?", [workspace.workspace_id])

    rows = await fetch_all(
        "SELECT * FROM scans WHERE workspace_id = ? ORDER BY created_at DESC LIMIT ? OFFSET ?",
        [workspace.workspace_id, limit, offset],
    )

    return ScanListResponse(
        scans=[
            ScanListItem(
                scan_id=s["id"], target=s["target"], target_type=s["target_type"],
                status=s["status"], overall_risk=s["overall_risk"], risk_level=s["risk_level"],
                created_at=s.get("created_at"),
                request_id=s.get("request_id"),
            )
            for s in rows
        ],
        total=total or 0, page=page, limit=limit,
    )


@router.get("/stats", response_model=StatsResponse)
async def stats(request: Request):
    workspace = await resolve_workspace(request)
    total = await fetch_val("SELECT COUNT(*) FROM scans WHERE workspace_id = ?", [workspace.workspace_id])

    risk_rows = await fetch_all("SELECT risk_level, COUNT(*) as cnt FROM scans WHERE workspace_id = ? GROUP BY risk_level", [workspace.workspace_id])
    risk_dist = {row["risk_level"]: row["cnt"] for row in risk_rows}

    recent = await fetch_all("SELECT * FROM scans WHERE workspace_id = ? ORDER BY created_at DESC LIMIT 5", [workspace.workspace_id])

    return StatsResponse(
        total_scans=total or 0,
        risk_distribution=risk_dist,
        recent_scans=[
            ScanListItem(
                scan_id=s["id"], target=s["target"], target_type=s["target_type"],
                status=s["status"], overall_risk=s["overall_risk"], risk_level=s["risk_level"],
                created_at=s.get("created_at"),
                request_id=s.get("request_id"),
            )
            for s in recent
        ],
    )


@router.get("/audit/events", response_model=AuditEventListResponse)
async def audit_events(
    request: Request,
    page: int = Query(1, ge=1),
    limit: int = Query(25, ge=1, le=100),
):
    workspace = await resolve_workspace(request)
    offset = (page - 1) * limit
    total = await fetch_val("SELECT COUNT(*) FROM audit_events WHERE workspace_id = ?", [workspace.workspace_id])
    rows = await fetch_all(
        "SELECT * FROM audit_events WHERE workspace_id = ? ORDER BY created_at DESC LIMIT ? OFFSET ?",
        [workspace.workspace_id, limit, offset],
    )

    return AuditEventListResponse(
        events=[
            AuditEvent(
                id=row["id"],
                event_type=row["event_type"],
                scan_id=row.get("scan_id"),
                target=row.get("target"),
                request_id=row.get("request_id"),
                created_at=row.get("created_at"),
                details=_decode_details(row.get("details_json")),
            )
            for row in rows
        ],
        total=total or 0,
        page=page,
        limit=limit,
    )


@router.post("/admin/workspaces")
async def create_workspace_endpoint(request: Request, payload: dict[str, str]):
    await require_admin(request)
    name = (payload.get("name") or "").strip()
    if not name:
        raise HTTPException(status_code=400, detail="Workspace name is required")
    workspace_id, api_key, key_prefix = await create_workspace(name)
    return {
        "workspace_id": workspace_id,
        "workspace_name": name,
        "api_key": api_key,
        "api_key_prefix": key_prefix,
    }
