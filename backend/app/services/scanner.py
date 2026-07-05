import json
import logging
import time

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models import Finding, Scan
from ..schemas import FindingCreate, ScanRequest, TargetType
from .content_hash import compare_hashes, hash_external_urls, hashes_from_json
from .mcp_scanner import scan_mcp_server
from .package_scanner import scan_package
from .risk_scorer import build_summary, calculate_risk
from .skill_scanner import scan_skill
from .ai_analyzer import run_ai_analysis
from ..config import settings

logger = logging.getLogger(__name__)


async def run_scan(scan_id: str, request: ScanRequest, db: AsyncSession) -> None:
    start = time.monotonic()

    try:
        # Update status to running
        result = await db.execute(select(Scan).where(Scan.id == scan_id))
        scan = result.scalar_one()
        scan.status = "running"
        await db.commit()

        # Run appropriate scanner
        all_findings: list[FindingCreate] = []
        metadata: dict = {"files_analyzed": 0, "urls_checked": 0, "deps_analyzed": 0}
        content_hashes: dict[str, str] = {}

        # Inline pasted scans do not store the original content. For re-scans,
        # the inline_content is now stored in the DB and passed via the request,
        # so we can re-run the full scan and compare hashes afterwards.

        if request.target_type == TargetType.MCP_SERVER:
            findings, meta = await scan_mcp_server(
                request.target, deep=request.options.deep, timeout=request.options.timeout,
                inline_content=request.options.inline_content,
            )
            all_findings.extend(findings)
            _merge_metadata(metadata, meta)

        elif request.target_type == TargetType.AGENT_SKILL:
            findings, meta = await scan_skill(
                request.target, deep=request.options.deep, timeout=request.options.timeout,
                inline_content=request.options.inline_content,
            )
            all_findings.extend(findings)
            _merge_metadata(metadata, meta)

        elif request.target_type in (TargetType.NPM_PACKAGE, TargetType.PYPI_PACKAGE):
            findings, meta = await scan_package(
                request.target,
                request.target_type.value,
                deep=request.options.deep,
                timeout=request.options.timeout,
            )
            all_findings.extend(findings)
            _merge_metadata(metadata, meta)

        # --- Re-scan comparison ---
        content_hashes = meta.get("content_hashes", {})
        if request.rescan_of and content_hashes:
            prev_result = await db.execute(select(Scan).where(Scan.id == request.rescan_of))
            prev_scan = prev_result.scalar_one_or_none()
            if prev_scan:
                old_hashes = hashes_from_json(prev_scan.content_hashes_json or "{}")
                changes = _append_hash_change_findings(all_findings, old_hashes, content_hashes)
                if changes:
                    # Escalate risk if content changed
                    metadata["content_changed"] = True
                    metadata["changed_urls"] = [c["url"] for c in changes]

        # Calculate risk
        overall_risk, risk_level = calculate_risk(all_findings)
        summary = build_summary(all_findings)

        # Run AI analysis if API key provided (user key or backend key)
        ai_results = {}
        ai_key = (request.options.ai_api_key if request.options else None) or settings.OPENROUTER_API_KEY
        if ai_key:
            findings_dicts = [
                {
                    "category": f.category,
                    "severity": f.severity,
                    "title": f.title,
                    "description": f.description,
                    "remediation": f.remediation,
                }
                for f in all_findings
            ]
            ai_results = await run_ai_analysis(
                findings=findings_dicts,
                target=request.target,
                target_type=request.target_type.value,
                risk_score=overall_risk,
                trust_score=summary.get("trust_score", 100),
                api_key=ai_key,
                model=request.options.ai_model if request.options and request.options.ai_model else "openai/gpt-oss-20b:free",
            )

        duration_ms = int((time.monotonic() - start) * 1000)

        # Save findings to DB
        for f in all_findings:
            db_finding = Finding(
                scan_id=scan_id,
                category=f.category,
                severity=f.severity,
                title=f.title,
                description=f.description,
                evidence=f.evidence,
                remediation=f.remediation,
                cwe=f.cwe,
                owasp=f.owasp,
                references_json=json.dumps(f.references),
            )
            db.add(db_finding)

        # Update scan
        from .content_hash import hashes_to_json
        scan.status = "completed"
        scan.overall_risk = overall_risk
        scan.risk_level = risk_level
        scan.summary_json = json.dumps(summary)
        scan.scan_duration_ms = duration_ms
        scan.files_analyzed = metadata.get("files_analyzed", 0)
        scan.urls_checked = metadata.get("urls_checked", 0)
        scan.deps_analyzed = metadata.get("deps_analyzed", 0)
        scan.content_hashes_json = hashes_to_json(content_hashes) if content_hashes else "{}"
        scan.ai_json = json.dumps(ai_results) if ai_results else "{}"
        if request.rescan_of:
            scan.rescan_of = request.rescan_of

        await db.commit()

    except Exception as e:
        logger.exception("Scan %s failed", scan_id)
        duration_ms = int((time.monotonic() - start) * 1000)
        try:
            result = await db.execute(select(Scan).where(Scan.id == scan_id))
            scan = result.scalar_one()
            scan.status = "failed"
            scan.error_message = f"{type(e).__name__}: scan failed"
            scan.scan_duration_ms = duration_ms
            await db.commit()
        except Exception:
            await db.rollback()


def _merge_metadata(target: dict, source: dict) -> None:
    for key in ("files_analyzed", "urls_checked", "deps_analyzed"):
        target[key] = target.get(key, 0) + source.get(key, 0)
    # Preserve content hashes and dependency risk score
    if "content_hashes" in source:
        target["content_hashes"] = source["content_hashes"]
    if "dependency_risk_score" in source:
        target["dependency_risk_score"] = source["dependency_risk_score"]


def _append_hash_change_findings(
    findings: list[FindingCreate], old_hashes: dict[str, str], new_hashes: dict[str, str]
) -> list[dict]:
    changes = compare_hashes(old_hashes, new_hashes)
    for change in changes:
        sev = "critical" if change["status"] == "changed" else "high"
        old_hash = change.get("old_hash") or "N/A"
        new_hash = change.get("new_hash") or "N/A"
        findings.append(FindingCreate(
            category="supply_chain",
            severity=sev,
            title=f"External URL content changed: {change['status']}",
            description=(
                f"URL {change['url']} has {change['status']} since the previous scan. "
                "This is a strong indicator of a bait-and-switch attack."
            ),
            evidence=(
                f"URL: {change['url']}\nStatus: {change['status']}\n"
                f"Old hash: {old_hash[:16]}...\nNew hash: {new_hash[:16]}..."
            ),
            remediation="Review the URL content immediately. If this skill was approved, revoke access.",
            cwe="CWE-345",
        ))
    return changes
