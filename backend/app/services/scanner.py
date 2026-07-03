import json
import time
import traceback

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models import Finding, Scan
from ..schemas import FindingCreate, ScanRequest, TargetType
from .mcp_scanner import scan_mcp_server
from .package_scanner import scan_package
from .risk_scorer import build_summary, calculate_risk
from .skill_scanner import scan_skill


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

        # Calculate risk
        overall_risk, risk_level = calculate_risk(all_findings)
        summary = build_summary(all_findings)
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
        scan.status = "completed"
        scan.overall_risk = overall_risk
        scan.risk_level = risk_level
        scan.summary_json = json.dumps(summary)
        scan.scan_duration_ms = duration_ms
        scan.files_analyzed = metadata.get("files_analyzed", 0)
        scan.urls_checked = metadata.get("urls_checked", 0)
        scan.deps_analyzed = metadata.get("deps_analyzed", 0)

        await db.commit()

    except Exception as e:
        duration_ms = int((time.monotonic() - start) * 1000)
        try:
            result = await db.execute(select(Scan).where(Scan.id == scan_id))
            scan = result.scalar_one()
            scan.status = "failed"
            scan.error_message = f"{type(e).__name__}: {e}\n{traceback.format_exc()[-500:]}"
            scan.scan_duration_ms = duration_ms
            await db.commit()
        except Exception:
            await db.rollback()


def _merge_metadata(target: dict, source: dict) -> None:
    for key in ("files_analyzed", "urls_checked", "deps_analyzed"):
        target[key] = target.get(key, 0) + source.get(key, 0)
