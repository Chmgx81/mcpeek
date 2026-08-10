import json
import logging
import time
import uuid
from datetime import datetime, timezone

from ..database import fetch_one, execute
from ..schemas import FindingCreate, ScanRequest, TargetType
from .content_hash import compare_hashes, hashes_from_json
from .mcp_scanner import scan_mcp_server
from .package_scanner import scan_package
from .risk_scorer import build_summary, calculate_risk
from .skill_scanner import scan_skill
from .ai_analyzer import run_ai_analysis
from .ai_detector import detect_with_ai
from ..config import settings

logger = logging.getLogger(__name__)


async def run_scan(scan_id: str, request: ScanRequest) -> None:
    start = time.monotonic()

    try:
        await execute("UPDATE scans SET status = 'running' WHERE id = ?", [scan_id])

        all_findings: list[FindingCreate] = []
        metadata: dict = {"files_analyzed": 0, "urls_checked": 0, "deps_analyzed": 0}
        content_hashes: dict[str, str] = {}

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
        else:
            raise ValueError(f"Unsupported target type: {request.target_type}")

        content_hashes = meta.get("content_hashes", {})
        if request.rescan_of and content_hashes:
            prev_scan = await fetch_one("SELECT * FROM scans WHERE id = ?", [request.rescan_of])
            if prev_scan:
                old_hashes = hashes_from_json(prev_scan.get("content_hashes_json") or "{}")
                changes = _append_hash_change_findings(all_findings, old_hashes, content_hashes)
                if changes:
                    metadata["content_changed"] = True
                    metadata["changed_urls"] = [c["url"] for c in changes]

        # AI-native detection: validate, refine, and add to heuristic findings
        ai_key = settings.OPENROUTER_API_KEY
        ai_model = request.options.ai_model or "openai/gpt-oss-20b:free"
        if ai_key and request.options.ai_detect:
            try:
                raw_content = request.options.inline_content or ""
                all_findings = await detect_with_ai(
                    content=raw_content,
                    findings=all_findings,
                    target_type=request.target_type.value,
                    api_key=ai_key,
                    model=ai_model,
                )
                ai_findings = [f for f in all_findings if f.source == "ai_detected"]
                if ai_findings:
                    metadata["ai_findings_count"] = len(ai_findings)
            except Exception:
                logger.warning("AI detection failed, falling back to heuristics only")

        overall_risk, risk_level = calculate_risk(all_findings)
        summary = build_summary(all_findings)

        ai_results = {}
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

        # Insert findings
        for f in all_findings:
            finding_id = str(uuid.uuid4())
            await execute(
                """INSERT INTO findings (id, scan_id, category, severity, title, description, evidence, remediation, cwe, owasp, references_json, source)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                [finding_id, scan_id, f.category, f.severity, f.title, f.description,
                 f.evidence, f.remediation, f.cwe, f.owasp, json.dumps(f.references), getattr(f, "source", "heuristic")],
            )

        # Update scan
        from .content_hash import hashes_to_json
        await execute(
            """UPDATE scans SET
                status = 'completed',
                overall_risk = ?,
                risk_level = ?,
                summary_json = ?,
                scan_duration_ms = ?,
                files_analyzed = ?,
                urls_checked = ?,
                deps_analyzed = ?,
                content_hashes_json = ?,
                ai_json = ?,
                rescan_of = COALESCE(rescan_of, ?)
            WHERE id = ?""",
            [overall_risk, risk_level, json.dumps(summary), duration_ms,
             metadata.get("files_analyzed", 0), metadata.get("urls_checked", 0),
             metadata.get("deps_analyzed", 0),
             hashes_to_json(content_hashes) if content_hashes else "{}",
             json.dumps(ai_results) if ai_results else "{}",
             request.rescan_of, scan_id],
        )

    except Exception as e:
        logger.exception("Scan %s failed", scan_id)
        duration_ms = int((time.monotonic() - start) * 1000)
        try:
            await execute(
                "UPDATE scans SET status = 'failed', error_message = ?, scan_duration_ms = ? WHERE id = ?",
                [f"{type(e).__name__}: scan failed", duration_ms, scan_id],
            )
        except Exception:
            pass


def _merge_metadata(target: dict, source: dict) -> None:
    for key in ("files_analyzed", "urls_checked", "deps_analyzed"):
        target[key] = target.get(key, 0) + source.get(key, 0)
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
