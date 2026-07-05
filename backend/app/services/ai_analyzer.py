"""AI-powered analysis using OpenRouter free models.

Generates:
  - Dynamic attack scenarios (context-specific, not templates)
  - Remediation suggestions (exact config/code changes)
  - Risk narrative (plain-English executive summary)
  - Threat intelligence (real-world CVE mapping)
"""

from __future__ import annotations

import json
import logging
from typing import Any

import httpx

from ..config import settings

logger = logging.getLogger(__name__)

OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"

# Free models on OpenRouter (no credit card needed)
FREE_MODELS = [
    "openai/gpt-oss-20b:free",
    "meta-llama/llama-3.3-70b-instruct:free",
    "qwen/qwen3-next-80b-a3b-instruct:free",
    "meta-llama/llama-3.2-3b-instruct:free",
    "google/gemma-2-9b-it:free",
]

DEFAULT_MODEL = FREE_MODELS[0]


def _build_attack_prompt(findings: list[dict], target: str, target_type: str) -> str:
    findings_text = "\n".join(
        f"- [{f['severity'].upper()}] {f['title']}: {f['description']}"
        for f in findings[:20]
    )
    return f"""You are a cybersecurity expert analyzing an MCP (Model Context Protocol) configuration.

Target: {target}
Type: {target_type}

Findings from automated scan:
{findings_text}

Based on these findings, generate 2-3 realistic attack scenarios. For each scenario:
1. A short title
2. The attack vector (how an attacker would exploit this)
3. The impact (what data/systems are at risk)
4. A concrete step-by-step exploitation path

Be specific to THIS configuration. Reference the actual findings. Do not use generic templates.

Return ONLY valid JSON array with this structure:
[
  {{
    "title": "Attack scenario title",
    "vector": "How the attack works",
    "impact": "What gets compromised",
    "steps": ["Step 1", "Step 2", "Step 3"],
    "severity": "critical|high|medium",
    "related_finding": "title of the finding it relates to"
  }}
]"""


def _build_remediation_prompt(findings: list[dict], target_type: str) -> str:
    findings_text = "\n".join(
        f"- [{f['severity'].upper()}] {f['title']}: {f.get('remediation', 'No remediation provided')}"
        for f in findings[:20]
    )
    return f"""You are a security engineer providing remediation for MCP configuration issues.

Findings and current remediation suggestions:
{findings_text}

For each finding, provide a SPECIFIC, actionable fix. Include:
1. The exact config change needed (JSON snippet or code)
2. Why this fix works
3. Any trade-offs or things to watch out for

Return ONLY valid JSON array:
[
  {{
    "finding_title": "Title of the finding being addressed",
    "fix": "Exact config/code change (JSON snippet or description)",
    "explanation": "Why this works",
    "tradeoffs": "What to watch out for (or 'None')"
  }}
]"""


def _build_narrative_prompt(findings: list[dict], risk_score: int, trust_score: int, target: str) -> str:
    critical = sum(1 for f in findings if f.get("severity") == "critical")
    high = sum(1 for f in findings if f.get("severity") == "high")
    medium = sum(1 for f in findings if f.get("severity") == "medium")

    return f"""You are a security analyst writing an executive summary for a non-technical stakeholder.

Scan target: {target}
Risk score: {risk_score}/100
Trust score: {trust_score}/100
Critical findings: {critical}
High findings: {high}
Medium findings: {medium}

Write a 2-3 sentence executive summary that:
1. States the overall risk in plain English
2. Highlights the most critical issues without jargon
3. Gives a clear recommendation (approve/reject/fix-then-approve)

Be direct and actionable. No security buzzwords. Write at a 10th-grade reading level.

Return ONLY valid JSON:
{{
  "summary": "Your executive summary text here",
  "verdict": "approve|reject|fix-then-approve",
  "confidence": "high|medium|low"
}}"""


def _build_threat_intel_prompt(findings: list[dict]) -> str:
    categories = list(set(f.get("category", "") for f in findings))
    return f"""You are a threat intelligence analyst mapping MCP security findings to real-world threats.

Finding categories detected: {', '.join(categories)}

For each category, provide:
1. Relevant CVE IDs (if any match this type of vulnerability)
2. Known attack campaigns that use this technique
3. MITRE ATT&CK techniques that apply

Return ONLY valid JSON array:
[
  {{
    "category": "finding category",
    "cves": ["CVE-XXXX-XXXXX"],
    "campaigns": ["Campaign name and brief description"],
    "mitre_techniques": ["T1XXX: Technique name"]
  }}
]

If no specific CVE matches, return an empty array for that field. Be accurate — only cite real CVEs and techniques."""


async def _call_openrouter(
    prompt: str,
    api_key: str,
    model: str = DEFAULT_MODEL,
    max_tokens: int = 1024,
) -> str | None:
    """Call OpenRouter API and return the response text."""
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
        "HTTP-Referer": "https://mcpeek.dev",
        "X-Title": "MCPeek Security Scanner",
    }
    payload = {
        "model": model,
        "messages": [{"role": "user", "content": prompt}],
        "max_tokens": max_tokens,
        "temperature": 0.3,
    }

    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(OPENROUTER_URL, json=payload, headers=headers)
            resp.raise_for_status()
            data = resp.json()
            return data["choices"][0]["message"]["content"]
    except httpx.TimeoutException:
        logger.warning("OpenRouter timeout for model %s", model)
        return None
    except httpx.HTTPStatusError as e:
        logger.warning("OpenRouter HTTP %s: %s", e.response.status_code, e.response.text[:200])
        return None
    except Exception:
        logger.exception("OpenRouter call failed")
        return None


def _parse_json_response(text: str) -> Any:
    """Extract JSON from LLM response, handling markdown code blocks."""
    if not text:
        return None
    # Try direct parse
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    # Try extracting from code block
    import re
    match = re.search(r"```(?:json)?\s*\n?(.*?)\n?```", text, re.DOTALL)
    if match:
        try:
            return json.loads(match.group(1))
        except json.JSONDecodeError:
            pass
    # Try finding first [ or {
    for char, end_char in [("[", "]"), ("{", "}")]:
        start = text.find(char)
        if start == -1:
            continue
        depth = 0
        for i in range(start, len(text)):
            if text[i] == char:
                depth += 1
            elif text[i] == end_char:
                depth -= 1
                if depth == 0:
                    try:
                        return json.loads(text[start:i + 1])
                    except json.JSONDecodeError:
                        break
    return None


async def generate_attack_scenarios(
    findings: list[dict],
    target: str,
    target_type: str,
    api_key: str,
    model: str = DEFAULT_MODEL,
) -> list[dict]:
    """Generate dynamic, context-specific attack scenarios."""
    prompt = _build_attack_prompt(findings, target, target_type)
    raw = await _call_openrouter(prompt, api_key, model)
    result = _parse_json_response(raw)
    if isinstance(result, list):
        return result[:5]
    return []


async def generate_remediation(
    findings: list[dict],
    target_type: str,
    api_key: str,
    model: str = DEFAULT_MODEL,
) -> list[dict]:
    """Generate specific remediation suggestions."""
    prompt = _build_remediation_prompt(findings, target_type)
    raw = await _call_openrouter(prompt, api_key, model)
    result = _parse_json_response(raw)
    if isinstance(result, list):
        return result[:10]
    return []


async def generate_risk_narrative(
    findings: list[dict],
    risk_score: int,
    trust_score: int,
    target: str,
    api_key: str,
    model: str = DEFAULT_MODEL,
) -> dict:
    """Generate plain-English executive summary."""
    prompt = _build_narrative_prompt(findings, risk_score, trust_score, target)
    raw = await _call_openrouter(prompt, api_key, model)
    result = _parse_json_response(raw)
    if isinstance(result, dict) and "summary" in result:
        return result
    return {"summary": "", "verdict": "unknown", "confidence": "low"}


async def generate_threat_intel(
    findings: list[dict],
    api_key: str,
    model: str = DEFAULT_MODEL,
) -> list[dict]:
    """Map findings to real-world CVEs and MITRE ATT&CK."""
    prompt = _build_threat_intel_prompt(findings)
    raw = await _call_openrouter(prompt, api_key, model)
    result = _parse_json_response(raw)
    if isinstance(result, list):
        return result[:10]
    return []


async def run_ai_analysis(
    findings: list[dict],
    target: str,
    target_type: str,
    risk_score: int,
    trust_score: int,
    api_key: str,
    model: str = DEFAULT_MODEL,
) -> dict[str, Any]:
    """Run full AI analysis pipeline. Returns dict with all AI-generated content."""
    if not api_key:
        return {}

    try:
        # Run all analyses concurrently
        import asyncio
        scenarios, remediation, narrative, threat_intel = await asyncio.gather(
            generate_attack_scenarios(findings, target, target_type, api_key, model),
            generate_remediation(findings, target_type, api_key, model),
            generate_risk_narrative(findings, risk_score, trust_score, target, api_key, model),
            generate_threat_intel(findings, api_key, model),
            return_exceptions=True,
        )

        result = {}
        if isinstance(scenarios, list):
            result["ai_attack_scenarios"] = scenarios
        if isinstance(remediation, list):
            result["ai_remediation"] = remediation
        if isinstance(narrative, dict):
            result["ai_narrative"] = narrative
        if isinstance(threat_intel, list):
            result["ai_threat_intel"] = threat_intel

        return result
    except Exception:
        logger.exception("AI analysis pipeline failed")
        return {}
