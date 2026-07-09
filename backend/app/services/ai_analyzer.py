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
import re
from typing import Any

import httpx


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

# Characters that could enable prompt injection when embedded in LLM prompts
_INJECTION_CHARS = re.compile(r"[^\x20-\x7E\n\r\t]")


def _sanitize_for_llm(text: str, max_len: int = 500) -> str:
    """Sanitize text before embedding in an LLM prompt.

    Prevents prompt injection by:
    1. Stripping non-printable/control characters
    2. Truncating to a safe length
    3. Wrapping in delimiters to distinguish data from instructions
    """
    if not text:
        return ""
    # Remove non-printable characters (except newline/tab)
    cleaned = _INJECTION_CHARS.sub("", text)
    # Collapse excessive whitespace/newlines that could be used for injection
    cleaned = re.sub(r"\n{3,}", "\n\n", cleaned)
    cleaned = re.sub(r" {4,}", "  ", cleaned)
    # Truncate
    if len(cleaned) > max_len:
        cleaned = cleaned[:max_len] + "...[truncated]"
    return cleaned


def _build_attack_prompt(findings: list[dict], target: str, target_type: str) -> str:
    safe_target = _sanitize_for_llm(target, 200)
    findings_text = "\n".join(
        f"- [{f['severity'].upper()}] {_sanitize_for_llm(f['title'], 100)}: {_sanitize_for_llm(f['description'], 200)}"
        for f in findings[:10]
    )
    return f"""Analyze these MCP security findings and generate 2 attack scenarios.

Scan target: {safe_target}
Target type: {_sanitize_for_llm(target_type, 50)}

Findings:
{findings_text}

For each scenario return JSON with: title, vector, impact, steps (array of 2-3 strings), severity, related_finding.

Return ONLY a JSON array, no other text:
[{{"title":"...","vector":"...","impact":"...","steps":["...","..."],"severity":"critical","related_finding":"..."}}]"""


def _build_remediation_prompt(findings: list[dict], target_type: str) -> str:
    findings_text = "\n".join(
        f"- [{f['severity'].upper()}] {_sanitize_for_llm(f['title'], 100)}"
        for f in findings[:10]
    )
    return f"""Provide specific fixes for these MCP security findings:

Findings:
{findings_text}

For each finding return JSON with: finding_title, fix (exact config change), explanation, tradeoffs.

Return ONLY a JSON array, no other text:
[{{"finding_title":"...","fix":"...","explanation":"...","tradeoffs":"..."}}]"""


def _build_narrative_prompt(findings: list[dict], risk_score: int, trust_score: int, target: str) -> str:
    critical = sum(1 for f in findings if f.get("severity") == "critical")
    high = sum(1 for f in findings if f.get("severity") == "high")
    medium = sum(1 for f in findings if f.get("severity") == "medium")
    safe_target = _sanitize_for_llm(target, 200)

    return f"""You are a security analyst writing an executive summary for a non-technical stakeholder.

Scan target: {safe_target}
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
    safe_categories = [_sanitize_for_llm(c, 50) for c in categories]
    return f"""Map these MCP security finding categories to MITRE ATT&CK techniques.

Categories: {', '.join(safe_categories)}

For each category return JSON with: category, cves (array), campaigns (array), mitre_techniques (array like "T1059: Command and Scripting Interpreter").

Return ONLY a JSON array, no other text:
[{{"category":"...","cves":[],"campaigns":[],"mitre_techniques":["T1059:..."]}}]

Only include real MITRE technique IDs. If unknown, use empty arrays."""


async def _call_openrouter(
    prompt: str,
    api_key: str,
    model: str = DEFAULT_MODEL,
    max_tokens: int = 4096,
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
    # Disable reasoning/thinking for models that support it
    if "gpt-oss" in model or "qwen3" in model:
        payload["reasoning"] = {"exclude": True}

    try:
        async with httpx.AsyncClient(timeout=60.0) as client:
            resp = await client.post(OPENROUTER_URL, json=payload, headers=headers)
            resp.raise_for_status()
            data = resp.json()
            if "choices" not in data or not data["choices"]:
                logger.warning("OpenRouter response missing choices: %s", str(data)[:300])
                return None
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
    # Last resort: try to fix common issues (trailing commas, etc.)
    cleaned = re.sub(r',\s*([\]}])', r'\1', text)
    try:
        return json.loads(cleaned)
    except json.JSONDecodeError:
        pass
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
    if raw:
        logger.debug("Attack scenarios raw response: %s", raw[:500])
    result = _parse_json_response(raw)
    if isinstance(result, list):
        logger.info("Generated %d attack scenarios", len(result))
        return result[:5]
    logger.warning("Failed to parse attack scenarios. Raw: %s", raw[:300] if raw else "None")
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
    if raw:
        logger.debug("Remediation raw response: %s", raw[:500])
    result = _parse_json_response(raw)
    if isinstance(result, list):
        logger.info("Generated %d remediation items", len(result))
        return result[:10]
    logger.warning("Failed to parse remediation. Raw: %s", raw[:300] if raw else "None")
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
        logger.info("Generated risk narrative with verdict: %s", result.get("verdict"))
        return result
    logger.warning("Failed to parse risk narrative from LLM response")
    return {"summary": "", "verdict": "unknown", "confidence": "low"}


async def generate_threat_intel(
    findings: list[dict],
    api_key: str,
    model: str = DEFAULT_MODEL,
) -> list[dict]:
    """Map findings to real-world CVEs and MITRE ATT&CK."""
    prompt = _build_threat_intel_prompt(findings)
    raw = await _call_openrouter(prompt, api_key, model)
    if raw:
        logger.debug("Threat intel raw response: %s", raw[:500])
    result = _parse_json_response(raw)
    if isinstance(result, list):
        logger.info("Generated %d threat intel items", len(result))
        return result[:10]
    logger.warning("Failed to parse threat intel. Raw: %s", raw[:300] if raw else "None")
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
        import asyncio

        result = {}

        # Run each analysis with individual timeout and delay between calls to avoid rate limits
        try:
            scenarios = await asyncio.wait_for(
                generate_attack_scenarios(findings, target, target_type, api_key, model),
                timeout=60,
            )
            if isinstance(scenarios, list):
                result["ai_attack_scenarios"] = scenarios
        except (asyncio.TimeoutError, Exception):
            logger.warning("Attack scenarios generation failed or timed out")

        await asyncio.sleep(6)  # Rate limit delay

        try:
            remediation = await asyncio.wait_for(
                generate_remediation(findings, target_type, api_key, model),
                timeout=60,
            )
            if isinstance(remediation, list):
                result["ai_remediation"] = remediation
        except (asyncio.TimeoutError, Exception):
            logger.warning("Remediation generation failed or timed out")

        await asyncio.sleep(6)  # Rate limit delay

        try:
            narrative = await asyncio.wait_for(
                generate_risk_narrative(findings, risk_score, trust_score, target, api_key, model),
                timeout=60,
            )
            if isinstance(narrative, dict):
                result["ai_narrative"] = narrative
        except (asyncio.TimeoutError, Exception):
            logger.warning("Narrative generation failed or timed out")

        await asyncio.sleep(6)  # Rate limit delay

        try:
            threat_intel = await asyncio.wait_for(
                generate_threat_intel(findings, api_key, model),
                timeout=60,
            )
            if isinstance(threat_intel, list):
                result["ai_threat_intel"] = threat_intel
        except (asyncio.TimeoutError, Exception):
            logger.warning("Threat intel generation failed or timed out")

        return result
    except Exception:
        logger.exception("AI analysis pipeline failed")
        return {}
