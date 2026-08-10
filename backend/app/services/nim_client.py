"""
NVIDIA NIM client — uses free NIM API endpoints for AI detection, defense, and enrichment.
Models available: nemotron, llama, qwen3, gpt-oss, gemma series.
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass
from typing import Optional

import httpx

from ..config import settings

logger = logging.getLogger(__name__)

# ── Free NIM Model Catalog (from user's NVIDIA NIM endpoint) ──

NIM_MODELS = {
    "meta/llama-3.3-70b-instruct": {
        "context_window": 128000,
        "max_output": 32768,
        "strengths": ["reasoning", "analysis", "code_review"],
        "cost": "free",
    },
    "meta/llama-3.1-8b-instruct": {
        "context_window": 128000,
        "max_output": 32768,
        "strengths": ["fast", "lightweight", "classification"],
        "cost": "free",
    },
    "nvidia/nemotron-nano-12b-v2-vl": {
        "context_window": 128000,
        "max_output": 32768,
        "strengths": ["vision", "multimodal", "fast"],
        "cost": "free",
    },
    "nvidia/nemotron-nano-12b-v2": {
        "context_window": 128000,
        "max_output": 32768,
        "strengths": ["reasoning", "instruction_following"],
        "cost": "free",
    },
    "qwen/qwen3-4b": {
        "context_window": 128000,
        "max_output": 32768,
        "strengths": ["fast", "classification", "lightweight"],
        "cost": "free",
    },
    "qwen/qwen3-8b": {
        "context_window": 128000,
        "max_output": 32768,
        "strengths": ["balanced", "reasoning", "analysis"],
        "cost": "free",
    },
    "qwen/qwen3-14b": {
        "context_window": 128000,
        "max_output": 32768,
        "strengths": ["deep_reasoning", "analysis"],
        "cost": "free",
    },
    "qwen/qwen3-coder-480b-a17b": {
        "context_window": 128000,
        "max_output": 32768,
        "strengths": ["code_review", "vulnerability_detection"],
        "cost": "free",
    },
    "nvidia/gpt-oss-120b-a12b": {
        "context_window": 128000,
        "max_output": 32768,
        "strengths": ["deep_analysis", "reasoning"],
        "cost": "free",
    },
    "nvidia/gpt-oss-20b": {
        "context_window": 128000,
        "max_output": 32768,
        "strengths": ["fast", "classification"],
        "cost": "free",
    },
    "nvidia/nemotron-250b-instruct": {
        "context_window": 128000,
        "max_output": 32768,
        "strengths": ["advanced_reasoning", "instruction_following"],
        "cost": "free",
    },
    "google/gemma-3n-e4b-it": {
        "context_window": 32000,
        "max_output": 8192,
        "strengths": ["ultra_lightweight", "edge"],
        "cost": "free",
    },
    "moonshotai/kimi-k2": {
        "context_window": 128000,
        "max_output": 32768,
        "strengths": ["agentic", "tool_use", "reasoning"],
        "cost": "free",
    },
}


@dataclass
class NIMResponse:
    """Response from NIM API."""
    content: str
    model: str
    tokens_used: int = 0
    latency_ms: float = 0.0
    error: Optional[str] = None

    @property
    def ok(self) -> bool:
        return self.error is None


class NIMClient:
    """Client for NVIDIA NIM free API endpoints."""

    def __init__(self) -> None:
        self._api_key = settings.NVIDIA_NIM_API_KEY
        self._base_url = settings.NVIDIA_NIM_BASE_URL.rstrip("/")
        self._http = httpx.Client(timeout=60.0)
        self._last_call: float = 0.0
        self._min_interval: float = 0.5  # 500ms between calls (rate limit)

    @property
    def available(self) -> bool:
        return bool(self._api_key)

    def chat(
        self,
        prompt: str,
        system: str = "",
        model: Optional[str] = None,
        temperature: float = 0.3,
        max_tokens: int = 4096,
    ) -> NIMResponse:
        """Send a chat completion request to NIM."""
        if not self.available:
            return NIMResponse(content="", model="", error="NVIDIA NIM API key not configured")

        model = model or settings.AI_MODEL_DETECTION
        if model not in NIM_MODELS:
            # Fallback to a known model
            model = "meta/llama-3.3-70b-instruct"

        # Rate limiting
        elapsed = time.time() - self._last_call
        if elapsed < self._min_interval:
            time.sleep(self._min_interval - elapsed)

        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})

        start = time.time()
        try:
            response = self._http.post(
                f"{self._base_url}/chat/completions",
                headers={
                    "Authorization": f"Bearer {self._api_key}",
                    "Content-Type": "application/json",
                },
                json={
                    "model": model,
                    "messages": messages,
                    "temperature": temperature,
                    "max_tokens": max_tokens,
                },
            )
            latency = (time.time() - start) * 1000

            if response.status_code != 200:
                error_msg = f"NIM API error {response.status_code}: {response.text[:200]}"
                logger.warning(error_msg)
                return NIMResponse(content="", model=model, error=error_msg, latency_ms=latency)

            data = response.json()
            content = data.get("choices", [{}])[0].get("message", {}).get("content", "")
            tokens = data.get("usage", {}).get("total_tokens", 0)

            return NIMResponse(
                content=content,
                model=model,
                tokens_used=tokens,
                latency_ms=latency,
            )
        except Exception as e:
            latency = (time.time() - start) * 1000
            error_msg = f"NIM request failed: {e}"
            logger.warning(error_msg)
            return NIMResponse(content="", model=model, error=error_msg, latency_ms=latency)

    def detect_threats(self, content: str, context: str = "") -> dict:
        """Use AI to detect threats in content."""
        system = (
            "You are a security analyst specialized in detecting AI agent attacks. "
            "Analyze the following content for prompt injection, data exfiltration, "
            "jailbreaking, tool abuse, or other adversarial attacks.\n\n"
            "Respond in JSON format:\n"
            '{"threats": [{"type": "...", "severity": "critical|high|medium|low|info", '
            '"evidence": "...", "mitigation": "..."}], "overall_risk": "critical|high|medium|low|safe"}'
        )
        prompt = f"Analyze this content for security threats:\n\n{content}"
        if context:
            prompt += f"\n\nContext: {context}"

        # Use llama-3.3-70b which is verified to work
        result = self.chat(prompt, system=system, model="meta/llama-3.3-70b-instruct")
        if result.ok:
            try:
                return json.loads(result.content)
            except json.JSONDecodeError:
                return {"threats": [], "overall_risk": "safe", "raw": result.content}
        return {"threats": [], "overall_risk": "safe", "error": result.error}

    def analyze_finding(self, finding: dict, scan_results: list[dict]) -> dict:
        """Use AI to analyze a finding for attack scenarios and remediation."""
        system = (
            "You are a cybersecurity expert analyzing MCP tool scan findings. "
            "For each finding, provide:\n"
            "1. Attack scenario: How an attacker could exploit this\n"
            "2. Impact: What data/systems could be compromised\n"
            "3. Remediation: Specific steps to fix\n"
            "4. Detection rules: YARA/Sigma rules for detection\n"
            "Respond in JSON: {\"attack_scenario\": \"...\", \"impact\": \"...\", "
            "\"remediation\": \"...\", \"detection_rules\": \"...\"}"
        )
        prompt = f"Analyze finding: {json.dumps(finding, indent=2)}\n\nFull scan results:\n{json.dumps(scan_results[:10], indent=2)}"

        result = self.chat(prompt, system=system, model=settings.AI_MODEL_DETECTION)
        if result.ok:
            try:
                return json.loads(result.content)
            except json.JSONDecodeError:
                return {"raw": result.content}
        return {"error": result.error}

    def generate_narrative(self, scan_results: list[dict]) -> str:
        """Generate a human-readable narrative of scan results."""
        system = (
            "You are a security report writer. Write a clear, concise narrative "
            "summary of the scan results. Highlight critical findings first, "
            "then high, medium, and low. Use plain language. Format as markdown."
        )
        prompt = f"Write a narrative summary for these scan results:\n\n{json.dumps(scan_results[:20], indent=2)}"

        # Use llama-3.3-70b which is verified to work
        result = self.chat(prompt, system=system, model="meta/llama-3.3-70b-instruct")
        return result.content if result.ok else f"Error: {result.error}"

    def recommend_fixes(self, finding: dict) -> str:
        """Get AI-powered fix recommendations."""
        system = (
            "You are an expert at fixing MCP tool security issues. "
            "Provide specific, actionable fix recommendations with code examples where applicable. "
            "Format as markdown."
        )
        prompt = f"Recommend fixes for this finding:\n\n{json.dumps(finding, indent=2)}"

        # Use llama-3.3-70b which is verified to work
        result = self.chat(prompt, system=system, model="meta/llama-3.3-70b-instruct")
        return result.content if result.ok else f"Error: {result.error}"

    def close(self) -> None:
        self._http.close()


# Singleton
_client: Optional[NIMClient] = None


def get_nim_client() -> NIMClient:
    global _client
    if _client is None:
        _client = NIMClient()
    return _client
