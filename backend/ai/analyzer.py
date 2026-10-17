"""
AI-Powered Email Analyzer
Uses a local LLM (via Ollama) to perform deep social engineering analysis:
- Tactic identification (pretexting, urgency, authority impersonation)
- Plain-English risk summary
- MITRE ATT&CK mapping
- Recommended actions

Supports multiple backends:
- Ollama (default, local, free)
- Claude API (optional, paid)
- Gemini API (optional, free tier)
"""
import json
import logging
import requests
from typing import Dict, Optional
from dataclasses import dataclass, asdict

logger = logging.getLogger(__name__)

# ── System Prompt ──

SYSTEM_PROMPT = """You are a senior cybersecurity analyst specializing in email-based social engineering attacks. You will be given the text of an email to analyze.

Respond ONLY with a valid JSON object (no markdown, no backticks, no preamble) using this exact structure:

{
  "verdict": "phishing" | "suspicious" | "legitimate",
  "confidence": 0-100,
  "risk_summary": "2-3 sentence plain-English explanation of why this email is or isn't dangerous. Write for a non-technical person.",
  "social_engineering_tactics": [
    {
      "tactic": "Name of the tactic (e.g., Pretexting, Urgency, Authority Impersonation, Fear/Threat, Reward/Greed, Curiosity)",
      "description": "How this tactic is used in this specific email"
    }
  ],
  "mitre_attack": [
    {
      "technique_id": "T1566.001",
      "technique_name": "Spearphishing Attachment/Link",
      "relevance": "Why this technique applies to this email"
    }
  ],
  "brand_impersonation": {
    "detected": true/false,
    "brand": "Brand name or null",
    "indicators": "What gives away the impersonation"
  },
  "recommended_actions": [
    "Specific action the recipient should take"
  ],
  "indicators_of_compromise": [
    "Any IOCs found: suspicious domains, IPs, email addresses, file hashes"
  ]
}"""


# ── Ollama Backend ──

class OllamaAnalyzer:
    """Analyze emails using a local Ollama LLM."""

    def __init__(self, model: str = "llama3", base_url: str = "http://localhost:11434"):
        self.model = model
        self.base_url = base_url.rstrip("/")
        self.api_url = f"{self.base_url}/api/generate"

    def is_available(self) -> bool:
        """Check if Ollama is running and the model is pulled."""
        try:
            resp = requests.get(f"{self.base_url}/api/tags", timeout=3)
            if resp.status_code == 200:
                models = [m["name"] for m in resp.json().get("models", [])]
                # Check for model name with or without tag
                return any(self.model in m for m in models)
            return False
        except (requests.ConnectionError, requests.Timeout):
            return False

    def analyze(self, email_text: str) -> Dict:
        """Send email to Ollama for analysis."""
        try:
            prompt = f"Analyze this email for phishing indicators:\n\n---\n{email_text[:3000]}\n---"

            resp = requests.post(
                self.api_url,
                json={
                    "model": self.model,
                    "prompt": prompt,
                    "system": SYSTEM_PROMPT,
                    "stream": False,
                    "options": {
                        "temperature": 0.1,
                        "num_predict": 1500,
                    },
                },
                timeout=120,
            )
            resp.raise_for_status()
            raw_response = resp.json().get("response", "")
            return _parse_llm_response(raw_response)

        except requests.ConnectionError:
            logger.error("Ollama not running. Start with: ollama serve")
            return _error_response("Ollama is not running. Start it with 'ollama serve'.")
        except requests.Timeout:
            logger.error("Ollama request timed out")
            return _error_response("Analysis timed out. The model may be loading.")
        except Exception as e:
            logger.error(f"Ollama analysis error: {e}")
            return _error_response(str(e))


# ── Claude API Backend (Optional) ──

class ClaudeAnalyzer:
    """Analyze emails using Claude API (requires API key)."""

    def __init__(self, api_key: str, model: str = "claude-sonnet-4-20250514"):
        self.api_key = api_key
        self.model = model
        self.api_url = "https://api.anthropic.com/v1/messages"

    def is_available(self) -> bool:
        return bool(self.api_key)

    def analyze(self, email_text: str) -> Dict:
        try:
            resp = requests.post(
                self.api_url,
                headers={
                    "x-api-key": self.api_key,
                    "anthropic-version": "2023-06-01",
                    "Content-Type": "application/json",
                },
                json={
                    "model": self.model,
                    "max_tokens": 1500,
                    "system": SYSTEM_PROMPT,
                    "messages": [
                        {"role": "user", "content": f"Analyze this email:\n\n---\n{email_text[:3000]}\n---"}
                    ],
                },
                timeout=60,
            )
            resp.raise_for_status()
            raw = resp.json()["content"][0]["text"]
            return _parse_llm_response(raw)

        except Exception as e:
            logger.error(f"Claude API error: {e}")
            return _error_response(str(e))


# ── Gemini API Backend (Optional) ──

class GeminiAnalyzer:
    """Analyze emails using Google Gemini API (free tier available)."""

    def __init__(self, api_key: str, model: str = "gemini-1.5-flash"):
        self.api_key = api_key
        self.model = model

    def is_available(self) -> bool:
        return bool(self.api_key)

    def analyze(self, email_text: str) -> Dict:
        try:
            url = f"https://generativelanguage.googleapis.com/v1beta/models/{self.model}:generateContent"
            resp = requests.post(
                url,
                params={"key": self.api_key},
                json={
                    "system_instruction": {"parts": [{"text": SYSTEM_PROMPT}]},
                    "contents": [
                        {"parts": [{"text": f"Analyze this email:\n\n---\n{email_text[:3000]}\n---"}]}
                    ],
                    "generationConfig": {"temperature": 0.1, "maxOutputTokens": 1500},
                },
                timeout=60,
            )
            resp.raise_for_status()
            raw = resp.json()["candidates"][0]["content"]["parts"][0]["text"]
            return _parse_llm_response(raw)

        except Exception as e:
            logger.error(f"Gemini API error: {e}")
            return _error_response(str(e))


# ── Provider Factory ──

def get_ai_analyzer(config: Dict) -> Optional[object]:
    """
    Get the best available AI analyzer based on config.
    Priority: Ollama (local) → Claude API → Gemini API
    """
    # Try Ollama first (local, free, private)
    ollama_model = config.get("OLLAMA_MODEL", "llama3")
    ollama_url = config.get("OLLAMA_URL", "http://localhost:11434")
    ollama = OllamaAnalyzer(model=ollama_model, base_url=ollama_url)
    if ollama.is_available():
        logger.info(f"Using Ollama ({ollama_model}) for AI analysis")
        return ollama

    # Try Claude API
    claude_key = config.get("CLAUDE_API_KEY", "")
    if claude_key:
        claude = ClaudeAnalyzer(api_key=claude_key)
        logger.info("Using Claude API for AI analysis")
        return claude

    # Try Gemini API
    gemini_key = config.get("GEMINI_API_KEY", "")
    if gemini_key:
        gemini = GeminiAnalyzer(api_key=gemini_key)
        logger.info("Using Gemini API for AI analysis")
        return gemini

    logger.warning("No AI backend available. Install Ollama or set an API key.")
    return None


# ── Response Parsing ──

def _parse_llm_response(raw: str) -> Dict:
    """Parse the LLM's JSON response, handling common formatting issues."""
    # Strip markdown code fences if present
    cleaned = raw.strip()
    cleaned = cleaned.removeprefix("```json").removeprefix("```")
    cleaned = cleaned.removesuffix("```")
    cleaned = cleaned.strip()

    try:
        parsed = json.loads(cleaned)
        parsed["ai_available"] = True
        parsed["error"] = None
        return parsed
    except json.JSONDecodeError:
        # Try to extract JSON from mixed text
        json_match = _extract_json(cleaned)
        if json_match:
            try:
                parsed = json.loads(json_match)
                parsed["ai_available"] = True
                parsed["error"] = None
                return parsed
            except json.JSONDecodeError:
                pass

        logger.error(f"Failed to parse LLM response as JSON: {cleaned[:200]}")
        return {
            "ai_available": True,
            "error": "Failed to parse AI response",
            "raw_response": cleaned[:500],
            "verdict": "unknown",
            "confidence": 0,
            "risk_summary": cleaned[:300] if cleaned else "Analysis failed",
            "social_engineering_tactics": [],
            "mitre_attack": [],
            "brand_impersonation": {"detected": False, "brand": None, "indicators": ""},
            "recommended_actions": ["Treat with caution — AI analysis encountered an error"],
            "indicators_of_compromise": [],
        }


def _extract_json(text: str) -> Optional[str]:
    """Try to extract a JSON object from mixed text."""
    depth = 0
    start = None
    for i, char in enumerate(text):
        if char == '{':
            if depth == 0:
                start = i
            depth += 1
        elif char == '}':
            depth -= 1
            if depth == 0 and start is not None:
                return text[start:i + 1]
    return None


def _error_response(error_msg: str) -> Dict:
    """Return a structured error response."""
    return {
        "ai_available": False,
        "error": error_msg,
        "verdict": "unknown",
        "confidence": 0,
        "risk_summary": f"AI analysis unavailable: {error_msg}",
        "social_engineering_tactics": [],
        "mitre_attack": [],
        "brand_impersonation": {"detected": False, "brand": None, "indicators": ""},
        "recommended_actions": [],
        "indicators_of_compromise": [],
    }
