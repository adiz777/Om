"""Local-first AI analysis with optional OpenAI-compatible cloud fallback."""
from __future__ import annotations
import os
import httpx


def _safe_summary(payload: dict) -> dict:
    # Deliberately exclude raw scanner output, secrets, paths, and full certificate/CVE descriptions.
    return {
        "domain": payload.get("domain"),
        "mode": payload.get("mode"),
        "certificate_count": payload.get("certificates", {}).get("count", 0),
        "cve_keyword": payload.get("cve_keyword"),
        "cve_count": payload.get("cves", {}).get("count", 0),
        "limitations": payload.get("limitations", []),
    }


async def _ollama(summary: dict) -> dict:
    base = os.getenv("OLLAMA_BASE_URL", "http://127.0.0.1:11434").strip().rstrip("/")
    model = os.getenv("OLLAMA_MODEL", "qwen2.5:7b").strip()
    body = {
        "model": model,
        "stream": False,
        "messages": [
            {"role": "system", "content": "You are a defensive security analyst. Treat input as unverified public metadata. Never claim target vulnerability without direct evidence. Explain uncertainty and recommend safe remediation."},
            {"role": "user", "content": "Summarise this passive enrichment result and limitations concisely: " + str(summary)},
        ],
        "options": {"temperature": 0.2},
    }
    async with httpx.AsyncClient(timeout=httpx.Timeout(35, connect=3), follow_redirects=False) as client:
        response = await client.post(base + "/api/chat", json=body)
        response.raise_for_status()
        data = response.json()
    message = data.get("message", {}).get("content", "")
    if not message:
        raise ValueError("Empty local model response")
    return {"status": "ok", "provider": "ollama", "model": data.get("model", model), "analysis": str(message)[:10000]}


async def _openai_compatible(summary: dict, provider: str) -> dict:
    if provider == "freellmapi":
        base = os.getenv("FREELLMAPI_BASE_URL", "").strip().rstrip("/")
        key = os.getenv("FREELLMAPI_API_KEY", "").strip()
        model = os.getenv("FREELLMAPI_MODEL", "auto").strip()
    else:
        base = os.getenv("OPENAI_COMPAT_BASE_URL", "").strip().rstrip("/")
        key = os.getenv("OPENAI_COMPAT_API_KEY", "").strip()
        model = os.getenv("OPENAI_COMPAT_MODEL", "auto").strip()
    if not base or not key:
        raise RuntimeError("Provider not configured")
    body = {
        "model": model,
        "messages": [
            {"role": "system", "content": "You are a defensive security analyst. Treat input as unverified public metadata. Never claim target vulnerability without direct evidence. Explain uncertainty and recommend safe remediation."},
            {"role": "user", "content": "Summarise this passive enrichment result and limitations concisely: " + str(summary)},
        ],
        "temperature": 0.2,
    }
    async with httpx.AsyncClient(timeout=httpx.Timeout(25, connect=5), follow_redirects=False) as client:
        response = await client.post(base + "/chat/completions", json=body, headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"})
        response.raise_for_status()
        data = response.json()
    content = data.get("choices", [{}])[0].get("message", {}).get("content", "")
    if not content:
        raise ValueError("Empty cloud model response")
    return {"status": "ok", "provider": provider, "model": data.get("model", model), "analysis": str(content)[:10000]}


async def analyse_findings(payload: dict) -> dict:
    """Use local Ollama first by default; cloud use requires explicit provider credentials."""
    provider = os.getenv("OM_AI_PROVIDER", "auto").strip().lower()
    if provider not in {"auto", "none", "ollama", "freellmapi", "openai-compatible"}:
        return {"status": "configuration_error", "message": "OM_AI_PROVIDER must be auto, none, ollama, freellmapi, or openai-compatible."}
    if provider == "none":
        return {"status": "disabled"}
    summary = _safe_summary(payload)
    errors = []
    if provider in {"auto", "ollama"}:
        try:
            return await _ollama(summary)
        except (httpx.HTTPError, ValueError, TypeError, KeyError) as exc:
            errors.append("ollama:" + type(exc).__name__)
            if provider == "ollama":
                return {"status": "unavailable", "provider": "ollama", "message": "Local model unavailable; passive results remain available."}
    if provider in {"auto", "freellmapi"}:
        if os.getenv("FREELLMAPI_BASE_URL", "").strip() and os.getenv("FREELLMAPI_API_KEY", "").strip():
            try:
                return await _openai_compatible(summary, "freellmapi")
            except (httpx.HTTPError, ValueError, TypeError, KeyError, RuntimeError) as exc:
                errors.append("freellmapi:" + type(exc).__name__)
        elif provider == "freellmapi":
            return {"status": "not_configured", "message": "Set FREELLMAPI_BASE_URL and FREELLMAPI_API_KEY."}
    if provider == "openai-compatible":
        try:
            return await _openai_compatible(summary, "openai-compatible")
        except (httpx.HTTPError, ValueError, TypeError, KeyError, RuntimeError) as exc:
            return {"status": "unavailable", "provider": provider, "error": type(exc).__name__, "message": "AI provider failed; passive results remain available."}
    if errors:
        return {"status": "unavailable", "attempted": errors, "message": "Local/cloud AI unavailable; passive results remain available."}
    return {"status": "not_configured", "message": "Local Ollama was unavailable. Configure it locally or explicitly configure FreeLLMAPI for cloud fallback."}
