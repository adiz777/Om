"""Optional FreeLLMAPI-compatible analysis. AI output is advisory, never proof."""
import os
import httpx

async def analyse_findings(payload: dict) -> dict:
    base = os.getenv("FREELLMAPI_BASE_URL", "").strip().rstrip("/")
    key = os.getenv("FREELLMAPI_API_KEY", "").strip()
    if not base or not key:
        return {"status": "not_configured", "message": "Configure FREELLMAPI_BASE_URL and FREELLMAPI_API_KEY to enable AI analysis."}
    # Only send compact public enrichment metadata, never credentials or local files.
    safe = {"domain": payload.get("domain"), "certificate_count": payload.get("certificates", {}).get("count", 0), "cve_keyword": payload.get("cve_keyword"), "cve_count": payload.get("cves", {}).get("count", 0)}
    body = {"model": os.getenv("FREELLMAPI_MODEL", "auto"), "messages": [
        {"role": "system", "content": "You are a defensive security analyst. Treat input as unverified public metadata. Do not claim a vulnerability exists on the target unless evidence proves it. Explain uncertainty and recommend safe validation and remediation."},
        {"role": "user", "content": "Summarise this passive-enrichment result and its limitations as concise JSON or Markdown:\n" + str(safe)}], "temperature": 0.2}
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(25, connect=5), follow_redirects=False) as client:
            response = await client.post(base + "/chat/completions", json=body, headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"})
            response.raise_for_status()
            data = response.json()
        content = data.get("choices", [{}])[0].get("message", {}).get("content", "")
        return {"status": "ok", "model": data.get("model", body["model"]), "analysis": str(content)[:10000]}
    except (httpx.HTTPError, ValueError, TypeError, IndexError, KeyError) as exc:
        return {"status": "unavailable", "error": type(exc).__name__, "message": "AI provider failed; passive results remain available."}
