# Om Sentinel (hybrid foundation)

This is an additive prototype inside the existing Om repository. The original `Om.sh` is preserved. The current API provides **passive public-data enrichment** and optional AI summaries; it does not yet wrap every legacy scanner or replace the original CLI.

## What it includes

- FastAPI backend and a dark web dashboard, plus a command-line client.
- `crt.sh` certificate-transparency lookup constrained to the supplied domain and its subdomains.
- CISA Known Exploited Vulnerabilities (KEV) catalogue metadata.
- Optional NVD CVE keyword search (set `NVD_API_KEY` for improved rate limits).
- Optional OpenAI-compatible FreeLLMAPI endpoint; AI output is explicitly advisory.
- API-key authentication, strict domain validation, bounded HTTP timeouts, no redirects, no auto-installation of scanners, and no credentials committed to Git.

## Local setup (Kali, Ubuntu, WSL)

```bash
cd sentinel
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
python -c 'import secrets; print(secrets.token_urlsafe(32))'
```

Put the generated secret in `OM_SENTINEL_API_KEY` in your shell or local `.env` file. This minimal version intentionally does not auto-load `.env`; export the values explicitly or use a local environment loader that you trust. Example:

```bash
export OM_SENTINEL_API_KEY='paste-a-generated-secret-here'
export FREELLMAPI_BASE_URL='http://127.0.0.1:3001/v1'
export FREELLMAPI_API_KEY='your-local-freellmapi-unified-key'
uvicorn app.main:app --host 127.0.0.1 --port 8787
```

Open `http://127.0.0.1:8787`. To use FreeLLMAPI, run your own trusted FreeLLMAPI instance and add provider keys through its dashboard; its documented OpenAI-compatible endpoint is `/v1/chat/completions`. Do not expose either service to the public internet without TLS, strong authentication, firewalling, and a production deployment review.

## CLI

In another terminal, export the same `OM_SENTINEL_API_KEY`, then:

```bash
cd sentinel
python cli.py example.com --cve-keyword nginx
python cli.py example.com --no-ai
```

Only submit domains you own or have explicit permission to assess. Enrichment makes requests to public data services; it does not prove that a host is vulnerable. The `cve_keyword` parameter searches general CVE metadata, not the target host's confirmed software inventory.

## Tests

```bash
cd sentinel
pip install -r requirements.txt
pytest -q
```

## Deployment

For initial local/hybrid testing, bind to `127.0.0.1`. For a remote deployment, put the app behind a TLS reverse proxy, set a high-entropy API key through your platform's secret manager, add rate limiting, persist audit logs carefully, and restrict access. Never put API keys in frontend source, URLs, screenshots, committed `.env` files, or browser local storage. Configure FreeLLMAPI as a separate service and keep its unified key server-side.

## Roadmap

1. Add JSON adapters for legacy `Om.sh` outputs and run scanner jobs only against explicitly approved scope.
2. Add persistent scan history and a structured asset/finding schema.
3. Add provider health checks, cache and rate-limit controls.
4. Add CI tests and deployment manifests after the chosen hosting platform is confirmed.
