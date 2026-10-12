# Om Sentinel

Om Sentinel is the hybrid dashboard and enrichment layer for Om. The original Bash scanner remains unchanged and available as `Om.sh`; Sentinel adds a FastAPI service for passive public-data enrichment, SQLite history, HTML/JSON reports, safe structured import, and optional AI summaries.

## Capabilities

- Dashboard and CLI client for authorized defensive workflows.
- Certificate-transparency records from crt.sh, constrained to the requested domain and its subdomains.
- CISA Known Exploited Vulnerabilities (KEV) catalogue metadata and optional NVD CVE keyword search.
- SQLite persistence for enrichment runs and imported findings.
- HTML and JSON report exports; report output escapes untrusted text.
- Local-first Ollama summaries, with optional FreeLLMAPI or another OpenAI-compatible endpoint.
- API-key authentication, strict domain validation, bounded HTTP timeouts, no redirects, and no automatic installation or execution of scanner binaries.

**Important:** This release performs passive enrichment and stores existing structured findings. It does not yet orchestrate all legacy `Om.sh` scanners. Public certificate/CVE matches are leads, not proof that a target is vulnerable. The metadata indicator is not CVSS.

## Local setup (Kali, Ubuntu, WSL)

```bash
cd sentinel
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
python -c 'import secrets; print(secrets.token_urlsafe(32))'
```

Put the generated value in `OM_SENTINEL_API_KEY` in `sentinel/.env`. Keep this file local and never commit real secrets. The application loads this file automatically when present.

Start the API:

```bash
uvicorn app.main:app --host 127.0.0.1 --port 8787
```

Open `http://127.0.0.1:8787`. Ollama runs separately on the host by default. Set `OM_AI_PROVIDER=off` to disable AI, or configure the server-side FreeLLMAPI/OpenAI-compatible variables in `.env`. Cloud AI receives a compact summary of public metadata, not raw scanner output or local files.

## CLI

In a second terminal:

```bash
cd sentinel
python cli.py example.com --cve-keyword nginx
python cli.py example.com --no-ai
```

Use only domains you own or are explicitly authorised to assess.

## Docker Compose

Set a strong API key in your shell; do not put it in the compose file:

```bash
export OM_SENTINEL_API_KEY="$(python -c 'import secrets; print(secrets.token_urlsafe(32))')"
docker compose up --build -d
docker compose logs -f sentinel
```

The service is published on port 8787 by default and SQLite history is stored in the named `sentinel_data` volume. For remote use, deploy behind TLS, use a secret manager, restrict ingress, and add rate limiting and monitoring. Do not expose the service directly to the public internet.

## API overview

- `GET /api/health` — unauthenticated health check.
- `POST /api/enrich` — authenticated passive enrichment.
- `GET /api/runs` and `GET /api/runs/{run_id}` — authenticated history.
- `GET /api/runs/{run_id}/report?format=html|json` — authenticated export.
- `POST /api/import` — authenticated structured import; imported content is never executed.

Authenticated requests use the `X-Om-Api-Key` header.

## Tests

```bash
cd sentinel
pytest -q
```

Tests should be run in CI and locally before treating a build as release-ready. Upstream public-data services and model providers can be unavailable independently of the API.

## Remaining work

- Add a structured adapter for legacy output folders and optional scanner orchestration with explicit scope confirmation, timeouts, and cancellation.
- Add task queueing for long-running jobs, rate limits, audit logging, and deployment-specific secret management.
- Validate CI, Docker builds, and deployment settings on the intended hosting platform.
