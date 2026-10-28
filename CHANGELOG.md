# Changelog

All notable changes to **Om** are documented in this file.

## [2.0.0] — 2026-10-28

### Added
- **Complete Modular Rebuild (`om` package):** Clean separation of `cli`, `core`, `models`, `security`, `modules`, `engine`, `storage`, `reporting`, and `api`.
- **10 Reconnaissance Tool Adapters (`om.modules.registry`):** Unified `ModuleContract` interface for `amass`, `sublist3r`, `dnsrecon`, `whatweb`, `wafw00f`, `nmap`, `sslscan`, `cmseek`, `theHarvester`, and `gobuster`, with non-destructive dependency detection (`--check-tools`, `--check-tools-json`) and version probing.
- **Concurrent Scan Orchestration Engine (`om.engine.orchestrator`):** Configurable worker concurrency (`--concurrency 1..8`), per-module timeouts (`--timeout`), mid-scan cancellation (`threading.Event`), partial result preservation, and `low`, `medium`, and `high` scanning profiles.
- **Target & Scope Security Guard (`om.security.scope`):** Validation for domains, subdomains, IPv4/IPv6, CIDR ranges, and HTTP(S) URLs; blocks shell metacharacters, leading-dash argument injection, path traversal, and private/loopback/metadata addresses unless explicitly scoped.
- **Evidence-Graded Normaliser (`om.core.normalizer`):** Separates `raw_observation`, `normalised_finding`, `inferred_finding`, and `confirmed_issue` with provenance deduplication.
- **Local Web Dashboard (`dashboard/index.html` & `om.api.server`):** 8-view local cybersecurity interface (*Overview*, *New Scan*, *Scan Details*, *Domain Intelligence*, *Network Intelligence*, *Web Intelligence*, *Reports & Diff*, *Settings & Modules*) bound to `127.0.0.1` with CSRF origin protection.
- **SQLite WAL History & Session Comparison (`om.storage.database`, `om.reporting.generator`):** Persistent scan history, retention pruning, HTML reports with strict `Content-Security-Policy` and `html.escape`, versioned JSON (`v2.0`), CSV export, and `--compare` diffing.
- **Automated Test Suite & CI:** 34 unit, integration, and FastAPI test cases (`pytest`) plus `ruff` linting and GitHub Actions workflow (`.github/workflows/ci.yml`).

### Changed
- Replaced the legacy monolithic root `Om.sh` with a safe wrapper delegating to `python3 -m om.cli.main`, while preserving the original script verbatim at `scripts/legacy/Om.sh` and retaining the classic interactive numbered menu (`1`–`11`).

### Fixed
- Eliminated automatic `sudo apt install` / `pip install` execution on startup.
- Fixed command/argument injection risks when passing user targets to external scanners.
- Fixed stored XSS in generated `Report.html` files by escaping all untrusted tool outputs and adding a strict CSP header.
