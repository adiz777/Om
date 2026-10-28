# Security Policy & Responsible Use — Om 2.0

## 1. Authorised Use Only

**Om 2.0** is developed by **Major_ADI** for:

- Authorised penetration testing and security assessments with explicit written permission.
- Defensive attack-surface monitoring of assets you own or administer.
- Cybersecurity education, academic labs, and CTF environments.

Scanning networks, domains, or web applications without prior written authorisation from the asset owner may violate applicable laws. Users are solely responsible for complying with all laws and scope agreements.

## 2. Built-in Safety & Security Controls

Om 2.0 implements defence-in-depth across its CLI, orchestration engine, reports, and local web dashboard:

1. **No Unsolicited System Modification:** Unlike legacy scripts that ran `sudo apt install` automatically, Om 2.0 never executes package managers or modifies system binaries. Missing tools are reported cleanly with installation instructions.
2. **Shell-Free Subprocess Execution:** Every external reconnaissance tool is invoked with `subprocess.Popen(cmd, shell=False)` using a validated `list[str]` argument array.
3. **Strict Target & Scope Validation (`om.security.scope`):**
   - Rejects shell metacharacters (`;`, `|`, `&`, `` ` ``, `$`, `>`, `<`, `\n`, `*`, `?`), path traversal (`..`), and leading-dash options (`-oG`) that could cause argument injection.
   - Blocks loopback (`127.0.0.0/8`, `::1`), link-local / cloud metadata (`169.254.0.0/16`, `metadata.google.internal`), and RFC 1918 private addresses by default unless explicitly permitted in `--scope`.
   - Filters discovered subdomains against the declared scope so scans never silently expand outside authorised boundaries.
4. **Active Reconnaissance Gate (`--authorize-active`):**
   - High-impact active scanners (`nmap`, `gobuster`) are blocked by default unless the operator explicitly passes `--authorize-active` (or checks the authorisation confirmation box in the dashboard/interactive menu).
5. **Safe Report Rendering (XSS & CSP Protection):**
   - All target inputs, findings, and raw console outputs embedded in `Report.html` are escaped via `html.escape(..., quote=True)`.
   - Generated HTML reports include `<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline';">` so untrusted target banners or DNS TXT records can never execute JavaScript.
6. **Local Dashboard Security (`om.api.server`):**
   - Binds to `127.0.0.1` (loopback) by default.
   - Enforces browser `Origin` validation on state-changing requests (`POST`, `PUT`, `DELETE`) to prevent Cross-Site Request Forgery (CSRF) from external websites.
   - Supports optional `OM_API_KEY` header authentication (`X-Om-Api-Key`) using constant-time `hmac.compare_digest`.
   - Before exposing the dashboard beyond `127.0.0.1`, always set a strong `OM_API_KEY` and place the service behind a TLS-terminating reverse proxy.

## 3. Reporting a Vulnerability

If you discover a security vulnerability in Om 2.0 (such as an argument injection bypass, report escaping flaw, or API access-control issue):

1. Do **not** open a public GitHub issue with live exploit details.
2. Report the finding privately via GitHub Security Advisories on [`https://github.com/adiz777/Om/security/advisories`](https://github.com/adiz777/Om/security/advisories) or contact **Major_ADI** through GitHub.
3. Include minimal reproduction steps, affected version/commit, and impact assessment.
