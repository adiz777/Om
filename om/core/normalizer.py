"""Output parsing, indicator normalisation, deduplication, and risk classification for Om 2.0.

Separates:
- `raw_observation`: Direct tool output line or record
- `normalised_finding`: Structured, deduplicated indicator (subdomain, DNS record, open port, etc.)
- `inferred_finding`: Heuristic or signature match (WAF, CMS, email harvest)
- `confirmed_issue`: Verified security misconfiguration backed by protocol evidence (e.g., AXFR zone transfer enabled, deprecated SSLv3/TLSv1.0 enabled, exposed `.env`/`.git`)
"""
from __future__ import annotations

import ipaddress
import re
from datetime import datetime, timezone

from om.models.schemas import Finding, ModuleExecutionResult, TargetSpec

ANSI_RE = re.compile(r"\x1b\[[0-9;]*[a-zA-Z]")
PORT_RE = re.compile(r"^\s*(\d{1,5})/(tcp|udp)\s+open\s+(\S+)(?:\s+(.*))?$", re.IGNORECASE)
EMAIL_RE = re.compile(r"\b[a-zA-Z0-9._%+-]+@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,24})\b")
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
GOBUSTER_RE = re.compile(r"^\s*(/\S*)\s+\(Status:\s*(\d{3})\)", re.IGNORECASE)


def strip_ansi(text: str) -> str:
    return ANSI_RE.sub("", text or "")


def _extract_subdomains(text: str, base_domain: str) -> list[str]:
    cleaned = strip_ansi(text)
    pattern = re.compile(
        r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+" + re.escape(base_domain) + r"\b",
        re.IGNORECASE,
    )
    found = set()
    for match in pattern.finditer(cleaned):
        sub = match.group(0).lower().rstrip(".")
        if not sub.startswith("-"):
            found.add(sub)
    return sorted(found)


def _extract_ips(text: str) -> list[str]:
    cleaned = strip_ansi(text)
    ips = set()
    for candidate in IPV4_RE.findall(cleaned):
        try:
            addr = ipaddress.ip_address(candidate)
            if not (addr.is_loopback or addr.is_unspecified or addr.is_multicast):
                ips.add(str(addr))
        except ValueError:
            continue
    return sorted(ips)


def parse_tool_findings(result: ModuleExecutionResult, target: TargetSpec) -> list[Finding]:
    """Parse structured findings from a single tool execution."""
    if result.status not in {"completed", "partial", "timed_out"} or not result.stdout.strip():
        return []

    text = strip_ansi(result.stdout)
    findings: list[Finding] = []
    tool = result.tool
    ts = result.ended_at or datetime.now(timezone.utc).isoformat()

    if tool in {"amass", "sublist3r"} and target.target_type == "domain":
        for sub in _extract_subdomains(text, target.host):
            findings.append(
                Finding(
                    category="subdomain",
                    value=sub,
                    classification="normalised_finding",
                    confidence="unverified",
                    severity="info",
                    source_tool=tool,
                    timestamp=ts,
                    evidence=f"Matched subdomain '{sub}' in {tool} output",
                    detail="Discovered via subdomain enumeration (unverified until DNS resolved)",
                    limitations="Passive/OSINT subdomain entries may point to decommissioned records.",
                )
            )
        for ip in _extract_ips(text):
            findings.append(
                Finding(
                    category="ip_address",
                    value=ip,
                    classification="inferred_finding",
                    confidence="inferred",
                    severity="info",
                    source_tool=tool,
                    timestamp=ts,
                    evidence=f"IP {ip} referenced in {tool} output",
                    detail="IP address referenced during subdomain enumeration",
                    limitations="Requires active or PTR verification to confirm current ownership.",
                )
            )

    elif tool == "dnsrecon":
        for line in text.splitlines():
            line_s = line.strip()
            if any(rec in line_s for rec in (" A ", " AAAA ", " MX ", " NS ", " TXT ", " SOA ", " SRV ", " CNAME ")):
                cleaned_val = line_s.lstrip("[*] ").strip()[:240]
                is_weak_spf = "TXT" in line_s and ("+all" in line_s or "?all" in line_s)
                findings.append(
                    Finding(
                        category="dns_record",
                        value=cleaned_val,
                        classification="confirmed_issue" if is_weak_spf else "normalised_finding",
                        confidence="confirmed",
                        severity="medium" if is_weak_spf else "info",
                        source_tool=tool,
                        timestamp=ts,
                        evidence=line_s[:240],
                        detail=(
                            "Permissive SPF policy (+all / ?all) allows spoofing"
                            if is_weak_spf
                            else "DNS record returned by resolver"
                        ),
                        limitations="Point-in-time DNS resolver response.",
                        remediation="Use `-all` or `~all` in SPF TXT record." if is_weak_spf else "",
                    )
                )
            if "Zone Transfer" in line_s and ("Successful" in line_s or "zone transfer" in line_s.lower()):
                if "failed" not in line_s.lower() and "refused" not in line_s.lower():
                    findings.append(
                        Finding(
                            category="dns_record",
                            value=f"AXFR Zone Transfer enabled on {target.host}",
                            classification="confirmed_issue",
                            confidence="confirmed",
                            severity="high",
                            source_tool=tool,
                            timestamp=ts,
                            evidence=line_s[:240],
                            detail="DNS zone transfer (AXFR) succeeded; full zone records exposed",
                            limitations="Verified against responding authoritative nameserver.",
                            remediation="Restrict AXFR transfers on authoritative DNS servers to trusted secondary IPs.",
                        )
                    )
        if target.target_type == "domain":
            for sub in _extract_subdomains(text, target.host):
                findings.append(
                    Finding(
                        category="subdomain",
                        value=sub,
                        classification="normalised_finding",
                        confidence="confirmed",
                        severity="info",
                        source_tool=tool,
                        timestamp=ts,
                        evidence=f"Resolved host '{sub}' via {tool}",
                        detail="Resolved via DNS enumeration",
                        limitations="Confirmed in DNS at scan time.",
                    )
                )

    elif tool == "nmap":
        for line in text.splitlines():
            m = PORT_RE.match(line)
            if m:
                port_num, proto, service, version_info = (
                    m.group(1),
                    m.group(2).lower(),
                    m.group(3),
                    (m.group(4) or "").strip(),
                )
                val = f"{port_num}/{proto} ({service})"
                sev = "info"
                classification = "normalised_finding"
                detail = version_info or f"Open {proto.upper()} service"
                remediation = ""
                if port_num in {"21", "23", "445", "3389", "5900", "6379", "27017"}:
                    sev = "medium"
                    classification = "inferred_finding"
                    detail = f"{detail} — sensitive management or unencrypted protocol port exposed".strip(" —")
                    remediation = "Restrict administrative/database ports via firewall or VPN if not intended to be public."
                findings.append(
                    Finding(
                        category="open_port",
                        value=val,
                        classification=classification,
                        confidence="confirmed",
                        severity=sev,
                        source_tool=tool,
                        timestamp=ts,
                        evidence=line.strip()[:240],
                        detail=detail[:240],
                        limitations="Port state and service banner observed remotely; does not prove CVE exploitability.",
                        remediation=remediation,
                    )
                )

    elif tool == "whatweb":
        for line in text.splitlines():
            line_s = line.strip()
            if line_s and (line_s.startswith("http://") or line_s.startswith("https://")):
                findings.append(
                    Finding(
                        category="web_tech",
                        value=line_s[:300],
                        classification="normalised_finding",
                        confidence="confirmed",
                        severity="info",
                        source_tool=tool,
                        timestamp=ts,
                        evidence=line_s[:300],
                        detail="HTTP response and technology fingerprint",
                        limitations="Banner/header fingerprints can be masked by reverse proxies.",
                    )
                )

    elif tool == "wafw00f":
        for line in text.splitlines():
            line_s = line.strip()
            if "is behind" in line_s.lower():
                findings.append(
                    Finding(
                        category="waf",
                        value=line_s.lstrip("[+] ").strip()[:240],
                        classification="inferred_finding",
                        confidence="inferred",
                        severity="info",
                        source_tool=tool,
                        timestamp=ts,
                        evidence=line_s[:240],
                        detail="WAF signature matched HTTP response",
                        limitations="Heuristic HTTP header/cookie/response match.",
                    )
                )
            elif "no waf detected" in line_s.lower():
                findings.append(
                    Finding(
                        category="waf",
                        value="No WAF detected by signature probe",
                        classification="inferred_finding",
                        confidence="inferred",
                        severity="info",
                        source_tool=tool,
                        timestamp=ts,
                        evidence=line_s[:240],
                        detail="Target did not match known WAF signatures",
                        limitations="Custom or passive upstream WAFs may not trigger signature responses.",
                    )
                )

    elif tool == "sslscan":
        for line in text.splitlines():
            line_s = line.strip()
            lower_s = line_s.lower()
            if any(proto in lower_s for proto in ("sslv2", "sslv3", "tlsv1.0", "tlsv1.1")) and "enabled" in lower_s:
                findings.append(
                    Finding(
                        category="tls",
                        value=line_s[:200],
                        classification="confirmed_issue",
                        confidence="confirmed",
                        severity="medium",
                        source_tool=tool,
                        timestamp=ts,
                        evidence=line_s[:200],
                        detail="Deprecated TLS/SSL protocol enabled",
                        limitations="Handshake accepted by target port.",
                        remediation="Disable SSLv2, SSLv3, TLSv1.0, and TLSv1.1; enforce TLSv1.2 and TLSv1.3 only.",
                    )
                )
            elif any(proto in lower_s for proto in ("tlsv1.2", "tlsv1.3")) and "enabled" in lower_s:
                findings.append(
                    Finding(
                        category="tls",
                        value=line_s[:200],
                        classification="normalised_finding",
                        confidence="confirmed",
                        severity="info",
                        source_tool=tool,
                        timestamp=ts,
                        evidence=line_s[:200],
                        detail="Modern TLS protocol enabled",
                        limitations="Verified TLS handshake.",
                    )
                )
            elif lower_s.startswith("subject:") or lower_s.startswith("issuer:") or "not valid after:" in lower_s:
                findings.append(
                    Finding(
                        category="tls",
                        value=line_s[:240],
                        classification="raw_observation",
                        confidence="confirmed",
                        severity="info",
                        source_tool=tool,
                        timestamp=ts,
                        evidence=line_s[:240],
                        detail="TLS certificate metadata",
                        limitations="Leaf certificate presented by server.",
                    )
                )

    elif tool == "cmseek":
        for line in text.splitlines():
            line_s = line.strip()
            if any(k in line_s.lower() for k in ("cms detected", "cms name", "version")):
                findings.append(
                    Finding(
                        category="cms",
                        value=line_s[:240],
                        classification="inferred_finding",
                        confidence="inferred",
                        severity="info",
                        source_tool=tool,
                        timestamp=ts,
                        evidence=line_s[:240],
                        detail="CMS indicator detected",
                        limitations="CMS version inference is based on static asset/meta indicators.",
                    )
                )

    elif tool == "theHarvester":
        for match in EMAIL_RE.finditer(text):
            email = match.group(0).lower()
            domain_part = match.group(1).lower()
            if target.target_type != "domain" or domain_part == target.host or domain_part.endswith("." + target.host):
                findings.append(
                    Finding(
                        category="osint_email",
                        value=email,
                        classification="inferred_finding",
                        confidence="unverified",
                        severity="info",
                        source_tool=tool,
                        timestamp=ts,
                        evidence=f"Harvested email '{email}' from OSINT sources",
                        detail="Publicly harvested email address (unverified)",
                        limitations="Public search results may contain stale or third-party addresses.",
                    )
                )
        if target.target_type == "domain":
            for sub in _extract_subdomains(text, target.host):
                findings.append(
                    Finding(
                        category="subdomain",
                        value=sub,
                        classification="normalised_finding",
                        confidence="unverified",
                        severity="info",
                        source_tool=tool,
                        timestamp=ts,
                        evidence=f"Harvested hostname '{sub}' via {tool}",
                        detail="Discovered via OSINT harvesting",
                        limitations="Requires DNS resolution to confirm active status.",
                    )
                )

    elif tool == "gobuster":
        for line in text.splitlines():
            m = GOBUSTER_RE.match(line)
            if m:
                path_val, status_code = m.group(1), m.group(2)
                is_sensitive = path_val.lower() in {"/.env", "/.git", "/wp-config.php", "/backup", "/.htaccess"}
                is_admin = path_val.lower() in {"/admin", "/wp-admin", "/administrator", "/phpmyadmin"}
                sev = "medium" if (is_sensitive and status_code == "200") else ("low" if is_admin else "info")
                classification = (
                    "confirmed_issue"
                    if (is_sensitive and status_code == "200")
                    else ("inferred_finding" if is_admin else "normalised_finding")
                )
                findings.append(
                    Finding(
                        category="http_path",
                        value=f"{path_val} [HTTP {status_code}]",
                        classification=classification,
                        confidence="confirmed",
                        severity=sev,
                        source_tool=tool,
                        timestamp=ts,
                        evidence=line.strip()[:240],
                        detail=f"Discovered HTTP endpoint (status {status_code})",
                        limitations="HTTP 200 on custom error pages (soft-404) requires manual response body verification.",
                        remediation=(
                            f"Block public access to '{path_val}' in web server configuration."
                            if is_sensitive
                            else ""
                        ),
                    )
                )

    return findings


def deduplicate_findings(findings: list[Finding]) -> list[Finding]:
    """Deduplicate findings by `(category, normalised_value)`, merging provenance and keeping highest confidence."""
    confidence_rank = {"confirmed": 3, "inferred": 2, "unverified": 1}
    severity_rank = {"high": 4, "medium": 3, "low": 2, "info": 1}
    class_rank = {
        "confirmed_issue": 4,
        "normalised_finding": 3,
        "inferred_finding": 2,
        "raw_observation": 1,
    }

    merged: dict[tuple[str, str], Finding] = {}
    sources: dict[tuple[str, str], list[str]] = {}

    for item in findings:
        key = (item.category, item.value.strip())
        if key not in merged:
            merged[key] = item
            sources[key] = [item.source_tool]
        else:
            existing = merged[key]
            for src in [s.strip() for s in item.source_tool.split(",") if s.strip()]:
                if src not in sources[key]:
                    sources[key].append(src)
            best_conf = (
                item.confidence
                if confidence_rank.get(item.confidence, 0) > confidence_rank.get(existing.confidence, 0)
                else existing.confidence
            )
            best_sev = (
                item.severity
                if severity_rank.get(item.severity, 0) > severity_rank.get(existing.severity, 0)
                else existing.severity
            )
            best_cls = (
                item.classification
                if class_rank.get(item.classification, 0) > class_rank.get(existing.classification, 0)
                else existing.classification
            )
            merged[key] = Finding(
                category=existing.category,
                value=existing.value,
                classification=best_cls,
                confidence=best_conf,
                severity=best_sev,
                source_tool=", ".join(sources[key]),
                timestamp=existing.timestamp or item.timestamp,
                evidence=existing.evidence or item.evidence,
                detail=existing.detail or item.detail,
                limitations=existing.limitations or item.limitations,
                remediation=existing.remediation or item.remediation,
            )

    return sorted(merged.values(), key=lambda f: (f.category, f.value))
