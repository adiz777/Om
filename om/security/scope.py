"""Target validation, normalisation, and scope enforcement for Om 2.0.

Prevents shell/argument injection, path traversal, unintended wildcard expansion,
and accidental scanning of loopback, link-local, or cloud metadata endpoints
unless explicitly in scope.
"""
from __future__ import annotations

import ipaddress
import re
from typing import Iterable
from urllib.parse import urlparse

from om.models.schemas import Finding, TargetSpec

DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$"
)
FORBIDDEN_CHARS = set(";&|`$><\n\r\t\x00'\"\\*?")
RESERVED_HOSTNAMES = {
    "localhost",
    "local",
    "metadata.google.internal",
    "metadata",
    "instance-data",
}
RESERVED_SUFFIXES = (".localhost", ".local", ".internal", ".home.arpa")


def _check_forbidden_chars(raw: str) -> None:
    if not raw or not raw.strip():
        raise ValueError("Target cannot be empty.")
    value = raw.strip()
    if value.startswith("-"):
        raise ValueError("Target must not start with '-' (argument injection protection).")
    if any(ch in FORBIDDEN_CHARS for ch in value):
        raise ValueError("Target contains unsafe shell, wildcard, or control characters.")
    if ".." in value:
        raise ValueError("Target must not contain '..' path traversal sequences.")


def _validate_ip_or_cidr(host: str, allow_private: bool = False) -> TargetSpec:
    if "/" in host:
        net = ipaddress.ip_network(host, strict=False)
        if net.is_loopback or net.is_link_local or net.is_multicast or net.is_unspecified:
            raise ValueError(
                f"Target CIDR '{host}' overlaps loopback, link-local, or reserved space and is blocked."
            )
        if net.is_private and not allow_private:
            raise ValueError(
                f"Target CIDR '{host}' is in a private range. Add it to --scope to scan internal/lab networks."
            )
        if net.num_addresses > 65536:
            raise ValueError(
                f"Target CIDR '{host}' is too broad ({net.num_addresses} addresses; max /16 or 65536)."
            )
        normalized = str(net)
        return TargetSpec(
            raw=host,
            host=normalized,
            target_type="cidr",
            scheme="http",
            url="",
        )

    addr = ipaddress.ip_address(host)
    if addr.is_loopback or addr.is_link_local or addr.is_multicast or addr.is_unspecified:
        raise ValueError(
            f"Target IP '{host}' is loopback, link-local, or reserved and is blocked for safety."
        )
    if addr.is_private and not allow_private:
        raise ValueError(
            f"Target IP '{host}' is in a private range. Add it to --scope to scan internal/lab networks."
        )
    normalized = str(addr)
    return TargetSpec(
        raw=host,
        host=normalized,
        target_type="ip",
        scheme="http",
        url=f"http://{normalized}" if addr.version == 4 else f"http://[{normalized}]",
    )


def parse_target(raw: str, *, allow_private: bool = False) -> TargetSpec:
    """Validate and normalise a domain/subdomain, IPv4/IPv6 address, CIDR range, or HTTP(S) URL."""
    _check_forbidden_chars(raw)
    value = raw.strip()
    scheme = "https"
    port: int | None = None
    host_candidate = value

    if "://" in value:
        parsed = urlparse(value)
        if parsed.scheme.lower() not in {"http", "https"}:
            raise ValueError(
                f"Unsupported URL scheme '{parsed.scheme}'. Use http, https, or a domain/IP."
            )
        if parsed.username or parsed.password:
            raise ValueError("Target URL must not embed credentials.")
        scheme = parsed.scheme.lower()
        if not parsed.hostname:
            raise ValueError("Target URL does not contain a valid hostname.")
        host_candidate = parsed.hostname
        try:
            port = parsed.port
        except ValueError as exc:
            raise ValueError(f"Invalid port in target URL: {exc}") from exc
    elif "/" in value:
        # Allow CIDR notations like 192.0.2.0/24 or 2001:db8::/120, reject URL paths without scheme
        try:
            ipaddress.ip_network(value, strict=False)
        except ValueError as exc:
            raise ValueError(
                "Provide a domain, IP, CIDR subnet, or full http(s):// URL without bare path segments."
            ) from exc

    host = host_candidate.strip().lower().rstrip(".")
    if not host or host.startswith("-"):
        raise ValueError("Target hostname is invalid.")

    # Check IP or CIDR first
    try:
        ip_spec = _validate_ip_or_cidr(host, allow_private=allow_private)
        if ip_spec.target_type == "cidr":
            return TargetSpec(
                raw=raw.strip(),
                host=ip_spec.host,
                target_type="cidr",
                scheme="http",
                port=None,
                url="",
            )
        host_fmt = f"[{ip_spec.host}]" if ":" in ip_spec.host else ip_spec.host
        url = f"{scheme}://{host_fmt}" + (f":{port}" if port else "")
        return TargetSpec(
            raw=raw.strip(),
            host=ip_spec.host,
            target_type="ip",
            scheme=scheme,
            port=port,
            url=url,
        )
    except ValueError as ip_err:
        if re.fullmatch(r"[\d./]+", host) or ":" in host:
            raise ip_err

    if host in RESERVED_HOSTNAMES or host.endswith(RESERVED_SUFFIXES):
        raise ValueError(f"Reserved or local hostname '{host}' is blocked.")
    if len(host) > 253 or not DOMAIN_RE.fullmatch(host):
        raise ValueError(
            f"Invalid target '{raw.strip()}'. Enter a valid domain (e.g. example.com), IPv4/IPv6, CIDR, or http(s) URL."
        )

    url = f"{scheme}://{host}" + (f":{port}" if port else "")
    return TargetSpec(
        raw=raw.strip(),
        host=host,
        target_type="domain",
        scheme=scheme,
        port=port,
        url=url,
    )


def verify_target_in_scope(target: TargetSpec, scope_entries: Iterable[str]) -> bool:
    """Verify that `target` matches at least one explicit scope entry.

    Supported scope entries:
    - Exact domain (`example.com`, which also permits subdomains `*.example.com`)
    - Wildcard domain (`*.example.com`)
    - Exact IP (`203.0.113.10`) or CIDR subnet (`203.0.113.0/24`)
    """
    cleaned = [s.strip().lower().rstrip(".") for s in scope_entries if s and s.strip()]
    if not cleaned:
        return True

    if target.target_type in {"ip", "cidr"}:
        target_net = (
            ipaddress.ip_network(target.host, strict=False)
            if target.target_type == "cidr"
            else ipaddress.ip_network(target.host)
        )
        for item in cleaned:
            try:
                scope_net = ipaddress.ip_network(item, strict=False)
                if (
                    target_net.version == scope_net.version
                    and target_net.subnet_of(scope_net)  # type: ignore[arg-type]
                ):
                    return True
            except ValueError:
                continue
        return False

    for item in cleaned:
        if item.startswith("*."):
            base = item[2:]
            if target.host == base or target.host.endswith("." + base):
                return True
        elif target.host == item or target.host.endswith("." + item):
            return True
    return False


def scope_allows_private_ip(raw_target: str, scope_entries: Iterable[str]) -> bool:
    """Return True if explicit scope entries cover a private IP or CIDR target."""
    cleaned = [s.strip() for s in scope_entries if s and s.strip()]
    if not cleaned:
        return False
    candidate = raw_target.strip()
    if "://" in candidate:
        parsed = urlparse(candidate)
        candidate = parsed.hostname or candidate
    try:
        target_net = ipaddress.ip_network(candidate, strict=False)
    except ValueError:
        return False
    for item in cleaned:
        try:
            scope_net = ipaddress.ip_network(item, strict=False)
            if target_net.version == scope_net.version and target_net.subnet_of(scope_net):  # type: ignore[arg-type]
                return True
        except ValueError:
            continue
    return False


def filter_findings_to_scope(
    findings: list[Finding], target: TargetSpec, scope_entries: Iterable[str]
) -> list[Finding]:
    """Ensure discovered subdomains and emails stay within the declared scope."""
    effective_scope = list(scope_entries) or ([target.host] if target.target_type == "domain" else [])
    if not effective_scope:
        return findings

    filtered: list[Finding] = []
    for f in findings:
        if f.category == "subdomain":
            try:
                sub_spec = parse_target(f.value)
                if not verify_target_in_scope(sub_spec, effective_scope):
                    continue
            except ValueError:
                continue
        filtered.append(f)
    return filtered
