"""Unit tests for target validation, scope enforcement, and SSRF/injection guards."""
from __future__ import annotations

import pytest

from om.models.schemas import Finding
from om.security.scope import (
    filter_findings_to_scope,
    parse_target,
    scope_allows_private_ip,
    verify_target_in_scope,
)


def test_parse_valid_domain_and_subdomain() -> None:
    spec = parse_target("  Sub.Example.COM. ")
    assert spec.host == "sub.example.com"
    assert spec.target_type == "domain"
    assert spec.scheme == "https"
    assert spec.base_url == "https://sub.example.com"
    assert spec.safe_slug == "sub.example.com"


def test_parse_valid_url_with_port() -> None:
    spec = parse_target("http://app.example.org:8080/login")
    assert spec.host == "app.example.org"
    assert spec.target_type == "domain"
    assert spec.scheme == "http"
    assert spec.port == 8080
    assert spec.base_url == "http://app.example.org:8080"


def test_parse_valid_public_ipv4_and_cidr() -> None:
    ip_spec = parse_target("93.184.216.34")
    assert ip_spec.host == "93.184.216.34"
    assert ip_spec.target_type == "ip"

    cidr_spec = parse_target("93.184.216.0/24")
    assert cidr_spec.host == "93.184.216.0/24"
    assert cidr_spec.target_type == "cidr"


@pytest.mark.parametrize(
    "malicious_input",
    [
        "",
        "   ",
        "-oG /etc/passwd",
        "--script=vuln",
        "example.com; id",
        "example.com | cat /etc/shadow",
        "example.com && whoami",
        "example.com`id`",
        "$(whoami).example.com",
        "*.example.com",
        "../etc/passwd",
        "http://user:pass@example.com",
        "ftp://example.com",
        "localhost",
        "api.localhost",
        "metadata.google.internal",
        "127.0.0.1",
        "::1",
        "169.254.169.254",
    ],
)
def test_reject_malicious_or_reserved_targets(malicious_input: str) -> None:
    with pytest.raises(ValueError):
        parse_target(malicious_input)


def test_private_ip_blocked_unless_explicitly_scoped() -> None:
    with pytest.raises(ValueError, match="private range"):
        parse_target("10.10.14.5", allow_private=False)

    assert scope_allows_private_ip("10.10.14.5", ["10.10.0.0/16"]) is True
    spec = parse_target("10.10.14.5", allow_private=True)
    assert spec.target_type == "ip"
    assert verify_target_in_scope(spec, ["10.10.0.0/16"]) is True
    assert verify_target_in_scope(spec, ["192.168.1.0/24"]) is False


def test_domain_and_cidr_scope_enforcement() -> None:
    sub = parse_target("dev.api.example.com")
    other = parse_target("evil-example.com")
    cidr = parse_target("93.184.216.0/25")

    assert verify_target_in_scope(sub, ["example.com"]) is True
    assert verify_target_in_scope(sub, ["*.example.com"]) is True
    assert verify_target_in_scope(other, ["example.com", "*.example.com"]) is False
    assert verify_target_in_scope(cidr, ["93.184.216.0/24"]) is True
    assert verify_target_in_scope(cidr, ["93.184.216.0/26"]) is False


def test_filter_findings_to_scope_removes_out_of_scope_subdomains() -> None:
    target = parse_target("example.com")
    findings = [
        Finding(
            category="subdomain",
            value="api.example.com",
            classification="normalised_finding",
            confidence="confirmed",
            severity="info",
            source_tool="amass",
        ),
        Finding(
            category="subdomain",
            value="cdn.unrelated-vendor.net",
            classification="normalised_finding",
            confidence="unverified",
            severity="info",
            source_tool="amass",
        ),
    ]
    scoped = filter_findings_to_scope(findings, target, ["example.com"])
    assert len(scoped) == 1
    assert scoped[0].value == "api.example.com"
