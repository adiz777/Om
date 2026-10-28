"""Unit tests for configuration validation, module command building, and output normalisation."""
from __future__ import annotations

from pathlib import Path

import pytest

from om.core.config import OmConfig, load_config, save_config
from om.core.normalizer import deduplicate_findings, parse_tool_findings, strip_ansi
from om.models.schemas import ModuleExecutionResult
from om.modules.registry import MODULE_REGISTRY, build_module_command
from om.security.scope import parse_target


def test_config_profiles_and_validation(tmp_path: Path) -> None:
    cfg = OmConfig()
    cfg.apply_profile_defaults("high")
    assert cfg.profile == "high"
    assert cfg.timeout == 300
    assert cfg.concurrency == 4
    assert "bruteforce" in cfg.resolved_modules()

    cfg_file = save_config(cfg, tmp_path / "om.json")
    loaded = load_config(cfg_file)
    assert loaded.profile == "high"
    assert loaded.concurrency == 4

    with pytest.raises(ValueError, match="Invalid profile"):
        bad = OmConfig(profile="extreme")
        bad.validate()

    with pytest.raises(ValueError, match="Concurrency"):
        bad2 = OmConfig(concurrency=99)
        bad2.validate()


def test_build_module_commands_for_domain_vs_ip(tmp_path: Path) -> None:
    domain_target = parse_target("example.com")
    ip_target = parse_target("93.184.216.34")
    cfg = OmConfig(profile="medium", rate_limit=15)
    out_file = tmp_path / "out.txt"

    by_name = {m.name: m for m in MODULE_REGISTRY}

    amass_cmd = build_module_command(by_name["amass"], "/usr/bin/amass", domain_target, cfg, out_file)
    assert amass_cmd == ["/usr/bin/amass", "enum", "-passive", "-d", "example.com", "-o", str(out_file)]
    assert build_module_command(by_name["amass"], "/usr/bin/amass", ip_target, cfg, out_file) is None

    nmap_cmd = build_module_command(by_name["nmap"], "/usr/bin/nmap", domain_target, cfg, out_file)
    assert nmap_cmd is not None
    assert "--max-rate" in nmap_cmd
    assert "--" in nmap_cmd
    assert nmap_cmd[-1] == "example.com"


def test_parse_and_deduplicate_all_ten_tools() -> None:
    target = parse_target("example.com")

    amass_res = ModuleExecutionResult(
        tool="amass",
        module_group="subdomains",
        category="Subdomains",
        traffic_mode="passive",
        estimated_impact="low",
        status="completed",
        stdout="\x1b[32mapi.example.com\x1b[0m\ndev.example.com (93.184.216.34)\n",
    )
    sublist3r_res = ModuleExecutionResult(
        tool="sublist3r",
        module_group="subdomains",
        category="Subdomains",
        traffic_mode="passive",
        estimated_impact="low",
        status="completed",
        stdout="api.example.com\nstaging.example.com\n",
    )
    dns_res = ModuleExecutionResult(
        tool="dnsrecon",
        module_group="dns",
        category="DNS",
        traffic_mode="light-active",
        estimated_impact="low",
        status="completed",
        stdout="[*] A api.example.com 93.184.216.34\n[*] TXT example.com v=spf1 +all\n[+] Zone Transfer was Successful!\n",
    )
    nmap_res = ModuleExecutionResult(
        tool="nmap",
        module_group="nmap",
        category="Nmap",
        traffic_mode="active",
        estimated_impact="medium",
        status="completed",
        stdout="80/tcp   open  http    nginx 1.24.0\n6379/tcp open  redis   Redis key-value store\n",
    )
    whatweb_res = ModuleExecutionResult(
        tool="whatweb",
        module_group="webtech",
        category="WebTech",
        traffic_mode="light-active",
        estimated_impact="low",
        status="completed",
        stdout="https://example.com [200 OK] Country[US], HTTPServer[nginx/1.24.0]\n",
    )
    waf_res = ModuleExecutionResult(
        tool="wafw00f",
        module_group="webtech",
        category="WebTech",
        traffic_mode="light-active",
        estimated_impact="low",
        status="completed",
        stdout="[+] The site https://example.com is behind Cloudflare (Cloudflare Inc.) WAF.\n",
    )
    ssl_res = ModuleExecutionResult(
        tool="sslscan",
        module_group="ssl",
        category="SSL",
        traffic_mode="light-active",
        estimated_impact="low",
        status="completed",
        stdout="TLSv1.0   enabled\nTLSv1.3   enabled\nSubject:  example.com\n",
    )
    cms_res = ModuleExecutionResult(
        tool="cmseek",
        module_group="cms",
        category="CMS",
        traffic_mode="light-active",
        estimated_impact="low",
        status="completed",
        stdout="CMS Detected: WordPress\nVersion: 6.4.2\n",
    )
    harvester_res = ModuleExecutionResult(
        tool="theHarvester",
        module_group="osint",
        category="OSINT",
        traffic_mode="passive",
        estimated_impact="low",
        status="completed",
        stdout="security@example.com\nportal.example.com\n",
    )
    gobuster_res = ModuleExecutionResult(
        tool="gobuster",
        module_group="bruteforce",
        category="BruteForce",
        traffic_mode="active",
        estimated_impact="high",
        status="completed",
        stdout="/.env                 (Status: 200) [Size: 412]\n/admin                (Status: 302) [Size: 0]\n",
    )

    raw = []
    for r in (
        amass_res,
        sublist3r_res,
        dns_res,
        nmap_res,
        whatweb_res,
        waf_res,
        ssl_res,
        cms_res,
        harvester_res,
        gobuster_res,
    ):
        raw.extend(parse_tool_findings(r, target))

    deduped = deduplicate_findings(raw)
    by_val = {(f.category, f.value): f for f in deduped}

    # api.example.com was seen in amass (unverified), sublist3r (unverified), and dnsrecon (confirmed)
    api_sub = by_val[("subdomain", "api.example.com")]
    assert api_sub.confidence == "confirmed"
    assert "amass" in api_sub.source_tool
    assert "sublist3r" in api_sub.source_tool
    assert "dnsrecon" in api_sub.source_tool

    # AXFR and TLSv1.0 and /.env [HTTP 200] are classified as confirmed_issue
    axfr = by_val[("dns_record", "AXFR Zone Transfer enabled on example.com")]
    assert axfr.classification == "confirmed_issue"
    assert axfr.severity == "high"

    tls10 = by_val[("tls", "TLSv1.0   enabled")]
    assert tls10.classification == "confirmed_issue"
    assert tls10.severity == "medium"

    env_path = by_val[("http_path", "/.env [HTTP 200]")]
    assert env_path.classification == "confirmed_issue"
    assert env_path.severity == "medium"

    assert strip_ansi("\x1b[31mALERT\x1b[0m") == "ALERT"
