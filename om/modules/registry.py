"""Common integration contract and adapters for all 10 reconnaissance tools in Om 2.0.

Executes external reconnaissance binaries with `shell=False` argument arrays,
explicit timeouts, cancellation event polling, and structured diagnostic capture.
Never auto-installs system packages with `sudo`.
"""
from __future__ import annotations

import shutil
import subprocess
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from om.core.config import OmConfig
from om.models.schemas import ModuleContract, ModuleExecutionResult, TargetSpec

MODULE_REGISTRY: tuple[ModuleContract, ...] = (
    ModuleContract(
        name="amass",
        binary_candidates=("amass",),
        module_group="subdomains",
        category="Subdomains",
        supported_targets=("domain",),
        traffic_mode="passive",
        estimated_impact="low",
        requires_active_auth=False,
        version_args=("-version",),
        apt_hint="sudo apt install -y amass",
        alt_hint="go install -v github.com/owasp-amass/amass/v4/...@master",
        description="OWASP Amass subdomain enumeration",
        limitations="Passive mode queries public certificate & DNS datasets; discovered hosts may not resolve.",
    ),
    ModuleContract(
        name="sublist3r",
        binary_candidates=("sublist3r",),
        module_group="subdomains",
        category="Subdomains",
        supported_targets=("domain",),
        traffic_mode="passive",
        estimated_impact="low",
        requires_active_auth=False,
        version_args=("--help",),
        apt_hint="sudo apt install -y sublist3r",
        alt_hint="pipx install sublist3r",
        description="OSINT-based subdomain enumeration",
        limitations="Relies on public search engines and OSINT sources subject to upstream rate limits.",
    ),
    ModuleContract(
        name="dnsrecon",
        binary_candidates=("dnsrecon",),
        module_group="dns",
        category="DNS",
        supported_targets=("domain",),
        traffic_mode="light-active",
        estimated_impact="low",
        requires_active_auth=False,
        version_args=("-v",),
        apt_hint="sudo apt install -y dnsrecon",
        alt_hint="pipx install dnsrecon",
        description="DNS record enumeration and zone transfer checks",
        limitations="Reflects point-in-time DNS resolver responses.",
    ),
    ModuleContract(
        name="whatweb",
        binary_candidates=("whatweb",),
        module_group="webtech",
        category="WebTech",
        supported_targets=("domain", "ip"),
        traffic_mode="light-active",
        estimated_impact="low",
        requires_active_auth=False,
        version_args=("--version",),
        apt_hint="sudo apt install -y whatweb",
        alt_hint="https://github.com/urbanadventurer/WhatWeb",
        description="Web server and technology stack fingerprinter",
        limitations="Reverse proxies or CDNs may mask origin server headers.",
    ),
    ModuleContract(
        name="wafw00f",
        binary_candidates=("wafw00f",),
        module_group="webtech",
        category="WebTech",
        supported_targets=("domain", "ip"),
        traffic_mode="light-active",
        estimated_impact="low",
        requires_active_auth=False,
        version_args=("--version",),
        apt_hint="sudo apt install -y wafw00f",
        alt_hint="pipx install wafw00f",
        description="Web Application Firewall (WAF) signature detection",
        limitations="Detects known WAF signatures; custom or silent WAF rules may not trigger.",
    ),
    ModuleContract(
        name="nmap",
        binary_candidates=("nmap",),
        module_group="nmap",
        category="Nmap",
        supported_targets=("domain", "ip", "cidr"),
        traffic_mode="active",
        estimated_impact="medium",
        requires_active_auth=True,
        version_args=("--version",),
        apt_hint="sudo apt install -y nmap",
        alt_hint="https://nmap.org/download.html",
        description="Network port and service version discovery",
        limitations="Service banners do not confirm CVE exploitability without patch verification.",
    ),
    ModuleContract(
        name="sslscan",
        binary_candidates=("sslscan",),
        module_group="ssl",
        category="SSL",
        supported_targets=("domain", "ip"),
        traffic_mode="light-active",
        estimated_impact="low",
        requires_active_auth=False,
        version_args=("--version",),
        apt_hint="sudo apt install -y sslscan",
        alt_hint="https://github.com/rbsec/sslscan",
        description="TLS/SSL cipher, protocol, and certificate scanner",
        limitations="Inspects the TLS endpoint on the target host/port (SNI).",
    ),
    ModuleContract(
        name="cmseek",
        binary_candidates=("cmseek", "cmseek.py"),
        module_group="cms",
        category="CMS",
        supported_targets=("domain", "ip"),
        traffic_mode="light-active",
        estimated_impact="low",
        requires_active_auth=False,
        version_args=("--version",),
        apt_hint="sudo apt install -y cmseek",
        alt_hint="git clone https://github.com/Tuhinshubhra/CMSeeK",
        description="Content Management System (CMS) detection",
        limitations="Heuristic detection from HTML meta tags, headers, and known CMS paths.",
    ),
    ModuleContract(
        name="theHarvester",
        binary_candidates=("theHarvester", "theharvester"),
        module_group="osint",
        category="OSINT",
        supported_targets=("domain",),
        traffic_mode="passive",
        estimated_impact="low",
        requires_active_auth=False,
        version_args=("--help",),
        apt_hint="sudo apt install -y theharvester",
        alt_hint="pipx install theHarvester",
        description="Public email, hostname, and OSINT harvester",
        limitations="Uses free public providers (crtsh, urlscan, rapiddns); harvested emails are unverified.",
    ),
    ModuleContract(
        name="gobuster",
        binary_candidates=("gobuster",),
        module_group="bruteforce",
        category="BruteForce",
        supported_targets=("domain", "ip"),
        traffic_mode="active",
        estimated_impact="high",
        requires_active_auth=True,
        version_args=("version",),
        apt_hint="sudo apt install -y gobuster",
        alt_hint="go install github.com/OJ/gobuster/v3@latest",
        description="Scoped HTTP URI/directory discovery tool",
        limitations="Requires an existing local wordlist file and explicit active authorisation.",
    ),
)


def resolve_tool_binary(
    module: ModuleContract, custom_paths: dict[str, str] | None = None
) -> str | None:
    """Locate a tool binary in custom config paths or system PATH."""
    if custom_paths and module.name in custom_paths:
        candidate = custom_paths[module.name]
        found = shutil.which(candidate)
        if found:
            return found
        if Path(candidate).is_file():
            return str(Path(candidate).resolve())
        return None
    for binary in module.binary_candidates:
        found = shutil.which(binary)
        if found:
            return found
    return None


def probe_tool_version(binary_path: str, version_args: tuple[str, ...]) -> str:
    """Safely query the first non-empty version line of an installed binary."""
    try:
        proc = subprocess.run(
            [binary_path, *version_args],
            capture_output=True,
            text=True,
            timeout=5,
            shell=False,
            check=False,
        )
        combined = (proc.stdout or proc.stderr or "").strip()
        for line in combined.splitlines():
            cleaned = line.strip()
            if cleaned:
                return cleaned[:120]
    except (OSError, subprocess.SubprocessError):
        pass
    return "installed (version unknown)"


def check_dependencies(
    custom_paths: dict[str, str] | None = None, probe_versions: bool = True
) -> list[dict[str, Any]]:
    """Inspect all registered reconnaissance modules without modifying the system."""
    statuses: list[dict[str, Any]] = []
    for mod in MODULE_REGISTRY:
        binary = resolve_tool_binary(mod, custom_paths)
        version = (
            probe_tool_version(binary, mod.version_args)
            if (binary and probe_versions)
            else None
        )
        statuses.append(
            {
                "name": mod.name,
                "module_group": mod.module_group,
                "category": mod.category,
                "supported_targets": list(mod.supported_targets),
                "traffic_mode": mod.traffic_mode,
                "estimated_impact": mod.estimated_impact,
                "requires_active_auth": mod.requires_active_auth,
                "installed": bool(binary),
                "path": binary,
                "version": version,
                "apt_hint": mod.apt_hint,
                "alt_hint": mod.alt_hint,
                "description": mod.description,
                "limitations": mod.limitations,
            }
        )
    return statuses


def build_module_command(
    module: ModuleContract,
    binary: str,
    target: TargetSpec,
    config: OmConfig,
    output_file: Path,
) -> list[str] | None:
    """Build a safe argument list for `subprocess.Popen(..., shell=False)`.

    Returns `None` if the module does not support `target.target_type`.
    """
    if target.target_type not in module.supported_targets:
        return None

    policy = config.policy()
    profile = config.profile

    if module.name == "amass":
        cmd = [binary, "enum", "-passive", "-d", target.host, "-o", str(output_file)]
        if profile == "high":
            cmd = [binary, "enum", "-d", target.host, "-o", str(output_file)]
        return cmd

    if module.name == "sublist3r":
        return [binary, "-d", target.host, "-o", str(output_file)]

    if module.name == "dnsrecon":
        return [binary, "-d", target.host, "-t", str(policy["dnsrecon_types"])]

    if module.name == "whatweb":
        aggression = "1" if profile in {"low", "medium"} else "3"
        return [binary, "--color=never", f"-a={aggression}", target.base_url]

    if module.name == "wafw00f":
        cmd = [binary, target.base_url]
        if profile == "high":
            cmd.append("-a")
        return cmd

    if module.name == "nmap":
        args = list(policy["nmap_args"])
        if config.rate_limit:
            args.extend(["--max-rate", str(config.rate_limit)])
        return [binary, *args, "-oN", str(output_file), "--", target.host]

    if module.name == "sslscan":
        host_arg = f"{target.host}:{target.port}" if target.port else target.host
        return [binary, "--no-colour", host_arg]

    if module.name == "cmseek":
        return [binary, "-u", target.base_url, "--follow-redirect", "--batch"]

    if module.name == "theHarvester":
        limit = str(policy["theharvester_limit"])
        return [binary, "-d", target.host, "-l", limit, "-b", "crtsh,urlscan,rapiddns"]

    if module.name == "gobuster":
        threads = str(min(int(policy["gobuster_threads"]), max(1, config.rate_limit)))
        return [
            binary,
            "dir",
            "-u",
            target.base_url,
            "-w",
            config.wordlist,
            "-t",
            threads,
            "--no-color",
            "-q",
            "-o",
            str(output_file),
        ]

    return None


def execute_module(
    module: ModuleContract,
    target: TargetSpec,
    config: OmConfig,
    session_dir: Path,
    cancel_event: threading.Event | None = None,
) -> ModuleExecutionResult:
    """Run a single reconnaissance module with timeout, cancellation support, and error isolation."""
    category_dir = session_dir / module.category
    category_dir.mkdir(parents=True, exist_ok=True)
    out_file = category_dir / f"{module.name}.txt"
    rel_out = f"{module.category}/{module.name}.txt"
    started_iso = datetime.now(timezone.utc).isoformat()

    if cancel_event and cancel_event.is_set():
        return ModuleExecutionResult(
            tool=module.name,
            module_group=module.module_group,
            category=module.category,
            traffic_mode=module.traffic_mode,
            estimated_impact=module.estimated_impact,
            status="cancelled",
            started_at=started_iso,
            ended_at=started_iso,
            error="Scan cancelled before module started.",
            limitations=module.limitations,
        )

    if target.target_type not in module.supported_targets:
        return ModuleExecutionResult(
            tool=module.name,
            module_group=module.module_group,
            category=module.category,
            traffic_mode=module.traffic_mode,
            estimated_impact=module.estimated_impact,
            status="skipped_target_type",
            started_at=started_iso,
            ended_at=started_iso,
            error=(
                f"{module.name} supports target types ({', '.join(module.supported_targets)}), "
                f"not '{target.target_type}'."
            ),
            limitations=module.limitations,
        )

    binary = resolve_tool_binary(module, config.tool_paths)
    if not binary:
        return ModuleExecutionResult(
            tool=module.name,
            module_group=module.module_group,
            category=module.category,
            traffic_mode=module.traffic_mode,
            estimated_impact=module.estimated_impact,
            status="skipped_missing",
            started_at=started_iso,
            ended_at=started_iso,
            error=f"{module.name} is not installed on this system.",
            install_hint=f"{module.apt_hint} (or: {module.alt_hint})",
            limitations=module.limitations,
        )

    if module.name == "gobuster" and not Path(config.wordlist).is_file():
        return ModuleExecutionResult(
            tool=module.name,
            module_group=module.module_group,
            category=module.category,
            traffic_mode=module.traffic_mode,
            estimated_impact=module.estimated_impact,
            status="failed",
            started_at=started_iso,
            ended_at=started_iso,
            error=f"Wordlist not found at '{config.wordlist}'. Configure --wordlist or settings.",
            limitations=module.limitations,
        )

    cmd = build_module_command(module, binary, target, config, out_file)
    if cmd is None:
        return ModuleExecutionResult(
            tool=module.name,
            module_group=module.module_group,
            category=module.category,
            traffic_mode=module.traffic_mode,
            estimated_impact=module.estimated_impact,
            status="skipped_target_type",
            started_at=started_iso,
            ended_at=started_iso,
            error=f"{module.name} is not applicable to target type '{target.target_type}'.",
            limitations=module.limitations,
        )

    version = probe_tool_version(binary, module.version_args)
    t0 = time.monotonic()

    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            shell=False,
        )
        # Poll in slices when cancel_event is provided so cancellation terminates subprocesses promptly
        deadline = t0 + config.timeout
        while True:
            if cancel_event and cancel_event.is_set():
                proc.terminate()
                try:
                    stdout_text, stderr_text = proc.communicate(timeout=2)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    stdout_text, stderr_text = proc.communicate()
                duration = round(time.monotonic() - t0, 3)
                ended_iso = datetime.now(timezone.utc).isoformat()
                if (stdout_text or "").strip():
                    out_file.write_text(stdout_text, encoding="utf-8")
                return ModuleExecutionResult(
                    tool=module.name,
                    module_group=module.module_group,
                    category=module.category,
                    traffic_mode=module.traffic_mode,
                    estimated_impact=module.estimated_impact,
                    status="cancelled",
                    command=cmd,
                    exit_code=proc.returncode,
                    started_at=started_iso,
                    ended_at=ended_iso,
                    duration_seconds=duration,
                    stdout_file=rel_out if out_file.is_file() else "",
                    stdout=stdout_text or "",
                    stderr=stderr_text or "",
                    version=version,
                    error=f"{module.name} cancelled by user.",
                    limitations=module.limitations,
                )

            remaining = deadline - time.monotonic()
            if remaining <= 0:
                proc.kill()
                stdout_text, stderr_text = proc.communicate()
                raise subprocess.TimeoutExpired(cmd=cmd, timeout=config.timeout, output=stdout_text, stderr=stderr_text)

            try:
                stdout_text, stderr_text = proc.communicate(timeout=min(0.25, remaining))
                break
            except subprocess.TimeoutExpired:
                continue

        duration = round(time.monotonic() - t0, 3)
        ended_iso = datetime.now(timezone.utc).isoformat()
        stdout_text = stdout_text or ""
        stderr_text = stderr_text or ""

        if out_file.is_file():
            try:
                file_text = out_file.read_text(encoding="utf-8", errors="replace")
            except OSError:
                file_text = ""
            if file_text and not stdout_text.strip():
                stdout_text = file_text
            elif stdout_text.strip() and not file_text.strip():
                out_file.write_text(stdout_text, encoding="utf-8")
        elif stdout_text.strip():
            out_file.write_text(stdout_text, encoding="utf-8")

        if stderr_text.strip():
            err_file = category_dir / f"{module.name}.stderr.txt"
            err_file.write_text(stderr_text, encoding="utf-8")

        status = "completed" if proc.returncode == 0 else ("partial" if stdout_text.strip() else "failed")
        error_msg = None
        if proc.returncode != 0:
            err_snippet = (stderr_text.strip() or stdout_text.strip() or f"Exit code {proc.returncode}")[:300]
            error_msg = f"Command exited with code {proc.returncode}: {err_snippet}"

        return ModuleExecutionResult(
            tool=module.name,
            module_group=module.module_group,
            category=module.category,
            traffic_mode=module.traffic_mode,
            estimated_impact=module.estimated_impact,
            status=status,
            command=cmd,
            exit_code=proc.returncode,
            started_at=started_iso,
            ended_at=ended_iso,
            duration_seconds=duration,
            stdout_file=rel_out if out_file.is_file() else "",
            stdout=stdout_text,
            stderr=stderr_text,
            version=version,
            error=error_msg,
            limitations=module.limitations,
        )

    except subprocess.TimeoutExpired as exc:
        duration = round(time.monotonic() - t0, 3)
        ended_iso = datetime.now(timezone.utc).isoformat()
        partial_out = (
            exc.output.decode("utf-8", errors="replace")
            if isinstance(exc.output, bytes)
            else (exc.output or "")
        )
        partial_err = (
            exc.stderr.decode("utf-8", errors="replace")
            if isinstance(exc.stderr, bytes)
            else (exc.stderr or "")
        )
        if out_file.is_file() and not partial_out.strip():
            try:
                partial_out = out_file.read_text(encoding="utf-8", errors="replace")
            except OSError:
                pass
        elif partial_out.strip():
            out_file.write_text(partial_out, encoding="utf-8")

        return ModuleExecutionResult(
            tool=module.name,
            module_group=module.module_group,
            category=module.category,
            traffic_mode=module.traffic_mode,
            estimated_impact=module.estimated_impact,
            status="timed_out",
            command=cmd,
            exit_code=None,
            started_at=started_iso,
            ended_at=ended_iso,
            duration_seconds=duration,
            stdout_file=rel_out if out_file.is_file() else "",
            stdout=partial_out,
            stderr=partial_err,
            version=version,
            error=f"{module.name} timed out after {config.timeout}s.",
            limitations=module.limitations,
        )
    except PermissionError as exc:
        duration = round(time.monotonic() - t0, 3)
        ended_iso = datetime.now(timezone.utc).isoformat()
        return ModuleExecutionResult(
            tool=module.name,
            module_group=module.module_group,
            category=module.category,
            traffic_mode=module.traffic_mode,
            estimated_impact=module.estimated_impact,
            status="failed",
            command=cmd,
            exit_code=None,
            started_at=started_iso,
            ended_at=ended_iso,
            duration_seconds=duration,
            version=version,
            error=f"Permission denied executing {module.name}: {exc}",
            limitations=module.limitations,
        )
    except OSError as exc:
        duration = round(time.monotonic() - t0, 3)
        ended_iso = datetime.now(timezone.utc).isoformat()
        return ModuleExecutionResult(
            tool=module.name,
            module_group=module.module_group,
            category=module.category,
            traffic_mode=module.traffic_mode,
            estimated_impact=module.estimated_impact,
            status="failed",
            command=cmd,
            exit_code=None,
            started_at=started_iso,
            ended_at=ended_iso,
            duration_seconds=duration,
            version=version,
            error=f"OS error executing {module.name}: {exc}",
            limitations=module.limitations,
        )
