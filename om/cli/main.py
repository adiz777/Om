"""Command-line interface, interactive menu, and local dashboard launcher for Om 2.0.

Supports:
- Full non-interactive CLI flags (`--target`, `--profile`, `--modules`, `--concurrency`, etc.)
- Classic interactive menu (`1`–`11`) when invoked without arguments or with `--interactive`
- Dependency verification (`--check-tools`, `--check-tools-json`)
- Scan history and session comparison (`--history`, `--compare`)
- Local web dashboard launch (`--dashboard --host 127.0.0.1 --port 8787`)
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Sequence

from om import AUTHOR, SCHEMA_VERSION, __version__
from om.core.config import (
    ALL_MODULE_GROUPS,
    VALID_PROFILES,
    OmConfig,
    load_config,
)
from om.engine.orchestrator import ScanOrchestrator, run_scan_session
from om.models.schemas import TargetSpec
from om.modules.registry import check_dependencies
from om.reporting.generator import compare_reports
from om.security.scope import parse_target, scope_allows_private_ip
from om.storage.database import list_sessions, load_report_file

BANNER = r"""
 ██████╗ ███╗   ███╗   ██████╗     ██████╗
██╔═══██╗████╗ ████║   ╚════██╗   ██╔═████╗
██║   ██║██╔████╔██║    █████╔╝   ██║██╔██║
██║   ██║██║╚██╔╝██║   ██╔═══╝    ████╔╝██║
╚██████╔╝██║ ╚═╝ ██║   ███████╗██╗╚██████╔╝
 ╚═════╝ ╚═╝     ╚═╝   ╚══════╝╚═╝ ╚═════╝
"""


def print_dependency_report(
    custom_paths: dict[str, str] | None = None, as_json: bool = False
) -> int:
    statuses = check_dependencies(custom_paths=custom_paths, probe_versions=True)
    if as_json:
        print(json.dumps(statuses, indent=2))
        return 0
    print(f"Om v{__version__} - External Reconnaissance Module Status")
    print("=" * 82)
    installed_count = 0
    for item in statuses:
        state = "INSTALLED" if item["installed"] else "MISSING  "
        if item["installed"]:
            installed_count += 1
            detail = f"{item['path']} ({item['version']})"
        else:
            detail = f"Install: {item['apt_hint']}  |  Alt: {item['alt_hint']}"
        print(
            f"[{state}] {item['name']:<13} ({item['module_group']:<10} / {item['traffic_mode']:<12}) -> {detail}"
        )
    print("=" * 82)
    print(
        f"Summary: {installed_count}/{len(statuses)} optional reconnaissance modules detected."
    )
    return 0


def interactive_session(config: OmConfig, initial_target: str | None = None) -> int:
    """Interactive menu mode preserving the classic Om.sh workflow with safety upgrades."""
    print(BANNER)
    print(
        f"Welcome to OM v{__version__} - Automated Reconnaissance & Intelligence Platform (by {AUTHOR})\n"
    )
    print_dependency_report(config.tool_paths)
    print()

    raw_target = initial_target or ""
    target_spec: TargetSpec | None = None
    while target_spec is None:
        if not raw_target:
            try:
                raw_target = input(
                    "Enter the authorised target domain, IP, or CIDR (example.com): "
                ).strip()
            except EOFError:
                return 1
        try:
            allow_priv = scope_allows_private_ip(raw_target, config.scope)
            target_spec = parse_target(raw_target, allow_private=allow_priv)
        except ValueError as exc:
            print(f"[ERROR] {exc}")
            raw_target = ""

    try:
        prof_in = (
            input(
                f"Select scan profile (low, medium, high) [default: {config.profile}]: "
            )
            .strip()
            .lower()
        )
    except EOFError:
        prof_in = ""
    if prof_in in VALID_PROFILES:
        config.apply_profile_defaults(prof_in)

    pol = config.policy()
    print(f"\nProfile '{config.profile.upper()}': {pol['description']}")
    if pol.get("warning"):
        print(f"[WARNING] {pol['warning']}")

    try:
        auth_in = (
            input(
                f"Confirm you have explicit written authorisation to assess '{target_spec.host}'? (y/N): "
            )
            .strip()
            .lower()
        )
    except EOFError:
        auth_in = "n"
    if auth_in in {"y", "yes"}:
        config.authorize_active = True
        if not config.scope:
            config.scope = [target_spec.host]
    else:
        print(
            "[NOTICE] Active scanning not authorised; active modules (nmap, gobuster) will be blocked."
        )

    menu_map = {
        "1": ["subdomains"],
        "2": ["dns"],
        "3": ["webtech"],
        "4": ["nmap"],
        "5": ["ssl"],
        "6": ["cms"],
        "7": ["osint"],
        "8": ["bruteforce"],
    }

    last_session_dir: Path | None = None
    while True:
        print("\nSelect an option:")
        print("1) Subdomain Enumeration (Amass, Sublist3r)")
        print("2) DNS Recon (DNSRecon)")
        print("3) Web Technology & WAF Scan (WhatWeb, WafW00f)")
        print("4) Nmap Port & Service Scan [Active]")
        print("5) SSL/TLS Scan (SSLScan)")
        print("6) CMS Detection (CMSeeK)")
        print("7) OSINT Harvesting (theHarvester)")
        print("8) Directory Brute Force (Gobuster) [Active]")
        print("9) Run Profile Default Modules & Generate Reports")
        print("10) Run All Modules & Archive")
        print("11) Exit")
        try:
            choice = input("Enter choice: ").strip()
        except EOFError:
            print("\nExiting...")
            return 0

        if choice in menu_map:
            try:
                _, last_session_dir = run_scan_session(
                    target_spec, config, selected_modules=menu_map[choice]
                )
            except PermissionError as exc:
                print(f"[BLOCKED] {exc}")
        elif choice == "9":
            try:
                _, last_session_dir = run_scan_session(
                    target_spec, config, selected_modules=config.resolved_modules()
                )
            except PermissionError as exc:
                print(f"[BLOCKED] {exc}")
        elif choice == "10":
            try:
                _, last_session_dir = run_scan_session(
                    target_spec, config, selected_modules=list(ALL_MODULE_GROUPS)
                )
            except PermissionError as exc:
                print(f"[BLOCKED] {exc}")
        elif choice == "11":
            if last_session_dir:
                print(f"Latest reports saved in: {last_session_dir}")
            print("Exiting...")
            return 0
        else:
            print("[ERROR] Invalid choice. Try again.")


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="om",
        description=f"Om v{__version__} - Automated Reconnaissance & Intelligence Platform (by {AUTHOR})",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  om --check-tools\n"
            "  om --target example.com --profile low\n"
            "  om --target example.com --profile medium --scope example.com --authorize-active\n"
            "  om --target example.com --modules subdomains,dns,ssl --output ./reports\n"
            "  om --dashboard --host 127.0.0.1 --port 8787\n"
            "  om --history\n"
            "  om --compare ./reports/session1/report.json ./reports/session2/report.json\n"
        ),
    )
    parser.add_argument(
        "positional_target",
        nargs="?",
        help="Optional target domain, IPv4/IPv6, CIDR, or http(s) URL",
    )
    parser.add_argument(
        "-t", "--target", help="Target domain, IPv4/IPv6 address, CIDR, or http(s) URL"
    )
    parser.add_argument(
        "-p",
        "--profile",
        choices=VALID_PROFILES,
        help="Scanning profile: low (passive/lightweight), medium (balanced), high (comprehensive)",
    )
    parser.add_argument(
        "-m",
        "--modules",
        help=f"Comma-separated modules or tools to run ({', '.join(ALL_MODULE_GROUPS)}, or 'all')",
    )
    parser.add_argument(
        "-o", "--output", help="Base output directory for scan sessions and reports"
    )
    parser.add_argument("--db-path", help="SQLite database path for local scan history")
    parser.add_argument("-c", "--config", help="Path to JSON configuration file")
    parser.add_argument(
        "--scope",
        help="Comma-separated authorised scope entries (domains, *.wildcards, IPs, or CIDRs)",
    )
    parser.add_argument(
        "--authorize-active",
        action="store_true",
        help="Confirm explicit written authorisation for active scanning modules (nmap, gobuster)",
    )
    parser.add_argument(
        "--timeout", type=int, help="Per-module execution timeout in seconds (5-3600)"
    )
    parser.add_argument(
        "--concurrency", type=int, help="Concurrent module worker limit (1-8)"
    )
    parser.add_argument(
        "--rate-limit",
        type=int,
        help="Max rate/threads for active scanners (1-500)",
    )
    parser.add_argument(
        "--wordlist", help="Wordlist path for Gobuster directory discovery"
    )
    parser.add_argument(
        "--format",
        help="Comma-separated report formats to generate (html,json,csv; default: html,json,csv)",
    )
    parser.add_argument(
        "--no-zip",
        action="store_true",
        help="Skip creating a .zip archive of the session folder",
    )
    parser.add_argument(
        "--check-tools",
        action="store_true",
        help="Inspect installed/missing recon tools and exit",
    )
    parser.add_argument(
        "--check-tools-json",
        action="store_true",
        help="Output tool status as JSON and exit",
    )
    parser.add_argument(
        "--history",
        action="store_true",
        help="List previous local scan sessions and exit",
    )
    parser.add_argument(
        "--compare",
        nargs=2,
        metavar=("OLD_REPORT", "NEW_REPORT"),
        help="Compare two Om JSON reports (or session folders) and output added/removed/changed findings",
    )
    parser.add_argument(
        "--dashboard",
        action="store_true",
        help="Launch the local Om 2.0 web dashboard (bound to loopback 127.0.0.1 by default)",
    )
    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="Dashboard bind address (default: 127.0.0.1)",
    )
    parser.add_argument(
        "--port", type=int, default=8787, help="Dashboard bind port (default: 8787)"
    )
    parser.add_argument(
        "-i", "--interactive", action="store_true", help="Launch interactive menu mode"
    )
    parser.add_argument(
        "-q", "--quiet", action="store_true", help="Suppress progress logs on stdout"
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Enable verbose output"
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"Om {__version__} (schema v{SCHEMA_VERSION})",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    try:
        config = load_config(args.config)
    except (FileNotFoundError, ValueError, json.JSONDecodeError) as exc:
        print(f"[ERROR] Configuration error: {exc}", file=sys.stderr)
        return 2

    if args.profile:
        config.apply_profile_defaults(args.profile)
    if args.output:
        config.output_dir = args.output
        if not args.db_path:
            config.db_path = str(Path(args.output) / "om_history.db")
    if args.db_path:
        config.db_path = args.db_path
    if args.modules:
        mods = [m.strip().lower() for m in args.modules.split(",") if m.strip()]
        config.modules = list(ALL_MODULE_GROUPS) if "all" in mods else mods
    if args.scope:
        config.scope = [s.strip() for s in args.scope.split(",") if s.strip()]
    if args.authorize_active:
        config.authorize_active = True
    if args.timeout is not None:
        config.timeout = args.timeout
    if args.concurrency is not None:
        config.concurrency = args.concurrency
    if args.rate_limit is not None:
        config.rate_limit = args.rate_limit
    if args.wordlist:
        config.wordlist = args.wordlist
    if args.format:
        config.report_formats = [
            f.strip().lower() for f in args.format.split(",") if f.strip()
        ]
    if args.no_zip:
        config.archive_zip = False
    if args.quiet:
        config.quiet = True
    if args.verbose:
        config.verbose = True

    try:
        config.validate()
    except ValueError as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 2

    if args.check_tools or args.check_tools_json:
        return print_dependency_report(
            config.tool_paths, as_json=args.check_tools_json
        )

    if args.history:
        res = list_sessions(
            db_path=config.db_path, target_filter=args.target
        )
        print(
            json.dumps(
                {"count": res["total"], "sessions": res["sessions"]}, indent=2
            )
        )
        return 0

    if args.compare:
        try:
            old_doc = load_report_file(args.compare[0])
            new_doc = load_report_file(args.compare[1])
            diff = compare_reports(old_doc, new_doc)
        except (FileNotFoundError, ValueError, json.JSONDecodeError) as exc:
            print(f"[ERROR] Report comparison failed: {exc}", file=sys.stderr)
            return 2
        print(json.dumps(diff, indent=2, ensure_ascii=False))
        return 0

    if args.dashboard:
        import uvicorn

        from om.api.server import create_app

        if args.host not in {"127.0.0.1", "localhost", "::1"}:
            print(
                f"[WARNING] Binding dashboard to non-loopback address '{args.host}'. "
                "EnsureOM_API_KEY and a TLS reverse proxy are configured before remote exposure.",
                file=sys.stderr,
            )
        print(
            f"Launching Om 2.0 Local Dashboard on http://{args.host}:{args.port} ..."
        )
        app = create_app(config)
        uvicorn.run(app, host=args.host, port=args.port, log_level="info")
        return 0

    raw_target = args.target or args.positional_target
    if args.interactive or not raw_target:
        return interactive_session(config, initial_target=raw_target)

    try:
        allow_priv = scope_allows_private_ip(raw_target, config.scope)
        target_spec = parse_target(raw_target, allow_private=allow_priv)
    except ValueError as exc:
        print(f"[ERROR] Invalid target: {exc}", file=sys.stderr)
        return 2

    if not config.quiet:
        orchestrator = ScanOrchestrator(config)
        planned = [m.name for m in orchestrator.resolve_planned_modules(args.modules.split(",") if args.modules and args.modules != "all" else None)]
        print(
            f"Target: {target_spec.host} ({target_spec.target_type}) | "
            f"Profile: {config.profile.upper()} | "
            f"Scope: {', '.join(config.scope or [target_spec.host])} | "
            f"Planned Modules: {', '.join(planned)}"
        )

    try:
        selected = (
            [m.strip().lower() for m in args.modules.split(",") if m.strip()]
            if (args.modules and args.modules != "all")
            else None
        )
        report_doc, session_dir = run_scan_session(
            target_spec, config, selected_modules=selected
        )
    except PermissionError as exc:
        print(f"[BLOCKED] {exc}", file=sys.stderr)
        return 3
    except Exception as exc:  # pragma: no cover
        print(f"[ERROR] Scan failed: {exc}", file=sys.stderr)
        return 1

    if not config.quiet:
        summary = report_doc["summary"]
        print(
            f"\nScan complete for {target_spec.host} (session={report_doc['session_id']}, status={report_doc['status']}). "
            f"Findings: {summary['total_findings']} ({summary['confirmed_findings']} confirmed). "
            f"Output: {session_dir}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
