"""Configuration and scanning profile policies for Om 2.0.

Supports JSON config files, environment variables, and CLI/API overrides without
storing secrets in source code.
"""
from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

VALID_PROFILES = ("low", "medium", "high")
ALL_MODULE_GROUPS = (
    "subdomains",
    "dns",
    "webtech",
    "nmap",
    "ssl",
    "cms",
    "osint",
    "bruteforce",
)

PROFILE_POLICIES: dict[str, dict[str, Any]] = {
    "low": {
        "label": "Low (Lightweight / Minimal Footprint)",
        "description": (
            "Passive and conservative checks only: passive subdomain enumeration, "
            "standard DNS lookup, low-aggression web/WAF/CMS header identification, "
            "TLS configuration check, and public OSINT harvesting. Skips port scanning "
            "and directory brute-forcing by default."
        ),
        "warning": "",
        "default_modules": ["subdomains", "dns", "webtech", "ssl", "cms", "osint"],
        "requires_active_auth": False,
        "default_timeout": 90,
        "default_concurrency": 2,
        "rate_limit_rps": 5,
        "nmap_args": ["-F", "-T3", "--open"],
        "dnsrecon_types": "std",
        "theharvester_limit": 100,
        "gobuster_threads": 5,
    },
    "medium": {
        "label": "Medium (Balanced Reconnaissance)",
        "description": (
            "Broader reconnaissance within declared scope: subdomains, DNS (std,srv), "
            "web technology, TLS, CMS, OSINT, and service version detection on common ports. "
            "Skips high-volume directory brute-forcing unless explicitly requested."
        ),
        "warning": "Generates active TCP port probes against the target host.",
        "default_modules": ["subdomains", "dns", "webtech", "nmap", "ssl", "cms", "osint"],
        "requires_active_auth": True,
        "default_timeout": 180,
        "default_concurrency": 3,
        "rate_limit_rps": 15,
        "nmap_args": ["-sV", "--top-ports", "100", "-T3", "--open"],
        "dnsrecon_types": "std,srv",
        "theharvester_limit": 300,
        "gobuster_threads": 10,
    },
    "high": {
        "label": "High (Comprehensive Scoped Assessment)",
        "description": (
            "Comprehensive authorised reconnaissance including subdomain enumeration, "
            "extended DNS checks (std,srv,axfr), web technology and WAF checks, "
            "Nmap service/default-script scanning (-sV -sC), TLS inspection, CMS detection, "
            "OSINT harvesting, and rate-limited Gobuster directory discovery. "
            "Strictly bounded by scope, timeouts, and concurrency; never performs exploitation."
        ),
        "warning": (
            "HIGH PROFILE WARNING: Generates increased network and HTTP traffic (top-1000 ports + "
            "directory discovery). Ensure explicit written authorisation before running."
        ),
        "default_modules": list(ALL_MODULE_GROUPS),
        "requires_active_auth": True,
        "default_timeout": 300,
        "default_concurrency": 4,
        "rate_limit_rps": 25,
        "nmap_args": ["-sV", "-sC", "-T4", "--top-ports", "1000", "--open"],
        "dnsrecon_types": "std,srv,axfr",
        "theharvester_limit": 500,
        "gobuster_threads": 15,
    },
}


@dataclass
class OmConfig:
    """Runtime configuration for an Om 2.0 scan session or dashboard server."""

    output_dir: str = "om_reports"
    db_path: str = "om_reports/om_history.db"
    profile: str = "low"
    modules: list[str] = field(default_factory=list)
    scope: list[str] = field(default_factory=list)
    authorize_active: bool = False
    timeout: int = 90
    concurrency: int = 2
    rate_limit: int = 5
    retention_days: int = 90
    max_sessions: int = 250
    wordlist: str = "/usr/share/wordlists/dirb/common.txt"
    tool_paths: dict[str, str] = field(default_factory=dict)
    report_formats: list[str] = field(default_factory=lambda: ["html", "json", "csv"])
    archive_zip: bool = True
    quiet: bool = False
    verbose: bool = False

    def resolved_modules(self) -> list[str]:
        if self.modules:
            return [m for m in self.modules if m in ALL_MODULE_GROUPS]
        policy = PROFILE_POLICIES.get(self.profile, PROFILE_POLICIES["low"])
        return list(policy["default_modules"])

    def policy(self) -> dict[str, Any]:
        return PROFILE_POLICIES.get(self.profile, PROFILE_POLICIES["low"])

    def apply_profile_defaults(self, profile: str) -> None:
        if profile not in VALID_PROFILES:
            raise ValueError(f"Invalid profile '{profile}'. Choose from: {', '.join(VALID_PROFILES)}")
        self.profile = profile
        pol = PROFILE_POLICIES[profile]
        self.timeout = int(pol["default_timeout"])
        self.concurrency = int(pol["default_concurrency"])
        self.rate_limit = int(pol["rate_limit_rps"])

    def validate(self) -> None:
        if self.profile not in VALID_PROFILES:
            raise ValueError(f"Invalid profile '{self.profile}'. Choose from: {', '.join(VALID_PROFILES)}")
        if self.timeout < 5 or self.timeout > 3600:
            raise ValueError("Timeout must be between 5 and 3600 seconds.")
        if self.concurrency < 1 or self.concurrency > 8:
            raise ValueError("Concurrency must be between 1 and 8 concurrent workers.")
        if self.rate_limit < 1 or self.rate_limit > 500:
            raise ValueError("Rate limit must be between 1 and 500 requests/packets per second.")
        if self.retention_days < 1 or self.retention_days > 3650:
            raise ValueError("Retention days must be between 1 and 3650.")
        if self.max_sessions < 10 or self.max_sessions > 10000:
            raise ValueError("Max sessions must be between 10 and 10000.")
        invalid_mods = [m for m in self.modules if m not in ALL_MODULE_GROUPS]
        if invalid_mods:
            raise ValueError(
                f"Unknown module(s): {', '.join(invalid_mods)}. Valid modules: {', '.join(ALL_MODULE_GROUPS)}"
            )
        invalid_formats = [f for f in self.report_formats if f not in {"html", "json", "csv"}]
        if invalid_formats:
            raise ValueError("Report formats must be a subset of: html, json, csv")

    def to_public_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["resolved_modules"] = self.resolved_modules()
        data["policy"] = self.policy()
        return data


def load_config(path: str | Path | None = None) -> OmConfig:
    """Load configuration from a JSON file and/or `OM_*` environment variables."""
    cfg = OmConfig()
    cfg.apply_profile_defaults(cfg.profile)

    if path:
        cfg_path = Path(path).expanduser()
        if not cfg_path.exists():
            raise FileNotFoundError(f"Configuration file not found: {cfg_path}")
        raw = json.loads(cfg_path.read_text(encoding="utf-8"))
        if not isinstance(raw, dict):
            raise ValueError("Configuration file root must be a JSON object.")
        if "profile" in raw:
            cfg.apply_profile_defaults(str(raw["profile"]).lower().strip())
        if "output_dir" in raw:
            cfg.output_dir = str(raw["output_dir"])
        if "db_path" in raw:
            cfg.db_path = str(raw["db_path"])
        else:
            cfg.db_path = str(Path(cfg.output_dir) / "om_history.db")
        if "modules" in raw and isinstance(raw["modules"], list):
            cfg.modules = [str(m).lower().strip() for m in raw["modules"]]
        if "scope" in raw and isinstance(raw["scope"], list):
            cfg.scope = [str(s).strip() for s in raw["scope"] if str(s).strip()]
        if "authorize_active" in raw:
            cfg.authorize_active = bool(raw["authorize_active"])
        if "timeout" in raw:
            cfg.timeout = int(raw["timeout"])
        if "concurrency" in raw:
            cfg.concurrency = int(raw["concurrency"])
        if "rate_limit" in raw:
            cfg.rate_limit = int(raw["rate_limit"])
        if "retention_days" in raw:
            cfg.retention_days = int(raw["retention_days"])
        if "max_sessions" in raw:
            cfg.max_sessions = int(raw["max_sessions"])
        if "wordlist" in raw:
            cfg.wordlist = str(raw["wordlist"])
        if "tool_paths" in raw and isinstance(raw["tool_paths"], dict):
            cfg.tool_paths = {str(k): str(v) for k, v in raw["tool_paths"].items()}
        if "report_formats" in raw and isinstance(raw["report_formats"], list):
            cfg.report_formats = [str(f).lower().strip() for f in raw["report_formats"]]
        if "archive_zip" in raw:
            cfg.archive_zip = bool(raw["archive_zip"])

    # Environment overrides
    if os.getenv("OM_PROFILE"):
        cfg.apply_profile_defaults(os.environ["OM_PROFILE"].strip().lower())
    if os.getenv("OM_OUTPUT_DIR"):
        cfg.output_dir = os.environ["OM_OUTPUT_DIR"].strip()
        if not os.getenv("OM_DB_PATH"):
            cfg.db_path = str(Path(cfg.output_dir) / "om_history.db")
    if os.getenv("OM_DB_PATH"):
        cfg.db_path = os.environ["OM_DB_PATH"].strip()
    if os.getenv("OM_SCOPE"):
        cfg.scope = [s.strip() for s in os.environ["OM_SCOPE"].split(",") if s.strip()]
    if os.getenv("OM_TIMEOUT"):
        cfg.timeout = int(os.environ["OM_TIMEOUT"])
    if os.getenv("OM_CONCURRENCY"):
        cfg.concurrency = int(os.environ["OM_CONCURRENCY"])
    if os.getenv("OM_RATE_LIMIT"):
        cfg.rate_limit = int(os.environ["OM_RATE_LIMIT"])
    if os.getenv("OM_AUTHORIZE_ACTIVE", "").lower() in {"1", "true", "yes"}:
        cfg.authorize_active = True

    cfg.validate()
    return cfg


def save_config(cfg: OmConfig, path: str | Path) -> Path:
    """Validate and persist an OmConfig to a JSON file."""
    cfg.validate()
    dest = Path(path).expanduser()
    dest.parent.mkdir(parents=True, exist_ok=True)
    payload = asdict(cfg)
    dest.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    return dest
