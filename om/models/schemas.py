"""Core schemas and dataclasses for targets, modules, observations, and scan sessions."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(frozen=True)
class TargetSpec:
    """Validated, normalised target representation safe for subprocess argument arrays."""

    raw: str
    host: str
    target_type: str  # "domain" | "ip" | "cidr"
    scheme: str = "https"
    port: int | None = None
    url: str = ""

    @property
    def safe_slug(self) -> str:
        import re

        slug = re.sub(r"[^a-zA-Z0-9._-]+", "_", self.host).strip("._-")
        return slug[:80] or "target"

    @property
    def base_url(self) -> str:
        if self.url:
            return self.url
        if self.port:
            return f"{self.scheme}://{self.host}:{self.port}"
        return f"{self.scheme}://{self.host}"

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["safe_slug"] = self.safe_slug
        data["base_url"] = self.base_url
        return data


@dataclass(frozen=True)
class ModuleContract:
    """Common integration contract exposed by every reconnaissance module."""

    name: str
    binary_candidates: tuple[str, ...]
    module_group: str  # "subdomains" | "dns" | "webtech" | "nmap" | "ssl" | "cms" | "osint" | "bruteforce"
    category: str
    supported_targets: tuple[str, ...]  # ("domain",) or ("domain", "ip", "cidr")
    traffic_mode: str  # "passive" | "light-active" | "active"
    estimated_impact: str  # "low" | "medium" | "high"
    requires_active_auth: bool
    version_args: tuple[str, ...]
    apt_hint: str
    alt_hint: str
    description: str
    limitations: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class Finding:
    """Normalised, evidence-graded reconnaissance observation."""

    category: str  # "subdomain" | "dns_record" | "open_port" | "web_tech" | "waf" | "tls" | "cms" | "osint_email" | "http_path" | "ip_address"
    value: str
    classification: str  # "raw_observation" | "normalised_finding" | "inferred_finding" | "confirmed_issue"
    confidence: str  # "confirmed" | "inferred" | "unverified"
    severity: str  # "info" | "low" | "medium" | "high"
    source_tool: str
    timestamp: str = ""
    evidence: str = ""
    detail: str = ""
    limitations: str = ""
    remediation: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ModuleExecutionResult:
    """Structured execution record for a single reconnaissance tool run."""

    tool: str
    module_group: str
    category: str
    traffic_mode: str
    estimated_impact: str
    status: str  # "completed" | "partial" | "failed" | "timed_out" | "cancelled" | "skipped_missing" | "skipped_target_type" | "skipped_scope"
    command: list[str] = field(default_factory=list)
    exit_code: int | None = None
    started_at: str = ""
    ended_at: str = ""
    duration_seconds: float = 0.0
    stdout_file: str = ""
    stdout: str = ""
    stderr: str = ""
    version: str | None = None
    error: str | None = None
    install_hint: str | None = None
    limitations: str = ""
    findings_count: int = 0

    def to_dict(self, include_raw: bool = False) -> dict[str, Any]:
        data = asdict(self)
        data["stdout_preview"] = self.stdout[:4000]
        data["stderr_preview"] = self.stderr[:2000]
        if not include_raw:
            del data["stdout"]
            del data["stderr"]
        return data


@dataclass
class ScanProgress:
    """Live progress snapshot of an active or completed scan session."""

    session_id: str
    target: str
    profile: str
    status: str  # "running" | "completed" | "partial" | "failed" | "cancelled"
    total_modules: int
    completed_modules: int
    current_modules: list[str] = field(default_factory=list)
    started_at: str = ""
    updated_at: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ScanSession:
    """Complete scan session record stored in SQLite and exported to reports."""

    session_id: str
    target: str
    target_type: str
    profile: str
    scope: list[str]
    status: str  # "completed" | "partial" | "failed" | "cancelled"
    started_at: str
    completed_at: str
    duration_seconds: float
    session_dir: str
    summary: dict[str, Any]
    tools: list[dict[str, Any]]
    findings: list[dict[str, Any]]
    errors: list[dict[str, str]]
    limitations: list[str]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
