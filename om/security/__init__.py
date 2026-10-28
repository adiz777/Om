"""Target validation, scope enforcement, and safety guards for Om 2.0."""
from __future__ import annotations

from om.security.scope import (
     DOMAIN_RE,
    FORBIDDEN_CHARS,
    RESERVED_HOSTNAMES,
    RESERVED_SUFFIXES,
    filter_findings_to_scope,
    parse_target,
    scope_allows_private_ip,
    verify_target_in_scope,
)

__all__ = [
    "DOMAIN_RE",
    "FORBIDDEN_CHARS",
    "RESERVED_HOSTNAMES",
    "RESERVED_SUFFIXES",
    "filter_findings_to_scope",
    "parse_target",
    "scope_allows_private_ip",
    "verify_target_in_scope",
]
