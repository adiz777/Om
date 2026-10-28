"""Core configuration and output normalisation for Om 2.0."""
from __future__ import annotations

from om.core.config import (
    ALL_MODULE_GROUPS,
    PROFILE_POLICIES,
    VALID_PROFILES,
    OmConfig,
    load_config,
    save_config,
)
from om.core.normalizer import deduplicate_findings, parse_tool_findings, strip_ansi

__all__ = [
    "ALL_MODULE_GROUPS",
    "PROFILE_POLICIES",
    "VALID_PROFILES",
    "OmConfig",
    "deduplicate_findings",
    "load_config",
    "parse_tool_findings",
    "save_config",
    "strip_ansi",
]
