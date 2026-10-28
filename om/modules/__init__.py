"""Reconnaissance module registry, dependency detection, and safe subprocess execution."""
from __future__ import annotations

from om.modules.registry import (
    MODULE_REGISTRY,
    build_module_command,
    check_dependencies,
    execute_module,
    probe_tool_version,
    resolve_tool_binary,
)

__all__ = [
    "MODULE_REGISTRY",
    "build_module_command",
    "check_dependencies",
    "execute_module",
    "probe_tool_version",
    "resolve_tool_binary",
]
