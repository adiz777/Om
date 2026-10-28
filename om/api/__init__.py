"""Local loopback FastAPI application for the Om 2.0 Web Dashboard."""
from __future__ import annotations

from om.api.server import app, create_app

__all__ = ["app", "create_app"]
